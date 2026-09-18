"""
SHIELD.USB — telemetry_engine.py
Keystroke telemetry with thread-safe state management.

Fixes:
  #3 — reset_session() renamed fix (usb_monitor called reset_session,
       function was named reset_for_device — now both names work)
     — listener restart after reset no longer spawns duplicate threads
"""

import time
import threading
from collections import deque
from pynput import keyboard

# ── Thresholds ────────────────────────────────────────────────────────────────

WINDOW_SHORT = 2        # seconds — fast CPS window
WINDOW_LONG  = 10       # seconds — sustained CPS window

CPS_HUMAN_MAX  = 8
CPS_SUSPICIOUS = 20
CPS_HIGH_RISK  = 40
CPS_BADUSB     = 60

BURST_CONFIRM_COUNT  = 3       # consecutive HIGH_RISK windows → confirmed burst
VARIANCE_BOT_CEILING = 0.003   # std-dev below this → bot-like timing

# ── Internal State ────────────────────────────────────────────────────────────

_lock = threading.Lock()

_keypress_times   = deque()
_recent_intervals = deque(maxlen=20)

_last_keypress    = None

_cps_short        = 0.0
_cps_long         = 0.0

_anomaly_score    = 0
_threat_detected  = False
_burst_counter    = 0

_total_keys_logged = 0
_session_start     = time.time()

_listener = None
_running  = False


# ── Math Helpers ──────────────────────────────────────────────────────────────

def _calculate_variance(intervals: list) -> float:
    if len(intervals) < 3:
        return 999.0
    avg = sum(intervals) / len(intervals)
    return (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5


def _classify_cps(cps: float) -> tuple[str, int]:
    if cps < CPS_HUMAN_MAX:
        return "HUMAN", 0
    elif cps < CPS_SUSPICIOUS:
        return "SUSPICIOUS", 10
    elif cps < CPS_HIGH_RISK:
        return "HIGH_RISK", 25
    elif cps < CPS_BADUSB:
        return "BADUSB", 40
    else:
        return "BADUSB_CONFIRMED", 50


def _update_anomaly_score():
    global _anomaly_score, _threat_detected, _burst_counter

    _, risk_delta = _classify_cps(_cps_short)

    variance_penalty = 0
    if len(_recent_intervals) >= 5:
        std_dev = _calculate_variance(list(_recent_intervals))
        if std_dev < VARIANCE_BOT_CEILING:
            variance_penalty = 15

    composite = risk_delta + variance_penalty

    if _cps_short >= CPS_HIGH_RISK:
        _burst_counter += 1
    else:
        _burst_counter = max(0, _burst_counter - 1)

    if _burst_counter >= BURST_CONFIRM_COUNT:
        composite = min(50, composite + 10)

    _anomaly_score   = min(50, composite)
    _threat_detected = _anomaly_score >= 30


# ── Keystroke Listener ────────────────────────────────────────────────────────

def _on_press(key):
    global _cps_short, _cps_long, _last_keypress, _total_keys_logged

    now = time.time()

    with _lock:
        _total_keys_logged += 1

        if _last_keypress is not None:
            _recent_intervals.append(now - _last_keypress)

        _last_keypress = now
        _keypress_times.append(now)

        cutoff_long = now - WINDOW_LONG
        while _keypress_times and _keypress_times[0] < cutoff_long:
            _keypress_times.popleft()

        cutoff_short  = now - WINDOW_SHORT
        keys_in_short = sum(1 for t in _keypress_times if t >= cutoff_short)
        keys_in_long  = len(_keypress_times)

        _cps_short = keys_in_short / WINDOW_SHORT
        _cps_long  = keys_in_long  / WINDOW_LONG

        _update_anomaly_score()


# ── Lifecycle ─────────────────────────────────────────────────────────────────

def start_monitoring():
    """
    FIX #3: Guard against double-start — only spawns one listener thread.
    """
    global _listener, _running, _session_start

    with _lock:
        if _running:
            return
        _running       = True
        _session_start = time.time()

    _listener         = keyboard.Listener(on_press=_on_press)
    _listener.daemon  = True
    _listener.start()
    print("[TELEMETRY] Keystroke monitor started.")


def stop_monitoring():
    global _listener, _running

    with _lock:
        _running = False

    if _listener and _listener.is_alive():
        _listener.stop()
    print("[TELEMETRY] Keystroke monitor stopped.")


def reset_session():
    """
    FIX #3: Canonical reset name that usb_monitor.py calls.
    Wipes rolling windows so the next device gets a clean baseline.
    Does NOT restart the listener — it stays active across resets.
    """
    global _last_keypress, _cps_short, _cps_long
    global _anomaly_score, _threat_detected, _burst_counter, _total_keys_logged

    with _lock:
        _keypress_times.clear()
        _recent_intervals.clear()

        _last_keypress     = None
        _cps_short         = 0.0
        _cps_long          = 0.0
        _anomaly_score     = 0
        _threat_detected   = False
        _burst_counter     = 0
        _total_keys_logged = 0

    print("[TELEMETRY] Session reset — clean baseline.")


# Alias for backward compatibility (original name in codebase)
reset_for_device = reset_session


# ── Read-only Exports ─────────────────────────────────────────────────────────

def get_telemetry() -> dict:
    """Full snapshot for the Flask /api/telemetry endpoint."""
    with _lock:
        label, _ = _classify_cps(_cps_short)

        if len(_recent_intervals) >= 5:
            std_dev     = _calculate_variance(list(_recent_intervals))
            variance_ok = std_dev >= VARIANCE_BOT_CEILING
        else:
            variance_ok = True

        return {
            "cps_short":       round(_cps_short, 2),
            "cps_long":        round(_cps_long,  2),
            "anomaly_score":   _anomaly_score,
            "threat_detected": _threat_detected,
            "classification":  label,
            "variance_ok":     variance_ok,
            "total_keys":      _total_keys_logged,
            "uptime_seconds":  round(time.time() - _session_start, 1),
        }


def get_live_snapshot() -> dict:
    """
    Lightweight snapshot polled by HIDWatcher every tick.
    Includes burst_counter for direct use in security_engine.
    """
    with _lock:
        label, risk_delta = _classify_cps(_cps_short)

        if len(_recent_intervals) >= 5:
            std_dev     = _calculate_variance(list(_recent_intervals))
            variance_ok = std_dev >= VARIANCE_BOT_CEILING
        else:
            variance_ok = True

        return {
            "cps_short":       round(_cps_short, 2),
            "cps_long":        round(_cps_long,  2),
            "anomaly_score":   _anomaly_score,
            "threat_detected": _threat_detected,
            "classification":  label,
            "variance_ok":     variance_ok,
            "burst_counter":   _burst_counter,
            "total_keys":      _total_keys_logged,
            "uptime_seconds":  round(time.time() - _session_start, 1),
        }


# Auto-start listener when module is imported
start_monitoring()
