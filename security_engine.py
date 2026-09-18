"""
SHIELD.USB — security_engine.py
Pre-emptive HID quarantine + blacklist-first enforcement.

Fixes:
  #1 — Unknown HID inserted → immediate QUARANTINE before telemetry
  #2 — Blacklist checked FIRST at insertion, before trust lookup
  #3 — evaluate_live_hid CPS threshold bug fixed (was `cps >= 0`)
"""

import db

# ── Thresholds ────────────────────────────────────────────────────────────────

BLOCK_THRESHOLD   = 45   # risk score → BLOCKED
MONITOR_THRESHOLD = 25   # risk score → MONITOR

# CPS above which live evaluation triggers containment
CPS_BLOCK_THRESHOLD = 20.0


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_risk_score(trust_status: str, device_class: str,
                         anomaly_score: int = 0) -> int:
    score = 0

    if trust_status == "BLACKLIST":
        score += 100
    elif trust_status == "UNKNOWN":
        score += 15
    elif trust_status == "WHITELIST":
        score += 0

    if device_class == "HID":
        score += 20
    elif device_class == "HID_RISK":
        score += 20   # CDC/Serial BadUSB (Pico etc.) same risk as HID
    elif device_class == "USB_STORAGE":
        score += 10

    score += anomaly_score
    return min(score, 100)


def determine_action(score: int) -> str:
    if score >= BLOCK_THRESHOLD:
        return "BLOCKED"
    elif score >= MONITOR_THRESHOLD:
        return "MONITOR"
    return "ALLOWED"


# ── Insertion-Time Evaluation ─────────────────────────────────────────────────

def get_initial_action(device_info: dict) -> dict:
    """
    FIX #1 + #2: Decision tree at insertion time:

      1. Blacklist match? → BLOCKED immediately (no telemetry phase)
      2. HID device?      → QUARANTINE (monitor mode, watcher spawned)
      3. Non-HID unknown? → score-based ALLOWED / MONITOR
    """
    vid          = device_info["vid"].upper()
    pid          = device_info["pid"].upper()
    device_name  = device_info["device_name"]
    device_class = device_info["device_class"]

    # ── Step 1: Blacklist check FIRST (FIX #2) ──────────────────────────────
    if db.is_blacklisted(vid, pid):
        db.log_security_event(
            vid=vid, pid=pid,
            device_name=device_name, device_class=device_class,
            trust_status="BLACKLIST", risk_score=100,
            action_taken="BLOCKED", cps=0.0,
            containment_status="INSTANT_BLACKLIST_HIT"
        )
        return {
            "action_taken":  "BLOCKED",
            "risk_score":    100,
            "trust_status":  "BLACKLIST",
            "is_blacklisted": True
        }

    # ── Step 2: HID gets immediate QUARANTINE (FIX #1) ──────────────────────
    # Unknown HID devices are quarantined (watched) immediately.
    # They are NOT allowed to run freely while telemetry warms up.
    trust_status = db.check_device_trust(vid, pid)

    if device_class in ("HID", "HID_RISK") and trust_status != "WHITELIST":
        db.log_security_event(
            vid=vid, pid=pid,
            device_name=device_name, device_class=device_class,
            trust_status=trust_status, risk_score=35,
            action_taken="QUARANTINE", cps=0.0,
            containment_status="HID_QUARANTINE"
        )
        print(f"[SECURITY] {device_class} QUARANTINE → {device_name} ({vid}:{pid})")
        return {
            "action_taken":  "QUARANTINE",
            "risk_score":    35,
            "trust_status":  trust_status,
            "is_blacklisted": False
        }

    # ── Step 3: Normal scoring for non-HID / whitelisted devices ────────────
    risk_score   = calculate_risk_score(trust_status, device_class)
    action_taken = determine_action(risk_score)

    db.log_security_event(
        vid=vid, pid=pid,
        device_name=device_name, device_class=device_class,
        trust_status=trust_status, risk_score=risk_score,
        action_taken=action_taken, cps=0.0,
        containment_status="NOT_TRIGGERED"
    )

    return {
        "action_taken":  action_taken,
        "risk_score":    risk_score,
        "trust_status":  trust_status,
        "is_blacklisted": False
    }


# ── Live HID Evaluation (called by HIDWatcher every tick) ────────────────────

def evaluate_live_hid(*args, **kwargs) -> dict:
    """
    Evaluates live HID telemetry for high-velocity injection or bot cadence.
    Accepts both:
      evaluate_live_hid(device_info, telemetry_snapshot)
    and
      evaluate_live_hid(cps=..., anomaly_score=..., variance_ok=..., current_risk_score=..., device_info=...)
    """
    device_info = kwargs.get("device_info")
    telemetry_snapshot = kwargs.get("telemetry_snapshot")

    if args:
        if len(args) >= 1 and isinstance(args[0], dict) and "vid" in args[0]:
            device_info = args[0]
        if len(args) >= 2 and isinstance(args[1], dict):
            telemetry_snapshot = args[1]

    if not device_info:
        device_info = {
            "vid": kwargs.get("vid", "UNKNOWN"),
            "pid": kwargs.get("pid", "UNKNOWN"),
            "device_class": kwargs.get("device_class", "HID"),
            "device_name": kwargs.get("device_name", "USB HID Device")
        }

    vid = str(device_info.get("vid", "")).upper()
    pid = str(device_info.get("pid", "")).upper()
    trust_status = db.check_device_trust(vid, pid)

    # Extract CPS, anomaly score, and threat indicators
    if telemetry_snapshot:
        cps = float(telemetry_snapshot.get("cps_short", 0.0))
        anomaly_score = int(telemetry_snapshot.get("anomaly_score", 0))
        classification = telemetry_snapshot.get("classification", "HUMAN")
        threat_detected = bool(telemetry_snapshot.get("threat_detected", False))
    else:
        cps = float(kwargs.get("cps", 0.0))
        anomaly_score = int(kwargs.get("anomaly_score", 0))
        classification = "BADUSB" if cps >= CPS_BLOCK_THRESHOLD else "HUMAN"
        threat_detected = cps >= CPS_BLOCK_THRESHOLD or not kwargs.get("variance_ok", True)

    normalized_class = "HID" if device_info.get("device_class") == "HID_RISK" else device_info.get("device_class", "HID")
    final_score = calculate_risk_score(trust_status, normalized_class, anomaly_score)
    action_taken = determine_action(final_score)

    if cps >= CPS_BLOCK_THRESHOLD or threat_detected:
        action_taken = "BLOCKED"
        final_score = max(final_score, 85)

    return {
        "should_block": action_taken == "BLOCKED",
        "action_taken": action_taken,
        "final_risk_score": final_score,
        "cps": cps,
        "classification": classification,
        "anomaly_score": anomaly_score
    }


# ── Static Device Analysis (non-HID) ─────────────────────────────────────────

def analyze_device(device_info: dict) -> dict:
    vid          = device_info["vid"].upper()
    pid          = device_info["pid"].upper()
    device_name  = device_info["device_name"]
    device_class = device_info["device_class"]
    trust_status = db.check_device_trust(vid, pid)
    risk_score   = calculate_risk_score(trust_status, device_class)
    action_taken = determine_action(risk_score)

    db.log_security_event(
        vid=vid, pid=pid,
        device_name=device_name, device_class=device_class,
        trust_status=trust_status, risk_score=risk_score,
        action_taken=action_taken, cps=0.0,
        containment_status="NOT_TRIGGERED"
    )

    return {
        "vid": vid, "pid": pid,
        "device_name":  device_name,
        "device_class": device_class,
        "trust_status": trust_status,
        "risk_score":   risk_score,
        "action_taken": action_taken
    }
