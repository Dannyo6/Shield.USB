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

def evaluate_live_hid(device_info: dict, telemetry_snapshot: dict) -> dict:
    """
    FIX #3: Bug fix — original code used `if cps >= 0` which blocked
    every single keystroke, including 0.0 at device insertion.
    Corrected to use CPS_BLOCK_THRESHOLD (20 CPS).

    Also checks anomaly_score independently so bot-like variance
    triggers containment even at moderate CPS.
    """
    vid          = device_info["vid"].upper()
    pid          = device_info["pid"].upper()
    trust_status = db.check_device_trust(vid, pid)

    cps           = telemetry_snapshot["cps_short"]
    anomaly_score = telemetry_snapshot["anomaly_score"]
    classification = telemetry_snapshot["classification"]
    threat_detected = telemetry_snapshot.get("threat_detected", False)

    normalized_class = "HID" if device_info.get("device_class") == "HID_RISK" else device_info.get("device_class", "HID")
    final_score  = calculate_risk_score(trust_status, normalized_class, anomaly_score)
    action_taken = determine_action(final_score)

    # FIX #3: Correct threshold — was `cps >= 0` (always True)
    if cps >= CPS_BLOCK_THRESHOLD or threat_detected:
        action_taken = "BLOCKED"
        final_score  = max(final_score, 85)

    return {
        "should_block":    action_taken == "BLOCKED",
        "action_taken":    action_taken,
        "final_risk_score": final_score,
        "cps":             cps,
        "classification":  classification,
        "anomaly_score":   anomaly_score
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
