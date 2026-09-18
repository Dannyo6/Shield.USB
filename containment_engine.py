"""
SHIELD.USB — containment_engine.py
Advanced containment engine with:
- parent composite device containment
- blacklist persistence
- DB-backed audit
- retry handling
- fallback containment targeting
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import subprocess
import ctypes
import threading
import time
from datetime import datetime

import db



# ── Global State ─────────────────────────────────────────

_lock = threading.Lock()

_contained_keys = set()

_session_log = []


# ── Admin Check ──────────────────────────────────────────

def is_admin():

    try:

        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )

    except Exception:

        return False


# ── Main Containment ─────────────────────────────────────

def disable_hid_device(

    device_instance_id: str,

    vid: str,
    pid: str,

    device_name: str = "",

    cps_at_block: float = 0.0,

    reason: str = "BEHAVIORAL_DETECTION",

    parent_device_id: str = None
):

    key = (
        f"{vid.upper()}:"
        f"{pid.upper()}:"
        f"{device_instance_id}"
    )

    with _lock:

        if key in _contained_keys:

            return {
                "success": True,
                "status": "ALREADY_CONTAINED"
            }

        _contained_keys.add(key)

    print(
        f"[CONTAINMENT] "
        f"Disabling {device_name} "
        f"({vid}:{pid})"
    )

    success, message = _run_containment(

        device_instance_id=device_instance_id,

        parent_device_id=parent_device_id
    )

    # ── Persist Blacklist ────────────────────────────────

    db.blacklist_device(

        vid=vid,

        pid=pid,

        device_name=device_name,

        reason=reason
    )

    # ── DB Audit ─────────────────────────────────────────

    db.log_containment(

        vid=vid,

        pid=pid,

        device_name=device_name,

        device_instance_id=device_instance_id,

        success=success,

        message=message,

        cps_at_block=cps_at_block,

        reason=reason
    )

    event = {

        "timestamp":
            datetime.now().isoformat(),

        "vid":
            vid.upper(),

        "pid":
            pid.upper(),

        "device_name":
            device_name,

        "device_instance_id":
            device_instance_id,

        "success":
            success,

        "message":
            message,

        "cps_at_block":
            cps_at_block,

        "reason":
            reason,

        "status":
            (
                "DISABLED"
                if success
                else "DISABLE_FAILED"
            )
    }

    with _lock:

        _session_log.append(event)

    print(
        f"[CONTAINMENT] "
        f"{'OK' if success else 'FAILED'} "
        f"— {message}"
    )

    return {

        "success": success,

        "status": event["status"],

        "message": message
    }


# ── Parent + Interface Containment ──────────────────────

def _run_containment(

    device_instance_id: str,

    parent_device_id: str = None,

    retries: int = 3
):

    targets = []

    # ── FIRST TRY PARENT COMPOSITE DEVICE ───────────────

    if parent_device_id:

        targets.append(parent_device_id)

    # ── THEN TRY SPECIFIC INTERFACE ─────────────────────

    targets.append(device_instance_id)

    last_err = ""

    for target in targets:

        print(
            f"[CONTAINMENT TARGET] "
            f"{target}"
        )

        for attempt in range(1, retries + 1):

            try:

                result = subprocess.run(

                    [
                        "pnputil",
                        "/remove-device",
                        target
                    ],

                    capture_output=True,

                    text=True,

                    timeout=8
                )

                output = (
                    result.stdout +
                    result.stderr
                ).strip()

                if result.returncode == 0:

                    print(
                        f"[CONTAINMENT SUCCESS] "
                        f"{target}"
                    )

                    return (
                        True,
                        output or
                        "Device removed"
                    )

                last_err = (
                    output or
                    f"pnputil exit "
                    f"{result.returncode}"
                )

                print(
                    f"[CONTAINMENT] "
                    f"Attempt {attempt} failed"
                )

                print(last_err)

            except subprocess.TimeoutExpired:

                last_err = (
                    f"Timeout on "
                    f"attempt {attempt}"
                )

                print(last_err)

            except Exception as e:

                last_err = str(e)

                print(
                    f"[CONTAINMENT ERROR] "
                    f"{last_err}"
                )

            if attempt < retries:

                time.sleep(0.3 * attempt)

    return False, last_err


# ── Status API ──────────────────────────────────────────

def get_containment_status():

    db_records = db.fetch_containment_logs(
        limit=200
    )

    db_keys = {

        f"{r['vid']}:"
        f"{r['pid']}:"
        f"{r['device_instance_id']}"

        for r in db_records
    }

    with _lock:

        extra = [

            e for e in _session_log

            if (
                f"{e['vid']}:"
                f"{e['pid']}:"
                f"{e['device_instance_id']}"
            ) not in db_keys
        ]

    combined = db_records + extra

    combined.sort(

        key=lambda r: r.get(
            "timestamp",
            ""
        ),

        reverse=True
    )

    return {

        "session_records": combined,

        "contained_count": len(
            _contained_keys
        )
    }
