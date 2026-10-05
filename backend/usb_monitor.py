"""
SHIELD.USB — usb_monitor.py
USB insertion monitor with pre-emptive HID quarantine,
parent-device containment support, normalized descriptors,
and resilient interactive fallback for non-WMI environments.
"""

import sys
import time
import threading

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Graceful optional WMI import
try:
    import wmi
except ImportError:
    wmi = None

import telemetry_engine
import containment_engine
import security_engine
import ak_database
import db
import db_manager


# ── Global State ─────────────────────────────────────────

_known_devices = {}
_active_watchers = {}
_monitor_lock = threading.Lock()


# ── Device Filtering ─────────────────────────────────────

IGNORE_KEYWORDS = [
    "Bluetooth",
    "Fingerprint",
    "Wireless",
    "Controller",
    "System",
    "Root Hub",
    "Composite Device"
]


def _should_ignore(device_name: str) -> bool:
    return any(
        kw.lower() in (device_name or "").lower()
        for kw in IGNORE_KEYWORDS
    )


# ── Parsing Helpers ──────────────────────────────────────

def normalize_descriptor(desc: str) -> str:
    """Strips whitespace, removes 0x prefix if present, and normalizes to uppercase without stripping leading zeros."""
    if not desc:
        return ""
    s = str(desc).strip()
    if s.upper().startswith("0X"):
        s = s[2:]
    return s.strip().upper()


def extract_vid_pid(device_id: str):
    """
    Extracts and normalizes VID and PID from standard USB device strings.
    Example: USB\\VID_16C0&PID_27DB\\... -> ('16C0', '27DB')
    """
    try:
        segment = device_id.split("\\")[1]
        parts = segment.split("&")
        vid = normalize_descriptor(parts[0].replace("VID_", ""))
        pid = normalize_descriptor(parts[1].replace("PID_", ""))
        return vid, pid
    except Exception:
        return None, None


# ── Parent Device Finder ─────────────────────────────────

def find_parent_composite_device(wmi_obj, vid: str, pid: str):
    """
    Finds the ROOT composite USB device instance ID.
    Example: USB\\VID_2E8A&PID_000B\\... instead of USB\\VID_2E8A&PID_000B&MI_03\\...
    """
    if not wmi_obj:
        return None
    try:
        v_norm = normalize_descriptor(vid)
        p_norm = normalize_descriptor(pid)
        for dev in wmi_obj.Win32_PnPEntity():
            did = getattr(dev, "DeviceID", "")
            if not did:
                continue
            upper = did.upper()
            if f"VID_{v_norm}" in upper and f"PID_{p_norm}" in upper and "&MI_" not in upper:
                return did
    except Exception as e:
        print(f"[PARENT LOOKUP ERROR] {e}")
    return None


def classify_device_class(device_id: str, device_name: str = "") -> str:
    upper = (device_id or "").upper()
    name_upper = (device_name or "").upper()

    if "HID" in upper:
        return "HID"
    if "USBSTOR" in upper:
        return "USB_STORAGE"

    CDC_SIGNALS = ["CDC", "SERIAL", "ACM", "CDCS", "MODEM"]
    if any(s in upper or s in name_upper for s in CDC_SIGNALS):
        return "HID_RISK"

    BADUSB_VIDS = ["2E8A", "16C0", "1B4F", "2341", "239A", "1209", "1D50", "0483"]
    try:
        vid, _ = extract_vid_pid(device_id)
        if vid and vid in BADUSB_VIDS:
            return "HID_RISK"
    except Exception:
        pass

    return "UNKNOWN"


# ── HID Watcher ──────────────────────────────────────────

class HIDWatcher(threading.Thread):
    def __init__(self, device_info: dict):
        super().__init__(daemon=True)
        self.device_info = device_info
        self._running = threading.Event()
        self._running.set()
        self.name = f"HIDWatcher-{device_info['vid']}:{device_info['pid']}"

    def stop(self):
        self._running.clear()

    def run(self):
        info = self.device_info
        vid = info["vid"]
        pid = info["pid"]
        device_id = info["device_id"]
        parent_device_id = info.get("parent_device_id")
        device_name = info["device_name"]

        print(f"[WATCHER] Started → {device_name} ({vid}:{pid})")
        telemetry_engine.reset_session()

        while self._running.is_set():
            try:
                snap = telemetry_engine.get_live_snapshot()
                cps = snap.get("cps_short", 0.0)

                if cps > 0:
                    print(f"[WATCHER] {device_name} — CPS: {cps:.1f} | Score: {snap.get('anomaly_score', 0)}")

                eval_result = security_engine.evaluate_live_hid(
                    cps=cps,
                    anomaly_score=snap.get("anomaly_score", 0),
                    variance_ok=snap.get("variance_ok", True),
                    current_risk_score=info.get("initial_risk_score", 35)
                )

                if eval_result.get("action_taken") == "BLOCKED":
                    print(f"\n[THREAT TRIGGERED] BadUSB detected on {device_name} (CPS: {cps:.1f})")
                    containment_engine.disable_hid_device(
                        device_instance_id=device_id,
                        parent_device_id=parent_device_id,
                        vid=vid,
                        pid=pid,
                        device_name=device_name,
                        cps_at_block=cps,
                        reason="REALTIME_BEHAVIORAL_DETECTION"
                    )
                    db.log_security_event(
                        vid=vid,
                        pid=pid,
                        device_name=device_name,
                        device_class="HID",
                        trust_status="THREAT",
                        risk_score=eval_result.get("final_risk_score", 95),
                        action_taken="BLOCKED",
                        cps=cps,
                        containment_status="CONTAINED"
                    )
                    self._running.clear()
                    break

                time.sleep(0.1)
            except Exception as e:
                print(f"[WATCHER ERROR] {device_name}: {e}")
                time.sleep(1)

        with _monitor_lock:
            _active_watchers.pop(device_id, None)

        print(f"[WATCHER] Stopped → {device_name}")


# ── New Device Handler ───────────────────────────────────

def _handle_new_device(device_id: str, device_info: dict):
    vid = normalize_descriptor(device_info["vid"])
    pid = normalize_descriptor(device_info["pid"])
    device_name = device_info.get("device_name", f"USB Device ({vid}:{pid})")
    device_class = device_info.get("device_class", "UNKNOWN")
    parent_device_id = device_info.get("parent_device_id")

    print(f"\n[USB CONNECTED] {device_name} | {device_class} | VID:{vid} PID:{pid}")
    if parent_device_id:
        print(f"[PARENT DEVICE] {parent_device_id}")

    initial = security_engine.get_initial_action(device_info)
    action = initial.get("action_taken", "UNKNOWN")

    if action == "BLOCKED":
        print(f"[BLACKLIST HIT] Instant containment → {device_name}")
        containment_engine.disable_hid_device(
            device_instance_id=device_id,
            parent_device_id=parent_device_id,
            vid=vid,
            pid=pid,
            device_name=device_name,
            cps_at_block=0.0,
            reason="BLACKLIST_INSTANT_BLOCK"
        )
        return

    if action == "QUARANTINE" or device_class in ("HID", "HID_RISK"):
        with _monitor_lock:
            if device_id in _active_watchers:
                print(f"[WATCHER] Watcher already active for {device_name}")
                return
            watcher = HIDWatcher(device_info)
            _active_watchers[device_id] = watcher
            watcher.start()
        return

    print(f"[USB ALLOWED] {device_name} ({vid}:{pid}) verified.")


def _handle_removed_device(device_id: str):
    info = _known_devices.get(device_id, {})
    name = info.get("device_name", device_id)
    print(f"\n[USB REMOVED] {name}")

    with _monitor_lock:
        watcher = _active_watchers.pop(device_id, None)
    if watcher:
        watcher.stop()
    _known_devices.pop(device_id, None)


# ── Interactive Console Fallback Mode ────────────────────

def interactive_console_fallback():
    """
    Console fallback mode providing interactive USB event injection
    for testing, non-Windows platforms, or environments where native WMI is restricted.
    """
    print("\n" + "=" * 62)
    print("  SHIELD.USB PRO — HARDWARE SENTRY CONSOLE MODE")
    print("  (Interactive Bus Simulator & Live Telemetry Sentry)")
    print("=" * 62)
    print("  Controls:")
    print("    [ENTER]         -> Simulate Hak5 Rubber Ducky / RPi Pico (16C0:27DB)")
    print("    'wh' or 'logi'  -> Simulate Whitelisted Logitech Receiver (046D:C52B)")
    print("    'omg'           -> Simulate O.MG Malicious Cable (1209:0001)")
    print("    '<VID>:<PID>'   -> Interrogate custom hardware descriptor")
    print("    'q' or 'exit'   -> Clean shutdown")
    print("=" * 62 + "\n")

    if not telemetry_engine._running:
        telemetry_engine.start_monitoring()

    try:
        while True:
            cmd = input("[SHIELD-USB-PRO] Enter command or press [Enter] to test: ").strip()
            if cmd.lower() in ("q", "exit"):
                break

            if cmd == "":
                simulate_device_insertion("16C0", "27DB", "Hak5 Rubber Ducky / RPi Pico", "HID")
            elif cmd.lower() in ("wh", "logi"):
                simulate_device_insertion("046D", "C52B", "Logitech USB Unifying Receiver", "HID")
            elif cmd.lower() == "omg":
                simulate_device_insertion("1209", "0001", "O.MG Cable Malicious Injector", "HID")
            elif ":" in cmd:
                v, p = cmd.split(":", 1)
                simulate_device_insertion(v, p, f"Custom Peripheral ({v.upper()}:{p.upper()})", "HID")
            else:
                print(f"[WARN] Unrecognized command '{cmd}'. Press Enter to test 16C0:27DB or 'q' to quit.")
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _shutdown_monitor()


def _shutdown_monitor():
    print("\n[MONITOR] Shutting down bus sentry...")
    with _monitor_lock:
        for w in list(_active_watchers.values()):
            w.stop()
    telemetry_engine.stop_monitoring()
    print("[MONITOR] Stopped cleanly.")


# ── Main Monitor Entry ───────────────────────────────────

def start_usb_monitor():
    """
    Primary monitoring loop with native WMI interrogation
    and automatic graceful fallback.
    """
    if wmi is None:
        print("[MONITOR NOTICE] Python 'wmi' module not available. Activating interactive console fallback.")
        interactive_console_fallback()
        return

    try:
        c = wmi.WMI()
    except Exception as e:
        print(f"[MONITOR NOTICE] WMI subsystem initialization failed ({e}). Activating interactive console fallback.")
        interactive_console_fallback()
        return

    if not telemetry_engine._running:
        telemetry_engine.start_monitoring()

    print("=" * 48)
    print("  SHIELD.USB PRO HARDWARE SENTRY ACTIVE")
    print("  Parent containment: ENABLED | Engine: WAL")
    print("=" * 48)

    try:
        while True:
            try:
                active_ids = set()
                for device in c.Win32_PnPEntity():
                    try:
                        device_id = getattr(device, "DeviceID", "")
                        if not device_id:
                            continue

                        if not ("USB" in device_id.upper() and "VID_" in device_id and "PID_" in device_id):
                            continue

                        active_ids.add(device_id)
                        if device_id in _known_devices:
                            continue

                        vid, pid = extract_vid_pid(device_id)
                        if not vid or not pid:
                            continue

                        device_name = getattr(device, "Name", "") or f"Unknown USB {vid}:{pid}"
                        if _should_ignore(device_name):
                            continue

                        device_class = classify_device_class(device_id, device_name)
                        parent_device_id = find_parent_composite_device(c, vid, pid)

                        device_info = {
                            "vid": vid,
                            "pid": pid,
                            "device_name": device_name,
                            "device_class": device_class,
                            "device_id": device_id,
                            "parent_device_id": parent_device_id
                        }

                        _known_devices[device_id] = device_info
                        _handle_new_device(device_id, device_info)

                    except Exception as inner_err:
                        pass

                for stored_id in list(_known_devices.keys()):
                    if stored_id not in active_ids:
                        _handle_removed_device(stored_id)

                time.sleep(0.2)

            except Exception as loop_err:
                print(f"[MONITOR WARNING] {loop_err}")
                time.sleep(1)

    except (KeyboardInterrupt, SystemExit):
        _shutdown_monitor()


def simulate_device_insertion(vid: str, pid: str, device_name: str = "Simulated USB Peripheral",
                              device_class: str = "HID"):
    """
    Simulates a hardware device insertion event for preflight testing and CI validation.
    Extracts descriptors, interrogates ak_database, logs verdict, and triggers quarantine/containment.
    """
    v_norm = normalize_descriptor(vid)
    p_norm = normalize_descriptor(pid)
    print(f"\n[SIMULATION] Intercepted hardware insertion event: {v_norm}:{p_norm} ({device_name})")
    device_id = f"USB\\VID_{v_norm}&PID_{p_norm}\\SIMULATED_INSTANCE"
    device_info = {
        "vid": v_norm,
        "pid": p_norm,
        "device_name": device_name,
        "device_class": device_class,
        "device_id": device_id,
        "parent_device_id": None
    }
    _handle_new_device(device_id, device_info)


# ── CLI Entrypoint ───────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shield.USB Pro Hardware Bus Sentry")
    parser.add_argument("--simulate", action="store_true", help="Run simulated hardware insertion smoke test")
    parser.add_argument("--fallback", action="store_true", help="Force interactive console fallback mode")
    parser.add_argument("--vid", type=str, default="16C0", help="VID for simulation")
    parser.add_argument("--pid", type=str, default="27DB", help="PID for simulation")
    parser.add_argument("--name", type=str, default="BadUSB Emulation Dongle", help="Device name for simulation")
    args = parser.parse_args()

    ak_database.setup_database()

    if args.simulate:
        print("[MONITOR] Running in SIMULATION mode...")
        simulate_device_insertion(args.vid, args.pid, args.name)
        print("[MONITOR] Simulation complete.")
    elif args.fallback:
        interactive_console_fallback()
    else:
        start_usb_monitor()
