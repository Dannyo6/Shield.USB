"""
SHIELD.USB — usb_monitor.py
USB insertion monitor with pre-emptive HID quarantine
and parent-device containment support.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import time
import threading
import wmi

import telemetry_engine
import containment_engine
import security_engine
import db



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
        kw.lower() in device_name.lower()
        for kw in IGNORE_KEYWORDS
    )


# ── Parsing Helpers ──────────────────────────────────────

def extract_vid_pid(device_id: str):

    try:

        segment = device_id.split("\\")[1]

        parts = segment.split("&")

        vid = parts[0].replace(
            "VID_",
            ""
        ).strip()

        pid = parts[1].replace(
            "PID_",
            ""
        ).strip()

        return vid, pid

    except Exception:

        return None, None


# ── NEW PARENT DEVICE FINDER ─────────────────────────────

def find_parent_composite_device(
    wmi_obj,
    vid,
    pid
):

    """
    Finds the ROOT composite USB device.

    Example:
    USB\\VID_2E8A&PID_000B\\...

    instead of:
    USB\\VID_2E8A&PID_000B&MI_03\\...
    """

    try:

        for dev in wmi_obj.Win32_PnPEntity():

            did = getattr(dev, "DeviceID", "")

            if not did:
                continue

            upper = did.upper()

            if (
                f"VID_{vid}" in upper and
                f"PID_{pid}" in upper and
                "&MI_" not in upper
            ):

                return did

    except Exception as e:

        print(
            f"[PARENT LOOKUP ERROR] {e}"
        )

    return None


def classify_device_class(
    device_id: str,
    device_name: str = ""
):

    upper = device_id.upper()

    name_upper = device_name.upper()

    if "HID" in upper:
        return "HID"

    if "USBSTOR" in upper:
        return "USB_STORAGE"

    CDC_SIGNALS = [
        "CDC",
        "SERIAL",
        "ACM",
        "CDCS",
        "MODEM"
    ]

    if any(
        s in upper or s in name_upper
        for s in CDC_SIGNALS
    ):

        return "HID_RISK"

    BADUSB_VIDS = [
        "2E8A",
        "16C0",
        "1B4F",
        "2341",
        "239A",
        "1209",
        "0483"
    ]

    try:

        vid = (
            device_id
            .split("\\")[1]
            .split("&")[0]
            .replace("VID_", "")
            .strip()
            .upper()
        )

        if vid in BADUSB_VIDS:
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

        self.name = (
            f"HIDWatcher-"
            f"{device_info['vid']}:"
            f"{device_info['pid']}"
        )

    def stop(self):

        self._running.clear()

    def run(self):

        info = self.device_info

        vid = info["vid"]
        pid = info["pid"]

        device_id = info["device_id"]

        parent_device_id = info.get(
            "parent_device_id"
        )

        device_name = info["device_name"]

        print(
            f"[WATCHER] Started → "
            f"{device_name} "
            f"({vid}:{pid})"
        )

        telemetry_engine.reset_session()

        while self._running.is_set():

            try:

                snap = (
                    telemetry_engine
                    .get_live_snapshot()
                )

                cps = snap["cps_short"]

                if cps > 0:

                    print(
                        f"[WATCHER] "
                        f"{device_name} "
                        f"— CPS: {cps:.1f} "
                        f"| anomaly: "
                        f"{snap['anomaly_score']} "
                        f"| class: "
                        f"{snap['classification']}"
                    )

                eval_result = (
                    security_engine
                    .evaluate_live_hid(
                        device_info=info,
                        telemetry_snapshot=snap
                    )
                )

                if eval_result["should_block"]:

                    print(
                        f"\n{'='*45}"
                    )

                    print(
                        f"[THREAT CONFIRMED] "
                        f"{device_name}"
                    )

                    print(
                        f"  CPS       : "
                        f"{cps:.1f}"
                    )

                    print(
                        f"  Score     : "
                        f"{eval_result['final_risk_score']}"
                    )

                    print(
                        f"  Class     : "
                        f"{eval_result['classification']}"
                    )

                    print(
                        f"  ACTION    : "
                        f"CONTAINMENT"
                    )

                    print(
                        f"{'='*45}\n"
                    )

                    containment_engine.disable_hid_device(

                        device_instance_id=device_id,

                        parent_device_id=parent_device_id,

                        vid=vid,
                        pid=pid,

                        device_name=device_name,

                        cps_at_block=cps,

                        reason=(
                            "REALTIME_BEHAVIORAL_DETECTION"
                        )
                    )

                    db.log_security_event(

                        vid=vid,
                        pid=pid,

                        device_name=device_name,

                        device_class="HID",

                        trust_status="THREAT",

                        risk_score=(
                            eval_result[
                                "final_risk_score"
                            ]
                        ),

                        action_taken="BLOCKED",

                        cps=cps,

                        containment_status="CONTAINED"
                    )

                    self._running.clear()

                    break

                time.sleep(0.1)

            except Exception as e:

                print(
                    f"[WATCHER ERROR] "
                    f"{device_name}: {e}"
                )

                time.sleep(1)

        with _monitor_lock:

            _active_watchers.pop(
                device_id,
                None
            )

        print(
            f"[WATCHER] Stopped → "
            f"{device_name}"
        )


# ── New Device Handler ───────────────────────────────────

def _handle_new_device(
    device_id: str,
    device_info: dict
):

    vid = device_info["vid"]

    pid = device_info["pid"]

    device_name = device_info["device_name"]

    device_class = device_info["device_class"]

    parent_device_id = device_info.get(
        "parent_device_id"
    )

    print(
        f"\n[USB CONNECTED] "
        f"{device_name} | "
        f"{device_class} | "
        f"VID:{vid} PID:{pid}"
    )

    if parent_device_id:

        print(
            f"[PARENT DEVICE] "
            f"{parent_device_id}"
        )

    initial = (
        security_engine
        .get_initial_action(device_info)
    )

    action = initial["action_taken"]

    if action == "BLOCKED":

        print(
            f"[BLACKLIST HIT] "
            f"Instant containment → "
            f"{device_name}"
        )

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

    if (
        action == "QUARANTINE"
        or
        device_class in (
            "HID",
            "HID_RISK"
        )
    ):

        with _monitor_lock:

            if device_id in _active_watchers:

                print(
                    f"[WATCHER] "
                    f"Already watching "
                    f"{device_name}"
                )

                return

            watcher = HIDWatcher(device_info)

            _active_watchers[
                device_id
            ] = watcher

        watcher.start()

        print(
            f"[QUARANTINE] "
            f"Watcher active "
            f"({device_class}) → "
            f"{device_name}"
        )

        return

    print(
        f"[ALLOWED] "
        f"{device_name} | "
        f"action={action} | "
        f"score={initial['risk_score']}"
    )


# ── Removal Handler ──────────────────────────────────────

def _handle_removed_device(device_id: str):

    info = _known_devices.get(
        device_id,
        {}
    )

    name = info.get(
        "device_name",
        device_id
    )

    print(f"[USB REMOVED] {name}")

    with _monitor_lock:

        watcher = _active_watchers.pop(
            device_id,
            None
        )

    if watcher:

        watcher.stop()

    _known_devices.pop(
        device_id,
        None
    )


# ── Main Monitor ─────────────────────────────────────────

def start_usb_monitor():

    c = wmi.WMI()

    if not telemetry_engine._running:

        telemetry_engine.start_monitoring()

    print("=" * 44)

    print(
        " SHIELD.USB MONITOR ACTIVE"
    )

    print(
        " Parent containment : ENABLED"
    )

    print("=" * 44)

    try:

        while True:

            try:

                active_ids = set()

                for device in c.Win32_PnPEntity():

                    try:

                        device_id = device.DeviceID

                        if not device_id:
                            continue

                        if not (
                            "USB" in device_id.upper()
                            and
                            "VID_" in device_id
                            and
                            "PID_" in device_id
                        ):

                            continue

                        active_ids.add(device_id)

                        if device_id in _known_devices:
                            continue

                        vid, pid = (
                            extract_vid_pid(
                                device_id
                            )
                        )

                        if not vid or not pid:
                            continue

                        device_name = (
                            device.Name
                            or
                            f"Unknown USB "
                            f"{vid}:{pid}"
                        )

                        device_class = (
                            classify_device_class(
                                device_id,
                                device_name
                            )
                        )

                        if _should_ignore(device_name):
                            continue

                        parent_device_id = (
                            find_parent_composite_device(
                                c,
                                vid.upper(),
                                pid.upper()
                            )
                        )

                        device_info = {

                            "vid": vid.upper(),

                            "pid": pid.upper(),

                            "device_name": device_name,

                            "device_class": device_class,

                            "device_id": device_id,

                            "parent_device_id":
                                parent_device_id
                        }

                        _known_devices[
                            device_id
                        ] = device_info

                        _handle_new_device(
                            device_id,
                            device_info
                        )

                    except Exception as inner_err:

                        print(
                            f"[DEVICE ERROR] "
                            f"{inner_err}"
                        )

                for stored_id in list(
                    _known_devices.keys()
                ):

                    if stored_id not in active_ids:

                        _handle_removed_device(
                            stored_id
                        )

                time.sleep(0.2)

            except Exception as loop_err:

                print(
                    f"[MONITOR ERROR] "
                    f"{loop_err}"
                )

                time.sleep(2)

    except KeyboardInterrupt:

        print(
            "\n[MONITOR] "
            "Shutting down..."
        )

        with _monitor_lock:

            for w in list(
                _active_watchers.values()
            ):

                w.stop()

        telemetry_engine.stop_monitoring()

        print("[MONITOR] Stopped.")


def simulate_device_insertion(vid: str, pid: str, device_name: str = "Simulated USB Peripheral",
                              device_class: str = "HID"):
    """
    Simulates a hardware device insertion event for preflight testing and CI validation.
    Extracts descriptors, interrogates ak_database, logs verdict, and triggers quarantine/containment.
    """
    print(f"\n[SIMULATION] Intercepted hardware insertion event: {vid}:{pid} ({device_name})")
    device_id = f"USB\\VID_{vid}&PID_{pid}\\SIMULATED_INSTANCE"
    device_info = {
        "vid": vid.upper(),
        "pid": pid.upper(),
        "device_name": device_name,
        "device_class": device_class,
        "device_id": device_id,
        "parent_device_id": None
    }
    _handle_new_device(device_id, device_info)


# ── Entry ────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Shield.USB Pro Hardware Bus Sentry")
    parser.add_argument("--simulate", action="store_true", help="Run simulated hardware insertion smoke test")
    parser.add_argument("--vid", type=str, default="16C0", help="VID for simulation")
    parser.add_argument("--pid", type=str, default="27DB", help="PID for simulation")
    parser.add_argument("--name", type=str, default="BadUSB Emulation Dongle", help="Device name for simulation")
    args = parser.parse_args()

    db.setup_database()

    if args.simulate:
        print("[MONITOR] Running in SIMULATION mode...")
        simulate_device_insertion(args.vid, args.pid, args.name)
        print("[MONITOR] Simulation complete.")
    else:
        start_usb_monitor()
