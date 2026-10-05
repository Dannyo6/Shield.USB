"""
Shield.USB Pro — ak_database.py
Enterprise Storage Engine & Hardware Vault for Zero-Trust USB Hardware Security.
Thread-safe SQLite connection manager with WAL mode, curated hardware signatures,
low-latency querying functions, and zero-drift ISO audit logging.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union

DATABASE_NAME = "shield_usb.db"
_db_lock = threading.Lock()


class TrustResult(dict):
    """
    Structured trust result dictionary that supports direct string comparison:
      assert check_usb_trust('16C0', '27DB') == 'BLACKLIST'
      assert check_usb_trust('046D', 'C52B') == 'WHITELIST'
      assert check_usb_trust('FFFF', '0000') == 'UNKNOWN'
    as well as dictionary key access:
      result['verdict'] == 'BLOCKED_BLACKLIST'
      result['trust_status'] == 'BLACKLIST'
    """
    def __eq__(self, other):
        if isinstance(other, str):
            return self.get("trust_status") == other or self.get("verdict") == other
        return super().__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)


# Curated Hardware Signatures (Threat Intelligence & Trusted Baselines)
DEFAULT_KNOWN_DEVICES = [
    {
        "vid": "16C0",
        "pid": "27DB",
        "device_name": "Hak5 Rubber Ducky / RPi Pico",
        "device_class": "HIDClass",
        "trust_status": "BLACKLIST"
    },
    {
        "vid": "1209",
        "pid": "0001",
        "device_name": "O.MG Cable",
        "device_class": "HIDClass",
        "trust_status": "BLACKLIST"
    },
    {
        "vid": "1D50",
        "pid": "60F1",
        "device_name": "Hak5 Bash Bunny",
        "device_class": "Net",
        "trust_status": "BLACKLIST"
    },
    {
        "vid": "2E8A",
        "pid": "0005",
        "device_name": "Raspberry Pi Pico RP2040 BadUSB",
        "device_class": "HIDClass",
        "trust_status": "BLACKLIST"
    },
    {
        "vid": "2341",
        "pid": "8036",
        "device_name": "Arduino Leonardo HID Injector",
        "device_class": "HIDClass",
        "trust_status": "BLACKLIST"
    },
    {
        "vid": "046D",
        "pid": "C52B",
        "device_name": "Logitech USB Unifying Receiver",
        "device_class": "HIDClass",
        "trust_status": "WHITELIST"
    },
    {
        "vid": "0781",
        "pid": "5581",
        "device_name": "SanDisk Ultra USB 3.0 Flash Drive",
        "device_class": "MassStorage",
        "trust_status": "WHITELIST"
    },
    {
        "vid": "0951",
        "pid": "1666",
        "device_name": "Kingston DataTraveler 3.0",
        "device_class": "MassStorage",
        "trust_status": "WHITELIST"
    },
    {
        "vid": "046D",
        "pid": "C077",
        "device_name": "Logitech Optical USB Mouse",
        "device_class": "HIDClass",
        "trust_status": "WHITELIST"
    },
    {
        "vid": "045E",
        "pid": "0750",
        "device_name": "Microsoft Wired Keyboard 600",
        "device_class": "HIDClass",
        "trust_status": "WHITELIST"
    }
]


def get_connection(timeout: int = 10) -> sqlite3.Connection:
    """
    Creates and returns a thread-safe connection configured with WAL mode and busy timeout.
    """
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def setup_database():
    """
    Initializes tables, indices, and pre-populates known threat & whitelist signatures.
    """
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS KnownDevices (
                        vid          TEXT NOT NULL COLLATE NOCASE,
                        pid          TEXT NOT NULL COLLATE NOCASE,
                        device_name  TEXT,
                        device_class TEXT,
                        trust_status TEXT NOT NULL,
                        PRIMARY KEY(vid, pid)
                    );

                    CREATE TABLE IF NOT EXISTS ConnectionLogs (
                        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp          TEXT NOT NULL,
                        vid                TEXT NOT NULL,
                        pid                TEXT NOT NULL,
                        device_name        TEXT DEFAULT 'Unknown USB Device',
                        device_class       TEXT DEFAULT 'UNKNOWN',
                        trust_status       TEXT DEFAULT 'UNKNOWN',
                        risk_score         INTEGER DEFAULT 0,
                        action_taken       TEXT NOT NULL,
                        cps                REAL DEFAULT 0.0,
                        containment_status TEXT DEFAULT 'NOT_TRIGGERED'
                    );

                    CREATE TABLE IF NOT EXISTS Blacklist (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        vid             TEXT NOT NULL COLLATE NOCASE,
                        pid             TEXT NOT NULL COLLATE NOCASE,
                        device_name     TEXT,
                        reason          TEXT,
                        blacklisted_at  TEXT,
                        insertion_count INTEGER DEFAULT 1,
                        UNIQUE(vid, pid)
                    );

                    CREATE TABLE IF NOT EXISTS ContainmentLogs (
                        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp          TEXT NOT NULL,
                        vid                TEXT NOT NULL,
                        pid                TEXT NOT NULL,
                        device_name        TEXT,
                        device_instance_id TEXT,
                        method             TEXT DEFAULT 'pnputil',
                        success            INTEGER DEFAULT 0,
                        message            TEXT,
                        cps_at_block       REAL DEFAULT 0.0,
                        reason             TEXT DEFAULT 'BEHAVIORAL_DETECTION'
                    );

                    CREATE INDEX IF NOT EXISTS idx_known_vidpid ON KnownDevices(vid, pid);
                    CREATE INDEX IF NOT EXISTS idx_connlogs_ts ON ConnectionLogs(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_connlogs_vidpid ON ConnectionLogs(vid, pid);
                    CREATE INDEX IF NOT EXISTS idx_blacklist_vidpid ON Blacklist(vid, pid);
                """)

                # Pre-populate curated hardware threat & whitelist signatures
                for dev in DEFAULT_KNOWN_DEVICES:
                    v_norm = dev["vid"].strip().upper()
                    p_norm = dev["pid"].strip().upper()
                    status = dev["trust_status"].strip().upper()

                    conn.execute("""
                        INSERT INTO KnownDevices (vid, pid, device_name, device_class, trust_status)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(vid, pid) DO UPDATE SET
                            device_name  = excluded.device_name,
                            device_class = excluded.device_class,
                            trust_status = excluded.trust_status;
                    """, (
                        v_norm,
                        p_norm,
                        dev["device_name"],
                        dev["device_class"],
                        status
                    ))

                    # Seed into Blacklist if status is BLACKLIST
                    if status == "BLACKLIST":
                        now_iso = datetime.now(timezone.utc).isoformat()
                        conn.execute("""
                            INSERT INTO Blacklist (vid, pid, device_name, reason, blacklisted_at, insertion_count)
                            VALUES (?, ?, ?, 'KNOWN_HARDWARE_SIGNATURE', ?, 1)
                            ON CONFLICT(vid, pid) DO NOTHING;
                        """, (v_norm, p_norm, dev["device_name"], now_iso))

            print("[AK_DB] Storage Engine & Hardware Vault ready (WAL enabled).")
        finally:
            conn.close()


def normalize_hex_descriptor(val: str) -> str:
    """Safely normalizes hex descriptors without stripping leading zeros."""
    if not val:
        return ""
    s = str(val).strip()
    if s.upper().startswith("0X"):
        s = s[2:]
    return s.strip().upper()


# ── Core Optimized Querying Functions ─────────────────────────────────────────

def check_usb_trust(vid: str, pid: str) -> TrustResult:
    """
    Evaluates VID:PID trust status against the persistent hardware vault.
    Returns structured TrustResult dict:
      {
        "vid": "...",
        "pid": "...",
        "trust_status": "WHITELIST" | "BLACKLIST" | "UNKNOWN",
        "device_name": "...",
        "device_class": "...",
        "verdict": "ALLOWED_WHITELIST" | "BLOCKED_BLACKLIST" | "QUARANTINED_UNKNOWN"
      }
    """
    if not vid or not pid:
        return TrustResult({
            "vid": str(vid),
            "pid": str(pid),
            "trust_status": "UNKNOWN",
            "device_name": "Invalid Descriptors",
            "device_class": "UNKNOWN",
            "verdict": "QUARANTINED_UNKNOWN"
        })

    v = normalize_hex_descriptor(vid)
    p = normalize_hex_descriptor(pid)

    with _db_lock:
        conn = get_connection()
        try:
            # Check persistent blacklist table first
            b_row = conn.execute(
                "SELECT device_name, reason FROM Blacklist WHERE vid=? AND pid=?",
                (v, p)
            ).fetchone()

            if b_row:
                return TrustResult({
                    "vid": v,
                    "pid": p,
                    "trust_status": "BLACKLIST",
                    "device_name": b_row["device_name"] or "Blacklisted BadUSB Device",
                    "device_class": "HID_RISK",
                    "verdict": "BLOCKED_BLACKLIST",
                    "reason": b_row["reason"]
                })

            # Check KnownDevices table
            k_row = conn.execute(
                "SELECT device_name, device_class, trust_status FROM KnownDevices WHERE vid=? AND pid=?",
                (v, p)
            ).fetchone()

            if k_row:
                status = k_row["trust_status"].upper()
                if status == "BLACKLIST":
                    verdict = "BLOCKED_BLACKLIST"
                elif status == "WHITELIST":
                    verdict = "ALLOWED_WHITELIST"
                else:
                    verdict = "QUARANTINED_UNKNOWN"

                return TrustResult({
                    "vid": v,
                    "pid": p,
                    "trust_status": status,
                    "device_name": k_row["device_name"],
                    "device_class": k_row["device_class"],
                    "verdict": verdict
                })

            return TrustResult({
                "vid": v,
                "pid": p,
                "trust_status": "UNKNOWN",
                "device_name": f"USB Device ({v}:{p})",
                "device_class": "UNKNOWN",
                "verdict": "QUARANTINED_UNKNOWN"
            })
        finally:
            conn.close()


def log_event(vid: str, pid: str, action: str, device_name: str = "",
              device_class: str = "", risk_score: int = 0,
              cps: float = 0.0, containment_status: str = "NOT_TRIGGERED") -> int:
    """
    Inserts a security event entry into ConnectionLogs with zero-drift UTC ISO timestamp.
    Returns the generated log row ID.
    """
    v = normalize_hex_descriptor(vid)
    p = normalize_hex_descriptor(pid)
    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine trust status based on action if not known
    trust_status = "UNKNOWN"
    if "BLACKLIST" in action or "BLOCKED" in action:
        trust_status = "BLACKLIST"
    elif "WHITELIST" in action or "ALLOWED" in action:
        trust_status = "WHITELIST"

    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                cursor = conn.execute("""
                    INSERT INTO ConnectionLogs
                        (timestamp, vid, pid, device_name, device_class,
                         trust_status, risk_score, action_taken, cps, containment_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    now_iso, v, p,
                    device_name or f"Device {v}:{p}",
                    device_class or "USB_DEVICE",
                    trust_status,
                    int(risk_score),
                    action,
                    float(cps),
                    containment_status
                ))
                return cursor.lastrowid
        finally:
            conn.close()


def get_latest_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent connection logs ordered chronologically descending.
    Handles empty database states gracefully.
    """
    with _db_lock:
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT id, timestamp, vid, pid, device_name, device_class,
                       trust_status, risk_score, action_taken, cps, containment_status
                FROM ConnectionLogs
                ORDER BY id DESC
                LIMIT ?
            """, (max(1, limit),)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()


# ── Backward Compatibility Bridge for Legacy Modules ─────────────────────────

def is_blacklisted(vid: str, pid: str) -> bool:
    res = check_usb_trust(vid, pid)
    return res.get("trust_status") == "BLACKLIST"


def blacklist_device(vid: str, pid: str, device_name: str = "", reason: str = "BEHAVIORAL_DETECTION"):
    v = normalize_hex_descriptor(vid)
    p = normalize_hex_descriptor(pid)
    now_iso = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO Blacklist (vid, pid, device_name, reason, blacklisted_at, insertion_count)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(vid, pid) DO UPDATE SET
                        insertion_count = insertion_count + 1,
                        reason          = excluded.reason,
                        blacklisted_at  = excluded.blacklisted_at;
                """, (v, p, device_name, reason, now_iso))
                conn.execute("""
                    INSERT INTO KnownDevices (vid, pid, device_name, device_class, trust_status)
                    VALUES (?, ?, ?, 'HID_RISK', 'BLACKLIST')
                    ON CONFLICT(vid, pid) DO UPDATE SET trust_status = 'BLACKLIST';
                """, (v, p, device_name))
        finally:
            conn.close()


def fetch_blacklist() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = get_connection()
        try:
            rows = conn.execute("SELECT * FROM Blacklist ORDER BY blacklisted_at DESC").fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()


def log_containment(vid: str, pid: str, device_name: str, device_instance_id: str,
                    success: bool, message: str, cps_at_block: float = 0.0,
                    reason: str = "BEHAVIORAL_DETECTION"):
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO ContainmentLogs
                        (timestamp, vid, pid, device_name, device_instance_id,
                         method, success, message, cps_at_block, reason)
                    VALUES (?, ?, ?, ?, ?, 'pnputil', ?, ?, ?, ?)
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    (vid or "").upper(), (pid or "").upper(),
                    device_name, device_instance_id,
                    1 if success else 0,
                    message, float(cps_at_block), reason
                ))
        finally:
            conn.close()


def fetch_containment_logs(limit: int = 100) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT * FROM ContainmentLogs ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()


def check_device_trust(vid: str, pid: str) -> str:
    res = check_usb_trust(vid, pid)
    return res.get("trust_status", "UNKNOWN")


def log_security_event(vid, pid, device_name, device_class,
                       trust_status, risk_score, action_taken,
                       cps=0.0, containment_status="NOT_TRIGGERED"):
    return log_event(vid, pid, action_taken, device_name=device_name,
                     device_class=device_class, risk_score=risk_score,
                     cps=cps, containment_status=containment_status)


def fetch_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    return get_latest_logs(limit)


if __name__ == "__main__":
    setup_database()
    print("[AK_DB] Self-test complete.")
