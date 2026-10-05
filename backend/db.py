"""
Shield.USB Pro — db.py
Unified database bridge linking existing system components directly to ak_database.py.
"""

from ak_database import (
    DATABASE_NAME,
    TrustResult,
    get_connection,
    setup_database,
    is_blacklisted,
    blacklist_device,
    fetch_blacklist,
    log_containment,
    fetch_containment_logs,
    check_device_trust,
    log_security_event,
    fetch_recent_logs,
    check_usb_trust,
    log_event,
    get_latest_logs,
    DEFAULT_KNOWN_DEVICES
)

__all__ = [
    "DATABASE_NAME",
    "TrustResult",
    "get_connection",
    "setup_database",
    "is_blacklisted",
    "blacklist_device",
    "fetch_blacklist",
    "log_containment",
    "fetch_containment_logs",
    "check_device_trust",
    "log_security_event",
    "fetch_recent_logs",
    "check_usb_trust",
    "log_event",
    "get_latest_logs",
    "DEFAULT_KNOWN_DEVICES"
]

if __name__ == "__main__":
    setup_database()
    print("[DB] Unified bridge initialized.")
