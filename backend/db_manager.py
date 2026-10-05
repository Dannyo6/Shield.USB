"""
Shield.USB Pro — db_manager.py
Standardized enterprise database bridge and alias for ak_database.py.
Provides zero-breaking-change backwards compatibility for all modules importing db_manager.
"""

from ak_database import *
from ak_database import (
    DATABASE_NAME,
    TrustResult,
    get_connection,
    setup_database,
    check_usb_trust,
    log_event,
    get_latest_logs,
    is_blacklisted,
    blacklist_device,
    fetch_blacklist,
    log_containment,
    fetch_containment_logs,
    check_device_trust,
    log_security_event,
    fetch_recent_logs,
    DEFAULT_KNOWN_DEVICES
)

if __name__ == "__main__":
    setup_database()
    print("[DB_MANAGER] Storage Engine & Hardware Vault ready via db_manager bridge.")
