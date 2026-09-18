"""
Shield.USB Pro — smoke_test.py
Automated Preflight Verification Suite.
Asserts database initialization, WAL journal mode, table integrity,
curated signature querying, event logging, and Flask REST API endpoints.
"""

import sys
import os
import unittest
import json
import sqlite3

# Ensure local modules are accessible
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import ak_database
import db
import app as flask_app_module


class TestShieldUsbProStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ak_database.setup_database()

    def test_01_wal_mode_and_tables(self):
        """Verify SQLite tables and PRAGMA journal_mode=WAL."""
        conn = ak_database.get_connection()
        try:
            # Check WAL mode
            wal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            self.assertEqual(wal_mode.upper(), "WAL", f"Expected WAL mode, got {wal_mode}")

            # Check expected tables
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()]
            expected = ["KnownDevices", "ConnectionLogs", "Blacklist", "ContainmentLogs"]
            for tbl in expected:
                self.assertIn(tbl, tables, f"Missing table: {tbl}")
            print("  [PASS] WAL mode enabled and all 4 tables verified.")
        finally:
            conn.close()

    def test_02_pre_populated_signatures(self):
        """Verify threat and trusted hardware signatures."""
        # 1. Raspberry Pi Pico / Rubber Ducky (Blacklist)
        ducky_trust = ak_database.check_usb_trust("16C0", "27DB")
        self.assertEqual(ducky_trust["trust_status"], "BLACKLIST")
        self.assertEqual(ducky_trust["verdict"], "BLOCKED_BLACKLIST")

        # 2. Logitech Unifying Receiver (Whitelist)
        logi_trust = ak_database.check_usb_trust("046D", "C52B")
        self.assertEqual(logi_trust["trust_status"], "WHITELIST")
        self.assertEqual(logi_trust["verdict"], "ALLOWED_WHITELIST")

        # 3. SanDisk Flash Drive (Whitelist)
        sandisk_trust = ak_database.check_usb_trust("0781", "5581")
        self.assertEqual(sandisk_trust["trust_status"], "WHITELIST")
        self.assertEqual(sandisk_trust["verdict"], "ALLOWED_WHITELIST")

        # 4. Unknown peripheral
        unknown_trust = ak_database.check_usb_trust("DEAD", "BEEF")
        self.assertEqual(unknown_trust["trust_status"], "UNKNOWN")
        self.assertEqual(unknown_trust["verdict"], "QUARANTINED_UNKNOWN")
        print("  [PASS] Hardware signature trust checks verified.")

    def test_03_event_logging_and_retrieval(self):
        """Verify event logging and retrieval."""
        log_id = ak_database.log_event(
            vid="16C0",
            pid="27DB",
            action="BLOCKED_BLACKLIST",
            device_name="Test Threat Device",
            device_class="HID_KEYBOARD",
            risk_score=95,
            cps=75.4,
            containment_status="CONTAINED_PRE_DRIVER"
        )
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)

        logs = ak_database.get_latest_logs(limit=5)
        self.assertGreater(len(logs), 0)
        latest = logs[0]
        self.assertEqual(latest["vid"], "16C0")
        self.assertEqual(latest["pid"], "27DB")
        self.assertEqual(latest["action_taken"], "BLOCKED_BLACKLIST")
        print(f"  [PASS] Security event logged (ID: {log_id}) and retrieved.")


class TestShieldUsbProApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app_module.app.testing = True
        cls.client = flask_app_module.app.test_client()

    def test_04_health_endpoint(self):
        """Verify GET /health probe."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "WAL_ENABLED")
        print("  [PASS] Health probe /health returns 200 OK.")

    def test_05_api_logs_endpoint(self):
        """Verify GET /api/logs dynamic query."""
        res = self.client.get("/api/logs?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        print(f"  [PASS] /api/logs returned {len(data)} log entries.")

    def test_06_api_verify_endpoint(self):
        """Verify POST /api/verify policy enforcement."""
        # Case A: Blacklisted hardware
        res_a = self.client.post(
            "/api/verify",
            data=json.dumps({"vid": "16C0", "pid": "27DB"}),
            content_type="application/json"
        )
        self.assertEqual(res_a.status_code, 200)
        data_a = res_a.get_json()
        self.assertEqual(data_a["verdict"], "BLOCKED_BLACKLIST")
        self.assertEqual(data_a["action_taken"], "BLOCKED_BLACKLIST")
        self.assertEqual(data_a["risk_score"], 95)

        # Case B: Whitelisted hardware
        res_b = self.client.post(
            "/api/verify",
            data=json.dumps({"vid": "046D", "pid": "C52B"}),
            content_type="application/json"
        )
        self.assertEqual(res_b.status_code, 200)
        data_b = res_b.get_json()
        self.assertEqual(data_b["verdict"], "ALLOWED_WHITELIST")
        self.assertEqual(data_b["action_taken"], "ALLOWED_WHITELIST")
        self.assertEqual(data_b["risk_score"], 5)

        # Case C: Unknown device
        res_c = self.client.post(
            "/api/verify",
            data=json.dumps({"vid": "AAAA", "pid": "BBBB"}),
            content_type="application/json"
        )
        self.assertEqual(res_c.status_code, 200)
        data_c = res_c.get_json()
        self.assertEqual(data_c["verdict"], "QUARANTINED_UNKNOWN")

        # Case D: Malformed payload
        res_d = self.client.post(
            "/api/verify",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(res_d.status_code, 400)
        print("  [PASS] Policy enforcement endpoint /api/verify validated across all states.")


if __name__ == "__main__":
    print("\n=======================================================")
    print("  SHIELD.USB PRO — PREFLIGHT VERIFICATION SUITE")
    print("=======================================================\n")
    runner = unittest.TextTestRunner(verbosity=1)
    suite = unittest.TestLoader().loadTestsFromNames([
        "smoke_test.TestShieldUsbProStorage",
        "smoke_test.TestShieldUsbProApi"
    ])
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    print("\n>>> ALL PREFLIGHT CHECKS PASSED SUCCESSFULLY <<<\n")
