"""
Shield.USB Pro — smoke_test.py
Automated Preflight Verification Suite.
Asserts SQLite WAL mode, table creation, threat intelligence seed existence,
hardware signature interrogation, audit event logging, and Flask REST API endpoints.
"""

import sys
import os
import unittest
import json
import sqlite3

# Ensure local repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import ak_database
import db
import db_manager
import app as flask_app_module


class TestShieldUsbProStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ak_database.setup_database()

    def test_01_wal_mode_and_tables(self):
        """Verify SQLite tables and PRAGMA journal_mode=WAL."""
        conn = ak_database.get_connection()
        try:
            wal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            self.assertEqual(wal_mode.upper(), "WAL", f"Expected WAL mode, got {wal_mode}")

            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()]
            expected = ["KnownDevices", "ConnectionLogs", "Blacklist", "ContainmentLogs"]
            for tbl in expected:
                self.assertIn(tbl, tables, f"Missing required table: {tbl}")
            print("  [PASS] WAL mode enabled and all 4 tables verified.")
        finally:
            conn.close()

    def test_02_seed_data_existence(self):
        """Verify presence of curated blacklist and whitelist threat signatures."""
        conn = ak_database.get_connection()
        try:
            # Verify Hak5 Rubber Ducky / Pico
            ducky = conn.execute(
                "SELECT trust_status, device_class FROM KnownDevices WHERE vid='16C0' AND pid='27DB'"
            ).fetchone()
            self.assertIsNotNone(ducky, "Missing Hak5 Rubber Ducky seed signature")
            self.assertEqual(ducky["trust_status"].upper(), "BLACKLIST")

            # Verify O.MG Cable
            omg = conn.execute(
                "SELECT trust_status FROM KnownDevices WHERE vid='1209' AND pid='0001'"
            ).fetchone()
            self.assertIsNotNone(omg, "Missing O.MG Cable seed signature")
            self.assertEqual(omg["trust_status"].upper(), "BLACKLIST")

            # Verify Hak5 Bash Bunny
            bunny = conn.execute(
                "SELECT trust_status FROM KnownDevices WHERE vid='1D50' AND pid='60F1'"
            ).fetchone()
            self.assertIsNotNone(bunny, "Missing Hak5 Bash Bunny seed signature")
            self.assertEqual(bunny["trust_status"].upper(), "BLACKLIST")

            # Verify Whitelist: Logitech Unifying Receiver
            logi = conn.execute(
                "SELECT trust_status FROM KnownDevices WHERE vid='046D' AND pid='C52B'"
            ).fetchone()
            self.assertIsNotNone(logi, "Missing Logitech Unifying Receiver seed signature")
            self.assertEqual(logi["trust_status"].upper(), "WHITELIST")

            # Verify Whitelist: SanDisk Ultra Flash Drive
            sandisk = conn.execute(
                "SELECT trust_status FROM KnownDevices WHERE vid='0781' AND pid='5581'"
            ).fetchone()
            self.assertIsNotNone(sandisk, "Missing SanDisk Flash Drive seed signature")
            self.assertEqual(sandisk["trust_status"].upper(), "WHITELIST")

            # Verify Whitelist: Kingston DataTraveler
            kingston = conn.execute(
                "SELECT trust_status FROM KnownDevices WHERE vid='0951' AND pid='1666'"
            ).fetchone()
            self.assertIsNotNone(kingston, "Missing Kingston Flash Drive seed signature")
            self.assertEqual(kingston["trust_status"].upper(), "WHITELIST")

            print("  [PASS] Curated threat intelligence seed signatures confirmed in vault.")
        finally:
            conn.close()

    def test_03_hardware_interrogation(self):
        """Assert exact hardware trust evaluations for Blacklist, Whitelist, and Unknown."""
        # 1. Blacklist interrogation
        ducky_trust = ak_database.check_usb_trust("16C0", "27DB")
        self.assertEqual(ducky_trust, "BLACKLIST")
        self.assertEqual(ducky_trust["trust_status"], "BLACKLIST")
        self.assertEqual(ducky_trust["verdict"], "BLOCKED_BLACKLIST")

        # 2. Whitelist interrogation
        logi_trust = ak_database.check_usb_trust("046D", "C52B")
        self.assertEqual(logi_trust, "WHITELIST")
        self.assertEqual(logi_trust["trust_status"], "WHITELIST")
        self.assertEqual(logi_trust["verdict"], "ALLOWED_WHITELIST")

        # 3. Unknown device interrogation
        unknown_trust = ak_database.check_usb_trust("FFFF", "0000")
        self.assertEqual(unknown_trust, "UNKNOWN")
        self.assertEqual(unknown_trust["trust_status"], "UNKNOWN")
        self.assertEqual(unknown_trust["verdict"], "QUARANTINED_UNKNOWN")

        print("  [PASS] Hardware signature interrogation asserted (16C0:27DB, 046D:C52B, FFFF:0000).")

    def test_04_event_logging_and_retrieval(self):
        """Verify event logging and structured audit log retrieval."""
        log_id = ak_database.log_event(
            vid="16C0",
            pid="27DB",
            action="BLOCKED_BLACKLIST",
            device_name="Hak5 Rubber Ducky / RPi Pico",
            device_class="HIDClass",
            risk_score=95,
            cps=1260.0,
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
        self.assertIn("T", latest["timestamp"])  # Valid ISO-8601 string
        print(f"  [PASS] Audit event logged (ID: {log_id}) and schema validated.")


class TestShieldUsbProApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app_module.app.testing = True
        cls.client = flask_app_module.app.test_client()

    def test_05_health_endpoint(self):
        """Verify GET /health probe returns 200 with status 'armed' and service 'shield-usb-vault'."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "armed")
        self.assertEqual(data.get("service"), "shield-usb-vault")
        self.assertEqual(data.get("database"), "WAL_ENABLED")
        print("  [PASS] Health probe /health returns 200 with armed vault status.")

    def test_06_api_logs_endpoint(self):
        """Verify GET /api/logs dynamic query."""
        res = self.client.get("/api/logs?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        print(f"  [PASS] /api/logs returned {len(data)} structured log entries.")

    def test_07_api_verify_endpoint(self):
        """Verify POST /api/verify policy enforcement."""
        # Case A: Blacklisted BadUSB
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

        # Case B: Whitelisted Hardware
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

        # Case C: Unknown Peripheral
        res_c = self.client.post(
            "/api/verify",
            data=json.dumps({"vid": "FFFF", "pid": "0000"}),
            content_type="application/json"
        )
        self.assertEqual(res_c.status_code, 200)
        data_c = res_c.get_json()
        self.assertEqual(data_c["verdict"], "QUARANTINED_UNKNOWN")

        # Case D: Malformed Payload
        res_d = self.client.post(
            "/api/verify",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(res_d.status_code, 400)
        print("  [PASS] /api/verify validated across Blacklist, Whitelist, Unknown, and Malformed states.")


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
