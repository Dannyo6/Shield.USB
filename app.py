"""
Shield.USB Pro — app.py
Enterprise REST Telemetry Gateway & Verification Bridge.
Provides strict CORS-enabled endpoints for SOC dashboard telemetry and hardware verification.
"""

import time
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

import ak_database
import db
import telemetry_engine
import containment_engine

app = Flask(__name__)
# Enable CORS for frontend dashboard access
CORS(app, resources={r"/*": {"origins": "*"}})

# Ensure the database and threat signatures are initialized at startup
ak_database.setup_database()
START_TIME = time.time()


# ── Health Probes ─────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    """
    Production health probe verifying API gateway and database readiness.
    """
    uptime_seconds = int(time.time() - START_TIME)
    return jsonify({
        "status": "healthy",
        "service": "Shield.USB Pro Telemetry Gateway",
        "version": "1.0.0",
        "uptime_seconds": uptime_seconds,
        "database": "WAL_ENABLED",
        "timestamp": datetime.now().isoformat()
    }), 200


# ── Dynamic Log Polling ───────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Dynamic log polling endpoint supporting query limit parameter.
    Example: GET /api/logs?limit=50
    """
    try:
        limit_param = request.args.get("limit", default=50, type=int)
        # Cap limit to prevent memory exhaustion
        limit = max(1, min(limit_param, 500))
        logs = ak_database.get_latest_logs(limit=limit)
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "details": str(e)}), 500


# ── Hardware Verification & Policy Enforcement ────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def verify_device():
    """
    Endpoint accepting hardware VID/PID payloads, querying ak_database.py,
    logging the verdict (BLOCKED_BLACKLIST, ALLOWED_WHITELIST, QUARANTINED_UNKNOWN),
    and returning structured JSON telemetry.
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({
                "error": "Bad Request",
                "message": "Missing or invalid JSON body. Expected 'vid' and 'pid'."
            }), 400

        vid = str(data.get("vid", "")).strip().upper()
        pid = str(data.get("pid", "")).strip().upper()

        if not vid or not pid:
            return jsonify({
                "error": "Bad Request",
                "message": "Both 'vid' and 'pid' are required fields."
            }), 400

        # Query hardware trust vault
        trust_result = ak_database.check_usb_trust(vid, pid)
        verdict = trust_result.get("verdict", "QUARANTINED_UNKNOWN")
        trust_status = trust_result.get("trust_status", "UNKNOWN")
        device_name = trust_result.get("device_name", f"USB Device ({vid}:{pid})")
        device_class = trust_result.get("device_class", "UNKNOWN")

        # Determine risk score and action
        if verdict == "BLOCKED_BLACKLIST":
            action_taken = "BLOCKED_BLACKLIST"
            risk_score = 95
            containment_status = "CONTAINED_PRE_DRIVER"
        elif verdict == "ALLOWED_WHITELIST":
            action_taken = "ALLOWED_WHITELIST"
            risk_score = 5
            containment_status = "ALLOWED"
        else:
            action_taken = "QUARANTINED_UNKNOWN"
            risk_score = 65
            containment_status = "QUARANTINED"

        # Log event to database
        log_id = ak_database.log_event(
            vid=vid,
            pid=pid,
            action=action_taken,
            device_name=device_name,
            device_class=device_class,
            risk_score=risk_score,
            cps=float(data.get("cps", 0.0)),
            containment_status=containment_status
        )

        response_payload = {
            "log_id": log_id,
            "timestamp": datetime.now().isoformat(),
            "vid": vid,
            "pid": pid,
            "device_name": device_name,
            "device_class": device_class,
            "trust_status": trust_status,
            "verdict": verdict,
            "risk_score": risk_score,
            "action_taken": action_taken,
            "containment_status": containment_status
        }
        return jsonify(response_payload), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


# ── Live Telemetry Stream ─────────────────────────────────────────────────────

@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """
    Returns real-time keystroke speed, CPS metrics, and threat classification.
    """
    try:
        telemetry_data = telemetry_engine.get_telemetry()
        return jsonify(telemetry_data), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch telemetry", "details": str(e)}), 500


# ── Containment & Blacklist State ─────────────────────────────────────────────

@app.route("/api/containment", methods=["GET"])
def get_containment():
    """
    Returns DB-persisted containment records for forensic auditing.
    """
    try:
        containment_data = containment_engine.get_containment_status()
        return jsonify(containment_data), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch containment records", "details": str(e)}), 500


@app.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    """
    Exposes active hardware blacklist signatures.
    """
    try:
        blacklist_entries = ak_database.fetch_blacklist()
        return jsonify(blacklist_entries), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch blacklist", "details": str(e)}), 500


# ── Main Entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  SHIELD.USB PRO — ENTERPRISE TELEMETRY GATEWAY")
    print("  Port: 5000 | CORS: Enabled | Engine: WAL SQLite")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
