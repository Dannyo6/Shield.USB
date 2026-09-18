<div align="center">

# 🛡️ Shield.USB

### **Zero-Trust USB Hardware Intercept & Behavioral Keystroke Velocity Telemetry System**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![SQLite WAL](https://img.shields.io/badge/Storage-SQLite_WAL-003B57.svg?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![RNSIT CSE Silver Jubilee](https://img.shields.io/badge/RNSIT%20CSE-Silver%20Jubilee-8A2BE2.svg)](#context--acknowledgments)

**Shield.USB ** is an enterprise-grade, interdisciplinary cybersecurity platform engineered to neutralize malicious USB Human Interface Devices (HID / BadUSB) such as Raspberry Pi Pico (RP2040), Teensy, and Hak5 Rubber Ducky before malicious keystroke sequences can execute.

</div>

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [System Architecture](#-system-architecture)
- [Core Protection Tenets](#-core-protection-tenets)
- [Prior Art & Comparative Matrix](#-prior-art--comparative-matrix)
- [Repository Structure](#-repository-structure)
- [Quickstart & Multi-Terminal Setup](#-quickstart--multi-terminal-setup)
- [Hardware Attack Emulation (CircuitPython)](#-hardware-attack-emulation-circuitpython)
- [Verification & Automated Smoke Testing](#-verification--automated-smoke-testing)
- [REST API Reference](#-rest-api-reference)
- [Context & Acknowledgments](#-context--acknowledgments)
- [License](#-license)

---

## 🔭 Executive Overview

Traditional endpoint operating systems inherently trust Human Interface Devices (HID) under the **Plug-and-Play (PnP)** paradigm. When a device presents itself as a standard keyboard or mouse, the host OS immediately binds generic input class drivers (`kbdhid.sys` / `hidclass.sys`) without authentication. 

Threat actors exploit this trust by weaponizing low-cost microcontrollers (BadUSB) to inject high-speed keystroke payloads that spawn elevated shells, exfiltrate credentials, or trigger denial-of-service loops within sub-second timeframes.

**Shield.USB Pro** fundamentally rejects implicit device trust by enforcing a **Zero-Trust Hardware Access Control Architecture**:
1. **Hardware Intercept at the Bus**: Detects device insertion events via low-level WMI and Device Management hooks prior to standard driver stabilization.
2. **Encrypted Vault Descriptors**: Cross-examines Vendor ID (VID) and Product ID (PID) against a thread-safe, high-concurrency SQLite WAL storage engine.
3. **Behavioral Keystroke Velocity Analysis**: Continuously calculates real-time **Characters Per Second (CPS)** and inter-keystroke timing variance. If typing velocity exceeds biological human capabilities ($CPS > 20-40$) or exhibits sub-millisecond bot cadence ($\sigma < 0.003s$), instant parent-device containment severs the device.
4. **Live SOC Dashboard**: Streams real-time telemetry, threat alerts, and device audit logs to a dark-mode React Security Operations Center dashboard.

---

## 🏛️ System Architecture

```
                                  ┌────────────────────────┐
                                  │   Physical USB Port    │
                                  └───────────┬────────────┘
                                              │
                                   [Device Insertion Event]
                                              │
                                              ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                              SHIELD.USB PRO HARDWARE SENTRY                            │
 ├────────────────────────────────────────────────────────────────────────────────────────┤
 │  1. Registry & WMI Interrogation: Intercepts raw PnP notification                      │
 │  2. Descriptor Extraction: Parses VID, PID, and Composite Parent Instance ID          │
 │  3. Hardware Vault Lookup: Cross-references KnownDevices & Blacklist signatures        │
 └─────────────┬──────────────────────────────────────────────────────────┬───────────────┘
               │                                                          │
      [Known Blacklist VID:PID]                                   [Whitelisted / Unknown]
               │                                                          │
               ▼                                                          ▼
 ┌───────────────────────────┐                             ┌──────────────────────────────┐
 │   INSTANT CONTAINMENT     │                             │    PRE-EMPTIVE QUARANTINE    │
 │ - Execute PnP driver cut  │                             │ - Spawn HID Watcher Thread   │
 │ - Log blacklist hit to DB │                             │ - Stream Keystroke Telemetry │
 └───────────────────────────┘                             └──────────────┬───────────────┘
                                                                          │
                                                      ┌───────────────────┴───────────────┐
                                                      ▼                                   ▼
                                           [CPS < 20 & Human Cadence]            [CPS > 20 or Var < 3ms]
                                                      │                                   │
                                                      ▼                                   ▼
                                           ┌──────────────────────┐            ┌──────────────────────┐
                                           │  ALLOW ACCESS (SAFE) │            │  CONTAINMENT ENGINE  │
                                           │ - Log normal session │            │ - PnP Driver Sever   │
                                           │ - Retain monitoring  │            │ - Permanent Blacklist│
                                           └──────────────────────┘            └──────────┬───────────┘
                                                                                          │
                                                                                          ▼
                                                      ┌───────────────────────────────────────────────────┐
                                                      │           REST TELEMETRY GATEWAY (Flask API)      │
                                                      │           - CORS-enabled /api/logs & /api/verify  │
                                                      └───────────────────────────┬───────────────────────┘
                                                                                  │
                                                                                  ▼
                                                      ┌───────────────────────────────────────────────────┐
                                                      │              REACT SOC TELEMETRY DASHBOARD        │
                                                      │           - Live CPS Gauge & Traffic Intercept    │
                                                      │           - Dynamic Master Audit Trail Table      │
                                                      └───────────────────────────────────────────────────┘
```

---

## ⚡ Core Protection Tenets

| Protection Layer | Technology Stack | Action Trigger | Latency |
| :--- | :--- | :--- | :--- |
| **Pre-Driver Quarantine** | Windows SetupAPI / WMI | USB Device Insertion | $< 50\text{ ms}$ |
| **Hardware Signature Vault** | SQLite3 (`WAL` mode) | VID/PID Threat Signature Hit | $< 5\text{ ms}$ |
| **Behavioral Velocity Engine** | Python Sliding-Window Math | Keystrokes $> 20-40\text{ CPS}$ or $\sigma < 0.003\text{s}$ | $< 250\text{ ms}$ |
| **Parent-Device Severance** | `pnputil.exe` / Windows API | Anomaly Confirmation | $< 300\text{ ms}$ |
| **Forensic SOC Streaming** | Flask REST + React 18 | Continuous Event Polling | $3\text{ s}$ Interval |

---

## 📊 Prior Art & Comparative Matrix

| Feature / Metric | Standard Windows Defender | Linux USBGuard | CrowdStrike Falcon USB Device Control | **Shield.USB Pro** |
| :--- | :---: | :---: | :---: | :---: |
| **VID/PID Descriptor Blacklisting** | ❌ No | ⚠️ Static Rulebook | ✅ Centralized Policy | ✅ **Instant Hardware Vault** |
| **Behavioral CPS Velocity Detection**| ❌ No | ❌ No | ❌ No (Signature Only) | ✅ **Live Sliding Window CPS** |
| **Composite Device Root Containment**| ❌ No | ⚠️ Partial | ⚠️ OS Dependent | ✅ **Parent-Device Severance** |
| **Air-Gapped / Local Operation** | ⚠️ Partial | ✅ Yes | ❌ Requires Cloud Agent | ✅ **100% Local Thread-Safe Vault** |
| **Live Keystroke Forensic Ticker** | ❌ No | ❌ No | ❌ No | ✅ **Live React SOC Dashboard** |
| **Protection Against Spoofed VIDs** | ❌ None | ❌ Bypassed | ❌ Bypassed | ✅ **Neutralized by CPS Velocity** |

---

## 📁 Repository Structure

```
Shield.USB-Pro/
├── ak_database.py           # Thread-safe SQLite WAL Storage Engine & Hardware Vault
├── app.py                   # Production Flask REST API Telemetry Gateway
├── usb_monitor.py           # Hardware Bus Sentry & Insertion Monitor (supports --simulate)
├── security_engine.py       # Policy Decision Tree, Anomaly Scoring & Evaluation
├── telemetry_engine.py      # Keystroke Velocity (CPS) Sliding Window Analyzer
├── containment_engine.py    # Parent Composite Device Containment & PnP Driver Severance
├── db.py                    # Unified database bridge module
├── smoke_test.py            # Automated Preflight Verification Suite
├── requirements.txt         # Backend Python dependencies
├── App.jsx                  # React SOC Telemetry Dashboard Component
├── index.css                # Tailwind CSS styling, glowing badges & animations
├── index.html               # Frontend HTML5 entry point
├── main.jsx                 # Vite React application bootstrap
├── package.json             # Frontend dependencies & build configuration
├── vite.config.js           # Vite dev server & production bundling configuration
├── tailwind.config.js       # Tailwind CSS theme extension
├── postcss.config.js        # PostCSS configuration
└── payloads/
    ├── code.py              # CircuitPython Dual-Mode Penetration Harness (Pico / Ducky)
    └── README.md            # Hardware flashing & attack execution guide
```

---

## 🚀 Quickstart & Multi-Terminal Setup

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.14 x64)
- **Node.js 18+** & **npm**
- **Windows 10/11** with Administrator privileges (for PnP containment execution)

### 2. Backend Installation
```bash
# Clone the repository
git clone https://github.com/Dannyo6/Shield.USB-Pro.git
cd Shield.USB-Pro

# Install Python requirements
pip install -r requirements.txt
```

### 3. Frontend Installation
```bash
# Install React dependencies
npm install
```

### 4. Multi-Terminal Execution

#### **Terminal 1: Start REST Telemetry Gateway (Port 5000)**
```bash
python app.py
```
*Output: Telemetry bridge online at `http://localhost:5000` with PRAGMA WAL enabled.*

#### **Terminal 2: Launch Hardware Bus Sentry (Admin Terminal)**
```bash
# Run in live hardware listener mode
python usb_monitor.py

# OR run in automated simulation mode (no physical USB required)
python usb_monitor.py --simulate --vid 16C0 --pid 27DB --name "Hak5 Rubber Ducky Test"
```

#### **Terminal 3: Start React SOC Dashboard (Port 5173)**
```bash
npm run dev
```
*Open your browser and navigate to `http://localhost:5173` to access the live SOC dashboard.*

---

## 🧪 Hardware Attack Emulation (CircuitPython)

The `payloads/code.py` script turns any **Raspberry Pi Pico ($4)** or **Hak5 Rubber Ducky** into a controlled penetration test device:
- **Mode 1 (Resource Exhaustion Bomb)**: Injects parallel `cmd.exe` browser spawns.
- **Mode 2 (High-CPS Injection Bomb)**: Pumps high-velocity text streams ($>60\text{ CPS}$) with sub-3ms keypress variance.

To test:
1. Flash CircuitPython to your RP2040 board.
2. Copy `payloads/code.py` into the root of `CIRCUITPY/`.
3. Plug the device in; watch **Shield.USB Pro** detect the signature or kill the interface before malicious execution finishes.

---

## 🔬 Verification & Automated Smoke Testing

Shield.USB Pro includes a rigorous unit and integration testing suite. Run preflight verification at any time:

```bash
python smoke_test.py
```

**Test Suite Coverage**:
- `test_01_wal_mode_and_tables`: Confirms WAL journal mode and table schema (`KnownDevices`, `ConnectionLogs`, `Blacklist`, `ContainmentLogs`).
- `test_02_pre_populated_signatures`: Validates detection of Rubber Ducky (`16C0:27DB`), Logitech Whitelist (`046D:C52B`), SanDisk (`0781:5581`), and unknown devices.
- `test_03_event_logging_and_retrieval`: Validates thread-safe connection logging and retrieval.
- `test_04_health_endpoint`: Asserts `GET /health` probe status.
- `test_05_api_logs_endpoint`: Asserts `GET /api/logs` query limits and output schema.
- `test_06_api_verify_endpoint`: Asserts `POST /api/verify` policy enforcement across all device classes.

---

## 🔌 REST API Reference

### 1. Health Probe
```http
GET /health
```
**Response (200 OK):**
```json
{
  "database": "WAL_ENABLED",
  "service": "Shield.USB Pro Telemetry Gateway",
  "status": "healthy",
  "uptime_seconds": 128,
  "version": "1.0.0"
}
```

### 2. Real-Time Telemetry Logs
```http
GET /api/logs?limit=50
```
**Response (200 OK):**
```json
[
  {
    "id": 1,
    "timestamp": "2026-09-18T18:28:00.123456",
    "vid": "16C0",
    "pid": "27DB",
    "device_name": "Hak5 Rubber Ducky / Teensy HID",
    "device_class": "HID_KEYBOARD",
    "trust_status": "BLACKLIST",
    "risk_score": 95,
    "action_taken": "BLOCKED_BLACKLIST",
    "cps": 75.4,
    "containment_status": "CONTAINED_PRE_DRIVER"
  }
]
```

### 3. Device Trust Verification
```http
POST /api/verify
Content-Type: application/json

{
  "vid": "16C0",
  "pid": "27DB",
  "cps": 0.0
}
```
**Response (200 OK):**
```json
{
  "action_taken": "BLOCKED_BLACKLIST",
  "containment_status": "CONTAINED_PRE_DRIVER",
  "device_class": "HID_RISK",
  "device_name": "Hak5 Rubber Ducky / Teensy HID",
  "log_id": 2,
  "pid": "27DB",
  "risk_score": 95,
  "timestamp": "2026-09-18T18:28:05.987654",
  "trust_status": "BLACKLIST",
  "verdict": "BLOCKED_BLACKLIST",
  "vid": "16C0"
}
```

---

## 🎓 Context & Academic Metadata

This research and engineering implementation was developed under the following academic initiative:

- **Academic Institution**:  
  Department of Computer Science & Engineering  
  **RNS Institute of Technology (RNSIT)**, Bengaluru, Karnataka, India.
- **Milestone & Initiative**:  
  **Silver Jubilee Year Interdisciplinary Research & Engineering Showcase**
- **Project Title**:  
  *Shield.USB Pro: Zero-Trust USB Hardware Intercept & Behavioral Keystroke Velocity Telemetry System*
- **Role & Authorship**:  
  System Architect & Lead Developer: **Dhanush V** ([@Dannyo6](https://github.com/Dannyo6)).
- **Faculty Guide & Institutional Mentorship**:  
  Faculty Mentors, Laboratory Coordinators & Project Review Committee, Department of Computer Science & Engineering, RNSIT Bengaluru.

Special thanks to the Department of CSE and the Centre for Cybersecurity Studies at RNSIT for providing the embedded systems instrumentation, microcontroller hardware harnesses, and laboratory facilities.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for details.
