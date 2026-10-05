<div align="center">
  <h1>🛡️ Shield.USB</h1>
  <p><b>Hardware-Level BadUSB Containment & Telemetry Engine</b></p>
  <p>
    <img src="https://img.shields.io/badge/Backend-Python%20Flask-3776AB?style=for-the-badge&logo=python" alt="Python" />
    <img src="https://img.shields.io/badge/Hardware-PyUSB-FF4154?style=for-the-badge" alt="Hardware" />
    <img src="https://img.shields.io/badge/Frontend-React.js-61DAFB?style=for-the-badge&logo=react" alt="React" />
    <img src="https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC?style=for-the-badge&logo=tailwind-css" alt="Tailwind" />
  </p>
</div>

<br/>

> **Shield.USB** is a low-level hardware security monitor designed to intercept, analyze, and contain malicious USB peripherals (such as BadUSB or Rubber Ducky devices) before they can execute keystroke injection attacks against the host operating system.

---

## 🏗 System Architecture

The platform operates across a strict hardware-to-UI bridge, separating low-level device polling from the user-facing telemetry dashboard.

| Layer | Component | Responsibility |
| :--- | :--- | :--- |
| **Hardware** | `usb_monitor.py` | Polls the OS for hardware interrupts and newly enumerated USB devices. |
| **Security** | `containment_engine.py` | Analyzes device behavior/payloads against known BadUSB signatures. |
| **Backend** | `Flask API` | Exposes a lightweight local server to stream telemetry and threat logs. |
| **Frontend** | `React + Vite` | Renders a real-time command center for threat visualization and device management. |

---

## 🚀 Core Features

* 🔌 **Real-Time Enumeration:** Instantly detects and logs USB device connections at the hardware level.
* 🛑 **Payload Containment:** Identifies anomalous HID (Human Interface Device) behavior typical of automated keystroke injection attacks.
* 📊 **Live Telemetry:** Streams hardware events directly to a React-based dashboard for immediate threat assessment.
* 🧪 **Safe Testing Environment:** Includes simulated BadUSB payloads (e.g., `code.py`, `bad_usb_rickrollbomb.txt`) to safely validate containment logic.

---

## ⚙️ Local Deployment & Execution

Because Shield.USB interacts directly with hardware APIs, the backend **must be run with elevated privileges** (Administrator / `sudo`).

### 1. Boot the Security Backend
```bash
# Clone the repository
git clone https://github.com/Dannyo6/Shield.USB.git
cd Shield.USB

# Navigate to backend and install dependencies
cd backend
pip install -r requirements.txt

# Start the Flask API with elevated privileges (Required for USB interception)
sudo python app.py
```

### 2. Boot the Frontend Command Center
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start the Vite development server
npm run dev
```

