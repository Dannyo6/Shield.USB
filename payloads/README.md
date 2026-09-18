# Shield.USB Pro — Hardware Attack Emulation Payloads

This directory contains test harnesses and penetration payloads designed to simulate BadUSB/HID hardware injection attacks against **Shield.USB Pro**.

---

## Supported Microcontrollers
- **Raspberry Pi Pico (RP2040)** (`VID: 2E8A`, `PID: 0005` or `000B`)
- **Hak5 Rubber Ducky / Teensy 3.x** (`VID: 16C0`, `PID: 27DB`)
- **Arduino Leonardo / Pro Micro (ATmega32U4)** (`VID: 2341`, `PID: 8036`)

---

## Flashing Instructions (CircuitPython)

1. **Install CircuitPython**:
   - Download the latest CircuitPython `.uf2` image for your board from [circuitpython.org](https://circuitpython.org).
   - Hold the `BOOTSEL` button on your Raspberry Pi Pico, plug it into your computer, and drag-and-drop the `.uf2` file into the mounted `RPI-RP2` drive.
2. **Install Adafruit HID Library**:
   - Download the Adafruit CircuitPython Bundle.
   - Copy the `adafruit_hid` folder into the `CIRCUITPY/lib/` directory on your board.
3. **Deploy Payload**:
   - Copy `payloads/code.py` to the root of the `CIRCUITPY` drive as `code.py`.
   - The microcontroller will automatically reboot and execute the payload.

---

## Payload Profiles

### 1. Payload 1: Browser-Loop Resource Exhaustion Bomb
- **Mechanism**:
  - Injects `GUI + R` (Windows Run Dialog).
  - Executes a shell loop spawning parallel, memory-intensive web browser instances.
  - Switches active tabs and forces media execution loops.
- **Defense Mitigation**:
  - **Pre-Driver Quarantine**: Shield.USB Pro detects the non-whitelisted VID/PID before system driver initialization and blocks or isolates the composite USB peripheral.

### 2. Payload 2: Rapid Keystroke Messaging Loop (CPS Injection Bomb)
- **Mechanism**:
  - Injects keystrokes with ultra-low delay (`< 5ms` per character), achieving speeds of `60 to 180+ CPS` (Characters Per Second) with standard deviation approaching `0.001s`.
- **Defense Mitigation**:
  - **Behavioral Velocity Engine**: The sliding window CPS detector flags speeds exceeding human biological limits (`> 20-40 CPS`) and sub-millisecond cadence consistency (`variance < 0.003s`), triggering immediate PnP driver severance within `0.25 seconds`.
