"""
Shield.USB Pro — CircuitPython Hardware Emulation Test Harness (code.py)
Platform: Raspberry Pi Pico (RP2040) / Hak5 Rubber Ducky / Teensy 3.x
Purpose: Controlled penetration testing & behavioral keystroke velocity validation.

Mode 1: Browser-Loop Resource Exhaustion Bomb
Mode 2: High-Velocity Keystroke Injection Bomb (60+ CPS Velocity Burst)
"""

import time
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS

# ==============================================================================
# CONFIGURATION & MODE SELECTION
# ==============================================================================
# 1 = Browser Resource Exhaustion Bomb
# 2 = Rapid Keystroke Messaging Loop (High-CPS Injection Test)
PAYLOAD_MODE = 2

# Configuration for Payload 1 (Browser Exhaustion)
TARGET_URL = "https://youtu.be/QDia3e12czc?autoplay=1"
NUM_TABS = 5
LOAD_DELAY = 10.0

# Configuration for Payload 2 (High-CPS Keystroke Stream)
BURST_ITERATIONS = 20
MESSAGE = "SHIELD_USB_PRO_TEST_INJECTION_ALERT_MALICIOUS_KEYSTROKE_CADENCE_CPS_TEST"
TYPING_DELAY = 0.005  # 5ms per key -> ~100-200 CPS to trigger behavioral containment
# ==============================================================================

# Hardware initialization grace period (allows bus enumeration)
time.sleep(2.0)

try:
    kbd = Keyboard(usb_hid.devices)
    layout = KeyboardLayoutUS(kbd)
except Exception as e:
    # If USB HID is quarantined or disconnected
    while True:
        time.sleep(1.0)


def execute_browser_exhaustion():
    """
    Payload 1: Spawns recursive browser processes via Windows Run dialog to exhaust
    system memory, CPU cycles, and network sockets.
    """
    # 1. Open Windows Run Dialog (GUI + R)
    kbd.send(Keycode.GUI, Keycode.R)
    time.sleep(0.5)

    # 2. Inject command to spawn parallel browser processes
    cmd = f'cmd.exe /c "for /l %x in (1,1,{NUM_TABS}) do start {TARGET_URL}"\n'
    layout.write(cmd)

    # 3. Wait for browser threads to spawn
    time.sleep(LOAD_DELAY)

    # 4. Multi-tab interaction loop
    for _ in range(NUM_TABS):
        kbd.send(Keycode.K)  # Trigger video playback
        time.sleep(0.3)
        kbd.send(Keycode.CONTROL, Keycode.TAB)  # Switch tab
        time.sleep(1.0)


def execute_high_cps_keystroke_bomb():
    """
    Payload 2: High-velocity synthetic keystroke injection.
    Opens Notepad and injects high-cadence streams with minimal variance (<3ms)
    and high CPS (>60 CPS), triggering Shield.USB Pro's behavioral CPS engine.
    """
    # 1. Open Windows Run Dialog
    kbd.send(Keycode.GUI, Keycode.R)
    time.sleep(0.4)

    # 2. Launch notepad
    layout.write("notepad.exe\n")
    time.sleep(0.8)

    # 3. High-velocity burst typing loop
    for i in range(BURST_ITERATIONS):
        text_line = f"[{i:02d}] {MESSAGE}\n"
        for char in text_line:
            layout.write(char)
            time.sleep(TYPING_DELAY)


# Main Execution
if PAYLOAD_MODE == 1:
    execute_browser_exhaustion()
elif PAYLOAD_MODE == 2:
    execute_high_cps_keystroke_bomb()
