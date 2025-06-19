import serial
import time
import os
import random

def entropy_glitch(length=64):
    """Simulate entropy burst to cause sync failure."""
    return os.urandom(length)

def null_payloads(port):
    """Send garbage or 0x00 blocks as invalid preboot commands."""
    for _ in range(4):
        garbage = b"\x00" * random.randint(16, 48)
        port.write(garbage)
        print(f"[TX] Sent null block: {len(garbage)} bytes")
        time.sleep(0.1)

def bootrom_trigger_packets(port):
    """Send malformed or masked BootROM handshake signatures."""
    triggers = [
        b"\xA5\x5A\xA5\x5A",  # Preloader-style panic
        b"MTK_BROM?",         # Simulate signature scan fail
        b"QCOM_FAIL\0",       # Invalid vendor packet
        entropy_glitch(48),   # Entropy spike
        b"\xFF" * 64          # Fuse jitter
    ]
    for t in triggers:
        port.write(t)
        print(f"[TX] Sent trigger: {t[:8].hex()}...")
        time.sleep(0.15)

def crash_qslcl_elf(port_name="COM10", baudrate=115200):
    """Crash the ELF into fallback loader mode via entropy + panic triggers."""
    try:
        print(f"[🧠] Connecting to {port_name} at {baudrate}...")
        port = serial.Serial(port=port_name, baudrate=baudrate, timeout=0.5)
        time.sleep(1)

        print("[⚠️] Sending null/garbage commands...")
        null_payloads(port)

        print("[💥] Sending entropy glitch burst...")
        port.write(entropy_glitch(128))
        time.sleep(0.3)

        print("[⛓️] Injecting BootROM-style fallback signatures...")
        bootrom_trigger_packets(port)

        print("[⌛] Waiting for fallback response or freeze...")
        time.sleep(1)

        response = port.read(256)
        if response:
            print(f"[RX] Received from device:\n{response}")
        else:
            print("[✅] No response — likely crashed or dropped into fallback logic.")

        port.close()
    except Exception as e:
        print(f"[❌] Serial error: {e}")

if __name__ == "__main__":
    # 📝 Replace "COM5" with your actual COM port (e.g., "COM3", "COM6", etc.)
    crash_qslcl_elf("COM10")
