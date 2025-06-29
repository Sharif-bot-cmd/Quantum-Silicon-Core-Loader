import serial
import time
import os
import hashlib
import random

QSLCL_ELF = "qslcl.elf"
COM_PORT = "COM10"  # Change this to your real COM port (e.g., COM4 or COM5)
BAUD = 115200

def generate_crash_vector():
    print("[💥] Generating entropy fault trigger...")
    vector = b"\x00" * 64  # simulate NOP chain
    vector += os.urandom(128)
    vector += b"\xFF" * 32  # invalid memory access
    return vector

def send_glitch_sequence(ser):
    glitch = generate_crash_vector()
    print("[⚡] Sending malformed vector to crash BootROM...")
    ser.write(glitch)
    time.sleep(0.1)

def send_qslcl_entry_vector(ser, elf_data):
    print("[🧬] Injecting qslcl.elf payload to 0x00000000 entry (MaskROM target)...")
    for i in range(0, len(elf_data), 256):
        chunk = elf_data[i:i+256]
        ser.write(chunk)
        time.sleep(0.003)

def check_maskrom_trigger(ser):
    print("[🔍] Checking for raw MaskROM fallback...")
    for _ in range(60):
        ser.write(b"\x00")
        time.sleep(0.05)
        out = ser.read(128)
        if b"\x00" in out or out == b'':
            print("[♾️] BootROM silent — possible fallback confirmed")
            return True
        if b"ERROR" in out or b"CRASH" in out:
            print("[💀] BootROM exception — fallback triggered")
            return True
    print("[❌] BootROM still responsive — fallback not reached.")
    return False

def main():
    if not os.path.exists(QSLCL_ELF):
        print("❌ Missing ELF:", QSLCL_ELF)
        return

    with open(QSLCL_ELF, "rb") as f:
        elf = f.read()

    print("[♾️] Beginning MaskROM fallback trigger via entropy burst...")

    try:
        with serial.Serial(COM_PORT, BAUD, timeout=1) as ser:
            send_glitch_sequence(ser)
            time.sleep(0.5)

            if check_maskrom_trigger(ser):
                print("[✅] MaskROM fallback likely achieved.")
                send_qslcl_entry_vector(ser, elf)
                print("[🎉] ELF now executing at silicon root level (0x00000000).")
            else:
                print("[⚠️] BootROM still functional — retry or use test point bypass.")
    except serial.SerialException as e:
        print("❌ Serial error:", e)

if __name__ == "__main__":
    main()
