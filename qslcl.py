import serial
import time
import struct
import os

QSLCL_ELF_PATH = "qslcl.elf"   # Your sovereign .elf loader
COM_PORT = "COM10"      # Replace with your actual COM port (e.g., COM3 for Windows)
BAUDRATE = 921600              # High-speed for large binary transfer

# Optional handshake and boot constants
HANDSHAKE_MAGIC = b"QSLCL-HANDSHAKE\x00"
TRIGGER_BOOT_MAGIC = b"QSLCL-EXEC-0x00\x00"
QSLCL_MODE_TAG = b"QSLCL-ENTRY-MODE"  # Marker for QSLCL-only devices

def trigger_qslcl_mode(ser, elf_data):
    print(f"[🔌] Sending QSLCL mode handshake...")
    ser.write(HANDSHAKE_MAGIC)
    time.sleep(0.2)

    print("[📎] Sending QSLCL ELF payload length...")
    ser.write(struct.pack("<I", len(elf_data)))

    print(f"[📦] Transmitting {len(elf_data)} bytes of qslcl.elf...")
    ser.write(elf_data)

    print("[⏳] Waiting for memory load completion...")
    time.sleep(0.5)

    print("[🚀] Sending execution trigger to jump to 0x00000000...")
    ser.write(TRIGGER_BOOT_MAGIC)

    print("[✅] qslcl.elf should now be running at 0x0 — QSLCL mode entered successfully.")

def main():
    if not os.path.exists(QSLCL_ELF_PATH):
        print(f"❌ ELF not found: {QSLCL_ELF_PATH}")
        return

    with open(QSLCL_ELF_PATH, "rb") as f:
        elf_data = f.read()

    print(f"[🧠] Detected qslcl.elf: {len(elf_data)} bytes")

    try:
        print(f"[🔌] Opening COM port: {COM_PORT} at {BAUDRATE} baud...")
        with serial.Serial(COM_PORT, BAUDRATE, timeout=1) as ser:
            time.sleep(0.2)  # Give the serial buffer some time
            ser.write(QSLCL_MODE_TAG)
            time.sleep(0.1)

            trigger_qslcl_mode(ser, elf_data)

    except serial.SerialException as e:
        print(f"❌ Serial communication error: {e}")

if __name__ == "__main__":
    main()
