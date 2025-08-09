import serial
import time
import os
import sys

# === Configuration ===
PORT = "/dev/ttyUSB0"  # Replace with your actual COM port (e.g., "COM3" on Windows)
BAUDRATE = 115200
TRIGGER_SEQUENCE = b'\xA0'  # Custom REM trigger byte/sequence
ELF_PATH = "qslcl.elf"       # Your ELF payload
CHUNK_SIZE = 512             # Bytes per write chunk
TRIGGER_DELAY = 0.5          # Delay after trigger
CHUNK_DELAY = 0.01           # Delay between chunks

def main():
    # === Check ELF file existence ===
    if not os.path.isfile(ELF_PATH):
        print(f"[ERROR] ELF file not found: {ELF_PATH}")
        sys.exit(1)

    # === Load ELF payload ===
    with open(ELF_PATH, "rb") as f:
        elf_data = f.read()

    print(f"[✓] Loaded ELF payload ({len(elf_data)} bytes)")

    # === Open serial port ===
    try:
        ser = serial.Serial(PORT, BAUDRATE, timeout=2)
        time.sleep(0.3)
    except serial.SerialException as e:
        print(f"[ERROR] Could not open serial port {PORT}: {e}")
        sys.exit(1)

    print(f"[✓] Connected to {PORT} at {BAUDRATE} baud")

    # === Trigger REM mode ===
    print("[*] Triggering REM mode...")
    ser.write(TRIGGER_SEQUENCE)
    time.sleep(TRIGGER_DELAY)

    # === Check for response ===
    response = ser.read(2)
    if response:
        print(f"[✓] Device responded to REM trigger: {response.hex()}")
    else:
        print("[!] No response to REM trigger. Proceeding anyway...")

    # === Send ELF payload in chunks ===
    print("[*] Uploading qslcl.elf via serial...")

    for offset in range(0, len(elf_data), CHUNK_SIZE):
        chunk = elf_data[offset:offset + CHUNK_SIZE]
        ser.write(chunk)
        time.sleep(CHUNK_DELAY)

    print("[✓] Payload upload complete.")

    # === Optional: Confirm final response ===
    ser.write(b'\x7E')  # Optional EOF or finalize byte
    final_response = ser.read(4)
    if final_response:
        print(f"[✓] Final device response: {final_response.hex()}")
    else:
        print("[*] No final response. Payload likely running.")

    ser.close()
    print("[✓] Serial port closed. REM mode triggered, ELF uploaded successfully.")

if __name__ == "__main__":
    main()
