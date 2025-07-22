import os
import serial
import time
import struct
import hashlib

# === CONFIGURATION ===
QSLCL_ELF = "qslcl.elf"          # Must be compiled with real JTAG trigger logic
COM_PORT = "COM10"                # Adjust for your system
BAUDRATE = 115200
TIMEOUT = 5
CHUNK_SIZE = 512
EXEC_ADDRESS_DEFAULT = 0x00000000

# === ENTROPY SCANNER TO FIND JTAG CAPSULE ===
def find_jtag_trigger_region(buffer):
    print("[🔍] Scanning ELF for JTAG trigger logic region...")

    best_offset = None
    best_entropy = 0
    region_size = 0x400  # Assumed JTAG capsule size

    for offset in range(0, len(buffer) - region_size, 0x100):
        region = buffer[offset:offset + region_size]
        entropy = calculate_entropy(region)

        if entropy > 6.5:  # Threshold for highly obfuscated logic
            if entropy > best_entropy:
                best_entropy = entropy
                best_offset = offset

    if best_offset is not None:
        print(f"[📌] Found high-entropy region @ 0x{best_offset:X} (entropy={best_entropy:.2f})")
        return best_offset, region_size
    else:
        print("[❌] No valid JTAG trigger region found.")
        return None, None

# === RAW ENTROPY CALCULATOR ===
def calculate_entropy(data):
    if not data:
        return 0.0
    histogram = [0] * 256
    for b in data:
        histogram[b] += 1
    entropy = 0
    for count in histogram:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * (p.bit_length())
    return entropy * 8  # Convert from log base 2

# === SERIAL FUNCTIONS ===
def open_serial():
    try:
        s = serial.Serial(COM_PORT, baudrate=BAUDRATE, timeout=TIMEOUT)
        print(f"[🔌] Opened serial port: {COM_PORT}")
        return s
    except Exception as e:
        print(f"[❌] Serial open error: {e}")
        exit(1)

def send_capsule(serial_conn, data):
    print(f"[📤] Sending {len(data)} bytes of JTAG trigger capsule...")
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        serial_conn.write(chunk)
        serial_conn.flush()
        time.sleep(0.005)
    print("[✅] Capsule sent.")

def trigger_execution(serial_conn, address):
    print(f"[⚡] Triggering execution at 0x{address:08X}")
    jump = struct.pack("<I", address) + b"\x00\x00\x00\x00"
    serial_conn.write(jump)
    serial_conn.flush()

# === MAIN ===
def main():
    if not os.path.exists(QSLCL_ELF):
        print(f"[❌] ELF not found: {QSLCL_ELF}")
        return

    with open(QSLCL_ELF, "rb") as f:
        buffer = f.read()

    offset, size = find_jtag_trigger_region(buffer)
    if offset is None:
        return

    capsule = buffer[offset:offset + size]
    exec_address = EXEC_ADDRESS_DEFAULT + offset  # Adjust if needed

    ser = open_serial()
    time.sleep(0.5)
    send_capsule(ser, capsule)
    time.sleep(0.5)
    trigger_execution(ser, exec_address)
    ser.close()
    print("[🔒] Done. JTAG trigger sent and executed.")

if __name__ == "__main__":
    main()
