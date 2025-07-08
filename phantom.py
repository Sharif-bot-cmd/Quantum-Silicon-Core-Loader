import serial
import time
import struct
import hashlib
import os
import random

# === USER CONFIGURATION ===
COM_PORT   = "COM10"            # ⚠️ Change to your active COM port
BAUD_RATE  = 1500000            # High-speed for high entropy payloads
ELF_PATH   = "qslcl.elf"        # Path to qslcl.elf
PHANTOM_IV_VECTOR = 0x00000000  # Entry address for Phantom IV trigger (0x0)

# === PHANTOM IV SYNC SEQUENCE ===
def send_phantom_sync(ser):
    print("[👻] Sending Phantom IV entropy sync...")

    seed = os.urandom(64)
    mask = hashlib.sha3_512(seed).digest()[:32]
    phantom_token = hashlib.blake2s(b"PHANTOM_IV" + mask).digest()

    sync_packet = b"\xFA\x17" + seed + phantom_token + b"\xAF\xAF"
    ser.write(sync_packet)
    time.sleep(0.3)

    print("[✓] Phantom IV sync packet sent.")

# === LOAD qslcl.elf ===
def load_qslcl_elf():
    with open(ELF_PATH, "rb") as f:
        elf_data = f.read()
    print(f"[✓] ELF loaded: {len(elf_data)} bytes")
    return elf_data

# === SEND ELF PAYLOAD ===
def send_payload(ser, elf):
    print("[*] Uploading qslcl.elf to Phantom IV entry vector...")
    chunk_size = 512
    for i in range(0, len(elf), chunk_size):
        chunk = elf[i:i+chunk_size]
        ser.write(chunk)
        time.sleep(0.008)  # Slight delay for entropy sync
    print("[✓] ELF transfer complete.")

# === EXECUTE PHANTOM IV VECTOR ===
def trigger_phantom_iv(ser):
    print("[🚀] Sending Phantom IV execution trigger...")

    jump_addr = struct.pack("<I", PHANTOM_IV_VECTOR)
    spoof_hash = hashlib.blake2b(jump_addr + b"phantom_exec", digest_size=8).digest()
    packet = b"\xD3\xD3" + jump_addr + spoof_hash + b"\xE4\xE4"

    ser.write(packet)
    print(f"[✓] Jump triggered @ 0x{PHANTOM_IV_VECTOR:08X} (Spoof: {spoof_hash.hex()})")

# === LISTEN FOR PHANTOM IV SIGNALS ===
def listen_for_response(ser):
    print("[📡] Listening for Phantom IV signature output...")
    try:
        while True:
            response = ser.readline()
            if response:
                print(f"[Phantom IV] {response.hex()}")
    except KeyboardInterrupt:
        ser.close()
        print("\n[✖] Disconnected from COM")

# === MAIN EXECUTION FLOW ===
if __name__ == "__main__":
    print(f"[🧬] Connecting to {COM_PORT} at {BAUD_RATE} baud...")
    ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
    time.sleep(0.2)

    elf = load_qslcl_elf()
    send_phantom_sync(ser)
    send_payload(ser, elf)
    trigger_phantom_iv(ser)
    listen_for_response(ser)
