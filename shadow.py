import serial
import time
import struct
import hashlib
import os

# === USER CONFIGURATION ===
COM_PORT   = "COM10"           # ⚠️ Change to your active COM port
BAUD_RATE  = 1152000           # High-speed reliable for ELF payload
ELF_PATH   = "qslcl.elf"       # qslcl.elf path
SHADOWROM_OFFSET = 0x00000000  # Must be 0x0 for silicon vector override

# === CUSTOM ENTROPY SYNC HEADER ===
def send_entropy_sync(serial_obj):
    sync = b"\x7E\x55\xAA\x7E"  # Magic handshake
    tag = b"QSLCL"              # Identity tag
    entropy = os.urandom(32)
    combined = sync + tag + entropy
    serial_obj.write(combined)
    time.sleep(0.25)
    print(f"[+] Entropy sync header sent ({len(combined)} bytes)")

# === STAGE 1: CONNECT TO COM PORT ===
print(f"[✳️] Connecting to {COM_PORT} @ {BAUD_RATE}...")
ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
time.sleep(0.2)
print("[✓] COM port ready")

# === STAGE 2: LOAD qslcl.elf ===
with open(ELF_PATH, "rb") as f:
    elf_data = f.read()
print(f"[✓] ELF loaded: {len(elf_data)} bytes")

# === STAGE 3: ENTROPY SYNC TO TRIGGER SHADOWROM ENTRY ===
send_entropy_sync(ser)

# === STAGE 4: SEND ELF PAYLOAD TO 0x0 ===
print("[*] Sending ELF to 0x0 (ShadowROM expected entrypoint)...")
chunk_size = 512
for i in range(0, len(elf_data), chunk_size):
    chunk = elf_data[i:i+chunk_size]
    ser.write(chunk)
    time.sleep(0.01)

print("[✓] ELF payload sent successfully")

# === STAGE 5: SEND SHADOWROM VECTOR EXECUTION TRIGGER ===
def send_shadowrom_trigger():
    print("[*] Dispatching ShadowROM execution trigger...")
    magic_tag = b"\x78\x78"  # Device expects this before jump
    jump_addr = struct.pack("<I", SHADOWROM_OFFSET)
    anchor = hashlib.sha1(b"shadowrom_trigger" + jump_addr).digest()[:6]
    footer = b"\xEE\xEE"
    trigger = magic_tag + jump_addr + anchor + footer
    ser.write(trigger)
    print(f"[✓] Jump to 0x0 triggered (Anchor: {anchor.hex()})")

send_shadowrom_trigger()

# === STAGE 6: LISTEN FOR RESPONSE LOOP ===
print("[📡] Listening for ShadowROM loop signature...")
try:
    while True:
        line = ser.readline()
        if line:
            print(f"[ShadowROM] {line.hex()}")
except KeyboardInterrupt:
    ser.close()
    print("\n[✖] Disconnected from COM")
