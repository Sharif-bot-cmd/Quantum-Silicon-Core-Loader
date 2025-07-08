import serial
import time
import struct
import os

# === Configuration ===
COM_PORT   = "COM10"             # Your COM port (change if needed)
BAUD_RATE  = 1152000             # Max safe UART speed
ELF_PATH   = "qslcl.elf"         # Your binary payload
LOAD_ADDR  = 0x00000000          # Raw execution address
TRIGGER_DELAY = 0.15             # Delay between write and jump

# === Open COM Port ===
ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
print(f"[✓] Serial connected to {COM_PORT} at {BAUD_RATE} baud")

# === Load ELF Payload ===
with open(ELF_PATH, "rb") as f:
    elf_data = f.read()

print(f"[✓] Loaded qslcl.elf ({len(elf_data)} bytes)")

# === Send Vendor-Agnostic ShadowROM Sync ===
# Forces chip to fallback to Pre-MaskROM handler
def send_shadowrom_sync():
    print("[*] Sending ShadowROM sync pattern...")
    sync_sequence = b"\xF1\x00\xAA\x55\xCC\x33\x7E\x7E"  # Chaotic preboot sync
    ser.write(sync_sequence)
    time.sleep(0.25)

# === Send ELF Payload ===
def send_payload():
    print("[*] Transmitting ELF payload to 0x0...")
    chunk_size = 512
    for i in range(0, len(elf_data), chunk_size):
        chunk = elf_data[i:i+chunk_size]
        ser.write(chunk)
        time.sleep(0.01)
    print("[✓] ELF payload sent")

# === Send Execution Trigger ===
def send_raw_jump():
    print("[*] Triggering raw execution at 0x00000000...")
    jump_vector = struct.pack("<I", LOAD_ADDR)
    trigger_packet = b"\x78\x78" + jump_vector + b"\xEE\xEE"  # Custom neutral trigger
    ser.write(trigger_packet)
    print("[✓] Raw jump command sent")

# === Optional: Confuse BootROM Further ===
def send_noise_burst():
    print("[*] Sending entropy burst to trigger ROM confusion...")
    for _ in range(16):
        ser.write(os.urandom(64))
        time.sleep(0.02)

# === Execution Flow ===
send_shadowrom_sync()
send_noise_burst()
send_payload()
time.sleep(TRIGGER_DELAY)
send_raw_jump()

# === Hold Serial for Output Capture ===
print("[*] Awaiting device response (PreMaskROM log)...")
try:
    while True:
        response = ser.readline()
        if response:
            print(f"[Serial] {response.hex()}  |  {response.decode(errors='ignore').strip()}")
except KeyboardInterrupt:
    ser.close()
    print("\n[!] Disconnected.")