import serial
import time
import struct

# === Configuration ===
COM_PORT = "COM10"           # Change to your COM port
BAUD_RATE = 1152000         # High-speed for binary transfer
ELF_PATH = "qslcl.elf"      # Your generated .elf
LOAD_ADDR = 0x00000000      # Execution at 0x0

# === Open COM Port ===
ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
print(f"[+] Connected to {COM_PORT} at {BAUD_RATE} baud")

# === Load ELF ===
with open(ELF_PATH, "rb") as f:
    elf_data = f.read()

print(f"[+] Loaded qslcl.elf ({len(elf_data)} bytes)")

# === Send Sync Header ===
sync_header = b"\x7E\x01\x00\x7E"  # Custom sync (vendor-agnostic)
ser.write(sync_header)
time.sleep(0.2)

# === Send ELF ===
print("[*] Sending ELF payload...")
chunk_size = 512
for i in range(0, len(elf_data), chunk_size):
    chunk = elf_data[i:i+chunk_size]
    ser.write(chunk)
    time.sleep(0.01)

print("[+] ELF sent successfully")

# === Optional: Send Execution Trigger ===
# Many SoCs accept this as a jump vector payload
def send_jump_to_0x0():
    print("[*] Triggering execution at 0x00000000...")
    jump_vector = struct.pack("<I", LOAD_ADDR)
    trigger_packet = b"\x78\x78" + jump_vector + b"\xEE\xEE"
    ser.write(trigger_packet)
    print("[✓] Jump command sent (raw 0x0 execution)")

send_jump_to_0x0()

# === Hold Serial for Output (Optional) ===
try:
    while True:
        response = ser.readline()
        if response:
            print(f"[Serial] {response.hex()}")
except KeyboardInterrupt:
    ser.close()
    print("\n[!] Disconnected.")
