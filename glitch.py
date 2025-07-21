import serial
import time
import os
import struct
import random
import hashlib

# === Configuration ===
COM_PORT = "COM10"             # 🛠️ Set your COM port here
BAUDRATE = 115200             # Or higher if needed
TIMEOUT = 3
QSLCL_ELF = "qslcl.elf"       # Your loader with entropy glitch logic
INJECT_OFFSET = 0x0           # Targeting Silicon Reset Vector
GLITCH_ITERATIONS = 32        # Number of glitch attempts
ENTROPY_PULSE_SIZE = 512      # Each entropy burst size in bytes

# === Load ELF into memory ===
with open(QSLCL_ELF, "rb") as f:
    elf_data = f.read()

print(f"[📦] Loaded qslcl.elf ({len(elf_data)} bytes)")

# === Entropy Pulse Generator ===
def generate_entropy_pulse(seed=None):
    if seed is None:
        seed = os.urandom(64)
    chaotic = os.urandom(ENTROPY_PULSE_SIZE)
    fold = hashlib.shake_256(chaotic + seed).digest(ENTROPY_PULSE_SIZE)
    pulse = bytearray()
    for i in range(ENTROPY_PULSE_SIZE):
        pulse.append(chaotic[i] ^ fold[i])
    return bytes(pulse)

# === Connect to COM Port ===
with serial.Serial(COM_PORT, baudrate=BAUDRATE, timeout=TIMEOUT) as ser:
    print(f"[🔌] Connected to {COM_PORT} @ {BAUDRATE}")

    # 1. Trigger reset state glitch
    print("[🚨] Sending entropy-glitch pulses to pre-boot silicon vector...")
    for i in range(GLITCH_ITERATIONS):
        pulse = generate_entropy_pulse()
        try:
            ser.write(pulse)
            time.sleep(0.05)
            response = ser.read(128)
            print(f"[⚡] Glitch {i+1:02}: {response.hex()[:64]}...")
        except Exception as e:
            print(f"[❌] Error during glitch {i+1}: {e}")
        time.sleep(0.1)

    # 2. Inject actual qslcl.elf payload
    print(f"[📤] Uploading qslcl.elf to 0x{INJECT_OFFSET:X} after glitch desync...")
    try:
        for i in range(0, len(elf_data), 256):
            chunk = elf_data[i:i+256]
            ser.write(chunk)
            time.sleep(0.01)
        print("[✅] ELF injected after entropy glitch pulses.")
    except Exception as e:
        print(f"[❌] Failed to inject ELF: {e}")
