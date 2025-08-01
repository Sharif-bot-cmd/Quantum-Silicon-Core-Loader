import os
import serial
import time
import struct
import random
import hashlib

# === CONFIGURATION ===
QSLCL_ELF = "qslcl.elf"
COM_PORT = "COM10"  # Adjust per platform
BAUDRATE = 115200
TIMEOUT = 0.2  # Short timeout to detect small echoes

# === Glitch Parameters (Entropy-Based Timing)
GLITCH_ATTEMPTS = 256
TIMING_WINDOW_US = [500, 750, 1000, 1250, 1500]  # µs delay for entropy timing
ENTROPY_MODES = [0x00, 0x7F, 0xFF, 0xA5, 0x5A]  # Glitch entropy bytes

# === ELF Loader
def load_qslcl_elf():
    with open(QSLCL_ELF, "rb") as f:
        return f.read()

# === Simulate Glitch Voltage Trigger
def send_entropy_trigger(serial_port, entropy_byte, delay_us):
    glitch = struct.pack("<B", entropy_byte) * 4
    time.sleep(delay_us / 1_000_000.0)
    serial_port.write(glitch)

# === Mutate ELF Capsule by XOR
def simulate_voltage_entropy(entropy_byte, elf_blob):
    return bytes(b ^ entropy_byte for b in elf_blob)

# === Baremetal I/O detection: Detect *any* byte return or line pulse
def detect_any_feedback(serial_port):
    try:
        data = serial_port.read(2)  # Expect minimal echo/feedback
        return any(data)
    except:
        return False

def main():
    print("[⚡] QSLCL MaskROM Glitch Injection Initiated (Bare-Metal Logic)")

    if not os.path.exists(QSLCL_ELF):
        print(f"[❌] ELF '{QSLCL_ELF}' not found.")
        return

    elf_blob = load_qslcl_elf()

    try:
        with serial.Serial(COM_PORT, BAUDRATE, timeout=TIMEOUT) as ser:
            print(f"[🔌] Connected to {COM_PORT} @ {BAUDRATE} baud.")
            time.sleep(0.5)

            for attempt in range(GLITCH_ATTEMPTS):
                entropy = random.choice(ENTROPY_MODES)
                delay = random.choice(TIMING_WINDOW_US)
                mutated = simulate_voltage_entropy(entropy, elf_blob)

                print(f"[⚙️] Attempt #{attempt+1} | Entropy=0x{entropy:02X} | Delay={delay}µs")
                send_entropy_trigger(ser, entropy, delay)

                # Send partial ELF (pre-header or first stub capsule)
                ser.write(mutated[:512])
                time.sleep(0.05)

                if detect_any_feedback(ser):
                    print(f"[✅] Feedback detected — QSLCL.ELF likely executing (Entropy: 0x{entropy:02X})")
                    break
                else:
                    print("[🌀] No baremetal feedback. Continue...")

                time.sleep(0.25)

    except serial.SerialException as e:
        print(f"[‼️] Serial error: {e}")
    except KeyboardInterrupt:
        print("[🚫] Interrupted by user.")

if __name__ == "__main__":
    main()
