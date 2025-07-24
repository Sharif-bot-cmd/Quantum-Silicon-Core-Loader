import serial
import time
import struct
import os

# === Configuration ===
QSLCL_ELF = "qslcl.elf"
COM_PORT = "COM10"          # Change based on your system
BAUDRATE = 115200
TIMEOUT = 5
TRIGGER_DELAY = 0.3        # Allow microcontroller reset and sync

# === Load qslcl.elf ===
def load_qslcl_elf(path):
    with open(path, "rb") as f:
        return f.read()

# === Transmit to device ===
def send_payload(ser, data):
    print("[📤] Sending qslcl.elf payload...")
    chunk_size = 512
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        ser.write(chunk)
        time.sleep(0.002)
    print("[✅] Payload sent")

# === Trigger execution (no command strings) ===
def trigger_execution(ser):
    print("[⚡] Triggering Deep Factory Mode...")
    # Direct opcode pulse triggering via entropy sync
    ser.write(b'\x00\xEE\xFE\x00')  # Entropy sync preamble
    time.sleep(0.1)
    ser.write(b'\xDE\xFA\xCE\x01')  # Quantum trigger opcode
    ser.flush()
    print("[🚀] Awaiting device response (if any)...")

# === Main Execution ===
def main():
    elf_data = load_qslcl_elf(QSLCL_ELF)
    
    with serial.Serial(COM_PORT, baudrate=BAUDRATE, timeout=TIMEOUT) as ser:
        time.sleep(TRIGGER_DELAY)  # Sync with device reset
        
        # Optionally force into RAM mode via short
        print("[🌀] Preparing bare-metal injection...")
        ser.setDTR(False)
        ser.setRTS(True)
        time.sleep(0.2)
        ser.setRTS(False)

        send_payload(ser, elf_data)
        trigger_execution(ser)

        try:
            response = ser.read_all()
            if response:
                print(f"[📡] Raw Device Response: {response.hex()}")
            else:
                print("[🔇] No response (expected in silent DFM).")
        except Exception as e:
            print(f"[❌] Serial error: {e}")

if __name__ == "__main__":
    main()
