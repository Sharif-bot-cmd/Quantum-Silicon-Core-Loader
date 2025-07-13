import serial
import time
import struct
import os

QSLCL_ELF = "qslcl.elf"  # Your quantum ELF file
COM_PORT = "COM10"       # Change as needed
BAUD_RATE = 115200
CHUNK_SIZE = 4096

def open_serial(port, baud):
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=2)
        print(f"[✅] Connected to {port} at {baud} baud.")
        return ser
    except serial.SerialException:
        print("[❌] Failed to open COM port.")
        return None

def send_entropy_vector(serial_port):
    print("[💥] Sending entropy unlock vector to initiate phase drift...")
    vector = b'\xD3\xAD\xFE\xED' * 4 + os.urandom(16)
    serial_port.write(vector)
    time.sleep(0.3)
    serial_port.flush()

def upload_qslcl_elf(serial_port, elf_path):
    print(f"[📤] Uploading {elf_path} to target RAM...")
    with open(elf_path, "rb") as f:
        elf_data = f.read()

    total = len(elf_data)
    sent = 0

    while sent < total:
        chunk = elf_data[sent:sent+CHUNK_SIZE]
        serial_port.write(chunk)
        time.sleep(0.01)
        sent += len(chunk)
        print(f"    Uploaded {sent}/{total} bytes", end="\r")

    print(f"\n[✅] ELF upload complete.")

def trigger_execution(serial_port):
    print("[🚀] Triggering execution of uploaded ELF from 0x0 (ghost RAM)...")
    exec_cmd = b"\xA5\x5A\x00\x00\x00\x00\x00\x00"
    serial_port.write(exec_cmd)
    time.sleep(1)

def wait_for_maskrom_override(serial_port):
    print("[🧠] Awaiting MaskROM override response...")
    serial_port.timeout = 3
    response = serial_port.read(128)

    if b"QSLCL_OK" in response:
        print("[🔓] MaskROM unlock confirmed.")
    elif b"QSLCL_FAIL" in response:
        print("[❌] ELF failed to override MaskROM.")
    else:
        print("[❔] Unknown response. Possibly succeeded silently.")
    print(f"[📡] Raw Output: {response.hex()}")

def unlock_maskrom():
    ser = open_serial(COM_PORT, BAUD_RATE)
    if not ser:
        return

    send_entropy_vector(ser)
    upload_qslcl_elf(ser, QSLCL_ELF)
    trigger_execution(ser)
    wait_for_maskrom_override(ser)

    ser.close()
    print("[✅] Done.")

if __name__ == "__main__":
    unlock_maskrom()
