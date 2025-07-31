import os
import serial
import time
import struct

# === CONFIGURATION ===
QSLCL_ELF = "qslcl.elf"
COM_PORT = "COM10"                 # Change to your actual port
BAUDRATE = 115200
TIMEOUT = 5

SHELLCODE_PATH = "shellcode.bin"
FLASH_OFFSET = 0x1900        # Change to desired JTAG address (e.g., IRAM, TCM, etc.)

# === LOW-LEVEL FUNCTION ===
def send_command(ser, cmd: bytes):
    ser.write(cmd)
    time.sleep(0.1)
    return ser.read(ser.in_waiting or 1)

def jtag_write_mem(ser, addr, data):
    print(f"[📤] Writing {len(data)} bytes to 0x{addr:08X}")
    for i in range(0, len(data), 4):
        chunk = data[i:i+4].ljust(4, b'\x00')
        word = struct.unpack("<I", chunk)[0]
        cmd = struct.pack("<cII", b'W', addr + i, word)
        send_command(ser, cmd)

def jtag_exec(ser, addr):
    print(f"[🚀] Executing at 0x{addr:08X}")
    cmd = struct.pack("<cI", b'X', addr)
    send_command(ser, cmd)

def trigger_jtag_mode():
    print("[🔧] Triggering JTAG via qslcl.elf...")
    os.system(f"./{QSLCL_ELF}")  # Assumes qslcl.elf is RAM-executed and triggers JTAG
    time.sleep(1)

# === MAIN LOGIC ===
def main():
    # Load shellcode
    if not os.path.exists(SHELLCODE_PATH):
        print(f"[❌] Shellcode not found: {SHELLCODE_PATH}")
        return

    with open(SHELLCODE_PATH, "rb") as f:
        shellcode = f.read()

    trigger_jtag_mode()

    with serial.Serial(COM_PORT, BAUDRATE, timeout=TIMEOUT) as ser:
        print("[🔌] Connected to serial port.")

        # Optional: wait for banner or sync
        time.sleep(1)
        ser.reset_input_buffer()

        print("[📡] Flashing shellcode...")
        jtag_write_mem(ser, FLASH_OFFSET, shellcode)

        print("[🟢] Launching shellcode...")
        jtag_exec(ser, FLASH_OFFSET)

if __name__ == "__main__":
    main()
