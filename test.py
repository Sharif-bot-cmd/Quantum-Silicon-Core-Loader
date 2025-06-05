import serial
import serial.tools.list_ports
import time
import os

ELF_PATH = "qslcl.elf"

def find_valid_com_port():
    print("[🔄] Waiting for COM port...")
    while True:
        ports = serial.tools.list_ports.comports()
        for port in ports:
            try:
                s = serial.Serial(port.device, baudrate=115200, timeout=0.2)
                s.close()
                print(f"[✔] COM port detected: {port.device}")
                return port.device
            except:
                continue
        time.sleep(1)  # Wait 1s before checking again

def load_elf_payload(path):
    if not os.path.exists(path):
        print(f"[✘] ELF file not found: {path}")
        return None
    with open(path, "rb") as f:
        return f.read()

def send_payload(serial_port, data):
    try:
        with serial.Serial(serial_port, baudrate=115200, timeout=0.1) as s:
            print(f"[♾️] Sending ELF payload to {serial_port}...")
            s.write(data)
            time.sleep(0.5)
            s.flush()
            print("[♾️] Waiting for response...")
            response = s.read_all()
            print(f"[✔] Response: {response.hex()}")
    except Exception as e:
        print(f"[✘] Communication error: {e}")

def main():
    port = find_valid_com_port()
    elf_data = load_elf_payload(ELF_PATH)
    if not elf_data:
        return
    send_payload(port, elf_data)

if __name__ == "__main__":
    main()
