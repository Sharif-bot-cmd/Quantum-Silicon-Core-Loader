import serial
import serial.tools.list_ports
import struct
import time
import os

# Loader path
QSLCL_BIN = "qslcl.bin"
CHUNK_SIZE = 512

# USB micro-routines
USB_TX_ROUTINE = bytes([
    0x02, 0x00, 0x10, 0x00,  # MOV R0, 0x0010 (TX start)
    0x03, 0x00, 0x40, 0x00,  # MOV R1, 0x0040 (len)
    0x04, 0x00, 0x00, 0xF0,  # CALL USB_WRITE
    0x06, 0x00, 0x00, 0x00   # HLT / RET
])

USB_RX_ROUTINE = bytes([
    0x02, 0x00, 0x20, 0x00,  # MOV R0, 0x0020 (RX start)
    0x03, 0x00, 0x40, 0x00,  # MOV R1, 0x0040 (len)
    0x04, 0x00, 0x10, 0xF0,  # CALL USB_READ
    0x06, 0x00, 0x00, 0x00   # HLT / RET
])

USB_BULK_TEST_ROUTINE = bytes([
    0x02, 0x00, 0x30, 0x00,  # MOV R0, 0x0030 (bulk buffer)
    0x03, 0x00, 0x40, 0x00,  # MOV R1, 0x0040 (len)
    0x04, 0x00, 0x20, 0xF0,  # CALL USB_BULK (TX->RX test)
    0x06, 0x00, 0x00, 0x00   # HLT / RET
])

# ---------------- Core functions ----------------
def probe_port(port):
    try:
        ser = serial.Serial(port, 115200, timeout=0.2)
        ser.write(b"\x00")
        ser.flush()
        resp = ser.read(4)
        ser.close()
        return bool(resp)
    except Exception:
        return False

def discover_devices():
    ports_info = serial.tools.list_ports.comports()
    valid_ports = []
    for p in ports_info:
        if probe_port(p.device):
            vid = getattr(p, "vid", 0)
            pid = getattr(p, "pid", 0)
            print(f"[+] Loader device detected on {p.device} (VID:PID {vid:04X}:{pid:04X})")
            valid_ports.append((p.device, vid, pid))
    return valid_ports

def upload_loader(port):
    if not os.path.isfile(QSLCL_BIN):
        print(f"[-] {QSLCL_BIN} not found")
        return False
    print(f"[*] Uploading {QSLCL_BIN} to {port}...")
    try:
        with open(QSLCL_BIN, "rb") as f:
            data = f.read()
        size = len(data)
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(0.2)
        ser.write(b"\x55"*8)
        ser.flush()
        time.sleep(0.05)
        ser.write(struct.pack("<I", size))
        ser.flush()
        ack = ser.read(1)
        if not ack:
            print("[!] No ACK before upload, continuing anyway")
        sent = 0
        for i in range(0, size, CHUNK_SIZE):
            chunk = data[i:i+CHUNK_SIZE]
            ser.write(chunk)
            ser.flush()
            sent += len(chunk)
            print(f"[{port}] Sent {sent}/{size} bytes", end="\r")
        print("\n[+] Upload complete")
        ser.write(b"\xAA")
        ser.flush()
        ser.close()
        print(f"[*] Loader execution signal sent on {port}")
        return True
    except Exception as e:
        print(f"[-] Upload failed: {e}")
        return False

def parse_handshake(resp):
    if not resp or len(resp) < 16:
        return "No handshake received"
    return f"Routine ID {resp[0]}, Status {resp[12]} (0=OK)"

def run_micro_routine(port, routine, name=""):
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(0.2)
        print(f"[*] Sending {name} routine...")
        ser.write(routine)
        ser.flush()
        time.sleep(0.5)
        resp = ser.read_all()
        print(f"[{port}][{name}] {parse_handshake(resp)}")
        ser.close()
    except Exception as e:
        print(f"[-] {name} routine failed: {e}")

# ---------------- USB descriptor testing ----------------
def create_usb_descriptors():
    device_desc = bytearray([
        0x12, 0x01, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x01
    ])
    config_desc = bytearray([
        0x09, 0x02, 0x00, 0x00,
        0x01, 0x01, 0x00,
        0x80, 0x32
    ])
    interface_desc = bytearray([
        0x09, 0x04, 0x00, 0x00,
        0x02, 0xFF, 0x00, 0x00, 0x00
    ])
    return device_desc + config_desc + interface_desc

def test_usb_descriptors(port):
    descriptors = create_usb_descriptors()
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(0.2)
        print("[*] Sending USB descriptors for testing...")
        ser.write(descriptors)
        ser.flush()
        time.sleep(0.5)
        resp = ser.read_all()
        print(f"[{port}][USB_DESC] {parse_handshake(resp)}")
        ser.close()
    except Exception as e:
        print(f"[-] USB descriptor test failed: {e}")

# ---------------- Main ----------------
def main():
    devices = discover_devices()
    if not devices:
        print("[-] No loader devices found")
        return
    for port, vid, pid in devices:
        if upload_loader(port):
            time.sleep(1.0)
            run_micro_routine(port, USB_TX_ROUTINE, "USB_TX")
            run_micro_routine(port, USB_RX_ROUTINE, "USB_RX")
            run_micro_routine(port, USB_BULK_TEST_ROUTINE, "USB_BULK_TEST")
            test_usb_descriptors(port)

if __name__ == "__main__":
    main()
