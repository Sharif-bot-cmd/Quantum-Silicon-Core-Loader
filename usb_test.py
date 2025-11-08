import serial
import serial.tools.list_ports
import struct
import time
import os
from tqdm import tqdm  # Progress bar

# Loader path
QSLCL_BIN = "qslcl.bin"
CHUNK_SIZE = 512

# USB micro-routines
USB_TX_ROUTINE = bytes([
    0x02, 0x00, 0x10, 0x00,
    0x03, 0x00, 0x40, 0x00,
    0x04, 0x00, 0x00, 0xF0,
    0x06, 0x00, 0x00, 0x00
])

USB_RX_ROUTINE = bytes([
    0x02, 0x00, 0x20, 0x00,
    0x03, 0x00, 0x40, 0x00,
    0x04, 0x00, 0x10, 0xF0,
    0x06, 0x00, 0x00, 0x00
])

USB_BULK_TEST_ROUTINE = bytes([
    0x02, 0x00, 0x30, 0x00,
    0x03, 0x00, 0x40, 0x00,
    0x04, 0x00, 0x20, 0xF0,
    0x06, 0x00, 0x00, 0x00
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

        # Progress bar
        sent = 0
        for i in tqdm(range(0, size, CHUNK_SIZE), desc=f"[{port}] Upload progress"):
            chunk = data[i:i+CHUNK_SIZE]
            ser.write(chunk)
            ser.flush()
            sent += len(chunk)
        print("\n[+] Upload complete")
        ser.write(b"\xAA")
        ser.flush()
        ser.close()
        print(f"[*] Loader execution signal sent on {port} [PASS]")
        return True
    except Exception as e:
        print(f"[-] Upload failed: {e} [FAIL]")
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
        status = parse_handshake(resp)
        result = "PASS" if "0=OK" in status else "FAIL"
        print(f"[{port}][{name}] {status} [{result}]")
        ser.close()
    except Exception as e:
        print(f"[-] {name} routine failed: {e} [FAIL]")

# ---------------- USB descriptor + control requests ----------------
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
    packets = [device_desc + config_desc + interface_desc]

    # Device Requests
    device_requests = [
        (0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00),
        (0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00),
        (0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00),
        (0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00),
        (0x80, 0x06, 0x00, 0x04, 0x00, 0x00, 0x12, 0x00),
        (0x80, 0x06, 0x00, 0x05, 0x00, 0x00, 0x0A, 0x00),
        (0x80, 0x06, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00),
        (0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00),
    ]
    packets.extend([bytes(r) for r in device_requests])

    # Interface Requests
    interface_requests = [
        (0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00),
        (0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        (0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    ]
    packets.extend([bytes(r) for r in interface_requests])

    # HID Requests
    hid_requests = [
        (0xA1, 0x01), (0xA1, 0x02), (0x21, 0x09), (0x21, 0x0B), (0x21, 0x0A)
    ]
    packets.extend([bytes(r) for r in hid_requests])

    # Vendor Requests
    vendor_requests = [(0xC0, 0x01), (0x40, 0x01)]
    packets.extend([bytes(r) for r in vendor_requests])

    return packets

def test_usb_descriptors(port):
    packets = create_usb_descriptors()
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(0.2)
        print("[*] Sending USB descriptors + requests for testing...")

        for pkt in tqdm(packets, desc=f"[{port}] USB test progress"):
            ser.write(pkt)
            ser.flush()
            time.sleep(0.05)
            resp = ser.read_all()
            status = parse_handshake(resp)
            result = "PASS" if "0=OK" in status else "FAIL"
            print(f"[{port}][USB_PKT] {status} [{result}]")

        ser.close()
    except Exception as e:
        print(f"[-] USB descriptor/request test failed: {e} [FAIL]")

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
