import serial
import serial.tools.list_ports
import struct
import time
import threading
import os
import usb.core
import usb.util

# QSLCL command constants
CMD_ENTER_META = 0x3A
CMD_ENTER_ENG  = 0x41

QSLCL_BIN = "qslcl.bin"

# ----------------------------------------------------------
def probe_port(port):
    """Check if port responds."""
    try:
        with serial.Serial(port, 115200, timeout=0.2) as ser:
            ser.write(b"\x00")
            ser.flush()
            return bool(ser.read(2))
    except Exception:
        return False


def discover_qslcl_devices():
    """Scan and validate available COM ports."""
    print("[*] Scanning available COM ports...")
    ports = [p.device for p in serial.tools.list_ports.comports()]
    if not ports:
        print("[-] No serial interfaces available.")
        return []
    valid = []
    for port in ports:
        if probe_port(port):
            print(f"[+] Device detected on {port}")
            valid.append(port)
    return valid


def detect_endpoints(port):
    """Enumerate USB endpoints."""
    endpoints = {"bulk_in": None, "bulk_out": None, "int_in": None}
    for dev in usb.core.find(find_all=True):
        try:
            for cfg in dev:
                for intf in cfg:
                    for ep in intf:
                        addr = ep.bEndpointAddress
                        if usb.util.endpoint_direction(addr) == usb.util.ENDPOINT_IN:
                            if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                                endpoints["bulk_in"] = addr
                            elif usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR:
                                endpoints["int_in"] = addr
                        else:
                            if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                                endpoints["bulk_out"] = addr
        except Exception:
            continue
    print(f"[{port}] Detected endpoints: {endpoints}")
    return endpoints


def send_cmd(ser, cmd_id, payload=b"\x01"):
    """Binary framed command: [cmd][len][payload]."""
    if not isinstance(payload, bytes):
        payload = bytes(payload)
    frame = struct.pack("<BB", cmd_id, len(payload)) + payload
    ser.write(frame)
    ser.flush()


def parse_resp(data):
    """Decode and format binary responses nicely."""
    if not data:
        return "<no response>"
    # Try to decode as 32-bit integers if length multiple of 4
    if len(data) % 4 == 0:
        ints = struct.unpack("<" + "I" * (len(data) // 4), data)
        return " ".join([f"0x{x:08X}({x})" for x in ints])
    # Otherwise hex fallback
    return data.hex(" ")


def read_resp(ser, expected_len=32):
    data = ser.read(expected_len)
    return parse_resp(data)


# ----------------------------------------------------------
def upload_loader_and_trigger_modes(port):
    """Upload qslcl.bin and trigger/activate modes."""
    try:
        with open(QSLCL_BIN, "rb") as f:
            data = f.read()
        size = len(data)
        print(f"[*] Uploading {QSLCL_BIN} to {port} ({size} bytes)...")

        detect_endpoints(port)
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(0.2)

        ser.write(b"\x55" * 8)
        ser.write(struct.pack("<I", size))
        ser.flush()
        time.sleep(0.1)

        chunk_size = 512
        for i in range(0, size, chunk_size):
            chunk = data[i:i + chunk_size]
            ser.write(chunk)
            ser.flush()
            print(f"[{port}] Sent {min(i + chunk_size, size)}/{size} bytes", end="\r")

        print(f"\n[+] Upload complete on {port}")

        ser.write(b"\xAA")
        ser.flush()
        print(f"[*] Loader execution signal sent on {port}")
        ser.close()
        time.sleep(1.0)

        # Reconnect to loader runtime
        ser = serial.Serial(port, 115200, timeout=0.5)
        time.sleep(0.2)
        print(f"[+] Connected to loader runtime on {port}")

        # --- Wait for handshake ---
        handshake = ser.read(8)
        if handshake:
            print(f"[{port}] Loader handshake: {handshake.hex(' ')}")
        else:
            print(f"[{port}] No handshake, continuing anyway...")

        # --- Trigger Meta Mode ---
        print("[*] Triggering Meta Mode...")
        send_cmd(ser, CMD_ENTER_META, b"\x01")
        resp = read_resp(ser)
        print(f"[{port}][META] {resp}")

        # --- Activate Engineering Mode ---
        print("[*] Activating Engineering Mode...")
        send_cmd(ser, CMD_ENTER_ENG, b"\x01")
        resp = read_resp(ser)
        print(f"[{port}][ENG] {resp}")

        ser.close()
        print(f"[+] Mode operations complete on {port}")

    except Exception as e:
        print(f"[-] Error on {port}: {e}")


# ----------------------------------------------------------
def run_all_devices():
    devices = discover_qslcl_devices()
    if not devices:
        print("[-] No QSLCL devices detected.")
        return

    print(f"[+] Launching parallel sessions for {len(devices)} device(s)...")
    threads = []
    for port in devices:
        t = threading.Thread(target=upload_loader_and_trigger_modes, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


# ----------------------------------------------------------
if __name__ == "__main__":
    run_all_devices()
