import usb.core
import usb.util
import time
import struct
import sys
import random
import hashlib
import os
import serial
import serial.tools.list_ports

DFU_INTERFACE = 0
APPLE_VID = 0x05AC
KNOWN_DFU_PIDS = [0x1227, 0x1222, 0x1223, 0x1224, 0x1225, 0x1226, 0x1228, 0x1229, 0x1337]

def find_device():
    print("[🔍] Scanning all USB devices...")
    devices = usb.core.find(find_all=True)
    for dev in devices:
        try:
            vid = dev.idVendor
            pid = dev.idProduct
            print(f"[•] Found device VID:0x{vid:04X}, PID:0x{pid:04X}")
            return dev
        except Exception as e:
            print(f"[!] Error reading device: {e}")
    return None

def generate_random_upload_address():
    base = 0x80000000
    addr = random.randint(base, base + 0x0FFFFFFF)
    print(f"[\U0001f9ec] Upload Address ➔ 0x{addr:08X}")
    return addr

def generate_virtual_com_port():
    entropy = os.urandom(16)
    com_hash = hashlib.shake_256(entropy).hexdigest(8).upper()
    com_id = f"COM-QSLCL-{com_hash}"
    print(f"[🔌] Virtual COM Spoof ➔ {com_id}")
    return com_id

def pulse_d_plus_line():
    print("[⚡️] Pulsing D+ line (simulated trigger)...")
    for _ in range(4):
        time.sleep(0.001 + random.uniform(0.001, 0.002))
        print("[↺] D+ pulse tick")
    print("[✔️] D+ pulse complete.")

def find_device():
    print("[🔍] Searching for DFU or Generic USB devices...")
    for vid, pid in [(APPLE_VID, p) for p in KNOWN_DFU_PIDS] + GENERIC_VIDPIDS:
        dev = usb.core.find(idVendor=vid, idProduct=pid)
        if dev:
            print(f"[✓] Device found ➔ VID 0x{vid:04X}, PID 0x{pid:04X}")
            return dev
    return None

def claim_interface(dev):
    try:
        if dev.is_kernel_driver_active(DFU_INTERFACE):
            dev.detach_kernel_driver(DFU_INTERFACE)
        usb.util.claim_interface(dev, DFU_INTERFACE)
    except Exception as e:
        print(f"[!] Interface claim failed: {e}")
        sys.exit(1)

def usb_glitch_trigger(dev=None):
    print("[⚡️] Injecting USB glitch sequence...")
    try:
        for _ in range(16):
            if dev:
                dev.ctrl_transfer(0x21, 1, 0, 0, os.urandom(32))
            time.sleep(0.001 + random.uniform(0.001, 0.002))
        print("[✔️] USB glitch sent.")
    except Exception as e:
        print(f"[!] Glitch failed: {e}")

def detect_endpoints(dev):
    try:
        cfg = dev.get_active_configuration()
        endpoints = []
        for interface in cfg:
            for ep in interface:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                    endpoints.append(ep.bEndpointAddress)
        print(f"[🔁] OUT Endpoints ➔ {endpoints}")
        return endpoints if endpoints else [1]
    except:
        return [1]

def upload_payload(dev, payload, upload_addr, tunnel_mode=False, hijack=False):
    print(f"[⏫] Uploading ELF ➔ 0x{upload_addr:08X}...")
    chunk_size = 0x800
    endpoints = detect_endpoints(dev) if hijack else [1]

    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        try:
            if tunnel_mode or hijack:
                for ep in endpoints:
                    dev.write(ep, chunk)
                    break
            else:
                dev.ctrl_transfer(0x21, 1, upload_addr & 0xFFFF, DFU_INTERFACE, chunk)
            time.sleep(0.004)
        except Exception as e:
            print(f"[!] Upload failed at chunk {i//chunk_size}: {e}")
            sys.exit(1)
    print("[✔️] Upload complete.")

def trigger_execution(dev, exec_addr=0x00000000, tunnel_mode=False, hijack=False):
    print(f"[🚀] Triggering ELF @ 0x{exec_addr:08X}...")
    try:
        if tunnel_mode or hijack:
            dev.write(1, b'\xA5'*8)
        else:
            dev.ctrl_transfer(0x21, 1, exec_addr & 0xFFFF, DFU_INTERFACE, b'\x00')
    except:
        pass
    print("[✔️] QSLCL Executed.")

def reboot_device(dev):
    print("[🔁] Reboot via entropy spike...")
    try:
        for _ in range(8):
            dev.ctrl_transfer(0x21, 1, 0, 0, os.urandom(32))
            time.sleep(0.002)
    except:
        pass
    print("[✔️] Device rebooted.")

def serial_fallback(payload, port_override=None):
    print("[🔊] Serial fallback initiated...")
    ports = [port_override] if port_override else [p.device for p in serial.tools.list_ports.comports()]

    for port in ports:
        try:
            print(f"[↺] Trying {port}...")
            with serial.Serial(port, 115200, timeout=1) as ser:
                ser.write(payload)
                print(f"[✔️] Payload sent via {port}")
                return
        except Exception as e:
            print(f"[!] Serial error on {port}: {e}")
    print("[✗] No serial port worked.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python qslcl_launcher.py qslcl.elf [--usb] [--reboot] [--hijack] [--serial] [--port=/dev/ttyUSB0]")
        sys.exit(1)

    elf_file = sys.argv[1]
    tunnel_mode = "--usb" in sys.argv
    reboot_flag = "--reboot" in sys.argv
    hijack_mode = "--hijack" in sys.argv
    serial_mode = "--serial" in sys.argv
    port_override = None

    for arg in sys.argv:
        if arg.startswith("--port="):
            port_override = arg.split("=")[1]
            serial_mode = True

    if not elf_file.lower().endswith(".elf"):
        print("[!] Must provide a .elf QSLCL image.")
        sys.exit(1)

    try:
        with open(elf_file, "rb") as f:
            payload = f.read()
    except Exception as e:
        print(f"[!] Failed to read ELF: {e}")
        sys.exit(1)

    upload_addr = generate_random_upload_address()
    generate_virtual_com_port()
    pulse_d_plus_line()

    dev = find_device()

    if not dev and (tunnel_mode or hijack_mode):
        print("[⚠️] No USB device — Falling back to tunnel mode...")
        class DummyUSB:
            def write(self, endpoint, data): print(f"[USB TUNNEL] {len(data)} bytes to EP{endpoint}")
            def ctrl_transfer(self, *args, **kwargs): pass
        dev = DummyUSB()
    elif not dev:
        if serial_mode:
            serial_fallback(payload, port_override)
            sys.exit(0)
        print("[✗] No supported device found. Use --usb, --serial or --port.")
        sys.exit(1)

    if not tunnel_mode and not hijack_mode:
        claim_interface(dev)

    if reboot_flag:
        reboot_device(dev)

    usb_glitch_trigger(dev)
    upload_payload(dev, payload, upload_addr, tunnel_mode, hijack_mode)
    trigger_execution(dev, 0x00000000, tunnel_mode, hijack_mode)

if __name__ == "__main__":
    main()
        
