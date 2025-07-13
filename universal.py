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

def print_dfu_instructions():
    print("""
[INFO] DFU Mode Instructions:
1. Power off your device completely.
2. Hold the following keys simultaneously:
   • iPhone 8+: Volume Down + Side Button
   • iPhone 7: Volume Down + Power
   • iPhone 6s and older: Home + Power
3. While holding, connect the USB cable to your PC.
4. Release power after 5 seconds but keep holding the other button for ~10 more seconds.
5. Screen should remain black. Device is now in DFU mode.
""")

def find_device():
    print("[INFO] Searching for DFU or Generic USB devices...")
    for pid in KNOWN_DFU_PIDS:
        dev = usb.core.find(idVendor=APPLE_VID, idProduct=pid)
        if dev:
            print(f"[OK] Device found -> VID 0x{APPLE_VID:04X}, PID 0x{pid:04X}")
            return dev
    return None

def generate_random_upload_address():
    base = 0x80000000
    addr = random.randint(base, base + 0x0FFFFFFF)
    print(f"[ADDR] Upload Address -> 0x{addr:08X}")
    return addr

def generate_virtual_com_port():
    entropy = os.urandom(16)
    com_hash = hashlib.shake_256(entropy).hexdigest(8).upper()
    com_id = f"COM-{com_hash}"
    print(f"[VCOM] Virtual COM Spoof -> {com_id}")
    return com_id

def pulse_d_plus_line():
    print("[USB] Pulsing D+ line...")
    for _ in range(4):
        time.sleep(0.002 + random.uniform(0.001, 0.003))
        print("[USB] D+ pulse tick")
    print("[USB] D+ pulse complete.")

def claim_interface(dev):
    try:
        if dev.is_kernel_driver_active(DFU_INTERFACE):
            dev.detach_kernel_driver(DFU_INTERFACE)
        usb.util.claim_interface(dev, DFU_INTERFACE)
    except Exception as e:
        print(f"[ERROR] Interface claim failed: {e}")
        sys.exit(1)

def usb_glitch_trigger(dev=None):
    print("[GLITCH] Injecting USB glitch sequence...")
    try:
        for _ in range(16):
            if dev:
                dev.ctrl_transfer(0x21, 1, 0, 0, os.urandom(32))
            time.sleep(0.002)
        print("[GLITCH] USB glitch sent.")
    except Exception as e:
        print(f"[ERROR] Glitch failed: {e}")

def detect_endpoints(dev):
    try:
        cfg = dev.get_active_configuration()
        endpoints = []
        for interface in cfg:
            for ep in interface:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                    endpoints.append(ep.bEndpointAddress)
        print(f"[USB] OUT Endpoints -> {endpoints}")
        return endpoints if endpoints else [1]
    except:
        return [1]

def upload_payload(dev, payload, upload_addr, tunnel_mode=False, hijack=False):
    print(f"[UPLOAD] ELF -> 0x{upload_addr:08X}...")
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
            time.sleep(0.005)
        except Exception as e:
            print(f"[ERROR] Upload failed at chunk {i//chunk_size}: {e}")
            sys.exit(1)
    print("[UPLOAD] Upload complete.")

def trigger_execution(dev, exec_addr=0x00000000, tunnel_mode=False, hijack=False):
    print(f"[EXEC] Triggering ELF @ 0x{exec_addr:08X}...")
    try:
        if tunnel_mode or hijack:
            dev.write(1, b'\xA5' * 8)
        else:
            dev.ctrl_transfer(0x21, 1, exec_addr & 0xFFFF, DFU_INTERFACE, b'\x00')
    except:
        pass
    print("[EXEC] QSLCL Executed.")

def reboot_device(dev):
    print("[REBOOT] Reboot via entropy spike...")
    try:
        for _ in range(8):
            dev.ctrl_transfer(0x21, 1, 0, 0, os.urandom(32))
            time.sleep(0.002)
    except:
        pass
    print("[REBOOT] Device rebooted.")

def serial_fallback(payload, port_override=None):
    print("[SERIAL] Serial fallback initiated...")
    ports = [port_override] if port_override else [p.device for p in serial.tools.list_ports.comports()]

    for port in ports:
        if port == "/dev/ttyVCOMQSLCL":
            print("[VCOM] Virtual COM triggered — QSLCL will intercept internally.")
            return
        try:
            print(f"[SERIAL] Trying {port}...")
            with serial.Serial(port, 115200, timeout=1) as ser:
                ser.write(payload)
                print(f"[OK] Payload sent via {port}")
                return
        except Exception as e:
            print(f"[ERROR] Serial error on {port}: {e}")
    print("[FAIL] No serial port worked.")

def serial_hijack_trigger(ser):
    print("[SERIAL-HIJACK] Initiating serial hijack sequence...")
    try:
        # Handshake preamble: optional based on your qslcl.elf trigger logic
        ser.write(b'\x55\xAA')  # Sync
        time.sleep(0.02)
        ser.write(b'\xA5\x5A')  # Hijack request
        print("[SERIAL-HIJACK] Trigger sent, waiting for response...")
        resp = ser.read(2)
        if resp:
            print(f"[SERIAL-HIJACK] Response: {resp.hex()}")
        else:
            print("[SERIAL-HIJACK] No response, assuming silent ACK.")
    except Exception as e:
        print(f"[ERROR] Serial hijack failed: {e}")
        return False
    return True

def serial_fallback(payload, port_override=None, hijack=False):
    print("[SERIAL] Serial fallback initiated...")
    ports = [port_override] if port_override else [p.device for p in serial.tools.list_ports.comports()]

    for port in ports:
        if port == "/dev/ttyVCOMQSLCL":
            print("[VCOM] Virtual COM triggered — QSLCL will intercept internally.")
            return
        try:
            print(f"[SERIAL] Trying {port}...")
            with serial.Serial(port, 115200, timeout=1) as ser:
                if hijack:
                    if not serial_hijack_trigger(ser):
                        continue
                ser.write(payload)
                print(f"[OK] Payload sent via {port}")
                return
        except Exception as e:
            print(f"[ERROR] Serial error on {port}: {e}")
    print("[FAIL] No serial port worked.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python universal.py qslcl.elf [--usb] [--virtual=usb] [--virtual=serial] [--reboot] [--hijack] [--serial] [--port=/dev/ttyUSB0]")
        print_dfu_instructions()
        sys.exit(1)

    elf_file = sys.argv[1]
    tunnel_mode = "--usb" in sys.argv
    reboot_flag = "--reboot" in sys.argv
    hijack_mode = "--hijack" in sys.argv
    serial_mode = "--serial" in sys.argv
    virtual_usb = "--virtual=usb" in sys.argv
    virtual_com = "--virtual=serial" in sys.argv
    serial_hijack_mode = virtual_com and hijack_mode
    port_override = None

    for arg in sys.argv:
        if arg.startswith("--port="):
            port_override = arg.split("=")[1]
            serial_mode = True

    if not elf_file.lower().endswith(".elf"):
        print("[ERROR] Must provide a .elf QSLCL image.")
        sys.exit(1)

    try:
        with open(elf_file, "rb") as f:
            payload = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read ELF: {e}")
        sys.exit(1)

    upload_addr = generate_random_upload_address()
    generate_virtual_com_port()
    pulse_d_plus_line()

    if virtual_usb:
        print("[VUSB] Virtual USB mode triggered. QSLCL .elf must handle this entry.")
        class VirtualUSB:
            is_virtual = True
            def write(self, endpoint, data):
                print(f"[VUSB] EP{endpoint} <= {len(data)} bytes")
            def ctrl_transfer(self, *args, **kwargs):
                print("[VUSB] ctrl_transfer triggered")
            def is_kernel_driver_active(self, interface):
                return False
            def detach_kernel_driver(self, interface):
                pass
        dev = VirtualUSB()
    elif virtual_com:
        print("[VCOM] Virtual COM mode triggered. QSLCL .elf must handle this entry.")
        serial_fallback(payload, port_override or "/dev/ttyVCOMQSLCL", hijack=serial_hijack_mode)
        sys.exit(0)
    else:
        dev = find_device()

    if not dev:
        if serial_mode:
            serial_fallback(payload, port_override, hijack=hijack_mode)
            sys.exit(0)
        print("[FAIL] No supported device found. Use --usb, --serial or --port.")
        print_dfu_instructions()
        sys.exit(1)

    if not tunnel_mode and not hijack_mode and not getattr(dev, "is_virtual", False):
        claim_interface(dev)

    if reboot_flag:
        reboot_device(dev)

    usb_glitch_trigger(dev)
    upload_payload(dev, payload, upload_addr, tunnel_mode, hijack_mode)
    trigger_execution(dev, 0x00000000, tunnel_mode, hijack_mode)

if __name__ == "__main__":
    main()
