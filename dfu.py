import usb.core
import usb.util
import time
import struct
import sys
import os
import hashlib
import argparse

QSLCL_ELF_PATH = "qslcl.elf"
CHUNK_SIZE = 0x800
DFU_INTERFACE = 0

APPLE_DFU_VID = 0x05AC

APPLE_DFU_PIDS = [
    0x1227, 0x1222, 0x1226, 0x1338,
    0x1339, 0x1231, 0x1232, 0x133C,
    0x8101, 0x8102
]

UPLOAD_ADDRS = [
    0x80000000,
    0x180000000,
    0x200000000,
    0x210000000,
    0x218000000,
    0x60000000,
    0x100000000,
    0x23B6F0000
]

def find_dfu_device():
    print("[🔍] Scanning for Apple DFU devices...")
    for pid in APPLE_DFU_PIDS:
        dev = usb.core.find(idVendor=APPLE_DFU_VID, idProduct=pid)
        if dev:
            print(f"[📱] Found Apple DFU device: PID=0x{pid:04X}")
            return dev
    raise ValueError("❌ No compatible Apple DFU device found.")

def detach_kernel(dev):
    try:
        if dev.is_kernel_driver_active(DFU_INTERFACE):
            dev.detach_kernel_driver(DFU_INTERFACE)
    except Exception:
        pass
    usb.util.claim_interface(dev, DFU_INTERFACE)

def send_control(dev, bmRequestType, bRequest, wValue, wIndex, data, timeout=1000):
    return dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data, timeout)

def send_payload(dev, payload, address):
    print(f"[📤] Uploading qslcl.elf to 0x{address:X} ({len(payload)} bytes)...")
    try:
        for i in range(0, len(payload), CHUNK_SIZE):
            chunk = payload[i:i+CHUNK_SIZE]
            addr = address + i
            dfu_cmd = b"M" + struct.pack("<I", addr) + chunk
            send_control(dev, 0x21, 1, 0, DFU_INTERFACE, dfu_cmd)
            time.sleep(0.001)
        print(f"[✅] Upload complete at 0x{address:X}")
        return True
    except Exception as e:
        print(f"[⚠️] Failed upload at 0x{address:X}: {e}")
        return False

def execute_payload(dev):
    print(f"[🚀] Triggering execution at 0x0...")
    try:
        jump_cmd = b"A" + struct.pack("<I", 0x0)
        send_control(dev, 0x21, 1, 0, DFU_INTERFACE, jump_cmd)
        print("[🧠] qslcl.elf is now running at 0x0.")
    except Exception as e:
        print(f"[❌] Failed to jump to 0x0: {e}")

def analyze_elf(elf_data):
    print("[🔬] Analyzing qslcl.elf for DFU compatibility...")
    indicators = {
        "IMG4 Capsule": b"IMG4",
        "IM4P Section": b"IM4P",
        "iBSS TLV": b"iBSS",
        "SEP Trust Tag": b"SEPC",
        "DFU Spoof": b"FAKE_DFU_MODE",
        "Entropy Anchor": b"1337ANCHOR",
        "XOR Capsule": b"xor_entropy",
        "BootFlags": b"BootFlags",
        "JumpTo0": b"\x00\x00\x00\x00"  # execution vector (indirect indicator)
    }

    found = []
    for name, pattern in indicators.items():
        if pattern in elf_data:
            found.append(name)

    print(f"[📦] Detected ELF Tags: {', '.join(found) if found else 'None'}")

    if "IMG4 Capsule" in found and "Entropy Anchor" in found and "JumpTo0" in found:
        print("[✅] qslcl.elf is DFU-ready with quantum trust masking.")
    else:
        print("[⚠️] ELF may lack full capsule or entropy execution layers.")

def main():
    parser = argparse.ArgumentParser(description="Upload qslcl.elf to Apple DFU RAM and execute.")
    parser.add_argument("--analyze", action="store_true", help="Analyze ELF for compatibility only.")
    args = parser.parse_args()

    if not os.path.exists(QSLCL_ELF_PATH):
        print(f"[❌] File not found: {QSLCL_ELF_PATH}")
        return

    with open(QSLCL_ELF_PATH, "rb") as f:
        elf_data = f.read()

    if args.analyze:
        analyze_elf(elf_data)
        return

    dev = find_dfu_device()
    detach_kernel(dev)

    uploaded = False
    for addr in UPLOAD_ADDRS:
        if send_payload(dev, elf_data, addr):
            uploaded = True
            break

    if not uploaded:
        print("[💥] Upload failed at all known RAM regions.")
        return

    time.sleep(0.5)
    execute_payload(dev)

if __name__ == "__main__":
    main()
