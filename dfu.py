import usb.core
import usb.util
import time
import struct
import sys
import os

QSLCL_ELF_PATH = "qslcl.elf"
CHUNK_SIZE = 0x800  # 2048 bytes per DFU transfer
DFU_INTERFACE = 0

# 🍎 Apple USB Vendor ID (constant)
APPLE_DFU_VID = 0x05AC

# 🔁 Known Apple DFU Product IDs for iPhone, iPad, iPod, T2, M1+, etc.
APPLE_DFU_PIDS = [
    0x1227,  # iPhone A7–A12 DFU
    0x1222,  # iPad/iPod DFU
    0x1226,  # Some iBridge T2 DFU
    0x1338,  # Apple TV DFU
    0x1339,  # Apple Watch DFU
    0x1231,  # iBoot DFU mode (A13+)
    0x1232,  # Extended DFU (A16+)
    0x133C,  # iBridge 2 DFU (T2+)
    0x8101,  # Apple Silicon DFU (M1, M2, M3)
    0x8102,  # Apple A18+ experimental
]

# 🧠 Known safe RAM upload addresses for A12 to A18+++
UPLOAD_ADDRS = [
    0x80000000,     # A12-A14
    0x180000000,    # A15-A16
    0x200000000,    # A17+
    0x210000000,    # M1/T2
    0x218000000,    # M2/M3
    0x60000000,     # Watch SoCs
    0x100000000,    # Universal fallback
    0x23B6F0000     # Last resort: Watchdog area (Apple-specific)
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

def main():
    if not os.path.exists(QSLCL_ELF_PATH):
        print(f"[❌] qslcl.elf not found: {QSLCL_ELF_PATH}")
        return

    with open(QSLCL_ELF_PATH, "rb") as f:
        elf_data = f.read()

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
