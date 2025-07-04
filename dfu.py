import usb.core
import usb.util
import time
import struct
import sys
import random
import hashlib
import os

# ⚙️ Known Apple DFU VID
APPLE_VID = 0x05AC

# 🔍 Common DFU PIDs (Extendable)
KNOWN_DFU_PIDS = [
    0x1227, 0x1222, 0x1223, 0x1224,
    0x1225, 0x1226, 0x1228, 0x1229,
    0x1337
]

DFU_INTERFACE = 0  # DFU mode interface index

def generate_random_upload_address():
    # Safe high RAM range (can vary per SoC)
    base = 0x80000000
    addr = random.randint(base, base + 0x0FFFFFFF)
    print(f"[🧬] Random Upload Address ➜ 0x{addr:08X}")
    return addr

def generate_virtual_com_port():
    entropy = os.urandom(16)
    com_hash = hashlib.shake_256(entropy).hexdigest(8).upper()
    com_id = f"COM-QSLCL-{com_hash}"
    print(f"[🔌] Virtual COM Port Spoof ➜ {com_id}")
    return com_id

def find_dfu_device():
    print("[🔍] Scanning for Apple DFU devices...")
    for pid in KNOWN_DFU_PIDS:
        dev = usb.core.find(idVendor=APPLE_VID, idProduct=pid)
        if dev:
            print(f"[✓] DFU Found ➜ VID 0x{APPLE_VID:04X}, PID 0x{pid:04X}")
            return dev
    print("[!] No DFU device detected. Hold Power + Volume Down.")
    sys.exit(1)

def claim_interface(dev):
    try:
        if dev.is_kernel_driver_active(DFU_INTERFACE):
            dev.detach_kernel_driver(DFU_INTERFACE)
        usb.util.claim_interface(dev, DFU_INTERFACE)
    except Exception as e:
        print(f"[!] Interface claim failed: {e}")
        sys.exit(1)

def upload_payload(dev, payload, upload_addr):
    print(f"[⏫] Uploading ELF to 0x{upload_addr:08X}...")
    chunk_size = 0x800
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        try:
            # Future-proof: attach address as wValue in ctrl_transfer (ignored by Apple but may spoof stack)
            dev.ctrl_transfer(0x21, 1, upload_addr & 0xFFFF, DFU_INTERFACE, chunk)
            time.sleep(0.005)
        except Exception as e:
            print(f"[!] Upload failed at chunk {i//chunk_size}: {e}")
            sys.exit(1)
    print("[✓] Upload complete.")

def trigger_execution(dev, exec_addr=0x00000000):
    print(f"[🚀] Triggering ELF execution at 0x{exec_addr:08X}...")
    try:
        dev.ctrl_transfer(0x21, 1, exec_addr & 0xFFFF, DFU_INTERFACE, b'\x00')
    except Exception:
        pass  # Reboot or detach expected
    print("[✓] QSLCL Mode Triggered.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python dfu_qslcl_uploader.py qslcl.elf")
        sys.exit(1)

    elf_file = sys.argv[1]
    if not elf_file.lower().endswith(".elf"):
        print("[!] Input must be a .elf QSLCL image (IMG4-masked).")
        sys.exit(1)

    try:
        with open(elf_file, "rb") as f:
            payload = f.read()
    except Exception as e:
        print(f"[!] Failed to read ELF file: {e}")
        sys.exit(1)

    upload_addr = generate_random_upload_address()
    com_spoof = generate_virtual_com_port()

    dev = find_dfu_device()
    claim_interface(dev)
    upload_payload(dev, payload, upload_addr)
    trigger_execution(dev)

if __name__ == "__main__":
    main()
    
