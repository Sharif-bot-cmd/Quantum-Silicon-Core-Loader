import usb.core
import usb.util
import time
import struct
import sys

# ⚙️ Known Apple DFU VID
APPLE_VID = 0x05AC

# 🔍 List of common DFU PIDs (iPhone, iPad, iPod, Apple TV, etc.)
KNOWN_DFU_PIDS = [
    0x1227, 0x1222, 0x1223, 0x1224, 0x1225,
    0x1226, 0x1228, 0x1229, 0x1337  # Extend as needed
]

DFU_INTERFACE = 0  # Default DFU interface
UPLOAD_ADDR = 0x80000000  # Arbitrary upload address
EXEC_ADDR = 0x00000000     # QSLCL runs at 0x0 (IMG4 masked inside ELF)

def find_dfu_device():
    print("[🔍] Scanning for Apple DFU devices...")
    for pid in KNOWN_DFU_PIDS:
        dev = usb.core.find(idVendor=APPLE_VID, idProduct=pid)
        if dev:
            print(f"[✓] DFU device found: VID 0x{APPLE_VID:04X}, PID 0x{pid:04X}")
            return dev
    print("[!] No DFU device found. Please enter DFU mode:")
    print("    • Hold Power + Volume Down (iPhones)")
    print("    • Use checkra1n or cable trigger if needed")
    sys.exit(1)

def claim_interface(dev):
    try:
        if dev.is_kernel_driver_active(DFU_INTERFACE):
            dev.detach_kernel_driver(DFU_INTERFACE)
        usb.util.claim_interface(dev, DFU_INTERFACE)
    except Exception as e:
        print(f"[!] Failed to claim interface: {e}")
        sys.exit(1)

def upload_payload(dev, payload):
    print(f"[⏫] Uploading QSLCL ELF capsule to RAM at 0x{UPLOAD_ADDR:08X}...")
    chunk_size = 0x800
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        try:
            dev.ctrl_transfer(0x21, 1, 0, DFU_INTERFACE, chunk)
            time.sleep(0.01)
        except Exception as e:
            print(f"[!] Upload failed at chunk {i//chunk_size}: {e}")
            sys.exit(1)
    print("[✓] ELF upload complete.")

def trigger_execution(dev):
    print(f"[🚀] Triggering execution at 0x{EXEC_ADDR:08X} (QSLCL Mode)...")
    try:
        dev.ctrl_transfer(0x21, 1, 0, DFU_INTERFACE, b'\x00')
    except Exception:
        pass  # Expected: device may reboot or drop DFU
    print("[✓] Trigger sent — QSLCL Mode should now be live.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python dfu_qslcl_uploader.py qslcl.elf")
        sys.exit(1)

    elf_file = sys.argv[1]
    if not elf_file.lower().endswith(".elf"):
        print("[!] Input must be a valid .elf file containing masked IMG4 logic.")
        sys.exit(1)

    with open(elf_file, "rb") as f:
        payload = f.read()

    dev = find_dfu_device()
    claim_interface(dev)
    upload_payload(dev, payload)
    trigger_execution(dev)

if __name__ == "__main__":
    main()
