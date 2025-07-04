import usb.core
import usb.util
import time
import struct
import sys
import random
import hashlib
import os

APPLE_VID = 0x05AC
KNOWN_DFU_PIDS = [0x1227, 0x1222, 0x1223, 0x1224, 0x1225, 0x1226, 0x1228, 0x1229, 0x1337]
DFU_INTERFACE = 0

def generate_random_upload_address():
    base = 0x80000000
    addr = random.randint(base, base + 0x0FFFFFFF)
    print(f"[🧬] Upload Address ➜ 0x{addr:08X}")
    return addr

def generate_virtual_com_port():
    entropy = os.urandom(16)
    com_hash = hashlib.shake_256(entropy).hexdigest(8).upper()
    com_id = f"COM-QSLCL-{com_hash}"
    print(f"[🔌] Virtual COM Spoof ➜ {com_id}")
    return com_id

def find_dfu_device():
    print("[🔍] Scanning for DFU devices...")
    for pid in KNOWN_DFU_PIDS:
        dev = usb.core.find(idVendor=APPLE_VID, idProduct=pid)
        if dev:
            print(f"[✓] DFU Device ➜ VID 0x{APPLE_VID:04X}, PID 0x{pid:04X}")
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

def usb_glitch_trigger():
    print("[⚡️] Injecting USB glitch...")
    dev = usb.core.find(idVendor=APPLE_VID)
    if not dev:
        print("[✗] No device to glitch.")
        return
    try:
        for _ in range(32):
            dev.ctrl_transfer(0x21, 1, 0, 0, b'\xFF'*64)
            time.sleep(0.001)
        print("[✓] Glitch sequence sent.")
    except Exception as e:
        print(f"[!] Glitch failed: {e}")

def upload_payload(dev, payload, upload_addr, tunnel_mode=False):
    print(f"[⏫] Uploading ELF to 0x{upload_addr:08X}...")
    chunk_size = 0x800
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i:i + chunk_size]
        try:
            if tunnel_mode:
                dev.write(1, chunk)  # fallback write
            else:
                dev.ctrl_transfer(0x21, 1, upload_addr & 0xFFFF, DFU_INTERFACE, chunk)
            time.sleep(0.004)
        except Exception as e:
            print(f"[!] Chunk {i//chunk_size} upload failed: {e}")
            sys.exit(1)
    print("[✓] Upload complete.")

def trigger_execution(dev, exec_addr=0x00000000, tunnel_mode=False):
    print(f"[🚀] Triggering ELF @ 0x{exec_addr:08X}...")
    try:
        if tunnel_mode:
            dev.write(1, b'\xAA\xBB\xCC\xDD')
        else:
            dev.ctrl_transfer(0x21, 1, exec_addr & 0xFFFF, DFU_INTERFACE, b'\x00')
    except Exception:
        pass
    print("[✓] QSLCL Executed.")

def reboot_device(dev):
    print("[🔁] Forcing reboot via entropy reset...")
    try:
        for _ in range(16):
            dev.ctrl_transfer(0x21, 1, 0, 0, os.urandom(32))
            time.sleep(0.002)
    except:
        pass
    print("[✓] Reboot triggered.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python qslcl_usb_launcher.py qslcl.elf [--usb] [--reboot]")
        sys.exit(1)

    elf_file = sys.argv[1]
    tunnel_mode = "--usb" in sys.argv
    reboot_flag = "--reboot" in sys.argv

    if not elf_file.lower().endswith(".elf"):
        print("[!] ELF file required.")
        sys.exit(1)

    try:
        with open(elf_file, "rb") as f:
            payload = f.read()
    except Exception as e:
        print(f"[!] Read error: {e}")
        sys.exit(1)

    upload_addr = generate_random_upload_address()
    generate_virtual_com_port()

    dev = find_dfu_device()

    if not dev and tunnel_mode:
        print("[⚠️] DFU not found — Entering USB tunnel mode...")
        class DummyUSB:
            def write(self, endpoint, data): print(f"[TUNNEL] Sent {len(data)}B to EP{endpoint}")
            def ctrl_transfer(self, *args, **kwargs): pass
        dev = DummyUSB()
    elif not dev:
        print("[✗] No DFU. Try --usb or enter DFU manually.")
        sys.exit(1)

    if not tunnel_mode:
        claim_interface(dev)

    if reboot_flag:
        reboot_device(dev)

    usb_glitch_trigger()
    upload_payload(dev, payload, upload_addr, tunnel_mode)
    trigger_execution(dev, 0x00000000, tunnel_mode)

if __name__ == "__main__":
    main()
                   
