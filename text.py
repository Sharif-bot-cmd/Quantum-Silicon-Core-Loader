import mmap
import os
import struct
import hashlib

# Partition Info (2048 KB FSG)
NUM_SECTORS = 4096
SECTOR_SIZE = 512
PART_SIZE = NUM_SECTORS * SECTOR_SIZE  # = 0x200000
START_ADDR = 0x6D2BD000                # From rawprogram0.xml
DUMP_DEST_OFFSET = 0x0          # You can customize (tool offset)

FUSE_ADDR = 0x5FA91000                # Simulated eFUSE
EXPECTED_FUSE = hashlib.sha256(b"fsg_unlock_key").digest()
QSLCL_ELF_PATH = "qslcl.elf"

# Initialize RAM
def init_ram(size):
    return mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)

# Inject ELF at 0x0
def inject_qslcl_elf(ram):
    if not os.path.exists(QSLCL_ELF_PATH):
        raise FileNotFoundError(f"Missing: {QSLCL_ELF_PATH}")
    elf = open(QSLCL_ELF_PATH, "rb").read()
    ram.seek(0)
    ram.write(elf)
    print(f"[⚡] Injected ELF ({len(elf)} bytes) @ 0x0")

# Inject fake eFUSE unlock pattern
def inject_fuse(ram):
    ram.seek(FUSE_ADDR)
    ram.write(EXPECTED_FUSE)
    print(f"[🔐] Injected simulated FUSE unlock at 0x{FUSE_ADDR:X}")

# Check trust access before writing
def check_fuse(ram):
    ram.seek(FUSE_ADDR)
    val = ram.read(32)
    return val == EXPECTED_FUSE

# Real entropy block fill (trust-based)
def entropy_block(entropy, offset):
    return hashlib.shake_256(entropy + struct.pack("<I", offset)).digest(SECTOR_SIZE)

# Clean FSG injection: no skip, start from 0x0
def inject_full_fsg(ram, entropy):
    print(f"[🧬] Injecting full FSG (0x0 → 0x{PART_SIZE:X}) with entropy...")
    for i in range(NUM_SECTORS):
        offset = START_ADDR + i * SECTOR_SIZE
        ram.seek(offset)
        ram.write(entropy_block(entropy, offset))
    print(f"[✔] Done writing FSG into memory.")

# Dump with offset (for rawprogram-style layout)
def dump_fsg(ram, outfile, dump_offset):
    ram.seek(START_ADDR)
    raw = ram.read(PART_SIZE)
    if raw.count(b"\x00") >= PART_SIZE * 0.95:
        print("[❌] Dump failed: mostly zeroes — fuse might be missing.")
        return
    full = b"\x00" * dump_offset + raw
    with open(outfile, "wb") as f:
        f.write(full)
    print(f"[📦] Dump saved to: {outfile} ({len(full)} bytes)")
    print(f"[📏] Real FSG size: 0x{PART_SIZE:X} | Offset in file: 0x{dump_offset:X}")

# Main
def main():
    ram_size = START_ADDR + PART_SIZE + 0x10000
    ram = init_ram(ram_size)

    inject_qslcl_elf(ram)
    inject_fuse(ram)

    if check_fuse(ram):
        entropy = hashlib.sha256(b"qslcl_fsg_entropy_unlock_clean").digest()
        inject_full_fsg(ram, entropy)
        dump_fsg(ram, "fsg_clean_dump.bin", dump_offset=DUMP_DEST_OFFSET)
    else:
        print("[🛑] FUSE check failed. Aborting FSG dump.")

    ram.close()
    print("[✔] RAM sandbox closed.")

if __name__ == "__main__":
    main()
