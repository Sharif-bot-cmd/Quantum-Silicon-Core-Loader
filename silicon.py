import struct
import hashlib
import time
import os
import random
import sys

def generate_fake_bootlog():
    log = [
        "[BOOTROM] Init: SM8 Chain v1.0",
        "[TRUSTZONE] SHA3 Verified",
        "[FUSE] Secure Boot: Enabled",
        "[FUSE] Debug Boot: Disabled",
        "[QFPROM] UID: AABB-CCDD-EEFF-0011",
        "[NAND] Write Sector: 0x1F400 - Status: OK",
        "[RPM] Entropy Lock Passed",
        "[SM8] Mirage Execution: Success",
        "[SECURE OS] Trust Drift Tolerance: 0.97",
        "[DFU] Handshake Complete - Image Accepted"
    ]
    return "\n".join(log).encode()

def random_fuse_block():
    return struct.pack(">Q", random.getrandbits(64))

def convert_qslcl_to_siliconm8(input_path, output_path,
                                dry_run=False, verbose=False,
                                fuse_random=False, entropy_zero=False,
                                minimal=False):

    with open(input_path, "rb") as f:
        elf_data = f.read()

    # Core values
    magic = b'SM8\x00'
    entry_point = 0x00000000
    uid_mask = 0xAABBCCDDEEFF0011

    entropy_seed = (0x0000000000000000 if entropy_zero
                    else int.from_bytes(hashlib.sha256(elf_data).digest()[:8], 'big'))
    sha3_hash = hashlib.sha3_256(elf_data).digest()
    trust_score = b'\xFF'

    header = (
        magic +
        struct.pack(">I", entry_point) +
        struct.pack(">Q", uid_mask) +
        struct.pack(">Q", entropy_seed) +
        sha3_hash +
        trust_score
    )

    # Optional hallucination payloads
    if not minimal:
        bootlog = generate_fake_bootlog()
        fuse_block = random_fuse_block() if fuse_random else struct.pack(">Q", 0xDEADC0DEF05E0001)
        nand_block_meta = struct.pack(">I", 0x1F400) + b"OKAY"
        drift_hash = hashlib.sha1(os.urandom(16)).digest()

        sm8_binary = (
            header +
            bootlog +
            fuse_block +
            nand_block_meta +
            drift_hash +
            elf_data
        )
    else:
        sm8_binary = header + elf_data

    if verbose:
        print("\n[INFO] siliconm8 Header:")
        print(f"  Magic        : {magic}")
        print(f"  Entry Point  : 0x{entry_point:08X}")
        print(f"  UID Mask     : 0x{uid_mask:016X}")
        print(f"  Entropy Seed : {entropy_seed}")
        print(f"  SHA3 Hash    : {sha3_hash.hex()}")
        print(f"  Trust Score  : {trust_score.hex()}")
        if not minimal:
            print("\n[INFO] Simulated Boot Log:")
            print(generate_fake_bootlog().decode())
            print()

    if not dry_run:
        with open(output_path, "wb") as f_out:
            f_out.write(sm8_binary)
        print(f"[✓] siliconm8 created: {output_path}")
    else:
        print("[DRY RUN] File was not written.")

def print_usage():
    print("\nUsage:")
    print("  python3 convert_to_siliconm8.py <input.elf> <output.sm8> [options]")
    print("\nOptions:")
    print("  --dry-run        Don’t write the .sm8 file")
    print("  --verbose        Print internal info + bootlog")
    print("  --simulate       Print hallucinated boot log only")
    print("  --fuse-random    Generate random fake fuse block")
    print("  --entropy-zero   Disable entropy randomness (static seed)")
    print("  --minimal        Header + ELF only (no hallucinated parts)")
    print("\nExamples:")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --dry-run --verbose")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --fuse-random --entropy-zero")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --minimal")
    print("  python3 convert_to_siliconm8.py ignore ignore --simulate\n")

if __name__ == "__main__":
    if "--simulate" in sys.argv:
        print(generate_fake_bootlog().decode())
        sys.exit(0)

    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Flags
    dry_run = "--dry-run" in sys.argv
    verbose = "--verbose" in sys.argv
    fuse_random = "--fuse-random" in sys.argv
    entropy_zero = "--entropy-zero" in sys.argv
    minimal = "--minimal" in sys.argv

    convert_qslcl_to_siliconm8(
        input_path, output_path,
        dry_run=dry_run,
        verbose=verbose,
        fuse_random=fuse_random,
        entropy_zero=entropy_zero,
        minimal=minimal
    )
