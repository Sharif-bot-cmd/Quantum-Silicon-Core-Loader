import struct
import hashlib
import time
import os
import random
import sys

def generate_bootlog():
    log = [
        "[BOOTROM] Init: SM8 Chain v1.0",
        "[TRUSTZONE] SHA3 Verified",
        "[FUSE] Secure Boot: Enabled",
        "[FUSE] Debug Boot: Disabled",
        "[QFPROM] UID: AABB-CCDD-EEFF-0011",
        "[NAND] Write Sector: 0x1F400 - Status: OK",
        "[RPM] Entropy Lock Passed",
        "[SM8] Execution Complete",
        "[SECURE OS] Drift Tolerance: 0.97",
        "[DFU] Handshake Complete - Image Accepted"
    ]
    return "\n".join(log).encode()

def generate_attack_log(level=1):
    levels = {
        1: [b"[ATTACK-1] Basic Entropy Bypass"],
        2: [b"[ATTACK-2] Header Obfuscation Enabled"],
        3: [b"[ATTACK-3] Recursive Trust Pattern Injection"],
        4: [b"[ATTACK-4] Signature Drift Response Emulated"],
        5: [b"[ATTACK-5] Full Chain Execution Reported"]
    }
    return b"\n".join(levels.get(level, [])) + b"\n" if level in levels else b""

def random_fuse_block():
    return struct.pack(">Q", random.getrandbits(64))

def convert_qslcl_to_siliconm8(input_path, output_path,
                                dry_run=False, verbose=False,
                                fuse_random=False, entropy_zero=False,
                                minimal=False, attack_level=0):

    with open(input_path, "rb") as f:
        elf_data = f.read()

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

    if not minimal:
        bootlog = generate_bootlog()
        fuse_block = random_fuse_block() if fuse_random else struct.pack(">Q", 0xDEADC0DEF05E0001)
        nand_block_meta = struct.pack(">I", 0x1F400) + b"OKAY"
        drift_hash = hashlib.sha1(os.urandom(16)).digest()
        attack_log = generate_attack_log(level=attack_level) if attack_level > 0 else b""

        sm8_binary = (
            header +
            bootlog +
            fuse_block +
            nand_block_meta +
            drift_hash +
            attack_log +
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
            print("\n[INFO] Boot Log:")
            print(generate_bootlog().decode())
            if attack_level > 0:
                print("[INFO] Attack Report:")
                print(generate_attack_log(level=attack_level).decode())

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
    print("  --dry-run            Do not write the .sm8 file")
    print("  --verbose            Show header and bootlog info")
    print("  --simulate           Print boot log only")
    print("  --fuse-random        Use a randomized fuse block")
    print("  --entropy-zero       Use static entropy value")
    print("  --minimal            Output only header + ELF (no metadata/logs)")
    print("  --attacks-mode <N>   Include attack mode log (1–5)")
    print("\nExamples:")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --verbose")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --attacks-mode 3")
    print("  python3 convert_to_siliconm8.py qslcl.elf q.sm8 --dry-run --verbose")
    print("  python3 convert_to_siliconm8.py ignore ignore --simulate\n")

if __name__ == "__main__":
    if "--simulate" in sys.argv:
        print(generate_bootlog().decode())
        sys.exit(0)

    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    dry_run = "--dry-run" in sys.argv
    verbose = "--verbose" in sys.argv
    fuse_random = "--fuse-random" in sys.argv
    entropy_zero = "--entropy-zero" in sys.argv
    minimal = "--minimal" in sys.argv

    # Extract attack level if set
    attack_level = 0
    for arg in sys.argv:
        if arg.startswith("--attacks-mode"):
            try:
                attack_level = int(arg.split("=")[1])
                if not 1 <= attack_level <= 5:
                    raise ValueError
            except:
                print("[!] Invalid --attacks-mode (must be 1–5)")
                sys.exit(1)

    convert_qslcl_to_siliconm8(
        input_path, output_path,
        dry_run=dry_run,
        verbose=verbose,
        fuse_random=fuse_random,
        entropy_zero=entropy_zero,
        minimal=minimal,
        attack_level=attack_level
    )
    
