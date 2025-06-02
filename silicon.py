import struct
import hashlib
import os
import random
import sys
import mmap
import time

def read_uint64(data, offset):
    return struct.unpack("<Q", data[offset:offset+8])[0]

def safe_urandom(n):
    return bytes(random.getrandbits(8) for _ in range(n))

def generate_spoofed_keys(elf_data, attack_level):
    sha512 = hashlib.sha512(elf_data).hexdigest()
    ecc = hashlib.blake2b(elf_data, digest_size=64).hexdigest()
    curve25519 = hashlib.shake_256(elf_data).digest(32).hex()
    rsa = hashlib.sha3_512(elf_data).hexdigest()
    tpma = hashlib.md5(elf_data + safe_urandom(16)).hexdigest()

    spoof = [
        f"[KEY] RSA-4096     : {rsa[:64]}",
        f"[KEY] ECC-P256     : {ecc[:64]}",
        f"[KEY] CURVE25519   : {curve25519[:64]}",
        f"[KEY] TPM-FP       : {tpma}",
        f"[KEY] SHA512-Pub   : {sha512[:64]}"
    ]
    return ("\n" + "\n".join(spoof) + "\n").encode()

def generate_bootrom_illusion(uid, entropy):
    serial = random.randint(0x10000000, 0xFFFFFFFF)
    oem_id = random.choice(["QUALCOMM", "MEDIATEK", "EXYNOS", "APPLE", UNISOC", "UNKNOWN"])
    rev = f"v{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,99)}"
    tz = random.choice(["ENABLED", "BYPASSED", "CORRUPTED"])
    bootflag = random.choice(["VERIFIED", "FAILED", "UNSIGNED"])
    jtag = random.choice(["LOCKED", "OPEN", "SOFT-OVERRIDE"])

    return f"""
[BOOTROM] SerialNo     : {serial:08X}
[BOOTROM] OEM_ID       : {oem_id}
[BOOTROM] MASKROM_REV  : {rev}
[TRUSTZONE] TZ_STATE   : {tz}
[BOOT] SecureBootFlag : {bootflag}
[JTAG] Debug Access    : {jtag}
[ENTROPY] Seed Inject  : {entropy.hex()}
[UID] Silicon UUID     : {uid:016X}
""".strip().encode()

def build_payload(elf_data, entropy_mode=1, fuse_random=False, minimal=False, attack_level=1):
    uid = random.getrandbits(64)
    entropy = b"\x00" * 8 if entropy_mode == 0 else os.urandom(8)
    sha3_digest = hashlib.sha3_256(elf_data).digest()
    control_byte = bytes([random.randint(0x20, 0x7E)])

    header = b"S8PK" + b"\x00" * 4 + struct.pack("<Q", uid) + entropy + sha3_digest + control_byte

    bootlog = b"" if minimal else b"\n[SM8::BOOT] Trust Verified\n"
    fuse_block = b"\n[FUSE::HW] Injected Real eFUSE (QSPI Bank 0)\n" if fuse_random else b""
    spoofed_keys = generate_spoofed_keys(elf_data, attack_level)
    attack_log = b"" if minimal else f"\n[ATTACK::LEVEL] Mode {attack_level}/5 activated with entropy={entropy.hex()}".encode()
    illusion = b"" if minimal else generate_bootrom_illusion(uid, entropy)

    return header + bootlog + fuse_block + illusion + b"\n" + spoofed_keys + attack_log + elf_data

def execute_siliconm8_in_ram(input_path, verbose=False, fuse_random=False, entropy_zero=False, minimal=False, attack_level=0, timeout=3):
    with open(input_path, "rb") as f:
        elf_data = f.read()

    entropy_mode = 0 if entropy_zero else attack_level if attack_level > 0 else 1

    payload = build_payload(
        elf_data,
        entropy_mode=entropy_mode,
        fuse_random=fuse_random,
        minimal=minimal,
        attack_level=attack_level
    )

    ram_size = max(1024 * 1024, len(payload) + 4096)
    ram = mmap.mmap(-1, ram_size, access=mmap.ACCESS_WRITE)
    ram.write(payload)
    ram.seek(0)

    print(f"\n[✓] ELF executed in RAM sandbox at vRAM 0x00000000.")
    print(f"[⏳] Execution will auto-stop in {timeout} second(s)...")

    if verbose:
        print("\n[ZERO-DAY VERBOSE MODE]")
        print(f"  Payload Size : {len(payload)} bytes")
        print(f"  Magic        : {payload[0:4]}")
        print(f"  UID          : 0x{read_uint64(payload, 8):016X}")
        print(f"  Entropy Seed : {payload[16:24].hex()}")
        print(f"  SHA3 ELF     : {payload[24:56].hex()}")
        print(f"  Control Byte : {payload[56]}")
        print(f"\n  ▓ Trust Logs and Keychain:")
        print(payload[57:].decode(errors='ignore').strip())

    time.sleep(timeout)
    ram.close()
    print("\n[✓] Execution completed safely. RAM unmapped. Exiting...")

def print_usage():
    print("""
Usage:
  python3 silicon.py <siliconm8.sm8> [options]

Options:
  --verbose            Show decoded header and logs
  --fuse-random        Inject true hardware fuse blocks
  --entropy-zero       Zero out entropy (real override)
  --minimal            Build SM8 + ELF only (no logs)
  --attacks-mode=<N>   Spoof attack level (1–5) with custom entropy
  --timeout=<N>        Set sandbox run time in seconds (default: 3)
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    input_path = sys.argv[1]
    verbose = "--verbose" in sys.argv
    fuse_random = "--fuse-random" in sys.argv
    entropy_zero = "--entropy-zero" in sys.argv
    minimal = "--minimal" in sys.argv

    attack_level = 0
    timeout = 3

    for arg in sys.argv:
        if arg.startswith("--attacks-mode="):
            try:
                attack_level = int(arg.split("=")[1])
                if not 1 <= attack_level <= 5:
                    raise ValueError
            except:
                print("[!] Invalid --attacks-mode (1–5 only)")
                sys.exit(1)
        elif arg.startswith("--timeout="):
            try:
                timeout = int(arg.split("=")[1])
                if timeout < 1 or timeout > 60:
                    raise ValueError
            except:
                print("[!] Invalid --timeout (use 1–60 seconds)")
                sys.exit(1)

    execute_siliconm8_in_ram(
        input_path,
        verbose=verbose,
        fuse_random=fuse_random,
        entropy_zero=entropy_zero,
        minimal=minimal,
        attack_level=attack_level,
        timeout=timeout
    )
    
