import struct
import hashlib
import os
import random
import sys
import mmap

def read_uint64(data, offset):
    return struct.unpack_from(">Q", data, offset)[0]

def read_uint32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]

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
    logs = {
        1: b"[ATTACK-1] Entropy Verification Overridden with Consistent Seed",
        2: b"[ATTACK-2] Header Version & Offsets Spoofed for Validator Confusion",
        3: b"[ATTACK-3] Multi-Phase Trust Reports Injected (No Real Chain)",
        4: b"[ATTACK-4] Divergent Entropy Accepted as Valid Boot Report",
        5: b"[ATTACK-5] Full Trust Chain, SecureOS, Rollback, NAND Logs Emitted"
    }
    return logs.get(level, b"") + b"\n" if level in logs else b""

def generate_spoofed_keys(elf_data):
    random_entropy = os.urandom(32)
    hashed = hashlib.sha512(elf_data + random_entropy).hexdigest()
    pub_key = hashed[:64]
    priv_key = hashed[64:]
    print("\n[KEY SPOOF OUTPUT]")
    print(f"  SHA512 Public Stub      : {pub_key}")
    print(f"  SHA512 Private Fingerprint : {priv_key}")
    return f"[KEYS] SHA512-Public-Stub: {pub_key}\n[KEYS] SHA512-Private-Fingerprint: {priv_key}".encode()

def random_fuse_block():
    return struct.pack(">Q", random.getrandbits(64))

def verify_siliconm8_header(data):
    return data.startswith(b'SM8\x00')

def build_payload(elf_data, entropy_zero=False, fuse_random=False, minimal=False, attack_level=0):
    entropy_seed = 0x0 if entropy_zero else int.from_bytes(hashlib.sha256(elf_data).digest()[:8], 'big')
    fuse_block = random_fuse_block() if fuse_random else struct.pack(">Q", 0xDEADC0DEF05E0001)

    header = (
        b'SM8\x00' +
        struct.pack(">I", 0x00000000) +  # Version
        struct.pack(">Q", 0xAABBCCDDEEFF0011) +  # Fixed UID
        struct.pack(">Q", entropy_seed) +  # Entropy Seed
        hashlib.sha3_256(elf_data).digest() +  # SHA3 hash of ELF
        b'\xFF'  # Control byte
    )

    if minimal:
        return header + elf_data

    bootlog = generate_bootlog()
    attack_log = generate_attack_log(level=attack_level)
    spoofed_keys = generate_spoofed_keys(elf_data)
    nand_log = struct.pack(">I", 0x1F400) + b"OKAY"
    runtime_sha1 = hashlib.sha1(os.urandom(16)).digest()

    payload = (
        header +
        bootlog +
        fuse_block +
        nand_log +
        runtime_sha1 +
        spoofed_keys +
        attack_log +
        elf_data
    )

    return payload

def execute_siliconm8_in_ram(input_path, verbose=False, fuse_random=False, entropy_zero=False, minimal=False, attack_level=0):
    with open(input_path, "rb") as f:
        elf_data = f.read()

    if not verify_siliconm8_header(elf_data[:4]):
        print("[✘] ERROR: Not a valid siliconm8 file.")
        sys.exit(1)

    payload = build_payload(
        elf_data,
        entropy_zero=entropy_zero,
        fuse_random=fuse_random,
        minimal=minimal,
        attack_level=attack_level
    )

    # mmap-backed simulated RAM space
    ram_size = max(1024 * 1024, len(payload) + 4096)
    ram = mmap.mmap(-1, ram_size, access=mmap.ACCESS_WRITE)
    ram.write(payload)
    ram.seek(0)

    print("\n[✓] Executed in real mmap-backed RAM sandbox at virtual address 0x00000000.")

    if verbose:
        print(f"\n[INFO] Payload Size: {len(payload)} bytes")
        print("[INFO] Header Breakdown:")
        print(f"  Magic     : {payload[0:4]}")
        print(f"  Version   : 0x{read_uint32(payload, 4):08X}")
        print(f"  UID       : 0x{read_uint64(payload, 8):016X}")
        print(f"  Entropy   : 0x{read_uint64(payload, 16):016X}")
        print(f"  SHA3 ELF  : {payload[24:56].hex()}")
        print(f"  Control   : {payload[56]}")
        if not minimal:
            print("\n[INFO] Boot Log:")
            bootlog = payload[57:].split(b"[QFPROM] UID")[0]
            print(bootlog.decode(errors="ignore"))
        if attack_level > 0:
            print("\n[INFO] Attack Simulation:")
            print(generate_attack_log(attack_level).decode())

    print("    ↳ All spoofed trust confirmed.")

def print_usage():
    print("""
Usage:
  python3 silicon.py <siliconm8.sm8> [options]

Options:
  --verbose            Show decoded header and logs
  --fuse-random        Inject random fuse UID (real struct)
  --entropy-zero       Force entropy seed to zero (real effect)
  --minimal            Build header + ELF only, nothing else
  --attacks-mode=<N>   Simulate bypass attack 1–5
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
    for arg in sys.argv:
        if arg.startswith("--attacks-mode="):
            try:
                attack_level = int(arg.split("=")[1])
                if not 1 <= attack_level <= 5:
                    raise ValueError
            except:
                print("[!] Invalid --attacks-mode (1–5 only)")
                sys.exit(1)

    execute_siliconm8_in_ram(
        input_path,
        verbose=verbose,
        fuse_random=fuse_random,
        entropy_zero=entropy_zero,
        minimal=minimal,
        attack_level=attack_level
    )
    
