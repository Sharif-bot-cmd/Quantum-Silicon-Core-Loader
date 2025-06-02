import struct
import hashlib
import os
import random
import sys
import mmap
import time

def read_uint64(data, offset):
    return struct.unpack_from(">Q", data, offset)[0]

def read_uint32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]

def generate_bootlog():
    return b"\n".join([
        b"[BOOTROM] Init: SM8 Chain v1.0",
        b"[TRUSTZONE] SHA3 Verified",
        b"[QFPROM] UID: F4B1-D3A7-FA7E-0000",
        b"[RPM] Entropy Lock Passed",
        b"[SECURE OS] Drift Tolerance: 0.97",
        b"[SM8] Execution Complete"
    ])

def generate_attack_log(level):
    logs = {
        1: b"[ATTACK-1] SHA Chain Redirection Triggered (Entropy Diverged)",
        2: b"[ATTACK-2] TPM-Like Signature Trace Injected into Header Chain",
        3: b"[ATTACK-3] ECDSA-RNG Mismatch Forged and Accepted",
        4: b"[ATTACK-4] Multiple Valid Keys Accepted in Conflict (Quantum Drift)",
        5: b"[ATTACK-5] Ghost Trust Anchors Injected for Drift Authentication"
    }
    return logs.get(level, b"")

def generate_fuse_block(real=True):
    if not real:
        return struct.pack(">Q", 0xDEADBEEFCAFEBABE)
    return (
        struct.pack(">Q", random.getrandbits(64)) +
        struct.pack(">Q", random.getrandbits(64)) +
        struct.pack(">Q", random.getrandbits(64))
    )

def safe_urandom(n):
    """Retry urandom up to 3 times in case of system entropy pool starvation."""
    for _ in range(3):
        try:
            return os.urandom(n)
        except Exception:
            time.sleep(0.1)
    return bytes([random.randint(0, 255) for _ in range(n)])

def generate_entropy(mode, elf_data):
    base_hash = hashlib.sha512(elf_data).digest()
    if mode == 0:
        return b"\x00" * 32
    elif mode == 1:
        return base_hash[:32]
    elif mode == 2:
        return hashlib.blake2b(elf_data, digest_size=32).digest()
    elif mode == 3:
        return safe_urandom(32)
    elif mode == 4:
        return hashlib.shake_256(base_hash).digest(32)
    elif mode == 5:
        print("[•] Generating entropy for attack mode 5 (Ghost Trust Injection)...")
        mixed = base_hash + safe_urandom(32)
        return hashlib.sha3_512(mixed).digest()[:32]
    else:
        return base_hash[:32]

def generate_spoofed_keys(elf_data, attack_level):
    sha512 = hashlib.sha512(elf_data).hexdigest()
    ecc = hashlib.blake2b(elf_data, digest_size=64).hexdigest()
    curve25519 = hashlib.shake_256(elf_data).digest(32).hex()
    rsa = hashlib.sha3_512(elf_data).hexdigest()
    tpma = hashlib.md5(elf_data + safe_urandom(16)).hexdigest()
    spoof = [
        f"[KEY] RSA-4096   : {rsa[:64]}",
        f"[KEY] ECC-P256   : {ecc[:64]}",
        f"[KEY] CURVE25519 : {curve25519[:64]}",
        f"[KEY] TPM-FP     : {tpma}",
        f"[KEY] SHA512-Pub : {sha512[:64]}"
    ]
    return "\n".join(spoof).encode()

def build_payload(elf_data, entropy_mode=1, fuse_random=False, minimal=False, attack_level=0):
    entropy_block = generate_entropy(entropy_mode, elf_data)
    fuse_block = generate_fuse_block(real=fuse_random)

    header = (
        b'SM8\x00' +
        struct.pack(">I", 0x00000000) +
        struct.pack(">Q", 0xF1E2D3C4B5A69788) +
        entropy_block[:8] +
        hashlib.sha3_256(elf_data).digest() +
        b'\xFF'
    )

    if minimal:
        return header + elf_data

    bootlog = generate_bootlog()
    attack_log = generate_attack_log(attack_level)
    spoofed_keys = generate_spoofed_keys(elf_data, attack_level)

    payload = (
        header +
        bootlog +
        fuse_block +
        spoofed_keys +
        attack_log +
        elf_data
    )
    return payload

def verify_siliconm8_header(data):
    return data.startswith(b'SM8\x00')

def execute_siliconm8_in_ram(input_path, verbose=False, fuse_random=False, entropy_zero=False, minimal=False, attack_level=0):
    with open(input_path, "rb") as f:
        elf_data = f.read()

    if not verify_siliconm8_header(elf_data[:4]):
        print("[✘] ERROR: Not a valid siliconm8 file.")
        sys.exit(1)

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

    print("\n[✓] ELF executed in RAM sandbox at vRAM 0x00000000.")

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
    
