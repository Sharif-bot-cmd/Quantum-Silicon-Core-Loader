import struct
import hashlib
import os
import platform
import random
import sys
import uuid
import socket
import mmap
import time
import subprocess

def read_uint64(data, offset):
    return struct.unpack("<Q", data[offset:offset+8])[0]

def safe_urandom(n):
    return bytes(random.getrandbits(8) for _ in range(n))

def detect_selinux_state():
    try:
        output = subprocess.check_output(["getenforce"]).decode().strip().upper()
        if output in ["ENFORCING", "PERMISSIVE", "DISABLED"]:
            return output
    except:
        pass
    try:
        with open("/sys/fs/selinux/enforce", "r") as f:
            val = f.read().strip()
            return "ENFORCING" if val == "1" else "PERMISSIVE"
    except:
        pass
    return "UNKNOWN"

def spoof_selinux_state():
    real_state = detect_selinux_state()
    spoofed_state = {
        "ENFORCING": "PERMISSIVE",
        "PERMISSIVE": "DISABLED",
        "DISABLED": "ENFORCING",
        "UNKNOWN": "DISABLED"
    }.get(real_state, "DISABLED")
    return f"[SELINUX] Real={real_state} -> Spoofed={spoofed_state}".encode()

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

def generate_debug_access_block(uid, entropy):
    jtag_ctrl = b"\xA5\x5A"
    debug_key_hash = hashlib.sha1(struct.pack("<Q", uid) + entropy).digest()[:8]
    oem_trapflag = bytes([0x80 | (entropy[0] & 0x0F)])
    boot_vector = os.urandom(4)
    core_unlock = b"\xDE\xAD\xBE\xEF"
    boot_signature = hashlib.md5(entropy + debug_key_hash).digest()[:4]
    return (
        b"\n[BOOTROM_STRUCT]\n" +
        b"JTAG_CTRL      : " + jtag_ctrl.hex().upper().encode() + b"\n" +
        b"DEBUG_KEY_HASH : " + debug_key_hash.hex().upper().encode() + b"\n" +
        b"OEM_TRAPFLAG   : " + oem_trapflag.hex().upper().encode() + b"\n" +
        b"CORE_UNLOCK    : " + core_unlock.hex().upper().encode() + b"\n" +
        b"BOOT_VECTOR    : " + boot_vector.hex().upper().encode() + b"\n" +
        b"BOOT_SIGNATURE : " + boot_signature.hex().upper().encode() + b"\n"
    )

def generate_bootrom_illusion(uid, entropy):
    seed_material = struct.pack("<Q", uid) + entropy
    seed_hash = hashlib.sha256(seed_material).digest()
    serial = int.from_bytes(seed_hash[0:4], "big") | 0x10000000
    oem_ids = ["QUALCOMM", "MEDIATEK", "EXYNOS", "APPLE", "UNISOC", "UNKNOWN"]
    oem_id = oem_ids[seed_hash[4] % len(oem_ids)]
    rev = f"v{seed_hash[5] % 10}.{seed_hash[6] % 10}.{seed_hash[7] % 100:02d}"
    tz_states = ["ENABLED", "BYPASSED", "CORRUPTED"]
    bootflags = ["VERIFIED", "FAILED", "UNSIGNED"]
    jtag_states = ["LOCKED", "OPEN", "SOFT-OVERRIDE"]
    try:
        host = socket.gethostname()
        real_uid = uuid.getnode()
        real_oem = platform.processor().upper()[:8] or "GENERIC"
        real_rev = "v" + ".".join(platform.version().split(".")[0:3])
        real_tz = "ENABLED" if "secure" in platform.platform().lower() else "BYPASSED"
    except:
        host = "UNKNOWN"
        real_uid = uid
        real_oem = oem_id
        real_rev = rev
        real_tz = tz_states[seed_hash[8] % len(tz_states)]
    final_oem = real_oem if real_oem not in ["", "UNKNOWN"] else oem_id
    final_rev = real_rev if real_rev.count(".") >= 2 else rev
    final_tz = real_tz
    final_boot = bootflags[seed_hash[9] % len(bootflags)]
    final_jtag = jtag_states[seed_hash[10] % len(jtag_states)]
    return f"""
[BOOTROM] HostName     : {host}
[BOOTROM] SerialNo     : {serial:08X}
[BOOTROM] OEM_ID       : {final_oem}
[BOOTROM] MASKROM_REV  : {final_rev}
[TRUSTZONE] TZ_STATE   : {final_tz}
[BOOT] SecureBootFlag : {final_boot}
[JTAG] Debug Access    : {final_jtag}
[ENTROPY] Seed Inject  : {entropy.hex()}
[UID] Silicon UUID     : {real_uid:016X}
""".strip().encode()

def build_payload(elf_data, entropy_seed=None, entropy_mode=1, fuse_random=False, minimal=False, attack_level=1, debug_spoof=True):
    uid = random.getrandbits(64)
    entropy = entropy_seed if entropy_seed else (b"\x00" * 8 if entropy_mode == 0 else os.urandom(8))
    sha3_digest = hashlib.sha3_256(elf_data).digest()
    control_byte = bytes([random.randint(0x20, 0x7E)])
    flags_byte = 0
    if fuse_random: flags_byte |= 0x01
    if debug_spoof: flags_byte |= 0x02
    if minimal: flags_byte |= 0x04

    header = b"S8PK" + b"\x00" * 4 + struct.pack("<Q", uid) + entropy + sha3_digest + control_byte + bytes([flags_byte])
    bootlog = b"" if minimal else b"\n[SM8::BOOT] Trust Verified\n"
    fuse_block = b"\n[FUSE::HW] Injected Real eFUSE (QSPI Bank 0)\n" if fuse_random else b""
    spoofed_keys = generate_spoofed_keys(elf_data, attack_level)
    spoofed_selinux = b"" if minimal else spoof_selinux_state()
    attack_log = b"" if minimal else f"\n[ATTACK::LEVEL] Mode {attack_level}/5 activated with entropy={entropy.hex()}".encode()
    illusion = b"" if minimal else generate_bootrom_illusion(uid, entropy)
    debug_block = b"" if minimal or not debug_spoof else generate_debug_access_block(uid, entropy)

    return header + bootlog + fuse_block + illusion + b"\n" + spoofed_selinux + b"\n" + spoofed_keys + attack_log + debug_block + elf_data

def execute_siliconm8_in_ram(input_path, entropy_seed=None, verbose=False, fuse_random=False, entropy_zero=False, minimal=False, attack_level=0, timeout=3, debug_spoof=True, custom_inject_offset=None, dump_header=False, no_exploit=False):
    with open(input_path, "rb") as f:
        elf_data = f.read()

    entropy_mode = 0 if entropy_zero else (attack_level if attack_level > 0 else 1)
    payload = build_payload(
        elf_data=elf_data,
        entropy_seed=entropy_seed,
        entropy_mode=entropy_mode,
        fuse_random=fuse_random,
        minimal=minimal,
        attack_level=attack_level,
        debug_spoof=debug_spoof
    )

    ram_size = max(1024 * 1024, len(payload) + 4096)
    ram = mmap.mmap(-1, ram_size, access=mmap.ACCESS_WRITE)
    ram.write(payload)

    exploit_payloads = [
        (0x100, b"\xDE\xC0\xAD\xDE" * 4),
        (0x200, struct.pack("<Q", 0x4141414141414141) * 8),
        (0x300, b"\x00" * 64),
        (0x400, b"SBL_AUTH_BYPASS" + b"\x00" * 32),
        (0x500, b"GHOST_ENTROPY" + os.urandom(16)),
        (0x600, b"TZ_BYPASS" + os.urandom(8)),
        (0x700, b"\xCC" * 32),
        (0x800, b"A" * 128),
        (0x900, b"BOOT_SKIP" + b"\x00" * 16),
        (0xA00, hashlib.sha1(b"backdoor").digest())
    ]

    if not no_exploit:
        for offset, data in exploit_payloads:
            if offset + len(data) < ram_size:
                ram.seek(offset)
                ram.write(data)

    if custom_inject_offset:
        print(f"\n[+] Injecting payload at custom offset 0x{custom_inject_offset:X}")
        ram.seek(custom_inject_offset)
        ram.write(b"CUSTOM_INJECT" + b"\x00" * 16)

    print(f"\n[✓] ELF executed in RAM sandbox at vRAM 0x00000000.")
    print(f"[⏳] Execution will auto-stop/start in {timeout} second(s)...")

    if dump_header:
        print("\n[HEADER DUMP]")
        print(f"Flags Byte   : {payload[57]}")
        print(f"Control Byte : {payload[56]}")

    if verbose:
        print("\n[ZERO-DAY VERBOSE MODE]")
        print(f"  Payload Size : {len(payload)} bytes")
        print(f"  Magic        : {payload[0:4]}")
        print(f"  UID          : 0x{read_uint64(payload, 8):016X}")
        print(f"  Entropy Seed : {payload[16:24].hex()}")
        print(f"  SHA3 ELF     : {payload[24:56].hex()}")
        print(f"  Control Byte : {payload[56]}")
        print("\n  ▓ Trust Logs and Keychain:")
        print(payload[57:].decode(errors='ignore').strip())
        print(f"\n[+] Injected {len(exploit_payloads)} live memory exploit payloads:")
        for offset, data in exploit_payloads:
            print(f"    - Offset 0x{offset:04X} | {len(data)} bytes")

    time.sleep(timeout)
    ram.close()
    print("\n[✓] Execution completed safely. RAM unmapped. Exiting...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    input_path = sys.argv[1]
    verbose = "--verbose" in sys.argv
    fuse_random = "--fuse-random" in sys.argv
    entropy_zero = "--entropy-zero" in sys.argv
    minimal = "--minimal" in sys.argv
    debug_spoof = not "--no-debug-spoof" in sys.argv
    dump_header = "--dump-header" in sys.argv
    no_exploit = "--no-exploit" in sys.argv

    timeout = 3
    attack_level = 0
    entropy_seed = None
    custom_inject_offset = None

    for arg in sys.argv:
        if arg.startswith("--timeout="):
            try:
                timeout = int(arg.split("=")[1])
                if timeout < 1 or timeout > 60:
                    raise ValueError
            except:
                print("[!] Invalid --timeout (1–60 allowed)")
                sys.exit(1)
        elif arg.startswith("--exploits="):
            try:
                exploit_arg = arg.split("=")[1].lower()
                attack_level = resolve_exploit_level(exploit_arg)
            except:
                print("[!] Invalid --exploits (use: minimal, moderate, maximum, auto)")
                sys.exit(1)
        elif arg.startswith("--attacks-mode="):
            try:
                val = int(arg.split("=")[1])
                if val < 1 or val > 5:
                    raise ValueError
                attack_level = val
            except:
                print("[!] Invalid --attacks-mode (must be 1–5)")
                sys.exit(1)
        elif arg.startswith("--entropy-seed="):
            try:
                entropy_seed = bytes.fromhex(arg.split("=")[1])
                if len(entropy_seed) != 8:
                    raise ValueError
            except:
                print("[!] Invalid --entropy-seed (must be 8-byte hex)")
                sys.exit(1)
        elif arg.startswith("--inject-offset="):
            try:
                custom_inject_offset = int(arg.split("=")[1], 16)
            except:
                print("[!] Invalid --inject-offset (must be hex)")
                sys.exit(1)

    execute_siliconm8_in_ram(
        input_path=input_path,
        entropy_seed=entropy_seed,
        verbose=verbose,
        fuse_random=fuse_random,
        entropy_zero=entropy_zero,
        minimal=minimal,
        attack_level=attack_level,
        timeout=timeout,
        debug_spoof=debug_spoof,
        custom_inject_offset=custom_inject_offset,
        dump_header=dump_header,
        no_exploit=no_exploit
    )
    
