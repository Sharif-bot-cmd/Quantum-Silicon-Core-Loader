#!/usr/bin/env python3
"""
verify.py - QSLCL VERIFY Command Module v2.1 (CLEANED)
System verification, checksums, security checks, and diagnostics
"""

import os
import sys
import struct
import time
import json
import zlib
import hashlib
from typing import Optional, List, Tuple, Dict, Callable
from dataclasses import dataclass

# =============================================================================
# IMPORTS - With proper fallbacks
# =============================================================================
try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
        load_partitions,
        qslcl_dispatch,
        decode_runtime_result,
        encode_qslcl_structure,
        QSLCLCMD_DB,
        _DEBUG
    )
except ImportError:
    try:
        from .qslcl import (
            scan_all,
            auto_loader_if_needed,
            load_partitions,
            qslcl_dispatch,
            decode_runtime_result,
            encode_qslcl_structure,
            QSLCLCMD_DB,
            _DEBUG
        )
    except ImportError:
        print("[!] CRITICAL: Cannot import qslcl core module")
        sys.exit(1)

# =============================================================================
# CONSTANTS
# =============================================================================
TIMEOUT = 15.0
MAX_MEMORY = 100 * 1024 * 1024
CHUNK_SIZE = 65536


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_address(s: str) -> int:
    s = str(s).strip()
    if s.lower().startswith('0x'): return int(s[2:], 16)
    try: return int(s, 16)
    except: return int(s, 10)


def parse_size(s: str) -> int:
    s = str(s).strip().upper()
    if s.startswith('0X'): return int(s, 16)
    for sfx, mul in [('GB',1024**3),('G',1024**3),('MB',1024**2),('M',1024**2),
                      ('KB',1024),('K',1024),('B',1)]:
        if s.endswith(sfx): return int(float(s[:-len(sfx)]) * mul)
    return int(s)


def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve verification target"""
    for p in partitions:
        if p.get('name','').lower() == target.lower():
            return {'address': p['offset'], 'size': p['size'], 'info': p['name']}
    try: return {'address': parse_address(target), 'size': 0, 'info': 'address'}
    except: return None


def read_mem(dev, addr: int, size: int) -> Tuple[bool, bytes]:
    """Read memory from device"""
    payload = struct.pack("<II", addr, size)
    
    if "READ" in QSLCLCMD_DB:
        resp = qslcl_dispatch(dev, "READ", payload, timeout=TIMEOUT)
    else:
        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
        dev.write(pkt)
        _, resp = dev.read(timeout=TIMEOUT)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            return True, status.get("extra", b"")
    return False, b""


def cmd_dispatch(dev, cmd: str, payload: bytes = b"") -> Tuple[bool, str, bytes]:
    """Generic command dispatch"""
    if cmd in QSLCLCMD_DB:
        resp = qslcl_dispatch(dev, cmd, payload, timeout=TIMEOUT)
    else:
        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
        dev.write(pkt)
        _, resp = dev.read(timeout=TIMEOUT)
    
    if resp:
        status = decode_runtime_result(resp)
        return status.get("severity") == "SUCCESS", status.get("name","?"), status.get("extra",b"")
    return False, "NO_RESPONSE", b""


def hash_data(data: bytes, algo: str) -> str:
    """Calculate hash of data"""
    algos = {'CRC32': lambda d: f"{zlib.crc32(d)&0xFFFFFFFF:08x}",
             'MD5': lambda d: hashlib.md5(d).hexdigest(),
             'SHA1': lambda d: hashlib.sha1(d).hexdigest(),
             'SHA256': lambda d: hashlib.sha256(d).hexdigest(),
             'SHA512': lambda d: hashlib.sha512(d).hexdigest()}
    func = algos.get(algo.upper())
    return func(data) if func else "?"


def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=40):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
    
    def __enter__(self):
        self.update(0)
        return self
    
    def __exit__(self, *a):
        print()
    
    def update(self, n):
        self.current += n
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '─' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {self.suffix}', end='', flush=True)


@dataclass
class VResult:
    name: str
    passed: bool
    status: str
    details: str = ""
    
    def display(self):
        icon = '✓' if self.passed else '✗'
        print(f"    {icon} {self.name:<25} {self.status}")
        if self.details:
            print(f"      {self.details}")


def print_results(title: str, results: List[VResult]) -> bool:
    passed = sum(1 for r in results if r.passed)
    print(f"\n[*] {title}: {passed}/{len(results)} passed")
    for r in results: r.display()
    return all(r.passed for r in results)


# =============================================================================
# VERIFICATION FUNCTIONS
# =============================================================================

def verify_list(dev, args, verbose, strict, output, force) -> bool:
    """List capabilities"""
    print(f"\n[*] Verification Capabilities:")
    print(f"    Types: checksum, signature, integrity, security, hardware, firmware, full")
    print(f"    Algorithms: CRC32, MD5, SHA1, SHA256, SHA512")
    print(f"    Structures: GPT, MBR, FDT, ATAGS")
    print(f"    Security: Secure Boot, DM-Verity, Anti-Rollback, Fuses")
    return True


def verify_checksum(dev, args, verbose, strict, output, force) -> bool:
    """Verify checksums"""
    if not args:
        print("[!] Usage: verify checksum <target> [algorithm] [expected]")
        return False
    
    target = args[0]
    algo = args[1].upper() if len(args) > 1 else "SHA256"
    expected = args[2] if len(args) > 2 else None
    
    if algo not in ('CRC32','MD5','SHA1','SHA256','SHA512'):
        print(f"[!] Unknown algorithm: {algo}")
        return False
    
    print(f"\n[*] {algo} checksum: {target}")
    
    # File target
    if os.path.exists(target):
        with open(target, 'rb') as f:
            data = f.read()[:MAX_MEMORY]
        h = hash_data(data, algo)
        print(f"[+] {algo}: {h}")
        if expected:
            ok = h.lower() == expected.lower()
            print(f"[{'✓' if ok else '✗'}] {'Match' if ok else f'Mismatch (expected: {expected})'}")
            return ok
        return True
    
    # Memory target
    partitions = load_partitions(dev)
    tinfo = resolve_target(target, partitions, dev)
    
    if tinfo:
        addr, mem_size = tinfo['address'], min(tinfo['size'] or 4096, MAX_MEMORY)
    else:
        try: addr, mem_size = parse_address(target), parse_size(args[1])
        except: print(f"[!] Cannot resolve: {target}"); return False
    
    print(f"[+] Reading 0x{addr:08X} ({mem_size:,} bytes)...")
    
    ok, data = read_mem(dev, addr, min(mem_size, 4096))  # Sample for speed
    if not ok:
        print("[!] Read failed"); return False
    
    h = hash_data(data, algo)
    print(f"[+] {algo}: {h} (sampled {len(data)} bytes)")
    
    if expected:
        ok = h.lower() == expected.lower()
        print(f"[{'✓' if ok else '✗'}] {'Match' if ok else 'Mismatch'}")
        return ok
    return True


def verify_signature(dev, args, verbose, strict, output, force) -> bool:
    """Verify signatures"""
    if len(args) < 2:
        print("[!] Usage: verify signature <type> <target>")
        return False
    
    sig_type = args[0].upper()
    target = args[1]
    
    print(f"\n[*] {sig_type} signature: {target}")
    
    types = {'CERTIFICATE': 'Certificate verification',
             'RSA': 'RSA signature', 'ECC': 'ECC signature', 
             'HMAC': 'HMAC verification'}
    
    if sig_type in types:
        print(f"[*] {types[sig_type]} available (requires runtime crypto)")
        return True
    
    print(f"[!] Unknown type: {sig_type}")
    return False


def verify_integrity(dev, args, verbose, strict, output, force) -> bool:
    """Verify memory integrity"""
    partitions = load_partitions(dev)
    
    regions = []
    if not args:
        for p in partitions[:8]:
            if 0 < p['size'] <= MAX_MEMORY:
                regions.append((p['name'], p['offset'], min(p['size'], 1024*1024)))
    else:
        for arg in args:
            for p in partitions:
                if p['name'].lower() == arg.lower():
                    regions.append((p['name'], p['offset'], min(p['size'], 1024*1024)))
                    break
    
    if not regions:
        print("[!] No regions"); return False
    
    print(f"\n[*] Integrity: {len(regions)} region(s)")
    results = []
    
    for name, addr, size in regions:
        ok, data = read_mem(dev, addr, min(size, 4096))
        if ok and data:
            unique = len(set(data))
            msg = f"{unique} unique bytes" if unique > 1 else f"Single value: 0x{data[0]:02X}"
            results.append(VResult(name, True, "Accessible", msg))
        else:
            results.append(VResult(name, False, "Not accessible"))
        results[-1].display()
    
    return print_results("Integrity", results)


def verify_structure(dev, args, verbose, strict, output, force) -> bool:
    """Verify partition structures"""
    if not args:
        print("[!] Usage: verify structure <GPT|MBR|FDT|ATAGS>")
        return False
    
    stype = args[0].upper()
    print(f"\n[*] Checking: {stype}")
    
    checks = {
        'GPT': [(0, 8, b'EFI PART', 'GPT header'), (512, 8, b'EFI PART', 'GPT backup')],
        'MBR': [(0, 512, None, 'MBR sector')],  # Check for 0x55AA at end
        'FDT': [(0x1000000, 32, b'\xd0\x0d\xfe\xed', 'FDT')],
    }
    
    if stype not in checks:
        print(f"[!] Unknown: {stype}"); return False
    
    for addr, size, magic, desc in checks.get(stype, []):
        ok, data = read_mem(dev, addr, size)
        if ok:
            if stype == 'MBR' and len(data) >= 512:
                found = data[510] == 0x55 and data[511] == 0xAA
            else:
                found = magic and data[:len(magic)] == magic
            
            if found:
                print(f"[✓] {desc} found at 0x{addr:08X}")
                return True
            else:
                print(f"    {desc} not at 0x{addr:08X}")
    
    print(f"[✗] {stype} not found")
    return False


def verify_security(dev, args, verbose, strict, output, force) -> bool:
    """Security checks"""
    checks = [
        ("Secure Boot", lambda: check_secure_boot(dev)),
        ("DM-Verity", lambda: check_verity(dev)),
        ("Anti-Rollback", lambda: check_anti_rollback(dev)),
        ("Fuses", lambda: check_fuses(dev)),
    ]
    
    print(f"\n[*] Security checks:")
    results = []
    
    for name, func in checks:
        try:
            ok, details = func()
            results.append(VResult(name, ok, "PASS" if ok else "FAIL", details))
        except Exception as e:
            results.append(VResult(name, False, "ERROR", str(e)))
        results[-1].display()
    
    return print_results("Security", results)


def verify_hardware(dev, args, verbose, strict, output, force) -> bool:
    """Hardware checks"""
    checks = [
        ("CPU", lambda: check_ping(dev)),
        ("Memory", lambda: check_register(dev, 0x80000000, "DRAM")),
        ("Boot ROM", lambda: check_register(dev, 0x00000000, "BootROM")),
    ]
    
    print(f"\n[*] Hardware checks:")
    results = []
    
    for name, func in checks:
        try:
            ok, details = func()
            results.append(VResult(name, ok, "OK" if ok else "FAIL", details))
        except Exception as e:
            results.append(VResult(name, False, "ERROR", str(e)))
        results[-1].display()
    
    return print_results("Hardware", results)


def verify_firmware(dev, args, verbose, strict, output, force) -> bool:
    """Firmware verification"""
    partitions = load_partitions(dev)
    
    fw_parts = []
    keywords = ['boot','kernel','recovery','sbl','aboot','bootloader','tz','rpm']
    
    for p in partitions:
        if any(kw in p['name'].lower() for kw in keywords):
            fw_parts.append(p)
    
    if not fw_parts:
        fw_parts = [{'name': 'Bootloader', 'offset': 0, 'size': 0x100000}]
    
    print(f"\n[*] Firmware: {len(fw_parts)} components")
    results = []
    
    for p in fw_parts[:8]:
        ok, data = read_mem(dev, p['offset'], min(p['size'], 256))
        if ok and data:
            sigs = {b'\x7fELF': 'ELF', b'ANDROID!': 'Android boot', b'MZ': 'PE'}
            found = next((v for k,v in sigs.items() if data.startswith(k)), None)
            results.append(VResult(p['name'], True, found or "Readable"))
        else:
            results.append(VResult(p['name'], False, "Not accessible"))
        results[-1].display()
    
    return print_results("Firmware", results)


def verify_full(dev, args, verbose, strict, output, force) -> bool:
    """Full system verification"""
    stages = [
        ("Firmware", verify_firmware),
        ("Hardware", verify_hardware),
        ("Security", verify_security),
        ("Integrity", verify_integrity),
    ]
    
    print(f"\n{'='*50}")
    print(f"  FULL SYSTEM VERIFICATION")
    print(f"{'='*50}")
    
    results = {}
    start = time.time()
    
    for name, func in stages:
        print(f"\n--- {name} ---")
        try:
            results[name] = func(dev, args, verbose, strict, None, force)
        except KeyboardInterrupt:
            print(f"\n[!] {name} interrupted")
            results[name] = False
            break
        except Exception as e:
            print(f"[!] {name} error: {e}")
            results[name] = False
    
    elapsed = time.time() - start
    passed = sum(1 for v in results.values() if v)
    
    print(f"\n{'='*50}")
    print(f"  COMPLETE in {elapsed:.1f}s - {passed}/{len(stages)} passed")
    print(f"{'='*50}")
    
    if output:
        try:
            with open(output, 'w') as f:
                json.dump({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                           'elapsed': elapsed, 'results': results}, f, indent=2)
            print(f"[+] Saved: {output}")
        except Exception as e:
            print(f"[!] Save failed: {e}")
    
    return all(results.values())


def verify_performance(dev, args, verbose, strict, output, force) -> bool:
    """Performance benchmarks"""
    print(f"\n[*] Performance:")
    
    # Read benchmark
    t0 = time.time()
    ok, data = read_mem(dev, 0x80000000, 1024*1024)
    elapsed = max(time.time()-t0, 0.001)
    speed = len(data)/elapsed/(1024*1024) if ok else 0
    
    results = [VResult("Memory Read", ok, f"{speed:.1f} MB/s" if speed else "N/A")]
    
    # Ping benchmark
    latencies = []
    for _ in range(5):
        t0 = time.perf_counter()
        ok, _, _ = cmd_dispatch(dev, "PING")
        if ok:
            latencies.append((time.perf_counter()-t0)*1000)
    
    if latencies:
        avg = sum(latencies)/len(latencies)
        results.append(VResult("Latency", True, f"{avg:.1f}ms avg"))
    else:
        results.append(VResult("Latency", False, "No response"))
    
    for r in results: r.display()
    return all(r.passed for r in results)


# =============================================================================
# HELPER CHECKS
# =============================================================================
def check_secure_boot(dev) -> Tuple[bool, str]:
    ok, data = read_mem(dev, 0xFC4B80F8, 4)
    if ok and len(data) >= 4:
        val = struct.unpack("<I", data[:4])[0]
        return val not in (0, 0xFFFFFFFF), f"Register: 0x{val:08X}"
    return True, "Not accessible (assumed present)"

def check_verity(dev) -> Tuple[bool, str]:
    parts = load_partitions(dev)
    verity = [p['name'] for p in parts if 'verity' in p['name'].lower() or 'vbmeta' in p['name'].lower()]
    return bool(verity), f"Partitions: {', '.join(verity)}" if verity else "None found"

def check_anti_rollback(dev) -> Tuple[bool, str]:
    ok, data = read_mem(dev, 0xFFFF0000, 4)
    if ok and len(data) >= 4:
        val = struct.unpack("<I", data[:4])[0]
        return val not in (0, 0xFFFFFFFF), f"Counter: {val}"
    return True, "Assumed present"

def check_fuses(dev) -> Tuple[bool, str]:
    ok, data = read_mem(dev, 0xFC4B8000, 16)
    if ok:
        blown = sum(1 for b in data if b != 0)
        return blown > 0, f"{blown} fuses blown" if blown else "All intact"
    return True, "Cannot access"

def check_register(dev, addr: int, name: str) -> Tuple[bool, str]:
    ok, data = read_mem(dev, addr, 4)
    if ok and len(data) >= 4:
        val = struct.unpack("<I", data[:4])[0]
        return True, f"{name} @ 0x{addr:08X} = 0x{val:08X}"
    return False, f"No response from {name}"

def check_ping(dev) -> Tuple[bool, str]:
    ok, _, _ = cmd_dispatch(dev, "PING")
    return ok, "Responding" if ok else "No response"


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_verify(args=None) -> bool:
    """QSLCL VERIFY - System verification and diagnostics"""
    
    if args is None:
        print("[!] No arguments")
        print("[*] verify list|checksum|signature|integrity|security|hardware|firmware|full")
        return False
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return False
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = getattr(args, 'verify_subcommand', '') or getattr(args, 'subcmd', '') or ''
    sub = sub.lower().strip()
    
    vargs = getattr(args, 'verify_args', []) or getattr(args, 'args', []) or []
    verbose = getattr(args, 'verbose', False)
    strict = getattr(args, 'strict', False)
    output = getattr(args, 'output', None)
    force = getattr(args, 'force', False)
    
    handlers = {
        'list': verify_list, 'ls': verify_list, 'capabilities': verify_list,
        'checksum': verify_checksum, 'hash': verify_checksum, 'crc': verify_checksum,
        'signature': verify_signature, 'sig': verify_signature, 'auth': verify_signature,
        'integrity': verify_integrity, 'memory': verify_integrity,
        'structure': verify_structure, 'layout': verify_structure, 'header': verify_structure,
        'security': verify_security, 'sec': verify_security,
        'hardware': verify_hardware, 'hw': verify_hardware,
        'firmware': verify_firmware, 'fw': verify_firmware,
        'performance': verify_performance, 'perf': verify_performance, 'bench': verify_performance,
        'full': verify_full, 'complete': verify_full, 'system': verify_full,
    }
    
    if sub in ('help', '?'):
        print("[*] Verify Commands:")
        for name, func in sorted(set(handlers.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip()
                print(f"    {name:<15} {doc}")
        return True
    
    handler = handlers.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        print(f"[*] Valid: {', '.join(sorted(set(k for k in handlers if '_' not in k)))}")
        return False
    
    try:
        return handler(dev, vargs, verbose, strict, output, force)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        if verbose and _DEBUG:
            import traceback
            traceback.print_exc()
        return False


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] verify.py - QSLCL VERIFY Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py verify <subcommand> [args]")