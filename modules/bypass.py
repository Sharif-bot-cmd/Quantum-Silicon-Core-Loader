#!/usr/bin/env python3
"""
bypass.py - QSLCL BYPASS Command Module v2.1 (CLEANED)
Security bypass engine with auto-detection and enforcement point analysis
"""

import os
import sys
import struct
import time
from typing import Optional, List, Tuple, Dict

# =============================================================================
# IMPORTS - With proper fallbacks
# =============================================================================
try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
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
TIMEOUT = 20.0

# Opcodes
OP_TEST = 0x00
OP_DEVICE_INFO = 0x01
OP_MEMORY_SCAN = 0x02
OP_ENFORCEMENT = 0x03
OP_REGION_CHECK = 0x04
OP_APPLE = 0x11
OP_SOC = 0x20
OP_SECUREBOOT = 0x21
OP_APRR = 0x30
OP_SEP = 0x31
OP_KPP = 0x32
OP_AMFI = 0x33
OP_SANDBOX = 0x34
OP_CSR = 0x35
OP_TEMP = 0x40
OP_QUANTUM = 0x50

# SOC families
SOC_FAMILIES = {
    'APPLE':    {'features': ['SEP', 'APRR', 'KPP', 'AMFI', 'SANDBOX'], 'base': 0x80000000},
    'QUALCOMM': {'features': ['TRUSTZONE', 'SECUREBOOT', 'QFP'], 'base': 0xFC400000},
    'SAMSUNG':  {'features': ['TRUSTZONE', 'KNOX', 'RKP'], 'base': 0x80000000},
    'HISILICON':{'features': ['TRUSTZONE', 'HISE'], 'base': 0x80000000},
    'GENERIC':  {'features': ['SECUREBOOT', 'MEMORY_PROTECTION'], 'base': 0x80000000},
}

# Module cache
_MEMORY_CACHE: Dict[str, Dict] = {}
_ENFORCEMENT_CACHE: Dict[str, List] = {}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


def bypass_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send bypass command"""
    for attempt in range(2):
        try:
            if "BYPASS" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "BYPASS", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt == 0: time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""


def cache_key(dev) -> str:
    return getattr(dev, 'serial', None) or getattr(dev, 'identifier', 'default')


def run_bypass(dev, opcode: int, name: str, data: bytes = b"", force: bool = False) -> bool:
    """Execute bypass with consistent output"""
    payload = struct.pack("<B", opcode) + data
    ok, status_name, _ = bypass_cmd(dev, payload)
    
    if ok:
        print(f"[+] {name} bypass successful")
    else:
        print(f"[!] {name} bypass failed: {status_name}")
    
    return ok


# =============================================================================
# AUTO-DETECTION
# =============================================================================
def identify_device(dev) -> dict:
    """Identify device type and SOC"""
    info = {'device_name': 'Unknown', 'soc_family': 'GENERIC'}
    
    try:
        ok, _, data = bypass_cmd(dev, struct.pack("<B", OP_DEVICE_INFO))
        if ok and data and len(data) >= 56:
            info['device_name'] = data[0:32].decode('ascii', 'ignore').rstrip('\x00').strip()
            soc_name = data[32:48].decode('ascii', 'ignore').rstrip('\x00').strip()
            
            soc_upper = soc_name.upper()
            if any(k in soc_upper for k in ['APPLE', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A18']):
                info['soc_family'] = 'APPLE'
            elif any(k in soc_upper for k in ['QUALCOMM', 'SD', 'MSM', 'QCM', 'SM']):
                info['soc_family'] = 'QUALCOMM'
            elif any(k in soc_upper for k in ['EXYNOS', 'S5E']):
                info['soc_family'] = 'SAMSUNG'
            elif any(k in soc_upper for k in ['KIRIN', 'HI3']):
                info['soc_family'] = 'HISILICON'
    except: pass
    
    return info


def scan_offsets(dev, info: dict) -> dict:
    """Scan for memory offsets"""
    keys = ['secure_boot', 'memory_protection', 'crypto_engine',
            'kernel_integrity', 'enclave', 'code_signing', 'recovery']
    offsets = {k: {'found': False, 'address': 0} for k in keys}
    
    try:
        base = SOC_FAMILIES.get(info.get('soc_family', 'GENERIC'), {}).get('base', 0x80000000)
        payload = struct.pack("<B", OP_MEMORY_SCAN) + struct.pack("<II", base, 0x10000000)
        ok, _, data = bypass_cmd(dev, payload)
        
        if ok and data and len(data) >= 28:
            vals = struct.unpack("<7I", data[:28])
            for i, v in enumerate(vals):
                if i < len(keys) and v > 0:
                    offsets[keys[i]] = {'found': True, 'address': v}
        
        # Heuristic fallback
        patterns = {
            'APPLE': [(0x80000000, 'secure_boot'), (0x80200000, 'enclave')],
            'QUALCOMM': [(0xFC400000, 'secure_boot'), (0xFD000000, 'memory_protection')],
            'GENERIC': [(0x80000000, 'secure_boot'), (0x81000000, 'memory_protection')],
        }
        for addr, key in patterns.get(info.get('soc_family', 'GENERIC'), patterns['GENERIC']):
            if not offsets[key]['found']:
                ok2, _, d2 = bypass_cmd(dev, struct.pack("<BII", OP_REGION_CHECK, addr, 0x1000))
                if ok2 and d2 and len(d2) >= 4 and struct.unpack("<I", d2[:4])[0]:
                    offsets[key] = {'found': True, 'address': addr}
    except: pass
    
    return offsets


def detect_points(dev, offsets: dict) -> List[dict]:
    """Detect enforcement points"""
    points = []
    
    for otype, odata in offsets.items():
        if odata.get('found'):
            payload = struct.pack("<B", OP_ENFORCEMENT) + struct.pack("<I", odata['address'])
            ok, _, data = bypass_cmd(dev, payload)
            if ok and data and len(data) >= 16:
                etype = data[0:4].decode('ascii', 'ignore').rstrip('\x00').strip()
                level = struct.unpack("<I", data[4:8])[0]
                desc = data[8:16].decode('ascii', 'ignore').rstrip('\x00').strip()
                if etype:
                    points.append({'type': etype, 'address': odata['address'],
                                  'level': level, 'desc': desc})
    
    return points


def auto_detect(dev, verbose: bool = True) -> dict:
    """Run comprehensive auto-detection"""
    if verbose: print("\n[*] Auto-Detection:")
    
    # Phase 1: Device ID
    if verbose: print("    Phase 1: Device identification...")
    info = identify_device(dev)
    if verbose: print(f"      {info.get('device_name', '?')} ({info.get('soc_family', '?')})")
    
    # Phase 2: Memory offsets
    if verbose: print("    Phase 2: Memory scan...")
    offsets = scan_offsets(dev, info)
    found = sum(1 for o in offsets.values() if o['found'])
    if verbose: print(f"      {found} offsets found")
    
    # Phase 3: Enforcement points
    if verbose: print("    Phase 3: Enforcement points...")
    points = detect_points(dev, offsets)
    if verbose: print(f"      {len(points)} points detected")
    
    # Phase 4: Security assessment
    score = sum(p.get('level', 0) for p in points)
    if score > 80: security = "VERY HIGH"
    elif score > 60: security = "HIGH"
    elif score > 30: security = "MEDIUM"
    else: security = "LOW"
    if verbose: print(f"    Security: {security}")
    
    results = {
        'device': info, 'offsets': offsets, 'points': points,
        'security': security, 'score': score,
    }
    
    # Cache
    key = cache_key(dev)
    _MEMORY_CACHE[key] = results
    _ENFORCEMENT_CACHE[key] = points
    
    return results


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force):
    """List bypass methods"""
    print(f"""
[*] Bypass Methods:
    detect/scan        Auto-detection scan
    offsets            Show memory offsets
    enforce/points     Show enforcement points
    apple [SOC]        Apple A12+ bypass
    soc [type]         Universal SOC bypass
    secureboot         Secure boot bypass
    aprr/sep/kpp       Apple-specific bypasses
    amfi/sandbox/csr   Software security bypasses
    quantum [level]    Quantum Core Loader bypass
    temp               Temporary bypasses
    test               Test bypass engine
""")
    return True


def cmd_detect(dev, args, force):
    """Auto-detection"""
    results = auto_detect(dev, True)
    print(f"\n[+] Results:")
    print(f"    Device:   {results['device'].get('device_name','?')}")
    print(f"    Family:   {results['device'].get('soc_family','?')}")
    print(f"    Security: {results['security']}")
    print(f"    Offsets:  {sum(1 for o in results['offsets'].values() if o['found'])} found")
    print(f"    Points:   {len(results['points'])} detected")
    return True


def cmd_offsets(dev, args, force):
    """Show detected offsets"""
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    
    if not offsets:
        offsets = scan_offsets(dev, identify_device(dev))
    
    print(f"\n[+] Memory Offsets:")
    for k, v in offsets.items():
        if v.get('found'):
            print(f"    {k:<24} 0x{v['address']:08X}")
        else:
            print(f"    {k:<24} NOT FOUND")
    return True


def cmd_enforce(dev, args, force):
    """Show enforcement points"""
    key = cache_key(dev)
    points = _ENFORCEMENT_CACHE.get(key, [])
    
    if not points:
        offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
        if not offsets:
            offsets = scan_offsets(dev, identify_device(dev))
        points = detect_points(dev, offsets)
    
    print(f"\n[+] Enforcement Points ({len(points)}):")
    for p in points:
        print(f"    {p['type']:<16} @ 0x{p['address']:08X} L{p.get('level', 0)}")
        if p.get('desc'): print(f"      {p['desc']}")
    return True


def cmd_apple(dev, args, force):
    """Apple security bypass"""
    soc = args[0].upper() if args else "A12"
    
    if not confirm(
        f"⚡ APPLE SECURITY BYPASS: {soc}+\n"
        "This bypasses Apple hardware security mechanisms!\n"
        "Use only on devices you own!", 'APPLEBY', force
    ): return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = scan_offsets(dev, {'soc_family': 'APPLE'})
    
    data = soc.encode()[:8].ljust(8, b'\x00')
    for k in ['enclave', 'memory_protection', 'kernel_integrity', 'code_signing']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return run_bypass(dev, OP_APPLE, f"Apple {soc}", data, force)


def cmd_soc(dev, args, force):
    """Universal SOC bypass"""
    soc_type = args[0].upper() if args else "GENERIC"
    
    if not confirm(
        f"⚡ SOC BYPASS: {soc_type}\n"
        "This bypasses SOC-level security!\n"
        "Use only on devices you own!", 'SOCBYPASS', force
    ): return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = scan_offsets(dev, {'soc_family': soc_type})
    
    data = soc_type.encode()[:8].ljust(8, b'\x00')
    for k in ['secure_boot', 'memory_protection', 'crypto_engine']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return run_bypass(dev, OP_SOC, f"SOC {soc_type}", data, force)


def cmd_secureboot(dev, args, force):
    """Secure boot bypass"""
    if not confirm("⚡ SECURE BOOT BYPASS - Bypasses boot verification!", 'QSLCLLOAD', force):
        return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    addr = offsets.get('secure_boot', {}).get('address', 0x80001000) if offsets else 0x80001000
    
    return run_bypass(dev, OP_SECUREBOOT, "Secure Boot", struct.pack("<I", addr), force)


def cmd_aprr(dev, args, force):
    return run_bypass(dev, OP_APRR, "APRR", b"", force)

def cmd_sep(dev, args, force):
    return run_bypass(dev, OP_SEP, "SEP", b"", force)

def cmd_kpp(dev, args, force):
    return run_bypass(dev, OP_KPP, "KPP", b"", force)

def cmd_amfi(dev, args, force):
    mode = args[0] if args else "full"
    return run_bypass(dev, OP_AMFI, "AMFI", mode.encode()[:8].ljust(8, b'\x00'), force)

def cmd_sandbox(dev, args, force):
    return run_bypass(dev, OP_SANDBOX, "Sandbox", b"", force)

def cmd_csr(dev, args, force):
    return run_bypass(dev, OP_CSR, "CSR", b"", force)

def cmd_temp(dev, args, force):
    return run_bypass(dev, OP_TEMP, "Temporary", b"", force)

def cmd_quantum(dev, args, force):
    level = args[0] if args else "standard"
    data = level.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_QUANTUM, "Quantum", data, force)

def cmd_test(dev, args, force):
    ok, name, _ = bypass_cmd(dev, struct.pack("<B", OP_TEST))
    status = 'ACTIVE' if ok else f'INACTIVE ({name})'
    print(f"[{'✓' if ok else '✗'}] Bypass engine: {status}")
    return ok


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'list': cmd_list, 'ls': cmd_list, 'methods': cmd_list,
    'detect': cmd_detect, 'scan': cmd_detect, 'auto': cmd_detect,
    'offsets': cmd_offsets, 'memory': cmd_offsets, 'regions': cmd_offsets,
    'enforce': cmd_enforce, 'points': cmd_enforce, 'security': cmd_enforce,
    'apple': cmd_apple, 'a12': cmd_apple, 'iphone': cmd_apple,
    'soc': cmd_soc, 'universal': cmd_soc, 'generic': cmd_soc,
    'secureboot': cmd_secureboot, 'boot': cmd_secureboot,
    'aprr': cmd_aprr, 'sep': cmd_sep, 'kpp': cmd_kpp,
    'amfi': cmd_amfi, 'sandbox': cmd_sandbox, 'csr': cmd_csr,
    'temp': cmd_temp, 'temporary': cmd_temp,
    'quantum': cmd_quantum, 'qslcl': cmd_quantum,
    'test': cmd_test, 'validate': cmd_test, 'check': cmd_test,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_bypass(args=None) -> int:
    """
    QSLCL BYPASS - Security bypass engine
    
    Examples:
        bypass detect                    - Auto-detect device and security
        bypass offsets                   - Show memory offsets
        bypass enforce                   - Show enforcement points
        bypass apple A12                 - Apple A12+ bypass
        bypass soc QUALCOMM              - Qualcomm SOC bypass
        bypass secureboot                - Secure boot bypass
        bypass quantum standard          - Quantum Core Loader bypass
        bypass test                      - Test bypass engine
    
    ⚠️  Use only on devices you own or have explicit permission!
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: bypass <detect|offsets|enforce|apple|soc|secureboot|quantum|test>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'bypass_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    bargs = getattr(args, 'bypass_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Bypass Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<15} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    # Global confirmation for bypass operations
    if sub not in ('list', 'detect', 'offsets', 'enforce', 'test', 'scan', 'auto'):
        if not force:
            if not confirm(
                "⚡ SECURITY BYPASS ENGINE\n"
                "Use only on devices you own or have explicit permission!\n"
                "Unauthorized use may violate laws.", 'QSLCLBYPASS', force
            ):
                return 0
    
    # Auto-detect if needed
    if sub not in ('list', 'detect', 'scan', 'auto'):
        auto_detect(dev, verbose=False)
    
    try:
        return 0 if handler(dev, bargs, force) else 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] bypass.py - QSLCL BYPASS Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py bypass <subcommand> [args]")