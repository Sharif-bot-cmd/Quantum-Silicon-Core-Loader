#!/usr/bin/env python3
"""
bypass.py - QSLCL BYPASS Command Module v3.0 (CLEANED)
Security bypass engine with auto-detection and enforcement point analysis
"""

import os
import sys
import struct
import time
from typing import Optional, List, Tuple, Dict

# =============================================================================
# IMPORTS
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

# Core opcodes
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
OP_WATCHDOG = 0x60

# SOC Families (simplified)
SOC_FAMILIES = {
    'APPLE': {
        'features': ['SEP', 'APRR', 'KPP', 'AMFI', 'SANDBOX', 'PAC'],
        'base': 0x80000000,
        'watchdog_offsets': [0x20E00000, 0x20E01000, 0x20E02000],
        'versions': ['A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A18', 'M1', 'M2', 'M3'],
    },
    'QUALCOMM': {
        'features': ['TRUSTZONE', 'SECUREBOOT', 'SMMU'],
        'base': 0xFC400000,
        'watchdog_offsets': [0x02000000, 0x02000004, 0x02000008, 0x0200000C],
        'versions': ['SDM845', 'SM8150', 'SM8250', 'SM8350', 'SM8450', 'SM8550'],
    },
    'MEDIATEK': {
        'features': ['TRUSTZONE', 'SECUREBOOT', 'TEE'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10000000, 0x10000004, 0x1C000000, 0x1C000004],
        'versions': ['MT6765', 'MT6785', 'MT6833', 'MT6853', 'MT6873', 'MT6893', 'MT6983'],
    },
    'SAMSUNG': {
        'features': ['TRUSTZONE', 'KNOX', 'RKP', 'DEFEX'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10060000, 0x10060004, 0x10070000, 0x10070004],
        'versions': ['Exynos2100', 'Exynos2200', 'Exynos2400'],
    },
    'GENERIC': {
        'features': ['SECUREBOOT', 'MEMORY_PROTECTION'],
        'base': 0x80000000,
        'watchdog_offsets': [0x80000000, 0x80001000, 0x80002000],
        'versions': [],
    },
}

# Module cache
_MEMORY_CACHE: Dict[str, Dict] = {}
_ENFORCEMENT_CACHE: Dict[str, List] = {}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force:
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}': ") == req
    except:
        return False

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
            if attempt == 0:
                time.sleep(0.1)
    
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
            elif any(k in soc_upper for k in ['QUALCOMM', 'SD', 'MSM', 'SM']):
                info['soc_family'] = 'QUALCOMM'
            elif any(k in soc_upper for k in ['EXYNOS', 'S5E']):
                info['soc_family'] = 'SAMSUNG'
            elif any(k in soc_upper for k in ['MT', 'MEDIATEK']):
                info['soc_family'] = 'MEDIATEK'
    except:
        pass
    
    return info

def scan_offsets(dev, info: dict) -> dict:
    """Scan for memory offsets"""
    keys = ['secure_boot', 'memory_protection', 'crypto_engine', 'kernel_integrity', 'enclave', 'code_signing']
    offsets = {k: {'found': False, 'address': 0} for k in keys}
    
    try:
        base = SOC_FAMILIES.get(info.get('soc_family', 'GENERIC'), {}).get('base', 0x80000000)
        payload = struct.pack("<B", OP_MEMORY_SCAN) + struct.pack("<II", base, 0x10000000)
        ok, _, data = bypass_cmd(dev, payload)
        
        if ok and data and len(data) >= 24:
            vals = struct.unpack("<6I", data[:24])
            for i, v in enumerate(vals):
                if i < len(keys) and v > 0:
                    offsets[keys[i]] = {'found': True, 'address': v}
    except:
        pass
    
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
                    points.append({'type': etype, 'address': odata['address'], 'level': level, 'desc': desc})
    
    return points

def auto_detect(dev, verbose: bool = True) -> dict:
    """Run comprehensive auto-detection"""
    if verbose:
        print("\n[*] Auto-Detection:")
    
    # Phase 1: Device ID
    if verbose:
        print("    Phase 1: Device identification...")
    info = identify_device(dev)
    if verbose:
        print(f"      {info.get('device_name', '?')} ({info.get('soc_family', '?')})")
    
    # Phase 2: Memory offsets
    if verbose:
        print("    Phase 2: Memory scan...")
    offsets = scan_offsets(dev, info)
    found = sum(1 for o in offsets.values() if o['found'])
    if verbose:
        print(f"      {found} offsets found")
    
    # Phase 3: Enforcement points
    if verbose:
        print("    Phase 3: Enforcement points...")
    points = detect_points(dev, offsets)
    if verbose:
        print(f"      {len(points)} points detected")
    
    # Phase 4: Security assessment
    score = sum(p.get('level', 0) for p in points)
    if score > 80:
        security = "VERY HIGH"
    elif score > 60:
        security = "HIGH"
    elif score > 30:
        security = "MEDIUM"
    else:
        security = "LOW"
    if verbose:
        print(f"    Security: {security}")
    
    results = {
        'device': info,
        'offsets': offsets,
        'points': points,
        'security': security,
        'score': score,
    }
    
    # Cache
    key = cache_key(dev)
    _MEMORY_CACHE[key] = results
    _ENFORCEMENT_CACHE[key] = points
    
    return results

# =============================================================================
# SUBCOMMANDS (CORE ONLY)
# =============================================================================
def cmd_list(dev, args, force):
    """List bypass methods"""
    print("""
[*] Bypass Methods:

    === DETECTION ===
    detect/scan        Auto-detection scan
    offsets            Show memory offsets
    enforce/points     Show enforcement points

    === SOC BYPASSES ===
    apple [SOC]        Apple A12+ bypass (A12/A13/A14/A15/A16/A17/A18/M1/M2/M3)
    soc [type]         Universal SOC bypass (APPLE/QUALCOMM/MEDIATEK/SAMSUNG)
    watchdog           Watchdog timer disable (auto-detects SoC)

    === BOOT & SECURITY ===
    secureboot         Secure boot bypass
    aprr               APRR bypass (Apple)
    sep                SEP bypass (Apple)
    kpp                KPP bypass (Apple)
    amfi [mode]        AMFI bypass (Apple)
    sandbox            Sandbox bypass
    csr                CSR bypass
    trustzone [mode]   TrustZone/TEE bypass
    smmu               SMMU memory protection bypass

    === SPECIAL ===
    quantum [level]    Quantum Core Loader bypass
    temp               Temporary bypasses
    test               Test bypass engine

⚠️  Use only on devices you own or have explicit permission!
""")
    return True

def cmd_detect(dev, args, force):
    """Auto-detection"""
    results = auto_detect(dev, True)
    print(f"\n[+] Results:")
    print(f"    Device:   {results['device'].get('device_name', '?')}")
    print(f"    Family:   {results['device'].get('soc_family', '?')}")
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
        if p.get('desc'):
            print(f"      {p['desc']}")
    return True

def cmd_apple(dev, args, force):
    """Apple security bypass"""
    soc = args[0].upper() if args else "A12"
    
    if not confirm(
        f"⚡ APPLE SECURITY BYPASS: {soc}+\n"
        "This bypasses Apple hardware security mechanisms!\n"
        "Use only on devices you own!", 'APPLEBY', force
    ):
        return False
    
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
    
    if soc_type not in SOC_FAMILIES:
        print(f"[!] Unknown SOC: {soc_type}")
        print(f"    Available: {', '.join(SOC_FAMILIES.keys())}")
        return False
    
    if not confirm(
        f"⚡ SOC BYPASS: {soc_type}\n"
        "This bypasses SOC-level security!\n"
        "Use only on devices you own!", 'SOCBYPASS', force
    ):
        return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = scan_offsets(dev, {'soc_family': soc_type})
    
    data = soc_type.encode()[:8].ljust(8, b'\x00')
    for k in ['secure_boot', 'memory_protection']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return run_bypass(dev, OP_SOC, f"SOC {soc_type}", data, force)

def cmd_watchdog(dev, args, force):
    """Disable watchdog timer (auto-detects offsets)"""
    if not confirm(
        "⚡ WATCHDOG DISABLE - May cause system instability!\n"
        "Use only on devices you own!", 'WDOGDIS', force
    ):
        return False
    
    info = identify_device(dev)
    soc_family = info.get('soc_family', 'GENERIC')
    soc_data = SOC_FAMILIES.get(soc_family, SOC_FAMILIES['GENERIC'])
    
    offsets = soc_data.get('watchdog_offsets', [])
    data = struct.pack("<I", len(offsets))
    for off in offsets:
        data += struct.pack("<I", off)
    
    return run_bypass(dev, OP_WATCHDOG, f"Watchdog ({soc_family})", data, force)

def cmd_secureboot(dev, args, force):
    """Secure boot bypass"""
    if not confirm(
        "⚡ SECURE BOOT BYPASS - Bypasses boot verification!\n"
        "Use only on devices you own!", 'QSLCLLOAD', force
    ):
        return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    addr = offsets.get('secure_boot', {}).get('address', 0x80001000) if offsets else 0x80001000
    
    return run_bypass(dev, OP_SECUREBOOT, "Secure Boot", struct.pack("<I", addr), force)

def cmd_aprr(dev, args, force):
    """APRR (Apple Protected Region Registers) bypass"""
    return run_bypass(dev, OP_APRR, "APRR", b"", force)

def cmd_sep(dev, args, force):
    """SEP (Secure Enclave Processor) bypass"""
    return run_bypass(dev, OP_SEP, "SEP", b"", force)

def cmd_kpp(dev, args, force):
    """KPP (Kernel Patch Protection) bypass"""
    return run_bypass(dev, OP_KPP, "KPP", b"", force)

def cmd_amfi(dev, args, force):
    """AMFI (Apple Mobile File Integrity) bypass"""
    mode = args[0] if args else "full"
    return run_bypass(dev, OP_AMFI, "AMFI", mode.encode()[:8].ljust(8, b'\x00'), force)

def cmd_sandbox(dev, args, force):
    """Sandbox bypass"""
    return run_bypass(dev, OP_SANDBOX, "Sandbox", b"", force)

def cmd_csr(dev, args, force):
    """CSR (System Integrity Protection) bypass"""
    return run_bypass(dev, OP_CSR, "CSR", b"", force)

def cmd_trustzone(dev, args, force):
    """TrustZone/TEE secure world bypass"""
    if not confirm(
        "⚡ TRUSTZONE BYPASS - Accesses secure world!\n"
        "Use only on devices you own!", 'TRUSTZONE', force
    ):
        return False
    mode = args[0] if args else "full"
    data = mode.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_TRUSTZONE, "TrustZone", data, force)

def cmd_smmu(dev, args, force):
    """SMMU (System Memory Management Unit) bypass"""
    if not confirm(
        "⚡ SMMU BYPASS - Removes memory protection!\n"
        "Use only on devices you own!", 'SMMUBYPASS', force
    ):
        return False
    return run_bypass(dev, OP_SMMU, "SMMU", b"", force)

def cmd_temp(dev, args, force):
    """Temporary bypasses"""
    return run_bypass(dev, OP_TEMP, "Temporary", b"", force)

def cmd_quantum(dev, args, force):
    """Quantum Core Loader bypass"""
    level = args[0] if args else "standard"
    data = level.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_QUANTUM, "Quantum", data, force)

def cmd_test(dev, args, force):
    """Test bypass engine"""
    ok, name, _ = bypass_cmd(dev, struct.pack("<B", OP_TEST))
    status = 'ACTIVE' if ok else f'INACTIVE ({name})'
    print(f"[{'✓' if ok else '✗'}] Bypass engine: {status}")
    return ok

# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    # Detection
    'list': cmd_list,
    'ls': cmd_list,
    'detect': cmd_detect,
    'scan': cmd_detect,
    'auto': cmd_detect,
    'offsets': cmd_offsets,
    'enforce': cmd_enforce,
    'points': cmd_enforce,
    # SOC bypasses
    'apple': cmd_apple,
    'soc': cmd_soc,
    'watchdog': cmd_watchdog,
    'wdog': cmd_watchdog,
    # Boot & Security
    'secureboot': cmd_secureboot,
    'aprr': cmd_aprr,
    'sep': cmd_sep,
    'kpp': cmd_kpp,
    'amfi': cmd_amfi,
    'sandbox': cmd_sandbox,
    'csr': cmd_csr,
    'trustzone': cmd_trustzone,
    'tz': cmd_trustzone,
    'tee': cmd_trustzone,
    'smmu': cmd_smmu,
    # Special
    'temp': cmd_temp,
    'quantum': cmd_quantum,
    'test': cmd_test,
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
        bypass watchdog                  - Disable watchdog
        bypass secureboot                - Secure boot bypass
        bypass trustzone                 - TrustZone bypass
        bypass quantum                   - Quantum Core Loader bypass
        bypass test                      - Test bypass engine
    
    ⚠️  Use only on devices you own or have explicit permission!
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: bypass <detect|offsets|enforce|apple|soc|watchdog|secureboot|quantum|test>")
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
        for name in sorted(HANDLERS.keys()):
            if '_' not in name and len(name) < 15:
                doc = (HANDLERS[name].__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<15} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    # Global confirmation for dangerous bypass operations
    dangerous = ['apple', 'soc', 'secureboot', 'trustzone', 'smmu', 'watchdog']
    if sub in dangerous and not force:
        if not confirm(
            "⚡ SECURITY BYPASS ENGINE\n"
            "Use only on devices you own or have explicit permission!\n"
            "Unauthorized use may violate laws.", 'QSLCLBYPASS', force
        ):
            return 0
    
    # Auto-detect if needed (skip for detection commands)
    if sub not in ('list', 'detect', 'scan', 'auto', 'offsets', 'enforce', 'points', 'ls', 'test'):
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
    print("[*] bypass.py - QSLCL BYPASS Command Module v3.0")
    print("[*] Core bypass methods only")
    print("[*] Usage: python qslcl.py bypass <subcommand> [args]")