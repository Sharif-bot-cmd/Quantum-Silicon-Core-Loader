#!/usr/bin/env python3
"""
bypass.py - QSLCL BYPASS Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, auto-detection,
       security bypass operations, cache management
"""

import os
import sys
import struct
import time
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union

# =============================================================================
# FIXED: Proper relative imports with comprehensive fallbacks
# =============================================================================
_use_qslcl = False
_scan_all = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_QSLCLCMD_DB = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _auto_loader_if_needed = _qslcl_auto_loader
    _qslcl_dispatch = _qslcl_dispatch_fn
    _decode_runtime_result = _qslcl_decode_runtime
    _QSLCLCMD_DB = _qslcl_cmd_db
    _DEBUG = _qslcl_debug
    _use_qslcl = True
except ImportError:
    try:
        from .qslcl import (
            scan_all as _qslcl_scan_all,
            auto_loader_if_needed as _qslcl_auto_loader,
            qslcl_dispatch as _qslcl_dispatch_fn,
            decode_runtime_result as _qslcl_decode_runtime,
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _auto_loader_if_needed = _qslcl_auto_loader
        _qslcl_dispatch = _qslcl_dispatch_fn
        _decode_runtime_result = _qslcl_decode_runtime
        _QSLCLCMD_DB = _qslcl_cmd_db
        _DEBUG = _qslcl_debug
        _use_qslcl = True
    except ImportError:
        _use_qslcl = False


# =============================================================================
# FIXED: Standalone mode
# =============================================================================
_STANDALONE_WARNED = False
def _warn_standalone():
    global _STANDALONE_WARNED
    if not _STANDALONE_WARNED:
        print("[!] Running in standalone mode"); _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
BYPASS_TIMEOUT = 20.0
MAX_RETRIES = 2

# Cache
_MEMORY_CACHE: Dict[str, Dict] = {}
_ENFORCEMENT_CACHE: Dict[str, List] = {}

# Bypass opcodes
class BypassOp:
    TEST = 0x00
    DEVICE_INFO = 0x01
    MEMORY_SCAN = 0x02
    ENFORCEMENT_QUERY = 0x03
    REGION_CHECK = 0x04
    APPLE = 0x11
    SOC = 0x20
    SECUREBOOT = 0x21
    APRR = 0x30
    SEP = 0x31
    KPP = 0x32
    AMFI = 0x33
    SANDBOX = 0x34
    CSR = 0x35
    TEMP = 0x40
    QUANTUM = 0x50

# SOC families
SOC_FAMILIES = {
    'APPLE':    {'features':['SEP','APRR','KPP','AMFI','SANDBOX'], 'base':0x80000000},
    'QUALCOMM': {'features':['TRUSTZONE','SECUREBOOT','QFP'], 'base':0xFC400000},
    'SAMSUNG':  {'features':['TRUSTZONE','KNOX','RKP'], 'base':0x80000000},
    'HISILICON':{'features':['TRUSTZONE','HISE'], 'base':0x80000000},
    'GENERIC':  {'features':['SECUREBOOT','MEMORY_PROTECTION'], 'base':0x80000000},
}

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Cache key helper
# =============================================================================
def _cache_key(dev) -> str:
    return getattr(dev, 'serial', None) or getattr(dev, 'identifier', 'default')


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.RED}{msg}{C.RESET}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


# =============================================================================
# FIXED: Dispatch helper
# =============================================================================
def _find_cmd(name: str) -> Optional[Tuple]:
    if not _use_qslcl or not _QSLCLCMD_DB: return None
    u = name.upper()
    for k,v in _QSLCLCMD_DB.items():
        if isinstance(k,str) and k.upper()==u: return ("name",k)
        if isinstance(v,dict) and v.get("name","").upper()==u: return ("opcode",k)
    return None

def _dispatch(dev, cmd: str, payload: bytes, timeout: float=None) -> Tuple[bool,str,bytes]:
    if not _use_qslcl: return False,"NO_QSLCL",b""
    for attempt in range(MAX_RETRIES):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or BYPASS_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or BYPASS_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Generic bypass executor
# =============================================================================
def _run_bypass(dev, opcode: int, name: str, data: bytes = b"",
                force: bool = False, persistent: bool = False) -> bool:
    """Execute a bypass command with consistent error handling."""
    payload = struct.pack("<B", opcode) + data
    if persistent:
        payload += struct.pack("<B", 1)
    
    ok, status_name, extra = _dispatch(dev, "BYPASS", payload)
    
    if ok:
        print(f"{C.GREEN}[+] {name} bypass successful{C.RESET}")
        if persistent:
            print(f"    Persistent: YES")
    else:
        print(f"{C.RED}[!] {name} bypass failed: {status_name}{C.RESET}")
    
    return ok


# =============================================================================
# FIXED: Auto-detection system
# =============================================================================
def _auto_detect(dev, stealth: bool = False) -> Dict:
    """Run comprehensive auto-detection."""
    results = {
        'device_name': 'Unknown', 'soc_family': 'GENERIC',
        'architecture': 'Unknown', 'security_level': 'UNKNOWN',
        'offsets': {}, 'enforcement_points': [], 'universal_offsets': {},
    }
    
    if not stealth:
        print(f"\n{C.CYAN}[*] Auto-Detection{C.RESET}")
    
    # Phase 1: Device identification
    if not stealth: print("  Phase 1: Device ID...")
    info = _identify_device(dev)
    results.update(info)
    if not stealth: print(f"    {info.get('device_name','?')} ({info.get('soc_family','?')})")
    
    # Phase 2: Memory offset scanning
    if not stealth: print("  Phase 2: Memory scan...")
    offsets = _scan_offsets(dev, info)
    results['offsets'] = offsets
    if not stealth:
        for k,v in offsets.items():
            if v.get('found'): print(f"    {k}: 0x{v['address']:08X}")
    
    # Phase 3: Enforcement point detection
    if not stealth: print("  Phase 3: Enforcement points...")
    points = _detect_points(dev, offsets)
    results['enforcement_points'] = points
    if not stealth:
        for p in points:
            print(f"    {p['type']} @ 0x{p['address']:08X}")
    
    # Phase 4: Universal offsets
    if not stealth: print("  Phase 4: Universal offsets...")
    results['universal_offsets'] = _calc_universal(offsets, info)
    
    # Phase 5: Security assessment
    results['security_level'] = _assess_security(points, offsets)
    if not stealth:
        print(f"  Security: {results['security_level']} ({len(points)} points)")
    
    return results


def _identify_device(dev) -> Dict:
    """Identify device type and SOC."""
    info = {'device_name': 'Unknown', 'soc_name': 'Unknown', 
            'soc_family': 'GENERIC', 'architecture': 'Unknown'}
    try:
        ok, _, data = _dispatch(dev, "GETINFO", struct.pack("<B", BypassOp.DEVICE_INFO), timeout=10)
        if ok and data and len(data) >= 56:
            info['device_name'] = data[0:32].decode('ascii','ignore').rstrip('\x00').strip()
            info['soc_name'] = data[32:48].decode('ascii','ignore').rstrip('\x00').strip()
            info['architecture'] = data[48:56].decode('ascii','ignore').rstrip('\x00').strip()
            
            soc_upper = info['soc_name'].upper()
            if any(k in soc_upper for k in ['APPLE','A12','A13','A14','A15','A16','A17','A18']):
                info['soc_family'] = 'APPLE'
            elif any(k in soc_upper for k in ['QUALCOMM','SD','MSM','QCM','SM']):
                info['soc_family'] = 'QUALCOMM'
            elif any(k in soc_upper for k in ['EXYNOS','S5E']):
                info['soc_family'] = 'SAMSUNG'
            elif any(k in soc_upper for k in ['KIRIN','HI3']):
                info['soc_family'] = 'HISILICON'
    except: pass
    return info


def _scan_offsets(dev, info: Dict) -> Dict:
    """Scan for memory offsets."""
    offsets = {k: {'found':False,'address':0,'size':0} for k in 
               ['secure_boot','memory_protection','crypto_engine',
                'kernel_integrity','enclave','code_signing','recovery']}
    
    try:
        base = SOC_FAMILIES.get(info.get('soc_family','GENERIC'), {}).get('base', 0x80000000)
        payload = struct.pack("<B", BypassOp.MEMORY_SCAN) + struct.pack("<II", base, 0x10000000)
        ok, _, data = _dispatch(dev, "BYPASS", payload, timeout=15)
        
        if ok and data and len(data) >= 28:
            vals = struct.unpack("<7I", data[:28])
            keys = list(offsets.keys())
            for i, v in enumerate(vals):
                if i < len(keys) and v > 0:
                    offsets[keys[i]] = {'found':True, 'address':v, 'size':0x1000}
        
        # Heuristic scanning
        patterns = {
            'APPLE': [(0x80000000,'secure_boot'),(0x80200000,'enclave'),(0x80400000,'code_signing')],
            'QUALCOMM': [(0xFC400000,'secure_boot'),(0xFD000000,'memory_protection')],
            'GENERIC': [(0x80000000,'secure_boot'),(0x81000000,'memory_protection')],
        }
        for b, k in patterns.get(info.get('soc_family','GENERIC'), patterns['GENERIC']):
            if not offsets[k]['found']:
                ok2, _, d2 = _dispatch(dev, "BYPASS", 
                    struct.pack("<B", BypassOp.REGION_CHECK) + struct.pack("<II", b, 0x1000))
                if ok2 and d2 and len(d2) >= 4:
                    if struct.unpack("<I", d2[:4])[0]:
                        offsets[k] = {'found':True, 'address':b, 'size':0x1000, 'heuristic':True}
    except: pass
    
    return offsets


def _detect_points(dev, offsets: Dict) -> List[Dict]:
    """Detect enforcement points."""
    points = []
    try:
        for otype, odata in offsets.items():
            if odata.get('found'):
                payload = struct.pack("<B", BypassOp.ENFORCEMENT_QUERY) + struct.pack("<I", odata['address'])
                ok, _, data = _dispatch(dev, "BYPASS", payload)
                if ok and data and len(data) >= 16:
                    etype = data[0:4].decode('ascii','ignore').rstrip('\x00').strip()
                    level = struct.unpack("<I", data[4:8])[0]
                    desc = data[8:16].decode('ascii','ignore').rstrip('\x00').strip()
                    if etype:
                        points.append({'type':etype,'address':odata['address'],
                                      'level':level,'description':desc,'bypass_required':True})
    except: pass
    
    # Add universal points
    universal = [
        {'type':'SECURE_BOOT','address':0x80001000,'level':10,'description':'Secure boot verify','bypass_required':True},
        {'type':'MEMORY_PROTECT','address':0x80002000,'level':8,'description':'Memory access','bypass_required':True},
        {'type':'CODE_SIGNING','address':0x80003000,'level':7,'description':'Signature verify','bypass_required':True},
    ]
    points.extend(universal)
    return points


def _calc_universal(offsets: Dict, info: Dict) -> Dict:
    """Calculate universal offsets."""
    u = {}
    base = SOC_FAMILIES.get(info.get('soc_family','GENERIC'), {}).get('base', 0x80000000)
    for k, v in offsets.items():
        if v.get('found'):
            u[k] = {'absolute':v['address'],'relative':v['address']-base,
                    'base':base,'valid':abs(v['address']-base)<0x10000000}
    
    soc_offsets = {
        'APPLE': {'sep':(0x80200000,0x00200000),'aprr':(0x80240000,0x00240000),'kpp':(0x80280000,0x00280000)},
        'QUALCOMM': {'tz':(0xFC400000,0x7C400000),'qfp':(0xFC800000,0x7C800000)},
        'GENERIC': {'secmon':(0x80010000,0x00010000),'protmem':(0x80020000,0x00020000)},
    }
    for k, (abs_addr, rel_addr) in soc_offsets.get(info.get('soc_family','GENERIC'), {}).items():
        u[k+'_base'] = {'absolute':abs_addr,'relative':rel_addr,'base':base,'valid':True}
    
    return u


def _assess_security(points: List, offsets: Dict) -> str:
    """Assess security level."""
    score = sum(p.get('level',0) for p in points)
    score += sum(5 for o in offsets.values() if o.get('found'))
    max_score = len(points)*10 + len(offsets)*5
    if max_score == 0: return "UNKNOWN"
    pct = score/max_score*100
    if pct > 80: return "VERY HIGH"
    elif pct > 60: return "HIGH"
    elif pct > 40: return "MEDIUM"
    elif pct > 20: return "LOW"
    return "MINIMAL"


# =============================================================================
# FIXED: Bypass subcommand implementations
# =============================================================================
def bypass_list(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    print(f"""
{C.BOLD}[+] Bypass Methods:{C.RESET}
  detect/scan/auto     Auto-detection scan
  offsets/memory       Detected memory offsets
  enforce/points       Security enforcement points
  apple [SOC]          Apple A12+ security bypass
  soc [type]           Universal SOC bypass
  secureboot           Secure boot bypass
  aprr                 APRR memory protection bypass
  sep                  Secure Enclave bypass
  kpp                  Kernel Patch Protection bypass
  amfi [mode]          AMFI bypass
  sandbox              Sandbox isolation bypass
  csr                  System Recovery bypass
  quantum [level]      Quantum Core Loader bypass
  temp                 Temporary bypasses
  test                 Test bypass effectiveness
""")
    return True


def bypass_detect(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    results = _auto_detect(dev, stealth)
    key = _cache_key(dev)
    _MEMORY_CACHE[key] = results
    _ENFORCEMENT_CACHE[key] = results.get('enforcement_points', [])
    
    if not stealth:
        print(f"\n{C.BOLD}[+] Results:{C.RESET}")
        print(f"    Device: {results['device_name']} ({results['soc_family']})")
        print(f"    Security: {results['security_level']}")
        print(f"    Offsets: {sum(1 for o in results['offsets'].values() if o.get('found'))} found")
        print(f"    Points: {len(results['enforcement_points'])} detected")
    return True


def bypass_offsets(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    key = _cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = _scan_offsets(dev, _identify_device(dev))
    
    print(f"\n{C.BOLD}[+] Offsets:{C.RESET}")
    for k, v in offsets.items():
        if v.get('found'):
            print(f"    {k:<22} 0x{v['address']:08X} ({v.get('size',0)}B) [{v.get('confidence','MEDIUM')}]")
        else:
            print(f"    {k:<22} NOT FOUND")
    return True


def bypass_enforcement(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    key = _cache_key(dev)
    points = _ENFORCEMENT_CACHE.get(key, [])
    if not points:
        offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {}) or _scan_offsets(dev, _identify_device(dev))
        points = _detect_points(dev, offsets)
    
    print(f"\n{C.BOLD}[+] Enforcement Points:{C.RESET}")
    for p in points:
        print(f"    {p['type']:<15} @ 0x{p['address']:08X} L{p.get('level',0)}")
        print(f"      {p.get('description','?')} | Bypass: {'YES' if p.get('bypass_required') else 'NO'}")
    return True


# =============================================================================
# FIXED: Security bypass implementations
# =============================================================================
def bypass_apple(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    soc = args[0].upper() if args else "A12"
    
    if not _confirm(
        f"⚡ APPLE SECURITY BYPASS: {soc}+\n"
        "This bypasses Apple hardware security mechanisms!", 'APPLEBY', force
    ): return False
    
    # Get offsets from cache or scan
    key = _cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets and auto_detect:
        offsets = _scan_offsets(dev, {'soc_family':'APPLE'})
    
    data = soc.encode('ascii')[:8].ljust(8, b'\x00')
    data += struct.pack("<B", 1 if persistent else 0)
    for k in ['enclave','memory_protection','kernel_integrity','code_signing']:
        addr = offsets.get(k, {}).get('address', 0)
        data += struct.pack("<I", addr)
    
    return _run_bypass(dev, BypassOp.APPLE, f"Apple {soc}", data, force, persistent)


def bypass_soc(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    soc_type = args[0].upper() if args else "GENERIC"
    
    if not _confirm(
        f"⚡ UNIVERSAL SOC BYPASS: {soc_type}\n"
        "This bypasses SOC-level security mechanisms!", 'SOCBYPASS', force
    ): return False
    
    key = _cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets and auto_detect:
        offsets = _scan_offsets(dev, {'soc_family':soc_type})
    
    data = soc_type.encode('ascii')[:8].ljust(8, b'\x00')
    data += struct.pack("<B", 1 if persistent else 0)
    for k in ['secure_boot','memory_protection','crypto_engine']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return _run_bypass(dev, BypassOp.SOC, f"SOC {soc_type}", data, force, persistent)


def bypass_secureboot(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    if not _confirm("⚡ SECURE BOOT BYPASS - This bypasses boot verification!", 'QSLCLLOAD', force):
        return False
    
    key = _cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    sb_offset = offsets.get('secure_boot', {}).get('address', 0x80001000)
    
    data = struct.pack("<I", sb_offset) + struct.pack("<B", 1 if persistent else 0)
    return _run_bypass(dev, BypassOp.SECUREBOOT, "Secure Boot", data, force, persistent)


def bypass_aprr(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.APRR, "APRR", b"", force, persistent)

def bypass_sep(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.SEP, "SEP", b"", force, persistent)

def bypass_kpp(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.KPP, "KPP", b"", force, persistent)

def bypass_amfi(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    mode = args[0] if args else "full"
    data = mode.encode('ascii')[:8].ljust(8, b'\x00')
    return _run_bypass(dev, BypassOp.AMFI, "AMFI", data, force, persistent)

def bypass_sandbox(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.SANDBOX, "Sandbox", b"", force, persistent)

def bypass_csr(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.CSR, "CSR", b"", force, persistent)

def bypass_temp(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    return _run_bypass(dev, BypassOp.TEMP, "Temporary", b"", force, False)

def bypass_quantum(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    level = args[0] if args else "standard"
    data = level.encode('ascii')[:8].ljust(8, b'\x00') + struct.pack("<B", 1 if persistent else 0)
    return _run_bypass(dev, BypassOp.QUANTUM, "Quantum", data, force, persistent)

def bypass_test(dev, args, force=False, stealth=False, persistent=False, auto_detect=True) -> bool:
    ok, name, _ = _dispatch(dev, "BYPASS", struct.pack("<B", BypassOp.TEST))
    print(f"[{'✓' if ok else '✗'}] Bypass engine: {'ACTIVE' if ok else f'INACTIVE ({name})'}")
    return ok


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
BYPASS_HANDLERS = {
    'list': bypass_list, 'ls': bypass_list, 'methods': bypass_list,
    'detect': bypass_detect, 'scan': bypass_detect, 'auto': bypass_detect,
    'offsets': bypass_offsets, 'memory': bypass_offsets, 'regions': bypass_offsets,
    'enforce': bypass_enforcement, 'points': bypass_enforcement, 'security': bypass_enforcement,
    'apple': bypass_apple, 'a12': bypass_apple, 'iphone': bypass_apple, 'ios': bypass_apple,
    'soc': bypass_soc, 'universal': bypass_soc, 'generic': bypass_soc,
    'secureboot': bypass_secureboot, 'boot': bypass_secureboot, 'signature': bypass_secureboot,
    'aprr': bypass_aprr, 'page_protection': bypass_aprr,
    'sep': bypass_sep, 'secure_enclave': bypass_sep, 'enclave': bypass_sep,
    'kpp': bypass_kpp, 'kernel_patch': bypass_kpp, 'amcc': bypass_kpp,
    'amfi': bypass_amfi, 'code_signing': bypass_amfi, 'entitlements': bypass_amfi,
    'sandbox': bypass_sandbox, 'container': bypass_sandbox, 'isolation': bypass_sandbox,
    'csr': bypass_csr, 'system_recovery': bypass_csr, 'recovery': bypass_csr,
    'temp': bypass_temp, 'temporary': bypass_temp, 'session': bypass_temp,
    'quantum': bypass_quantum, 'qslcl': bypass_quantum, 'core': bypass_quantum,
    'test': bypass_test, 'validate': bypass_test, 'check': bypass_test,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_bypass_help():
    print(f"""
{C.BOLD}BYPASS - Security Bypass Engine{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  detect/scan/auto     Auto-detection scan
  offsets/memory       Show detected offsets
  enforce/points       Show enforcement points
  list                 List all methods
  apple [SOC]          Apple A12+ bypass
  soc [type]           Universal SOC bypass
  secureboot           Secure boot bypass
  aprr/seb/kpp         Apple-specific bypasses
  amfi/sandbox/csr     Software security bypasses
  quantum [level]      Quantum Core Loader bypass
  temp                 Temporary bypasses
  test                 Test bypass engine

{C.CYAN}OPTIONS:{C.RESET}
  --force         Skip confirmations
  --stealth       Minimal output
  --persistent    Make persistent
  --no-auto-detect  Skip auto-detection

{C.RED}⚠️  SECURITY: Use only on devices you own or have explicit permission!{C.RESET}
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_bypass(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_bypass_help(); return 1
    
    if not _use_qslcl: _warn_standalone()
    
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return 1
        if not devs: print(f"{C.RED}[!] No device{C.RESET}"); return 1
        dev = devs[0]
        print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        print(f"{C.RED}[!] No QSLCL{C.RESET}"); return 1
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    sub = (getattr(args, 'bypass_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    bargs = getattr(args, 'bypass_args', []) or []
    force = getattr(args, 'force', False)
    stealth = getattr(args, 'stealth', False)
    persistent = getattr(args, 'persistent', False)
    auto_detect = not getattr(args, 'no_auto_detect', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_bypass_help(); return 0
    
    # Global auto-detection if enabled
    if auto_detect and not stealth:
        results = _auto_detect(dev, stealth)
        key = _cache_key(dev)
        _MEMORY_CACHE[key] = results
        _ENFORCEMENT_CACHE[key] = results.get('enforcement_points', [])
    
    # Quantum bypass confirmation
    if not force and not stealth and sub not in ('list','detect','offsets','enforce','test','help'):
        if not _confirm(
            "⚡ QUANTUM SILICON CORE LOADER BYPASS ENGINE v5.0\n"
            "QSLCL-native security circumvention\n"
            "Use only on devices you own or have explicit permission!",
            'QSLCLBYPASS', force
        ): return 0
    
    handler = BYPASS_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_bypass_help(); return 1
    
    try:
        return 0 if handler(dev, bargs, force, stealth, persistent, auto_detect) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def add_bypass_arguments(parser):
    parser.add_argument('bypass_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('bypass_args', nargs='*', help='Arguments')
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--stealth', action='store_true')
    parser.add_argument('--persistent', action='store_true')
    parser.add_argument('--no-auto-detect', action='store_true')
    return parser


if __name__ == "__main__":
    print("[*] bypass.py - QSLCL BYPASS Module v2.0")
    print_bypass_help()