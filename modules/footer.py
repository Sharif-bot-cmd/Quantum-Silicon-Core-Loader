#!/usr/bin/env python3
"""
footer.py - QSLCL FOOTER Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, data parsing,
       display formatting, validation, security assessment
"""

import os
import sys
import struct
import time
import json
import zlib
import hashlib
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
FOOTER_TIMEOUT = 15.0
MAX_RETRIES = 2
FOOTER_READ_SIZE = 512

# Footer types
FOOTER_TYPES = ['STANDARD','EXTENDED','SECURITY','BOOT','LOADER','DEBUG','AUDIT','ALL']

# Footer type to read size
FOOTER_SIZES = {
    'STANDARD': 64, 'EXTENDED': 128, 'SECURITY': 256,
    'BOOT': 128, 'LOADER': 256, 'DEBUG': 512, 'AUDIT': 1024, 'ALL': 1024,
}

# Footer addresses (typical)
FOOTER_ADDRESSES = {
    'STANDARD': 0xFFFF0000, 'EXTENDED': 0xFFFF1000, 'SECURITY': 0xFFFF2000,
    'BOOT': 0xFFFF3000, 'LOADER': 0xFFFF4000, 'DEBUG': 0xFFFF5000,
    'AUDIT': 0xFFFF6000, 'ALL': 0xFFFF0000,
}

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Hex dump helper
# =============================================================================
def _hexdump(data: bytes, line_size: int = 16) -> str:
    """Format data as hex dump."""
    lines = []
    for i in range(0, len(data), line_size):
        chunk = data[i:i+line_size]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        lines.append(f"    0x{i:04x}: {hx:<48} |{asc}|")
    return '\n'.join(lines)


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
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or FOOTER_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or FOOTER_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Read footer data
# =============================================================================
def _read_footer(dev, footer_type: str) -> Optional[bytes]:
    """Read footer data from device."""
    size = FOOTER_SIZES.get(footer_type, 512)
    addr = FOOTER_ADDRESSES.get(footer_type, 0xFFFF0000)
    
    # Try FOOTER command first
    if _find_cmd("FOOTER"):
        type_code = {'STANDARD':1,'EXTENDED':2,'SECURITY':3,'BOOT':4,
                     'LOADER':5,'DEBUG':6,'AUDIT':7,'ALL':0xFF}.get(footer_type, 1)
        ok, _, data = _dispatch(dev, "FOOTER", struct.pack("<B", type_code))
        if ok and data: return data
    
    # Fallback: direct read
    ok, _, data = _dispatch(dev, "READ", struct.pack("<II", addr, size), timeout=10)
    if ok and data: return data[:size]
    
    return None


# =============================================================================
# FIXED: Flag parsers
# =============================================================================
_FLAG_DEFS = {
    'footer': {
        0x00000001:'VALIDATED',0x00000002:'SIGNED',0x00000004:'ENCRYPTED',
        0x00000008:'COMPRESSED',0x00000010:'DEBUG_ENABLED',0x00000020:'PRODUCTION',
        0x00000040:'DEVELOPMENT',0x00000080:'TEST_BUILD',0x00000100:'SECURE_BOOT',
        0x00000200:'TRUSTZONE',0x00000400:'ENCRYPTED_STORAGE',
    },
    'loader': {
        0x00000001:'RELOCATABLE',0x00000002:'PIC',0x00000004:'COMPRESSED',
        0x00000008:'ENCRYPTED',0x00000010:'SIGNED',0x00000020:'VERIFIED',
        0x00000040:'TRUSTED',0x00000080:'SECURE',0x00000100:'DEBUG_SYMBOLS',
        0x00000200:'STRIPPED',0x00000400:'SHARED_LIBRARY',0x00000800:'EXECUTABLE',
    },
    'debug': {
        0x00000001:'LOG_ENABLED',0x00000002:'TRACE_ENABLED',0x00000004:'PROFILING',
        0x00000008:'MEMORY_DEBUG',0x00000010:'ASSERT_ENABLED',0x00000020:'BREAK_ON_ERROR',
        0x00000040:'METRICS_ENABLED',0x00000080:'STACK_PROTECTION',
    },
    'security': {
        0x00000001:'SECURE_BOOT',0x00000002:'TRUSTZONE',0x00000004:'ENCRYPTION',
        0x00000008:'INTEGRITY_CHECK',0x00000010:'ANTI_ROLLBACK',0x00000020:'TAMPER_DETECT',
        0x00000040:'SECURE_DEBUG_OFF',0x00000080:'SECURE_STORAGE',0x00000100:'KEY_PROTECTION',
    },
}

def _parse_flags(flags: int, flag_type: str) -> List[str]:
    """Parse flags into human-readable list."""
    defs = _FLAG_DEFS.get(flag_type, {})
    return [d for f,d in defs.items() if flags & f]

def _format_ts(ts: int) -> str:
    """Format timestamp safely."""
    try:
        if 946684800 < ts < 2000000000:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    except: pass
    return f"0x{ts:08X}"


# =============================================================================
# FIXED: Footer parsers
# =============================================================================
def _parse_standard(data: bytes) -> Dict:
    info = {'type':'STANDARD'}
    if len(data) < 24: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['timestamp'] = struct.unpack('<I', data[12:16])[0]
        info['checksum'] = struct.unpack('<I', data[16:20])[0]
        info['data_size'] = struct.unpack('<I', data[20:24])[0]
        if len(data) >= 28:
            info['flags'] = struct.unpack('<I', data[24:28])[0]
            info['flags_parsed'] = _parse_flags(info['flags'], 'footer')
        info['timestamp_human'] = _format_ts(info['timestamp'])
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_extended(data: bytes) -> Dict:
    info = _parse_standard(data)
    info['type'] = 'EXTENDED'
    if len(data) < 64: return info
    try:
        info['build_id'] = data[32:48].hex()
        info['hw_compat'] = struct.unpack('<I', data[48:52])[0]
        info['sw_compat'] = struct.unpack('<I', data[52:56])[0]
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_security(data: bytes) -> Dict:
    info = {'type':'SECURITY'}
    if len(data) < 64: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['crypto_algo'] = struct.unpack('<I', data[12:16])[0]
        info['hash_type'] = struct.unpack('<I', data[16:20])[0]
        info['sig_type'] = struct.unpack('<I', data[20:24])[0]
        if len(data) >= 64:
            info['hash'] = data[32:64].hex()
        if len(data) >= 128:
            info['signature'] = data[64:128].hex()[:32]+'...'
        algo_map = {1:'AES-128',2:'AES-256',3:'RSA-2048',4:'RSA-4096',
                    5:'ECDSA-P256',6:'ECDSA-P384',7:'ECDSA-P521',
                    8:'SHA-256',9:'SHA-384',10:'SHA-512',11:'HMAC-SHA256'}
        info['crypto_name'] = algo_map.get(info['crypto_algo'], f'0x{info["crypto_algo"]:08X}')
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_boot(data: bytes) -> Dict:
    info = {'type':'BOOT'}
    if len(data) < 32: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['timestamp'] = struct.unpack('<I', data[12:16])[0]
        info['boot_source'] = struct.unpack('<I', data[16:20])[0]
        info['boot_reason'] = struct.unpack('<I', data[20:24])[0]
        info['boot_count'] = struct.unpack('<I', data[24:28])[0]
        info['boot_status'] = struct.unpack('<I', data[28:32])[0]
        source_map = {0:'POWER_ON',1:'SOFT_RESET',2:'WATCHDOG',3:'RECOVERY',
                      4:'BOOTLOADER',5:'CRASH',6:'SLEEP_WAKE'}
        reason_map = {0:'NORMAL',1:'UPDATE',2:'FACTORY_RESET',3:'SECURITY',
                      4:'HW_FAILURE',5:'SW_FAILURE',6:'WDT_TIMEOUT'}
        status_map = {0:'SUCCESS',1:'FAILED',2:'CRASHED',3:'WDT',4:'SEC_FAIL',5:'HW_ERROR'}
        info['source_name'] = source_map.get(info['boot_source'], f'0x{info["boot_source"]:X}')
        info['reason_name'] = reason_map.get(info['boot_reason'], f'0x{info["boot_reason"]:X}')
        info['status_name'] = status_map.get(info['boot_status'], f'0x{info["boot_status"]:X}')
        info['timestamp_human'] = _format_ts(info['timestamp'])
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_loader(data: bytes) -> Dict:
    info = {'type':'LOADER'}
    if len(data) < 44: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['timestamp'] = struct.unpack('<I', data[12:16])[0]
        info['checksum'] = struct.unpack('<I', data[16:20])[0]
        info['size'] = struct.unpack('<I', data[20:24])[0]
        info['entry'] = struct.unpack('<I', data[24:28])[0]
        info['load_addr'] = struct.unpack('<I', data[28:32])[0]
        arch_map = {0:'ARM32',1:'ARM64',2:'x86',3:'x64',4:'MIPS',5:'RISCV32',6:'RISCV64'}
        endian_map = {0:'LITTLE',1:'BIG'}
        info['arch'] = struct.unpack('<I', data[32:36])[0]
        info['arch_name'] = arch_map.get(info['arch'], f'0x{info["arch"]:X}')
        info['endian'] = struct.unpack('<I', data[36:40])[0]
        info['endian_name'] = endian_map.get(info['endian'], f'0x{info["endian"]:X}')
        if len(data) >= 44:
            info['flags'] = struct.unpack('<I', data[40:44])[0]
            info['flags_parsed'] = _parse_flags(info['flags'], 'loader')
        info['timestamp_human'] = _format_ts(info['timestamp'])
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_debug(data: bytes) -> Dict:
    info = {'type':'DEBUG'}
    if len(data) < 60: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['timestamp'] = struct.unpack('<I', data[12:16])[0]
        info['exceptions'] = struct.unpack('<I', data[16:20])[0]
        info['wdt_resets'] = struct.unpack('<I', data[20:24])[0]
        info['mem_errors'] = struct.unpack('<I', data[24:28])[0]
        info['io_errors'] = struct.unpack('<I', data[28:32])[0]
        info['last_error'] = struct.unpack('<I', data[40:44])[0]
        info['last_err_addr'] = struct.unpack('<I', data[44:48])[0]
        if len(data) >= 60:
            info['flags'] = struct.unpack('<I', data[56:60])[0]
            info['flags_parsed'] = _parse_flags(info['flags'], 'debug')
        if len(data) >= 128:
            desc = data[60:128]
            null = desc.find(b'\x00')
            info['error_desc'] = desc[:null].decode('ascii','ignore') if null!=-1 else desc.decode('ascii','ignore')
        info['timestamp_human'] = _format_ts(info['timestamp'])
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_audit(data: bytes) -> Dict:
    info = {'type':'AUDIT'}
    if len(data) < 52: return info
    try:
        info['magic'] = data[0:8].decode('ascii','ignore').rstrip('\x00').strip()
        info['version'] = struct.unpack('<I', data[8:12])[0]
        info['timestamp'] = struct.unpack('<I', data[12:16])[0]
        info['auth_fails'] = struct.unpack('<I', data[16:20])[0]
        info['access_denied'] = struct.unpack('<I', data[20:24])[0]
        info['integrity_fails'] = struct.unpack('<I', data[24:28])[0]
        info['tamper_events'] = struct.unpack('<I', data[28:32])[0]
        info['last_event'] = struct.unpack('<I', data[40:44])[0]
        info['last_event_ts'] = struct.unpack('<I', data[44:48])[0]
        info['last_severity'] = struct.unpack('<I', data[48:52])[0]
        state_map = {0:'SECURE',1:'WARNING',2:'COMPROMISED',3:'TAMPERED',4:'LOCKED'}
        if len(data) >= 132:
            info['sec_state'] = struct.unpack('<I', data[128:132])[0]
            info['sec_state_name'] = state_map.get(info['sec_state'], f'0x{info["sec_state"]:X}')
        if len(data) >= 136:
            info['flags'] = struct.unpack('<I', data[132:136])[0]
            info['flags_parsed'] = _parse_flags(info['flags'], 'security')
        info['timestamp_human'] = _format_ts(info['timestamp'])
    except Exception as e:
        info['error'] = str(e)
    return info

def _parse_all(data: bytes) -> Dict:
    """Try all parsers and pick best match."""
    parsers = [_parse_standard, _parse_extended, _parse_security, 
               _parse_boot, _parse_loader, _parse_debug, _parse_audit]
    best = None; best_score = -1
    for parser in parsers:
        try:
            result = parser(data)
            score = _match_score(result)
            if score > best_score:
                best_score = score; best = result
        except: pass
    if best:
        best['detected_type'] = best.get('type','UNKNOWN')
        best['confidence'] = best_score
    return best or {'type':'UNKNOWN','error':'Could not detect footer type'}

def _match_score(info: Dict) -> int:
    """Score how well parsed data matches expected footer structure."""
    score = 0
    if info.get('magic'): score += 30
    ts = info.get('timestamp', 0)
    if 946684800 < ts < 2000000000: score += 20
    ver = info.get('version', 0)
    if 0 < ver < 0xFFFF: score += 15
    if info.get('error'): score -= 40
    return max(0, score)


# =============================================================================
# FIXED: Validation
# =============================================================================
def _validate(data: bytes, info: Dict, ftype: str) -> Dict:
    """Validate footer integrity."""
    v = {}
    crc = zlib.crc32(data) & 0xFFFFFFFF
    v['crc_calculated'] = f"0x{crc:08X}"
    
    for key in ['checksum','loader_checksum']:
        if key in info:
            embedded = info[key]
            v['crc_match'] = (crc == embedded)
            v['crc_embedded'] = f"0x{embedded:08X}"
            break
    
    # Magic validation
    expected = {
        'STANDARD':['QSLCL'],'EXTENDED':['QSLCL'],'SECURITY':['SECURE','SECURITY'],
        'BOOT':['BOOT'],'LOADER':['LOADER','LDR'],'DEBUG':['DEBUG','DIAG'],
        'AUDIT':['AUDIT','SECLOG']
    }.get(ftype, [])
    
    if expected and 'magic' in info:
        v['magic_valid'] = any(e in info['magic'].upper() for e in expected)
    
    # Timestamp validation
    for k in ['timestamp','boot_timestamp','debug_timestamp','audit_timestamp']:
        if k in info and isinstance(info[k], int):
            ts = info[k]
            if 946684800 < ts < 2000000000:
                v[f'{k}_valid'] = True
    
    v['overall'] = all(v[k] for k in v if isinstance(v[k], bool))
    return v


# =============================================================================
# FIXED: Display functions
# =============================================================================
def _display_info(info: Dict, ftype: str):
    """Display structured footer information."""
    print(f"\n{C.BOLD}[+] Footer: {ftype}{C.RESET}")
    
    # Basic fields
    fields = [
        ('Magic', info.get('magic','?')),
        ('Version', f"0x{info.get('version',0):08X}" if 'version' in info else None),
        ('Checksum', f"0x{info.get('checksum',0):08X}" if 'checksum' in info else None),
        ('Data Size', f"{info.get('data_size',0)} bytes" if 'data_size' in info else None),
        ('Size', f"{info.get('size',0)} bytes" if 'size' in info else None),
    ]
    for label, val in fields:
        if val: print(f"    {label:<14} {val}")
    
    # Timestamps
    ts_fields = ['timestamp_human','boot_timestamp_human']
    for k in ts_fields:
        if k in info: print(f"    {'Timestamp':<14} {info[k]}")
    
    # Type-specific
    if ftype == 'SECURITY':
        if info.get('crypto_name'): print(f"    Crypto:     {info['crypto_name']}")
        if info.get('hash'): print(f"    Hash:       {info['hash'][:32]}...")
    elif ftype == 'BOOT':
        if info.get('source_name'): print(f"    Source:     {info['source_name']}")
        if info.get('reason_name'): print(f"    Reason:     {info['reason_name']}")
        if info.get('status_name'): print(f"    Status:     {info['status_name']}")
        if 'boot_count' in info: print(f"    Boot Count: {info['boot_count']}")
    elif ftype == 'LOADER':
        if info.get('arch_name'): print(f"    Arch:       {info['arch_name']}")
        if info.get('endian_name'): print(f"    Endian:     {info['endian_name']}")
        if 'entry' in info: print(f"    Entry:      0x{info['entry']:08X}")
        if 'load_addr' in info: print(f"    Load:       0x{info['load_addr']:08X}")
    elif ftype == 'DEBUG':
        if 'exceptions' in info: print(f"    Exceptions: {info['exceptions']}")
        if 'wdt_resets' in info: print(f"    WDT Resets: {info['wdt_resets']}")
        if 'error_desc' in info: print(f"    Last Error: {info['error_desc']}")
    elif ftype == 'AUDIT':
        if info.get('sec_state_name'): print(f"    State:      {info['sec_state_name']}")
        if 'auth_fails' in info: print(f"    Auth Fails: {info['auth_fails']}")
        if 'tamper_events' in info: print(f"    Tamper:     {info['tamper_events']}")
        if 'integrity_fails' in info: print(f"    Integrity:  {info['integrity_fails']}")
    
    # Flags
    for k in ['flags_parsed','loader_flags_parsed','debug_flags_parsed','security_flags_parsed']:
        if info.get(k): print(f"    Flags:      {', '.join(info[k])}")
    
    # ALL type
    if ftype == 'ALL' and 'detected_type' in info:
        print(f"    Detected:   {info['detected_type']} (confidence: {info.get('confidence',0)})")
    
    if info.get('error'): print(f"    {C.RED}[!] Error: {info['error']}{C.RESET}")

def _display_validation(v: Dict):
    """Display validation results."""
    print(f"\n{C.BOLD}[+] Validation:{C.RESET}")
    for k, val in sorted(v.items()):
        if k == 'overall': continue
        if isinstance(val, bool):
            icon = f"{C.GREEN}✓{C.RESET}" if val else f"{C.RED}✗{C.RESET}"
            print(f"    {icon} {k}: {'PASS' if val else 'FAIL'}")
        elif isinstance(val, str):
            print(f"    {k}: {val}")
    
    if 'overall' in v:
        icon = f"{C.GREEN}✓{C.RESET}" if v['overall'] else f"{C.RED}✗{C.RESET}"
        print(f"\n    {icon} OVERALL: {'VALID' if v['overall'] else 'INVALID'}")

def _security_assessment(info: Dict, ftype: str) -> List[str]:
    """Generate security assessment."""
    a = []
    
    if ftype == 'SECURITY':
        cn = info.get('crypto_name','')
        if any(w in cn for w in ['AES-128','RSA-2048']):
            a.append("🟡 Crypto algorithm could be stronger")
        elif any(w in cn for w in ['AES-256','RSA-4096','ECDSA']):
            a.append("🟢 Strong crypto algorithm")
        elif 'UNKNOWN' in cn or not cn:
            a.append("🔴 Unknown crypto - SECURITY RISK")
    
    elif ftype == 'BOOT':
        if info.get('source_name') == 'CRASH':
            a.append("🔴 Last boot was crash - investigate")
        if info.get('status_name') not in ('SUCCESS', None):
            a.append("🟡 Previous boot had issues")
    
    elif ftype == 'AUDIT':
        if info.get('sec_state_name') in ('COMPROMISED','TAMPERED'):
            a.append("🔴 SECURITY COMPROMISED - IMMEDIATE ACTION")
        if info.get('tamper_events', 0) > 0:
            a.append(f"🔴 {info['tamper_events']} tamper event(s)")
        if info.get('auth_fails', 0) > 50:
            a.append(f"🔴 {info['auth_fails']} auth failures - possible attack")
    
    elif ftype == 'LOADER':
        flags = info.get('flags_parsed', [])
        if 'SIGNED' not in flags and 'VERIFIED' not in flags:
            a.append("🔴 Loader not signed/verified")
    
    if info.get('error'):
        a.append("🔴 Parse errors - footer may be corrupted")
    
    if not a:
        a.append("🟢 No obvious security issues")
    return a


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_footer(args=None) -> Optional[Dict]:
    """QSLCL FOOTER Command v2.0"""
    
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_help(); return None
    
    if not _use_qslcl: _warn_standalone()
    
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return None
        if not devs: print(f"{C.RED}[!] No device{C.RESET}"); return None
        dev = devs[0]
        print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        print(f"{C.RED}[!] No QSLCL{C.RESET}"); return None
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    # Parse options
    ftype = getattr(args, 'footer_type', 'STANDARD') or 'STANDARD'
    ftype = ftype.upper() if ftype in FOOTER_TYPES else 'STANDARD'
    
    show_raw = getattr(args, 'raw', False)
    show_hex = getattr(args, 'hex', False)
    show_verbose = getattr(args, 'verbose', False)
    show_crc = getattr(args, 'crc', False)
    show_meta = getattr(args, 'metadata', False)
    show_struct = getattr(args, 'structured', False)
    show_json = getattr(args, 'json', False)
    validate = getattr(args, 'validate', False)
    save_file = getattr(args, 'save', None)
    show_all = getattr(args, 'all', False)
    
    if show_all:
        show_raw = show_hex = show_verbose = show_crc = show_meta = show_struct = validate = True
    
    print(f"\n{C.CYAN}[*] Footer: {ftype}{C.RESET}")
    
    # Read footer
    data = _read_footer(dev, ftype)
    if not data:
        print(f"{C.RED}[!] Failed to read footer{C.RESET}")
        return None
    
    print(f"[+] Read {len(data)} bytes")
    
    # Parse
    parsers = {
        'STANDARD':_parse_standard,'EXTENDED':_parse_extended,
        'SECURITY':_parse_security,'BOOT':_parse_boot,
        'LOADER':_parse_loader,'DEBUG':_parse_debug,
        'AUDIT':_parse_audit,'ALL':_parse_all,
    }
    
    info = parsers.get(ftype, _parse_standard)(data)
    
    # Validate
    v = _validate(data, info, ftype) if validate else {}
    
    # Display
    if show_raw or show_hex:
        print(f"\n{C.BOLD}[+] Raw Data:{C.RESET}")
        print(_hexdump(data[:256]))
    
    if show_struct or not (show_raw or show_hex):
        _display_info(info, ftype)
    
    if show_verbose:
        print(f"\n{C.BOLD}[+] All Fields:{C.RESET}")
        for k, val in sorted(info.items()):
            if isinstance(val, (int, str)) and len(str(val)) < 100:
                print(f"    {k:<20} {val}")
    
    if show_crc:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        print(f"\n{C.BOLD}[+] CRC32: 0x{crc:08X}{C.RESET}")
    
    if show_meta:
        ints = sum(1 for v in info.values() if isinstance(v,int))
        strs = sum(1 for v in info.values() if isinstance(v,str))
        print(f"\n{C.BOLD}[+] Metadata: {len(info)} fields ({ints} int, {strs} str){C.RESET}")
    
    if validate and v:
        _display_validation(v)
    
    # Security assessment
    if ftype in ('SECURITY','BOOT','AUDIT','LOADER'):
        print(f"\n{C.BOLD}[+] Security Assessment:{C.RESET}")
        for a in _security_assessment(info, ftype):
            print(f"    {a}")
    
    # JSON
    if show_json:
        print(f"\n{C.BOLD}[+] JSON:{C.RESET}")
        print(json.dumps({'footer_type':ftype,'size':len(data),'analysis':info,'validation':v}, 
                        indent=2, default=str))
    
    # Save
    if save_file:
        try:
            d = os.path.dirname(os.path.abspath(save_file))
            if d: os.makedirs(d, exist_ok=True)
            with open(save_file, 'wb') as f: f.write(data)
            print(f"\n{C.GREEN}[+] Saved: {save_file} ({len(data)}B){C.RESET}")
        except Exception as e:
            print(f"{C.RED}[!] Save failed: {e}{C.RESET}")
    
    return info


def print_help():
    print(f"""
{C.BOLD}FOOTER - Footer Analysis & Validation{C.RESET}
{'='*50}

{C.CYAN}USAGE:{C.RESET}
  qslcl footer [options]

{C.CYAN}TYPES:{C.RESET}
  --type STANDARD|EXTENDED|SECURITY|BOOT|LOADER|DEBUG|AUDIT|ALL

{C.CYAN}OPTIONS:{C.RESET}
  --raw           Show raw hex dump
  --hex           Show hex dump
  --structured    Show structured info
  --verbose       Show all fields
  --crc           Show CRC32
  --metadata      Show metadata
  --validate      Validate footer integrity
  --json          JSON output
  --all           Enable all display options
  --save <file>   Save footer data to file

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl footer --type STANDARD --validate
  qslcl footer --type SECURITY --all
  qslcl footer --type ALL --json
  qslcl footer --save footer.bin
""")


def add_footer_arguments(parser):
    parser.add_argument('--type', dest='footer_type', default='STANDARD',
                       choices=[t.lower() for t in FOOTER_TYPES] + FOOTER_TYPES)
    parser.add_argument('footer_args', nargs='*')
    parser.add_argument('--raw', action='store_true')
    parser.add_argument('--hex', action='store_true')
    parser.add_argument('--extended', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--crc', action='store_true')
    parser.add_argument('--metadata', action='store_true')
    parser.add_argument('--structured', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--validate', action='store_true')
    parser.add_argument('--save', metavar='FILE')
    return parser


if __name__ == "__main__":
    print("[*] footer.py - QSLCL FOOTER Module v2.0")
    print_help()