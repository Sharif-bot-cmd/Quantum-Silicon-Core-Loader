#!/usr/bin/env python3
"""
footer.py - QSLCL FOOTER Command Module v2.1 (CLEANED)
Footer analysis, validation, and security assessment
"""

import os
import sys
import struct
import time
import json
import zlib
from typing import Optional, List, Dict, Tuple

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
TIMEOUT = 15.0

FOOTER_TYPES = ['STANDARD', 'EXTENDED', 'SECURITY', 'BOOT', 'LOADER', 'DEBUG', 'AUDIT', 'ALL']

FOOTER_SIZES = {
    'STANDARD': 64, 'EXTENDED': 128, 'SECURITY': 256,
    'BOOT': 128, 'LOADER': 256, 'DEBUG': 512, 'AUDIT': 1024, 'ALL': 1024,
}

FOOTER_ADDRS = {
    'STANDARD': 0xFFFF0000, 'EXTENDED': 0xFFFF1000, 'SECURITY': 0xFFFF2000,
    'BOOT': 0xFFFF3000, 'LOADER': 0xFFFF4000, 'DEBUG': 0xFFFF5000,
    'AUDIT': 0xFFFF6000, 'ALL': 0xFFFF0000,
}

# Flag definitions
FLAGS = {
    'footer': {1:'VALIDATED', 2:'SIGNED', 4:'ENCRYPTED', 8:'COMPRESSED',
               16:'DEBUG', 32:'PRODUCTION', 64:'DEVELOPMENT', 128:'TEST',
               256:'SECURE_BOOT', 512:'TRUSTZONE', 1024:'ENCRYPTED_STORAGE'},
    'loader': {1:'RELOCATABLE', 2:'PIC', 4:'COMPRESSED', 8:'ENCRYPTED',
               16:'SIGNED', 32:'VERIFIED', 64:'TRUSTED', 128:'SECURE',
               256:'DEBUG_SYMBOLS', 512:'STRIPPED', 1024:'SHARED', 2048:'EXECUTABLE'},
    'debug': {1:'LOG', 2:'TRACE', 4:'PROFILING', 8:'MEM_DEBUG',
              16:'ASSERT', 32:'BREAK', 64:'METRICS', 128:'STACK_PROTECT'},
    'security': {1:'SECURE_BOOT', 2:'TRUSTZONE', 4:'ENCRYPTION',
                 8:'INTEGRITY', 16:'ANTI_ROLLBACK', 32:'TAMPER_DETECT',
                 64:'SECURE_DEBUG_OFF', 128:'SECURE_STORAGE', 256:'KEY_PROTECT'},
}

ARCH_MAP = {0:'ARM32', 1:'ARM64', 2:'x86', 3:'x64', 4:'MIPS', 5:'RISCV32', 6:'RISCV64'}
SOURCE_MAP = {0:'POWER_ON', 1:'SOFT_RESET', 2:'WATCHDOG', 3:'RECOVERY', 4:'BOOTLOADER', 5:'CRASH', 6:'SLEEP'}
REASON_MAP = {0:'NORMAL', 1:'UPDATE', 2:'FACTORY', 3:'SECURITY', 4:'HW_FAIL', 5:'SW_FAIL', 6:'WDT'}
STATUS_MAP = {0:'OK', 1:'FAILED', 2:'CRASHED', 3:'WDT', 4:'SEC_FAIL', 5:'HW_ERROR'}
STATE_MAP = {0:'SECURE', 1:'WARNING', 2:'COMPROMISED', 3:'TAMPERED', 4:'LOCKED'}
CRYPTO_MAP = {1:'AES-128', 2:'AES-256', 3:'RSA-2048', 4:'RSA-4096', 5:'ECDSA-P256', 6:'ECDSA-P384', 7:'ECDSA-P521'}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def footer_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send footer command"""
    for attempt in range(2):
        try:
            if "FOOTER" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "FOOTER", payload, timeout=TIMEOUT)
            elif "READ" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "READ", payload, timeout=TIMEOUT)
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


def read_footer(dev, ftype: str) -> Optional[bytes]:
    """Read footer from device"""
    size = FOOTER_SIZES.get(ftype, 512)
    addr = FOOTER_ADDRS.get(ftype, 0xFFFF0000)
    
    # Try FOOTER command first
    type_code = {'STANDARD':1, 'EXTENDED':2, 'SECURITY':3, 'BOOT':4,
                 'LOADER':5, 'DEBUG':6, 'AUDIT':7, 'ALL':0xFF}.get(ftype, 1)
    
    ok, _, data = footer_cmd(dev, struct.pack("<B", type_code))
    if ok and data:
        return data
    
    # Fallback: direct read
    ok, _, data = footer_cmd(dev, struct.pack("<II", addr, size))
    if ok and data:
        return data[:size]
    
    return None


def parse_flags(flags: int, flag_type: str) -> List[str]:
    """Parse flags to list"""
    defs = FLAGS.get(flag_type, {})
    return [d for f, d in defs.items() if flags & f]


def format_ts(ts: int) -> str:
    """Safe timestamp formatting"""
    try:
        if 946684800 < ts < 2000000000:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    except: pass
    return f"0x{ts:08X}"


def hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Format hex dump"""
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"    0x{i:04x}: {hx:<48} |{asc}|")
    return '\n'.join(lines)


# =============================================================================
# FOOTER PARSERS
# =============================================================================
def parse_standard(data: bytes) -> dict:
    r = {'type': 'STANDARD'}
    if len(data) < 28: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['timestamp'] = struct.unpack('<I', data[12:16])[0]
        r['checksum'] = struct.unpack('<I', data[16:20])[0]
        r['data_size'] = struct.unpack('<I', data[20:24])[0]
        r['flags'] = struct.unpack('<I', data[24:28])[0]
        r['flags_list'] = parse_flags(r['flags'], 'footer')
        r['timestamp_str'] = format_ts(r['timestamp'])
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_extended(data: bytes) -> dict:
    r = parse_standard(data)
    r['type'] = 'EXTENDED'
    if len(data) < 56: return r
    try:
        r['build_id'] = data[32:48].hex()
        r['hw_compat'] = struct.unpack('<I', data[48:52])[0]
        r['sw_compat'] = struct.unpack('<I', data[52:56])[0]
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_security(data: bytes) -> dict:
    r = {'type': 'SECURITY'}
    if len(data) < 64: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['crypto'] = struct.unpack('<I', data[12:16])[0]
        r['hash_type'] = struct.unpack('<I', data[16:20])[0]
        r['sig_type'] = struct.unpack('<I', data[20:24])[0]
        r['crypto_name'] = CRYPTO_MAP.get(r['crypto'], f'0x{r["crypto"]:08X}')
        if len(data) >= 64: r['hash'] = data[32:64].hex()
        if len(data) >= 128: r['signature'] = data[64:128].hex()[:32] + '...'
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_boot(data: bytes) -> dict:
    r = {'type': 'BOOT'}
    if len(data) < 32: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['timestamp'] = struct.unpack('<I', data[12:16])[0]
        r['source'] = struct.unpack('<I', data[16:20])[0]
        r['reason'] = struct.unpack('<I', data[20:24])[0]
        r['count'] = struct.unpack('<I', data[24:28])[0]
        r['status'] = struct.unpack('<I', data[28:32])[0]
        r['source_name'] = SOURCE_MAP.get(r['source'], f'0x{r["source"]:X}')
        r['reason_name'] = REASON_MAP.get(r['reason'], f'0x{r["reason"]:X}')
        r['status_name'] = STATUS_MAP.get(r['status'], f'0x{r["status"]:X}')
        r['timestamp_str'] = format_ts(r['timestamp'])
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_loader(data: bytes) -> dict:
    r = {'type': 'LOADER'}
    if len(data) < 44: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['timestamp'] = struct.unpack('<I', data[12:16])[0]
        r['checksum'] = struct.unpack('<I', data[16:20])[0]
        r['size'] = struct.unpack('<I', data[20:24])[0]
        r['entry'] = struct.unpack('<I', data[24:28])[0]
        r['load_addr'] = struct.unpack('<I', data[28:32])[0]
        r['arch'] = struct.unpack('<I', data[32:36])[0]
        r['arch_name'] = ARCH_MAP.get(r['arch'], f'0x{r["arch"]:X}')
        r['endian'] = struct.unpack('<I', data[36:40])[0]
        r['endian_name'] = {0:'LITTLE', 1:'BIG'}.get(r['endian'], '?')
        r['flags'] = struct.unpack('<I', data[40:44])[0]
        r['flags_list'] = parse_flags(r['flags'], 'loader')
        r['timestamp_str'] = format_ts(r['timestamp'])
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_debug(data: bytes) -> dict:
    r = {'type': 'DEBUG'}
    if len(data) < 60: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['timestamp'] = struct.unpack('<I', data[12:16])[0]
        r['exceptions'] = struct.unpack('<I', data[16:20])[0]
        r['wdt_resets'] = struct.unpack('<I', data[20:24])[0]
        r['mem_errors'] = struct.unpack('<I', data[24:28])[0]
        r['io_errors'] = struct.unpack('<I', data[28:32])[0]
        r['last_error'] = struct.unpack('<I', data[40:44])[0]
        r['last_addr'] = struct.unpack('<I', data[44:48])[0]
        r['flags'] = struct.unpack('<I', data[56:60])[0]
        r['flags_list'] = parse_flags(r['flags'], 'debug')
        r['timestamp_str'] = format_ts(r['timestamp'])
        if len(data) >= 128:
            desc = data[60:128]
            null = desc.find(b'\x00')
            r['error_desc'] = desc[:null].decode('ascii', 'ignore') if null != -1 else desc.decode('ascii', 'ignore')
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_audit(data: bytes) -> dict:
    r = {'type': 'AUDIT'}
    if len(data) < 52: return r
    try:
        r['magic'] = data[0:8].decode('ascii', 'ignore').rstrip('\x00').strip()
        r['version'] = struct.unpack('<I', data[8:12])[0]
        r['timestamp'] = struct.unpack('<I', data[12:16])[0]
        r['auth_fails'] = struct.unpack('<I', data[16:20])[0]
        r['access_denied'] = struct.unpack('<I', data[20:24])[0]
        r['integrity_fails'] = struct.unpack('<I', data[24:28])[0]
        r['tamper_events'] = struct.unpack('<I', data[28:32])[0]
        r['last_event'] = struct.unpack('<I', data[40:44])[0]
        r['last_event_ts'] = struct.unpack('<I', data[44:48])[0]
        r['last_severity'] = struct.unpack('<I', data[48:52])[0]
        r['sec_state'] = struct.unpack('<I', data[128:132])[0] if len(data) >= 132 else 0
        r['sec_state_name'] = STATE_MAP.get(r['sec_state'], f'0x{r["sec_state"]:X}')
        r['flags'] = struct.unpack('<I', data[132:136])[0] if len(data) >= 136 else 0
        r['flags_list'] = parse_flags(r['flags'], 'security')
        r['timestamp_str'] = format_ts(r['timestamp'])
    except Exception as e:
        r['error'] = str(e)
    return r


def parse_all(data: bytes) -> dict:
    """Auto-detect footer type"""
    parsers = [parse_standard, parse_extended, parse_security, parse_boot, parse_loader, parse_debug, parse_audit]
    best, best_score = None, -1
    
    for parser in parsers:
        try:
            result = parser(data)
            score = 0
            if result.get('magic'): score += 30
            ts = result.get('timestamp', 0)
            if 946684800 < ts < 2000000000: score += 20
            if 0 < result.get('version', 0) < 0xFFFF: score += 15
            if result.get('error'): score -= 40
            if score > best_score:
                best_score, best = score, result
        except: pass
    
    if best:
        best['detected_type'] = best.get('type', 'UNKNOWN')
        best['confidence'] = best_score
    return best or {'type': 'UNKNOWN', 'error': 'Could not detect'}


def validate_footer(data: bytes, info: dict) -> dict:
    """Validate footer integrity"""
    v = {}
    crc = zlib.crc32(data) & 0xFFFFFFFF
    v['crc_calculated'] = f"0x{crc:08X}"
    
    for key in ['checksum', 'loader_checksum']:
        if key in info:
            v['crc_match'] = (crc == info[key])
            v['crc_embedded'] = f"0x{info[key]:08X}"
            break
    
    expected = {
        'STANDARD': ['QSLCL'], 'SECURITY': ['SECURE', 'SECURITY'],
        'BOOT': ['BOOT'], 'LOADER': ['LOADER', 'LDR'],
        'DEBUG': ['DEBUG', 'DIAG'], 'AUDIT': ['AUDIT', 'SECLOG']
    }.get(info.get('type', ''), [])
    
    if expected and 'magic' in info:
        v['magic_valid'] = any(e in str(info['magic']).upper() for e in expected)
    
    for k, v2 in info.items():
        if 'timestamp' in k and isinstance(v2, int):
            if 946684800 < v2 < 2000000000:
                v[f'{k}_valid'] = True
    
    v['overall'] = all(v[k] for k in v if isinstance(v[k], bool))
    return v


def security_assess(info: dict) -> List[str]:
    """Security assessment"""
    a = []
    ftype = info.get('type', '')
    
    if ftype == 'SECURITY':
        cn = info.get('crypto_name', '')
        if any(w in cn for w in ['AES-256', 'RSA-4096', 'ECDSA']):
            a.append("🟢 Strong crypto")
        elif any(w in cn for w in ['AES-128', 'RSA-2048']):
            a.append("🟡 Moderate crypto")
        else:
            a.append("🔴 Unknown/weak crypto")
    
    elif ftype == 'BOOT':
        if info.get('source_name') == 'CRASH':
            a.append("🔴 Last boot was crash")
        if info.get('status_name') not in ('OK', None):
            a.append("🟡 Previous boot had issues")
    
    elif ftype == 'AUDIT':
        state = info.get('sec_state_name', '')
        if state in ('COMPROMISED', 'TAMPERED'):
            a.append("🔴 SECURITY COMPROMISED!")
        if info.get('tamper_events', 0) > 0:
            a.append(f"🔴 {info['tamper_events']} tamper event(s)")
        if info.get('auth_fails', 0) > 50:
            a.append(f"🔴 {info['auth_fails']} auth failures")
    
    elif ftype == 'LOADER':
        flags = info.get('flags_list', [])
        if 'SIGNED' not in flags and 'VERIFIED' not in flags:
            a.append("🔴 Loader not signed/verified")
    
    if info.get('error'):
        a.append("🔴 Parse errors - possible corruption")
    
    return a or ["🟢 No obvious issues"]


# =============================================================================
# DISPLAY FUNCTIONS
# =============================================================================
def display_info(info: dict):
    """Display footer info"""
    ftype = info.get('type', '?')
    print(f"\n[*] Footer: {ftype}")
    
    # Basic fields
    for label, key in [('Magic', 'magic'), ('Version', 'version'), ('Size', 'data_size')]:
        if key in info:
            val = f"0x{info[key]:08X}" if isinstance(info[key], int) and key != 'magic' else info[key]
            print(f"    {label:<12} {val}")
    
    # Timestamp
    if 'timestamp_str' in info:
        print(f"    {'Time':<12} {info['timestamp_str']}")
    
    # Type-specific
    if ftype == 'SECURITY':
        if info.get('crypto_name'): print(f"    Crypto:   {info['crypto_name']}")
        if info.get('hash'): print(f"    Hash:     {info['hash'][:32]}...")
    elif ftype == 'BOOT':
        if info.get('source_name'): print(f"    Source:   {info['source_name']}")
        if info.get('reason_name'): print(f"    Reason:   {info['reason_name']}")
        if info.get('status_name'): print(f"    Status:   {info['status_name']}")
        if 'count' in info: print(f"    Boots:    {info['count']}")
    elif ftype == 'LOADER':
        if info.get('arch_name'): print(f"    Arch:     {info['arch_name']}")
        if 'entry' in info: print(f"    Entry:    0x{info['entry']:08X}")
        if 'load_addr' in info: print(f"    Load:     0x{info['load_addr']:08X}")
    elif ftype == 'DEBUG':
        if 'exceptions' in info: print(f"    Exceptions: {info['exceptions']}")
        if 'wdt_resets' in info: print(f"    WDT:      {info['wdt_resets']}")
        if 'error_desc' in info: print(f"    Last Err: {info['error_desc']}")
    elif ftype == 'AUDIT':
        if info.get('sec_state_name'): print(f"    State:    {info['sec_state_name']}")
        if 'auth_fails' in info: print(f"    AuthFail: {info['auth_fails']}")
        if 'tamper_events' in info: print(f"    Tamper:   {info['tamper_events']}")
    elif ftype == 'ALL' and 'detected_type' in info:
        print(f"    Detected: {info['detected_type']} ({info.get('confidence', 0)}%)")
    
    # Flags
    for k in ['flags_list']:
        if info.get(k):
            print(f"    Flags:    {', '.join(info[k])}")
    
    if info.get('error'):
        print(f"    [!] Error: {info['error']}")


def display_validation(v: dict):
    """Display validation"""
    print(f"\n[*] Validation:")
    for k, val in sorted(v.items()):
        if k == 'overall': continue
        if isinstance(val, bool):
            print(f"    {'✓' if val else '✗'} {k}: {'PASS' if val else 'FAIL'}")
        elif isinstance(val, str):
            print(f"      {k}: {val}")
    
    if 'overall' in v:
        print(f"\n    {'✓' if v['overall'] else '✗'} OVERALL: {'VALID' if v['overall'] else 'INVALID'}")


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_footer(args=None) -> Optional[dict]:
    """
    QSLCL FOOTER - Footer analysis and validation
    
    Examples:
        footer --type STANDARD              - Standard footer
        footer --type SECURITY --validate   - Security footer with validation
        footer --type ALL --json            - Auto-detect with JSON output
        footer --type BOOT --all            - Boot footer with all info
        footer --save footer.bin            - Save raw footer data
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: footer [--type TYPE] [options]")
        return None
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return None
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Options
    ftype = (getattr(args, 'footer_type', 'STANDARD') or 'STANDARD').upper()
    ftype = ftype if ftype in FOOTER_TYPES else 'STANDARD'
    
    show_raw = getattr(args, 'raw', False) or getattr(args, 'hex', False)
    show_struct = getattr(args, 'structured', False)
    show_verbose = getattr(args, 'verbose', False)
    show_crc = getattr(args, 'crc', False)
    show_json = getattr(args, 'json', False)
    do_validate = getattr(args, 'validate', False)
    save_file = getattr(args, 'save', None)
    show_all = getattr(args, 'all', False)
    
    if show_all:
        show_raw = show_struct = show_verbose = show_crc = show_json = do_validate = True
    
    print(f"\n[*] Footer type: {ftype}")
    
    # Read
    data = read_footer(dev, ftype)
    if not data:
        print("[!] Failed to read footer")
        return None
    
    print(f"[+] Read {len(data)} bytes")
    
    # Parse
    parsers = {
        'STANDARD': parse_standard, 'EXTENDED': parse_extended,
        'SECURITY': parse_security, 'BOOT': parse_boot,
        'LOADER': parse_loader, 'DEBUG': parse_debug,
        'AUDIT': parse_audit, 'ALL': parse_all,
    }
    info = parsers.get(ftype, parse_standard)(data)
    
    # Display raw
    if show_raw:
        print(f"\n[*] Raw Data:")
        print(hexdump(data))
    
    # Display structured
    if show_struct or not show_raw:
        display_info(info)
    
    # Verbose
    if show_verbose:
        print(f"\n[*] All Fields:")
        for k, v in sorted(info.items()):
            if isinstance(v, (int, str)) and len(str(v)) < 100:
                print(f"    {k:<20} {v}")
    
    # CRC
    if show_crc:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        print(f"\n[*] CRC32: 0x{crc:08X}")
    
    # Validate
    if do_validate:
        v = validate_footer(data, info)
        display_validation(v)
    
    # Security
    if ftype in ('SECURITY', 'BOOT', 'AUDIT', 'LOADER'):
        print(f"\n[*] Security Assessment:")
        for a in security_assess(info):
            print(f"    {a}")
    
    # JSON
    if show_json:
        print(f"\n[*] JSON:")
        v = validate_footer(data, info) if do_validate else {}
        print(json.dumps({'type': ftype, 'size': len(data), 'analysis': info, 'validation': v},
                        indent=2, default=str))
    
    # Save
    if save_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(save_file)) or '.', exist_ok=True)
            with open(save_file, 'wb') as f:
                f.write(data)
            print(f"\n[+] Saved: {save_file} ({len(data)} bytes)")
        except Exception as e:
            print(f"[!] Save failed: {e}")
    
    return info


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] footer.py - QSLCL FOOTER Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py footer [--type TYPE] [options]")