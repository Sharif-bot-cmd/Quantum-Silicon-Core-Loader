#!/usr/bin/env python3
"""
patch.py - QSLCL PATCH Command Module v2.1 (CLEANED)
Binary patching with backup, verification, and safety checks
"""

import os
import sys
import struct
import time
import json
import hashlib
from typing import Optional, List, Tuple

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
TIMEOUT = 30.0
MAX_PATCH = 100 * 1024 * 1024
DEFAULT_CHUNK = 65536
MAX_RETRIES = 3

CRITICAL_PARTS = {'boot','bootloader','aboot','sbl','xbl','recovery','tz','rpm','hyp','preloader'}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_addr(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    if s.startswith('0b'): return int(s[2:], 2)
    try: return int(s, 16)
    except: return int(s, 10)


def parse_size(s: str) -> int:
    s = str(s).strip().upper()
    if not s: return 0
    if s.startswith('0X'): return int(s, 16)
    for sfx, mul in [('GB',1024**3),('G',1024**3),('MB',1024**2),('M',1024**2),
                      ('KB',1024),('K',1024),('B',1)]:
        if s.endswith(sfx): return int(float(s[:-len(sfx)]) * mul)
    try: return int(s)
    except: return int(float(s))


def format_size(n: int) -> str:
    if n < 1024: return f"{n}B"
    elif n < 1024**2: return f"{n/1024:.0f}KB"
    return f"{n/(1024**2):.1f}MB"


def confirm(msg: str, req: str, force: bool) -> bool:
    if force:
        print("\n[!] Force mode: skipping confirmation")
        return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ").upper() == req.upper()
    except: return False


def patch_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send patch command"""
    for attempt in range(MAX_RETRIES):
        try:
            if "PATCH" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "PATCH", payload, timeout=TIMEOUT)
            elif "WRITE" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "WRITE", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.2)
    
    return False, "NO_RESPONSE", b""


def read_cmd(dev, addr: int, size: int) -> Tuple[bool, bytes]:
    """Read memory"""
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


# =============================================================================
# TARGET RESOLUTION
# =============================================================================
def resolve_target(target: str, dev) -> Optional[Tuple[int, int, Optional[dict]]]:
    """Resolve patch target to (address, size, partition_info)"""
    s = str(target).strip()
    sl = s.lower()
    
    # Hex address
    if sl.startswith('0x'):
        try: return parse_addr(s), 0, None
        except: pass
    
    # Range: start-end
    if '-' in s and s.count('-') == 1:
        try:
            parts = s.split('-')
            a, b = parse_addr(parts[0]), parse_addr(parts[1])
            if a < b: return a, b - a, None
        except: pass
    
    # Partition+offset: "boot+0x1000"
    if '+' in s:
        try:
            name, off_str = s.split('+', 1)
            offset = parse_addr(off_str.strip())
            parts = load_partitions(dev)
            for p in parts:
                if p.get('name','').lower() == name.strip().lower():
                    addr = p['offset'] + offset
                    remaining = p['size'] - offset
                    if remaining <= 0:
                        print(f"[!] Offset exceeds partition size")
                        return None
                    return addr, remaining, p
        except: pass
    
    # Partition name
    try:
        parts = load_partitions(dev)
        for p in parts:
            if p.get('name','').lower() == sl:
                return p['offset'], p['size'], p
    except: pass
    
    # Decimal address
    try: return int(s), 0, None
    except: pass
    
    return None


def list_targets(dev):
    """List available patch targets"""
    print(f"\n[*] Available Patch Targets:")
    
    try:
        parts = load_partitions(dev)
        if parts:
            print(f"\n    Partitions:")
            print(f"    {'Name':<18} {'Start':<12} {'Size':<12}")
            print(f"    {'-'*18} {'-'*12} {'-'*12}")
            for p in sorted(parts, key=lambda x: x.get('offset',0)):
                name = p.get('name','?')
                off = p.get('offset',0)
                sz = p.get('size',0)
                crit = ' ⚠' if name.lower() in CRITICAL_PARTS else ''
                print(f"    {name:<18} 0x{off:08X} {format_size(sz):>10}{crit}")
    except: pass
    
    print(f"\n    Formats: 0xADDR, PARTITION, PARTITION+0xOFFSET, START-END")


# =============================================================================
# DATA PREPARATION
# =============================================================================
def prepare_data(spec: str, ptype: str = 'auto', target_size: int = 0) -> Tuple[Optional[bytes], str]:
    """Prepare patch data from various formats"""
    spec = str(spec).strip()
    
    # File
    if ptype == 'file' or (ptype == 'auto' and os.path.isfile(spec)):
        try:
            sz = os.path.getsize(spec)
            if sz > MAX_PATCH:
                print(f"[!] File too large: {sz} > {MAX_PATCH}")
                return None, 'error'
            with open(spec, 'rb') as f:
                return f.read(), 'file'
        except Exception as e:
            print(f"[!] File error: {e}")
            return None, 'error'
    
    # Zero fill
    if spec.lower().startswith('zero'):
        size_str = spec[4:].strip().lstrip(':').strip() or str(target_size)
        try:
            sz = parse_size(size_str)
            if sz <= 0 or sz > MAX_PATCH:
                print(f"[!] Invalid zero size: {sz}")
                return None, 'error'
            return b'\x00' * sz, 'zero'
        except:
            print(f"[!] Cannot parse zero size: {size_str}")
            return None, 'error'
    
    # Pattern: "FF:4096"
    if ':' in spec and not spec.lower().startswith(('replace:', 'instruction:')):
        parts = spec.split(':', 1)
        if len(parts) == 2:
            try:
                val_str = parts[0].strip()
                cnt_str = parts[1].strip()
                value = int(val_str, 16) & 0xFF if len(val_str) <= 2 else int(val_str, 0) & 0xFF
                count = parse_size(cnt_str)
                if count <= 0 or count > MAX_PATCH:
                    print(f"[!] Invalid count: {count}")
                    return None, 'error'
                return bytes([value] * count), 'pattern'
            except: pass
    
    # Hex string
    clean = ''.join(spec.split())
    if clean and all(c in '0123456789ABCDEFabcdef' for c in clean):
        try:
            if len(clean) % 2: clean = '0' + clean
            return bytes.fromhex(clean), 'hex'
        except ValueError as e:
            print(f"[!] Invalid hex: {e}")
            return None, 'error'
    
    # String fallback
    return spec.encode('utf-8'), 'string'


# =============================================================================
# PATCH EXECUTION
# =============================================================================
def execute_patch(dev, addr: int, data: bytes, verify: bool, chunk_size: int,
                  backup_file: str = None, dry_run: bool = False) -> bool:
    """Execute patch with chunking, backup, and verification"""
    
    total = len(data)
    
    if dry_run:
        print(f"\n[*] DRY RUN - No changes made")
        print(f"    Would patch 0x{addr:08X} with {format_size(total)}")
        return True
    
    # Backup
    if backup_file:
        if not create_backup(dev, addr, total, backup_file):
            if not confirm("Backup failed. Continue?", 'YES', False):
                return False
    
    # Single chunk
    if total <= chunk_size:
        return patch_single(dev, addr, data, verify)
    
    # Chunked
    chunks = (total + chunk_size - 1) // chunk_size
    print(f"\n[*] Patching {format_size(total)} in {chunks} chunks of {format_size(chunk_size)}")
    
    for i in range(chunks):
        start = i * chunk_size
        end = min(start + chunk_size, total)
        chunk = data[start:end]
        caddr = addr + start
        
        print(f"    Chunk {i+1}/{chunks}: 0x{caddr:08X} ({format_size(len(chunk))})")
        
        if not patch_single(dev, caddr, chunk, verify):
            print(f"[!] Chunk {i+1} failed")
            return False
        
        pct = (i + 1) * 100 // chunks
        print(f"    Progress: {pct}%")
    
    return True


def patch_single(dev, addr: int, data: bytes, verify: bool) -> bool:
    """Patch a single chunk with retries"""
    payload = struct.pack("<II", addr, len(data)) + data
    
    for attempt in range(MAX_RETRIES + 1):
        if attempt > 0:
            time.sleep(0.5 * attempt)
        
        ok, name, _ = patch_cmd(dev, payload)
        
        if ok:
            if verify and not verify_patch(dev, addr, data):
                if attempt < MAX_RETRIES:
                    print(f"    Retry {attempt+1}/{MAX_RETRIES}...")
                    continue
                return False
            return True
        
        if attempt < MAX_RETRIES:
            print(f"    Retry {attempt+1}/{MAX_RETRIES}...")
        else:
            print(f"[!] Patch failed: {name}")
    
    return False


def verify_patch(dev, addr: int, expected: bytes) -> bool:
    """Verify patch by reading back"""
    ok, data = read_cmd(dev, addr, len(expected))
    
    if not ok or not data or len(data) != len(expected):
        print(f"    ✗ Verify failed")
        return False
    
    if data == expected:
        print(f"    ✓ Verified")
        return True
    
    # Find mismatch
    for i in range(len(expected)):
        if i < len(data) and data[i] != expected[i]:
            print(f"    ✗ Mismatch at +0x{i:X}: exp=0x{expected[i]:02X} got=0x{data[i]:02X}")
            # Show context
            start = max(0, i-8)
            end = min(len(expected), i+8)
            print(f"      Exp: {expected[start:end].hex()}")
            print(f"      Got: {data[start:end].hex()}")
            return False
    
    return False


def create_backup(dev, addr: int, size: int, path: str) -> bool:
    """Create backup before patching"""
    print(f"\n[*] Creating backup: {path}")
    
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
    except: pass
    
    ok, data = read_cmd(dev, addr, min(size, MAX_PATCH))
    
    if not ok or not data:
        print("[!] Backup read failed")
        return False
    
    try:
        with open(path, 'wb') as f:
            f.write(data)
        
        meta = {
            'address': addr, 'size': size, 'actual': len(data),
            'timestamp': time.time(), 'sha256': hashlib.sha256(data).hexdigest()
        }
        with open(path + '.meta', 'w') as f:
            json.dump(meta, f, indent=2)
        
        print(f"[+] Backup saved: {path} ({format_size(len(data))})")
        return True
    except Exception as e:
        print(f"[!] Backup save failed: {e}")
        return False


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_patch(args=None) -> int:
    """
    QSLCL PATCH - Binary patching with safety checks
    
    Examples:
        patch boot file update.bin              - Patch boot partition from file
        patch boot+0x1000 hex DEADBEEF          - Write hex at offset
        patch system pattern 00:4096            - Fill with zeros
        patch 0x880000 file patch.bin           - Patch raw address
        patch 0x880000 zero 1024                - Zero 1KB at address
        patch list                              - List available targets
        patch boot file update.bin --backup bk  - Patch with backup
        patch boot file update.bin --dry-run    - Test without writing
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: patch <target> <data> [options]")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Parse arguments
    pargs = getattr(args, 'patch_args', []) or getattr(args, 'args', []) or []
    
    # Handle "patch list"
    if not pargs or (len(pargs) == 1 and pargs[0].lower() == 'list'):
        list_targets(dev)
        return 0
    
    if len(pargs) < 2:
        print("[!] Need target and data source")
        print("[*] Usage: patch <target> <data> [options]")
        return 1
    
    target = str(pargs[0])
    data_spec = str(pargs[1])
    
    # Handle multi-arg data formats
    if len(pargs) > 2:
        extra = pargs[2:]
        if data_spec.lower() in ('replace', 'string') and len(extra) >= 2:
            data_spec = f"replace:{extra[0]}:{extra[1]}"
        elif data_spec.lower() in ('instruction', 'asm'):
            data_spec = f"instruction:{' '.join(extra)}"
    
    # Options
    ptype = getattr(args, 'patch_type', 'auto') or 'auto'
    verify = not getattr(args, 'no_verify', False)
    force = getattr(args, 'force', False)
    chunk_size = max(512, min(getattr(args, 'chunk_size', DEFAULT_CHUNK) or DEFAULT_CHUNK, 16*1024*1024))
    retries = max(1, min(getattr(args, 'retries', MAX_RETRIES) or MAX_RETRIES, 10))
    backup = getattr(args, 'backup', None)
    dry_run = getattr(args, 'dry_run', False)
    
    # Resolve target
    resolved = resolve_target(target, dev)
    if resolved is None:
        print(f"[!] Cannot resolve: {target}")
        print("[*] Use 'patch list' to see available targets")
        return 1
    
    addr, tsize, pinfo = resolved
    
    print(f"\n[+] Target:")
    print(f"    Address: 0x{addr:08X}")
    if pinfo:
        print(f"    Partition: {pinfo['name']} (0x{pinfo['offset']:08X}, {format_size(pinfo['size'])})")
    if tsize > 0:
        print(f"    Size: {format_size(tsize)}")
    
    # Prepare data
    data, dtype = prepare_data(data_spec, ptype, tsize)
    if data is None:
        return 1
    
    dsize = len(data)
    print(f"    Data: {format_size(dsize)} [{dtype}]")
    
    # Size check
    if tsize > 0 and dsize > tsize:
        if not force:
            print(f"[!] Data ({format_size(dsize)}) exceeds target ({format_size(tsize)})")
            print("[*] Use --force to truncate")
            return 1
        print(f"[!] Truncating to {format_size(tsize)}")
        data = data[:tsize]
        dsize = tsize
    
    if dsize > MAX_PATCH:
        print(f"[!] Too large: {format_size(dsize)} > {format_size(MAX_PATCH)}")
        return 1
    
    # Safety for critical partitions
    if pinfo and pinfo.get('name', '').lower() in CRITICAL_PARTS:
        if not confirm(
            f"⚠️  CRITICAL PARTITION: {pinfo['name']}\nPatching this may BRICK the device!",
            'PATCH', force
        ):
            return 0
    
    # Safety for raw addresses
    if not pinfo and tsize == 0 and not force:
        if not confirm(f"Patch raw address 0x{addr:08X} with no size limit?", 'YES', force):
            return 0
    
    # Safety for large patches
    if dsize > 1024*1024 and not force:
        if not confirm(f"Apply {format_size(dsize)} patch?", 'YES', force):
            return 0
    
    # Execute
    print(f"\n[*] Applying patch: {dtype} | {format_size(dsize)} | Verify: {'ON' if verify else 'OFF'}")
    
    success = execute_patch(dev, addr, data, verify, chunk_size, backup, dry_run)
    
    if success:
        print(f"\n[✓] Patch complete!")
        return 0
    else:
        print(f"\n[✗] Patch failed")
        if backup:
            print(f"[*] Backup available: {backup}")
        return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] patch.py - QSLCL PATCH Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py patch <target> <data> [options]")