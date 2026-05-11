#!/usr/bin/env python3
"""
patch.py - QSLCL PATCH Command Module v2.0 (FIXED)
Fixed: Import handling, target resolution, data preparation,
       chunked patching, backup, verification, error recovery
"""

import os
import sys
import re
import struct
import time
import json
import hashlib
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union

# =============================================================================
# FIXED: Proper relative imports with comprehensive fallbacks
# =============================================================================
_use_qslcl = False
_scan_all = None
_load_partitions = None
_detect_memory_regions = None
_resolve_target = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_QSLCLCMD_DB = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        load_partitions as _qslcl_load_partitions,
        detect_memory_regions as _qslcl_detect_memory_regions,
        resolve_target as _qslcl_resolve_target,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _load_partitions = _qslcl_load_partitions
    _detect_memory_regions = _qslcl_detect_memory_regions
    _resolve_target = _qslcl_resolve_target
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
            load_partitions as _qslcl_load_partitions,
            detect_memory_regions as _qslcl_detect_memory_regions,
            resolve_target as _qslcl_resolve_target,
            auto_loader_if_needed as _qslcl_auto_loader,
            qslcl_dispatch as _qslcl_dispatch_fn,
            decode_runtime_result as _qslcl_decode_runtime,
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _load_partitions = _qslcl_load_partitions
        _detect_memory_regions = _qslcl_detect_memory_regions
        _resolve_target = _qslcl_resolve_target
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
PATCH_TIMEOUT = 30.0
MAX_PATCH_SIZE = 100 * 1024 * 1024  # 100MB
DEFAULT_CHUNK_SIZE = 65536  # 64KB
MAX_RETRIES = 3
CRITICAL_PARTITIONS = {'boot','bootloader','aboot','sbl','xbl','recovery','tz','rpm','hyp','preloader'}

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Parse helpers
# =============================================================================
def _parse_address(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    if s.startswith('0b'): return int(s[2:], 2)
    try: return int(s, 16)
    except: return int(s, 10)

def _parse_size(s: str) -> int:
    s = str(s).strip().upper()
    if not s: return 0
    if s.startswith('0X'): return int(s, 16)
    for sfx, mul in [('GB',1024**3),('G',1024**3),('MB',1024**2),('M',1024**2),
                      ('KB',1024),('K',1024),('B',1)]:
        if s.endswith(sfx): return int(float(s[:-len(sfx)]) * mul)
    try: return int(s)
    except: return int(float(s))


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
    for attempt in range(2):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or PATCH_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or PATCH_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.2)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.RED}{msg}{C.RESET}")
    try: return input(f"    Type '{req}': ").upper() == req.upper()
    except: return False


# =============================================================================
# FIXED: Target resolution
# =============================================================================
def _resolve_patch_target(target: str, dev) -> Optional[Tuple[int, int, Optional[Dict]]]:
    """
    Resolve patch target to (address, size, partition_info).
    Returns None if unresolvable.
    """
    target_str = str(target).strip()
    target_lower = target_str.lower()
    
    # 1. Raw hex address
    if target_lower.startswith('0x'):
        try: return (_parse_address(target_str), 0, None)
        except: pass
    
    # 2. Range format: start-end
    if '-' in target_str and target_str.count('-') == 1:
        try:
            parts = target_str.split('-')
            start = _parse_address(parts[0])
            end = _parse_address(parts[1])
            if start < end: return (start, end - start, None)
        except: pass
    
    # 3. Partition+offset: "boot+0x1000"
    if '+' in target_str:
        try:
            pname, off_str = target_str.split('+', 1)
            offset = _parse_address(off_str.strip())
            parts = _load_partitions(dev) if _load_partitions else []
            for p in parts:
                if p.get('name','').lower() == pname.strip().lower():
                    addr = p['offset'] + offset
                    remaining = p['size'] - offset
                    if remaining <= 0:
                        print(f"{C.RED}[!] Offset exceeds partition size{C.RESET}")
                        return None
                    return (addr, remaining, p)
        except: pass
    
    # 4. Partition name only
    if _load_partitions:
        parts = _load_partitions(dev)
        for p in parts:
            if p.get('name','').lower() == target_lower:
                return (p['offset'], p['size'], p)
    
    # 5. Try QSLCL resolve_target
    if _use_qslcl and _resolve_target:
        try:
            parts = _load_partitions(dev) if _load_partitions else []
            regions = _detect_memory_regions(dev) if _detect_memory_regions else []
            res = _resolve_target(target_str, parts, regions, dev)
            if res:
                pinfo = res.get('partition_info')
                return (res['address'], res.get('size', 0), pinfo)
        except: pass
    
    # 6. Plain decimal address
    try: return (int(target_str), 0, None)
    except: pass
    
    return None


def _list_patch_targets(dev):
    """List available patch targets."""
    print(f"\n{C.BOLD}[+] Available Patch Targets:{C.RESET}")
    
    parts = []
    if _load_partitions:
        try: parts = _load_partitions(dev)
        except: pass
    
    if parts:
        print(f"\n{C.CYAN}Partitions:{C.RESET}")
        print(f"  {'Name':<18} {'Start':<12} {'End':<12} {'Size':<12}")
        print(f"  {'-'*18} {'-'*12} {'-'*12} {'-'*12}")
        for p in sorted(parts, key=lambda x: x.get('offset',0)):
            name = p.get('name','?')
            off = p.get('offset',0)
            size = p.get('size',0)
            end = off + size - 1 if size > 0 else off
            size_str = f"{size/1024:.0f}KB" if size<1024*1024 else f"{size/(1024*1024):.1f}MB"
            critical = f" {C.RED}⚠{C.RESET}" if name.lower() in CRITICAL_PARTITIONS else ""
            print(f"  {name:<18} 0x{off:08X}  0x{end:08X}  {size_str:>10}{critical}")
    
    regions = []
    if _detect_memory_regions:
        try: regions = _detect_memory_regions(dev)
        except: pass
    
    if regions:
        print(f"\n{C.CYAN}Memory Regions:{C.RESET}")
        for r in regions[:10]:
            name = r.get('name','?')
            start = r.get('start',0)
            end = r.get('end',0)
            size = end - start
            perms = r.get('permissions','---')
            print(f"  {name:<18} 0x{start:08X}-0x{end:08X} ({size/1024:.0f}KB) [{perms}]")
    
    print(f"\n{C.CYAN}Examples:{C.RESET}")
    print(f"  qslcl patch boot file update.bin")
    print(f"  qslcl patch boot+0x1000 hex DEADBEEF")
    print(f"  qslcl patch 0x880000 file patch.bin")
    print(f"  qslcl patch system pattern 00:4096")


# =============================================================================
# FIXED: Data preparation
# =============================================================================
def _prepare_patch_data(spec: str, patch_type: str = 'auto',
                        target_size: int = 0) -> Tuple[Optional[bytes], str]:
    """
    Prepare patch data from various formats.
    Returns (data_bytes, detected_type) or (None, 'error').
    """
    if not spec: return None, 'error'
    
    spec_str = str(spec).strip()
    
    # 1. File input
    if patch_type == 'file' or (patch_type == 'auto' and os.path.isfile(spec_str)):
        try:
            fsize = os.path.getsize(spec_str)
            if fsize > MAX_PATCH_SIZE:
                print(f"{C.RED}[!] File too large: {fsize} > {MAX_PATCH_SIZE}{C.RESET}")
                return None, 'error'
            with open(spec_str, 'rb') as f:
                return f.read(), 'file'
        except Exception as e:
            print(f"{C.RED}[!] File error: {e}{C.RESET}")
            return None, 'error'
    
    # 2. Zero fill: "zero:1024" or "zero 1024"
    if patch_type == 'zero' or spec_str.lower().startswith('zero'):
        size_str = spec_str[4:].strip().lstrip(':').strip() if spec_str.lower().startswith('zero') else spec_str
        if not size_str and target_size > 0: size_str = str(target_size)
        try:
            size = _parse_size(size_str)
            if size <= 0 or size > MAX_PATCH_SIZE:
                print(f"{C.RED}[!] Invalid zero size: {size}{C.RESET}")
                return None, 'error'
            return b'\x00' * size, 'zero'
        except:
            print(f"{C.RED}[!] Cannot parse zero size: {size_str}{C.RESET}")
            return None, 'error'
    
    # 3. FF fill: "ff:1024"
    if patch_type in ('auto','pattern') and ':' in spec_str and not spec_str.lower().startswith(('replace:','instruction:')):
        parts = spec_str.split(':', 1)
        if len(parts) == 2:
            try:
                val_str = parts[0].strip()
                cnt_str = parts[1].strip()
                
                if len(val_str) <= 2 and all(c in '0123456789ABCDEFabcdef' for c in val_str):
                    value = int(val_str, 16) & 0xFF if val_str else 0
                else:
                    value = int(val_str, 0) & 0xFF
                
                count = _parse_size(cnt_str)
                if count <= 0 or count > MAX_PATCH_SIZE:
                    print(f"{C.RED}[!] Invalid count: {count}{C.RESET}")
                    return None, 'error'
                
                return bytes([value] * count), 'pattern'
            except:
                if patch_type == 'pattern':
                    print(f"{C.RED}[!] Invalid pattern: {spec_str}{C.RESET}")
                    return None, 'error'
    
    # 4. Replace format: replace:old:new
    if spec_str.lower().startswith('replace:'):
        try:
            parts = spec_str.split(':', 2)
            if len(parts) >= 3:
                return parts[2].encode('utf-8'), 'replace'
            # replace:string means replace all
            return b'', 'replace'
        except:
            print(f"{C.RED}[!] Invalid replace format{C.RESET}")
            return None, 'error'
    
    # 5. Instruction (placeholder)
    if spec_str.lower().startswith('instruction:') or patch_type in ('instruction','asm'):
        print(f"{C.YELLOW}[!] Instruction patching not implemented{C.RESET}")
        print(f"[*] Supported: nop, ret, bkpt (ARM/x86)")
        return None, 'error'
    
    # 6. Hex string
    clean = ''.join(spec_str.split()).replace('\n','').replace('\r','')
    hex_chars = set('0123456789ABCDEFabcdef')
    if clean and all(c in hex_chars for c in clean):
        try:
            if len(clean) % 2: clean = '0' + clean
            return bytes.fromhex(clean), 'hex'
        except ValueError as e:
            print(f"{C.RED}[!] Invalid hex: {e}{C.RESET}")
            return None, 'error'
    
    # 7. String fallback
    try:
        return spec_str.encode('utf-8'), 'string'
    except:
        return None, 'error'


# =============================================================================
# FIXED: Patch execution
# =============================================================================
def _execute_patch(dev, address: int, data: bytes, verify: bool,
                   chunk_size: int, max_retries: int, backup_file: str = None,
                   dry_run: bool = False) -> bool:
    """Execute patch with chunking, backup, and verification."""
    
    total_size = len(data)
    
    if dry_run:
        print(f"\n{C.YELLOW}[*] DRY RUN - No changes made{C.RESET}")
        print(f"    Would patch 0x{address:08X} with {total_size} bytes")
        return True
    
    # Backup
    if backup_file:
        if not _create_backup(dev, address, total_size, backup_file):
            if not _confirm("Backup failed. Continue anyway?", 'YES', False):
                return False
    
    # Single chunk
    if total_size <= chunk_size:
        return _patch_single(dev, address, data, verify, max_retries)
    
    # Chunked
    chunks = (total_size + chunk_size - 1) // chunk_size
    print(f"\n{C.CYAN}[*] Chunked: {total_size}B in {chunks} chunks of {chunk_size}B{C.RESET}")
    
    for i in range(chunks):
        start = i * chunk_size
        end = min(start + chunk_size, total_size)
        chunk = data[start:end]
        caddr = address + start
        
        print(f"\n  Chunk {i+1}/{chunks}: 0x{caddr:08X} ({len(chunk)}B)")
        
        if not _patch_single(dev, caddr, chunk, verify, max_retries):
            print(f"{C.RED}[!] Chunk {i+1} failed{C.RESET}")
            return False
        
        pct = (i + 1) * 100 // chunks
        print(f"  {C.GREEN}Progress: {pct}%{C.RESET}")
    
    return True


def _patch_single(dev, address: int, data: bytes, verify: bool, max_retries: int) -> bool:
    """Patch a single chunk with retries."""
    payload = struct.pack("<II", address, len(data)) + data
    
    for attempt in range(max_retries + 1):
        if attempt > 0:
            print(f"  Retry {attempt}/{max_retries}...")
            time.sleep(0.5 * attempt)
        
        ok, name, extra = _dispatch(dev, "PATCH", payload)
        
        if ok:
            if verify and not _verify_patch(dev, address, data):
                if attempt < max_retries: continue
                return False
            return True
        
        print(f"  {C.RED}PATCH failed: {name}{C.RESET}")
        if attempt >= max_retries: return False
    
    return False


# =============================================================================
# FIXED: Backup
# =============================================================================
def _create_backup(dev, address: int, size: int, backup_file: str) -> bool:
    """Create backup of memory region."""
    print(f"\n{C.CYAN}[*] Backup: {backup_file} ({size}B){C.RESET}")
    
    try:
        d = os.path.dirname(os.path.abspath(backup_file))
        if d: os.makedirs(d, exist_ok=True)
    except Exception as e:
        print(f"{C.RED}[!] Cannot create directory: {e}{C.RESET}")
        return False
    
    payload = struct.pack("<II", address, min(size, MAX_PATCH_SIZE))
    ok, name, data = _dispatch(dev, "READ", payload, timeout=30)
    
    if not ok:
        print(f"{C.RED}[!] Backup read failed: {name}{C.RESET}")
        return False
    
    try:
        with open(backup_file, 'wb') as f:
            f.write(data if data else b'')
        
        meta = {
            'address': address, 'size': size, 'actual_size': len(data) if data else 0,
            'timestamp': time.time(), 'sha256': hashlib.sha256(data).hexdigest() if data else '',
        }
        with open(backup_file + '.meta', 'w') as f:
            json.dump(meta, f, indent=2)
        
        print(f"{C.GREEN}[+] Backup saved: {backup_file} ({len(data) if data else 0}B){C.RESET}")
        return True
    except Exception as e:
        print(f"{C.RED}[!] Backup save failed: {e}{C.RESET}")
        return False


# =============================================================================
# FIXED: Verification
# =============================================================================
def _verify_patch(dev, address: int, expected: bytes) -> bool:
    """Verify patch by reading back."""
    payload = struct.pack("<II", address, len(expected))
    ok, name, data = _dispatch(dev, "READ", payload, timeout=10)
    
    if not ok:
        print(f"  {C.RED}Verify read failed: {name}{C.RESET}")
        return False
    
    if not data or len(data) != len(expected):
        print(f"  {C.RED}Size mismatch: {len(data) if data else 0} vs {len(expected)}{C.RESET}")
        return False
    
    if data == expected:
        print(f"  {C.GREEN}✓ Verified{C.RESET}")
        return True
    
    # Find first mismatch
    for i in range(len(expected)):
        if data[i] != expected[i]:
            print(f"  {C.RED}✗ Mismatch at +0x{i:X}: exp=0x{expected[i]:02X} got=0x{data[i]:02X}{C.RESET}")
            _show_diff(expected, data, address, i)
            return False
    
    return False


def _show_diff(expected: bytes, actual: bytes, base: int, mismatch: int):
    """Show hex diff around mismatch."""
    start = max(0, mismatch - 16)
    end = min(len(expected), mismatch + 16)
    
    print(f"\n  Expected (0x{base+start:08X}):")
    _hex_dump_line(expected[start:end], base + start)
    print(f"  Got:")
    _hex_dump_line(actual[start:end], base + start)
    
    # Show difference markers
    marker = [' '] * (end - start)
    for i in range(start, end):
        if i < len(expected) and i < len(actual) and expected[i] != actual[i]:
            marker[i - start] = '^'
    print(f"  Diff:     {'  '.join(marker)}")

def _hex_dump_line(data: bytes, addr: int):
    """Print single hex dump line."""
    hx = ' '.join(f'{b:02x}' for b in data)
    asc = ''.join(chr(b) if 32<=b<127 else '.' for b in data)
    print(f"    0x{addr:08x}: {hx:<48} |{asc}|")


# =============================================================================
# FIXED: Help
# =============================================================================
def print_help():
    print(f"""
{C.BOLD}PATCH - Advanced Binary Patching{C.RESET}
{'='*50}

{C.CYAN}USAGE:{C.RESET}
  qslcl patch <target> <data> [options]

{C.CYAN}TARGETS:{C.RESET}
  0xADDRESS            Raw memory address
  PARTITION            Partition name (boot, system, etc.)
  PARTITION+0xOFFSET   Partition with offset
  START-END            Address range
  list                 List available targets

{C.CYAN}DATA SOURCES:{C.RESET}
  file <path>          Binary file
  hex <string>         Hex string (AABBCCDD)
  pattern <val:count>  Fill pattern (00:4096, FF:1024)
  zero <size>          Zero fill
  replace <old:new>    String replacement
  instruction <asm>    Assembly (nop, ret, bkpt)

{C.CYAN}OPTIONS:{C.RESET}
  --patch-type <type>  Force patch type
  --no-verify          Skip read-back verification
  --chunk-size <size>  Chunk size (default: 64KB)
  --retries <count>    Max retries (default: 3)
  --force              Skip safety checks
  --backup <file>      Create backup before patching
  --dry-run            Test without writing

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl patch boot file update.bin
  qslcl patch boot+0x1000 hex DEADBEEF
  qslcl patch system pattern 00:4096
  qslcl patch 0x880000 file patch.bin --backup backup.bin
  qslcl patch list
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_patch(args=None) -> int:
    """QSLCL PATCH Command v2.0"""
    
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_help(); return 1
    
    if not _use_qslcl: _warn_standalone()
    
    # Device
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return 1
        if not devs: print(f"{C.RED}[!] No device{C.RESET}"); return 1
        dev = devs[0]
        print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        print(f"{C.RED}[!] No QSLCL support{C.RESET}"); return 1
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    # Parse arguments
    pargs = getattr(args, 'patch_args', []) or []
    
    # Handle "patch list"
    if not pargs or (len(pargs) == 1 and pargs[0].lower() == 'list'):
        _list_patch_targets(dev)
        return 0
    
    if len(pargs) < 2:
        print(f"{C.RED}[!] Need target and data source{C.RESET}")
        print_help()
        return 1
    
    target = pargs[0]
    data_spec = pargs[1]
    
    # Handle multi-arg data formats
    if len(pargs) > 2:
        extra = pargs[2:]
        if data_spec.lower() in ('replace','string') and len(extra) >= 2:
            data_spec = f"replace:{extra[0]}:{extra[1]}"
        elif data_spec.lower() in ('instruction','asm'):
            data_spec = f"instruction:{' '.join(extra)}"
    
    ptype = getattr(args, 'patch_type', 'auto') or 'auto'
    verify = not getattr(args, 'no_verify', False)
    force = getattr(args, 'force', False) or getattr(args, 'force_reset', False)
    chunk_size = int(getattr(args, 'chunk_size', DEFAULT_CHUNK_SIZE) or DEFAULT_CHUNK_SIZE)
    max_retries = int(getattr(args, 'retries', MAX_RETRIES) or MAX_RETRIES)
    backup = getattr(args, 'backup', None)
    dry_run = getattr(args, 'dry_run', False)
    
    # Clamp values
    chunk_size = max(512, min(chunk_size, 16*1024*1024))
    max_retries = max(1, min(max_retries, 10))
    
    # Resolve target
    resolved = _resolve_patch_target(target, dev)
    if resolved is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}")
        print(f"[*] Use 'patch list' to see available targets")
        return 1
    
    addr, tsize, pinfo = resolved
    
    print(f"\n{C.BOLD}[+] Target:{C.RESET}")
    print(f"    Address: 0x{addr:08X}")
    if pinfo:
        print(f"    Partition: {pinfo['name']} (0x{pinfo['offset']:08X}, {pinfo['size']}B)")
    if tsize > 0:
        print(f"    Size: {tsize}B ({tsize/1024:.1f}KB)")
    
    # Prepare data
    data, dtype = _prepare_patch_data(data_spec, ptype, tsize)
    if data is None:
        return 1
    
    dsize = len(data)
    print(f"    Data: {dsize}B ({dsize/1024:.1f}KB) [{dtype}]")
    
    # Check size
    if tsize > 0 and dsize > tsize:
        if not force:
            print(f"{C.RED}[!] Data ({dsize}B) exceeds target ({tsize}B){C.RESET}")
            print(f"[*] Use --force to truncate")
            return 1
        print(f"{C.YELLOW}[!] Truncating to {tsize}B{C.RESET}")
        data = data[:tsize]
        dsize = tsize
    
    if dsize > MAX_PATCH_SIZE:
        print(f"{C.RED}[!] Too large: {dsize}B > {MAX_PATCH_SIZE}B{C.RESET}")
        return 1
    
    # Safety for critical partitions
    if pinfo and pinfo.get('name','').lower() in CRITICAL_PARTITIONS:
        if not _confirm(
            f"⚠️  CRITICAL PARTITION: {pinfo['name']}\n"
            f"Patching this may BRICK the device!", 'PATCH', force
        ):
            return 0
    
    # Safety for large patches
    if dsize > 1024*1024 and not force:
        if not _confirm(f"Apply {dsize/1024:.0f}KB patch?", 'YES', force):
            return 0
    
    # Safety for raw addresses
    if not pinfo and tsize == 0 and not force:
        if not _confirm(f"Patch raw address 0x{addr:08X} with no size limit?", 'YES', force):
            return 0
    
    # Execute
    print(f"\n{C.CYAN}[*] Applying patch...{C.RESET}")
    print(f"    Type: {dtype} | Size: {dsize}B | Verify: {'ON' if verify else 'OFF'}")
    
    success = _execute_patch(dev, addr, data, verify, chunk_size, max_retries, backup, dry_run)
    
    if success:
        print(f"\n{C.GREEN}[✓] Patch complete!{C.RESET}")
        return 0
    else:
        print(f"\n{C.RED}[✗] Patch failed{C.RESET}")
        if backup:
            print(f"[*] Backup available: {backup}")
        return 1


def add_patch_arguments(parser):
    parser.add_argument('patch_args', nargs='*', help='Target and data source')
    parser.add_argument('--patch-type', choices=['auto','file','hex','pattern','zero','replace','instruction'])
    parser.add_argument('--no-verify', action='store_true')
    parser.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument('--retries', type=int, default=MAX_RETRIES)
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--backup', help='Backup file path')
    parser.add_argument('--dry-run', action='store_true')
    return parser


if __name__ == "__main__":
    print("[*] patch.py - QSLCL PATCH Module v2.0")
    print_help()