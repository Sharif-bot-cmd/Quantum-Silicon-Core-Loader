#!/usr/bin/env python3
"""
dump.py - QSLCL DUMP Command Module v2.0 (FIXED)
Fixed: Import handling, chunked reading, progress tracking,
       resume support, verification, compression, metadata
"""

import os
import sys
import re
import struct
import time
import json
import gzip
import shutil
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
_ProgressBar = None
_QSLCLCMD_DB = None
_parse_address_fn = None
_parse_size_fn = None
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
        ProgressBar as _qslcl_ProgressBar,
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
    _ProgressBar = _qslcl_ProgressBar
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
            ProgressBar as _qslcl_ProgressBar,
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
        _ProgressBar = _qslcl_ProgressBar
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
DUMP_TIMEOUT = 20.0
MAX_DUMP_SIZE = 4 * 1024 * 1024 * 1024  # 4GB
DEFAULT_CHUNK_SIZE = 65536  # 64KB
MAX_RETRIES = 3
MAX_ERRORS_BEFORE_ABORT = 50

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Local ProgressBar fallback
# =============================================================================
class LocalProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50):
        self.total = max(total, 1); self.prefix = prefix
        self.suffix = suffix; self.length = length; self.current = 0
        self._started = False
    def __enter__(self): return self
    def __exit__(self, *a):
        if self._started: print()
    def update(self, n):
        self._started = True
        self.current += n
        pct = min(100, 100 * self.current / self.total)
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '-' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {pct:.0f}% {self.suffix}', end='', flush=True)


# =============================================================================
# FIXED: Parse helpers
# =============================================================================
def _parse_address(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
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
# FIXED: Format helpers
# =============================================================================
def _format_size(s: int) -> str:
    if s < 1024: return f"{s}B"
    elif s < 1024*1024: return f"{s/1024:.1f}KB"
    elif s < 1024*1024*1024: return f"{s/(1024*1024):.2f}MB"
    else: return f"{s/(1024*1024*1024):.2f}GB"

def _format_time(seconds: float) -> str:
    if seconds < 1: return f"{seconds*1000:.0f}ms"
    elif seconds < 60: return f"{seconds:.1f}s"
    elif seconds < 3600: return f"{seconds//60}m {seconds%60:.0f}s"
    else: return f"{seconds//3600}h {(seconds%3600)//60}m"

def _format_speed(bps: float) -> str:
    if bps < 1024: return f"{bps:.0f}B/s"
    elif bps < 1024*1024: return f"{bps/1024:.1f}KB/s"
    elif bps < 1024*1024*1024: return f"{bps/(1024*1024):.1f}MB/s"
    else: return f"{bps/(1024*1024*1024):.2f}GB/s"


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
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or DUMP_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or DUMP_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Read memory chunk
# =============================================================================
def _read_chunk(dev, address: int, size: int, max_retries: int = MAX_RETRIES) -> Tuple[Optional[bytes], bool]:
    """Read a memory chunk with retries and backoff."""
    payload = struct.pack("<II", address, size)
    
    for attempt in range(max_retries + 1):
        try:
            ok, name, data = _dispatch(dev, "READ", payload, timeout=10)
            if ok and data:
                if len(data) >= size: return data[:size], True
                # Partial read - pad
                padded = data.ljust(size, b'\x00')
                return padded, True
            if attempt < max_retries:
                time.sleep(0.1 * (2 ** attempt))
        except KeyboardInterrupt:
            raise
        except Exception:
            if attempt >= max_retries: break
            time.sleep(0.2)
    
    return None, False


# =============================================================================
# FIXED: Disk check
# =============================================================================
def _check_disk_space(path: str, required: int) -> bool:
    """Check if enough disk space is available."""
    try:
        d = os.path.dirname(os.path.abspath(path)) or '.'
        stat = shutil.disk_usage(d)
        needed = int(required * 1.1)  # 10% overhead
        if stat.free < needed:
            print(f"{C.RED}[!] Insufficient space: need {_format_size(needed)}, have {_format_size(stat.free)}{C.RESET}")
            return False
        return True
    except Exception as e:
        print(f"{C.YELLOW}[!] Cannot check disk space: {e}{C.RESET}")
        return True


# =============================================================================
# FIXED: Generate filename
# =============================================================================
def _gen_filename(address: int, size: int, region: str) -> str:
    """Generate automatic output filename."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = re.sub(r'[^a-z0-9_-]', '_', region.lower())[:30]
    sz = _format_size(size).replace('.','_').lower()
    return f"dump_{name}_0x{address:08X}_{sz}_{ts}.bin"


# =============================================================================
# FIXED: Verification
# =============================================================================
def _verify_dump(dev, base_addr: int, file_path: str, total_size: int, 
                 chunk_size: int, verbose: bool) -> bool:
    """Verify dump by reading back and comparing."""
    print(f"\n{C.CYAN}[*] Verifying...{C.RESET}")
    
    verified = 0
    errors = 0
    mismatch_bytes = 0
    
    try:
        with open(file_path, 'rb') as f:
            with LocalProgressBar(total_size, prefix='Verify', suffix='Complete') as pb:
                while verified < total_size:
                    addr = base_addr + verified
                    remaining = total_size - verified
                    cs = min(chunk_size, remaining)
                    
                    file_data = f.read(cs)
                    if not file_data: break
                    
                    # Skip all-zero chunks (known failed reads)
                    if file_data == b'\x00' * len(file_data):
                        verified += len(file_data)
                        pb.update(len(file_data))
                        continue
                    
                    dev_data, ok = _read_chunk(dev, addr, len(file_data), 1)
                    if ok and dev_data:
                        if dev_data == file_data:
                            verified += len(file_data)
                        else:
                            errors += 1
                            mm = sum(1 for i in range(min(len(file_data),len(dev_data))) 
                                   if file_data[i] != dev_data[i])
                            mismatch_bytes += mm
                            if verbose:
                                print(f"\n{C.YELLOW}[!] Mismatch at 0x{addr:08X}: {mm} bytes{C.RESET}")
                    else:
                        errors += 1
                    
                    verified += len(file_data)
                    pb.update(len(file_data))
        
        rate = verified / total_size * 100 if total_size > 0 else 0
        print(f"\n    Verified: {_format_size(verified)}/{_format_size(total_size)} ({rate:.1f}%)")
        if errors:
            print(f"    {C.YELLOW}Errors: {errors}, Mismatched bytes: {mismatch_bytes}{C.RESET}")
        return errors == 0 and verified >= total_size * 0.95
    
    except Exception as e:
        print(f"{C.RED}[!] Verify error: {e}{C.RESET}")
        return False


# =============================================================================
# FIXED: Metadata
# =============================================================================
def _save_metadata(meta_path: str, addr: int, expected: int, actual: int,
                   file_hash: str, region: str, failed: List[Tuple[int,int]]):
    """Save dump metadata JSON."""
    meta = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'address': f"0x{addr:08X}",
        'expected_size': expected,
        'actual_size': actual,
        'sha256': file_hash,
        'region': region,
        'failed_chunks': len(failed),
        'failed_details': [{'address':f"0x{a:08X}",'size':s} for a,s in failed[:20]],
    }
    try:
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        print(f"{C.RED}[!] Metadata save failed: {e}{C.RESET}")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_dump(args=None) -> int:
    """QSLCL DUMP Command v2.0"""
    
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
        print(f"{C.RED}[!] No QSLCL{C.RESET}"); return 1
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    # Parse args
    addr_str = getattr(args, 'address', '') or (getattr(args, 'dump_args', [''])[0] if hasattr(args, 'dump_args') else '')
    size_str = getattr(args, 'size', '')
    output = getattr(args, 'output', '')
    chunk_size = max(512, min(int(getattr(args, 'chunk_size', DEFAULT_CHUNK_SIZE) or DEFAULT_CHUNK_SIZE), 16*1024*1024))
    verify = getattr(args, 'verify', False)
    compress = getattr(args, 'compress', False)
    resume = getattr(args, 'resume', False)
    retries = max(1, min(int(getattr(args, 'retries', MAX_RETRIES) or MAX_RETRIES), 10))
    verbose = getattr(args, 'verbose', False)
    
    if not addr_str:
        print(f"{C.RED}[!] No address specified{C.RESET}")
        return 1

    # Resolve address
    parts = _load_partitions(dev) if _load_partitions else []
    regions = _detect_memory_regions(dev) if _detect_memory_regions else []
    
    if _resolve_target:
        try:
            res = _resolve_target(addr_str, parts, regions, dev)
            if res:
                address = res['address']
                max_size = res.get('size', 0)
                pi = res.get('partition_info')
                ri = res.get('region_info')
                region_desc = f"Partition: {pi['name']}" if pi else f"Region: {ri['name']}" if ri else "Raw address"
        except:
            address = _parse_address(addr_str)
            max_size = 0
            region_desc = "Raw address"
        else:
            address = _parse_address(addr_str)
            max_size = 0
            region_desc = "Raw address"
    else:
        address = _parse_address(addr_str)
        max_size = 0
        region_desc = "Raw address"
    
    print(f"\n{C.BOLD}[+] Target: 0x{address:08X} ({region_desc}){C.RESET}")
    
    # Determine size
    if size_str:
        dump_size = _parse_size(size_str)
        if dump_size <= 0:
            print(f"{C.RED}[!] Invalid size: {size_str}{C.RESET}"); return 1
    elif max_size > 0:
        dump_size = max_size
        print(f"[+] Auto size: {_format_size(dump_size)}")
    else:
        print(f"{C.RED}[!] Size required for raw address. Use --size{C.RESET}")
        return 1
    
    if dump_size > MAX_DUMP_SIZE:
        print(f"{C.RED}[!] Size {_format_size(dump_size)} exceeds max {_format_size(MAX_DUMP_SIZE)}{C.RESET}")
        return 1
    
    print(f"[+] Size: {_format_size(dump_size)}")
    
    # Output file
    if not output:
        output = _gen_filename(address, dump_size, region_desc)
        print(f"[+] Output: {output}")
    
    # Resume
    existing = 0
    start_addr = address
    remaining = dump_size
    
    if resume and os.path.exists(output):
        existing = os.path.getsize(output)
        if existing >= dump_size:
            print(f"{C.YELLOW}[*] Already complete: {_format_size(existing)}{C.RESET}")
            return 0
        if existing > 0:
            start_addr = address + existing
            remaining = dump_size - existing
            print(f"[+] Resume from offset: {_format_size(existing)}")
    
    # Disk space
    if not _check_disk_space(output, remaining):
        return 1
    
    # Confirm overwrite
    if not resume and os.path.exists(output):
        try:
            r = input(f"\n[!] File exists: {output}. Overwrite? (y/N): ")
            if r.lower() not in ('y','yes'): return 0
        except: pass
    
    # Summary
    print(f"\n{C.BOLD}[+] Dump Summary:{C.RESET}")
    print(f"    Source: 0x{start_addr:08X}, Size: {_format_size(remaining)}")
    print(f"    Chunk: {_format_size(chunk_size)}, Retries: {retries}")
    print(f"    Verify: {'ON' if verify else 'OFF'}, Compress: {'ON' if compress else 'OFF'}")
    
    # Execute
    print(f"\n{C.CYAN}[*] Dumping...{C.RESET}")
    
    bytes_done = 0
    errors = 0
    failed = []
    start_time = time.time()
    
    try:
        mode = 'ab' if resume and existing > 0 else 'wb'
        with open(output, mode) as f:
            with LocalProgressBar(remaining, prefix='Dumping', suffix='Complete') as pb:
                while bytes_done < remaining:
                    addr = start_addr + bytes_done
                    cs = min(chunk_size, remaining - bytes_done)
                    
                    data, ok = _read_chunk(dev, addr, cs, retries)
                    
                    if ok and data:
                        f.write(data[:cs])
                        f.flush()
                        bytes_done += cs
                    else:
                        # Write zeros for failed chunk
                        f.write(b'\x00' * cs)
                        f.flush()
                        bytes_done += cs
                        errors += 1
                        failed.append((addr, cs))
                        if verbose:
                            print(f"\n{C.YELLOW}[!] Failed at 0x{addr:08X}{C.RESET}")
                    
                    pb.update(cs)
                    
                    # Abort on excessive errors
                    if errors > MAX_ERRORS_BEFORE_ABORT:
                        print(f"\n{C.RED}[!] Too many errors ({errors}), aborting{C.RESET}")
                        break
    
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!] Interrupted - partial data saved{C.RESET}")
        return 1
    except Exception as e:
        print(f"\n{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1
    
    elapsed = time.time() - start_time
    speed = bytes_done / elapsed if elapsed > 0 else 0
    total_bytes = existing + bytes_done
    
    print(f"\n{C.BOLD}[+] Complete:{C.RESET}")
    print(f"    Dumped: {_format_size(bytes_done)} in {_format_time(elapsed)} ({_format_speed(speed)})")
    print(f"    Total:  {_format_size(total_bytes)}/{_format_size(dump_size)}")
    if errors:
        print(f"    {C.YELLOW}Errors: {errors} chunks{C.RESET}")
    if failed and verbose:
        for a, s in failed[:5]:
            print(f"      - 0x{a:08X} ({_format_size(s)})")
    
    # Verify
    if verify and total_bytes > 0:
        _verify_dump(dev, address, output, total_bytes, chunk_size, verbose)
    
    # Compress
    final_output = output
    if compress and total_bytes > 0:
        gz_path = output + '.gz'
        try:
            print(f"\n{C.CYAN}[*] Compressing...{C.RESET}")
            with open(output, 'rb') as fi, gzip.open(gz_path, 'wb') as fo:
                shutil.copyfileobj(fi, fo)
            orig = os.path.getsize(output)
            comp = os.path.getsize(gz_path)
            ratio = (1 - comp/orig) * 100 if orig > 0 else 0
            print(f"[+] Compressed: {_format_size(orig)} → {_format_size(comp)} ({ratio:.1f}%)")
            final_output = gz_path
            
            try:
                if input("    Remove original? (y/N): ").lower() in ('y','yes'):
                    os.remove(output)
            except: pass
        except Exception as e:
            print(f"{C.RED}[!] Compression failed: {e}{C.RESET}")
    
    # Hash & metadata
    if os.path.exists(final_output):
        try:
            h = hashlib.sha256()
            with open(final_output, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            fhash = h.hexdigest()
            print(f"\n[+] SHA256: {fhash[:32]}...")
            
            _save_metadata(final_output + '.meta', address, dump_size, total_bytes,
                          fhash, region_desc, failed)
        except Exception as e:
            print(f"{C.RED}[!] Hash error: {e}{C.RESET}")
    
    print(f"\n{C.GREEN}[✓] Done: {final_output}{C.RESET}")
    return 0


def print_help():
    print(f"""
{C.BOLD}DUMP - Memory Dump & Export{C.RESET}
{'='*50}

{C.CYAN}USAGE:{C.RESET}
  qslcl dump <address> [--size SIZE] [options]

{C.CYAN}OPTIONS:{C.RESET}
  --size <size>       Dump size (supports K/M/G)
  --output <file>     Output file path
  --chunk-size <n>    Chunk size (default: 64KB)
  --verify            Verify dump integrity
  --compress          GZIP compress output
  --resume            Resume interrupted dump
  --retries <n>       Max retries (default: 3)
  --verbose, -v       Verbose output

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl dump boot boot.img
  qslcl dump 0x10000000 --size 1M --output dump.bin
  qslcl dump system --size 100M --compress --verify
  qslcl dump boot+0x1000 --size 64K --verbose
""")


def add_dump_arguments(parser):
    parser.add_argument('address', help='Target address/partition')
    parser.add_argument('--size', help='Size to dump')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--compress', action='store_true')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--retries', type=int, default=MAX_RETRIES)
    parser.add_argument('--verbose', '-v', action='store_true')
    return parser


if __name__ == "__main__":
    print("[*] dump.py - QSLCL DUMP Module v2.0")
    print_help()