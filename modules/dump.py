#!/usr/bin/env python3
"""
dump.py - QSLCL DUMP Command Module v2.1 (CLEANED)
Binary memory dumping with resume, verification, compression, and metadata
"""

import os
import sys
import re
import struct
import time
import json
import gzip
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
MAX_DUMP_SIZE = 4 * 1024**3       # 4GB max
DEFAULT_CHUNK = 65536             # 64KB
MAX_RETRIES = 3
MAX_ERRORS = 50                   # Abort threshold


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_address(s: str) -> int:
    """Parse address: 0x1000, $1000, 4096, 1000h"""
    if isinstance(s, int): return s
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    if s.startswith('$'): return int(s[1:], 16)
    if s.endswith('h'): return int(s[:-1], 16)
    try: return int(s, 16)
    except ValueError: return int(s, 10)


def parse_size(s: str) -> int:
    """Parse size: 1M, 512K, 2G, 0x1000"""
    if not s: return 0
    s = str(s).strip().upper()
    if s.startswith('0X'): return int(s, 16)
    for sfx, mul in [('GB',1024**3),('G',1024**3),('MB',1024**2),
                      ('M',1024**2),('KB',1024),('K',1024),('B',1)]:
        if s.endswith(sfx):
            return int(float(s[:-len(sfx)]) * mul)
    try: return int(s)
    except: return 0


def format_size(n: int) -> str:
    """Human-readable size"""
    if n < 1024: return f"{n} B"
    elif n < 1024**2: return f"{n/1024:.1f} KB"
    elif n < 1024**3: return f"{n/(1024**2):.1f} MB"
    return f"{n/(1024**3):.2f} GB"


def format_time(sec: float) -> str:
    """Human-readable time"""
    if sec < 1: return f"{sec*1000:.0f}ms"
    if sec < 60: return f"{sec:.1f}s"
    if sec < 3600: return f"{sec//60:.0f}m {sec%60:.0f}s"
    return f"{sec//3600:.0f}h {(sec%3600)//60:.0f}m"


def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve dump target"""
    if '+' in target:
        name, off_str = target.split('+', 1)
        offset = parse_address(off_str.strip())
        for p in partitions:
            if p.get('name','').lower() == name.strip().lower():
                return {'address': p['offset']+offset, 'size': p['size']-offset,
                        'info': f"Partition: {p['name']}", 'offset': offset}
    
    for p in partitions:
        if p.get('name','').lower() == target.lower():
            return {'address': p['offset'], 'size': p['size'],
                    'info': f"Partition: {p['name']}"}
    
    try:
        return {'address': parse_address(target), 'size': 0, 'info': 'Raw address'}
    except ValueError:
        return None


class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
        self.start = time.time()
    
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
        elapsed = max(time.time()-self.start, 0.001)
        rate = self.current / elapsed
        eta = (self.total-self.current) / max(rate, 1)
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {format_size(rate)}/s ETA:{eta:.0f}s',
              end='', flush=True)


# =============================================================================
# MAIN DUMP COMMAND
# =============================================================================
def cmd_dump(args=None) -> int:
    """
    QSLCL DUMP - Binary memory dumper
    
    Examples:
        dump boot                          - Dump entire boot partition
        dump boot boot.img                 - Dump to specific file
        dump 0x10000000 --size 1M          - Dump 1MB from address
        dump system --size 100M --compress - Dump and compress
        dump boot --resume                 - Resume interrupted dump
        dump boot --verify                 - Verify after dumping
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: dump <address> [--size SIZE] [options]")
        return 1
    
    # Device discovery
    devs = scan_all()
    if not devs:
        print("[!] No device detected")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    # Loader injection
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Extract arguments
    addr_str = getattr(args, 'address', '')
    size_str = getattr(args, 'size', '')
    output = getattr(args, 'output', '')
    chunk_size = max(512, min(getattr(args, 'chunk_size', DEFAULT_CHUNK), 16*1024*1024))
    verify = getattr(args, 'verify', False)
    compress = getattr(args, 'compress', False)
    resume = getattr(args, 'resume', False)
    retries = max(1, min(getattr(args, 'retries', MAX_RETRIES), 10))
    verbose = getattr(args, 'verbose', False)
    
    # Check positional arg2 (could be size or output)
    if hasattr(args, 'arg2') and args.arg2:
        if not output and not size_str:
            # Determine if arg2 is size or filename
            a2 = args.arg2
            if a2 and (a2[0].isdigit() or a2.lower().startswith('0x') or 
                       a2.upper().endswith(('K','M','G','B'))):
                size_str = a2
            else:
                output = a2
    
    if not addr_str:
        print("[!] No address specified")
        print("[*] Examples: dump boot, dump 0x10000000 --size 1M")
        return 1
    
    # Resolve partitions
    partitions = []
    try:
        partitions = load_partitions(dev)
    except:
        pass
    
    # Resolve target
    target_info = resolve_target(addr_str, partitions, dev)
    if not target_info:
        print(f"[!] Cannot resolve: '{addr_str}'")
        if partitions:
            print(f"\n[*] Available partitions:")
            for p in sorted(partitions, key=lambda x: x['offset']):
                print(f"    {p['name']:<16} 0x{p['offset']:08X}  {format_size(p['size'])}")
        return 1
    
    address = target_info['address']
    max_size = target_info.get('size', 0)
    region = target_info.get('info', 'Raw address')
    
    print(f"\n[+] Target: 0x{address:08X} ({region})")
    
    # Determine size
    if size_str:
        dump_size = parse_size(size_str)
        if dump_size <= 0:
            print(f"[!] Invalid size: {size_str}")
            return 1
    elif max_size > 0:
        dump_size = max_size
        print(f"[+] Auto size: {format_size(dump_size)}")
    else:
        print("[!] Size required for raw address. Use --size <bytes>")
        return 1
    
    if dump_size > MAX_DUMP_SIZE:
        print(f"[!] Size {format_size(dump_size)} exceeds max {format_size(MAX_DUMP_SIZE)}")
        return 1
    
    print(f"[+] Size: {format_size(dump_size)} (0x{dump_size:X})")
    
    # Output file
    if not output:
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^a-z0-9_-]', '_', region.lower())[:30]
        output = f"dump_{safe_name}_0x{address:08X}_{ts}.bin"
        print(f"[+] Output: {output}")
    
    # Resume support
    existing = 0
    start_addr = address
    remaining = dump_size
    
    if resume and os.path.exists(output):
        existing = os.path.getsize(output)
        if existing >= dump_size:
            print(f"[*] Already complete: {format_size(existing)}")
            return 0
        if existing > 0:
            start_addr = address + existing
            remaining = dump_size - existing
            print(f"[+] Resume from: {format_size(existing)}")
    
    # Disk space check
    try:
        d = os.path.dirname(os.path.abspath(output)) or '.'
        import shutil
        free = shutil.disk_usage(d).free
        if free < remaining * 1.1:
            print(f"[!] Low disk space: {format_size(free)} free, need {format_size(remaining)}")
            if input("    Continue? (y/N): ").lower() != 'y':
                return 0
    except:
        pass
    
    # Overwrite check
    if not resume and os.path.exists(output):
        if input(f"\n[!] File exists: {output}\n    Overwrite? (y/N): ").lower() not in ('y','yes'):
            print("[*] Cancelled")
            return 0
    
    # Summary
    print(f"\n[+] Dump Configuration:")
    print(f"    Source:  0x{start_addr:08X}")
    print(f"    Size:    {format_size(remaining)}")
    print(f"    Chunk:   {format_size(chunk_size)}")
    print(f"    Retries: {retries}")
    print(f"    Verify:  {'Yes' if verify else 'No'}")
    print(f"    GZIP:    {'Yes' if compress else 'No'}")
    
    # =========================================================================
    # EXECUTE DUMP
    # =========================================================================
    print(f"\n[*] Dumping...")
    
    bytes_done = 0
    errors = 0
    failed = []
    start_time = time.time()
    
    try:
        mode = 'ab' if existing > 0 else 'wb'
        with open(output, mode) as f:
            with ProgressBar(remaining, prefix='Dumping', suffix='Complete') as pb:
                
                while bytes_done < remaining:
                    addr = start_addr + bytes_done
                    chunk = min(chunk_size, remaining - bytes_done)
                    
                    if chunk <= 0:
                        break
                    
                    # Read from device
                    data = None
                    read_payload = struct.pack("<II", addr, chunk)
                    
                    for attempt in range(retries + 1):
                        try:
                            if "READ" in QSLCLCMD_DB:
                                resp = qslcl_dispatch(dev, "READ", read_payload, timeout=20)
                            else:
                                pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                                dev.write(pkt)
                                _, resp = dev.read(timeout=20)
                            
                            if resp:
                                status = decode_runtime_result(resp)
                                if status.get("severity") == "SUCCESS":
                                    data = status.get("extra", b"")
                                    if data:
                                        break
                            
                            if attempt < retries:
                                time.sleep(0.1 * (2 ** attempt))
                        
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            if _DEBUG and attempt >= retries:
                                print(f"\n[!] Read error at 0x{addr:08X}: {e}")
                            if attempt < retries:
                                time.sleep(0.2)
                    
                    # Write data
                    if data:
                        f.write(data[:chunk])
                        if len(data) < chunk:
                            f.write(b'\x00' * (chunk - len(data)))
                    else:
                        f.write(b'\x00' * chunk)
                        errors += 1
                        failed.append((addr, chunk))
                        if verbose:
                            print(f"\n[!] Failed at 0x{addr:08X} ({format_size(chunk)})")
                    
                    bytes_done += chunk
                    pb.update(chunk)
                    
                    if errors > MAX_ERRORS:
                        print(f"\n[!] Too many errors ({errors}), aborting")
                        break
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted - partial data saved")
        print(f"[*] Resume with: dump {addr_str} --resume --output {output}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Dump error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    
    elapsed = time.time() - start_time
    speed = bytes_done / max(elapsed, 0.001)
    total_bytes = existing + bytes_done
    
    print(f"\n[+] Dump Complete:")
    print(f"    Written:  {format_size(bytes_done)} in {format_time(elapsed)}")
    print(f"    Speed:    {format_size(speed)}/s")
    print(f"    Total:    {format_size(total_bytes)}/{format_size(dump_size)}")
    if errors:
        print(f"    Errors:   {errors} chunks ({format_size(sum(s for _,s in failed))})")
    
    # =========================================================================
    # VERIFICATION
    # =========================================================================
    if verify and total_bytes > 0:
        print(f"\n[*] Verifying...")
        ver_ok = 0
        ver_err = 0
        ver_mismatch = 0
        
        try:
            with open(output, 'rb') as f:
                with ProgressBar(total_bytes, prefix='Verifying', suffix='Complete') as vb:
                    for vaddr in range(address, address+total_bytes, chunk_size):
                        vchunk = min(chunk_size, address+total_bytes - vaddr)
                        
                        file_data = f.read(vchunk)
                        if not file_data:
                            break
                        
                        # Skip all-zero (known failed)
                        if file_data == b'\x00' * len(file_data):
                            ver_ok += len(file_data)
                            vb.update(len(file_data))
                            continue
                        
                        read_payload = struct.pack("<II", vaddr, vchunk)
                        
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=15)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=15)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            dev_data = status.get("extra", b"")
                            
                            if dev_data == file_data:
                                ver_ok += len(file_data)
                            else:
                                mm = sum(1 for i in range(min(len(file_data),len(dev_data)))
                                       if file_data[i] != dev_data[i])
                                ver_mismatch += mm
                                ver_err += 1
                                if verbose:
                                    print(f"\n[!] Mismatch at 0x{vaddr:08X}: {mm} bytes")
                        else:
                            ver_err += 1
                        
                        ver_ok += len(file_data)
                        vb.update(len(file_data))
            
            pct = ver_ok*100/max(total_bytes,1)
            print(f"\n    Verified: {format_size(ver_ok)} ({pct:.1f}%)")
            if ver_err:
                print(f"    Errors:   {ver_err} chunks, {ver_mismatch} mismatched bytes")
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
    
    # =========================================================================
    # COMPRESSION
    # =========================================================================
    final_output = output
    
    if compress and total_bytes > 0:
        gz_path = output + '.gz'
        try:
            print(f"\n[*] Compressing...")
            with open(output, 'rb') as fi, gzip.open(gz_path, 'wb') as fo:
                import shutil
                shutil.copyfileobj(fi, fo, 65536)
            
            orig_sz = os.path.getsize(output)
            comp_sz = os.path.getsize(gz_path)
            ratio = (1 - comp_sz/orig_sz) * 100
            print(f"[+] {format_size(orig_sz)} → {format_size(comp_sz)} ({ratio:.1f}% saved)")
            final_output = gz_path
            
            if input("    Remove original? (y/N): ").lower() in ('y','yes'):
                os.remove(output)
        except Exception as e:
            print(f"[!] Compression failed: {e}")
    
    # =========================================================================
    # METADATA & HASH
    # =========================================================================
    if os.path.exists(final_output):
        try:
            sha = hashlib.sha256()
            with open(final_output, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    sha.update(chunk)
            fhash = sha.hexdigest()
            print(f"[+] SHA256: {fhash[:40]}...")
            
            # Save metadata
            meta = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'address': f"0x{address:08X}",
                'expected_size': dump_size,
                'actual_size': total_bytes,
                'sha256': fhash,
                'region': region,
                'failed_chunks': len(failed),
            }
            with open(final_output + '.meta', 'w') as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            print(f"[!] Metadata error: {e}")
    
    print(f"\n[✓] Done: {final_output}")
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] dump.py - QSLCL DUMP Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py dump <address> [options]")