#!/usr/bin/env python3
"""
dump.py - QSLCL DUMP Command Module v2.2 (RAW ADDRESS ONLY)
Simple raw memory dumper for low-level modes (DFU/EDL/BROM)

NO partitions, NO parsing, NO auto-detection.
Just dump from address A to address B.
"""

import os
import sys
import struct
import time
import hashlib
from typing import Optional

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
DEFAULT_CHUNK = 4096          # 4KB chunks (DFU friendly)
MAX_CHUNK = 1024 * 1024       # 1MB max
MAX_DUMP_SIZE = 1024 * 1024 * 1024  # 1GB max
MAX_RETRIES = 3


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_address(s: str) -> int:
    """Parse address: 0x1000, 0xFFFFFFFF, 4096, 0x80000000"""
    if isinstance(s, int):
        return s
    
    s = str(s).strip().lower()
    
    # Hex with 0x prefix
    if s.startswith('0x'):
        return int(s[2:], 16)
    
    # Hex without prefix (assume hex if contains a-f)
    if any(c in 'abcdef' for c in s):
        return int(s, 16)
    
    # Decimal
    try:
        return int(s, 10)
    except ValueError:
        raise ValueError(f"Cannot parse address: {s}")


def parse_size(s: str) -> int:
    """Parse size: 1M, 512K, 2G, 0x1000, or just number"""
    if not s:
        return 0
    
    s = str(s).strip().upper()
    
    # Hex
    if s.startswith('0X'):
        return int(s, 16)
    
    # With suffix
    suffixes = {
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
    }
    
    for suffix, multiplier in suffixes.items():
        if s.endswith(suffix):
            try:
                return int(float(s[:-len(suffix)]) * multiplier)
            except:
                pass
    
    # Plain number
    try:
        return int(s, 16) if s.startswith('0x') else int(s, 10)
    except:
        raise ValueError(f"Cannot parse size: {s}")


def format_size(n: int) -> str:
    """Human readable size"""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n/(1024*1024):.1f} MB"
    else:
        return f"{n/(1024*1024*1024):.2f} GB"


def format_time(sec: float) -> str:
    """Human readable time"""
    if sec < 1:
        return f"{sec*1000:.0f} ms"
    if sec < 60:
        return f"{sec:.1f} s"
    if sec < 3600:
        return f"{sec//60:.0f}m {sec%60:.0f}s"
    return f"{sec//3600:.0f}h {(sec%3600)//60:.0f}m"


class ProgressBar:
    """Simple progress bar"""
    def __init__(self, total: int, prefix: str = '', length: int = 40):
        self.total = max(total, 1)
        self.prefix = prefix
        self.length = length
        self.current = 0
        self.start = time.time()
    
    def update(self, n: int):
        self.current += n
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '░' * (self.length - filled)
        
        elapsed = max(time.time() - self.start, 0.001)
        rate = self.current / elapsed
        eta = (self.total - self.current) / max(rate, 1)
        
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {format_size(rate)}/s ETA:{eta:.0f}s',
              end='', flush=True)
    
    def close(self):
        print()


# =============================================================================
# MAIN DUMP COMMAND
# =============================================================================

def cmd_dump(args=None) -> int:
    """
    QSLCL DUMP - Raw memory dumper for low-level modes
    
    USAGE:
        dump <start> <end>                    - Dump from start to end address
        dump <start> --size <bytes>           - Dump N bytes from start
        dump <start> <end> --output file.bin  - Save to specific file
    
    EXAMPLES:
        dump 0x00000000 0x00010000            - Dump 64KB from 0x0
        dump 0x80000000 --size 1M             - Dump 1MB from 0x80000000
        dump 0x10000000 0x20000000 --output dump.bin
        dump 0xFFFFFFFF --size 4096           - Dump 4KB from top of memory
    
    NOTES:
        - Works in DFU, EDL, BROM, and low-level modes
        - No partition parsing - just raw addresses
        - Use --verify to compare with device after dump
    """
    
    # =====================================================================
    # Parse arguments
    # =====================================================================
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: dump <start> [end or --size SIZE] [--output FILE]")
        return 1
    
    # Get device
    devs = scan_all()
    if not devs:
        print("[!] No device detected")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    # Loader if specified
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Extract arguments
    start_str = getattr(args, 'address', '') or getattr(args, 'start', '')
    end_str = getattr(args, 'end', '')
    size_str = getattr(args, 'size', '')
    output_file = getattr(args, 'output', '')
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK)
    verify = getattr(args, 'verify', False)
    retries = getattr(args, 'retries', MAX_RETRIES)
    
    # Handle positional arg2 (could be end address)
    if hasattr(args, 'arg2') and args.arg2 and not end_str:
        end_str = args.arg2
    
    # Validate start address
    if not start_str:
        print("[!] No start address specified")
        print("[*] Examples:")
        print("    dump 0x00000000 0x00010000")
        print("    dump 0x80000000 --size 1M")
        return 1
    
    try:
        start_addr = parse_address(start_str)
    except ValueError as e:
        print(f"[!] Invalid start address: {start_str}")
        print(f"    {e}")
        return 1
    
    # Determine dump size
    dump_size = 0
    
    if end_str:
        # Range mode: start to end
        try:
            end_addr = parse_address(end_str)
            if end_addr <= start_addr:
                print(f"[!] End address (0x{end_addr:08X}) must be greater than start (0x{start_addr:08X})")
                return 1
            dump_size = end_addr - start_addr
            print(f"[*] Mode: Range (0x{start_addr:08X} → 0x{end_addr:08X})")
        except ValueError as e:
            print(f"[!] Invalid end address: {end_str}")
            return 1
    
    elif size_str:
        # Size mode
        try:
            dump_size = parse_size(size_str)
            if dump_size <= 0:
                print(f"[!] Invalid size: {size_str}")
                return 1
            print(f"[*] Mode: Size ({format_size(dump_size)} from 0x{start_addr:08X})")
        except ValueError as e:
            print(f"[!] Invalid size: {size_str}")
            return 1
    
    else:
        print("[!] Specify either end address or --size")
        print("[*] Examples:")
        print("    dump 0x00000000 0x00010000")
        print("    dump 0x00000000 --size 64K")
        return 1
    
    # Validate size
    if dump_size <= 0:
        print(f"[!] Invalid dump size: {dump_size} bytes")
        return 1
    
    if dump_size > MAX_DUMP_SIZE:
        print(f"[!] Size {format_size(dump_size)} exceeds maximum {format_size(MAX_DUMP_SIZE)}")
        return 1
    
    # Validate chunk size
    chunk_size = max(64, min(chunk_size, MAX_CHUNK))
    
    # Output file
    if not output_file:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = f"dump_0x{start_addr:08X}_{format_size(dump_size).replace(' ', '')}_{timestamp}.bin"
    
    # Check if file exists
    if os.path.exists(output_file):
        overwrite = input(f"\n[!] File exists: {output_file}\n    Overwrite? (y/N): ").lower()
        if overwrite not in ('y', 'yes'):
            print("[*] Cancelled")
            return 0
    
    # =====================================================================
    # Summary
    # =====================================================================
    print(f"\n[+] Dump Configuration:")
    print(f"    Start:    0x{start_addr:08X}")
    print(f"    End:      0x{start_addr + dump_size:08X}")
    print(f"    Size:     {format_size(dump_size)}")
    print(f"    Chunk:    {format_size(chunk_size)}")
    print(f"    Retries:  {retries}")
    print(f"    Verify:   {'Yes' if verify else 'No'}")
    print(f"    Output:   {output_file}")
    
    # =====================================================================
    # Execute dump
    # =====================================================================
    print(f"\n[*] Dumping...")
    
    bytes_read = 0
    errors = 0
    failed_chunks = []
    start_time = time.time()
    
    try:
        with open(output_file, 'wb') as f:
            progress = ProgressBar(dump_size, prefix='Dumping')
            
            while bytes_read < dump_size:
                addr = start_addr + bytes_read
                chunk = min(chunk_size, dump_size - bytes_read)
                
                # Read from device
                data = None
                read_payload = struct.pack("<II", addr, chunk)
                
                for attempt in range(retries + 1):
                    try:
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=10)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=10)
                        
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
                        if attempt >= retries and _DEBUG:
                            print(f"\n[!] Read error at 0x{addr:08X}: {e}")
                        if attempt < retries:
                            time.sleep(0.2)
                
                # Write data (or zeros on failure)
                if data:
                    f.write(data[:chunk])
                    if len(data) < chunk:
                        f.write(b'\x00' * (chunk - len(data)))
                else:
                    f.write(b'\x00' * chunk)
                    errors += 1
                    failed_chunks.append((addr, chunk))
                    if _DEBUG:
                        print(f"\n[!] Failed at 0x{addr:08X}")
                
                bytes_read += chunk
                progress.update(chunk)
            
            progress.close()
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted at {format_size(bytes_read)}/{format_size(dump_size)}")
        print(f"    Partial data saved to {output_file}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Dump failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    
    # =====================================================================
    # Results
    # =====================================================================
    elapsed = time.time() - start_time
    speed = bytes_read / max(elapsed, 0.001)
    
    print(f"\n[+] Dump Complete:")
    print(f"    Size:     {format_size(bytes_read)}")
    print(f"    Time:     {format_time(elapsed)}")
    print(f"    Speed:    {format_size(speed)}/s")
    
    if errors > 0:
        print(f"    Errors:   {errors} chunks ({format_size(errors * chunk_size)} zeros written)")
    
    # =====================================================================
    # Verification (optional)
    # =====================================================================
    if verify and bytes_read > 0:
        print(f"\n[*] Verifying...")
        
        verify_ok = 0
        verify_errors = 0
        
        try:
            with open(output_file, 'rb') as f:
                progress = ProgressBar(bytes_read, prefix='Verifying')
                offset = 0
                
                while offset < bytes_read:
                    addr = start_addr + offset
                    chunk = min(chunk_size, bytes_read - offset)
                    
                    file_data = f.read(chunk)
                    if not file_data:
                        break
                    
                    # Skip zeros (likely failed reads)
                    if file_data == b'\x00' * len(file_data):
                        verify_ok += len(file_data)
                        offset += len(file_data)
                        progress.update(len(file_data))
                        continue
                    
                    # Read from device
                    read_payload = struct.pack("<II", addr, chunk)
                    
                    try:
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=10)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=10)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            dev_data = status.get("extra", b"")
                            
                            if dev_data == file_data:
                                verify_ok += len(file_data)
                            else:
                                mismatches = sum(1 for i in range(min(len(file_data), len(dev_data)))
                                               if file_data[i] != dev_data[i])
                                verify_errors += mismatches
                                if _DEBUG:
                                    print(f"\n[!] Mismatch at 0x{addr:08X}: {mismatches} bytes")
                        else:
                            verify_errors += chunk
                    
                    except Exception as e:
                        verify_errors += chunk
                        if _DEBUG:
                            print(f"\n[!] Verify error at 0x{addr:08X}: {e}")
                    
                    offset += chunk
                    progress.update(chunk)
                
                progress.close()
            
            if verify_errors == 0:
                print(f"\n[+] Verification PASSED - {format_size(verify_ok)} matched")
            else:
                print(f"\n[!] Verification FAILED - {format_size(verify_errors)} mismatched bytes")
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
    
    # =====================================================================
    # SHA256 hash
    # =====================================================================
    try:
        sha = hashlib.sha256()
        with open(output_file, 'rb') as f:
            while chunk_data := f.read(65536):
                sha.update(chunk_data)
        print(f"\n[*] SHA256: {sha.hexdigest()}")
    except:
        pass
    
    print(f"\n[✓] Saved to: {output_file}")
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] dump.py - QSLCL RAW Memory Dumper v2.2")
    print("[*] For low-level modes (DFU/EDL/BROM)")
    print("[*] Imported by qslcl.py")