#!/usr/bin/env python3
"""
read.py - QSLCL READ Command Module v2.2 (PARTITION ONLY)
Read entire partitions from device in low-level mode.

NOTE: For raw address dumping, use the 'dump' command instead.
This command is ONLY for reading named partitions.
"""

import os
import sys
import time
import struct
import hashlib
from typing import Optional, List, Dict

# =============================================================================
# IMPORTS
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
DEFAULT_CHUNK = 65536          # 64KB default
MAX_RETRIES = 3
READ_TIMEOUT = 15.0


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
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


def list_available_partitions(partitions: List[Dict]) -> None:
    """Display available partitions"""
    if not partitions:
        print("[!] No partitions detected")
        return
    
    print("\n[*] Available Partitions:")
    print(f"    {'Name':<20} {'Offset':<12} {'Size':<12}")
    print(f"    {'-'*20} {'-'*12} {'-'*12}")
    
    for p in sorted(partitions, key=lambda x: x['offset']):
        name = p.get('name', 'unknown')[:20]
        offset = f"0x{p['offset']:08X}"
        size = format_size(p['size'])
        print(f"    {name:<20} {offset:<12} {size:<12}")


# =============================================================================
# MAIN READ COMMAND
# =============================================================================

def cmd_read(args=None) -> int:
    """
    QSLCL READ - Read entire partition from device
    
    USAGE:
        read <partition_name>                    - Read partition to <name>.bin
        read <partition_name> <output_file>      - Read to specific file
        read --list                               - List available partitions
    
    EXAMPLES:
        read boot                                 - Read boot partition
        read system system.img                   - Read system to system.img
        read userdata --output user.bin          - Read userdata to custom file
        read --list                               - Show all partitions
    
    NOTES:
        - Only reads NAMED partitions (no raw addresses)
        - For raw address dumping, use 'dump' command
        - Works in DFU, EDL, BROM, and low-level modes
    """
    
    # =====================================================================
    # Parse arguments
    # =====================================================================
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: read <partition_name> [output_file]")
        print("[*]        read --list")
        return 1
    
    # Handle --list flag
    if getattr(args, 'list', False) or (hasattr(args, 'subcmd') and args.subcmd == 'list'):
        devs = scan_all()
        if not devs:
            print("[!] No device detected")
            return 1
        
        dev = devs[0]
        print(f"[*] Device: {dev.product}")
        
        try:
            partitions = load_partitions(dev)
            list_available_partitions(partitions)
        except Exception as e:
            print(f"[!] Failed to load partitions: {e}")
        return 0
    
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
    
    # Get partition name
    partition_name = getattr(args, 'target', '') or getattr(args, 'partition', '')
    
    # Check positional args
    if not partition_name and hasattr(args, 'args') and args.args:
        partition_name = args.args[0] if args.args else ''
    
    if not partition_name:
        print("[!] No partition specified")
        print("[*] Usage: read <partition_name> [output_file]")
        print("[*]        read --list  (show available partitions)")
        return 1
    
    # Get output file
    output_file = getattr(args, 'output', '')
    
    # Check positional arg2 as output
    if not output_file and hasattr(args, 'arg2') and args.arg2:
        output_file = args.arg2
    
    # Load partitions
    try:
        partitions = load_partitions(dev)
    except Exception as e:
        print(f"[!] Cannot load partitions: {e}")
        return 1
    
    if not partitions:
        print("[!] No partitions detected on device")
        return 1
    
    # Find partition
    target_partition = None
    for p in partitions:
        if p.get('name', '').lower() == partition_name.lower():
            target_partition = p
            break
    
    if not target_partition:
        print(f"[!] Partition not found: '{partition_name}'")
        list_available_partitions(partitions)
        return 1
    
    # Partition info
    start_addr = target_partition['offset']
    size = target_partition['size']
    
    print(f"\n[+] Partition: {target_partition['name']}")
    print(f"    Offset:   0x{start_addr:08X}")
    print(f"    Size:     {format_size(size)}")
    
    # Default output filename
    if not output_file:
        output_file = f"{target_partition['name']}.bin"
    
    # Check if file exists
    if os.path.exists(output_file):
        overwrite = input(f"\n[!] File exists: {output_file}\n    Overwrite? (y/N): ").lower()
        if overwrite not in ('y', 'yes'):
            print("[*] Cancelled")
            return 0
    
    # Read configuration
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK)
    chunk_size = max(512, min(chunk_size, 16 * 1024 * 1024))  # 512B to 16MB
    
    verify = getattr(args, 'verify', False)
    
    print(f"\n[+] Read Configuration:")
    print(f"    Chunk:    {format_size(chunk_size)}")
    print(f"    Output:   {output_file}")
    print(f"    Verify:   {'Yes' if verify else 'No'}")
    
    # =====================================================================
    # Read partition
    # =====================================================================
    print(f"\n[*] Reading {target_partition['name']}...")
    
    bytes_read = 0
    errors = 0
    start_time = time.time()
    
    try:
        with open(output_file, 'wb') as f:
            progress = ProgressBar(size, prefix='Reading')
            
            while bytes_read < size:
                addr = start_addr + bytes_read
                chunk = min(chunk_size, size - bytes_read)
                
                # Build READ payload
                payload = struct.pack("<II", addr, chunk)
                
                # Send READ command
                try:
                    if "READ" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "READ", payload, timeout=READ_TIMEOUT)
                    else:
                        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                        dev.write(pkt)
                        _, resp = dev.read(timeout=READ_TIMEOUT)
                    
                    if resp:
                        status = decode_runtime_result(resp)
                        data = status.get("extra", b"")
                        
                        if data:
                            # Write data
                            f.write(data[:chunk])
                            if len(data) < chunk:
                                f.write(b'\x00' * (chunk - len(data)))
                            
                            bytes_read += chunk
                            progress.update(chunk)
                        else:
                            # No data, write zeros
                            f.write(b'\x00' * chunk)
                            bytes_read += chunk
                            progress.update(chunk)
                            errors += 1
                    else:
                        # No response, write zeros
                        f.write(b'\x00' * chunk)
                        bytes_read += chunk
                        progress.update(chunk)
                        errors += 1
                
                except Exception as e:
                    # On error, write zeros and continue
                    f.write(b'\x00' * chunk)
                    bytes_read += chunk
                    progress.update(chunk)
                    errors += 1
                    if _DEBUG:
                        print(f"\n[!] Error at 0x{addr:08X}: {e}")
            
            progress.close()
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted at {format_size(bytes_read)}/{format_size(size)}")
        print(f"    Partial data saved to {output_file}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Read failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    
    # =====================================================================
    # Results
    # =====================================================================
    elapsed = time.time() - start_time
    speed = bytes_read / max(elapsed, 0.001)
    
    print(f"\n[+] Read Complete:")
    print(f"    Read:     {format_size(bytes_read)}")
    print(f"    Time:     {format_time(elapsed)}")
    print(f"    Speed:    {format_size(speed)}/s")
    
    if errors > 0:
        print(f"    Errors:   {errors} chunks ({format_size(errors * chunk_size)} zeros written)")
    
    if bytes_read < size:
        print(f"    Status:   PARTIAL ({bytes_read*100/size:.1f}%)")
    else:
        print(f"    Status:   COMPLETE")
    
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
                    
                    # Read from device
                    payload = struct.pack("<II", addr, chunk)
                    
                    try:
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", payload, timeout=READ_TIMEOUT)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=READ_TIMEOUT)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            dev_data = status.get("extra", b"")
                            
                            if dev_data == file_data[:len(dev_data)]:
                                verify_ok += len(file_data)
                            else:
                                mismatches = sum(1 for i in range(min(len(file_data), len(dev_data)))
                                               if file_data[i] != dev_data[i])
                                verify_errors += mismatches
                    except Exception as e:
                        verify_errors += chunk
                    
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
            while chunk := f.read(65536):
                sha.update(chunk)
        print(f"\n[*] SHA256: {sha.hexdigest()}")
    except:
        pass
    
    print(f"\n[✓] Saved to: {output_file}")
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] read.py - QSLCL PARTITION READER v2.2")
    print("[*] For reading named partitions in low-level modes")
    print("[*] For raw addresses, use 'dump' command")