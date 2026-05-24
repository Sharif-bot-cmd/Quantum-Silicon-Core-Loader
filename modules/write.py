#!/usr/bin/env python3
"""
write.py - QSLCL WRITE Command Module v2.2 (PARTITION ONLY)
Write data to named partitions ONLY. NO raw address writing.

RAW ADDRESS WRITING IS DISABLED FOR SAFETY.
If you need to write raw addresses, use 'poke' command instead.

DANGEROUS: Writing to wrong partition CAN BRICK your device!
"""

import os
import sys
import struct
import time
import hashlib
from typing import Optional, List, Dict, Tuple

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
DEFAULT_CHUNK = 65536           # 64KB
MAX_RETRIES = 3
WRITE_TIMEOUT = 20.0
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB


# =============================================================================
# DANGEROUS PARTITIONS - Writing these WILL BRICK your device
# =============================================================================
DANGEROUS_PARTITIONS = {
    # CRITICAL - WILL BRICK DEVICE
    'bootrom':      "CRITICAL - BootROM - PERMANENT BRICK",
    'brom':         "CRITICAL - BootROM - PERMANENT BRICK", 
    'irom':         "CRITICAL - Internal ROM - PERMANENT BRICK",
    'pbl':          "CRITICAL - Primary Boot Loader - HIGH BRICK RISK",
    'preloader':    "CRITICAL - Preloader - HIGH BRICK RISK",
    'sbl':          "CRITICAL - Secondary Boot Loader - HIGH BRICK RISK",
    'sbl1':         "CRITICAL - Secondary Boot Loader - HIGH BRICK RISK",
    'aboot':        "CRITICAL - Android Bootloader - HIGH BRICK RISK",
    'lk':           "CRITICAL - Little Kernel - HIGH BRICK RISK",
    'xbl':          "CRITICAL - eXtensible Boot Loader - HIGH BRICK RISK",
    
    # HIGH RISK - May brick device
    'boot':         "HIGH - Boot partition - May cause boot failure",
    'bootloader':   "HIGH - Bootloader - May brick device",
    'rpm':          "HIGH - Resource Power Manager - May cause boot failure",
    'hyp':          "HIGH - Hypervisor - May cause boot failure",
    'tz':           "HIGH - TrustZone - May affect security",
    'sec':          "HIGH - Security partition - May brick device",
    
    # MEDIUM RISK - Recoverable but dangerous
    'recovery':     "MEDIUM - Recovery partition - Recoverable",
    'system':       "MEDIUM - System partition - May require reflash",
    'vendor':       "MEDIUM - Vendor partition - May require reflash",
    'userdata':     "LOW - User data - Safe but data loss",
    'cache':        "LOW - Cache - Safe",
    'misc':         "LOW - Misc - Safe",
}


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


def list_partitions(partitions: List[Dict]) -> None:
    """Display available partitions with safety levels"""
    if not partitions:
        print("[!] No partitions detected")
        return
    
    print("\n[*] Available Partitions:")
    print(f"    {'Name':<20} {'Offset':<12} {'Size':<12} {'Risk':<10}")
    print(f"    {'-'*20} {'-'*12} {'-'*12} {'-'*10}")
    
    for p in sorted(partitions, key=lambda x: x['offset']):
        name = p.get('name', 'unknown')[:20]
        offset = f"0x{p['offset']:08X}"
        size = format_size(p['size'])
        
        # Determine risk level
        risk = "LOW"
        for dangerous in DANGEROUS_PARTITIONS:
            if dangerous in name.lower():
                if "CRITICAL" in DANGEROUS_PARTITIONS[dangerous]:
                    risk = "💀 CRITICAL"
                elif "HIGH" in DANGEROUS_PARTITIONS[dangerous]:
                    risk = "⚠️ HIGH"
                else:
                    risk = "🟡 MEDIUM"
                break
        
        print(f"    {name:<20} {offset:<12} {size:<12} {risk:<10}")


def get_partition_risk(partition_name: str) -> Tuple[str, str]:
    """Get risk level and warning for a partition"""
    name_lower = partition_name.lower()
    
    for dangerous, warning in DANGEROUS_PARTITIONS.items():
        if dangerous in name_lower:
            if "CRITICAL" in warning:
                return "CRITICAL", warning
            elif "HIGH" in warning:
                return "HIGH", warning
            elif "MEDIUM" in warning:
                return "MEDIUM", warning
    
    return "LOW", "Safe to write, but verify first"


# =============================================================================
# MAIN WRITE COMMAND
# =============================================================================

def cmd_write(args=None) -> int:
    """
    QSLCL WRITE - Write data to partition (NO RAW ADDRESSES)
    
    USAGE:
        write <partition_name> <file.bin>           - Write file to partition
        write <partition_name> --fill <pattern>     - Fill with pattern
        write --list                                 - List partitions with risk levels
    
    EXAMPLES:
        write boot boot.img                          - Write to boot partition
        write system system.img --verify            - Write with verification
        write userdata userdata.bin --force         - Force write (skip confirm)
        write boot --fill FF                        - Fill boot with 0xFF
        write --list                                 - Show all partitions
    
    WARNINGS:
        - Writing to bootloader partitions CAN BRICK your device!
        - CRITICAL partitions (bootrom, pbl, sbl) are BLOCKED
        - HIGH risk partitions require --force
        - Verify your image files before writing!
    
    NOTE: For raw address writes, use 'poke' command instead.
    """
    
    # =====================================================================
    # Parse arguments
    # =====================================================================
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: write <partition_name> <file.bin>")
        print("[*]        write --list")
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
            list_partitions(partitions)
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
        print("[*] Usage: write <partition_name> <file.bin>")
        print("[*]        write --list  (show available partitions)")
        return 1
    
    # Get data source
    data_source = getattr(args, 'data', '')
    fill_pattern = getattr(args, 'fill', '')
    
    # Check positional arg2 as data source
    if not data_source and not fill_pattern and hasattr(args, 'arg2') and args.arg2:
        data_source = args.arg2
    
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
        list_partitions(partitions)
        return 1
    
    # Partition info
    start_addr = target_partition['offset']
    partition_size = target_partition['size']
    
    # Check risk level
    risk_level, risk_warning = get_partition_risk(partition_name)
    
    print(f"\n[+] Partition: {target_partition['name']}")
    print(f"    Offset:   0x{start_addr:08X}")
    print(f"    Size:     {format_size(partition_size)}")
    print(f"    Risk:     {risk_level}")
    
    if risk_level == "CRITICAL":
        print(f"\n💀💀💀 {risk_warning} 💀💀💀")
        print("\n[!] CRITICAL PARTITION - WRITE BLOCKED")
        print("    Writing to this partition would PERMANENTLY BRICK your device!")
        print("    This operation has been BLOCKED for safety.")
        return 1
    
    # =====================================================================
    # Load data
    # =====================================================================
    write_data = None
    source_type = None
    
    # Fill pattern mode
    if fill_pattern:
        if fill_pattern.upper() == 'FF':
            write_data = b'\xFF' * partition_size
            source_type = f"0xFF fill ({format_size(partition_size)})"
        elif fill_pattern.upper() == '00' or fill_pattern.upper() == 'ZERO':
            write_data = b'\x00' * partition_size
            source_type = f"Zero fill ({format_size(partition_size)})"
        else:
            try:
                # Try to parse as hex pattern
                pattern = bytes.fromhex(fill_pattern.replace(' ', ''))
                # Repeat pattern to fill partition
                repeats = (partition_size // len(pattern)) + 1
                write_data = (pattern * repeats)[:partition_size]
                source_type = f"Pattern '{fill_pattern}' ({format_size(len(write_data))})"
            except:
                print(f"[!] Invalid fill pattern: {fill_pattern}")
                return 1
    
    # File mode
    elif data_source:
        if not os.path.exists(data_source):
            print(f"[!] File not found: {data_source}")
            return 1
        
        file_size = os.path.getsize(data_source)
        if file_size == 0:
            print("[!] File is empty")
            return 1
        
        if file_size > MAX_FILE_SIZE:
            print(f"[!] File too large: {format_size(file_size)}")
            return 1
        
        if file_size > partition_size:
            print(f"[!] File ({format_size(file_size)}) exceeds partition ({format_size(partition_size)})")
            force = getattr(args, 'force', False)
            if not force:
                print("[*] Use --force to truncate (will cut off end of file)")
                return 1
            print("[!] Force mode: truncating file to fit partition")
        
        with open(data_source, 'rb') as f:
            write_data = f.read(partition_size)
        source_type = f"File '{data_source}' ({format_size(len(write_data))})"
        
        # Show file hash
        sha = hashlib.sha256(write_data).hexdigest()
        print(f"    SHA256: {sha[:32]}...")
    
    else:
        print("[!] No data source specified")
        print("[*] Use: write <partition> <file.bin>")
        print("[*] Or:  write <partition> --fill FF")
        return 1
    
    if not write_data or len(write_data) == 0:
        print("[!] No data to write")
        return 1
    
    data_size = len(write_data)
    
    # =====================================================================
    # Safety confirmation
    # =====================================================================
    force = getattr(args, 'force', False)
    verify = getattr(args, 'verify', False)
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK)
    chunk_size = max(512, min(chunk_size, 16 * 1024 * 1024))
    
    print(f"\n{'='*50}")
    print(f"  WRITE CONFIRMATION")
    print(f"{'='*50}")
    print(f"  Partition: {target_partition['name']}")
    print(f"  Address:   0x{start_addr:08X}")
    print(f"  Size:      {format_size(data_size)} / {format_size(partition_size)}")
    print(f"  Source:    {source_type}")
    print(f"  Chunk:     {format_size(chunk_size)}")
    print(f"  Verify:    {'Yes' if verify else 'No'}")
    print(f"  Risk:      {risk_level}")
    print(f"{'='*50}")
    
    if risk_level == "HIGH":
        print(f"\n⚠️  WARNING: {risk_warning}")
        if not force:
            response = input("\n  Type 'YES' to confirm write to HIGH RISK partition: ")
            if response != 'YES':
                print("[*] Cancelled")
                return 0
    elif risk_level == "MEDIUM":
        print(f"\n🟡 Warning: {risk_warning}")
        if not force:
            response = input("\n  Continue? (y/N): ")
            if response.lower() not in ('y', 'yes'):
                print("[*] Cancelled")
                return 0
    elif not force:
        response = input("\n  Confirm write? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Cancelled")
            return 0
    
    # =====================================================================
    # Execute write
    # =====================================================================
    print(f"\n[*] Writing to {target_partition['name']}...")
    
    bytes_written = 0
    errors = 0
    start_time = time.time()
    
    try:
        with ProgressBar(data_size, prefix='Writing') as progress:
            
            while bytes_written < data_size:
                addr = start_addr + bytes_written
                chunk = min(chunk_size, data_size - bytes_written)
                chunk_data = write_data[bytes_written:bytes_written + chunk]
                
                # Build write payload
                payload = struct.pack("<II", addr, chunk) + chunk_data
                
                try:
                    if "WRITE" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "WRITE", payload, timeout=WRITE_TIMEOUT)
                    else:
                        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                        dev.write(pkt)
                        _, resp = dev.read(timeout=WRITE_TIMEOUT)
                    
                    if resp:
                        status = decode_runtime_result(resp)
                        if status.get("severity") == "SUCCESS":
                            bytes_written += chunk
                            progress.update(chunk)
                        else:
                            print(f"\n[!] Write error at 0x{addr:08X}: {status.get('name', 'Unknown')}")
                            errors += 1
                            bytes_written += chunk  # Skip failed chunk
                            progress.update(chunk)
                    else:
                        print(f"\n[!] No response at 0x{addr:08X}")
                        errors += 1
                        bytes_written += chunk
                        progress.update(chunk)
                
                except Exception as e:
                    print(f"\n[!] Error at 0x{addr:08X}: {e}")
                    errors += 1
                    bytes_written += chunk
                    progress.update(chunk)
            
            progress.close()
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted at {format_size(bytes_written)}/{format_size(data_size)}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Write failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    
    # =====================================================================
    # Results
    # =====================================================================
    elapsed = time.time() - start_time
    speed = bytes_written / max(elapsed, 0.001)
    
    print(f"\n[+] Write Complete:")
    print(f"    Written:  {format_size(bytes_written)}")
    print(f"    Time:     {format_time(elapsed)}")
    print(f"    Speed:    {format_size(speed)}/s")
    
    if errors > 0:
        print(f"    Errors:   {errors} chunks")
    
    # =====================================================================
    # Verification
    # =====================================================================
    if verify and bytes_written > 0:
        print(f"\n[*] Verifying...")
        
        verify_ok = 0
        verify_errors = 0
        
        try:
            with ProgressBar(bytes_written, prefix='Verifying') as vprogress:
                offset = 0
                
                while offset < bytes_written:
                    addr = start_addr + offset
                    chunk = min(chunk_size, bytes_written - offset)
                    
                    read_payload = struct.pack("<II", addr, chunk)
                    
                    try:
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=15)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=15)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            read_data = status.get("extra", b"")
                            expected = write_data[offset:offset + chunk]
                            
                            if read_data == expected:
                                verify_ok += chunk
                            else:
                                mismatches = sum(1 for i in range(min(len(read_data), len(expected)))
                                               if read_data[i] != expected[i])
                                verify_errors += mismatches
                                if _DEBUG and mismatches > 0:
                                    print(f"\n[!] Mismatch at 0x{addr:08X}: {mismatches} bytes")
                        else:
                            verify_errors += chunk
                    
                    except Exception as e:
                        verify_errors += chunk
                    
                    offset += chunk
                    vprogress.update(chunk)
            
            if verify_errors == 0:
                print(f"\n[+] Verification PASSED - {format_size(verify_ok)} matched")
            else:
                print(f"\n[!] Verification FAILED - {format_size(verify_errors)} mismatched bytes")
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
    
    # =====================================================================
    # Final summary
    # =====================================================================
    print(f"\n[✓] Write to {target_partition['name']} complete")
    
    if risk_level == "HIGH":
        print(f"\n⚠️  Remember: You wrote to a HIGH RISK partition!")
        print(f"    {risk_warning}")
        print(f"    Test carefully before rebooting!")
    
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] write.py - QSLCL PARTITION WRITER v2.2")
    print("[*] For writing to named partitions ONLY")
    print("[*] RAW ADDRESS WRITING IS DISABLED for safety")
    print("[*] Use 'poke' command for raw address writes")