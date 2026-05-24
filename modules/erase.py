#!/usr/bin/env python3
"""
erase.py - QSLCL ERASE Command Module v2.2 (PARTITION ONLY)
Erase entire partitions or ranges within partitions.

NO RAW ADDRESS ERASING - Too dangerous!
Only erase named partitions or partition+offset.

DANGEROUS: Erasing bootloader partitions CAN BRICK your device!
"""

import os
import sys
import struct
import time
from typing import Optional, Dict, List, Tuple

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
DEFAULT_CHUNK = 1024 * 1024      # 1MB
ERASE_TIMEOUT = 30.0
VERIFY_TIMEOUT = 15.0

# Erase patterns
ERASE_PATTERNS = {
    'zero':   (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    '00':     (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    'zeros':  (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    'ff':     (0xFF, "One fill (0xFF)", "All bits set - common flash state"),
    'ones':   (0xFF, "One fill (0xFF)", "All bits set - common flash state"),
    'erase':  (0xFF, "One fill (0xFF)", "All bits set - common flash state"),
    'aa':     (0xAA, "Pattern 0xAA", "Alternating bit pattern"),
    '55':     (0x55, "Pattern 0x55", "Inverse alternating pattern"),
    'random': (None, "Random data", "Secure erase with random data"),
    'secure': (None, "Random data", "Secure erase with random data"),
}

# CRITICAL PARTITIONS - Erasing these WILL BRICK device
CRITICAL_PARTITIONS = {
    'bootrom':   "BootROM - PERMANENT BRICK",
    'brom':      "BootROM - PERMANENT BRICK", 
    'irom':      "Internal ROM - PERMANENT BRICK",
    'pbl':       "Primary Boot Loader - HIGH BRICK RISK",
    'preloader': "Preloader - HIGH BRICK RISK",
    'sbl':       "Secondary Boot Loader - HIGH BRICK RISK",
    'sbl1':      "Secondary Boot Loader - HIGH BRICK RISK",
    'aboot':     "Android Bootloader - HIGH BRICK RISK",
    'lk':        "Little Kernel - HIGH BRICK RISK",
    'xbl':       "eXtensible Boot Loader - HIGH BRICK RISK",
    'boot':      "Boot partition - May cause boot failure",
    'bootloader': "Bootloader - HIGH BRICK RISK",
    'rpm':       "Resource Power Manager - May brick device",
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


def parse_size(size_str: str) -> int:
    """Parse size: 1M, 512K, 2G"""
    if not size_str:
        return 0
    
    size_str = str(size_str).strip().upper()
    
    # Plain number
    try:
        return int(size_str)
    except ValueError:
        pass
    
    # With suffix
    suffixes = {
        'K': 1024, 'KB': 1024,
        'M': 1024 * 1024, 'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024, 'GB': 1024 * 1024 * 1024,
    }
    
    for suffix, multiplier in suffixes.items():
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[:-len(suffix)]) * multiplier)
            except:
                pass
    
    # Hex
    if size_str.startswith('0X'):
        try:
            return int(size_str, 16)
        except:
            pass
    
    return 0


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
    """Display available partitions with safety info"""
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
        risk = "🟢 LOW"
        for critical in CRITICAL_PARTITIONS:
            if critical in name.lower():
                if "PERMANENT" in CRITICAL_PARTITIONS[critical]:
                    risk = "💀 CRITICAL"
                elif "HIGH" in CRITICAL_PARTITIONS[critical]:
                    risk = "🔴 HIGH"
                else:
                    risk = "🟡 MEDIUM"
                break
        
        print(f"    {name:<20} {offset:<12} {size:<12} {risk:<10}")


def get_partition_risk(partition_name: str) -> Tuple[str, str]:
    """Get risk level for a partition"""
    name_lower = partition_name.lower()
    
    for critical, warning in CRITICAL_PARTITIONS.items():
        if critical in name_lower:
            if "PERMANENT" in warning:
                return "CRITICAL", warning
            elif "HIGH" in warning:
                return "HIGH", warning
            return "MEDIUM", warning
    
    return "LOW", "Safe to erase"


# =============================================================================
# MAIN ERASE COMMAND
# =============================================================================

def cmd_erase(args=None) -> int:
    """
    QSLCL ERASE - Erase partition (NO RAW ADDRESSES)
    
    USAGE:
        erase <partition_name>                     - Erase entire partition (zeros)
        erase <partition_name> --size <bytes>      - Erase part of partition
        erase <partition_name>+<offset> --size <N> - Erase from offset
        erase <partition_name> --pattern <pattern> - Use specific pattern
        erase --list                                - List partitions with risks
    
    PATTERNS:
        zero, 00, zeros    - Fill with zeros (default)
        ff, ones, erase    - Fill with 0xFF
        aa, 55             - Test patterns
        random, secure     - Random data (secure erase)
    
    EXAMPLES:
        erase userdata                           - Zero entire userdata
        erase boot --size 1M                     - Zero first 1MB of boot
        erase system --pattern ff                - Fill system with 0xFF
        erase cache --pattern random             - Secure erase cache
        erase boot+0x1000 --size 64K             - Erase 64KB at offset
        erase --list                             - Show partitions with risks
    
    WARNINGS:
        - Erasing bootloader partitions CAN BRICK your device!
        - CRITICAL partitions (bootrom, pbl, etc.) are BLOCKED
        - HIGH risk partitions require --force
        - This is IRREVERSIBLE!
    
    NOTE: For raw address erasing, use 'poke' with zero pattern instead.
    """
    
    # =====================================================================
    # Parse arguments
    # =====================================================================
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: erase <partition_name> [--size SIZE] [--pattern PATTERN]")
        print("[*]        erase --list")
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
    target = getattr(args, 'target', '') or getattr(args, 'partition', '')
    
    # Check positional args
    if not target and hasattr(args, 'args') and args.args:
        target = args.args[0] if args.args else ''
    
    if not target:
        print("[!] No partition specified")
        print("[*] Usage: erase <partition_name>")
        print("[*]        erase --list  (show available partitions)")
        return 1
    
    # Get size (optional)
    size_arg = getattr(args, 'size', '')
    if not size_arg and hasattr(args, 'arg2') and args.arg2:
        # Check if arg2 looks like a size
        arg2 = str(args.arg2).upper()
        if arg2.endswith(('K', 'M', 'G', 'B')) or arg2.isdigit() or arg2.startswith('0X'):
            size_arg = args.arg2
    
    # Get pattern
    pattern_name = getattr(args, 'pattern', 'zero')
    if hasattr(args, 'erase_pattern') and args.erase_pattern:
        pattern_name = args.erase_pattern
    
    # Parse pattern
    pattern_name = str(pattern_name).lower().strip()
    if pattern_name in ERASE_PATTERNS:
        byte_val, name, desc = ERASE_PATTERNS[pattern_name]
    else:
        print(f"[!] Invalid pattern: '{pattern_name}'")
        print(f"[*] Valid patterns: zero, ff, aa, 55, random")
        return 1
    
    is_random = byte_val is None
    
    # Get options
    force = getattr(args, 'force', False)
    verify = getattr(args, 'verify', False)
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK)
    chunk_size = max(4096, min(chunk_size, 16 * 1024 * 1024))
    
    # Load partitions
    try:
        partitions = load_partitions(dev)
    except Exception as e:
        print(f"[!] Cannot load partitions: {e}")
        return 1
    
    if not partitions:
        print("[!] No partitions detected on device")
        return 1
    
    # =====================================================================
    # Parse target (partition or partition+offset)
    # =====================================================================
    start_addr = 0
    erase_size = 0
    target_partition = None
    offset_in_partition = 0
    
    target_lower = target.lower()
    
    # Check for partition+offset syntax
    if '+' in target:
        part_name, offset_str = target.split('+', 1)
        part_name = part_name.strip()
        offset_str = offset_str.strip()
        
        try:
            if offset_str.startswith('0x'):
                offset_in_partition = int(offset_str, 16)
            else:
                offset_in_partition = int(offset_str)
        except ValueError:
            print(f"[!] Invalid offset: {offset_str}")
            return 1
        
        # Find partition
        for p in partitions:
            if p.get('name', '').lower() == part_name.lower():
                target_partition = p
                break
        
        if not target_partition:
            print(f"[!] Partition not found: '{part_name}'")
            list_partitions(partitions)
            return 1
        
        if offset_in_partition >= target_partition['size']:
            print(f"[!] Offset 0x{offset_in_partition:X} exceeds partition size {format_size(target_partition['size'])}")
            return 1
        
        start_addr = target_partition['offset'] + offset_in_partition
        max_size = target_partition['size'] - offset_in_partition
        
        if size_arg:
            erase_size = parse_size(size_arg)
            if erase_size <= 0:
                print(f"[!] Invalid size: {size_arg}")
                return 1
            if erase_size > max_size:
                print(f"[!] Size {format_size(erase_size)} exceeds available {format_size(max_size)}")
                return 1
        else:
            erase_size = max_size
        
        print(f"\n[+] Partition: {target_partition['name']}+0x{offset_in_partition:X}")
    
    # Plain partition name
    else:
        for p in partitions:
            if p.get('name', '').lower() == target_lower:
                target_partition = p
                break
        
        if not target_partition:
            print(f"[!] Partition not found: '{target}'")
            list_partitions(partitions)
            return 1
        
        start_addr = target_partition['offset']
        
        if size_arg:
            erase_size = parse_size(size_arg)
            if erase_size <= 0:
                print(f"[!] Invalid size: {size_arg}")
                return 1
            if erase_size > target_partition['size']:
                print(f"[!] Size {format_size(erase_size)} exceeds partition size {format_size(target_partition['size'])}")
                return 1
        else:
            erase_size = target_partition['size']
        
        print(f"\n[+] Partition: {target_partition['name']}")
    
    # Get risk level
    risk_level, risk_warning = get_partition_risk(target_partition['name'])
    
    print(f"    Address:  0x{start_addr:08X}")
    print(f"    Size:     {format_size(erase_size)}")
    print(f"    Pattern:  {name}")
    print(f"    Risk:     {risk_level}")
    
    # =====================================================================
    # Safety checks
    # =====================================================================
    if risk_level == "CRITICAL":
        print(f"\n💀💀💀 {risk_warning} 💀💀💀")
        print("\n[!] CRITICAL PARTITION - ERASE BLOCKED")
        print("    Erasing this partition would PERMANENTLY BRICK your device!")
        print("    This operation has been BLOCKED for safety.")
        return 1
    
    if risk_level == "HIGH":
        print(f"\n🔴 WARNING: {risk_warning}")
        print("    Erasing this partition MAY BRICK your device!")
        if not force:
            print("\n    Type 'I_ACCEPT_THE_RISK' to proceed:")
            if input("    > ").strip() != "I_ACCEPT_THE_RISK":
                print("[*] Cancelled")
                return 0
    
    # =====================================================================
    # Confirmation
    # =====================================================================
    print(f"\n{'='*50}")
    print(f"  ERASE CONFIRMATION")
    print(f"{'='*50}")
    print(f"  Partition: {target_partition['name']}")
    if offset_in_partition > 0:
        print(f"  Offset:    +0x{offset_in_partition:X}")
    print(f"  Size:      {format_size(erase_size)}")
    print(f"  Pattern:   {name}")
    print(f"  Verify:    {'Yes' if verify else 'No'}")
    print(f"  Risk:      {risk_level}")
    print(f"{'='*50}")
    
    if not force:
        print(f"\n  Type 'YES' to confirm erase:")
        if input("  > ").strip().upper() != 'YES':
            print("[*] Cancelled")
            return 0
    
    # =====================================================================
    # Execute erase
    # =====================================================================
    print(f"\n[*] Erasing {target_partition['name']}...")
    
    bytes_erased = 0
    errors = 0
    start_time = time.time()
    
    # Generate erase data function
    def gen_data(size: int) -> bytes:
        if is_random:
            return os.urandom(size)
        return bytes([byte_val]) * size
    
    try:
        with ProgressBar(erase_size, prefix='Erasing') as progress:
            
            while bytes_erased < erase_size:
                addr = start_addr + bytes_erased
                chunk = min(chunk_size, erase_size - bytes_erased)
                chunk_data = gen_data(chunk)
                
                # Build payload
                payload = struct.pack("<II", addr, chunk) + chunk_data
                
                try:
                    # Try ERASE command first, fallback to WRITE
                    if "ERASE" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "ERASE", payload, timeout=ERASE_TIMEOUT)
                    elif "WRITE" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "WRITE", payload, timeout=ERASE_TIMEOUT)
                    else:
                        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                        dev.write(pkt)
                        _, resp = dev.read(timeout=ERASE_TIMEOUT)
                    
                    if resp:
                        status = decode_runtime_result(resp)
                        if status.get("severity") == "SUCCESS":
                            bytes_erased += chunk
                            progress.update(chunk)
                        else:
                            if _DEBUG:
                                print(f"\n[!] Error at 0x{addr:08X}: {status.get('name', 'Unknown')}")
                            errors += 1
                            bytes_erased += chunk
                            progress.update(chunk)
                    else:
                        if _DEBUG:
                            print(f"\n[!] No response at 0x{addr:08X}")
                        errors += 1
                        bytes_erased += chunk
                        progress.update(chunk)
                
                except Exception as e:
                    if _DEBUG:
                        print(f"\n[!] Error at 0x{addr:08X}: {e}")
                    errors += 1
                    bytes_erased += chunk
                    progress.update(chunk)
            
            progress.close()
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted at {format_size(bytes_erased)}/{format_size(erase_size)}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Erase failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    
    # =====================================================================
    # Results
    # =====================================================================
    elapsed = time.time() - start_time
    speed = bytes_erased / max(elapsed, 0.001)
    
    print(f"\n[+] Erase Complete:")
    print(f"    Erased:   {format_size(bytes_erased)}")
    print(f"    Time:     {format_time(elapsed)}")
    print(f"    Speed:    {format_size(speed)}/s")
    
    if errors > 0:
        print(f"    Errors:   {errors} chunks")
    
    # =====================================================================
    # Verification (for non-random patterns)
    # =====================================================================
    if verify and not is_random and bytes_erased > 0:
        print(f"\n[*] Verifying erase...")
        
        verify_ok = 0
        verify_errors = 0
        expected_byte = byte_val
        
        try:
            with ProgressBar(bytes_erased, prefix='Verifying') as vprogress:
                offset = 0
                
                while offset < bytes_erased:
                    addr = start_addr + offset
                    chunk = min(chunk_size, bytes_erased - offset)
                    
                    read_payload = struct.pack("<II", addr, chunk)
                    
                    try:
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=VERIFY_TIMEOUT)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            data = status.get("extra", b"")
                            
                            # Check each byte
                            mismatches = 0
                            for i, b in enumerate(data[:chunk]):
                                if b != expected_byte:
                                    mismatches += 1
                            
                            if mismatches == 0:
                                verify_ok += chunk
                            else:
                                verify_errors += mismatches
                                if _DEBUG:
                                    print(f"\n[!] Mismatch at 0x{addr:08X}: {mismatches} bytes")
                        else:
                            verify_errors += chunk
                    
                    except Exception as e:
                        verify_errors += chunk
                    
                    offset += chunk
                    vprogress.update(chunk)
            
            if verify_errors == 0:
                print(f"\n[+] Verification PASSED - {format_size(verify_ok)} verified")
            else:
                print(f"\n[!] Verification FAILED - {format_size(verify_errors)} mismatched bytes")
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
    
    elif verify and is_random:
        print(f"\n[*] Skipping verification (random pattern)")
    
    # =====================================================================
    # Final warning for high risk partitions
    # =====================================================================
    if risk_level == "HIGH" and bytes_erased > 0:
        print(f"\n⚠️  WARNING: You erased a HIGH RISK partition!")
        print(f"    {risk_warning}")
        print(f"    Test carefully before rebooting!")
    
    print(f"\n[✓] Erase of {target_partition['name']} complete")
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] erase.py - QSLCL PARTITION ERASER v2.2")
    print("[*] For erasing named partitions ONLY")
    print("[*] RAW ADDRESS ERASING IS DISABLED for safety")
[file content end]