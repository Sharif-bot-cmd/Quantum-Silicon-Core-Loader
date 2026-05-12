#!/usr/bin/env python3
"""
write.py - QSLCL WRITE Command Module v2.1 (CLEANED)
Universal memory/storage writing with safety checks, verification, and pattern support
"""

import os
import sys
import re
import struct
import time
import hashlib
from typing import Optional, Dict, List, Tuple, Any

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
DEFAULT_CHUNK = 65536           # 64KB default write chunk
MAX_RETRIES = 3                 # Max retries per chunk
MAX_CONSECUTIVE_FAILS = 8       # Abort after this many failures
MAX_BACKOFF = 10.0              # Maximum retry backoff
WRITE_TIMEOUT = 20.0            # Write operation timeout
VERIFY_TIMEOUT = 15.0           # Verification read timeout
MAX_FILE_SIZE = 1024**3         # 1GB max input file

# =============================================================================
# CRITICAL REGIONS - Writing here WILL brick devices
# =============================================================================
PROTECTED_REGIONS = [
    {"name": "BOOTROM",       "start": 0x00000000, "end": 0x00010000, "reason": "BootROM - PERMANENT BRICK", "severity": "CRITICAL"},
    {"name": "IROM",          "start": 0x00000000, "end": 0x00008000, "reason": "Internal Mask ROM", "severity": "CRITICAL"},
    {"name": "RESET_VECTOR",  "start": 0x00000000, "end": 0x00000040, "reason": "CPU Reset Vector", "severity": "CRITICAL"},
    {"name": "IVT",           "start": 0x00000000, "end": 0x00000400, "reason": "Interrupt Vector Table", "severity": "CRITICAL"},
    {"name": "PBL",           "start": 0x00000000, "end": 0x00010000, "reason": "Primary Boot Loader", "severity": "HIGH"},
    {"name": "SBL",           "start": 0x00004000, "end": 0x00040000, "reason": "Secondary Boot Loader", "severity": "HIGH"},
    {"name": "TEE",           "start": 0x10000000, "end": 0x11000000, "reason": "Trusted Execution Environment", "severity": "MEDIUM"},
]

CRITICAL_PARTITIONS = {
    'bootrom':    ("CRITICAL", "BootROM - WILL BRICK DEVICE"),
    'brom':       ("CRITICAL", "BootROM - WILL BRICK DEVICE"),
    'irom':       ("CRITICAL", "Internal ROM - WILL BRICK DEVICE"),
    'pbl':        ("CRITICAL", "Primary Boot Loader - HIGH BRICK RISK"),
    'sbl':        ("HIGH",     "Secondary Boot Loader - May brick device"),
    'sbl1':       ("HIGH",     "Secondary Boot Loader - May brick device"),
    'xbl':        ("HIGH",     "eXtensible Boot Loader - May brick device"),
    'aboot':      ("HIGH",     "Android Bootloader - May brick device"),
    'lk':         ("HIGH",     "Little Kernel - May brick device"),
    'preloader':  ("HIGH",     "Preloader - May brick device"),
    'boot':       ("HIGH",     "Boot partition - May cause boot failure"),
    'recovery':   ("MEDIUM",   "Recovery partition - Recoverable"),
    'bootloader': ("HIGH",     "Bootloader - May brick device"),
    'tz':         ("MEDIUM",   "TrustZone - May affect security"),
    'rpm':        ("HIGH",     "Resource Power Manager - May cause boot failure"),
    'hyp':        ("MEDIUM",   "Hypervisor - May cause boot failure"),
    'devcfg':     ("MEDIUM",   "Device Configuration"),
    'sec':        ("MEDIUM",   "Security partition"),
    'keymaster':  ("MEDIUM",   "Keymaster - May affect security"),
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_size(size_str: str) -> int:
    """Parse size: 1M, 512K, 2G, 0x1000, 4096"""
    if not size_str:
        return 0
    size_str = str(size_str).strip().upper()
    
    try:
        if size_str.startswith('0X'):
            return int(size_str, 16)
        return int(size_str)
    except ValueError:
        pass
    
    for suffix, mul in [('GB', 1024**3), ('G', 1024**3), ('MB', 1024**2), 
                         ('M', 1024**2), ('KB', 1024), ('K', 1024), ('B', 1)]:
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[:-len(suffix)]) * mul)
            except ValueError:
                continue
    
    try:
        return int(size_str)
    except ValueError:
        return 0


def format_size(size_bytes: int) -> str:
    """Human-readable size"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.1f} MB"
    return f"{size_bytes/(1024**3):.2f} GB"


def parse_address(addr_str: str) -> int:
    """Parse address: 0x1000, $1000, 4096, 1000h, segment:offset"""
    if isinstance(addr_str, int):
        return addr_str
    
    addr_str = str(addr_str).strip()
    
    if not addr_str:
        raise ValueError("Empty address")
    
    # segment:offset (real mode)
    if ':' in addr_str and not addr_str.lower().startswith('0x'):
        parts = addr_str.split(':')
        if len(parts) == 2:
            return (int(parts[0], 16) << 4) + int(parts[1], 16)
    
    addr_lower = addr_str.lower()
    if addr_lower.startswith('0x'):
        return int(addr_str[2:], 16)
    elif addr_lower.startswith('$'):
        return int(addr_str[1:], 16)
    elif addr_lower.endswith('h'):
        return int(addr_str[:-1], 16)
    
    try:
        return int(addr_str, 16)
    except ValueError:
        return int(addr_str, 10)


def parse_pattern(pattern_str: str) -> bytes:
    """Parse pattern: AABB, FF:4096, DEADBEEF*100"""
    if not pattern_str:
        return b""
    
    pattern_str = pattern_str.strip().upper()
    
    # Fill: FF:4096
    if ':' in pattern_str and '*' not in pattern_str:
        try:
            val_str, size_str = pattern_str.split(':', 1)
            val = bytes.fromhex(val_str)
            size = int(size_str)
            if size > 100 * 1024 * 1024:
                raise ValueError("Pattern too large (max 100MB)")
            return bytes([val[0]] * size)
        except Exception as e:
            print(f"[!] Invalid fill pattern: {e}")
            return b""
    
    # Repeat: DEADBEEF*100
    if '*' in pattern_str:
        try:
            data_str, count_str = pattern_str.split('*', 1)
            data = bytes.fromhex(data_str)
            count = int(count_str)
            if len(data) * count > 100 * 1024 * 1024:
                raise ValueError("Pattern too large (max 100MB)")
            return data * count
        except Exception as e:
            print(f"[!] Invalid repeat pattern: {e}")
            return b""
    
    # Plain hex
    try:
        return bytes.fromhex(pattern_str.replace(' ', ''))
    except ValueError:
        print(f"[!] Cannot parse pattern: {pattern_str}")
        return b""


class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
        self.start_time = time.time()
    
    def __enter__(self):
        self.update(0)
        return self
    
    def __exit__(self, *args):
        print()
    
    def update(self, progress):
        self.current += progress
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '─' * (self.length - filled)
        
        elapsed = max(time.time() - self.start_time, 0.001)
        rate = self.current / elapsed
        eta = (self.total - self.current) / max(rate, 1)
        
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {format_size(rate)}/s ETA:{eta:.0f}s {self.suffix}', 
              end='', flush=True)


# =============================================================================
# TARGET RESOLUTION
# =============================================================================
def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve write target to address and size"""
    # Try hex address
    try:
        if target.lower().startswith('0x'):
            addr = int(target, 16)
            return {'address': addr, 'size': 0, 'partition': None}
    except ValueError:
        pass
    
    try:
        addr = int(target)
        if addr > 0:
            return {'address': addr, 'size': 0, 'partition': None}
    except ValueError:
        pass
    
    # Try partition name
    for part in partitions:
        if part.get('name', '').lower() == target.lower():
            return {'address': part['offset'], 'size': part['size'], 'partition': part}
    
    # Try partition+offset
    if '+' in target:
        name, offset_str = target.split('+', 1)
        try:
            offset = int(offset_str.strip(), 16 if offset_str.strip().lower().startswith('0x') else 10)
        except ValueError:
            offset = 0
        
        for part in partitions:
            if part.get('name', '').lower() == name.strip().lower():
                return {
                    'address': part['offset'] + offset,
                    'size': part['size'] - offset,
                    'partition': part,
                    'offset_in_partition': offset
                }
    
    return None


# =============================================================================
# SAFETY CHECKS
# =============================================================================
def check_safety(address: int, size: int, partition_name: str = None) -> Tuple[bool, str, Optional[dict]]:
    """Check if write target is in a protected region"""
    
    # Check fixed regions
    for region in PROTECTED_REGIONS:
        if address < region['end'] and address + size > region['start']:
            return False, f"{region['severity']}: {region['name']} - {region['reason']}", region
    
    # Check partition
    if partition_name:
        part_lower = partition_name.lower().strip()
        if part_lower in CRITICAL_PARTITIONS:
            severity, reason = CRITICAL_PARTITIONS[part_lower]
            if severity == "CRITICAL":
                return False, f"CRITICAL: {partition_name} - {reason}", {"partition": partition_name, "severity": severity}
            elif severity == "HIGH":
                return True, f"HIGH RISK: {partition_name} - {reason}", {"partition": partition_name, "severity": severity}
            else:
                return True, f"MEDIUM RISK: {partition_name} - {reason}", {"partition": partition_name, "severity": severity}
    
    return True, "Safe", None


def show_warning(protection: dict, force: bool = False):
    """Display formatted protection warning"""
    if not protection:
        return
    
    severity = protection.get('severity', 'UNKNOWN')
    name = protection.get('name', protection.get('partition', 'Unknown'))
    reason = protection.get('reason', '')
    
    if severity == "CRITICAL":
        print("\n" + "=" * 60)
        print("  💀💀💀  CRITICAL PROTECTION  💀💀💀")
        print("=" * 60)
        print(f"  Region:  {name}")
        print(f"  Reason:  {reason}")
        print(f"  Writing WILL permanently brick your device!")
        print("=" * 60 + "\n")
    elif severity == "HIGH":
        print(f"\n  ⚠️  HIGH RISK: {name} - {reason}\n")
    else:
        print(f"\n  [!] RISK: {name} - {reason}\n")


# =============================================================================
# DATA SOURCE PROCESSING
# =============================================================================
def process_data(data_source: str, target_size: int = 0) -> Tuple[bytes, str]:
    """Process data source into bytes"""
    
    if not data_source:
        return b"", "empty"
    
    # File source
    if os.path.exists(data_source) and os.path.isfile(data_source):
        file_size = os.path.getsize(data_source)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {format_size(file_size)} exceeds {format_size(MAX_FILE_SIZE)}")
        if file_size == 0:
            raise ValueError("File is empty")
        
        with open(data_source, 'rb') as f:
            data = f.read()
        
        print(f"[+] File: {data_source} ({format_size(len(data))})")
        print(f"    SHA256: {hashlib.sha256(data).hexdigest()[:32]}...")
        return data, "file"
    
    # Special fills
    data_lower = data_source.lower().strip()
    
    if data_lower in ('zero', 'zeros', '00', 'null'):
        if target_size <= 0:
            raise ValueError("Need target size for zero fill - specify partition or address")
        return b'\x00' * target_size, "zero-fill"
    
    if data_lower in ('ff', 'ones', 'erase', 'fill'):
        if target_size <= 0:
            raise ValueError("Need target size for 0xFF fill - specify partition or address")
        return b'\xFF' * target_size, "ff-fill"
    
    if data_lower == 'random':
        if target_size <= 0:
            raise ValueError("Need target size for random fill - specify partition or address")
        return os.urandom(target_size), "random-fill"
    
    # Pattern: *, :
    if '*' in data_source or ':' in data_source:
        data = parse_pattern(data_source)
        if not data:
            raise ValueError(f"Failed to parse pattern: {data_source}")
        return data, "pattern"
    
    # Hex string
    clean = data_source.replace(' ', '').replace('-', '')
    if re.match(r'^[0-9A-Fa-f]+$', clean) and len(clean) >= 2:
        try:
            return bytes.fromhex(clean), "hex"
        except ValueError:
            pass
    
    # Literal string
    return data_source.encode('utf-8'), "string"


# =============================================================================
# MAIN WRITE COMMAND
# =============================================================================
def cmd_write(args=None) -> int:
    """
    QSLCL WRITE - Universal memory/storage writer
    
    Examples:
        write boot boot.img           - Write file to boot partition
        write 0x10000000 data.bin     - Write file to address
        write system FF:1048576       - Fill system partition with 0xFF
        write 0x200000 DEADBEEF*100   - Write repeating pattern
        write boot --force            - Skip safety prompts
        write boot img --no-verify    - Skip verification
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: write <target> <data> [options]")
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
    target = getattr(args, 'target', None)
    data_source = getattr(args, 'data', None)
    
    if not target:
        print("[!] No target specified")
        print("[*] Examples: write boot image.img, write 0x10000000 data.bin")
        return 1
    
    if not data_source:
        print("[!] No data source specified")
        print("[*] Sources: file.bin, AABBCCDD, FF:4096, DEADBEEF*100, zero, ff, random")
        return 1
    
    # Resolve partitions
    partitions = []
    try:
        partitions = load_partitions(dev)
    except:
        pass
    
    # Resolve target
    target_info = resolve_target(target, partitions, dev)
    if not target_info:
        print(f"[!] Cannot resolve target: '{target}'")
        if partitions:
            print(f"\n[*] Available partitions:")
            for p in sorted(partitions, key=lambda x: x['offset']):
                print(f"    {p['name']:<16} 0x{p['offset']:08X}  {format_size(p['size'])}")
        return 1
    
    address = target_info['address']
    max_size = target_info.get('size', 0)
    part_info = target_info.get('partition')
    part_name = part_info['name'] if part_info else None
    
    print(f"\n[+] Target: 0x{address:08X}", end='')
    if part_info:
        print(f" ({part_info['name']}, {format_size(part_info['size'])})")
        if 'offset_in_partition' in target_info:
            print(f"    Offset in partition: +0x{target_info['offset_in_partition']:X}")
    else:
        print()
    
    # Process data
    try:
        write_data, source_type = process_data(data_source, max_size)
    except ValueError as e:
        print(f"[!] Data error: {e}")
        return 1
    
    if len(write_data) == 0:
        print("[!] No data to write")
        return 1
    
    data_size = len(write_data)
    print(f"[+] Data: {format_size(data_size)} ({source_type})")
    
    # Size check
    if max_size > 0 and data_size > max_size:
        print(f"[!] Data ({format_size(data_size)}) exceeds target ({format_size(max_size)})")
        if getattr(args, 'force', False):
            print("[!] Force mode: truncating")
            write_data = write_data[:max_size]
            data_size = max_size
        else:
            print("[*] Use --force to truncate")
            return 1
    
    # =========================================================================
    # SAFETY CHECKS
    # =========================================================================
    force = getattr(args, 'force', False)
    skip_protection = getattr(args, 'no_protection_checks', False)
    
    if not skip_protection:
        safe, message, protection = check_safety(address, data_size, part_name)
        
        if protection:
            show_warning(protection, force)
        
        if not safe:
            print(f"\n[!] WRITE BLOCKED: {message}")
            print("\n  💀 This would PERMANENTLY BRICK your device!")
            print("  Write has been BLOCKED to prevent irreversible damage.")
            return 1
        
        if "HIGH RISK" in message and not force:
            response = input(f"\n  [!] {message}\n  Type 'yes' to confirm: ")
            if response.lower() != 'yes':
                print("[*] Cancelled")
                return 0
    
    # Critical partition check
    if part_name and part_name.lower() in CRITICAL_PARTITIONS:
        severity, reason = CRITICAL_PARTITIONS[part_name.lower()]
        if severity in ("CRITICAL", "HIGH") and not force:
            print(f"\n[!!!] {severity} PARTITION: {part_name}")
            print(f"    {reason}")
            response = input("    Type 'YES' to confirm write: ")
            if response != 'YES':
                print("[*] Cancelled")
                return 0
    
    # =========================================================================
    # CONFIRMATION
    # =========================================================================
    chunk_size = max(512, min(getattr(args, 'chunk_size', DEFAULT_CHUNK), 16*1024*1024))
    no_verify = getattr(args, 'no_verify', False)
    
    print(f"\n{'='*50}")
    print(f"  WRITE CONFIRMATION")
    print(f"{'='*50}")
    print(f"  Target:   0x{address:08X}" + (f" ({part_name})" if part_name else ""))
    print(f"  Size:     {format_size(data_size)}")
    print(f"  Source:   {source_type}")
    print(f"  Chunk:    {format_size(chunk_size)}")
    print(f"  Verify:   {'Yes' if not no_verify else 'No'}")
    print(f"{'='*50}")
    
    if not force:
        response = input("\n  Confirm write? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Cancelled")
            return 0
    
    # =========================================================================
    # EXECUTE WRITE
    # =========================================================================
    print(f"\n[*] Writing {format_size(data_size)} to 0x{address:08X}...")
    
    bytes_written = 0
    consecutive_fails = 0
    failed_chunks = []
    
    try:
        with ProgressBar(data_size, prefix='Writing', suffix='Complete') as progress:
            
            while bytes_written < data_size:
                addr = address + bytes_written
                chunk = min(chunk_size, data_size - bytes_written)
                
                if chunk <= 0:
                    break
                
                chunk_data = write_data[bytes_written:bytes_written + chunk]
                
                try:
                    # Build write payload
                    payload = struct.pack("<II", addr, chunk) + chunk_data
                    
                    # Dispatch
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
                            consecutive_fails = 0
                        else:
                            print(f"\n[!] Error at 0x{addr:08X}: {status.get('name', 'Unknown')}")
                            failed_chunks.append((addr, chunk))
                            consecutive_fails += 1
                    else:
                        print(f"\n[!] No response at 0x{addr:08X}")
                        failed_chunks.append((addr, chunk))
                        consecutive_fails += 1
                
                except KeyboardInterrupt:
                    print(f"\n[!] Interrupted at {format_size(bytes_written)}")
                    return 1
                
                except Exception as e:
                    print(f"\n[!] Exception at 0x{addr:08X}: {e}")
                    failed_chunks.append((addr, chunk))
                    consecutive_fails += 1
                
                if consecutive_fails >= MAX_CONSECUTIVE_FAILS:
                    print(f"\n[!] Too many failures, aborting")
                    break
                
                if consecutive_fails > 0:
                    time.sleep(min(0.1 * (2 ** consecutive_fails), MAX_BACKOFF))
    
    except Exception as e:
        print(f"\n[!] Write failed: {e}")
        return 1
    
    # Retry failed chunks
    if failed_chunks:
        print(f"\n[*] Retrying {len(failed_chunks)} failed chunks...")
        for addr, chunk in failed_chunks[:]:
            offset = addr - address
            if 0 <= offset < data_size:
                for attempt in range(MAX_RETRIES):
                    try:
                        chunk_data = write_data[offset:offset + chunk]
                        payload = struct.pack("<II", addr, chunk) + chunk_data
                        
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
                                failed_chunks.remove((addr, chunk))
                                break
                        
                        time.sleep(0.5 * (2 ** attempt))
                    except:
                        pass
    
    # =========================================================================
    # VERIFICATION
    # =========================================================================
    verification_passed = True
    
    if not no_verify and bytes_written > 0:
        print(f"\n[*] Verifying {format_size(bytes_written)}...")
        
        try:
            with ProgressBar(bytes_written, prefix='Verifying', suffix='Complete') as vprogress:
                offset = 0
                remaining = bytes_written
                
                while remaining > 0:
                    addr = address + offset
                    chunk = min(chunk_size, remaining)
                    
                    read_payload = struct.pack("<II", addr, chunk)
                    
                    if "READ" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
                    else:
                        pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                        dev.write(pkt)
                        _, resp = dev.read(timeout=VERIFY_TIMEOUT)
                    
                    if resp:
                        status = decode_runtime_result(resp)
                        read_data = status.get("extra", b"")
                        expected = write_data[offset:offset + chunk]
                        
                        if read_data == expected:
                            vprogress.update(chunk)
                        else:
                            # Find mismatch location
                            for i in range(min(len(read_data), len(expected))):
                                if read_data[i] != expected[i]:
                                    print(f"\n[!] MISMATCH at 0x{addr + i:08X}")
                                    print(f"    Expected: {expected[max(0,i-4):i+12].hex()}")
                                    print(f"    Got:      {read_data[max(0,i-4):i+12].hex()}")
                                    break
                            verification_passed = False
                            break
                    else:
                        print(f"\n[!] Verify failed at 0x{addr:08X}")
                        verification_passed = False
                        break
                    
                    offset += chunk
                    remaining -= chunk
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
            verification_passed = False
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print(f"\n{'='*50}")
    print(f"  WRITE COMPLETE")
    print(f"{'='*50}")
    print(f"  Target:   0x{address:08X}" + (f" ({part_name})" if part_name else ""))
    print(f"  Written:  {format_size(bytes_written)}/{format_size(data_size)}")
    print(f"  Success:  {bytes_written*100/max(data_size,1):.1f}%")
    print(f"  Verified: {'✓ PASS' if verification_passed else '✗ FAIL' if not no_verify else 'SKIPPED'}")
    
    if failed_chunks:
        print(f"  Failed:   {len(failed_chunks)} chunks")
        for addr, sz in failed_chunks[:5]:
            print(f"    - 0x{addr:08X} ({format_size(sz)})")
    
    print(f"{'='*50}")
    
    return 0 if bytes_written > 0 else 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] write.py - QSLCL WRITE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py write <target> <data> [options]")