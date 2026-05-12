#!/usr/bin/env python3
"""
erase.py - QSLCL ERASE Command Module v2.1 (CLEANED)
Universal memory/partition erasing with multiple patterns and verification
"""

import os
import sys
import struct
import time
from typing import Optional, Dict, List, Tuple

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
DEFAULT_CHUNK = 1024 * 1024      # 1MB default erase chunk
MAX_RETRIES = 3                  # Max retries per chunk
MAX_CONSECUTIVE_FAILS = 8        # Abort after this many failures
MAX_BACKOFF = 10.0               # Maximum retry backoff
ERASE_TIMEOUT = 30.0             # Erase operation timeout
VERIFY_TIMEOUT = 15.0            # Verification read timeout

# Erase pattern definitions
ERASE_PATTERNS = {
    'zero':   (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    '00':     (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    'zeros':  (0x00, "Zero fill (0x00)", "Standard erase - all bits cleared"),
    'ff':     (0xFF, "One fill (0xFF)", "All bits set - common flash erase state"),
    'ones':   (0xFF, "One fill (0xFF)", "All bits set - common flash erase state"),
    'erase':  (0xFF, "One fill (0xFF)", "All bits set - common flash erase state"),
    'aa':     (0xAA, "Checker 0xAA (10101010)", "Alternating bit pattern"),
    '55':     (0x55, "Checker 0x55 (01010101)", "Inverse alternating pattern"),
    'f0':     (0xF0, "Stripes 0xF0 (11110000)", "Nibble stripe pattern"),
    '0f':     (0x0F, "Stripes 0x0F (00001111)", "Inverse nibble stripe"),
    '5a':     (0x5A, "Pattern 0x5A", "Common memory test pattern"),
    'a5':     (0xA5, "Pattern 0xA5", "Common memory test pattern"),
    'random': (None, "Random data", "Cryptographically secure random erase"),
    'rand':   (None, "Random data", "Cryptographically secure random erase"),
    'secure': (None, "Random data", "Cryptographically secure random erase"),
}

CRITICAL_PARTITIONS = [
    'bootrom', 'brom', 'irom', 'pbl', 'sbl', 'sbl1', 'sbl2', 'sbl3',
    'xbl', 'aboot', 'lk', 'llb', 'preloader', 'bootloader',
    'tz', 'tee1', 'tee2', 'rpm', 'hyp', 'boot', 'recovery',
]


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
    """Parse address: 0x1000, $1000, 4096, 1000h"""
    if isinstance(addr_str, int):
        return addr_str
    
    addr_str = str(addr_str).strip()
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
def resolve_target(target: str, partitions: list, size_arg: str = None) -> Tuple[int, int, Optional[dict]]:
    """Resolve erase target to (address, size, partition_info)"""
    target_str = str(target).strip()
    
    # Partition+offset: "boot+0x1000"
    if '+' in target_str:
        part_name, offset_str = target_str.split('+', 1)
        part_name = part_name.strip().lower()
        offset = parse_address(offset_str.strip())
        
        for p in partitions:
            if p.get('name', '').lower() == part_name:
                addr = p['offset'] + offset
                max_sz = p['size'] - offset
                if max_sz <= 0:
                    raise ValueError(f"Offset 0x{offset:X} exceeds partition '{p['name']}' size")
                sz = parse_size(size_arg) if size_arg else max_sz
                if sz > max_sz:
                    raise ValueError(f"Size {format_size(sz)} exceeds available {format_size(max_sz)}")
                return addr, sz, p
        
        raise ValueError(f"Partition not found: '{part_name}'")
    
    # Partition name
    target_lower = target_str.lower()
    for p in partitions:
        if p.get('name', '').lower() == target_lower:
            sz = parse_size(size_arg) if size_arg else p['size']
            if sz > p['size']:
                raise ValueError(f"Size {format_size(sz)} exceeds partition size {format_size(p['size'])}")
            return p['offset'], sz, p
    
    # Raw address
    try:
        addr = parse_address(target_str)
    except ValueError:
        raise ValueError(f"Cannot resolve: '{target_str}'. Use partition name, 0xADDR, or partition+0xOFFSET")
    
    if not size_arg:
        raise ValueError("Size required for raw address. Use --size <bytes>")
    
    return addr, parse_size(size_arg), None


# =============================================================================
# MAIN ERASE COMMAND
# =============================================================================
def cmd_erase(args=None) -> int:
    """
    QSLCL ERASE - Universal memory/partition eraser
    
    Examples:
        erase boot                          - Erase entire boot partition (zeros)
        erase system --size 1M              - Erase 1MB of system partition
        erase 0x10000000 --size 512K        - Erase 512KB at address
        erase userdata --pattern ff         - Erase with 0xFF fill
        erase cache --pattern random        - Secure erase with random data
        erase boot+0x1000 --size 64K        - Erase 64KB from offset in partition
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: erase <target> [--size SIZE] [--pattern PATTERN] [options]")
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
    if not target:
        # Try alternative attribute names
        for attr in ['arg1', 'erase_target']:
            if hasattr(args, attr) and getattr(args, attr):
                target = getattr(args, attr)
                break
    
    if not target:
        print("[!] No target specified")
        print("[*] Examples: erase boot, erase 0x10000000 --size 1M")
        return 1
    
    # Get size
    size_arg = getattr(args, 'size', None)
    if not size_arg and hasattr(args, 'arg2') and args.arg2:
        size_arg = args.arg2
    
    # Get pattern
    pattern_name = getattr(args, 'pattern', '00')
    if hasattr(args, 'erase_pattern') and args.erase_pattern:
        pattern_name = args.erase_pattern
    
    # Parse pattern
    pattern_name = str(pattern_name).lower().strip()
    if pattern_name in ERASE_PATTERNS:
        byte_val, name, desc = ERASE_PATTERNS[pattern_name]
    else:
        # Try custom hex byte
        try:
            clean = pattern_name.replace('0x', '').replace('0X', '')
            byte_val = int(clean, 16) & 0xFF
            name = f"Custom (0x{byte_val:02X})"
            desc = "User-specified erase pattern"
        except ValueError:
            print(f"[!] Invalid pattern: '{pattern_name}'")
            print(f"[*] Valid patterns: {', '.join(sorted(ERASE_PATTERNS.keys()))}")
            print(f"[*] Or specify hex byte: AB, 0xCD")
            return 1
    
    is_random = byte_val is None
    print(f"[*] Pattern: {name}")
    print(f"    {desc}")
    
    # Get other options
    chunk_size = max(4096, min(getattr(args, 'chunk_size', DEFAULT_CHUNK), 64*1024*1024))
    force = getattr(args, 'force', False)
    no_verify = getattr(args, 'no_verify', False)
    
    # Resolve partitions
    partitions = []
    try:
        partitions = load_partitions(dev)
    except:
        pass
    
    # Resolve target
    try:
        address, erase_size, part_info = resolve_target(target, partitions, size_arg)
    except ValueError as e:
        print(f"[!] {e}")
        if partitions:
            print(f"\n[*] Available partitions:")
            for p in sorted(partitions, key=lambda x: x['offset']):
                print(f"    {p['name']:<16} 0x{p['offset']:08X}  {format_size(p['size'])}")
        return 1
    
    if erase_size <= 0:
        print(f"[!] Invalid erase size: {erase_size}")
        return 1
    
    # Display target info
    print(f"\n[+] Target: 0x{address:08X}", end='')
    if part_info:
        print(f" ({part_info['name']}, {format_size(part_info['size'])})")
    else:
        print()
    print(f"[+] Size: {format_size(erase_size)} (0x{erase_size:X})")
    
    # =========================================================================
    # SAFETY CHECKS
    # =========================================================================
    if part_info:
        part_name = part_info.get('name', '').lower()
        is_critical = any(crit in part_name for crit in CRITICAL_PARTITIONS)
        
        if is_critical:
            print(f"\n{'='*60}")
            print(f"  ⚠️  WARNING: CRITICAL PARTITION")
            print(f"{'='*60}")
            print(f"  Partition: {part_info['name']}")
            print(f"  Address:   0x{part_info['offset']:08X}")
            print(f"  Size:      {format_size(part_info['size'])}")
            print(f"")
            print(f"  🔴 ERASING MAY BRICK YOUR DEVICE!")
            print(f"  🔴 This operation is IRREVERSIBLE!")
            print(f"  🔴 Only proceed with a backup!")
            print(f"{'='*60}")
            
            if not force:
                print(f"\n  Type 'I_ACCEPT_THE_RISK' to proceed:")
                if input("  > ") != "I_ACCEPT_THE_RISK":
                    print("[*] Cancelled")
                    return 0
    
    # =========================================================================
    # CONFIRMATION
    # =========================================================================
    print(f"\n{'='*50}")
    print(f"  ERASE CONFIGURATION")
    print(f"{'='*50}")
    print(f"  Target:   0x{address:08X}" + (f" ({part_info['name']})" if part_info else ""))
    print(f"  Size:     {format_size(erase_size)}")
    print(f"  Pattern:  {name}")
    print(f"  Chunk:    {format_size(chunk_size)}")
    print(f"  Verify:   {'Yes' if not no_verify else 'No'}")
    print(f"{'='*50}")
    
    if not force:
        print(f"\n  Type 'YES' to confirm:")
        if input("  > ").upper() != 'YES':
            print("[*] Cancelled")
            return 0
    
    # =========================================================================
    # EXECUTE ERASE
    # =========================================================================
    print(f"\n[*] Erasing {format_size(erase_size)} at 0x{address:08X}...")
    
    bytes_erased = 0
    consecutive_fails = 0
    failed_chunks = []
    start_time = time.time()
    
    # Generate erase data helper
    def gen_data(size: int) -> bytes:
        if is_random:
            return os.urandom(size)
        return bytes([byte_val]) * size
    
    try:
        with ProgressBar(erase_size, prefix='Erasing', suffix='Complete') as progress:
            
            while bytes_erased < erase_size:
                addr = address + bytes_erased
                chunk = min(chunk_size, erase_size - bytes_erased)
                
                if chunk <= 0:
                    break
                
                chunk_data = gen_data(chunk)
                
                try:
                    # Build payload
                    payload = struct.pack("<II", addr, chunk) + chunk_data
                    
                    # Try ERASE first, fallback to WRITE
                    if "ERASE" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "ERASE", payload, timeout=ERASE_TIMEOUT)
                    else:
                        # Use WRITE as fallback
                        if "WRITE" in QSLCLCMD_DB:
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
                            consecutive_fails = 0
                        else:
                            if _DEBUG:
                                print(f"\n[!] Error at 0x{addr:08X}: {status.get('name', 'Unknown')}")
                            failed_chunks.append({'address': addr, 'size': chunk})
                            consecutive_fails += 1
                    else:
                        if _DEBUG:
                            print(f"\n[!] No response at 0x{addr:08X}")
                        failed_chunks.append({'address': addr, 'size': chunk})
                        consecutive_fails += 1
                
                except KeyboardInterrupt:
                    print(f"\n[!] Interrupted at {format_size(bytes_erased)}")
                    break
                
                except Exception as e:
                    if _DEBUG:
                        print(f"\n[!] Exception at 0x{addr:08X}: {e}")
                    failed_chunks.append({'address': addr, 'size': chunk})
                    consecutive_fails += 1
                
                if consecutive_fails >= MAX_CONSECUTIVE_FAILS:
                    print(f"\n[!] Too many failures, aborting")
                    break
                
                if consecutive_fails > 0:
                    time.sleep(min(0.1 * (2 ** consecutive_fails), MAX_BACKOFF))
    
    except Exception as e:
        print(f"\n[!] Erase failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
    
    elapsed = time.time() - start_time
    
    # Retry failed chunks
    if failed_chunks:
        print(f"\n[*] Retrying {len(failed_chunks)} failed chunks...")
        for chunk_info in failed_chunks[:]:
            addr = chunk_info['address']
            sz = chunk_info['size']
            offset = addr - address
            
            if 0 <= offset < erase_size:
                for attempt in range(MAX_RETRIES):
                    try:
                        chunk_data = gen_data(sz)
                        payload = struct.pack("<II", addr, sz) + chunk_data
                        
                        if "WRITE" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "WRITE", payload, timeout=ERASE_TIMEOUT)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=ERASE_TIMEOUT)
                        
                        if resp and decode_runtime_result(resp).get("severity") == "SUCCESS":
                            bytes_erased += sz
                            failed_chunks.remove(chunk_info)
                            break
                        
                        time.sleep(0.5 * (2 ** attempt))
                    except:
                        pass
    
    # =========================================================================
    # VERIFICATION
    # =========================================================================
    verify_errors = []
    
    if not no_verify and bytes_erased > 0 and not is_random:
        print(f"\n[*] Verifying erase...")
        
        try:
            with ProgressBar(bytes_erased, prefix='Verifying', suffix='Complete') as vprogress:
                expected = bytes([byte_val])
                vaddr = address
                remaining = bytes_erased
                
                while remaining > 0:
                    vchunk = min(chunk_size, remaining)
                    
                    read_payload = struct.pack("<II", vaddr, vchunk)
                    
                    if "READ" in QSLCLCMD_DB:
                        resp = qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
                    else:
                        pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
                        dev.write(pkt)
                        _, resp = dev.read(timeout=VERIFY_TIMEOUT)
                    
                    if resp:
                        status = decode_runtime_result(resp)
                        data = status.get("extra", b"")
                        
                        # Count mismatches
                        mismatches = sum(1 for i, b in enumerate(data) 
                                       if i < vchunk and bytes([b]) != expected)
                        
                        if mismatches > 0:
                            mismatch_pct = mismatches * 100 / vchunk
                            if mismatch_pct > 5 and not force:
                                print(f"\n[!] High error rate at 0x{vaddr:08X}: {mismatch_pct:.1f}%")
                                verify_errors.append({'address': vaddr, 'mismatches': mismatches})
                                break
                            verify_errors.append({'address': vaddr, 'mismatches': mismatches})
                    
                    vprogress.update(vchunk)
                    vaddr += vchunk
                    remaining -= vchunk
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
            verify_errors.append({'error': str(e)})
    
    elif is_random and not no_verify:
        print(f"\n[*] Skipping verification (random pattern)")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    rate = bytes_erased / max(elapsed, 0.001)
    
    print(f"\n{'='*50}")
    print(f"  ERASE {'COMPLETE' if bytes_erased >= erase_size else 'INCOMPLETE'}")
    print(f"{'='*50}")
    print(f"  Target:   0x{address:08X}" + (f" ({part_info['name']})" if part_info else ""))
    print(f"  Erased:   {format_size(bytes_erased)}/{format_size(erase_size)}")
    print(f"  Success:  {bytes_erased*100/max(erase_size,1):.1f}%")
    print(f"  Pattern:  {name}")
    print(f"  Time:     {elapsed:.1f}s ({format_size(int(rate))}/s)")
    
    if verify_errors:
        total_mismatches = sum(e.get('mismatches', 0) for e in verify_errors)
        print(f"  Verify:   ✗ {len(verify_errors)} chunks with {total_mismatches} mismatches")
    elif not no_verify:
        print(f"  Verify:   ✓ PASS")
    
    if failed_chunks:
        print(f"  Failed:   {len(failed_chunks)} chunks")
    
    print(f"{'='*50}")
    
    return 0 if bytes_erased >= erase_size and not verify_errors else 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] erase.py - QSLCL ERASE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py erase <target> [options]")