#!/usr/bin/env python3
"""
erase.py - QSLCL ERASE Command Module v2.0 (FIXED)
Fixed: Import handling, target resolution, pattern management, 
       error recovery, verification, data generation
"""

import os
import sys
import re
import struct
import time
import hashlib
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union

# =============================================================================
# FIXED: Proper relative imports with comprehensive fallbacks
# =============================================================================
_use_qslcl = False
_scan_all = None
_load_partitions = None
_resolve_target = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_ProgressBar = None
_QSLCLCMD_DB = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        load_partitions as _qslcl_load_partitions,
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
# FIXED: Standalone mode handling
# =============================================================================
_STANDALONE_WARNED = False

def _warn_standalone():
    """Warn about standalone mode once"""
    global _STANDALONE_WARNED
    if not _STANDALONE_WARNED:
        print("[!] Running in standalone mode (limited functionality)")
        print("[*] For full features, ensure qslcl.py is in the Python path")
        _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
DEFAULT_ERASE_CHUNK_SIZE = 1024 * 1024  # 1MB default for erase
MAX_RETRIES = 3                          # Maximum retries per chunk
MAX_CONSECUTIVE_FAILURES = 8             # Max consecutive failures before abort
INITIAL_BACKOFF = 0.1                    # Initial backoff seconds
MAX_BACKOFF = 10.0                       # Maximum backoff cap
ERASE_TIMEOUT = 30.0                     # Erase/write timeout
VERIFY_TIMEOUT = 15.0                    # Verification read timeout

# Critical partitions that should trigger extra warnings
CRITICAL_PARTITIONS = [
    'bootrom', 'brom', 'irom',
    'pbl', 'sbl', 'sbl1', 'sbl2', 'sbl3',
    'xbl', 'xbl_config', 'aboot', 'lk', 'llb',
    'preloader', 'bootloader',
    'tz', 'tee1', 'tee2', 'rpm', 'hyp',
    'devcfg', 'devinfo', 'sec', 'keymaster',
    'boot', 'recovery',
]


# =============================================================================
# FIXED: Local Progress Bar for standalone mode
# =============================================================================
class LocalProgressBar:
    """Minimal progress bar for standalone operation."""
    
    def __init__(self, total: int, prefix: str = '', suffix: str = '',
                 decimals: int = 1, length: int = 50, fill: str = '█'):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.current = 0
        self._started = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        if self._started:
            print()
    
    def update(self, progress: int):
        """Update progress bar"""
        if not self._started:
            self._started = True
        self.current += progress
        percent = min(100.0, 100.0 * self.current / self.total)
        filled = int(self.length * self.current // self.total)
        bar = self.fill * filled + '-' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {percent:.{self.decimals}f}% {self.suffix}',
              end='', flush=True)


# =============================================================================
# FIXED: Address parsing
# =============================================================================
def parse_address(addr_str: str) -> int:
    """
    Parse address string in various formats:
    - 0x1000 or 0X1000 (hex)
    - $1000 (hex)
    - 4096 (decimal)
    - 1000h (hex suffix)
    
    Returns:
        int: Parsed address
    
    Raises:
        ValueError: If address cannot be parsed
    """
    if not isinstance(addr_str, str):
        if isinstance(addr_str, int):
            return addr_str
        raise ValueError(f"Cannot parse address from {type(addr_str)}")
    
    addr_str = addr_str.strip()
    
    if not addr_str:
        raise ValueError("Empty address string")
    
    addr_lower = addr_str.lower()
    
    if addr_lower.startswith('0x'):
        return int(addr_str[2:], 16)
    elif addr_lower.startswith('$'):
        return int(addr_str[1:], 16)
    elif addr_lower.endswith('h'):
        return int(addr_str[:-1], 16)
    
    # Try hex, then decimal
    try:
        return int(addr_str, 16)
    except ValueError:
        try:
            return int(addr_str, 10)
        except ValueError:
            raise ValueError(f"Invalid address format: '{addr_str}'")


# =============================================================================
# FIXED: Size parsing
# =============================================================================
def parse_size_string(size_str: str) -> int:
    """
    Parse size string like '1M', '512K', '0x1000', '4096'
    
    Returns:
        int: Size in bytes
    
    Raises:
        ValueError: If size cannot be parsed
    """
    if not isinstance(size_str, str):
        if isinstance(size_str, (int, float)):
            return int(size_str)
        raise ValueError(f"Cannot parse size from {type(size_str)}")
    
    size_str = size_str.strip().upper()
    
    if not size_str:
        raise ValueError("Empty size string")
    
    if size_str.startswith('0X'):
        return int(size_str, 16)
    
    multipliers = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
    }
    
    for suffix, multiplier in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            try:
                number = size_str[:-len(suffix)].strip()
                return int(float(number) * multiplier)
            except ValueError:
                continue
    
    try:
        return int(size_str)
    except ValueError:
        raise ValueError(f"Invalid size format: '{size_str}'")


# =============================================================================
# FIXED: Format bytes for display
# =============================================================================
def format_size(size_bytes: int) -> str:
    """Format byte count to human-readable string."""
    if size_bytes < 0:
        return f"-{format_size(-size_bytes)}"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.2f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"


# =============================================================================
# FIXED: Erase pattern configuration
# =============================================================================
class ErasePattern:
    """Manages erase pattern configuration and data generation."""
    
    # Pattern definitions
    PATTERNS = {
        'zero':    (0x00, "Zero fill (0x00)", "Standard erase, all bits cleared"),
        '00':      (0x00, "Zero fill (0x00)", "Standard erase, all bits cleared"),
        'zeros':   (0x00, "Zero fill (0x00)", "Standard erase, all bits cleared"),
        'clean':   (0x00, "Zero fill (0x00)", "Standard erase, all bits cleared"),
        
        'ff':      (0xFF, "One fill (0xFF)", "All bits set, common flash erase state"),
        'ones':    (0xFF, "One fill (0xFF)", "All bits set, common flash erase state"),
        'erase':   (0xFF, "One fill (0xFF)", "All bits set, common flash erase state"),
        'blank':   (0xFF, "One fill (0xFF)", "All bits set, common flash erase state"),
        
        'aa':      (0xAA, "Checker 0xAA (10101010)", "Alternating bit pattern"),
        'checker': (0xAA, "Checker 0xAA (10101010)", "Alternating bit pattern"),
        
        '55':      (0x55, "Checker 0x55 (01010101)", "Inverse alternating pattern"),
        'checker2':(0x55, "Checker 0x55 (01010101)", "Inverse alternating pattern"),
        
        'f0':      (0xF0, "Stripes 0xF0 (11110000)", "Nibble stripe pattern"),
        'stripes': (0xF0, "Stripes 0xF0 (11110000)", "Nibble stripe pattern"),
        
        '0f':      (0x0F, "Stripes 0x0F (00001111)", "Inverse nibble stripe"),
        
        '5a':      (0x5A, "Pattern 0x5A (01011010)", "Common memory test pattern"),
        'a5':      (0xA5, "Pattern 0xA5 (10100101)", "Common memory test pattern"),
        
        'random':  (None, "Random data (secure erase)", "Cryptographically secure random"),
        'rand':    (None, "Random data (secure erase)", "Cryptographically secure random"),
        'secure':  (None, "Random data (secure erase)", "Cryptographically secure random"),
    }
    
    def __init__(self, pattern_str: str = '00'):
        self._parse_pattern(pattern_str)
    
    def _parse_pattern(self, pattern_str: str):
        """Parse pattern specification string."""
        pattern_key = str(pattern_str).lower().strip()
        
        if pattern_key in self.PATTERNS:
            self.byte_value, self.name, self.description = self.PATTERNS[pattern_key]
            self.is_random = (self.byte_value is None)
            return
        
        # Try to parse as hex byte value
        try:
            clean = pattern_key.replace('0x', '').replace('0X', '')
            self.byte_value = int(clean, 16) & 0xFF
            self.name = f"Custom (0x{self.byte_value:02X})"
            self.description = f"User-specified erase pattern"
            self.is_random = False
        except ValueError:
            raise ValueError(
                f"Invalid erase pattern: '{pattern_str}'\n"
                f"Valid patterns: {', '.join(sorted(self.PATTERNS.keys()))}\n"
                f"Or specify a hex byte value like 'AB' or '0xCD'"
            )
    
    def generate_chunk(self, size: int, chunk_index: int = 0) -> bytes:
        """
        Generate erase data for a chunk.
        
        Args:
            size: Number of bytes to generate
            chunk_index: Chunk index (for deterministic random patterns)
        
        Returns:
            bytes: Generated data
        """
        if size <= 0:
            return b""
        
        if self.is_random:
            return os.urandom(size)
        else:
            return bytes([self.byte_value]) * size


# =============================================================================
# FIXED: Find command in QSLCLCMD database
# =============================================================================
def find_command(cmd_name: str) -> Optional[Tuple[str, Any]]:
    """
    Find a command in QSLCLCMD_DB.
    
    Returns:
        Optional[Tuple[str, Any]]: (key_type, key) or None
    """
    if not _use_qslcl or not _QSLCLCMD_DB:
        return None
    
    cmd_upper = cmd_name.upper()
    
    for key, value in _QSLCLCMD_DB.items():
        if isinstance(key, str) and key.upper() == cmd_upper:
            return ("name", key)
        if isinstance(value, dict) and value.get("name", "").upper() == cmd_upper:
            return ("opcode", key)
    
    return None


# =============================================================================
# FIXED: Command dispatch helper
# =============================================================================
def dispatch_command(dev, cmd_name: str, payload: bytes, timeout: float = None) -> Optional[bytes]:
    """
    Dispatch a command using the most appropriate method.
    
    Returns:
        Optional[bytes]: Response data or None
    """
    if not _use_qslcl:
        return None
    
    if timeout is None:
        timeout = ERASE_TIMEOUT
    
    # Try command database first
    cmd_info = find_command(cmd_name)
    if cmd_info:
        cmd_type, cmd_key = cmd_info
        if cmd_type == "name":
            return _qslcl_dispatch(dev, cmd_key, payload, timeout=timeout)
        else:
            return _qslcl_dispatch(dev, str(cmd_key), payload, timeout=timeout)
    
    # Generic dispatch
    return _qslcl_dispatch(dev, cmd_name, payload, timeout=timeout)


# =============================================================================
# FIXED: Check command success
# =============================================================================
def is_success_response(resp) -> bool:
    """Check if a response indicates success."""
    if not resp:
        return False
    
    if _use_qslcl and _decode_runtime_result:
        try:
            status = _decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
        except Exception:
            pass
    
    return False


# =============================================================================
# FIXED: Target resolution
# =============================================================================
def resolve_erase_target(target: str, partitions: List[Dict], 
                         size_arg: Optional[str] = None
                         ) -> Tuple[int, int, Optional[Dict]]:
    """
    Resolve erase target to address, size, and partition info.
    
    Returns:
        Tuple[int, int, Optional[Dict]]: (address, size, partition_info)
    
    Raises:
        ValueError: If target cannot be resolved
    """
    target_str = str(target).strip()
    
    # Try partition+offset format: "boot+0x1000"
    if '+' in target_str:
        try:
            part_name, offset_str = target_str.split('+', 1)
            part_name = part_name.strip().lower()
            offset = parse_address(offset_str.strip())
        except ValueError as e:
            raise ValueError(f"Invalid partition+offset format: {e}")
        
        for part in partitions:
            if part.get('name', '').lower() == part_name:
                address = part['offset'] + offset
                max_size = part['size'] - offset
                
                if max_size <= 0:
                    raise ValueError(
                        f"Offset 0x{offset:X} exceeds partition '{part['name']}' size "
                        f"(0x{part['size']:X})"
                    )
                
                size = parse_size_string(size_arg) if size_arg else max_size
                
                if size > max_size:
                    raise ValueError(
                        f"Erase size ({format_size(size)}) exceeds available space "
                        f"({format_size(max_size)}) at offset 0x{offset:X} in partition '{part['name']}'"
                    )
                
                print(f"[+] Target: {part['name']}+0x{offset:X} = 0x{address:08X}")
                return address, size, part
        
        raise ValueError(f"Unknown partition: '{part_name}'")
    
    # Try partition name
    target_lower = target_str.lower()
    for part in partitions:
        if part.get('name', '').lower() == target_lower:
            address = part['offset']
            max_size = part['size']
            
            size = parse_size_string(size_arg) if size_arg else max_size
            
            if size > max_size:
                raise ValueError(
                    f"Erase size ({format_size(size)}) exceeds partition size "
                    f"({format_size(max_size)})"
                )
            
            print(f"[+] Target: partition '{part['name']}' (0x{address:08X}, {format_size(size)})")
            return address, size, part
    
    # Try raw address
    try:
        address = parse_address(target_str)
    except ValueError:
        raise ValueError(
            f"Cannot resolve target: '{target_str}'\n"
            f"Valid formats: partition_name, 0xADDRESS, partition+0xOFFSET"
        )
    
    if not size_arg:
        raise ValueError(
            f"Size required for raw address target.\n"
            f"Use --size <bytes> or specify a partition name.\n"
            f"Examples: erase 0x10000000 --size 1M"
        )
    
    size = parse_size_string(size_arg)
    print(f"[+] Target: raw address 0x{address:08X}, size {format_size(size)}")
    return address, size, None


# =============================================================================
# FIXED: Verification function
# =============================================================================
def verify_erase(dev, address: int, size: int, expected_byte: Optional[int],
                 chunk_size: int, force: bool = False
                 ) -> Tuple[bool, List[Dict]]:
    """
    Verify that erase was successful by reading back data.
    
    Returns:
        Tuple[bool, List[Dict]]: (verified_ok, list_of_errors)
    """
    if expected_byte is None:
        print("\n[*] Skipping verification (random pattern - cannot verify)")
        return True, []
    
    print(f"\n[*] Verifying erase...")
    errors = []
    verified = 0
    expected = bytes([expected_byte])
    
    ProgressClass = _ProgressBar if _use_qslcl and _ProgressBar else LocalProgressBar
    
    try:
        with ProgressClass(size, prefix='Verifying', suffix='Complete', length=50) as progress:
            verify_addr = address
            remaining = size
            
            while remaining > 0:
                verify_chunk = min(chunk_size, remaining)
                
                # Read back data
                read_payload = struct.pack("<II", verify_addr, verify_chunk)
                resp = dispatch_command(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
                
                if not resp:
                    errors.append({
                        'address': verify_addr,
                        'size': verify_chunk,
                        'error': "No response from device"
                    })
                    if not force:
                        return False, errors
                    verified += verify_chunk
                    remaining -= verify_chunk
                    verify_addr += verify_chunk
                    progress.update(verify_chunk)
                    continue
                
                if _use_qslcl and _decode_runtime_result:
                    status = _decode_runtime_result(resp)
                    if status.get("severity") != "SUCCESS":
                        errors.append({
                            'address': verify_addr,
                            'size': verify_chunk,
                            'error': f"Read failed: {status.get('name', 'Unknown')}"
                        })
                        if not force:
                            return False, errors
                        verified += verify_chunk
                        remaining -= verify_chunk
                        verify_addr += verify_chunk
                        progress.update(verify_chunk)
                        continue
                    
                    read_data = status.get("extra", b"")
                else:
                    read_data = resp
                
                # Verify pattern
                if len(read_data) != verify_chunk:
                    errors.append({
                        'address': verify_addr,
                        'size': verify_chunk,
                        'error': f"Size mismatch: got {len(read_data)}, expected {verify_chunk}"
                    })
                    if not force:
                        return False, errors
                    verified += min(len(read_data), verify_chunk)
                    verified_chunk = min(len(read_data), verify_chunk)
                else:
                    # Count mismatched bytes
                    mismatch_count = sum(1 for b in read_data if bytes([b]) != expected)
                    
                    if mismatch_count > 0:
                        mismatch_pct = (mismatch_count / verify_chunk) * 100
                        
                        # Find first mismatch position
                        first_mismatch = 0
                        for i, b in enumerate(read_data):
                            if bytes([b]) != expected:
                                first_mismatch = i
                                break
                        
                        errors.append({
                            'address': verify_addr + first_mismatch,
                            'size': verify_chunk,
                            'mismatches': mismatch_count,
                            'total': verify_chunk,
                            'percentage': mismatch_pct,
                            'first_mismatch_offset': first_mismatch,
                            'expected_hex': expected.hex(),
                            'got_hex': read_data[max(0, first_mismatch-4):first_mismatch+12].hex()
                        })
                        
                        if mismatch_pct > 5 and not force:
                            print(f"\n[!] High error rate at 0x{verify_addr:08X}: "
                                  f"{mismatch_pct:.1f}% mismatched")
                            return False, errors
                    
                    verified_chunk = verify_chunk
                
                verified += verified_chunk
                remaining -= verify_chunk
                verify_addr += verify_chunk
                progress.update(verified_chunk)
    
    except KeyboardInterrupt:
        print(f"\n[!] Verification interrupted")
        return False, errors
    
    except Exception as e:
        print(f"\n[!] Verification error: {e}")
        errors.append({
            'address': verify_addr,
            'error': f"Exception: {type(e).__name__}: {e}"
        })
        return False, errors
    
    if not errors:
        print("[+] Verification: PASSED")
        return True, []
    else:
        total_mismatches = sum(e.get('mismatches', 0) for e in errors)
        total_verified = sum(e.get('total', 0) for e in errors if 'total' in e)
        
        if total_verified > 0:
            error_rate = (total_mismatches / total_verified) * 100
            print(f"[!] Verification: {len(errors)} chunk(s) with errors, "
                  f"{total_mismatches:,} bytes mismatched ({error_rate:.3f}%)")
        else:
            print(f"[!] Verification: {len(errors)} error(s)")
        
        return len(errors) == 0 or force, errors


# =============================================================================
# FIXED: Print summary function
# =============================================================================
def print_erase_summary(address: int, erase_size: int, bytes_erased: int,
                        pattern_name: str, elapsed: float, partition_info: Optional[Dict],
                        failed_chunks: List[Dict], verification_errors: List[Dict],
                        force: bool) -> int:
    """Print comprehensive erase summary. Returns 0 on complete success, 1 otherwise."""
    
    avg_speed = bytes_erased / elapsed if elapsed > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"  ERASE SUMMARY")
    print(f"{'='*60}")
    print(f"  Target:       0x{address:08X}" + 
          (f" ({partition_info['name']})" if partition_info else ""))
    print(f"  Requested:    {format_size(erase_size)}")
    print(f"  Erased:       {format_size(bytes_erased)}")
    
    if erase_size > 0:
        print(f"  Success rate: {bytes_erased*100/erase_size:.1f}%")
    
    print(f"  Pattern:      {pattern_name}")
    print(f"  Time:         {elapsed:.2f}s")
    print(f"  Speed:        {format_size(int(avg_speed))}/s")
    
    if failed_chunks:
        print(f"\n  Failed chunks: {len(failed_chunks)}")
        for chunk in failed_chunks[:5]:
            addr = chunk.get('address', 0)
            err = chunk.get('error', 'Unknown')
            size = chunk.get('size', 0)
            print(f"    - 0x{addr:08X} ({format_size(size)}): {err}")
        if len(failed_chunks) > 5:
            print(f"    ... and {len(failed_chunks) - 5} more")
    
    if verification_errors:
        print(f"\n  Verification errors: {len(verification_errors)}")
        total_mismatches = sum(e.get('mismatches', 0) for e in verification_errors)
        total_verified = sum(e.get('total', 0) for e in verification_errors if 'total' in e)
        
        if total_verified > 0:
            error_rate = (total_mismatches / total_verified) * 100
            print(f"  Mismatched:    {total_mismatches:,} bytes ({error_rate:.3f}%)")
        
        for err in verification_errors[:3]:
            addr = err.get('address', 0)
            if 'mismatches' in err:
                print(f"    - 0x{addr:08X}: {err['mismatches']}/{err['total']} bytes "
                      f"({err['percentage']:.1f}%)")
            else:
                print(f"    - 0x{addr:08X}: {err.get('error', 'Unknown')}")
    
    print(f"{'='*60}")
    
    # Determine status
    if bytes_erased == erase_size and not failed_chunks and not verification_errors:
        print(f"\n  [PASS] Erase completed successfully")
        return 0
    elif bytes_erased == erase_size and (failed_chunks or verification_errors):
        print(f"\n  [WARN] Erase completed with errors")
        return 1
    elif bytes_erased > 0:
        print(f"\n  [FAIL] Erase incomplete ({bytes_erased*100/erase_size:.1f}%)")
        return 1
    else:
        print(f"\n  [FAIL] No data erased")
        return 1


# =============================================================================
# FIXED: Main ERASE command function
# =============================================================================
def cmd_erase(args=None) -> int:
    """
    QSLCL ERASE Command v2.0 (FIXED)
    
    Erases device memory/partitions with:
    - Multiple erase patterns (zero, FF, checker, random, custom)
    - Partition and address targeting
    - Smart size detection
    - Chunked erase with retry logic
    - Optional verification
    - Comprehensive safety checks
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] ERASE: No arguments provided")
        print("[*] Usage: erase <target> [size] [--pattern PATTERN] [options]")
        return 1
    
    if not _use_qslcl:
        _warn_standalone()
    
    # =========================================================================
    # Device discovery
    # =========================================================================
    if _use_qslcl:
        try:
            devs = _scan_all()
        except Exception as e:
            print(f"[!] Device scan failed: {e}")
            return 1
        
        if not devs:
            print("[!] No QSLCL-compatible device detected")
            return 1
        
        dev = devs[0]
        print(f"[*] Device: {dev.product} ({dev.vendor})")
    else:
        print("[!] Cannot access device in standalone mode")
        return 1
    
    # =========================================================================
    # Loader injection
    # =========================================================================
    if hasattr(args, 'loader') and args.loader:
        try:
            _auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"[!] Loader injection failed: {e}")
            return 1
    
    # =========================================================================
    # Extract arguments
    # =========================================================================
    target = None
    for attr in ['target', 'arg1', 'erase_target']:
        if hasattr(args, attr) and getattr(args, attr):
            target = getattr(args, attr)
            break
    
    if not target:
        print("[!] No target specified")
        print("[*] Examples:")
        print("    erase boot                    - Erase entire boot partition")
        print("    erase system --size 1M        - Erase 1MB of system partition")
        print("    erase 0x10000000 --size 512K  - Erase 512KB at address")
        print("    erase userdata --pattern ff   - Erase with 0xFF fill")
        print("    erase cache --pattern random  - Secure erase with random data")
        return 1
    
    # Get size
    size_arg = None
    for attr in ['size', 'arg2', 'erase_size']:
        if hasattr(args, attr) and getattr(args, attr):
            size_arg = getattr(args, attr)
            break
    
    # Get other parameters
    chunk_size = getattr(args, 'chunk_size', DEFAULT_ERASE_CHUNK_SIZE)
    force = getattr(args, 'force', False)
    no_verify = getattr(args, 'no_verify', False)
    
    # Get erase pattern
    erase_pattern = getattr(args, 'pattern', '00')
    if hasattr(args, 'erase_pattern') and args.erase_pattern:
        erase_pattern = args.erase_pattern
    
    # Validate chunk size
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        chunk_size = DEFAULT_ERASE_CHUNK_SIZE
    chunk_size = max(4096, min(chunk_size, 64 * 1024 * 1024))  # 4KB to 64MB
    
    # =========================================================================
    # Parse erase pattern
    # =========================================================================
    try:
        pattern = ErasePattern(erase_pattern)
    except ValueError as e:
        print(f"[!] {e}")
        return 1
    
    print(f"[*] Erase pattern: {pattern.name}")
    print(f"    {pattern.description}")
    
    # =========================================================================
    # Target resolution
    # =========================================================================
    partitions = []
    if _load_partitions:
        try:
            partitions = _load_partitions(dev)
        except Exception as e:
            if _DEBUG:
                print(f"[!] Partition detection failed: {e}")
    
    try:
        address, erase_size, partition_info = resolve_erase_target(
            target, partitions, size_arg
        )
    except ValueError as e:
        print(f"[!] Target resolution failed: {e}")
        
        if partitions:
            print(f"\n[*] Available partitions:")
            for p in sorted(partitions, key=lambda x: x.get('offset', 0)):
                print(f"    {p.get('name', '?'):<16} offset=0x{p.get('offset', 0):08X}  "
                      f"size={format_size(p.get('size', 0))}")
        return 1
    
    if erase_size <= 0:
        print(f"[!] Invalid erase size: {erase_size}")
        return 1
    
    # =========================================================================
    # Safety checks
    # =========================================================================
    if partition_info:
        partition_name = partition_info.get('name', '').lower()
        
        # Check against critical partitions list
        is_critical = any(
            crit in partition_name for crit in CRITICAL_PARTITIONS
        )
        
        if is_critical:
            print(f"\n{'='*60}")
            print(f"  ⚠️  WARNING: CRITICAL PARTITION DETECTED")
            print(f"{'='*60}")
            print(f"  Partition: {partition_info['name']}")
            print(f"  Address:   0x{partition_info['offset']:08X}")
            print(f"  Size:      {format_size(partition_info['size'])}")
            print(f"")
            print(f"  🔴 ERASING THIS PARTITION MAY BRICK YOUR DEVICE!")
            print(f"  🔴 This operation is IRREVERSIBLE!")
            print(f"  🔴 Only proceed if you have a backup and know how to recover!")
            print(f"{'='*60}")
            
            if not force:
                print(f"\n  To confirm, type exactly: I_ACCEPT_THE_RISK")
                response = input("  > ")
                if response != "I_ACCEPT_THE_RISK":
                    print("[*] Operation cancelled - safety first!")
                    return 0
                print("[*] Risk accepted - proceeding with caution...")
    
    # =========================================================================
    # Display summary and confirm
    # =========================================================================
    print(f"\n{'='*60}")
    print(f"  ERASE CONFIGURATION")
    print(f"{'='*60}")
    print(f"  Target:   0x{address:08X}" + 
          (f" ({partition_info['name']})" if partition_info else ""))
    print(f"  Size:     {format_size(erase_size)} (0x{erase_size:08X})")
    print(f"  Pattern:  {pattern.name}")
    print(f"  Chunk:    {format_size(chunk_size)}")
    print(f"  Verify:   {'Yes' if not no_verify else 'No'}")
    print(f"{'='*60}")
    
    if not force:
        print(f"\n  Confirm erase? Type 'YES' to proceed:")
        response = input("  > ")
        if response.upper() != 'YES':
            print("[*] Operation cancelled")
            return 0
    
    # =========================================================================
    # Main erase operation
    # =========================================================================
    print(f"\n[*] Erasing {format_size(erase_size)} at 0x{address:08X}...")
    
    bytes_erased = 0
    retry_count = 0
    consecutive_failures = 0
    failed_chunks: List[Dict] = []
    start_time = time.time()
    
    ProgressClass = _ProgressBar if _use_qslcl and _ProgressBar else LocalProgressBar
    
    try:
        with ProgressClass(erase_size, prefix='Erasing', suffix='Complete', length=50) as progress:
            chunk_index = 0
            
            while bytes_erased < erase_size:
                chunk_addr = address + bytes_erased
                remaining = erase_size - bytes_erased
                current_chunk = min(chunk_size, remaining)
                chunk_index += 1
                
                if current_chunk <= 0:
                    break
                
                # Generate erase data
                chunk_data = pattern.generate_chunk(current_chunk, chunk_index)
                
                try:
                    # Build payload
                    erase_payload = struct.pack("<II", chunk_addr, current_chunk) + chunk_data
                    
                    # Try ERASE command first, fall back to WRITE
                    resp = dispatch_command(dev, "ERASE", erase_payload)
                    
                    if not resp or not is_success_response(resp):
                        # Fallback: use WRITE command for erasing
                        write_payload = struct.pack("<II", chunk_addr, current_chunk) + chunk_data
                        resp = dispatch_command(dev, "WRITE", write_payload)
                    
                    if resp and is_success_response(resp):
                        bytes_erased += current_chunk
                        progress.update(current_chunk)
                        retry_count = 0
                        consecutive_failures = 0
                    else:
                        # Determine error
                        error_msg = "No response"
                        if resp and _use_qslcl and _decode_runtime_result:
                            status = _decode_runtime_result(resp)
                            error_msg = status.get("name", "Unknown error")
                        
                        if _DEBUG:
                            print(f"\n[!] Erase error at 0x{chunk_addr:08X}: {error_msg}")
                        
                        failed_chunks.append({
                            'address': chunk_addr,
                            'size': current_chunk,
                            'error': error_msg,
                            'chunk_index': chunk_index
                        })
                        retry_count += 1
                        consecutive_failures += 1
                
                except KeyboardInterrupt:
                    print(f"\n\n[!] ERASE interrupted by user")
                    print(f"[*] {format_size(bytes_erased)}/{format_size(erase_size)} erased")
                    return 1
                
                except Exception as e:
                    if _DEBUG:
                        print(f"\n[!] Exception at 0x{chunk_addr:08X}: {type(e).__name__}: {e}")
                    failed_chunks.append({
                        'address': chunk_addr,
                        'size': current_chunk,
                        'error': f"{type(e).__name__}: {e}",
                        'chunk_index': chunk_index
                    })
                    retry_count += 1
                    consecutive_failures += 1
                
                # Handle retries
                if retry_count > 0 and consecutive_failures > 0:
                    if retry_count >= MAX_RETRIES:
                        print(f"\n[!] Max retries ({MAX_RETRIES}) exceeded")
                        break
                    
                    backoff = min(INITIAL_BACKOFF * (2 ** (retry_count - 1)), MAX_BACKOFF)
                    if _DEBUG:
                        print(f"[*] Backoff: {backoff:.2f}s (retry {retry_count}/{MAX_RETRIES})")
                    time.sleep(backoff)
                
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    print(f"\n[!] Too many consecutive failures ({consecutive_failures})")
                    break
        
        # Final progress update
        progress.update(0)
    
    except Exception as e:
        print(f"\n[!] Erase operation failed: {e}")
        if _DEBUG:
            traceback.print_exc()
        return 1
    
    elapsed = time.time() - start_time
    
    # =========================================================================
    # Retry failed chunks
    # =========================================================================
    if failed_chunks:
        print(f"\n[*] Retrying {len(failed_chunks)} failed chunks...")
        retried = 0
        
        for chunk_info in list(failed_chunks):
            chunk_addr = chunk_info['address']
            chunk_size = chunk_info['size']
            
            success = False
            for attempt in range(MAX_RETRIES):
                try:
                    chunk_data = pattern.generate_chunk(chunk_size, chunk_info.get('chunk_index', 0) + 1000)
                    write_payload = struct.pack("<II", chunk_addr, chunk_size) + chunk_data
                    
                    resp = dispatch_command(dev, "WRITE", write_payload)
                    
                    if resp and is_success_response(resp):
                        bytes_erased += chunk_size
                        failed_chunks.remove(chunk_info)
                        retried += 1
                        success = True
                        break
                    
                    time.sleep(INITIAL_BACKOFF * (2 ** attempt))
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] Retry exception for 0x{chunk_addr:08X}: {e}")
                    time.sleep(0.5)
            
            if not success and _DEBUG:
                print(f"[!] Permanent failure at 0x{chunk_addr:08X}")
        
        if retried > 0:
            print(f"[+] Successfully retried {retried} chunks")
    
    # =========================================================================
    # Verification
    # =========================================================================
    verification_errors = []
    
    if not no_verify and bytes_erased > 0:
        verify_ok, verification_errors = verify_erase(
            dev, address, bytes_erased, pattern.byte_value, chunk_size, force
        )
    
    # =========================================================================
    # Print summary
    # =========================================================================
    result = print_erase_summary(
        address=address,
        erase_size=erase_size,
        bytes_erased=bytes_erased,
        pattern_name=pattern.name,
        elapsed=elapsed,
        partition_info=partition_info,
        failed_chunks=failed_chunks,
        verification_errors=verification_errors,
        force=force
    )
    
    return result


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] erase.py - QSLCL ERASE Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py erase <target> [options]")