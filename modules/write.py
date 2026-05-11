#!/usr/bin/env python3
"""
write.py - QSLCL WRITE Command Module v2.0 (FIXED)
Fixed: Import handling, safety checks, error recovery, data parsing, verification
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
_detect_memory_regions = None
_resolve_target = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_ProgressBar = None
_QSLCLCMD_DB = None
_get_sector_size = None
_ENDPOINT_DB = None
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
        QSLCLEND_DB as _qslcl_end_db,
        get_sector_size as _qslcl_get_sector_size,
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
    _ENDPOINT_DB = _qslcl_end_db
    _get_sector_size = _qslcl_get_sector_size
    _DEBUG = _qslcl_debug
    _use_qslcl = True
except ImportError as e:
    # Try relative import for package usage
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
            QSLCLEND_DB as _qslcl_end_db,
            get_sector_size as _qslcl_get_sector_size,
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
        _ENDPOINT_DB = _qslcl_end_db
        _get_sector_size = _qslcl_get_sector_size
        _DEBUG = _qslcl_debug
        _use_qslcl = True
    except ImportError:
        _use_qslcl = False


# =============================================================================
# FIXED: Standalone mode warnings and fallbacks
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
# FIXED: Constants for maintainability
# =============================================================================
DEFAULT_CHUNK_SIZE = 65536       # 64KB default write chunk
MAX_RETRIES = 3                  # Maximum retry attempts per chunk
MAX_CONSECUTIVE_FAILURES = 8     # Max consecutive failures before abort
INITIAL_BACKOFF = 0.1            # Initial backoff in seconds
MAX_BACKOFF = 10.0               # Maximum backoff cap
WRITE_TIMEOUT = 20.0             # Write operation timeout
VERIFY_TIMEOUT = 15.0            # Verification read timeout
DEFAULT_MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB default max

# =============================================================================
# FIXED: Comprehensive pattern parser
# =============================================================================
def parse_pattern_data(pattern_str: str) -> bytes:
    """
    Parse pattern data strings with full validation:
    - "AABBCCDD" = literal hex bytes
    - "AA:1024" = fill 1024 bytes with 0xAA
    - "AABB*8" = repeat AABB pattern 8 times
    - "AABB:1024*2" = fill 2048 bytes (1024*2) with 0xAABB (first byte used)
    - "DEADBEEF*4" = repeat 4-byte pattern 4 times
    
    Args:
        pattern_str: Pattern specification string
    
    Returns:
        bytes: Generated pattern data
    """
    if not pattern_str or not isinstance(pattern_str, str):
        return b""
    
    pattern_str = pattern_str.strip().upper()
    
    # Remove whitespace from hex-only strings
    if not any(c in pattern_str for c in '*:'):
        clean = pattern_str.replace(' ', '').replace('-', '')
        try:
            return bytes.fromhex(clean)
        except ValueError as e:
            print(f"[!] Invalid hex data: {e}")
            return b""
    
    # Pattern with both fill and repetition: "VALUE:SIZE*COUNT"
    if '*' in pattern_str and ':' in pattern_str:
        try:
            fill_part, count_part = pattern_str.split('*', 1)
            value_str, size_str = fill_part.split(':', 1)
            
            value_bytes = bytes.fromhex(value_str)
            if not value_bytes:
                raise ValueError("Empty value")
            
            fill_byte = value_bytes[0]  # Use first byte for fill
            fill_size = int(size_str)
            repeat_count = int(count_part)
            
            total_size = fill_size * repeat_count
            if total_size > 100 * 1024 * 1024:  # 100MB sanity limit
                print(f"[!] Pattern too large ({total_size} bytes), limit is 100MB")
                return b""
            
            return bytes([fill_byte] * fill_size) * repeat_count
            
        except (ValueError, IndexError) as e:
            print(f"[!] Invalid fill*repeat pattern '{pattern_str}': {e}")
            return b""
    
    # Fill pattern: "VALUE:SIZE"
    elif ':' in pattern_str:
        try:
            value_str, size_str = pattern_str.split(':', 1)
            
            value_bytes = bytes.fromhex(value_str)
            if not value_bytes:
                raise ValueError("Empty value")
            
            fill_byte = value_bytes[0]
            fill_size = int(size_str)
            
            if fill_size > 100 * 1024 * 1024:
                print(f"[!] Fill size too large ({fill_size} bytes), limit is 100MB")
                return b""
            
            return bytes([fill_byte] * fill_size)
            
        except (ValueError, IndexError) as e:
            print(f"[!] Invalid fill pattern '{pattern_str}': {e}")
            return b""
    
    # Repetition pattern: "HEX*COUNT"
    elif '*' in pattern_str:
        try:
            data_part, count_part = pattern_str.split('*', 1)
            
            data_bytes = bytes.fromhex(data_part)
            if not data_bytes:
                raise ValueError("Empty data")
            
            repeat_count = int(count_part)
            
            total_size = len(data_bytes) * repeat_count
            if total_size > 100 * 1024 * 1024:
                print(f"[!] Pattern too large ({total_size} bytes), limit is 100MB")
                return b""
            
            return data_bytes * repeat_count
            
        except (ValueError, IndexError) as e:
            print(f"[!] Invalid repeat pattern '{pattern_str}': {e}")
            return b""
    
    # Fallback: try simple hex
    try:
        return bytes.fromhex(pattern_str.replace(' ', ''))
    except ValueError:
        print(f"[!] Cannot parse pattern: '{pattern_str}'")
        return b""


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
# FIXED: Address parsing with better error handling
# =============================================================================
def parse_address(addr_str: str) -> int:
    """
    Parse address string in various formats:
    - 0x1000 or 0X1000 (hex)
    - $1000 (hex)
    - &h1000 (hex)
    - 4096 (decimal)
    - 1000h (hex suffix)
    - segment:offset (real mode addressing)
    
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
    
    # Handle segment:offset format (real mode)
    if ':' in addr_str and not addr_str.lower().startswith('0x'):
        parts = addr_str.split(':')
        if len(parts) == 2:
            try:
                segment = int(parts[0], 16)
                offset = int(parts[1], 16)
                return (segment << 4) + offset
            except ValueError:
                pass
    
    # Remove common prefixes
    addr_lower = addr_str.lower()
    if addr_lower.startswith('0x'):
        return int(addr_str[2:], 16)
    elif addr_lower.startswith('$'):
        return int(addr_str[1:], 16)
    elif addr_lower.startswith('&h'):
        return int(addr_str[2:], 16)
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
# FIXED: Human-readable size parser
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
    
    # Hex format
    if size_str.startswith('0X'):
        return int(size_str, 16)
    
    # Suffix multipliers
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
    
    # Plain number
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
# FIXED: Comprehensive Write Protection System
# =============================================================================
class WriteProtectionManager:
    """
    Manages write protection with comprehensive safety checks:
    - Known protected memory regions
    - Critical partition detection
    - Alignment verification
    - Risk level assessment
    """
    
    # severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    
    def __init__(self):
        self._protected_regions = self._init_protected_regions()
        self._critical_partitions = self._init_critical_partitions()
    
    def _init_protected_regions(self) -> List[Dict]:
        """Initialize database of known protected memory regions"""
        return [
            # ABSOLUTE NO-GO ZONES
            {
                "name": "BOOTROM",
                "start": 0x00000000,
                "end": 0x00010000,
                "reason": "BootROM - Writing here WILL permanently brick the device",
                "severity": self.SEVERITY_CRITICAL,
                "reversible": False
            },
            {
                "name": "IROM",
                "start": 0x00000000,
                "end": 0x00008000,
                "reason": "Internal Mask ROM - Physically read-only on most devices",
                "severity": self.SEVERITY_CRITICAL,
                "reversible": False
            },
            {
                "name": "RESET_VECTOR",
                "start": 0x00000000,
                "end": 0x00000040,
                "reason": "CPU Reset Vector - Critical for boot",
                "severity": self.SEVERITY_CRITICAL,
                "reversible": False
            },
            {
                "name": "INTERRUPT_VECTORS",
                "start": 0x00000000,
                "end": 0x00000400,
                "reason": "Interrupt Vector Table",
                "severity": self.SEVERITY_CRITICAL,
                "reversible": False
            },
            
            # HIGH RISK BOOTLOADER REGIONS
            {
                "name": "PBL",
                "start": 0x00000000,
                "end": 0x00010000,
                "reason": "Primary Boot Loader region",
                "severity": self.SEVERITY_HIGH,
                "reversible": False
            },
            {
                "name": "SBL_REGION",
                "start": 0x00004000,
                "end": 0x00040000,
                "reason": "Secondary Boot Loader region",
                "severity": self.SEVERITY_HIGH,
                "reversible": False
            },
            
            # MEDIUM RISK (often recoverable with reflash)
            {
                "name": "TEE_REGION",
                "start": 0x10000000,
                "end": 0x11000000,
                "reason": "Trusted Execution Environment",
                "severity": self.SEVERITY_MEDIUM,
                "reversible": True
            },
        ]
    
    def _init_critical_partitions(self) -> Dict[str, Tuple[str, str, bool]]:
        """Initialize critical partition database"""
        return {
            # name: (risk_level, reason, reversible)
            'bootrom':     (self.SEVERITY_CRITICAL, "BootROM - WILL BRICK DEVICE", False),
            'brom':        (self.SEVERITY_CRITICAL, "BootROM - WILL BRICK DEVICE", False),
            'irom':        (self.SEVERITY_CRITICAL, "Internal ROM - WILL BRICK DEVICE", False),
            'pbl':         (self.SEVERITY_CRITICAL, "Primary Boot Loader - HIGH BRICK RISK", False),
            'sbl':         (self.SEVERITY_HIGH, "Secondary Boot Loader - May brick device", False),
            'sbl1':        (self.SEVERITY_HIGH, "Secondary Boot Loader - May brick device", False),
            'sbl2':        (self.SEVERITY_HIGH, "Secondary Boot Loader - May brick device", False),
            'sbl3':        (self.SEVERITY_HIGH, "Secondary Boot Loader - May brick device", False),
            'xbl':         (self.SEVERITY_HIGH, "eXtensible Boot Loader - May brick device", False),
            'xbl_config':  (self.SEVERITY_HIGH, "XBL Configuration - May brick device", False),
            'aboot':       (self.SEVERITY_HIGH, "Android Bootloader - May brick device", False),
            'lk':          (self.SEVERITY_HIGH, "Little Kernel - May brick device", False),
            'llb':         (self.SEVERITY_HIGH, "Low-Level Bootloader - May brick device", False),
            'preloader':   (self.SEVERITY_HIGH, "Preloader - May brick device", False),
            'boot':        (self.SEVERITY_HIGH, "Boot partition - May cause boot failure", True),
            'recovery':    (self.SEVERITY_MEDIUM, "Recovery partition - Recoverable", True),
            'bootloader':  (self.SEVERITY_HIGH, "Bootloader - May brick device", False),
            'tz':          (self.SEVERITY_MEDIUM, "TrustZone - May affect security", True),
            'tee1':        (self.SEVERITY_MEDIUM, "TEE partition - May affect security", True),
            'tee2':        (self.SEVERITY_MEDIUM, "TEE partition - May affect security", True),
            'rpm':         (self.SEVERITY_HIGH, "Resource Power Manager - May cause boot failure", False),
            'hyp':         (self.SEVERITY_MEDIUM, "Hypervisor - May cause boot failure", True),
            'devcfg':      (self.SEVERITY_MEDIUM, "Device Configuration - May affect functionality", True),
            'devinfo':     (self.SEVERITY_MEDIUM, "Device Info - May affect functionality", True),
            'dip':         (self.SEVERITY_MEDIUM, "Device Info Partition - May affect functionality", True),
            'limits':      (self.SEVERITY_MEDIUM, "Limits partition - May affect functionality", True),
            'sec':         (self.SEVERITY_MEDIUM, "Security partition - May affect security", True),
            'keymaster':   (self.SEVERITY_MEDIUM, "Keymaster - May affect security", True),
            'cmnlib':      (self.SEVERITY_MEDIUM, "Common Library - May affect security", True),
            'cmnlib64':    (self.SEVERITY_MEDIUM, "Common Library 64 - May affect security", True),
            'mdtp':        (self.SEVERITY_MEDIUM, "MDTP - May affect security", True),
            'apdp':        (self.SEVERITY_MEDIUM, "APDP - May affect functionality", True),
            'msadp':       (self.SEVERITY_MEDIUM, "MSADP - May affect functionality", True),
            'dpo':         (self.SEVERITY_MEDIUM, "DPO - May affect functionality", True),
            'splash':      (self.SEVERITY_LOW, "Splash screen - Low risk", True),
            'misc':        (self.SEVERITY_LOW, "Miscellaneous - Low risk", True),
        }
    
    def check_address(self, address: int, size: int = 1) -> Dict[str, Any]:
        """
        Check if an address range overlaps any protected region.
        
        Returns:
            dict with keys: protected, region, reason, severity, overlap_start, overlap_end
        """
        end_addr = address + size
        
        for region in self._protected_regions:
            if address < region["end"] and end_addr > region["start"]:
                overlap_start = max(address, region["start"])
                overlap_end = min(end_addr, region["end"])
                
                return {
                    "protected": True,
                    "region": region["name"],
                    "reason": region["reason"],
                    "severity": region["severity"],
                    "reversible": region.get("reversible", False),
                    "overlap_start": overlap_start,
                    "overlap_end": overlap_end,
                    "overlap_size": overlap_end - overlap_start
                }
        
        return {"protected": False}
    
    def check_partition(self, partition_name: str) -> Dict[str, Any]:
        """
        Check if a partition is considered critical.
        
        Returns:
            dict with keys: critical, risk_level, reason, reversible
        """
        name_lower = partition_name.lower().strip()
        
        if name_lower in self._critical_partitions:
            level, reason, reversible = self._critical_partitions[name_lower]
            return {
                "critical": True,
                "risk_level": level,
                "reason": reason,
                "reversible": reversible
            }
        
        return {
            "critical": False,
            "risk_level": self.SEVERITY_LOW,
            "reason": "Standard partition",
            "reversible": True
        }
    
    def check_alignment(self, address: int, sector_size: int) -> Dict[str, Any]:
        """Check if address is properly aligned to sector size."""
        if sector_size <= 0:
            return {"aligned": True}
        
        if address % sector_size == 0:
            return {"aligned": True}
        
        suggested = address - (address % sector_size)
        return {
            "aligned": False,
            "message": f"Address 0x{address:X} not aligned to sector size {sector_size}",
            "suggested": suggested,
            "misalignment": address % sector_size
        }


# =============================================================================
# FIXED: Write safety check function
# =============================================================================
def check_write_safety(dev, address: int, size: int, force: bool = False,
                       protection_level: str = 'normal',
                       protection_manager: Optional[WriteProtectionManager] = None
                       ) -> Tuple[bool, str, Optional[Dict]]:
    """
    Comprehensive write safety check.
    
    Returns:
        Tuple[bool, str, Optional[Dict]]: (is_safe, message, protection_info)
    """
    if protection_manager is None:
        protection_manager = WriteProtectionManager()
    
    warnings = []
    
    # Step 1: Check protected region database
    protection = protection_manager.check_address(address, size)
    
    if protection.get("protected"):
        severity = protection["severity"]
        region = protection["region"]
        reason = protection["reason"]
        
        if severity == WriteProtectionManager.SEVERITY_CRITICAL:
            return False, f"CRITICAL: {region} - {reason}", protection
        
        if severity == WriteProtectionManager.SEVERITY_HIGH and not force:
            if protection_level == 'strict':
                return False, f"HIGH RISK: {region} - {reason}", protection
            else:
                warnings.append(f"HIGH RISK: {region} - {reason}")
        
        if severity == WriteProtectionManager.SEVERITY_MEDIUM and protection_level == 'strict':
            warnings.append(f"MEDIUM RISK: {region} - {reason}")
    
    # Step 2: Check partition if known
    partition_name = getattr(dev, '_current_partition', None)
    if partition_name:
        part_check = protection_manager.check_partition(partition_name)
        
        if part_check["critical"]:
            risk_level = part_check["risk_level"]
            reason = part_check["reason"]
            
            if risk_level == WriteProtectionManager.SEVERITY_CRITICAL:
                return False, f"CRITICAL partition: {partition_name} - {reason}", part_check
            
            if risk_level == WriteProtectionManager.SEVERITY_HIGH and not force:
                if protection_level == 'strict':
                    return False, f"HIGH RISK partition: {partition_name} - {reason}", part_check
                else:
                    warnings.append(f"HIGH RISK partition: {partition_name} - {reason}")
    
    # Step 3: Check alignment
    if _use_qslcl and _get_sector_size:
        try:
            sector_size = _get_sector_size(dev)
            if sector_size > 0:
                alignment = protection_manager.check_alignment(address, sector_size)
                if not alignment["aligned"]:
                    suggested = alignment.get("suggested", 0)
                    msg = (f"Unaligned write: address 0x{address:X} not aligned to "
                           f"{sector_size}-byte sectors. Suggested: 0x{suggested:X}")
                    if protection_level == 'strict':
                        return False, msg, alignment
                    else:
                        warnings.append(msg)
        except Exception:
            pass  # Alignment check is advisory
    
    if warnings:
        return True, "; ".join(warnings), protection
    
    return True, "Safe to write", None


# =============================================================================
# FIXED: Read-only memory test
# =============================================================================
def test_memory_writable(dev, address: int, test_size: int = 4) -> Tuple[bool, str]:
    """
    Test if a memory region is writable by attempting a test write.
    
    Returns:
        Tuple[bool, str]: (is_writable, message)
    """
    if not _use_qslcl:
        return False, "Cannot test without QSLCL functions"
    
    try:
        # Read original data
        read_payload = struct.pack("<II", address, test_size)
        resp = _qslcl_dispatch(dev, "READ", read_payload, timeout=10.0)
        
        if not resp:
            return False, "No response to read test"
        
        status = _decode_runtime_result(resp)
        if status.get("severity") != "SUCCESS":
            return False, f"Read test failed: {status.get('name', 'Unknown error')}"
        
        original_data = status.get("extra", b"")
        if len(original_data) < test_size:
            return False, f"Insufficient data read ({len(original_data)} < {test_size})"
        
        original = original_data[:test_size]
        
        # Generate test pattern (something different from original)
        test_pattern = bytes([b ^ 0xFF for b in original])
        
        # Attempt write
        write_payload = struct.pack("<II", address, test_size) + test_pattern
        write_resp = _qslcl_dispatch(dev, "WRITE", write_payload, timeout=10.0)
        
        if not write_resp:
            return False, "No response to write test"
        
        write_status = _decode_runtime_result(write_resp)
        if write_status.get("severity") != "SUCCESS":
            return False, f"Write test rejected: {write_status.get('name', 'Unknown error')}"
        
        # Read back to verify
        read_back_resp = _qslcl_dispatch(dev, "READ", read_payload, timeout=10.0)
        
        # Restore original data
        restore_payload = struct.pack("<II", address, test_size) + original
        _qslcl_dispatch(dev, "WRITE", restore_payload, timeout=10.0)
        
        if not read_back_resp:
            return False, "No response to verify read"
        
        read_back_status = _decode_runtime_result(read_back_resp)
        read_back_data = read_back_status.get("extra", b"")[:test_size]
        
        if read_back_data == test_pattern:
            return True, "Region is writable"
        else:
            return False, "Region appears to be READ-ONLY (write was not persisted)"
    
    except Exception as e:
        return False, f"Writability test failed: {e}"


# =============================================================================
# FIXED: Display protection warning
# =============================================================================
def display_protection_warning(protection_info: Dict, force: bool = False):
    """Display formatted protection warning."""
    if not protection_info or not protection_info.get("protected", False):
        return
    
    severity = protection_info.get("severity", "UNKNOWN")
    region = protection_info.get("region", "Unknown")
    reason = protection_info.get("reason", "No reason provided")
    reversible = protection_info.get("reversible", False)
    
    if severity == WriteProtectionManager.SEVERITY_CRITICAL:
        print("\n" + "=" * 72)
        print("  💀💀💀  CRITICAL PROTECTION WARNING  💀💀💀")
        print("=" * 72)
        print(f"  Region:   {region}")
        print(f"  Reason:   {reason}")
        print(f"  Recovery: {'POSSIBLE with reflash' if reversible else 'IMPOSSIBLE - PERMANENT DAMAGE'}")
        if "overlap_start" in protection_info:
            print(f"  Overlap:  0x{protection_info['overlap_start']:08X} - "
                  f"0x{protection_info['overlap_end']:08X} "
                  f"({format_size(protection_info.get('overlap_size', 0))})")
        print("=" * 72)
        if not force:
            print("  🛡️  Write BLOCKED to prevent permanent device damage.")
        else:
            print("  ⚠️  FORCE MODE ACTIVE - Proceeding with EXTREME caution!")
        print("=" * 72 + "\n")
    
    elif severity == WriteProtectionManager.SEVERITY_HIGH:
        print("\n" + "-" * 56)
        print(f"  ⚠️  HIGH RISK: {region}")
        print(f"  {reason}")
        print(f"  Recovery: {'POSSIBLE with reflash' if reversible else 'DIFFICULT'}")
        print("-" * 56 + "\n")
    
    elif severity == WriteProtectionManager.SEVERITY_MEDIUM:
        print(f"\n  [!] MEDIUM RISK: {region} - {reason}\n")


# =============================================================================
# FIXED: Data source processing
# =============================================================================
def process_data_source(data_source: str, target_size: int = 0,
                        max_file_size: int = DEFAULT_MAX_FILE_SIZE
                        ) -> Tuple[bytes, str]:
    """
    Process data source into bytes ready for writing.
    
    Returns:
        Tuple[bytes, str]: (data, source_type_description)
    """
    if not data_source:
        return b"", "empty"
    
    # Check if it's a file path
    if os.path.exists(data_source) and os.path.isfile(data_source):
        file_size = os.path.getsize(data_source)
        
        if file_size > max_file_size:
            raise ValueError(
                f"File too large: {format_size(file_size)} exceeds maximum {format_size(max_file_size)}"
            )
        
        if file_size == 0:
            raise ValueError("File is empty")
        
        with open(data_source, 'rb') as f:
            data = f.read()
        
        print(f"[+] File source: {data_source}")
        print(f"    Size: {format_size(len(data))}")
        print(f"    SHA256: {hashlib.sha256(data).hexdigest()[:32]}...")
        
        return data, "file"
    
    # Check for special pattern/fill commands
    data_lower = data_source.lower().strip()
    
    if data_lower in ('zero', 'zeros', '00', '0x00', 'null'):
        if target_size <= 0:
            raise ValueError("Cannot determine size for zero fill on raw address. Specify size.")
        data = b'\x00' * target_size
        print(f"[+] Zero fill: {format_size(target_size)}")
        return data, "zero-fill"
    
    if data_lower in ('ff', 'ones', '0xff', 'erase', 'fill'):
        if target_size <= 0:
            raise ValueError("Cannot determine size for FF fill on raw address. Specify size.")
        data = b'\xFF' * target_size
        print(f"[+] FF fill: {format_size(target_size)}")
        return data, "ff-fill"
    
    if data_lower == 'random':
        if target_size <= 0:
            raise ValueError("Cannot determine size for random fill. Specify size.")
        data = os.urandom(target_size)
        print(f"[+] Random fill: {format_size(target_size)}")
        return data, "random-fill"
    
    # Check for pattern syntax: *, :
    if '*' in data_source or ':' in data_source:
        data = parse_pattern_data(data_source)
        if not data:
            raise ValueError(f"Failed to parse pattern: '{data_source}'")
        print(f"[+] Pattern data: {format_size(len(data))}")
        return data, "pattern"
    
    # Try as hex string
    clean_hex = data_source.replace(' ', '').replace('-', '').replace(':', '').upper()
    if re.match(r'^[0-9A-F]+$', clean_hex) and len(clean_hex) >= 2:
        try:
            data = bytes.fromhex(clean_hex)
            print(f"[+] Hex data: {len(data)} bytes")
            return data, "hex"
        except ValueError:
            pass
    
    # Treat as literal string
    data = data_source.encode('utf-8')
    print(f"[+] String data: {len(data)} bytes")
    return data, "string"


# =============================================================================
# FIXED: Find command in database
# =============================================================================
def find_command_in_db(command_name: str) -> Optional[Tuple[str, Any]]:
    """
    Find a command in QSLCLCMD_DB by name or opcode.
    
    Returns:
        Optional[Tuple[str, Any]]: (dispatch_key_type, dispatch_key) or None
    """
    if not _use_qslcl or not _QSLCLCMD_DB:
        return None
    
    cmd_upper = command_name.upper()
    
    # Search by name
    for key, value in _QSLCLCMD_DB.items():
        if isinstance(key, str) and key.upper() == cmd_upper:
            return ("name", key)
        if isinstance(value, dict) and value.get("name", "").upper() == cmd_upper:
            return ("opcode", key)
    
    return None


# =============================================================================
# FIXED: Main WRITE command function
# =============================================================================
def cmd_write(args=None) -> int:
    """
    QSLCL WRITE Command v2.0 (FIXED)
    
    Writes data to device memory/partitions with:
    - Comprehensive protection against bricking
    - Multiple data sources (file, hex, patterns, fills)
    - Chunked writes with retry logic
    - Optional write verification
    - Detailed progress reporting
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] WRITE: No arguments provided")
        print("[*] Usage: write <target> <data> [--options]")
        return 1
    
    # Warn about standalone mode
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
    target = getattr(args, 'target', None)
    data_source = getattr(args, 'data', None)
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK_SIZE)
    max_file_size = getattr(args, 'max_file_size', DEFAULT_MAX_FILE_SIZE)
    no_verify = getattr(args, 'no_verify', False)
    force = getattr(args, 'force', False)
    protection_level = getattr(args, 'protection', 'normal')
    skip_protection = getattr(args, 'no_protection_checks', False)
    test_readonly = getattr(args, 'test_readonly', False)
    
    # Validate required arguments
    if not target:
        print("[!] No target specified")
        print("[*] Examples:")
        print("    write boot boot.img")
        print("    write 0x10000000 myfile.bin")
        print("    write system FF:1048576  (fill 1MB with 0xFF)")
        return 1
    
    if not data_source:
        print("[!] No data source specified")
        print("[*] Examples of valid data sources:")
        print("    filename.bin       - Write file contents")
        print("    AABBCCDD           - Write hex bytes")
        print("    FF:4096            - Fill 4096 bytes with 0xFF")
        print("    DEADBEEF*100       - Repeat pattern 100 times")
        print("    zero               - Fill with zeros (needs target size)")
        print("    ff                 - Fill with 0xFF (needs target size)")
        return 1
    
    # Validate chunk size
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        print(f"[!] Invalid chunk size, using default: {DEFAULT_CHUNK_SIZE}")
        chunk_size = DEFAULT_CHUNK_SIZE
    chunk_size = max(512, min(chunk_size, 16 * 1024 * 1024))  # Clamp 512B-16MB
    
    # Validate protection level
    if protection_level not in ('strict', 'normal', 'permissive', 'off'):
        print(f"[!] Invalid protection level '{protection_level}', using 'normal'")
        protection_level = 'normal'
    
    if protection_level == 'off':
        skip_protection = True
    
    # =========================================================================
    # Target resolution
    # =========================================================================
    partitions = []
    memory_regions = []
    
    try:
        partitions = _load_partitions(dev) if _load_partitions else []
    except Exception as e:
        if _DEBUG:
            print(f"[!] Partition load failed: {e}")
    
    try:
        memory_regions = _detect_memory_regions(dev) if _detect_memory_regions else []
    except Exception as e:
        if _DEBUG:
            print(f"[!] Memory region detection failed: {e}")
    
    # Resolve target
    address = 0
    target_size = 0
    partition_info = None
    region_info = None
    
    if _resolve_target:
        try:
            target_info = _resolve_target(target, partitions, memory_regions, dev)
        except Exception as e:
            print(f"[!] Target resolution error: {e}")
            target_info = None
        
        if not target_info:
            # Show available targets
            print(f"[!] Cannot resolve target: '{target}'")
            if partitions:
                print(f"\n[*] Available partitions:")
                for p in sorted(partitions, key=lambda x: x.get('offset', 0)):
                    print(f"    {p.get('name', '?'):<16} offset=0x{p.get('offset', 0):08X}  "
                          f"size={format_size(p.get('size', 0))}")
            return 1
        
        address = target_info.get('address', 0)
        target_size = target_info.get('size', 0)
        partition_info = target_info.get('partition_info')
        region_info = target_info.get('region_info')
    else:
        # Legacy fallback
        try:
            address = parse_address(target)
            target_size = 0x10000  # Default 64KB for raw addresses
        except ValueError:
            # Try partition name
            for p in partitions:
                if p.get('name', '').lower() == target.lower():
                    partition_info = p
                    address = p['offset']
                    target_size = p['size']
                    break
            if not partition_info:
                print(f"[!] Cannot resolve target: '{target}'")
                return 1
    
    if partition_info:
        dev._current_partition = partition_info.get('name', '')
        print(f"\n[+] Target partition: {dev._current_partition}")
        print(f"    Base: 0x{address:08X}, Size: {format_size(target_size)}")
    elif region_info:
        print(f"\n[+] Target region: {region_info.get('name', 'unknown')}")
        print(f"    Start: 0x{address:08X}, Size: {format_size(target_size)}")
    else:
        print(f"\n[+] Target address: 0x{address:08X}")
    
    # =========================================================================
    # Data source processing
    # =========================================================================
    try:
        write_data, source_type = process_data_source(data_source, target_size, max_file_size)
    except ValueError as e:
        print(f"[!] Data source error: {e}")
        return 1
    
    data_size = len(write_data)
    
    if data_size == 0:
        print("[!] No data to write (empty source)")
        return 1
    
    # Check size against target
    if target_size > 0 and data_size > target_size:
        print(f"\n[!] Data size ({format_size(data_size)}) exceeds target size ({format_size(target_size)})")
        if force:
            print("[!] Force mode: truncating data to target size")
            write_data = write_data[:target_size]
            data_size = target_size
        else:
            print("[*] Use --force to truncate or provide smaller data")
            return 1
    
    # =========================================================================
    # Safety checks
    # =========================================================================
    protection_manager = WriteProtectionManager()
    protection_info = None
    
    if not skip_protection:
        safe, message, protection_info = check_write_safety(
            dev, address, data_size, force, protection_level, protection_manager
        )
        
        if protection_info:
            display_protection_warning(protection_info, force)
        
        if not safe:
            print(f"\n[!] WRITE BLOCKED: {message}")
            
            if (protection_info and 
                protection_info.get("severity") == WriteProtectionManager.SEVERITY_CRITICAL):
                print("\n  💀 This operation would PERMANENTLY BRICK your device!")
                print("  The write has been BLOCKED to prevent irreversible damage.")
                return 1
            
            if not force and protection_level != 'permissive':
                response = input("\n  Override protection? Type 'yes' to confirm: ")
                if response.lower() != 'yes':
                    print("[*] Write cancelled")
                    return 1
                print("[!] PROCEEDING WITH DANGEROUS WRITE - You have been warned!\n")
            elif not force:
                print("[!] Permissive mode: allowing potentially dangerous write\n")
    
    # Read-only test
    if test_readonly and _use_qslcl:
        print("[*] Testing if target region is writable...")
        is_writable, test_msg = test_memory_writable(dev, address)
        print(f"    Result: {test_msg}")
        
        if not is_writable and not force:
            response = input("\n  Region appears read-only. Attempt write anyway? (yes/NO): ")
            if response.lower() != 'yes':
                print("[*] Write cancelled")
                return 1
        elif not is_writable:
            print("[!] Force mode: attempting write to read-only region\n")
    
    # Critical partition check
    if partition_info and protection_manager.check_partition(partition_info['name'])["critical"]:
        part_check = protection_manager.check_partition(partition_info['name'])
        if part_check["risk_level"] in (WriteProtectionManager.SEVERITY_CRITICAL, 
                                         WriteProtectionManager.SEVERITY_HIGH):
            if not force:
                print(f"\n[!!!] CRITICAL PARTITION: {partition_info['name']}")
                print(f"    {part_check['reason']}")
                response = input("    Type 'YES' to confirm write: ")
                if response != 'YES':
                    print("[*] Write cancelled")
                    return 1
    
    # =========================================================================
    # Confirmation
    # =========================================================================
    print(f"\n{'='*60}")
    print(f"  WRITE CONFIRMATION")
    print(f"{'='*60}")
    print(f"  Target:      0x{address:08X}" + 
          (f" ({partition_info['name']})" if partition_info else ""))
    print(f"  Data size:   {format_size(data_size)} ({data_size} bytes)")
    print(f"  Source type: {source_type}")
    print(f"  Chunk size:  {format_size(chunk_size)}")
    print(f"  Protection:  {protection_level}")
    print(f"  Verify:      {'Yes' if not no_verify else 'No'}")
    if protection_info and protection_info.get("protected"):
        print(f"  ⚠️  Region:  {protection_info.get('region', 'Unknown')} (PROTECTED)")
    print(f"{'='*60}")
    
    if not force:
        response = input("\n  Confirm write? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Write cancelled")
            return 0
    
    # =========================================================================
    # Main write operation
    # =========================================================================
    print(f"\n[*] Writing {format_size(data_size)} to 0x{address:08X}...")
    
    bytes_written = 0
    retry_count = 0
    consecutive_failures = 0
    failed_chunks: List[Tuple[int, int]] = []
    
    ProgressClass = _ProgressBar if _use_qslcl and _ProgressBar else LocalProgressBar
    
    try:
        with ProgressClass(data_size, prefix='Writing', suffix='Complete', length=50) as progress:
            
            while bytes_written < data_size:
                chunk_addr = address + bytes_written
                remaining = data_size - bytes_written
                current_chunk_size = min(chunk_size, remaining)
                
                if current_chunk_size <= 0:
                    break
                
                chunk_data = write_data[bytes_written:bytes_written + current_chunk_size]
                
                # Strict protection: re-check each chunk
                if not skip_protection and protection_level == 'strict':
                    chunk_protection = protection_manager.check_address(chunk_addr, current_chunk_size)
                    if (chunk_protection.get("protected") and 
                        chunk_protection.get("severity") == WriteProtectionManager.SEVERITY_CRITICAL):
                        print(f"\n[!] BLOCKED: Critical region at 0x{chunk_addr:08X}")
                        failed_chunks.append((chunk_addr, current_chunk_size))
                        bytes_written += current_chunk_size
                        progress.update(current_chunk_size)
                        continue
                
                try:
                    # Build and send write payload
                    write_payload = struct.pack("<II", chunk_addr, current_chunk_size) + chunk_data
                    
                    # Use QSLCLCMD system
                    cmd_info = find_command_in_db("WRITE")
                    if cmd_info:
                        cmd_type, cmd_key = cmd_info
                        if cmd_type == "name":
                            resp = _qslcl_dispatch(dev, cmd_key, write_payload, timeout=WRITE_TIMEOUT)
                        else:
                            resp = _qslcl_dispatch(dev, str(cmd_key), write_payload, timeout=WRITE_TIMEOUT)
                    else:
                        resp = _qslcl_dispatch(dev, "WRITE", write_payload, timeout=WRITE_TIMEOUT)
                    
                    if resp:
                        status = _decode_runtime_result(resp)
                        if status.get("severity") == "SUCCESS":
                            bytes_written += current_chunk_size
                            progress.update(current_chunk_size)
                            retry_count = 0
                            consecutive_failures = 0
                        else:
                            error_name = status.get('name', 'Unknown error')
                            print(f"\n[!] Write error at 0x{chunk_addr:08X}: {error_name}")
                            failed_chunks.append((chunk_addr, current_chunk_size))
                            retry_count += 1
                            consecutive_failures += 1
                    else:
                        print(f"\n[!] No response at 0x{chunk_addr:08X}")
                        failed_chunks.append((chunk_addr, current_chunk_size))
                        retry_count += 1
                        consecutive_failures += 1
                
                except KeyboardInterrupt:
                    print(f"\n\n[!] WRITE interrupted by user")
                    print(f"[*] {format_size(bytes_written)}/{format_size(data_size)} written")
                    return 1
                
                except Exception as e:
                    print(f"\n[!] Exception at 0x{chunk_addr:08X}: {type(e).__name__}: {e}")
                    if _DEBUG:
                        traceback.print_exc()
                    failed_chunks.append((chunk_addr, current_chunk_size))
                    retry_count += 1
                    consecutive_failures += 1
                
                # Handle retries with backoff
                if retry_count > 0 and consecutive_failures > 0:
                    if retry_count >= MAX_RETRIES:
                        print(f"\n[!] Max retries exceeded at 0x{chunk_addr:08X}")
                        break
                    
                    backoff = min(INITIAL_BACKOFF * (2 ** (retry_count - 1)), MAX_BACKOFF)
                    time.sleep(backoff)
                
                # Check consecutive failure limit
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    print(f"\n[!] Too many consecutive failures ({consecutive_failures})")
                    break
        
        # Final progress update
        progress.update(0)
    
    except Exception as e:
        print(f"\n[!] Write operation failed: {e}")
        if _DEBUG:
            traceback.print_exc()
        return 1
    
    # =========================================================================
    # Retry failed chunks
    # =========================================================================
    if failed_chunks:
        print(f"\n[*] Retrying {len(failed_chunks)} failed chunks...")
        retry_failed = list(failed_chunks)
        retried_count = 0
        
        for chunk_addr, chunk_size in retry_failed:
            data_offset = chunk_addr - address
            
            if not (0 <= data_offset < data_size):
                continue
            
            success = False
            for attempt in range(MAX_RETRIES):
                try:
                    chunk_data = write_data[data_offset:data_offset + chunk_size]
                    write_payload = struct.pack("<II", chunk_addr, chunk_size) + chunk_data
                    
                    cmd_info = find_command_in_db("WRITE")
                    if cmd_info:
                        cmd_type, cmd_key = cmd_info
                        if cmd_type == "name":
                            resp = _qslcl_dispatch(dev, cmd_key, write_payload, timeout=WRITE_TIMEOUT)
                        else:
                            resp = _qslcl_dispatch(dev, str(cmd_key), write_payload, timeout=WRITE_TIMEOUT)
                    else:
                        resp = _qslcl_dispatch(dev, "WRITE", write_payload, timeout=WRITE_TIMEOUT)
                    
                    if resp:
                        status = _decode_runtime_result(resp)
                        if status.get("severity") == "SUCCESS":
                            bytes_written += chunk_size
                            failed_chunks.remove((chunk_addr, chunk_size))
                            retried_count += 1
                            success = True
                            break
                    
                    time.sleep(INITIAL_BACKOFF * (2 ** attempt))
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] Retry exception for 0x{chunk_addr:08X}: {e}")
                    time.sleep(0.5)
            
            if not success:
                if _DEBUG:
                    print(f"[!] Permanent failure at 0x{chunk_addr:08X}")
        
        if retried_count > 0:
            print(f"[+] Successfully retried {retried_count} chunks")
    
    # =========================================================================
    # Verification
    # =========================================================================
    verification_passed = True
    
    if not no_verify and bytes_written > 0:
        print(f"\n[*] Verifying written data...")
        
        try:
            with ProgressClass(bytes_written, prefix='Verifying', suffix='Complete', length=50) as vprogress:
                verify_addr = address
                verify_offset = 0
                remaining = bytes_written
                
                while remaining > 0 and verify_offset < data_size:
                    verify_chunk = min(chunk_size, remaining)
                    
                    read_payload = struct.pack("<II", verify_addr, verify_chunk)
                    
                    cmd_info = find_command_in_db("READ")
                    if cmd_info:
                        cmd_type, cmd_key = cmd_info
                        if cmd_type == "name":
                            resp = _qslcl_dispatch(dev, cmd_key, read_payload, timeout=VERIFY_TIMEOUT)
                        else:
                            resp = _qslcl_dispatch(dev, str(cmd_key), read_payload, timeout=VERIFY_TIMEOUT)
                    else:
                        resp = _qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
                    
                    if resp:
                        status = _decode_runtime_result(resp)
                        if status.get("severity") == "SUCCESS":
                            read_data = status.get("extra", b"")
                            expected = write_data[verify_offset:verify_offset + verify_chunk]
                            
                            if read_data == expected:
                                vprogress.update(verify_chunk)
                            else:
                                # Find first mismatch
                                mismatch_pos = 0
                                for i in range(min(len(read_data), len(expected))):
                                    if read_data[i] != expected[i]:
                                        mismatch_pos = i
                                        break
                                else:
                                    mismatch_pos = len(expected)
                                
                                print(f"\n[!] Verification failed at 0x{verify_addr + mismatch_pos:08X}")
                                print(f"    Expected: {expected[max(0,mismatch_pos-4):mismatch_pos+12].hex()}")
                                print(f"    Got:      {read_data[max(0,mismatch_pos-4):mismatch_pos+12].hex()}")
                                verification_passed = False
                                break
                        else:
                            print(f"\n[!] Verify read failed at 0x{verify_addr:08X}")
                            verification_passed = False
                            break
                    else:
                        print(f"\n[!] No verify response at 0x{verify_addr:08X}")
                        verification_passed = False
                        break
                    
                    verify_addr += verify_chunk
                    verify_offset += verify_chunk
                    remaining -= verify_chunk
            
            vprogress.update(0)  # Final update
            
            if verification_passed:
                print("\n[+] Verification: PASSED")
            else:
                print("\n[!] Verification: FAILED - Data mismatch detected!")
        
        except Exception as e:
            print(f"\n[!] Verification error: {e}")
            verification_passed = False
    
    # =========================================================================
    # Final summary
    # =========================================================================
    print(f"\n{'='*60}")
    print(f"  WRITE SUMMARY")
    print(f"{'='*60}")
    print(f"  Target:       0x{address:08X}" + 
          (f" ({partition_info['name']})" if partition_info else ""))
    print(f"  Data size:    {format_size(data_size)}")
    print(f"  Written:      {format_size(bytes_written)}")
    print(f"  Success rate: {bytes_written*100/max(data_size,1):.1f}%")
    print(f"  Verified:     {'PASS' if verification_passed else 'FAIL' if not no_verify else 'SKIPPED'}")
    
    if failed_chunks:
        print(f"  Failed:       {len(failed_chunks)} chunks")
        for addr, sz in failed_chunks[:10]:  # Show first 10
            print(f"    - 0x{addr:08X} ({format_size(sz)})")
        if len(failed_chunks) > 10:
            print(f"    ... and {len(failed_chunks) - 10} more")
    
    if source_type == "file":
        print(f"  Source:       {data_source}")
        print(f"  SHA256:       {hashlib.sha256(write_data).hexdigest()[:32]}...")
    
    print(f"{'='*60}")
    
    if protection_info and protection_info.get("protected") and not skip_protection:
        print(f"\n  ⚠️  REMINDER: You modified a protected region!")
        print(f"     Region: {protection_info.get('region', 'Unknown')}")
        print(f"     Please verify your device functions correctly before disconnecting.\n")
    
    if bytes_written > 0:
        return 0
    else:
        return 1


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] write.py - QSLCL WRITE Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py write <target> <data> [options]")