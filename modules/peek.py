#!/usr/bin/env python3
"""
peek.py - QSLCL PEEK Command Module v2.0 (FIXED)
Fixed: Import handling, address resolution, data reading, type interpretation,
       entropy calculation, pointer analysis, error handling
"""

import os
import sys
import re
import struct
import time
import math
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
_QSLCLCMD_DB = None
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
PEEK_TIMEOUT = 10.0           # Peek operation timeout
MAX_PEEK_SIZE = 1024 * 1024   # 1MB maximum peek size
DEFAULT_PEEK_SIZE = 4          # Default bytes to read
HEX_DUMP_LINE_SIZE = 16        # Bytes per hex dump line

# Data type sizes
TYPE_SIZES = {
    'uint8': 1, 'int8': 1, 'char': 1, 'byte': 1,
    'uint16': 2, 'int16': 2, 'short': 2, 'ushort': 2,
    'uint32': 4, 'int32': 4, 'float': 4, 'int': 4, 'uint': 4,
    'uint64': 8, 'int64': 8, 'double': 8, 'long': 8, 'ulong': 8,
    'string': 0, 'hex': 0, 'bytes': 0, 'raw': 0,  # Variable size
}

# Common magic values for highlighting
MAGIC_VALUES = {
    0x00000000: "NULL",
    0xFFFFFFFF: "ALL_ONES",
    0xDEADBEEF: "DEADBEEF (freed memory)",
    0xCAFEBABE: "CAFEBABE (Java class)",
    0xBAADF00D: "BAADF00D (uninitialized heap)",
    0x8BADF00D: "8BADF00D (ate bad food)",
    0xDEADC0DE: "DEADC0DE (dead code)",
    0xDEADFA11: "DEADFA11 (dead fall)",
    0xDEAD10CC: "DEAD10CC (dead lock)",
    0xABADBABE: "ABADBABE",
    0xABADCAFE: "ABADCAFE (a bad cafe)",
    0xFEEDFACE: "FEEDFACE (feed face)",
    0xFEEDF00D: "FEEDF00D (feed food)",
    0x0D15EA5E: "0D15EA5E (disease)",
    0x1BADB002: "1BADB002 (1 bad boot)",
    0x12345678: "TEST_PATTERN",
    0xAAAAAAAA: "ALT_BITS_1010",
    0x55555555: "ALT_BITS_0101",
    0x0000FFFF: "LOW_ONES",
    0xFFFF0000: "HIGH_ONES",
    0x00FF00FF: "BYTE_MASK",
    0xFF00FF00: "INV_BYTE_MASK",
}

# 32-bit pointer ranges for detection
POINTER_RANGES_32 = [
    (0x00000100, 0x000FFFFF, "Low memory"),
    (0x10000000, 0x60000000, "Peripheral/MMIO"),
    (0x80000000, 0xC0000000, "DRAM"),
    (0xC0000000, 0xFFFFFFFF, "Kernel space"),
]

# 64-bit pointer ranges
POINTER_RANGES_64 = [
    (0x00000000FFFFFFFF, 0x0000FFFFFFFFFFFF, "Low 64-bit"),
    (0xFFFF000000000000, 0xFFFFFFFFFFFFFFFF, "Kernel 64-bit"),
]


# =============================================================================
# FIXED: Address parsing
# =============================================================================
def parse_address(addr_str: str) -> int:
    """Parse address string in various formats."""
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
    
    try:
        return int(addr_str, 16)
    except ValueError:
        try:
            return int(addr_str, 10)
        except ValueError:
            raise ValueError(f"Invalid address format: '{addr_str}'")


# =============================================================================
# FIXED: Find command helper
# =============================================================================
def find_command(cmd_name: str) -> Optional[Tuple[str, Any]]:
    """Find a command in QSLCLCMD_DB."""
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
    """Dispatch a command using the most appropriate method."""
    if not _use_qslcl:
        return None
    
    if timeout is None:
        timeout = PEEK_TIMEOUT
    
    cmd_info = find_command(cmd_name)
    if cmd_info:
        cmd_type, cmd_key = cmd_info
        if cmd_type == "name":
            return _qslcl_dispatch(dev, cmd_key, payload, timeout=timeout)
        else:
            return _qslcl_dispatch(dev, str(cmd_key), payload, timeout=timeout)
    
    return _qslcl_dispatch(dev, cmd_name, payload, timeout=timeout)


# =============================================================================
# FIXED: Read memory with multiple fallback strategies
# =============================================================================
def read_memory(dev, address: int, size: int, max_strategies: int = 4) -> Tuple[bool, bytes, str]:
    """
    Read memory from device using multiple strategies.
    
    Returns:
        Tuple[bool, bytes, str]: (success, data, strategy_used)
    """
    if size <= 0:
        return False, b"", "Invalid size"
    
    if size > MAX_PEEK_SIZE:
        return False, b"", f"Size {size} exceeds maximum {MAX_PEEK_SIZE}"
    
    read_payload = struct.pack("<II", address, size)
    
    strategies = [
        ("QSLCLCMD READ", lambda: _read_via_command(dev, "READ", read_payload, size)),
        ("QSLCLCMD PEEK", lambda: _read_via_command(dev, "PEEK", read_payload, size)),
        ("QSLCLCMD MEMREAD", lambda: _read_via_command(dev, "MEMREAD", read_payload, size)),
        ("Generic READ", lambda: _read_generic(dev, address, size)),
    ]
    
    for strategy_name, read_func in strategies[:max_strategies]:
        try:
            data = read_func()
            if data and len(data) > 0:
                return True, data, strategy_name
        except Exception as e:
            if _DEBUG:
                print(f"[!] {strategy_name} failed: {e}")
    
    return False, b"", "All strategies failed"


def _read_via_command(dev, cmd_name: str, payload: bytes, expected_size: int) -> Optional[bytes]:
    """Read using QSLCL command dispatch."""
    resp = dispatch_command(dev, cmd_name, payload)
    
    if not resp:
        return None
    
    # Try structured response parsing
    if _use_qslcl and _decode_runtime_result:
        try:
            status = _decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if extra:
                    return extra[:expected_size]
            return None
        except Exception:
            pass
    
    # Try raw bytes response
    if isinstance(resp, bytes) and len(resp) > 0:
        # Check for DATA header
        if resp.startswith(b"DATA") and len(resp) >= 8:
            data_size = struct.unpack("<I", resp[4:8])[0]
            if len(resp) >= 8 + data_size:
                return resp[8:8+data_size]
        return resp[:expected_size]
    
    return None


def _read_generic(dev, address: int, size: int) -> Optional[bytes]:
    """Generic fallback read using device interface."""
    if not hasattr(dev, 'write') or not hasattr(dev, 'read'):
        return None
    
    try:
        cmd = f"READ 0x{address:08X} 0x{size:08X}".encode()
        dev.write(cmd)
        time.sleep(0.05)
        resp = dev.read(timeout=2.0)
        
        if resp and isinstance(resp, bytes):
            if resp.startswith(b"QSLCLRESP"):
                if len(resp) >= 14:
                    resp_size = struct.unpack("<I", resp[9:13])[0] if len(resp) >= 13 else 0
                    if len(resp) >= 14 + resp_size:
                        return resp[14:14+resp_size]
            return resp[:size]
    except Exception:
        pass
    
    return None


# =============================================================================
# FIXED: Memory region detection
# =============================================================================
def detect_memory_region(address: int, dev) -> str:
    """Detect what type of memory region an address belongs to."""
    # Try partition detection first
    if _use_qslcl and _load_partitions:
        try:
            partitions = _load_partitions(dev)
            for part in partitions:
                offset = part.get('offset', 0)
                size = part.get('size', 0)
                if offset <= address < offset + size:
                    name = part.get('name', 'unknown')
                    return f"Partition: {name} [0x{offset:08X}-0x{offset+size:08X}]"
        except Exception:
            pass
    
    # Common memory region mappings
    regions = [
        (0x00000000, 0x00010000, "Boot ROM / Reset Vector"),
        (0x00010000, 0x00100000, "Low Flash / Internal ROM"),
        (0x00100000, 0x10000000, "Flash / Internal Storage"),
        (0x10000000, 0x40000000, "Peripheral / MMIO Space"),
        (0x40000000, 0x60000000, "APB Peripherals"),
        (0x60000000, 0x80000000, "AHB Peripherals"),
        (0x80000000, 0xC0000000, "DRAM / External RAM"),
        (0xC0000000, 0xE0000000, "Kernel / Device Memory"),
        (0xE0000000, 0xFFFFFFFF, "System / Reserved"),
    ]
    
    for start, end, name in regions:
        if start <= address < end:
            return f"Memory: {name} [0x{start:08X}-0x{end:08X}]"
    
    if address >= 0x100000000:
        return "Memory: 64-bit Address Space"
    
    return "Memory: Unknown Region"


# =============================================================================
# FIXED: Auto-detect data type
# =============================================================================
def auto_detect_data_type(address: int, size: int, count: int) -> str:
    """Auto-detect the best data type based on address and size."""
    # Peripheral registers are typically 32-bit
    if 0x10000000 <= address < 0x60000000:
        return 'uint32'
    
    # STM32-style peripherals
    if 0x40000000 <= address < 0x50000000:
        return 'uint32'
    
    # DRAM regions - usually 32-bit or 64-bit
    if 0x80000000 <= address < 0xC0000000:
        if size >= 8 or count > 1:
            return 'uint64' if size == 8 else 'uint32'
        return 'uint32'
    
    # Size-based detection
    size_map = {1: 'uint8', 2: 'uint16', 4: 'uint32', 8: 'uint64'}
    if size in size_map:
        return size_map[size]
    
    # Large size with single count = raw data
    if size > 8 and count == 1:
        return 'hex'
    
    return 'uint32'


# =============================================================================
# FIXED: Hex dump formatter
# =============================================================================
def format_hex_dump(data: bytes, base_address: int, line_size: int = 16) -> str:
    """Create formatted hex dump with ASCII representation."""
    if not data:
        return "  [No data]"
    
    lines = []
    
    for offset in range(0, len(data), line_size):
        chunk = data[offset:offset + line_size]
        addr = base_address + offset
        
        # Hex representation
        hex_parts = []
        for i in range(0, len(chunk), 2):
            if i + 1 < len(chunk):
                hex_parts.append(f"{chunk[i]:02x}{chunk[i+1]:02x}")
            else:
                hex_parts.append(f"{chunk[i]:02x}")
        
        hex_str = ' '.join(hex_parts)
        
        # ASCII representation
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        lines.append(f"  {addr:08x}:  {hex_str:<48} |{ascii_str}|")
    
    return '\n'.join(lines)


# =============================================================================
# FIXED: Integer data display
# =============================================================================
def display_integer_data(data: bytes, element_size: int, count: int, 
                         data_type: str, base_address: int):
    """Display integer data with proper formatting."""
    fmt_map = {
        'uint8': ('<B', 1, False),
        'int8': ('<b', 1, True),
        'char': ('<B', 1, False),
        'uint16': ('<H', 2, False),
        'int16': ('<h', 2, True),
        'uint32': ('<I', 4, False),
        'int32': ('<i', 4, True),
        'uint64': ('<Q', 8, False),
        'int64': ('<q', 8, True),
    }
    
    info = fmt_map.get(data_type)
    if not info:
        print(f"  [Unknown integer type: {data_type}]")
        return
    
    fmt_str, elem_size, is_signed = info
    max_elements = min(count, len(data) // elem_size)
    
    if max_elements == 0:
        print("  [No data to display]")
        return
    
    print(f"\n  {'Offset':<12} {'Hex':<20} {'Decimal':<14} {'Notes'}")
    print(f"  {'-'*12} {'-'*20} {'-'*14} {'-'*30}")
    
    for i in range(max_elements):
        offset = i * elem_size
        addr = base_address + offset
        chunk = data[offset:offset + elem_size]
        
        if len(chunk) < elem_size:
            chunk = chunk.ljust(elem_size, b'\x00')
        
        try:
            value = struct.unpack(fmt_str, chunk)[0]
            
            # Format hex based on size
            hex_width = elem_size * 2
            hex_str = f"0x{value:0{hex_width}x}" if not is_signed else \
                      f"0x{value & ((1 << (elem_size*8)) - 1):0{hex_width}x}"
            
            # Format decimal
            if is_signed:
                dec_str = f"{value}"
            else:
                dec_str = f"{value}"
            
            # Check for magic values (32-bit only)
            notes = ""
            if elem_size == 4:
                magic = MAGIC_VALUES.get(value & 0xFFFFFFFF)
                if magic:
                    notes = f"[{magic}]"
            
            # Check for ASCII characters (8-bit only)
            if elem_size == 1 and 32 <= value < 127:
                notes = f"'{chr(value)}' {notes}"
            
            print(f"  +0x{offset:04x}     {hex_str:<20} {dec_str:<14} {notes}")
            
        except struct.error:
            print(f"  +0x{offset:04x}     {'<unpack error>':<20}")
        except Exception as e:
            print(f"  +0x{offset:04x}     {'<error>':<20} ({e})")


# =============================================================================
# FIXED: Float data display
# =============================================================================
def display_float_data(data: bytes, count: int, base_address: int):
    """Display 32-bit floating point data."""
    max_elements = min(count, len(data) // 4)
    
    if max_elements == 0:
        print("  [No float data to display]")
        return
    
    print(f"\n  {'Offset':<12} {'Float Value':<20} {'Hex':<12} {'Notes'}")
    print(f"  {'-'*12} {'-'*20} {'-'*12} {'-'*30}")
    
    for i in range(max_elements):
        offset = i * 4
        addr = base_address + offset
        chunk = data[offset:offset + 4]
        
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b'\x00')
        
        try:
            float_val = struct.unpack('<f', chunk)[0]
            int_val = struct.unpack('<I', chunk)[0]
            
            # Detect special values
            special = ""
            if math.isnan(float_val):
                special = "(NaN)"
            elif math.isinf(float_val):
                special = "(+Inf)" if float_val > 0 else "(-Inf)"
            elif float_val == 0.0 and int_val != 0:
                special = "(Denormal)"
            
            # Choose format
            if abs(float_val) > 1e7 or (0 < abs(float_val) < 1e-6):
                val_str = f"{float_val:.6e}"
            elif abs(float_val) >= 1000:
                val_str = f"{float_val:12.2f}"
            else:
                val_str = f"{float_val:12.6f}"
            
            print(f"  +0x{offset:04x}     {val_str:<20} 0x{int_val:08x}  {special}")
            
        except Exception:
            print(f"  +0x{offset:04x}     {'<unpack error>':<20}")


# =============================================================================
# FIXED: Double data display
# =============================================================================
def display_double_data(data: bytes, count: int, base_address: int):
    """Display 64-bit double precision data."""
    max_elements = min(count, len(data) // 8)
    
    if max_elements == 0:
        print("  [No double data to display]")
        return
    
    print(f"\n  {'Offset':<12} {'Double Value':<24} {'Hex':<20} {'Notes'}")
    print(f"  {'-'*12} {'-'*24} {'-'*20} {'-'*20}")
    
    for i in range(max_elements):
        offset = i * 8
        addr = base_address + offset
        chunk = data[offset:offset + 8]
        
        if len(chunk) < 8:
            chunk = chunk.ljust(8, b'\x00')
        
        try:
            double_val = struct.unpack('<d', chunk)[0]
            int_val = struct.unpack('<Q', chunk)[0]
            
            special = ""
            if math.isnan(double_val):
                special = "(NaN)"
            elif math.isinf(double_val):
                special = "(+Inf)" if double_val > 0 else "(-Inf)"
            
            if abs(double_val) > 1e10 or (0 < abs(double_val) < 1e-10):
                val_str = f"{double_val:.10e}"
            else:
                val_str = f"{double_val:16.8f}"
            
            print(f"  +0x{offset:04x}     {val_str:<24} 0x{int_val:016x}  {special}")
            
        except Exception:
            print(f"  +0x{offset:04x}     {'<unpack error>':<24}")


# =============================================================================
# FIXED: String data display
# =============================================================================
def display_string_data(data: bytes, base_address: int):
    """Display string data with encoding detection."""
    if not data:
        print("  [No data]")
        return
    
    # Find null terminator
    null_pos = data.find(b'\x00')
    str_data = data[:null_pos] if null_pos != -1 else data
    
    # Try common encodings
    encodings = ['utf-8', 'ascii', 'latin-1', 'utf-16-le', 'utf-16-be']
    best_string = None
    best_encoding = None
    
    for enc in encodings:
        try:
            decoded = str_data.decode(enc)
            # Prefer UTF-8/ASCII over others
            if best_string is None or (enc in ('utf-8', 'ascii') and best_encoding not in ('utf-8', 'ascii')):
                best_string = decoded
                best_encoding = enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    if best_string:
        # Escape non-printable characters
        display = repr(best_string)[1:-1]  # Remove quotes from repr
        
        print(f"  Address: 0x{base_address:08x}")
        print(f"  String:  \"{display}\"")
        print(f"  Encoding: {best_encoding}")
        print(f"  Length:   {len(str_data)} bytes")
        
        # Check for null termination
        if null_pos != -1:
            print(f"  Null-terminated at offset {null_pos}")
        
        # Check for non-printable content
        non_printable = sum(1 for b in str_data if b < 32 or b >= 127)
        if non_printable > 0:
            print(f"  Non-printable bytes: {non_printable}/{len(str_data)} ({non_printable*100/len(str_data):.1f}%)")
        
        # Show hex for short strings
        if len(str_data) <= 32:
            print(f"  Hex:     {str_data.hex()}")
    else:
        print(f"  Address: 0x{base_address:08x}")
        print(f"  Content: <binary data, {len(str_data)} bytes>")
        if len(str_data) <= 64:
            print(f"  Hex:     {str_data.hex()}")


# =============================================================================
# FIXED: Hex data display
# =============================================================================
def display_hex_data(data: bytes, base_address: int):
    """Display raw hex data."""
    if not data:
        print("  [No data]")
        return
    
    print(f"  Address: 0x{base_address:08x}")
    print(f"  Size:    {len(data)} bytes")
    
    if len(data) <= 128:
        # Show full hex for small data
        print(f"  Hex:     {data.hex()}")
        
        # Group by words if multiple of 4
        if len(data) % 4 == 0 and len(data) >= 4:
            words = [data[i:i+4].hex() for i in range(0, len(data), 4)]
            print(f"  Words:   {' '.join(words)}")
    else:
        print(f"  First 64: {data[:64].hex()}")
        print(f"  Last 64:  {data[-64:].hex()}")
    
    # ASCII preview
    if len(data) > 0:
        preview = data[:64] if len(data) > 64 else data
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
        print(f"  Preview:  |{ascii_str}|")


# =============================================================================
# FIXED: Pointer analysis
# =============================================================================
def analyze_pointers(data: bytes, base_address: int, dev) -> List[Dict]:
    """Analyze data for potential pointers."""
    found_pointers = []
    
    # Check 32-bit pointers
    for i in range(0, len(data) - 3, 4):
        try:
            value = struct.unpack('<I', data[i:i+4])[0]
            if is_likely_pointer(value, 32):
                region = detect_memory_region(value, dev)
                found_pointers.append({
                    'offset': i,
                    'address': base_address + i,
                    'value': value,
                    'bits': 32,
                    'region': region
                })
        except Exception:
            continue
    
    # Check 64-bit pointers
    if len(data) >= 8:
        for i in range(0, len(data) - 7, 8):
            try:
                value = struct.unpack('<Q', data[i:i+8])[0]
                if is_likely_pointer(value, 64):
                    region = detect_memory_region(value, dev)
                    found_pointers.append({
                        'offset': i,
                        'address': base_address + i,
                        'value': value,
                        'bits': 64,
                        'region': region
                    })
            except Exception:
                continue
    
    return found_pointers


def is_likely_pointer(value: int, bits: int = 32) -> bool:
    """Determine if a value is likely a valid pointer."""
    if value == 0:
        return True  # NULL pointer
    
    if bits == 32:
        if value > 0xFFFFFFFF:
            return False
        for start, end, _ in POINTER_RANGES_32:
            if start <= value < end:
                return value % 4 == 0  # Aligned
        return False
    
    elif bits == 64:
        if value < 0x1000:  # Too low
            return False
        if value > 0xFFFFFFFF:
            return value % 8 == 0  # Aligned
        # In 32-bit range, check common mappings
        for start, end, _ in POINTER_RANGES_32:
            if start <= value < end:
                return value % 4 == 0
        return False
    
    return False


# =============================================================================
# FIXED: Shannon entropy calculation
# =============================================================================
def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Returns:
        float: Entropy value in bits per byte (0.0 - 8.0)
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    total = len(data)
    entropy = 0.0
    
    for count in counts:
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    
    return entropy


# =============================================================================
# FIXED: Memory attributes display
# =============================================================================
def display_memory_attributes(address: int, data: bytes, dev):
    """Display memory attributes and characteristics."""
    if not data:
        print("  Content: (empty)")
        return
    
    data_len = len(data)
    
    # Content analysis
    zero_bytes = data.count(b'\x00')
    ff_bytes = data.count(b'\xFF')
    ascii_bytes = sum(1 for b in data if 32 <= b < 127)
    
    if zero_bytes == data_len:
        print("  Content:  All zeros (erased/uninitialized)")
    elif ff_bytes == data_len:
        print("  Content:  All ones (erased flash)")
    elif zero_bytes > data_len * 0.9:
        print(f"  Content:  Mostly zeros ({zero_bytes*100/data_len:.1f}%)")
    elif ff_bytes > data_len * 0.9:
        print(f"  Content:  Mostly ones ({ff_bytes*100/data_len:.1f}%)")
    else:
        # Check for repeating pattern
        if len(data) >= 2:
            first_byte = data[0]
            if all(b == first_byte for b in data):
                print(f"  Content:  Repeated 0x{first_byte:02X}")
            else:
                print(f"  Content:  Mixed data")
    
    # Alignment
    alignment = "Unaligned"
    for align in [16, 8, 4, 2]:
        if address % align == 0:
            alignment = f"{align}-byte aligned"
            break
    print(f"  Alignment: {alignment}")
    
    # Entropy
    entropy = calculate_entropy(data)
    if entropy > 7.5:
        quality = "very high (likely encrypted/compressed/random)"
    elif entropy > 6.0:
        quality = "high"
    elif entropy > 3.0:
        quality = "moderate"
    elif entropy > 1.0:
        quality = "low (structured data)"
    else:
        quality = "very low (mostly constant)"
    print(f"  Entropy:   {entropy:.2f} bits/byte ({quality})")
    
    # ASCII content
    ascii_pct = (ascii_bytes / data_len) * 100
    if ascii_pct > 80:
        print(f"  ASCII:     {ascii_pct:.1f}% (textual data)")
    elif ascii_pct > 30:
        print(f"  ASCII:     {ascii_pct:.1f}% (mixed content)")
    else:
        print(f"  ASCII:     {ascii_pct:.1f}% (binary data)")
    
    # Region info
    region = detect_memory_region(address, dev)
    print(f"  Region:    {region}")


# =============================================================================
# FIXED: Main PEEK command function
# =============================================================================
def cmd_peek(args=None) -> int:
    """
    QSLCL PEEK Command v2.0 (FIXED)
    
    Reads and displays memory contents with:
    - Multiple data type interpretations
    - Hex dump with ASCII preview
    - Pointer detection and analysis
    - Entropy calculation
    - Memory region identification
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] PEEK: No arguments provided")
        print("[*] Usage: peek <address> [-s size] [-t type] [-c count]")
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
    address_str = getattr(args, 'address', '')
    size = getattr(args, 'size', DEFAULT_PEEK_SIZE)
    data_type = getattr(args, 'data_type', 'auto')
    count = getattr(args, 'count', 1)
    
    if not address_str:
        print("[!] No address specified")
        print("[*] Examples:")
        print("    peek 0x1000")
        print("    peek boot+0x100 -s 64")
        print("    peek 0x2000 -t float -c 4")
        print("    peek 0x3000 -t string -s 128")
        return 1
    
    print(f"[*] PEEK: address={address_str}, size={size}, type={data_type}, count={count}")
    
    # =========================================================================
    # Address resolution
    # =========================================================================
    partitions = []
    memory_regions = []
    
    if _use_qslcl:
        try:
            if _load_partitions:
                partitions = _load_partitions(dev)
        except Exception:
            pass
        
        try:
            if _detect_memory_regions:
                memory_regions = _detect_memory_regions(dev)
        except Exception:
            pass
    
    if _use_qslcl and _resolve_target:
        try:
            target_info = _resolve_target(address_str, partitions, memory_regions, dev)
            if target_info:
                address = target_info['address']
                available_size = target_info.get('size', MAX_PEEK_SIZE)
                
                print(f"[+] Resolved: 0x{address:08X}")
                print(f"[+] Available: {available_size} bytes")
                
                if target_info.get('partition_info'):
                    part = target_info['partition_info']
                    print(f"[+] Partition: {part['name']} (0x{part['offset']:08X}+0x{part['size']:08X})")
                elif target_info.get('region_info'):
                    region = target_info['region_info']
                    print(f"[+] Region: {region['name']}")
            else:
                print(f"[!] Could not resolve: '{address_str}'")
                if partitions:
                    print(f"[*] Available partitions:")
                    for p in sorted(partitions, key=lambda x: x.get('offset', 0))[:8]:
                        print(f"    {p['name']:<16} 0x{p['offset']:08X}-0x{p['offset']+p['size']:08X}")
                return 1
        except Exception as e:
            print(f"[!] Resolution failed: {e}")
            try:
                address = parse_address(address_str)
                available_size = MAX_PEEK_SIZE
            except Exception:
                print(f"[!] Cannot parse address: '{address_str}'")
                return 1
    else:
        try:
            address = parse_address(address_str)
            available_size = MAX_PEEK_SIZE
        except Exception:
            print(f"[!] Cannot parse address: '{address_str}'")
            return 1
    
    # =========================================================================
    # Size and type determination
    # =========================================================================
    if data_type == 'auto':
        data_type = auto_detect_data_type(address, size, count)
        print(f"[+] Auto-detected type: {data_type}")
    
    # Calculate total bytes
    bytes_per_element = TYPE_SIZES.get(data_type, size)
    if bytes_per_element <= 0:
        bytes_per_element = size
    total_bytes = bytes_per_element * count
    
    # Clamp to available size
    if total_bytes > available_size:
        print(f"[!] Requested {total_bytes} bytes exceeds available {available_size}")
        total_bytes = available_size
        count = max(1, total_bytes // bytes_per_element)
        print(f"[*] Adjusted to {total_bytes} bytes ({count} elements)")
    
    # Size limit
    if total_bytes > MAX_PEEK_SIZE:
        print(f"[!] Size {total_bytes} exceeds maximum {MAX_PEEK_SIZE}")
        total_bytes = MAX_PEEK_SIZE
        count = total_bytes // bytes_per_element
        print(f"[*] Capped to {MAX_PEEK_SIZE} bytes")
    
    if total_bytes <= 0:
        print("[!] Invalid size (zero bytes)")
        return 1
    
    print(f"[*] Reading {total_bytes} bytes ({count} × {bytes_per_element} bytes)")
    
    # =========================================================================
    # Read memory
    # =========================================================================
    success, raw_data, strategy = read_memory(dev, address, total_bytes)
    
    if not success or not raw_data:
        print(f"[!] All read strategies failed")
        return 1
    
    print(f"[+] Read {len(raw_data)} bytes via {strategy}")
    
    # Handle short reads
    if len(raw_data) < total_bytes:
        print(f"[!] Short read: got {len(raw_data)} of {total_bytes} bytes")
        raw_data = raw_data.ljust(total_bytes, b'\x00')
    
    # =========================================================================
    # Display results
    # =========================================================================
    print(f"\n{'='*60}")
    print(f"  PEEK: 0x{address:08X}")
    print(f"{'='*60}")
    
    # Memory region
    region = detect_memory_region(address, dev)
    print(f"\n[*] Region: {region}")
    
    # Hex dump (for reasonable sizes)
    if total_bytes <= 4096:
        print(f"\n[*] Hex Dump:")
        print(format_hex_dump(raw_data, address))
    elif total_bytes <= 65536:
        print(f"\n[*] Hex Dump (first 1024 bytes):")
        print(format_hex_dump(raw_data[:1024], address))
        print(f"\n[*] Hex Dump (last 256 bytes):")
        print(format_hex_dump(raw_data[-256:], address + len(raw_data) - 256))
    
    # Type-specific interpretation
    print(f"\n[*] Interpretation as '{data_type}':")
    
    try:
        if data_type in ('uint8', 'int8', 'char'):
            display_integer_data(raw_data, 1, count, data_type, address)
        elif data_type in ('uint16', 'int16', 'short'):
            display_integer_data(raw_data, 2, count, data_type, address)
        elif data_type in ('uint32', 'int32', 'int'):
            display_integer_data(raw_data, 4, count, data_type, address)
        elif data_type in ('uint64', 'int64', 'long'):
            display_integer_data(raw_data, 8, count, data_type, address)
        elif data_type == 'float':
            display_float_data(raw_data, count, address)
        elif data_type == 'double':
            display_double_data(raw_data, count, address)
        elif data_type in ('string',):
            display_string_data(raw_data, address)
        elif data_type in ('hex', 'bytes', 'raw'):
            display_hex_data(raw_data, address)
        else:
            print(f"  [!] Unknown type: {data_type}")
            display_integer_data(raw_data, 4, count, 'uint32', address)
    except Exception as e:
        print(f"  [!] Interpretation error: {e}")
        display_hex_data(raw_data, address)
    
    # Pointer analysis
    if len(raw_data) >= 4:
        print(f"\n[*] Pointer Analysis:")
        pointers = analyze_pointers(raw_data, address, dev)
        
        if pointers:
            print(f"  Found {len(pointers)} potential pointer(s):")
            for p in pointers[:8]:
                if p['bits'] == 32:
                    print(f"    +0x{p['offset']:04x}: 0x{p['value']:08X} → {p['region']}")
                else:
                    print(f"    +0x{p['offset']:04x}: 0x{p['value']:016X} → {p['region']}")
            if len(pointers) > 8:
                print(f"    ... and {len(pointers) - 8} more")
        else:
            print("  No obvious pointers found")
    
    # Memory attributes
    print(f"\n[*] Memory Attributes:")
    display_memory_attributes(address, raw_data, dev)
    
    print(f"\n{'='*60}")
    
    return 0


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_peek_arguments(parser) -> None:
    """Add peek-specific arguments to an argument parser."""
    parser.add_argument(
        'address',
        help='Memory address (hex, decimal, partition, partition+offset)'
    )
    parser.add_argument(
        '-s', '--size',
        type=int,
        default=DEFAULT_PEEK_SIZE,
        help=f'Bytes per element (default: {DEFAULT_PEEK_SIZE})'
    )
    parser.add_argument(
        '-t', '--data-type',
        choices=['auto', 'uint8', 'int8', 'uint16', 'int16', 'uint32', 'int32',
                 'uint64', 'int64', 'float', 'double', 'string', 'hex', 'bytes',
                 'char', 'byte', 'short', 'int', 'long'],
        default='auto',
        help='Data type interpretation (default: auto)'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=1,
        help='Number of elements to display (default: 1)'
    )
    return parser


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] peek.py - QSLCL PEEK Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py peek <address> [options]")
    print()
    print("[*] Examples:")
    print("    qslcl peek 0x1000")
    print("    qslcl peek boot+0x100 -s 64")
    print("    qslcl peek 0x2000 -t float -c 4")
    print("    qslcl peek 0x3000 -t string -s 128")
    print("    qslcl peek GPT+0x200 -s 32 -t hex")