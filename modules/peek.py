#!/usr/bin/env python3
"""
peek.py - QSLCL PEEK Command Module v2.1 (CLEANED)
Memory inspection with type interpretation, pointer analysis, and hex dump
"""

import os
import sys
import re
import struct
import time
import math
from typing import Optional, List, Dict, Tuple

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
PEEK_TIMEOUT = 10.0
MAX_PEEK_SIZE = 1024 * 1024
DEFAULT_SIZE = 4

# Type definitions: (byte_size, unsigned_fmt, signed_fmt, category)
DATA_TYPES = {
    'uint8':  (1, 'B', 'b', 'int'),   'int8':   (1, 'B', 'b', 'int'),
    'uint16': (2, 'H', 'h', 'int'),   'int16':  (2, 'H', 'h', 'int'),
    'uint32': (4, 'I', 'i', 'int'),   'int32':  (4, 'I', 'i', 'int'),
    'uint64': (8, 'Q', 'q', 'int'),   'int64':  (8, 'Q', 'q', 'int'),
    'float':  (4, 'f', 'f', 'float'), 'double': (8, 'd', 'd', 'float'),
    'string': (0, None, None, 'str'), 'hex':    (0, None, None, 'hex'),
}

TYPE_ALIASES = {
    'char': 'int8', 'byte': 'uint8', 'short': 'int16', 'ushort': 'uint16',
    'int': 'int32', 'uint': 'uint32', 'long': 'int64', 'ulong': 'uint64',
    'f': 'float', 'd': 'double', 's': 'string', 'h': 'hex',
}

# Magic value detection
MAGIC_VALUES = {
    0x00000000: "NULL",
    0xFFFFFFFF: "ALL_ONES",
    0xDEADBEEF: "DEADBEEF",
    0xCAFEBABE: "CAFEBABE (Java)",
    0xBAADF00D: "BAADF00D (uninit heap)",
    0xFEEDFACE: "FEEDFACE",
    0xFEEDF00D: "FEEDF00D",
    0xAAAAAAAA: "ALT_BITS_1010",
    0x55555555: "ALT_BITS_0101",
}

# Pointer ranges
PTR_RANGES_32 = [
    (0x00000100, 0x000FFFFF, "Low memory"),
    (0x10000000, 0x60000000, "MMIO"),
    (0x80000000, 0xC0000000, "DRAM"),
    (0xC0000000, 0xFFFFFFFF, "Kernel"),
]
PTR_RANGES_64 = [
    (0x00000000FFFFFFFF, 0x0000FFFFFFFFFFFF, "Low 64-bit"),
    (0xFFFF000000000000, 0xFFFFFFFFFFFFFFFF, "Kernel 64-bit"),
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_address(addr_str: str) -> int:
    """Parse address: 0x1000, $1000, 4096, 1000h"""
    if isinstance(addr_str, int):
        return addr_str
    s = str(addr_str).strip().lower()
    if s.startswith('0x'): return int(addr_str[2:], 16)
    if s.startswith('$'): return int(addr_str[1:], 16)
    if s.endswith('h'): return int(addr_str[:-1], 16)
    try: return int(addr_str, 16)
    except ValueError: return int(addr_str, 10)


def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve peek target to address"""
    if '+' in target:
        name, off_str = target.split('+', 1)
        offset = parse_address(off_str.strip())
        for p in partitions:
            if p.get('name', '').lower() == name.strip().lower():
                return {'address': p['offset'] + offset, 'info': f"Partition: {p['name']}", 'partition': p}
    
    for p in partitions:
        if p.get('name', '').lower() == target.lower():
            return {'address': p['offset'], 'info': f"Partition: {p['name']}", 'partition': p}
    
    try:
        return {'address': parse_address(target), 'info': 'Direct address', 'partition': None}
    except ValueError:
        return None


def resolve_type(type_name: str) -> str:
    """Resolve type alias"""
    return TYPE_ALIASES.get(type_name.lower().strip(), type_name.lower().strip())


def detect_region(address: int) -> str:
    """Detect memory region by address range"""
    regions = [
        (0x00000000, 0x00010000, "Boot ROM"),
        (0x00010000, 0x10000000, "Flash/ROM"),
        (0x10000000, 0x60000000, "MMIO/Peripheral"),
        (0x80000000, 0xC0000000, "DRAM"),
        (0xC0000000, 0xFFFFFFFF, "Kernel/System"),
    ]
    for start, end, name in regions:
        if start <= address < end:
            return f"{name} [0x{start:08X}-0x{end:08X}]"
    return "Unknown Region" if address < 0x100000000 else "64-bit Address Space"


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy (0.0-8.0 bits/byte)"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts if c > 0)


def is_pointer_32(val: int) -> bool:
    """Check if 32-bit value looks like a pointer"""
    if val == 0: return True
    for start, end, _ in PTR_RANGES_32:
        if start <= val < end:
            return val % 4 == 0
    return False


def is_pointer_64(val: int) -> bool:
    """Check if 64-bit value looks like a pointer"""
    if val == 0: return True
    if val < 0x1000: return False
    if val <= 0xFFFFFFFF:
        return is_pointer_32(val)
    return val % 8 == 0


# =============================================================================
# DISPLAY FUNCTIONS
# =============================================================================
def hex_dump(data: bytes, base: int, max_lines: int = 256) -> str:
    """Format hex dump with ASCII"""
    if not data:
        return "  [No data]"
    
    lines = []
    chunk_size = 16
    
    for off in range(0, len(data), chunk_size):
        if off // chunk_size >= max_lines:
            lines.append(f"  ... ({len(data) - off} more bytes)")
            break
        
        chunk = data[off:off+chunk_size]
        addr = base + off
        
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {addr:08x}:  {hex_str:<48} |{ascii_str}|")
    
    return '\n'.join(lines)


def display_int(data: bytes, type_name: str, count: int, base: int):
    """Display integer data"""
    name = resolve_type(type_name)
    if name not in DATA_TYPES:
        print(f"  [Unknown type: {type_name}]")
        return
    
    byte_sz, ufmt, sfmt, _ = DATA_TYPES[name]
    is_signed = name.startswith('int')
    fmt = f'<{sfmt if is_signed else ufmt}'
    
    max_el = min(count, len(data) // byte_sz)
    if max_el == 0:
        print("  [No data]")
        return
    
    print(f"\n  {'Offset':<10} {'Value':<22} {'Notes'}")
    print(f"  {'-'*10} {'-'*22} {'-'*30}")
    
    for i in range(max_el):
        off = i * byte_sz
        chunk = data[off:off+byte_sz].ljust(byte_sz, b'\x00')
        val = struct.unpack(fmt, chunk)[0]
        
        hex_w = byte_sz * 2
        disp_val = val if is_signed else (val & ((1 << (byte_sz*8))-1))
        hex_str = f"0x{disp_val:0{hex_w}x}"
        
        notes = ""
        if byte_sz == 4:
            magic = MAGIC_VALUES.get(val & 0xFFFFFFFF)
            if magic: notes = f"[{magic}]"
        if byte_sz == 1 and 32 <= val < 127:
            notes = f"'{chr(val)}' {notes}"
        
        print(f"  +0x{off:04x}   {hex_str:<22} {notes}")


def display_float(data: bytes, count: int, base: int, is_double: bool = False):
    """Display float/double data"""
    byte_sz = 8 if is_double else 4
    fmt = '<d' if is_double else '<f'
    type_name = 'double' if is_double else 'float'
    
    max_el = min(count, len(data) // byte_sz)
    if max_el == 0:
        print("  [No data]")
        return
    
    print(f"\n  {'Offset':<10} {'Value':<24} {'Hex'}")
    print(f"  {'-'*10} {'-'*24} {'-'*18}")
    
    for i in range(max_el):
        off = i * byte_sz
        chunk = data[off:off+byte_sz].ljust(byte_sz, b'\x00')
        val = struct.unpack(fmt, chunk)[0]
        
        special = ""
        if math.isnan(val): special = "NaN"
        elif math.isinf(val): special = "+Inf" if val > 0 else "-Inf"
        
        int_val = struct.unpack('<Q' if is_double else '<I', chunk)[0]
        hex_w = 16 if is_double else 8
        print(f"  +0x{off:04x}   {val:<24} 0x{int_val:0{hex_w}x} {special}")


def display_string(data: bytes, base: int):
    """Display string data"""
    if not data:
        print("  [No data]")
        return
    
    null_pos = data.find(b'\x00')
    str_data = data[:null_pos] if null_pos != -1 else data
    
    # Try encodings
    for enc in ['utf-8', 'ascii', 'latin-1']:
        try:
            decoded = str_data.decode(enc)
            display = repr(decoded)[1:-1]
            print(f"  String:   \"{display}\"")
            print(f"  Encoding: {enc}")
            print(f"  Length:   {len(str_data)} bytes")
            if null_pos != -1:
                print(f"  Null-terminated at +0x{null_pos:x}")
            if len(str_data) <= 32:
                print(f"  Hex:      {str_data.hex()}")
            return
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    print(f"  Content:  <binary, {len(str_data)} bytes>")
    print(f"  Hex:      {str_data[:32].hex()}")


def display_hex(data: bytes, base: int):
    """Display raw hex"""
    if not data:
        print("  [No data]")
        return
    
    print(f"  Size:     {len(data)} bytes")
    
    if len(data) <= 128:
        print(f"  Hex:      {data.hex()}")
        if len(data) % 4 == 0:
            words = ' '.join(data[i:i+4].hex() for i in range(0, len(data), 4))
            print(f"  Words:    {words}")
    else:
        print(f"  First 64: {data[:64].hex()}")
        print(f"  Last 64:  {data[-64:].hex()}")
    
    preview = data[:64]
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
    print(f"  Preview:  |{ascii_str}|")


def analyze_pointers(data: bytes, base: int, bits: int = 32) -> List[Dict]:
    """Find potential pointers in data"""
    found = []
    
    if bits == 32:
        for i in range(0, len(data)-3, 4):
            val = struct.unpack('<I', data[i:i+4])[0]
            if is_pointer_32(val):
                region = detect_region(val)
                found.append({'offset': i, 'address': base+i, 'value': val, 'region': region})
    else:
        for i in range(0, len(data)-7, 8):
            val = struct.unpack('<Q', data[i:i+8])[0]
            if is_pointer_64(val):
                region = detect_region(val)
                found.append({'offset': i, 'address': base+i, 'value': val, 'region': region})
    
    return found


# =============================================================================
# MAIN PEEK COMMAND
# =============================================================================
def cmd_peek(args=None) -> int:
    """
    QSLCL PEEK - Memory inspector with type interpretation
    
    Examples:
        peek 0x1000                          - Read 4 bytes at address
        peek 0x1000 -s 64                    - Read 64 bytes, hex dump
        peek boot+0x100 -s 32               - Read from partition offset
        peek 0x2000 -t float -c 4           - Read 4 floats
        peek 0x3000 -t string -s 128        - Read string (128 bytes)
        peek 0x4000 -t uint32 -c 8          - Read 8 uint32 values
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: peek <address> [-s SIZE] [-t TYPE] [-c COUNT]")
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
    size = getattr(args, 'size', DEFAULT_SIZE)
    data_type = getattr(args, 'data_type', 'auto')
    count = getattr(args, 'count', 1)
    
    if not addr_str:
        print("[!] No address specified")
        print("[*] Examples: peek 0x1000, peek boot+0x100 -s 64, peek 0x2000 -t float")
        return 1
    
    # =========================================================================
    # ADDRESS RESOLUTION
    # =========================================================================
    partitions = []
    try:
        partitions = load_partitions(dev)
    except:
        pass
    
    target_info = resolve_target(addr_str, partitions, dev)
    
    if not target_info:
        print(f"[!] Cannot resolve: '{addr_str}'")
        if partitions:
            print(f"[*] Available partitions:")
            for p in sorted(partitions, key=lambda x: x['offset'])[:10]:
                print(f"    {p['name']:<16} 0x{p['offset']:08X}  {p['size']//1024}KB")
        return 1
    
    address = target_info['address']
    print(f"[+] Address: 0x{address:08X} ({target_info.get('info', '')})")
    
    # =========================================================================
    # TYPE AND SIZE
    # =========================================================================
    if data_type == 'auto':
        # Auto-detect based on context
        region = detect_region(address)
        if 'MMIO' in region:
            data_type = 'uint32'
        elif size == 1:
            data_type = 'uint8'
        elif size == 2:
            data_type = 'uint16'
        elif size == 8:
            data_type = 'uint64'
        elif size > 64:
            data_type = 'hex'
        else:
            data_type = 'uint32'
        print(f"[+] Auto-type: {data_type}")
    
    resolved_type = resolve_type(data_type)
    byte_sz = DATA_TYPES.get(resolved_type, (size, None, None, 'int'))[0]
    if byte_sz <= 0:
        byte_sz = size
    
    total_bytes = byte_sz * count
    total_bytes = min(total_bytes, MAX_PEEK_SIZE)
    
    print(f"[+] Reading {total_bytes} bytes ({count} × {byte_sz} bytes) as {resolved_type}")
    
    # =========================================================================
    # READ MEMORY
    # =========================================================================
    read_payload = struct.pack("<II", address, total_bytes)
    
    for attempt in range(3):
        if "READ" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=PEEK_TIMEOUT)
        elif "PEEK" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "PEEK", read_payload, timeout=PEEK_TIMEOUT)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=PEEK_TIMEOUT)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                raw_data = status.get("extra", b"")
                if raw_data:
                    break
            else:
                if _DEBUG:
                    print(f"[!] Read error: {status.get('name', 'Unknown')}")
        else:
            if _DEBUG:
                print(f"[!] No response (attempt {attempt+1})")
        
        time.sleep(0.1)
    else:
        print("[!] Failed to read memory")
        return 1
    
    actual = len(raw_data)
    if actual < total_bytes:
        print(f"[!] Short read: {actual}/{total_bytes} bytes")
    
    # =========================================================================
    # DISPLAY RESULTS
    # =========================================================================
    region = detect_region(address)
    
    print(f"\n{'='*60}")
    print(f"  PEEK: 0x{address:08X}  [{region}]")
    print(f"  Size: {actual} bytes, Type: {resolved_type}, Count: {count}")
    print(f"{'='*60}")
    
    # Hex dump
    if total_bytes <= 4096:
        print(f"\n[*] Hex Dump:")
        print(hex_dump(raw_data, address))
    elif total_bytes <= 65536:
        print(f"\n[*] First 1024 bytes:")
        print(hex_dump(raw_data[:1024], address, 64))
        print(f"\n[*] Last 256 bytes:")
        print(hex_dump(raw_data[-256:], address + len(raw_data) - 256, 16))
    else:
        print(f"\n[*] First 256 bytes:")
        print(hex_dump(raw_data[:256], address, 16))
    
    # Type-specific display
    print(f"\n[*] As {resolved_type}:")
    
    try:
        cat = DATA_TYPES.get(resolved_type, (0, None, None, 'int'))[3]
        
        if cat == 'int':
            display_int(raw_data, resolved_type, count, address)
        elif cat == 'float':
            if resolved_type == 'double':
                display_float(raw_data, count, address, is_double=True)
            else:
                display_float(raw_data, count, address)
        elif cat == 'str':
            display_string(raw_data, address)
        elif cat == 'hex':
            display_hex(raw_data, address)
        else:
            display_hex(raw_data, address)
    except Exception as e:
        print(f"  [!] Display error: {e}")
        display_hex(raw_data, address)
    
    # Pointer analysis
    if len(raw_data) >= 4:
        print(f"\n[*] Pointer Analysis:")
        ptrs32 = analyze_pointers(raw_data, address, 32)
        ptrs64 = analyze_pointers(raw_data, address, 64) if len(raw_data) >= 8 else []
        
        all_ptrs = ptrs32 + ptrs64
        if all_ptrs:
            print(f"  Found {len(all_ptrs)} potential pointer(s):")
            for p in all_ptrs[:10]:
                bits = 64 if p['value'] > 0xFFFFFFFF else 32
                hex_w = 16 if bits == 64 else 8
                print(f"    +0x{p['offset']:04x}: 0x{p['value']:0{hex_w}X} → {p['region']}")
            if len(all_ptrs) > 10:
                print(f"    ... and {len(all_ptrs)-10} more")
        else:
            print("  No pointers found")
    
    # Memory attributes
    print(f"\n[*] Memory Attributes:")
    zero_pct = raw_data.count(b'\x00') * 100 / max(actual, 1)
    ff_pct = raw_data.count(b'\xFF') * 100 / max(actual, 1)
    ascii_pct = sum(1 for b in raw_data if 32 <= b < 127) * 100 / max(actual, 1)
    entropy = calculate_entropy(raw_data)
    
    if zero_pct > 99:
        print(f"  Content:  All zeros (erased/uninitialized)")
    elif ff_pct > 99:
        print(f"  Content:  All ones (erased flash)")
    elif zero_pct > 90:
        print(f"  Content:  Mostly zeros ({zero_pct:.1f}%)")
    elif ff_pct > 90:
        print(f"  Content:  Mostly ones ({ff_pct:.1f}%)")
    else:
        # Check repeating pattern
        if len(raw_data) >= 2 and all(b == raw_data[0] for b in raw_data):
            print(f"  Content:  Repeated 0x{raw_data[0]:02X}")
        else:
            print(f"  Content:  Mixed data")
    
    print(f"  Entropy:   {entropy:.2f} bits/byte", end='')
    if entropy > 7.5:
        print(" (encrypted/compressed/random)")
    elif entropy > 6:
        print(" (high)")
    elif entropy > 3:
        print(" (moderate)")
    elif entropy > 1:
        print(" (low - structured)")
    else:
        print(" (very low - constant)")
    
    print(f"  ASCII:     {ascii_pct:.1f}%")
    print(f"  Zeros:     {zero_pct:.1f}%")
    print(f"  0xFFs:     {ff_pct:.1f}%")
    print(f"  Region:    {region}")
    
    print(f"\n{'='*60}")
    
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] peek.py - QSLCL PEEK Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py peek <address> [options]")