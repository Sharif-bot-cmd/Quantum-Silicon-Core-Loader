#!/usr/bin/env python3
"""
poke.py - QSLCL POKE Command Module v2.1 (CLEANED)
Precision memory writes with type support, bit operations, and verification
"""

import os
import sys
import re
import struct
import time
from typing import Optional, Tuple

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
POKE_TIMEOUT = 10.0           # Write operation timeout
VERIFY_TIMEOUT = 5.0          # Verification read timeout
MAX_RETRIES = 3               # Max retries

# Data type definitions: (byte_size, unsigned_fmt, signed_fmt, category)
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

CRITICAL_KEYWORDS = ['boot', 'bootrom', 'brom', 'irom', 'sbl', 'pbl', 'xbl',
                      'aboot', 'lk', 'tz', 'tee', 'keymaster', 'sec', 'gpt']


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_address(addr_str: str) -> int:
    """Parse address: 0x1000, $1000, 4096, 1000h"""
    if isinstance(addr_str, int):
        return addr_str
    
    s = str(addr_str).strip().lower()
    if s.startswith('0x'):
        return int(addr_str[2:], 16)
    if s.startswith('$'):
        return int(addr_str[1:], 16)
    if s.endswith('h'):
        return int(addr_str[:-1], 16)
    
    try:
        return int(addr_str, 16)
    except ValueError:
        return int(addr_str, 10)


def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve poke target to address"""
    # Try partition+offset
    if '+' in target:
        name, offset_str = target.split('+', 1)
        offset = parse_address(offset_str.strip())
        for p in partitions:
            if p.get('name', '').lower() == name.strip().lower():
                return {'address': p['offset'] + offset, 'info': f"Partition: {p['name']}"}
    
    # Try partition name
    for p in partitions:
        if p.get('name', '').lower() == target.lower():
            return {'address': p['offset'], 'info': f"Partition: {p['name']}"}
    
    # Try raw address
    try:
        return {'address': parse_address(target), 'info': 'Direct address'}
    except ValueError:
        return None


def safe_eval(expr: str) -> int:
    """Safely evaluate a math expression with hex support"""
    expr = expr.strip()
    if not expr:
        raise ValueError("Empty expression")
    
    # Only allow safe characters
    allowed = set('0123456789abcdefABCDEFxX.+-*/()&|^~% ')
    if not all(c in allowed for c in expr):
        raise ValueError("Expression contains unsafe characters")
    
    # Convert hex literals
    expr = re.sub(r'0[xX][0-9a-fA-F]+', lambda m: str(int(m.group(0), 16)), expr)
    
    try:
        return int(eval(expr, {"__builtins__": {}}))
    except Exception as e:
        raise ValueError(f"Expression error: {e}")


# =============================================================================
# DATA TYPE PACKING
# =============================================================================
def resolve_type(type_name: str) -> str:
    """Resolve type alias to canonical name"""
    return TYPE_ALIASES.get(type_name.lower().strip(), type_name.lower().strip())


def auto_detect_type(value: str, size: int = 4) -> str:
    """Auto-detect the best data type for a value"""
    value = value.strip()
    
    # Quoted strings
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return 'string'
    
    # Float
    clean = value.lower().replace('0x', '').replace(' ', '')
    if '.' in clean or 'e' in clean or clean in ('nan', 'inf', '-inf'):
        return 'double' if size == 8 else 'float'
    
    # Hex - determine size by length
    if re.match(r'^[0-9a-f]+$', clean) and len(clean) >= 2:
        sizes = {1: 'uint8', 2: 'uint16', 4: 'uint32', 8: 'uint64'}
        byte_len = len(clean) // 2
        return sizes.get(byte_len, 'hex' if byte_len > 8 else 'uint32')
    
    # Expression
    if any(c in value for c in '+-*/&|^~()'):
        sizes = {1: 'uint8', 2: 'uint16', 8: 'uint64'}
        return sizes.get(size, 'uint32')
    
    # Default by size
    return {1: 'uint8', 2: 'uint16', 8: 'uint64'}.get(size, 'uint32')


def pack_value(value, type_name: str, size: int = 0) -> Tuple[bytes, str]:
    """Pack a value into bytes based on type"""
    name = resolve_type(type_name)
    
    if name not in DATA_TYPES:
        raise ValueError(f"Unknown type: {type_name}. Valid: {', '.join(sorted(DATA_TYPES))}")
    
    byte_sz, ufmt, sfmt, cat = DATA_TYPES[name]
    
    if cat == 'int':
        actual_sz = byte_sz
        # Convert to int
        if isinstance(value, str):
            try:
                int_val = int(value, 0)
            except ValueError:
                int_val = safe_eval(value)
        else:
            int_val = int(value)
        
        is_signed = name.startswith('int')
        
        # Clamp to range
        if is_signed:
            min_v, max_v = -(1 << (byte_sz * 8 - 1)), (1 << (byte_sz * 8 - 1)) - 1
        else:
            min_v, max_v = 0, (1 << (byte_sz * 8)) - 1
        
        if int_val < min_v or int_val > max_v:
            print(f"[!] Value {int_val} outside [{min_v}, {max_v}] for {name}, clamping")
            int_val = max(min_v, min(int_val, max_v))
        
        fmt = f'<{sfmt if is_signed else ufmt}'
        data = struct.pack(fmt, int_val)
        desc = f"{int_val} (0x{data.hex().upper()})"
        return data, desc
    
    elif cat == 'float':
        actual_sz = byte_sz
        if isinstance(value, str):
            vl = value.strip().lower()
            fval = {'nan': float('nan'), 'inf': float('inf'), '-inf': float('-inf')}.get(vl, float(value))
        else:
            fval = float(value)
        
        data = struct.pack(f'<{ufmt}', fval)
        desc = f"{fval} (0x{data.hex().upper()})"
        return data, desc
    
    elif cat == 'str':
        # Unquote
        if isinstance(value, str):
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            value = bytes(value, 'utf-8').decode('unicode_escape')
            data = value.encode('utf-8')
        elif isinstance(value, bytes):
            data = value
        else:
            data = str(value).encode('utf-8')
        
        actual_sz = len(data) if not size else min(len(data), size)
        if size > 0:
            data = data[:size].ljust(size, b'\x00')
            actual_sz = size
        
        display = value if isinstance(value, str) else data.decode('utf-8', errors='replace')
        desc = f'"{display}" ({len(data)} bytes)'
        return data, desc
    
    elif cat == 'hex':
        if isinstance(value, bytes):
            data = value
        elif isinstance(value, str):
            clean = value.strip().replace(' ', '').replace('0x', '').replace('0X', '')
            if len(clean) % 2:
                clean = '0' + clean
            data = bytes.fromhex(clean)
        else:
            data = bytes(value)
        
        actual_sz = len(data)
        if size > 0:
            data = data[:size].ljust(size, b'\x00')
            actual_sz = size
        
        desc = f"0x{data.hex().upper()} ({len(data)} bytes)"
        return data, desc
    
    return b"", ""


def interpret_bytes(data: bytes, type_name: str) -> str:
    """Interpret bytes as a data type for display"""
    if not data:
        return "(empty)"
    
    name = resolve_type(type_name)
    if name not in DATA_TYPES:
        return f"0x{data.hex().upper()}"
    
    byte_sz, ufmt, sfmt, cat = DATA_TYPES[name]
    
    try:
        if cat == 'int':
            if name.startswith('int'):
                val = struct.unpack(f'<{sfmt}', data[:byte_sz])[0]
            else:
                val = struct.unpack(f'<{ufmt}', data[:byte_sz])[0]
            return f"{val} (0x{val:0{byte_sz*2}X})"
        
        elif cat == 'float':
            val = struct.unpack(f'<{ufmt}', data[:byte_sz])[0]
            return f"{val}"
        
        elif cat == 'str':
            null = data.find(b'\x00')
            txt = data[:null].decode('utf-8', errors='replace') if null != -1 else data.decode('utf-8', errors='replace')
            txt = txt.replace('\n', '\\n').replace('\t', '\\t')[:50]
            return f'"{txt}"'
        
        else:
            return f"0x{data.hex().upper()}"
    except:
        return f"0x{data.hex().upper()}"


def apply_bitop(original: bytes, operand: bytes, op: str) -> bytes:
    """Apply bitwise operation between two byte sequences"""
    max_len = max(len(original), len(operand))
    a = original.ljust(max_len, b'\x00')
    b = operand.ljust(max_len, b'\x00')
    
    op = op.upper()
    result = bytearray()
    for x, y in zip(a, b):
        if op == 'AND':
            result.append(x & y)
        elif op == 'OR':
            result.append(x | y)
        elif op == 'XOR':
            result.append(x ^ y)
    return bytes(result)


# =============================================================================
# MAIN POKE COMMAND
# =============================================================================
def cmd_poke(args=None) -> int:
    """
    QSLCL POKE - Precision memory writer
    
    Examples:
        poke 0x1000 0x1234                    - Write hex value
        poke 0x1000 0x12345678 -t uint32      - Write as uint32
        poke boot+0x100 42                    - Write to partition offset
        poke 0x2000 3.14 -t float             - Write float
        poke 0x3000 'hello' -t string -s 16   - Write string (16 bytes)
        poke 0x4000 0xFF -t uint8 --bitop XOR - XOR with existing value
        poke 0x5000 '0xFF + 0x10' -t uint32   - Evaluate expression
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: poke <address> <value> [-t TYPE] [-s SIZE] [options]")
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
    addr_str = getattr(args, 'address', None)
    value_str = getattr(args, 'value', None)
    
    if not addr_str:
        print("[!] No address specified")
        print("[*] Examples: poke 0x1000 0x1234, poke boot+0x100 42 -t uint32")
        return 1
    
    if not value_str:
        print("[!] No value specified")
        return 1
    
    data_type = getattr(args, 'data_type', 'auto')
    size = getattr(args, 'size', 4)
    force = getattr(args, 'force', False)
    no_verify = getattr(args, 'no_verify', False)
    bit_op = getattr(args, 'bit_op', None)
    
    # =========================================================================
    # ADDRESS RESOLUTION
    # =========================================================================
    partitions = []
    try:
        partitions = load_partitions(dev)
    except:
        pass
    
    region_info = "Direct address"
    target_info = resolve_target(addr_str, partitions, dev)
    
    if target_info:
        address = target_info['address']
        region_info = target_info.get('info', region_info)
    else:
        try:
            address = parse_address(addr_str)
        except ValueError as e:
            print(f"[!] Cannot parse address: {e}")
            return 1
    
    print(f"[+] Address: 0x{address:08X} ({region_info})")
    
    # =========================================================================
    # EXPRESSION EVALUATION
    # =========================================================================
    value_to_use = str(value_str)
    
    if any(c in value_to_use for c in '+-*/&|^~()') and \
       not (value_to_use.startswith('"') or value_to_use.startswith("'")):
        try:
            evaluated = safe_eval(value_to_use)
            print(f"[+] Expression: {value_to_use} = {evaluated} (0x{evaluated:X})")
            value_to_use = str(evaluated)
        except ValueError as e:
            print(f"[!] {e}")
            return 1
    
    # =========================================================================
    # DATA TYPE
    # =========================================================================
    if data_type == 'auto':
        data_type = auto_detect_type(value_to_use, size)
        print(f"[+] Auto-detected type: {data_type}")
    
    # =========================================================================
    # VALUE PACKING
    # =========================================================================
    try:
        write_data, value_desc = pack_value(value_to_use, data_type, size)
    except ValueError as e:
        print(f"[!] Value error: {e}")
        return 1
    
    actual_size = len(write_data)
    
    print(f"[+] Type: {resolve_type(data_type)}")
    print(f"[+] Value: {value_desc}")
    print(f"[+] Size: {actual_size} byte(s)")
    
    if actual_size == 0:
        print("[!] Empty data")
        return 1
    
    # =========================================================================
    # ALIGNMENT CHECK
    # =========================================================================
    if actual_size > 1 and address % actual_size != 0:
        print(f"\n[!] Unaligned: addr 0x{address:X} not aligned to {actual_size} bytes")
        if not force:
            if input("    Continue? (y/N): ").lower() != 'y':
                print("[*] Cancelled")
                return 0
    
    # =========================================================================
    # SAFETY CHECK
    # =========================================================================
    region_lower = region_info.lower()
    is_critical = any(kw in region_lower for kw in CRITICAL_KEYWORDS)
    
    if is_critical and not force:
        print(f"\n{'='*50}")
        print(f"  ⚠️  CRITICAL REGION: {region_info}")
        print(f"  Writing to 0x{address:08X} may cause damage!")
        print(f"{'='*50}")
        if input("\n  Type 'POKE' to confirm: ") != 'POKE':
            print("[*] Cancelled")
            return 0
    
    # =========================================================================
    # PRE-READ FOR BITOPS OR DISPLAY
    # =========================================================================
    original_data = None
    original_desc = "(not read)"
    
    if not no_verify or bit_op:
        print(f"\n[*] Reading current value...")
        
        read_payload = struct.pack("<II", address, actual_size)
        
        if "READ" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=VERIFY_TIMEOUT)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                original_data = status.get("extra", b"")[:actual_size]
                original_desc = interpret_bytes(original_data, data_type)
                print(f"[+] Current: {original_desc}")
            else:
                print(f"[!] Read failed: {status.get('name', 'Unknown')}")
        else:
            print(f"[!] No read response")
    
    # =========================================================================
    # BIT OPERATIONS
    # =========================================================================
    if bit_op and original_data:
        bit_op = bit_op.upper()
        print(f"\n[*] Applying {bit_op}...")
        
        result = apply_bitop(original_data, write_data, bit_op)
        result_desc = interpret_bytes(result, data_type)
        
        print(f"[+] Original:  {original_data.hex().upper()}")
        print(f"[+] Operand:   {write_data.hex().upper()}")
        print(f"[+] Result:    {result.hex().upper()}")
        print(f"[+] {bit_op}:     {original_desc} {bit_op} {value_desc} = {result_desc}")
        
        write_data = result
        value_desc = result_desc
    
    # =========================================================================
    # CONFIRMATION
    # =========================================================================
    print(f"\n{'='*45}")
    print(f"  POKE: 0x{address:08X} ← {value_desc}")
    if original_data:
        print(f"  Before: {original_desc}")
    if bit_op:
        print(f"  Operation: {bit_op}")
    print(f"{'='*45}")
    
    if not force:
        if input("\n  Confirm? (y/N): ").lower() != 'y':
            print("[*] Cancelled")
            return 0
    
    # =========================================================================
    # WRITE
    # =========================================================================
    print(f"\n[*] Writing...")
    
    write_payload = struct.pack("<II", address, actual_size) + write_data
    
    for attempt in range(MAX_RETRIES):
        if "POKE" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "POKE", write_payload, timeout=POKE_TIMEOUT)
        elif "WRITE" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "WRITE", write_payload, timeout=POKE_TIMEOUT)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", write_payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=POKE_TIMEOUT)
        
        if resp and decode_runtime_result(resp).get("severity") == "SUCCESS":
            print("[+] Write accepted")
            break
        else:
            if attempt < MAX_RETRIES - 1:
                print(f"[!] Retry {attempt+2}/{MAX_RETRIES}...")
                time.sleep(0.2 * (attempt + 1))
            else:
                print("[!] Write failed after all retries")
                return 1
    
    # =========================================================================
    # VERIFICATION
    # =========================================================================
    if not no_verify:
        print(f"[*] Verifying...")
        time.sleep(0.05)
        
        read_payload = struct.pack("<II", address, actual_size)
        
        if "READ" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", read_payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=VERIFY_TIMEOUT)
        
        if resp:
            status = decode_runtime_result(resp)
            vdata = status.get("extra", b"")[:actual_size]
            
            if vdata == write_data:
                print(f"[+] Verify: ✓ PASS - {interpret_bytes(vdata, data_type)}")
            else:
                print(f"[!] Verify: ✗ FAIL")
                print(f"    Expected: {write_data.hex().upper()}")
                print(f"    Got:      {vdata.hex().upper()}")
                # Show diffs
                for i in range(min(len(write_data), len(vdata))):
                    if write_data[i] != vdata[i]:
                        print(f"    Byte {i}: 0x{write_data[i]:02X} vs 0x{vdata[i]:02X}")
        else:
            print(f"[!] Verify read failed")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print(f"\n{'='*45}")
    print(f"  POKE COMPLETE")
    print(f"  Address:  0x{address:08X}")
    print(f"  Type:     {resolve_type(data_type)}")
    print(f"  Size:     {actual_size} byte(s)")
    if original_data:
        final = vdata if not no_verify and 'vdata' in dir() else write_data
        print(f"  Before:   {original_desc}")
        print(f"  After:    {interpret_bytes(final, data_type)}")
    print(f"{'='*45}")
    
    return 0


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] poke.py - QSLCL POKE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py poke <address> <value> [options]")