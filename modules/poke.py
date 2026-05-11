#!/usr/bin/env python3
"""
poke.py - QSLCL POKE Command Module v2.0 (FIXED)
Fixed: Import handling, value processing, expression evaluation,
       data type handling, error recovery, safety checks
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
POKE_TIMEOUT = 10.0          # Poke operation timeout
VERIFY_TIMEOUT = 5.0         # Verification timeout
MAX_RETRIES = 3              # Max retries for failed operations

# Critical memory regions that should trigger warnings
CRITICAL_REGION_KEYWORDS = [
    'boot', 'bootrom', 'brom', 'irom',
    'sbl', 'pbl', 'xbl', 'aboot', 'lk',
    'tz', 'trustzone', 'tee',
    'keymaster', 'sec',
    'gpt', 'partition_table',
    'recovery', 'bootloader',
    'system', 'vendor',
]


# =============================================================================
# FIXED: Address parsing
# =============================================================================
def parse_address(addr_str: str) -> int:
    """
    Parse address string in various formats.
    
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
    
    try:
        return int(addr_str, 16)
    except ValueError:
        try:
            return int(addr_str, 10)
        except ValueError:
            raise ValueError(f"Invalid address format: '{addr_str}'")


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
        timeout = POKE_TIMEOUT
    
    cmd_info = find_command(cmd_name)
    if cmd_info:
        cmd_type, cmd_key = cmd_info
        if cmd_type == "name":
            return _qslcl_dispatch(dev, cmd_key, payload, timeout=timeout)
        else:
            return _qslcl_dispatch(dev, str(cmd_key), payload, timeout=timeout)
    
    return _qslcl_dispatch(dev, cmd_name, payload, timeout=timeout)


# =============================================================================
# FIXED: Check response success
# =============================================================================
def is_success_response(resp) -> bool:
    """Check if response indicates success."""
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
# FIXED: Read memory helper
# =============================================================================
def read_memory(dev, address: int, size: int) -> Tuple[bool, Optional[bytes], str]:
    """
    Read memory from device.
    
    Returns:
        Tuple[bool, Optional[bytes], str]: (success, data, error_message)
    """
    if not _use_qslcl:
        return False, None, "QSLCL functions not available"
    
    try:
        read_payload = struct.pack("<II", address, size)
        resp = dispatch_command(dev, "READ", read_payload, timeout=VERIFY_TIMEOUT)
        
        if not resp:
            return False, None, "No response from device"
        
        status = _decode_runtime_result(resp)
        if status.get("severity") != "SUCCESS":
            return False, None, f"Read failed: {status.get('name', 'Unknown error')}"
        
        data = status.get("extra", b"")
        if len(data) < size:
            return False, data, f"Short read: got {len(data)}, expected {size}"
        
        return True, data[:size], ""
        
    except Exception as e:
        return False, None, f"Read exception: {type(e).__name__}: {e}"


# =============================================================================
# FIXED: Write memory helper
# =============================================================================
def write_memory(dev, address: int, data: bytes) -> Tuple[bool, str]:
    """
    Write data to device memory.
    
    Returns:
        Tuple[bool, str]: (success, error_message)
    """
    if not _use_qslcl:
        return False, "QSLCL functions not available"
    
    try:
        write_payload = struct.pack("<II", address, len(data)) + data
        
        # Try POKE first, then WRITE
        resp = dispatch_command(dev, "POKE", write_payload, timeout=POKE_TIMEOUT)
        if not resp or not is_success_response(resp):
            resp = dispatch_command(dev, "WRITE", write_payload, timeout=POKE_TIMEOUT)
        
        if not resp:
            return False, "No response from device"
        
        if not is_success_response(resp):
            if _use_qslcl and _decode_runtime_result:
                status = _decode_runtime_result(resp)
                return False, f"Write failed: {status.get('name', 'Unknown error')}"
            return False, "Write failed"
        
        return True, ""
        
    except Exception as e:
        return False, f"Write exception: {type(e).__name__}: {e}"


# =============================================================================
# FIXED: Safe expression evaluator
# =============================================================================
class SafeExpressionEvaluator:
    """Safely evaluate mathematical expressions with limited scope."""
    
    # Allowed functions and constants
    SAFE_FUNCTIONS = {
        'abs': abs,
        'round': round,
        'min': min,
        'max': max,
        'int': int,
        'float': float,
        'hex': hex,
        'bin': bin,
        'oct': oct,
        'len': len,
    }
    
    SAFE_CONSTANTS = {
        'True': True,
        'False': False,
        'None': None,
        'pi': 3.141592653589793,
        'e': 2.718281828459045,
    }
    
    # Allowed operators
    ALLOWED_OPS = set('0123456789abcdefABCDEFxX.+-*/<>()&|^~% ')
    
    @classmethod
    def evaluate(cls, expr: str) -> int:
        """
        Safely evaluate a mathematical expression.
        
        Args:
            expr: Expression string
        
        Returns:
            int: Result value
        
        Raises:
            ValueError: If expression is unsafe or evaluation fails
        """
        expr = expr.strip()
        
        if not expr:
            raise ValueError("Empty expression")
        
        # Security check: only allow safe characters
        if not all(c in cls.ALLOWED_OPS for c in expr):
            raise ValueError(
                "Expression contains unsafe characters. "
                "Only digits, hex (0x), and basic operators (+-*/()&|^~) are allowed."
            )
        
        # Convert hex literals to decimal for eval
        def hex_replace(match):
            return str(int(match.group(0), 16))
        
        expr = re.sub(r'0x[0-9a-fA-F]+', hex_replace, expr)
        
        # Also handle 0X prefix
        expr = re.sub(r'0X[0-9a-fA-F]+', hex_replace, expr)
        
        # Build safe evaluation environment
        safe_globals = {
            "__builtins__": {},
            **cls.SAFE_FUNCTIONS,
            **cls.SAFE_CONSTANTS
        }
        
        try:
            result = eval(expr, safe_globals)
            return int(result)
        except SyntaxError as e:
            raise ValueError(f"Syntax error in expression: {e}")
        except NameError as e:
            raise ValueError(f"Unknown name in expression: {e}")
        except ZeroDivisionError:
            raise ValueError("Division by zero in expression")
        except Exception as e:
            raise ValueError(f"Expression evaluation failed: {type(e).__name__}: {e}")


# =============================================================================
# FIXED: Data type system
# =============================================================================
class DataType:
    """Data type definitions and utilities for POKE operations."""
    
    # Type definitions: (name, byte_size, format_char_unsigned, format_char_signed, category)
    TYPES = {
        'uint8':  (1, 'B', 'b', 'integer'),
        'int8':   (1, 'b', 'b', 'integer'),
        'uint16': (2, 'H', 'h', 'integer'),
        'int16':  (2, 'h', 'h', 'integer'),
        'uint32': (4, 'I', 'i', 'integer'),
        'int32':  (4, 'i', 'i', 'integer'),
        'uint64': (8, 'Q', 'q', 'integer'),
        'int64':  (8, 'q', 'q', 'integer'),
        'float':  (4, 'f', 'f', 'float'),
        'double': (8, 'd', 'd', 'float'),
        'string': (0, None, None, 'string'),  # Variable size
        'hex':    (0, None, None, 'hex'),      # Variable size
    }
    
    # Aliases
    ALIASES = {
        'char': 'int8',
        'byte': 'uint8',
        'short': 'int16',
        'ushort': 'uint16',
        'int': 'int32',
        'uint': 'uint32',
        'long': 'int64',
        'ulong': 'uint64',
        'f': 'float',
        'd': 'double',
        's': 'string',
        'h': 'hex',
    }
    
    @classmethod
    def resolve(cls, type_name: str) -> str:
        """Resolve type alias to canonical name."""
        name = type_name.lower().strip()
        return cls.ALIASES.get(name, name)
    
    @classmethod
    def get_size(cls, type_name: str) -> int:
        """Get default byte size for a type."""
        name = cls.resolve(type_name)
        info = cls.TYPES.get(name)
        return info[0] if info else 0
    
    @classmethod
    def get_category(cls, type_name: str) -> str:
        """Get category (integer, float, string, hex) for a type."""
        name = cls.resolve(type_name)
        info = cls.TYPES.get(name)
        return info[4] if info else 'unknown'
    
    @classmethod
    def pack_value(cls, value, type_name: str, size: int = 0) -> Tuple[bytes, str]:
        """
        Pack a value into bytes according to type.
        
        Returns:
            Tuple[bytes, str]: (packed_bytes, description_string)
        """
        name = cls.resolve(type_name)
        category = cls.get_category(name)
        
        if category == 'integer':
            return cls._pack_integer(value, name)
        elif category == 'float':
            return cls._pack_float(value, name)
        elif category == 'string':
            return cls._pack_string(value, size)
        elif category == 'hex':
            return cls._pack_hex(value, size)
        else:
            raise ValueError(f"Unknown data type: {type_name}")
    
    @classmethod
    def _pack_integer(cls, value, type_name: str) -> Tuple[bytes, str]:
        """Pack an integer value."""
        info = cls.TYPES[type_name]
        byte_size = info[0]
        is_signed = type_name.startswith('int')
        
        try:
            if isinstance(value, (int, float)):
                int_value = int(value)
            elif isinstance(value, str):
                int_value = int(value, 0)
            else:
                raise ValueError(f"Cannot convert {type(value)} to integer")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid integer value: {e}")
        
        # Calculate range
        if is_signed:
            min_val = -(1 << (byte_size * 8 - 1))
            max_val = (1 << (byte_size * 8 - 1)) - 1
        else:
            min_val = 0
            max_val = (1 << (byte_size * 8)) - 1
        
        # Clamp value
        if int_value < min_val or int_value > max_val:
            print(f"[!] Value {int_value} outside range [{min_val}, {max_val}] for {type_name}")
            print(f"[*] Clamping to valid range")
            int_value = max(min_val, min(int_value, max_val))
        
        # Pack
        if is_signed:
            if byte_size == 1:
                data = struct.pack('<b', int_value)
            elif byte_size == 2:
                data = struct.pack('<h', int_value)
            elif byte_size == 4:
                data = struct.pack('<i', int_value)
            elif byte_size == 8:
                data = struct.pack('<q', int_value)
            else:
                data = int_value.to_bytes(byte_size, 'little', signed=True)
        else:
            if byte_size == 1:
                data = struct.pack('<B', int_value & 0xFF)
            elif byte_size == 2:
                data = struct.pack('<H', int_value & 0xFFFF)
            elif byte_size == 4:
                data = struct.pack('<I', int_value & 0xFFFFFFFF)
            elif byte_size == 8:
                data = struct.pack('<Q', int_value & 0xFFFFFFFFFFFFFFFF)
            else:
                data = int_value.to_bytes(byte_size, 'little')
        
        # Build description
        hex_str = data.hex().upper()
        desc = f"{int_value} (0x{hex_str})"
        
        return data, desc
    
    @classmethod
    def _pack_float(cls, value, type_name: str) -> Tuple[bytes, str]:
        """Pack a floating point value."""
        info = cls.TYPES[type_name]
        byte_size = info[0]
        fmt_char = info[2]
        
        if isinstance(value, str):
            value_lower = value.strip().lower()
            if value_lower == 'nan':
                float_value = float('nan')
            elif value_lower in ('inf', '+inf'):
                float_value = float('inf')
            elif value_lower == '-inf':
                float_value = float('-inf')
            else:
                float_value = float(value)
        else:
            float_value = float(value)
        
        data = struct.pack(f'<{fmt_char}', float_value)
        desc = f"{float_value} (0x{data.hex().upper()})"
        
        return data, desc
    
    @classmethod
    def _pack_string(cls, value, size: int) -> Tuple[bytes, str]:
        """Pack a string value."""
        if isinstance(value, str):
            # Remove surrounding quotes if present
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            
            # Unescape
            value = bytes(value, 'utf-8').decode('unicode_escape')
            data = value.encode('utf-8')
        elif isinstance(value, bytes):
            data = value
        else:
            data = str(value).encode('utf-8')
        
        # Handle size
        if size > 0:
            if len(data) > size:
                data = data[:size]
            else:
                data = data.ljust(size, b'\x00')
        else:
            size = len(data)
        
        # Create display string
        display = value if isinstance(value, str) else data.decode('utf-8', errors='replace')
        display = display.replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
        desc = f'"{display}" ({len(data)} bytes)'
        
        return data, desc
    
    @classmethod
    def _pack_hex(cls, value, size: int) -> Tuple[bytes, str]:
        """Pack a hex string value."""
        if isinstance(value, bytes):
            data = value
        elif isinstance(value, str):
            # Clean hex string
            clean = value.strip().replace(' ', '').replace('-', '').replace(':', '')
            clean = clean.replace('0x', '').replace('0X', '')
            
            # Pad to even length
            if len(clean) % 2 != 0:
                clean = '0' + clean
            
            try:
                data = bytes.fromhex(clean)
            except ValueError:
                # Try as integer then convert
                try:
                    int_val = int(clean, 16)
                    byte_count = max(1, (int_val.bit_length() + 7) // 8)
                    data = int_val.to_bytes(byte_count, 'little')
                except ValueError:
                    raise ValueError(f"Invalid hex value: '{value}'")
        else:
            data = bytes(value)
        
        # Handle size
        if size > 0:
            if len(data) > size:
                data = data[:size]
            else:
                data = data.ljust(size, b'\x00')
        else:
            size = len(data)
        
        desc = f"0x{data.hex().upper()} ({len(data)} bytes)"
        return data, desc
    
    @classmethod
    def interpret(cls, data: bytes, type_name: str) -> str:
        """
        Interpret bytes as a specific data type for display.
        
        Returns:
            str: Human-readable interpretation
        """
        if not data:
            return "(empty)"
        
        name = cls.resolve(type_name)
        category = cls.get_category(name)
        
        try:
            if category == 'integer':
                return cls._interpret_integer(data, name)
            elif category == 'float':
                return cls._interpret_float(data, name)
            elif category == 'string':
                return cls._interpret_string(data)
            elif category == 'hex':
                return f"0x{data.hex().upper()}"
            else:
                return f"0x{data.hex().upper()}"
        except Exception as e:
            return f"0x{data.hex().upper()} (interpret error: {e})"
    
    @classmethod
    def _interpret_integer(cls, data: bytes, type_name: str) -> str:
        """Interpret integer data."""
        info = cls.TYPES.get(type_name)
        if not info:
            return f"0x{data.hex().upper()}"
        
        byte_size = info[0]
        unsigned_fmt = info[2]
        signed_fmt = info[3]
        is_signed = type_name.startswith('int')
        
        if len(data) < byte_size:
            return f"0x{data.hex().upper()} (incomplete: {len(data)}/{byte_size} bytes)"
        
        chunk = data[:byte_size]
        
        if is_signed:
            signed_val = struct.unpack(f'<{signed_fmt}', chunk)[0]
            unsigned_val = struct.unpack(f'<{unsigned_fmt.upper()}', chunk)[0]
            return f"{signed_val} (0x{unsigned_val:0{byte_size*2}X})"
        else:
            unsigned_val = struct.unpack(f'<{unsigned_fmt}', chunk)[0]
            return f"{unsigned_val} (0x{unsigned_val:0{byte_size*2}X})"
    
    @classmethod
    def _interpret_float(cls, data: bytes, type_name: str) -> str:
        """Interpret floating point data."""
        info = cls.TYPES.get(type_name)
        if not info:
            return f"0x{data.hex().upper()}"
        
        byte_size = info[0]
        fmt_char = info[2]
        
        if len(data) < byte_size:
            return f"0x{data.hex().upper()} (incomplete)"
        
        val = struct.unpack(f'<{fmt_char}', data[:byte_size])[0]
        return f"{val} (0x{data[:byte_size].hex().upper()})"
    
    @classmethod
    def _interpret_string(cls, data: bytes) -> str:
        """Interpret string data."""
        null_pos = data.find(b'\x00')
        if null_pos != -1:
            str_data = data[:null_pos]
        else:
            str_data = data
        
        try:
            text = str_data.decode('utf-8', errors='replace')
            text = text.replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
            if len(text) > 50:
                text = text[:50] + '...'
            return f'"{text}"'
        except Exception:
            return f"0x{data.hex().upper()}"


# =============================================================================
# FIXED: Auto-detect data type
# =============================================================================
def auto_detect_type(value_str: str, size: int = 4) -> str:
    """
    Auto-detect the most appropriate data type for a value string.
    
    Args:
        value_str: The value string to analyze
        size: User-suggested size in bytes
    
    Returns:
        str: Detected data type name
    """
    value_str = value_str.strip()
    
    # Check for quoted strings
    if (value_str.startswith('"') and value_str.endswith('"')) or \
       (value_str.startswith("'") and value_str.endswith("'")):
        return 'string'
    
    # Remove hex prefix for analysis
    clean = value_str.lower().replace('0x', '').replace(' ', '')
    
    # Check for float indicators
    if '.' in clean or 'e' in clean or clean in ('nan', 'inf', '-inf', '+inf'):
        if size == 8:
            return 'double'
        return 'float'
    
    # Check if it's pure hex (even length, only hex chars)
    if re.match(r'^[0-9a-f]+$', clean) and len(clean) >= 2:
        # Determine appropriate integer type based on length
        byte_len = len(clean) // 2
        if byte_len == 1:
            return 'uint8'
        elif byte_len == 2:
            return 'uint16'
        elif byte_len <= 4:
            return 'uint32'
        elif byte_len <= 8:
            return 'uint64'
        else:
            return 'hex'  # Large hex, keep as hex data
    
    # Check for expression (contains operators)
    if any(c in value_str for c in '+-*/&|^~<>()'):
        # Expression - result size determines type
        if size == 1:
            return 'uint8'
        elif size == 2:
            return 'uint16'
        elif size == 8:
            return 'uint64'
        return 'uint32'
    
    # Default based on size
    size_map = {1: 'uint8', 2: 'uint16', 4: 'uint32', 8: 'uint64'}
    return size_map.get(size, 'uint32')


# =============================================================================
# FIXED: Bit operations
# =============================================================================
def apply_bit_operation(original: bytes, operand: bytes, operation: str) -> bytes:
    """
    Apply a bitwise operation between original and operand bytes.
    
    Args:
        original: Original data bytes
        operand: Operand bytes
        operation: 'AND', 'OR', or 'XOR'
    
    Returns:
        bytes: Result of operation
    """
    if len(original) != len(operand):
        # Pad shorter to match longer
        max_len = max(len(original), len(operand))
        original = original.ljust(max_len, b'\x00')
        operand = operand.ljust(max_len, b'\x00')
    
    result = bytearray()
    operation = operation.upper()
    
    for a, b in zip(original, operand):
        if operation == 'AND':
            result.append(a & b)
        elif operation == 'OR':
            result.append(a | b)
        elif operation == 'XOR':
            result.append(a ^ b)
        else:
            raise ValueError(f"Unknown bit operation: {operation}")
    
    return bytes(result)


# =============================================================================
# FIXED: Check critical region
# =============================================================================
def is_critical_region(region_info: str) -> bool:
    """Check if a region description indicates a critical/dangerous area."""
    region_lower = region_info.lower()
    return any(keyword in region_lower for keyword in CRITICAL_REGION_KEYWORDS)


# =============================================================================
# FIXED: Main POKE command function
# =============================================================================
def cmd_poke(args=None) -> int:
    """
    QSLCL POKE Command v2.0 (FIXED)
    
    Writes values to device memory with:
    - Multiple data types (uint8-64, int8-64, float, double, string, hex)
    - Bit-level operations (AND, OR, XOR)
    - Pre-write readback and post-write verification
    - Expression evaluation for addresses and values
    - Safety checks for critical regions
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] POKE: No arguments provided")
        print("[*] Usage: poke <address> <value> [-t type] [-s size] [options]")
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
    address_str = getattr(args, 'address', None)
    value_str = getattr(args, 'value', None)
    data_type = getattr(args, 'data_type', 'auto')
    size = getattr(args, 'size', 4)
    force = getattr(args, 'force', False)
    no_verify = getattr(args, 'no_verify', False)
    bit_operation = getattr(args, 'bit_op', None)
    
    if not address_str:
        print("[!] No address specified")
        print("[*] Examples:")
        print("    poke 0x1000 0x1234")
        print("    poke boot+0x100 42 -t uint32")
        print("    poke 0x2000 3.14 -t float")
        print("    poke 0x3000 'hello' -t string")
        return 1
    
    if not value_str:
        print("[!] No value specified")
        return 1
    
    # =========================================================================
    # Address resolution
    # =========================================================================
    region_info = "Unknown"
    
    if _use_qslcl and _resolve_target:
        try:
            partitions = _load_partitions(dev) if _load_partitions else []
            memory_regions = _detect_memory_regions(dev) if _detect_memory_regions else []
            
            resolved = _resolve_target(address_str, partitions, memory_regions, dev)
            
            if resolved:
                address = resolved['address']
                
                if resolved.get('partition_info'):
                    region_info = f"Partition: {resolved['partition_info']['name']}"
                elif resolved.get('region_info'):
                    region_info = f"Region: {resolved['region_info']['name']}"
                else:
                    region_info = "Direct address"
                
                print(f"[+] Resolved: 0x{address:08X} ({region_info})")
            else:
                # Fallback to direct parsing
                address = parse_address(address_str)
                print(f"[+] Address: 0x{address:08X} (direct)")
        except Exception as e:
            print(f"[!] Target resolution failed: {e}")
            try:
                address = parse_address(address_str)
                print(f"[+] Address: 0x{address:08X} (fallback)")
            except Exception as e2:
                print(f"[!] Cannot parse address: {e2}")
                return 1
    else:
        try:
            address = parse_address(address_str)
            print(f"[+] Address: 0x{address:08X}")
        except Exception as e:
            print(f"[!] Cannot parse address: {e}")
            return 1
    
    # =========================================================================
    # Evaluate expression if value contains operators
    # =========================================================================
    value_to_process = str(value_str)
    
    if any(c in value_to_process for c in '+-*/&|^~<>()') and \
       not (value_to_process.startswith('"') or value_to_process.startswith("'")):
        try:
            evaluated = SafeExpressionEvaluator.evaluate(value_to_process)
            print(f"[+] Expression evaluated: {value_to_process} = {evaluated} (0x{evaluated:X})")
            value_to_process = str(evaluated)
        except ValueError as e:
            print(f"[!] Expression error: {e}")
            return 1
    
    # =========================================================================
    # Data type determination
    # =========================================================================
    if data_type == 'auto':
        data_type = auto_detect_type(value_to_process, size)
        print(f"[+] Auto-detected type: {data_type}")
    
    data_type = DataType.resolve(data_type)
    
    if data_type not in DataType.TYPES:
        print(f"[!] Unknown data type: {data_type}")
        print(f"[*] Valid types: {', '.join(sorted(DataType.TYPES.keys()))}")
        return 1
    
    # Get actual size from type if not variable
    type_default_size = DataType.get_size(data_type)
    if type_default_size > 0:
        size = type_default_size
    
    # =========================================================================
    # Value processing
    # =========================================================================
    try:
        write_data, value_description = DataType.pack_value(value_to_process, data_type, size)
    except ValueError as e:
        print(f"[!] Value processing failed: {e}")
        return 1
    
    actual_size = len(write_data)
    
    print(f"[+] Value: {value_description}")
    print(f"[+] Data type: {data_type}")
    print(f"[+] Size: {actual_size} byte(s)")
    print(f"[+] Raw: {write_data.hex().upper()}")
    
    if actual_size == 0:
        print("[!] Resulting data is empty")
        return 1
    
    # =========================================================================
    # Alignment check
    # =========================================================================
    if actual_size > 1 and address % actual_size != 0:
        print(f"\n[!] Unaligned write: address 0x{address:X} not aligned to {actual_size} bytes")
        if not force:
            response = input("    Continue? (y/N): ")
            if response.lower() not in ('y', 'yes'):
                print("[*] Operation cancelled")
                return 0
    
    # =========================================================================
    # Safety checks for critical regions
    # =========================================================================
    if is_critical_region(region_info) and not force:
        print(f"\n{'='*60}")
        print(f"  ⚠️  WARNING: Critical memory region detected!")
        print(f"{'='*60}")
        print(f"  Address: 0x{address:08X}")
        print(f"  Region:  {region_info}")
        print(f"  Value:   {value_description}")
        print(f"  Size:    {actual_size} bytes")
        print(f"")
        print(f"  🔴 Modifying this region may BRICK your device!")
        print(f"  🔴 This operation is potentially IRREVERSIBLE!")
        print(f"{'='*60}")
        
        response = input("\n  Type 'POKE' to confirm: ")
        if response != 'POKE':
            print("[*] Operation cancelled")
            return 0
        print("[*] Confirmed - proceeding with caution...")
    
    # =========================================================================
    # Pre-write readback
    # =========================================================================
    original_data = None
    original_interpretation = "(unknown)"
    
    if not no_verify or bit_operation:
        print(f"\n[*] Reading current value at 0x{address:08X}...")
        
        success, data, error = read_memory(dev, address, actual_size)
        
        if success and data:
            original_data = data
            original_interpretation = DataType.interpret(original_data, data_type)
            print(f"[+] Current value: {original_interpretation}")
            print(f"[+] Raw: {original_data.hex().upper()}")
        else:
            print(f"[!] Readback failed: {error}")
            if not force and not bit_operation:
                response = input("    Continue without readback? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    print("[*] Operation cancelled")
                    return 0
    
    # =========================================================================
    # Bit operations
    # =========================================================================
    if bit_operation and original_data:
        bit_op = bit_operation.upper()
        print(f"\n[*] Applying bitwise {bit_op}...")
        
        try:
            result_data = apply_bit_operation(original_data, write_data, bit_op)
            result_interpretation = DataType.interpret(result_data, data_type)
            
            print(f"[+] Original:  {original_data.hex().upper()}")
            print(f"[+] Operand:   {write_data.hex().upper()}")
            print(f"[+] Result:    {result_data.hex().upper()}")
            print(f"[+] {bit_op}:   {original_interpretation} {bit_op} {value_description} = {result_interpretation}")
            
            write_data = result_data
            value_description = result_interpretation
            
        except Exception as e:
            print(f"[!] Bit operation failed: {e}")
            return 1
    else:
        bit_op = None
    
    # =========================================================================
    # Confirm operation
    # =========================================================================
    print(f"\n{'='*50}")
    print(f"  POKE CONFIRMATION")
    print(f"{'='*50}")
    print(f"  Address:   0x{address:08X}")
    print(f"  Region:    {region_info}")
    print(f"  Type:      {data_type}")
    print(f"  Value:     {value_description}")
    print(f"  Size:      {actual_size} byte(s)")
    if bit_op:
        print(f"  Operation: {bit_op}")
    if original_data:
        print(f"  Current:   {original_interpretation}")
    print(f"{'='*50}")
    
    if not force:
        response = input("\n  Confirm write? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Operation cancelled")
            return 0
    
    # =========================================================================
    # Write operation
    # =========================================================================
    print(f"\n[*] Writing to 0x{address:08X}...")
    
    success, error = write_memory(dev, address, write_data)
    
    if not success:
        print(f"[!] Write failed: {error}")
        
        # Retry logic
        for attempt in range(1, MAX_RETRIES):
            print(f"[*] Retry {attempt}/{MAX_RETRIES}...")
            time.sleep(0.2 * attempt)
            
            success, error = write_memory(dev, address, write_data)
            if success:
                print(f"[+] Write succeeded on retry {attempt}")
                break
        
        if not success:
            print(f"[!] Write failed after {MAX_RETRIES} attempts")
            return 1
    
    print("[+] Write command accepted")
    
    # =========================================================================
    # Post-write verification
    # =========================================================================
    if not no_verify:
        print(f"\n[*] Verifying write...")
        time.sleep(0.05)  # Brief delay
        
        success, verify_data, error = read_memory(dev, address, actual_size)
        
        if success and verify_data:
            if verify_data == write_data:
                print("[+] Verification: PASSED")
                verified_value = DataType.interpret(verify_data, data_type)
                print(f"[+] Verified value: {verified_value}")
            else:
                print("[!] Verification: FAILED - Data mismatch!")
                print(f"    Expected: {write_data.hex().upper()}")
                print(f"    Got:      {verify_data.hex().upper()}")
                
                # Show differences
                diffs = []
                for i in range(min(len(write_data), len(verify_data))):
                    if write_data[i] != verify_data[i]:
                        diffs.append(f"byte {i}: 0x{write_data[i]:02X} vs 0x{verify_data[i]:02X}")
                
                if diffs:
                    print(f"    Differences ({len(diffs)}):")
                    for d in diffs[:5]:
                        print(f"      {d}")
                    if len(diffs) > 5:
                        print(f"      ... and {len(diffs) - 5} more")
        else:
            print(f"[!] Verification read failed: {error}")
    
    # =========================================================================
    # Final summary
    # =========================================================================
    print(f"\n{'='*50}")
    print(f"  POKE COMPLETE")
    print(f"{'='*50}")
    print(f"  Address:  0x{address:08X}")
    print(f"  Type:     {data_type}")
    print(f"  Value:    {value_description}")
    print(f"  Size:     {actual_size} byte(s)")
    
    if original_data:
        print(f"  Before:   {original_interpretation}")
        final_data = verify_data if not no_verify and success else write_data
        final_value = DataType.interpret(final_data, data_type)
        print(f"  After:    {final_value}")
    
    if bit_op:
        print(f"  Operation: {bit_op}")
    
    print(f"{'='*50}")
    
    return 0


# =============================================================================
# FIXED: Argument extensions for poke command
# =============================================================================
def add_poke_arguments(parser) -> None:
    """Add poke-specific arguments to an argument parser."""
    parser.add_argument(
        'address',
        help='Memory address (hex, decimal, partition, partition+offset)'
    )
    parser.add_argument(
        'value',
        help='Value to write (integer, float, hex, string, expression)'
    )
    parser.add_argument(
        '-t', '--data-type',
        choices=['auto', 'uint8', 'int8', 'uint16', 'int16', 'uint32', 'int32',
                 'uint64', 'int64', 'float', 'double', 'string', 'hex',
                 'char', 'byte', 'short', 'int', 'uint', 'long', 'ulong'],
        default='auto',
        help='Data type (default: auto-detect)'
    )
    parser.add_argument(
        '-s', '--size',
        type=int,
        default=4,
        help='Size in bytes for string/hex types (default: 4)'
    )
    parser.add_argument(
        '--bit-op',
        choices=['AND', 'OR', 'XOR', 'and', 'or', 'xor'],
        help='Bitwise operation to apply with existing value'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip post-write verification'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Skip safety confirmations (DANGEROUS)'
    )
    return parser


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] poke.py - QSLCL POKE Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py poke <address> <value> [options]")
    print()
    print("[*] Examples:")
    print("    qslcl poke 0x1000 0x12345678")
    print("    qslcl poke boot+0x100 42 -t uint32")
    print("    qslcl poke 0x2000 3.14159 -t float")
    print("    qslcl poke 0x3000 'hello' -t string -s 16")
    print("    qslcl poke 0x4000 0xFF -t uint8 --bit-op XOR")
    print("    qslcl poke 0x5000 '0xFF + 0x10' -t uint32")