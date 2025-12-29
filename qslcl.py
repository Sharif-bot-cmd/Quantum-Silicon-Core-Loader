#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v1.2.5
# Author: Sharif — QSLCL Creator
# Works on all SOC
import sys, time, argparse, zlib, struct, threading, re, os, random, math, shutil, gzip, json, itertools, hashlib, queue
from dataclasses import dataclass, asdict
from collections import defaultdict
from queue import Queue
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union
# Import all command modules
from modules.read import cmd_read
from modules.write import cmd_write
from modules.erase import cmd_erase
from modules.peek import cmd_peek
from modules.poke import cmd_poke
from modules.rawmode import cmd_rawmode
from modules.dump import cmd_dump
from modules.reset import cmd_reset
from modules.bruteforce import cmd_bruteforce
from modules.oem import cmd_oem
from modules.config import cmd_config, cmd_config_list
from modules.glitch import cmd_glitch
from modules.odm import cmd_odm
from modules.footer import cmd_footer
from modules.mode import cmd_mode, cmd_mode_status
from modules.crash import cmd_crash, cmd_crash_test
from modules.bypass import cmd_bypass
from modules.voltage import cmd_voltage
from modules.power import cmd_power
from modules.verify import cmd_verify
from modules.rawstate import cmd_rawstate
from modules.patch import cmd_patch

# =============================================================================
# IMPORTS
# =============================================================================
try:
    import serial
    import serial.tools.list_ports as list_ports
    SERIAL_SUPPORT = True
except ImportError as e:
    print(f"[!] Serial support disabled: {e}")
    SERIAL_SUPPORT = False
    
try:
    import usb.core
    import usb.util
    USB_SUPPORT = True
except ImportError as e:
    print(f"[!] USB support disabled: {e}")
    USB_SUPPORT = False

APPLE_DFU_IDS = {
    (0x05AC, 0x1227): "Apple DFU (Legacy)",
    (0x05AC, 0x1226): "Apple DFU (iBoot)",
    (0x05AC, 0x1222): "Apple DFU (A12+)",
    (0x05AC, 0x1281): "Apple Recovery",
}

_DETECTED_SECTOR_SIZE = None
PARTITION_CACHE = {}
PARTITION_SCHEMA_CACHE = {}
MEMORY_REGION_CACHE = {}
SECTOR_SIZE_CACHE = {}

QSLCLHDR_DB = {}
QSLCLCMD_DB = {}  
QSLCLVM5_DB  = {}
QSLCLUSB_DB  = {}
QSLCLSPT_DB  = {}
QSLCLDISP_DB = {}
QSLCLIDX_DB  = {}
QSLCLRTF_DB  = {}
QSLCLBST_DB  = {}  # NEW: Dynamic Bootstrap Database

def align_up(x, block):
    return (x + block - 1) & ~(block - 1)

# =============================================================================
# QSLCL STRUCTURE PARSING UTILITIES - UPDATED TO CONSISTENT FORMAT
# =============================================================================
def parse_qslcl_structure(data, expected_magic=None):
    """
    Parse QSLCL structure with format: [MAGIC(8)][size(4)][flags(4)][crc(4)][body]
    
    Returns: dict with parsed fields or None if invalid
    """
    if len(data) < 20:
        return None
    
    magic = data[:8]
    
    # If specific magic expected, validate it
    if expected_magic and magic != expected_magic:
        return None
    
    try:
        size, flags, stored_crc = struct.unpack("<III", data[8:20])
        body_start = 20
        body_end = body_start + size
        
        if body_end > len(data):
            return None
        
        body_data = data[body_start:body_end]
        calculated_crc = zlib.crc32(body_data) & 0xFFFFFFFF
        
        return {
            "magic": magic,
            "size": size,
            "flags": flags,
            "stored_crc": stored_crc,
            "calculated_crc": calculated_crc,
            "crc_valid": (stored_crc == calculated_crc),
            "body": body_data,
            "full_data": data[:body_end],
            "total_size": body_end
        }
    except Exception as e:
        print(f"[!] Failed to parse structure {magic}: {e}")
        return None

def create_qslcl_structure(magic, body_data, flags=0):
    """Create a QSLCL structure with format: [MAGIC][size][flags][crc][body]"""
    if len(magic) != 8:
        magic = magic.ljust(8, b'\x00')[:8]
    
    size = len(body_data)
    crc = zlib.crc32(body_data) & 0xFFFFFFFF
    
    header = struct.pack("<8sIII", magic, size, flags, crc)
    return header + body_data

def decode_qslcl_structure(data):
    """
    Decode QSLCL structure with consistent format:
    8 bytes: Magic
    4 bytes: Body size (little endian)
    4 bytes: Flags (little endian)
    4 bytes: CRC32 (little endian)
    variable: Body content
    """
    if len(data) < 20:
        raise ValueError(f"Data too small for QSLCL structure: {len(data)} < 20 bytes")
    
    # Parse header
    magic, size, flags, stored_crc = struct.unpack("<8sIII", data[:20])
    
    # Validate size
    if 20 + size > len(data):
        raise ValueError(f"Insufficient data: header claims {size} bytes body, but only {len(data)-20} bytes available")
    
    # Extract body
    body = data[20:20+size]
    
    # Calculate CRC32
    calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
    
    return {
        'magic': magic,
        'size': size,
        'flags': flags,
        'stored_crc': stored_crc,
        'calculated_crc': calculated_crc,
        'crc_valid': stored_crc == calculated_crc,
        'body': body,
        'total_size': 20 + size
    }

def encode_qslcl_structure(magic, body, flags=0):
    """
    Encode QSLCL structure with consistent format:
    8 bytes: Magic
    4 bytes: Body size (little endian)
    4 bytes: Flags (little endian)  
    4 bytes: CRC32 (little endian)
    variable: Body content
    """
    if len(magic) != 8:
        magic = magic.ljust(8, b'\x00')[:8]
    
    size = len(body)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    
    return struct.pack("<8sIII", magic, size, flags, crc) + body

# =============================================================================
# DEVICE STRUCT - FIXED: Added missing methods
# =============================================================================
@dataclass
class QSLCLDevice:
    transport: str               # "usb" or "serial"
    identifier: str
    vendor: str
    product: str
    vid: int = None
    pid: int = None
    usb_class: int = None
    usb_subclass: int = None
    usb_protocol: int = None
    serial: str = "default"      # Added for cache compatibility

    handle: any = None           # raw USB/Serial handle object
    serial_mode: bool = False    # True = serial port, False = USB endpoint mode

    # Helper method to get dict representation
    def get(self, key, default=None):
        return getattr(self, key, default)

    # Unified write() wrapper - FIXED: Added proper return value
    def write(self, data: bytes):
        if self.handle is None:
            # Auto-open if not already open
            self.handle, self.serial_mode = open_transport(self)
            if self.handle is None:
                raise RuntimeError("Failed to open device transport")

        # USB write (endpoint 0x01)
        if not self.serial_mode:
            try:
                # Find the correct OUT endpoint
                cfg = self.handle.get_active_configuration()
                intf = cfg[(0,0)]
                ep_out = None
                for ep in intf.endpoints():
                    if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                        usb.util.ENDPOINT_OUT and
                        usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                        ep_out = ep
                        break
                
                if ep_out:
                    return self.handle.write(ep_out.bEndpointAddress, data, timeout=2000)
                else:
                    # Fallback to control transfer
                    return self.handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, data)
            except Exception as e:
                raise RuntimeError(f"USB write failed: {e}")
        else:
            # Serial write
            try:
                return self.handle.write(data)
            except Exception as e:
                raise RuntimeError(f"Serial write failed: {e}")

    # Unified read() wrapper - FIXED: Added parameters and proper return
    def read(self, size=None, timeout=1.0):
        if self.handle is None:
            # Auto-open if not already open
            self.handle, self.serial_mode = open_transport(self)
            if self.handle is None:
                raise RuntimeError("Failed to open device transport")

        try:
            if self.serial_mode:
                # Serial read with size parameter
                if size:
                    return self.handle.read(size)
                else:
                    return self.handle.read_all()
            else:
                # USB read - use recv function
                typ, payload = recv(self.handle, False, timeout=timeout)
                return payload
        except Exception as e:
            raise RuntimeError(f"Read failed: {e}")

    # FIXED: Added close method
    def close(self):
        if self.handle:
            try:
                if self.serial_mode:
                    self.handle.close()
                else:
                    usb.util.dispose_resources(self.handle)
            except:
                pass
            self.handle = None

class ProgressBar:
    def __init__(self, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.current = 0
        
    def __enter__(self):
        self.update(0)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        print()  # New line after completion
        
    def update(self, progress):
        # FIX: Added safety check for division by zero
        if self.total <= 0:
            return
        self.current += progress
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.current / float(self.total)))
        filled_length = int(self.length * self.current // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end='', flush=True)
        if self.current >= self.total:
            print()

class QSLCLLoader:
    def __init__(self):
        self.CMD  = {}  # Changed from PAR to CMD - contains QSLCLCMD commands
        self.IDX  = {}
        self.VM5  = {}
        self.USB  = {}
        self.SPT  = {}
        self.DISP = {}
        self.HDR  = {}
        self.RTF  = {}
        self.ENG  = {}  # Alias for CMD for compatibility
        self.BST  = {}  # NEW: Dynamic Bootstrap storage

    # ---------------------------------------------
    # STRUCTURE PARSER HELPER - CONSISTENT FORMAT
    # ---------------------------------------------
    def _parse_structured_block(self, blob, magic):
        """Parse a structured block with consistent format"""
        try:
            struct_info = decode_qslcl_structure(blob)
            if struct_info['magic'] != magic:
                return None, blob
            
            print(f"[+] {magic.decode()}: Structured format detected (size={struct_info['size']}, flags=0x{struct_info['flags']:08X})")
            if not struct_info['crc_valid']:
                print(f"[!] {magic.decode()}: CRC mismatch!")
            
            return struct_info, struct_info['body']
        except Exception as e:
            # Not a structured block, continue with raw parsing
            return None, blob

    # ---------------------------------------------
    # NEW: QSLCLBST PARSER - DYNAMIC BOOTSTRAP HEADER
    # ---------------------------------------------
    def load_qslclbst(self, blob):
        """QSLCLBST parser - Dynamic Bootstrap v5.0"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLBST"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
            
            try:
                # Check if we have enough data for structured format
                if idx + 20 <= len(blob):
                    # Try to parse as structured format at this position
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            # We have a structured block, parse its body
                            structured_body = local_struct['body']
                            idx_start = idx
                            body_offset = 0
                        else:
                            # Not a structured block at this position
                            pos = idx + 1
                            continue
                    except:
                        # Not a structured block, try legacy format
                        structured_body = None
                        body_offset = 0
                else:
                    pos = idx + 1
                    continue
                
                # Parse QSLCLBST header from body or raw data
                if structured_body is not None:
                    # Parse from structured body
                    if len(structured_body) < 24:
                        pos = idx + 1
                        continue
                    
                    # Parse bootstrap header: <BBHIII16s
                    version, flags, arch_count, code_size, stored_crc, entry_point = \
                        struct.unpack("<BBHIII", structured_body[:16])
                    arch_name = structured_body[16:32].decode("ascii", errors="ignore").rstrip('\x00')
                    bootstrap_start = 32
                    bootstrap_data = structured_body
                else:
                    # Legacy format
                    if idx + 32 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+32]
                    magic_found, version, flags, arch_count, code_size, stored_crc, entry_point = \
                        struct.unpack("<8sBBHIII", hdr[:28])
                    arch_name = blob[idx+28:idx+44].decode("ascii", errors="ignore").rstrip('\x00')
                    
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    bootstrap_start = idx + 44
                    bootstrap_data = blob
                
                # Check for security envelope (if secure mode flag is set)
                if flags & 0x01:  # Secure mode
                    security_start = bootstrap_start
                    if security_start + 24 <= len(bootstrap_data):
                        # Parse security header: <II16s
                        security_magic, security_crc, security_hash = \
                            struct.unpack("<II16s", bootstrap_data[security_start:security_start+24])
                        bootstrap_start += 24
                
                # Extract bootstrap code
                if bootstrap_start + code_size <= len(bootstrap_data):
                    bootstrap_code = bootstrap_data[bootstrap_start:bootstrap_start + code_size]
                    
                    # Verify CRC if available
                    calculated_crc = zlib.crc32(bootstrap_code) & 0xFFFFFFFF
                    crc_valid = (stored_crc == calculated_crc)
                    
                    # Extract data section
                    data_start = bootstrap_start + code_size
                    if data_start + 256 <= len(bootstrap_data):
                        bootstrap_data_section = bootstrap_data[data_start:data_start + 256]
                    else:
                        bootstrap_data_section = b""
                    
                    # Extract footer
                    footer_start = data_start + 256
                    if footer_start + 32 <= len(bootstrap_data):
                        footer_magic, footer_crc, footer_hash, footer_id = \
                            struct.unpack("<II16s8s", bootstrap_data[footer_start:footer_start+32])
                    else:
                        footer_magic = footer_crc = 0
                        footer_hash = b""
                        footer_id = b""
                    
                    # Store bootstrap information
                    bootstrap_info = {
                        "version": version,
                        "flags": flags,
                        "arch_count": arch_count,
                        "code_size": code_size,
                        "stored_crc": stored_crc,
                        "calculated_crc": calculated_crc,
                        "crc_valid": crc_valid,
                        "entry_point": entry_point,
                        "arch_name": arch_name,
                        "bootstrap_code": bootstrap_code,
                        "bootstrap_data": bootstrap_data_section,
                        "footer_magic": footer_magic,
                        "footer_crc": footer_crc,
                        "footer_hash": footer_hash,
                        "footer_id": footer_id,
                        "offset": idx,
                        "secure_mode": bool(flags & 0x01),
                        "structured": struct_info is not None
                    }
                    
                    # Store by architecture and by offset
                    out[arch_name] = bootstrap_info
                    out[f"offset_0x{idx:08X}"] = bootstrap_info
                    
                    print(f"[*] QSLCLBST: Found bootstrap for {arch_name} (v{version})")
                    print(f"    Entry: 0x{entry_point:08X}, Secure: {bootstrap_info['secure_mode']}")
                    print(f"    Code: {code_size} bytes, CRC: {'VALID' if crc_valid else 'INVALID'}")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLBST parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.BST = out
        global QSLCLBST_DB
        QSLCLBST_DB = out
        return out

    # ---------------------------------------------
    # REPLACED: QSLCLCMD PARSER (replaces QSLCLPAR)
    # ---------------------------------------------
    def load_qslclcmd(self, blob):
        """QSLCLCMD parser - Unified command system with QSLCLCMD wrapper"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLCMD"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
            print(f"[+] QSLCLCMD: Structured block detected, flags=0x{struct_info['flags']:08X}")
        
        # Also check for QSLCLPAR for backward compatibility
        par_magic = b"QSLCLPAR"
        par_struct_info, par_parsed_body = self._parse_structured_block(blob, par_magic)
        if par_struct_info:
            # Found QSLCLPAR inside QSLCLCMD body
            blob = par_parsed_body
            print(f"[+] QSLCLPAR: Nested structured block inside QSLCLCMD")
        
        pos = 0
        while pos < len(blob):
            # Look for either QSLCLCMD or QSLCLPAR
            idx = -1
            found_magic = None
            
            for search_magic in [b"QSLCLCMD", b"QSLCLPAR"]:
                test_idx = blob.find(search_magic, pos)
                if test_idx != -1 and (idx == -1 or test_idx < idx):
                    idx = test_idx
                    found_magic = search_magic
            
            if idx == -1:
                break
                
            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] in [b"QSLCLCMD", b"QSLCLPAR"]:
                            # Structured block found, parse its body
                            struct_body = local_struct['body']
                            structured = True
                            is_cmd_wrapper = (local_struct['magic'] == b"QSLCLCMD")
                        else:
                            # Not a structured block
                            struct_body = None
                            structured = False
                            is_cmd_wrapper = (found_magic == b"QSLCLCMD")
                    except:
                        struct_body = None
                        structured = False
                        is_cmd_wrapper = (found_magic == b"QSLCLCMD")
                else:
                    pos = idx + 1
                    continue
                
                if structured and struct_body:
                    # Parse from structured body
                    body_to_parse = struct_body
                else:
                    # Legacy format
                    if idx + 16 > len(blob):
                        pos = idx + 1
                        continue
                    
                    # Check magic
                    magic_found = blob[idx:idx+8]
                    if magic_found not in [b"QSLCLCMD", b"QSLCLPAR"]:
                        pos = idx + 1
                        continue
                    
                    is_cmd_wrapper = (magic_found == b"QSLCLCMD")
                    
                    # Try to parse header
                    try:
                        if is_cmd_wrapper:
                            # QSLCLCMD legacy header: magic(8) + version(1) + flags(1) + size(2)
                            if idx + 12 > len(blob):
                                pos = idx + 1
                                continue
                            
                            hdr = blob[idx:idx+12]
                            magic_found, version, flags, size = struct.unpack("<8sBBH", hdr)
                            cmd_pos = idx + 12
                            body_to_parse = blob[cmd_pos:cmd_pos+size] if cmd_pos+size <= len(blob) else blob[cmd_pos:]
                        else:
                            # QSLCLPAR legacy header: magic(8) + version(1) + flags(1) + count(2) + data_len(4)
                            if idx + 16 > len(blob):
                                pos = idx + 1
                                continue
                            
                            hdr = blob[idx:idx+16]
                            magic_found, version, flags, count, data_len = struct.unpack("<8sBBHI", hdr)
                            cmd_pos = idx + 16
                            body_to_parse = blob[cmd_pos:cmd_pos+data_len] if cmd_pos+data_len <= len(blob) else blob[cmd_pos:]
                    except:
                        pos = idx + 1
                        continue
                
                # Now parse the command entries from the body
                cmd_entries_parsed = 0
                
                # Try to parse as command entries (similar to old QSLCLPAR format)
                try:
                    if len(body_to_parse) >= 40:  # Minimum command entry size
                        entry_pos = 0
                        
                        while entry_pos + 40 <= len(body_to_parse):
                            # Parse command header: <16sBBBBHII
                            cmd_hdr = body_to_parse[entry_pos:entry_pos+40]
                            name_field, opcode, cmd_flags, tier, family_hash, length, crc, timestamp = \
                                struct.unpack("<16sBBBBHII", cmd_hdr)
                            
                            # Extract command name
                            name = name_field.decode("ascii", errors="ignore").rstrip('\x00')
                            
                            # Validate name and check data bounds
                            if (not name or len(name) < 2 or not name.isalnum() or
                                entry_pos + 40 + length > len(body_to_parse) or length > 4096):
                                entry_pos += 1
                                continue
                            
                            # Extract command data (micro-VM code)
                            cmd_data = body_to_parse[entry_pos+40:entry_pos+40+length]
                            
                            # Store command with both name and opcode access
                            command_entry = {
                                "name": name,
                                "opcode": opcode,
                                "flags": cmd_flags,
                                "tier": tier,
                                "family_hash": family_hash,
                                "length": length,
                                "crc": crc,
                                "timestamp": timestamp,
                                "data": cmd_data,  # This is the micro-VM code
                                "offset": idx + entry_pos if not structured else entry_pos,
                                "structured": structured,
                                "wrapper": "QSLCLCMD" if is_cmd_wrapper else "QSLCLPAR"
                            }
                            
                            # Store by name and by opcode
                            out[name] = command_entry
                            out[opcode] = command_entry  # Allow opcode-based lookup
                            
                            cmd_entries_parsed += 1
                            entry_pos += 40 + length
                            
                            print(f"    Command: {name} (opcode: 0x{opcode:02X}, size: {length} bytes)")
                except Exception as e:
                    print(f"[!] Command entry parsing error: {e}")
                
                if cmd_entries_parsed > 0:
                    print(f"[*] QSLCLCMD: Found {cmd_entries_parsed} commands")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLCMD parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.CMD = out
        self.ENG = out  # Alias for backward compatibility
        global QSLCLCMD_DB
        QSLCLCMD_DB = out
        return out

    # ---------------------------------------------
    # QSLCLDISP PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslcldisp(self, blob):
        """QSLCLDISP parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLDIS"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    pos = idx + 1
                    continue
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    # Parse header from structured body: <HHI (version, flags, count)
                    version, flags, count = struct.unpack("<HHI", struct_body[:8])
                    entry_pos = 8
                else:
                    # Legacy format
                    if idx + 16 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+16]
                    magic_found, version, flags, count = struct.unpack("<8sHHI", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    entry_pos = idx + 16
                    struct_body = blob
                
                # Parse dispatch entries
                entries_found = 0
                
                for i in range(count):
                    if entry_pos + 12 > len(struct_body):
                        break
                        
                    # Entry format: <8sI (cmd_hash, handler_addr)
                    cmd_hash, handler_addr = struct.unpack("<8sI", struct_body[entry_pos:entry_pos+12])
                    
                    # Try to find command name from hash
                    cmd_name = f"CMD_{i:04X}"
                    
                    out[cmd_name] = {
                        "hash": cmd_hash.hex(),
                        "handler_addr": handler_addr,
                        "index": i,
                        "structured": structured
                    }
                    
                    entry_pos += 12
                    entries_found += 1
                
                if entries_found > 0:
                    print(f"[*] QSLCLDISP: Found {entries_found} dispatch entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLDISP parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.DISP = out
        global QSLCLDISP_DB
        QSLCLDISP_DB = out
        return out

    # ---------------------------------------------
    # RTF PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclrtf(self, blob):
        """RTF parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLRTF"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
            
            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    # Legacy format minimum check
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                    
                    # Header: magic(8) + version(1) + flags(1) + count(2)
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    struct_body = blob
                    structured = False
                    entry_pos = idx + 12
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    ver, flags, count = struct.unpack("<BBH", struct_body[:4])
                    entry_pos = 4
                elif not structured and idx + 12 <= len(blob):
                    # Already parsed legacy header above
                    entry_pos = idx + 12
                else:
                    pos = idx + 1
                    continue
                    
                entries_found = 0
                
                for i in range(count):
                    if entry_pos + 12 > len(struct_body):
                        break
                    
                    # Fixed format: error_code(4) + severity(1) + category(1) + retry_count(2) + msg_hash(4)
                    code, severity, category, retry_count, msg_hash = struct.unpack("<IBBH I", struct_body[entry_pos:entry_pos+12])
                    
                    # Extract short name (8 bytes)
                    name_end = entry_pos + 20
                    if name_end > len(struct_body):
                        break
                    short_name = struct_body[entry_pos+12:name_end].decode("ascii", errors="ignore").rstrip('\x00')
                    
                    out[code] = {
                        "level": severity,
                        "msg": short_name,
                        "category": category,
                        "retry_count": retry_count,
                        "hash": msg_hash,
                        "structured": structured
                    }
                    entry_pos += 20
                    entries_found += 1
                
                if entries_found > 0:
                    print(f"[*] QSLCLRTF: Found {entries_found} entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLRTF parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.RTF = out
        global QSLCLRTF_DB
        QSLCLRTF_DB = out
        return out

    # ---------------------------------------------
    # IDX PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclidx(self, blob):
        """IDX parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLIDX"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    # Legacy format minimum check
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    struct_body = blob
                    structured = False
                    entry_pos = idx + 12
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    ver, flags, count = struct.unpack("<BBH", struct_body[:4])
                    entry_pos = 4
                elif not structured:
                    # Already parsed legacy header above
                    entry_pos = idx + 12
                else:
                    pos = idx + 1
                    continue
                    
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 3 > len(struct_body):
                        break
                        
                    idx_val = struct.unpack("<H", struct_body[entry_pos:entry_pos+2])[0]
                    name_len = struct_body[entry_pos+2]
                    
                    if entry_pos + 3 + name_len > len(struct_body) or name_len == 0 or name_len > 64:
                        break
                        
                    name = struct_body[entry_pos+3:entry_pos+3+name_len].decode("ascii", errors="ignore")
                    # Only add if name is valid
                    if name and name.isprintable():
                        out[name] = {"idx": idx_val, "name": name, "structured": structured}
                        entry_pos += 3 + name_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLIDX: Found {entries_found} entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLIDX parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.IDX = out
        global QSLCLIDX_DB
        QSLCLIDX_DB = out
        return out

    # ---------------------------------------------
    # VM5 PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclvm5(self, blob):
        """VM5 parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLVM5"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
            
            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    # Legacy format minimum check
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    struct_body = blob
                    structured = False
                    entry_pos = idx + 12
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    ver, flags, count = struct.unpack("<BBH", struct_body[:4])
                    entry_pos = 4
                elif not structured:
                    # Already parsed legacy header above
                    entry_pos = idx + 12
                else:
                    pos = idx + 1
                    continue
                    
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(struct_body):
                        break
                        
                    name_len = struct_body[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(struct_body) or name_len == 0 or name_len > 64:
                        break
                        
                    name = struct_body[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", struct_body[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(struct_body) or raw_len > 4096:
                        break
                        
                    raw = struct_body[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    # Only add if name is valid
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw, "structured": structured}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLVM5: Found {entries_found} entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLVM5 parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.VM5 = out
        global QSLCLVM5_DB
        QSLCLVM5_DB = out
        return out

    # ---------------------------------------------
    # USB ROUTINES PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclusb(self, blob):
        """USB parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLUSB"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    # Legacy format minimum check
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    struct_body = blob
                    structured = False
                    entry_pos = idx + 12
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    ver, flags, count = struct.unpack("<BBH", struct_body[:4])
                    entry_pos = 4
                elif not structured:
                    # Already parsed legacy header above
                    entry_pos = idx + 12
                else:
                    pos = idx + 1
                    continue
                    
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(struct_body):
                        break
                        
                    name_len = struct_body[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(struct_body) or name_len == 0 or name_len > 64:
                        break
                        
                    name = struct_body[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", struct_body[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(struct_body) or raw_len > 4096:
                        break
                        
                    raw = struct_body[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw, "structured": structured}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLUSB: Found {entries_found} entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLUSB parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.USB = out
        global QSLCLUSB_DB
        QSLCLUSB_DB = out
        return out

    # ---------------------------------------------
    # SPT SETUP PACKETS PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclspt(self, blob):
        """SPT parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLSPT"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    # Legacy format minimum check
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                    
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    # Validate magic
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    struct_body = blob
                    structured = False
                    entry_pos = idx + 12
                
                if structured:
                    # Parse from structured body
                    if len(struct_body) < 4:
                        pos = idx + 1
                        continue
                    
                    ver, flags, count = struct.unpack("<BBH", struct_body[:4])
                    entry_pos = 4
                elif not structured:
                    # Already parsed legacy header above
                    entry_pos = idx + 12
                else:
                    pos = idx + 1
                    continue
                    
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(struct_body):
                        break
                        
                    name_len = struct_body[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(struct_body) or name_len == 0 or name_len > 64:
                        break
                        
                    name = struct_body[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", struct_body[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(struct_body) or raw_len > 4096:
                        break
                        
                    raw = struct_body[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw, "structured": structured}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLSPT: Found {entries_found} entries")
                    break
                    
            except Exception as e:
                print(f"[!] QSLCLSPT parse error at 0x{idx:X}: {e}")
                pass
            
            pos = idx + 1

        self.SPT = out
        global QSLCLSPT_DB
        QSLCLSPT_DB = out
        return out

    # ---------------------------------------------
    # HEADER / CERTS PARSER - UPDATED FOR STRUCTURED FORMAT
    # ---------------------------------------------
    def load_qslclhdr(self, blob):
        """HDR parser"""
        out = {}
        
        # Try to parse as structured format first
        magic = b"QSLCLHDR"
        struct_info, parsed_body = self._parse_structured_block(blob, magic)
        if struct_info:
            blob = parsed_body
        
        pos = 0
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                # Check if this is a structured block
                if idx + 20 <= len(blob):
                    try:
                        local_struct = decode_qslcl_structure(blob[idx:])
                        if local_struct['magic'] == magic:
                            struct_body = local_struct['body']
                            structured = True
                            # Use structured body for parsing
                            # For HDR, the body is the payload itself
                            key = f"HDR_structured_0x{idx:08X}"
                            out[key] = struct_body
                            print(f"[*] QSLCLHDR: Structured block ({len(struct_body)} bytes)")
                            pos = idx + local_struct['total_size']
                            continue
                        else:
                            struct_body = None
                            structured = False
                    except:
                        struct_body = None
                        structured = False
                else:
                    struct_body = None
                    structured = False
                
                if not structured:
                    # Legacy format
                    if idx + 16 > len(blob):
                        pos = idx + 1
                        continue
                    
                    # Header: magic(8) + version(4) + size(4)
                    magic_found = blob[idx:idx+8]
                    if magic_found != magic:
                        pos = idx + 1
                        continue
                    
                    ver, size = struct.unpack("<II", blob[idx+8:idx+16])
                    
                    if idx + 32 + size > len(blob) or size > 65536:
                        pos = idx + 1
                        continue
                    
                    digest = blob[idx+16:idx+32]
                    payload = blob[idx+32 : idx+32+size]
                    
                    # Use a descriptive key
                    key = f"HDR_block_0x{idx:08X}"
                    out[key] = payload
                    
                    print(f"[*] QSLCLHDR: Found block ({size} bytes)")
                    pos = idx + 32 + size
                
            except Exception as e:
                print(f"[!] QSLCLHDR parse error at 0x{idx:X}: {e}")
                pos = idx + 1
                continue

        self.HDR = out
        global QSLCLHDR_DB
        QSLCLHDR_DB = out
        return out

    # ---------------------------------------------
    # UPDATED MASTER PARSER WITH STRUCTURED FORMAT SUPPORT
    # ---------------------------------------------
    def parse_loader(self, blob):
        """Parse QSLCL binary with structured format support"""
        print(f"[*] Parsing loader ({len(blob)} bytes)...")
        
        # First, check if this is a structured QSLCLBIN
        if len(blob) >= 20:
            try:
                # Try to decode as QSLCLBIN structure
                bin_struct = decode_qslcl_structure(blob)
                if bin_struct['magic'] == b"QSLCLBIN":
                    print("[+] Detected structured QSLCL binary format")
                    print(f"[+] QSLCL Binary Header:")
                    print(f"    Body Size: {bin_struct['size']} bytes")
                    print(f"    Flags: 0x{bin_struct['flags']:08X}")
                    print(f"    Stored CRC: 0x{bin_struct['stored_crc']:08X}")
                    print(f"    Calculated CRC: 0x{bin_struct['calculated_crc']:08X}")
                    print(f"    CRC Valid: {bin_struct['crc_valid']}")
                    
                    if not bin_struct['crc_valid']:
                        print("[!] WARNING: Binary CRC mismatch! Data may be corrupted.")
                    
                    # Use body data for parsing
                    blob = bin_struct['body']
            except:
                # Not a structured QSLCLBIN, continue with raw parsing
                pass
        
        # Extended marker set - ADDED QSLCLCMD
        ALL_MARKERS = [
            b"QSLCLBST", b"QSLCLCMD", b"QSLCLPAR", b"QSLCLRTF", b"QSLCLUSB", b"QSLCLSPT", 
            b"QSLCLVM5", b"QSLCLDISP", b"QSLCLIDX", b"QSLCLHDR", 
            b"QSLCLBIN", b"QSLCLPKT", b"QSLCLRESP", 
            b"QSLCLTBL", b"QSLCLSEC", b"QSLCLINT"
        ]
        
        discovered = {}
        blob_len = len(blob)
        
        # Scan for all possible markers
        for i in range(blob_len - 8):
            chunk = blob[i:i+8]
            if chunk in ALL_MARKERS:
                marker_name = chunk.decode('ascii', errors='ignore').rstrip('\x00')
                discovered.setdefault(marker_name, []).append(i)
        
        if not discovered:
            print("[!] No QSLCL headers found in loader")
            print("[*] First 64 bytes (hex):")
            print(blob[:64].hex())
            return False
        
        print(f"[+] Found {len(discovered)} different structure types:")
        for marker, positions in discovered.items():
            print(f"    {marker}: {len(positions)} occurrences")
        
        # Parse structures in order of importance - QSLCLCMD FIRST
        success_count = 0
        parse_order = ["QSLCLCMD", "QSLCLPAR", "QSLCLBST", "QSLCLDISP", "QSLCLRTF", 
                       "QSLCLHDR", "QSLCLUSB", "QSLCLVM5", "QSLCLSPT", "QSLCLIDX"]
        
        for marker in parse_order:
            if marker in discovered:
                parser_name = f"load_{marker.lower()}"
                if hasattr(self, parser_name):
                    for pos in discovered[marker]:
                        try:
                            result = getattr(self, parser_name)(blob[pos:])
                            if result:
                                success_count += 1
                                print(f"[+] {marker}: Parsed successfully")
                                break
                        except Exception as e:
                            print(f"[!] {marker} parse failed at 0x{pos:X}: {e}")
        
        print(f"\n[*] Parsing Summary:")
        print(f"    Successfully parsed: {success_count} structure types")
        
        # Show what we found
        found_modules = []
        if self.CMD:  found_modules.append(f"CMD({len(self.CMD)//2})")
        if self.BST:  found_modules.append(f"BST({len(self.BST)//2})")
        if self.DISP: found_modules.append(f"DISP({len(self.DISP)})")
        if self.RTF:  found_modules.append(f"RTF({len(self.RTF)})")
        if self.HDR:  found_modules.append(f"HDR({len(self.HDR)})")
        if self.IDX:  found_modules.append(f"IDX({len(self.IDX)})")
        if self.VM5:  found_modules.append(f"VM5({len(self.VM5)})")
        if self.USB:  found_modules.append(f"USB({len(self.USB)})")
        if self.SPT:  found_modules.append(f"SPT({len(self.SPT)})")
        
        if found_modules:
            print(f"[+] Detected modules: {', '.join(found_modules)}")
            
            # Show available bootstrap configurations
            if self.BST:
                bootstrap_archs = [arch for arch in self.BST.keys() if not arch.startswith('offset_')]
                print(f"[+] Bootstrap architectures: {', '.join(bootstrap_archs)}")
            
            # Show available commands
            if self.CMD:
                # Get unique command names (not opcodes)
                command_names = [name for name in self.CMD.keys() if isinstance(name, str) and name.isalpha()]
                commands = command_names[:10]  # Show first 10 commands
                print(f"[+] Available commands: {', '.join(commands)}" + 
                      ("..." if len(command_names) > 10 else ""))
            
            return True
        else:
            print("[!] No valid modules parsed")
            return False

# =============================================================================
# UPDATED VALIDATION FUNCTION WITH STRUCTURED FORMAT SUPPORT
# =============================================================================
def validate_binary_compatibility(blob):
    """Validate QSLCL binary with structured format support"""
    if len(blob) < 8:
        print("[!] Binary too small")
        return False
    
    # Check for QSLCLBIN structured format
    if len(blob) >= 20:
        try:
            bin_struct = decode_qslcl_structure(blob)
            if bin_struct['magic'] == b"QSLCLBIN":
                print(f"[+] Structured QSLCL Binary:")
                print(f"    Total size: {len(blob)} bytes")
                print(f"    Body size: {bin_struct['size']} bytes")
                print(f"    Flags: 0x{bin_struct['flags']:08X}")
                print(f"    CRC: {'VALID' if bin_struct['crc_valid'] else 'INVALID'}")
                
                # Check for required blocks in body
                required_blocks = [b"QSLCLCMD", b"QSLCLPAR"]  # Accept either
                found_blocks = []
                
                for block in required_blocks:
                    if block in bin_struct['body']:
                        found_blocks.append(block.decode())
                
                if found_blocks:
                    print(f"[+] Found required blocks: {found_blocks}")
                    return True
                else:
                    print("[!] No required QSLCL blocks found in body")
                    # Still try to parse
                    return True
        except:
            pass  # Not a structured binary
    
    # Legacy validation for raw binaries
    required_blocks = [b"QSLCLCMD", b"QSLCLPAR"]  # Accept either
    found_blocks = []
    
    for block in required_blocks:
        if block in blob:
            found_blocks.append(block.decode())
    
    if not found_blocks:
        print("[!] No required QSLCL blocks found")
        return False
        
    print(f"[+] Found required blocks: {found_blocks}")
    return True

# =============================================================================
# FIXED: DEVICE INFO PARSING FUNCTIONS
# =============================================================================
def parse_device_info(resp):
    """Properly parse device information from response - updated for bootstrap"""
    info = {
        "version": "Unknown",
        "architecture": "Unknown", 
        "sector_size": "Unknown",
        "capabilities": [],
        "loader_version": "Unknown",
        "bootstrap_available": False,
        "bootstrap_architectures": []
    }
    
    if not resp:
        return info
        
    try:
        # Parse QSLCL version if present
        if isinstance(resp, bytes):
            if b"QSLCL" in resp:
                idx = resp.find(b"QSLCL")
                if idx + 16 <= len(resp):
                    version_part = resp[idx:idx+16]
                    # Extract version number pattern
                    version_match = re.search(rb'v?(\d+\.\d+\.\d+)', version_part)
                    if version_match:
                        info["version"] = version_match.group(1).decode()
                
        # Architecture detection
        if isinstance(resp, bytes):
            arch_patterns = [
                (b"ARM", "ARM"), (b"x86", "x86"), (b"x64", "x86_64"), 
                (b"RISCV", "RISC-V"), (b"MIPS", "MIPS"), (b"AARCH64", "ARM64")
            ]
            for pattern, arch_name in arch_patterns:
                if pattern in resp:
                    info["architecture"] = arch_name
                    break
                
        # Bootstrap availability
        info["bootstrap_available"] = bool(QSLCLBST_DB)
        if QSLCLBST_DB:
            bootstrap_archs = [arch for arch in QSLCLBST_DB.keys() if not arch.startswith('offset_')]
            info["bootstrap_architectures"] = bootstrap_archs
                
        # Capabilities from response flags
        if isinstance(resp, bytes) and len(resp) > 8:
            flags = resp[8] if len(resp) > 8 else 0
            capabilities = []
            if flags & 0x01: capabilities.append("USB")
            if flags & 0x02: capabilities.append("SERIAL") 
            if flags & 0x04: capabilities.append("FLASH")
            if flags & 0x08: capabilities.append("MEMORY")
            if flags & 0x10: capabilities.append("BOOTSTRAP")
            info["capabilities"] = capabilities
            
        # Try to extract sector size
        if isinstance(resp, bytes) and len(resp) >= 12:
            try:
                sector_size = struct.unpack("<I", resp[8:12])[0]
                if sector_size in [512, 1024, 2048, 4096, 8192, 16384]:
                    info["sector_size"] = sector_size
            except:
                pass
                
    except Exception as e:
        print(f"[!] Device info parsing error: {e}")
        
    return info

def print_device_info(info):
    """Print device information in formatted way - updated for bootstrap"""
    print("\n   Device Information:")
    print(f"     Version:      {info['version']}")
    print(f"     Architecture: {info['architecture']}")
    print(f"     Sector Size:  {info['sector_size']}")
    print(f"     Capabilities: {', '.join(info['capabilities'])}")
    
    if info['bootstrap_available']:
        print(f"     Bootstrap:    AVAILABLE ({len(info['bootstrap_architectures'])} architectures)")
        if info['bootstrap_architectures']:
            print(f"                   {', '.join(info['bootstrap_architectures'])}")
    else:
        print("     Bootstrap:    NOT AVAILABLE")

# =============================================================================
# FIXED: PARTITION MANAGEMENT FUNCTIONS
# =============================================================================
def load_partitions(dev):
    """Load partition information from device - FIXED to match read.py interface"""
    global PARTITION_CACHE
    
    dev_key = dev.serial if hasattr(dev, 'serial') else 'default'
    if dev_key in PARTITION_CACHE:
        return PARTITION_CACHE[dev_key]
    
    partitions = []
    try:
        # Use universal detection
        partitions = detect_all_partitions(dev)
        PARTITION_CACHE[dev_key] = partitions
        
    except Exception as e:
        print(f"[!] Partition loading failed: {e}")
        # Fallback to common partition table
        partitions = [
            {"name": "boot", "offset": 0x880000, "size": 0x400000},
            {"name": "system", "offset": 0xC80000, "size": 0x8000000},
            {"name": "recovery", "offset": 0x88C80000, "size": 0x400000},
            {"name": "cache", "offset": 0x90C80000, "size": 0x4000000},
            {"name": "userdata", "offset": 0x94C80000, "size": 0x40000000},
        ]
        PARTITION_CACHE[dev_key] = partitions
        
    return partitions

# =============================================================================
# FIXED: UNIVERSAL PARTITION DETECTION FUNCTIONS
# =============================================================================
def detect_all_partitions(dev):
    """Universal partition detection for all SOCs - FIXED version"""
    global PARTITION_CACHE
    
    dev_key = dev.serial if hasattr(dev, 'serial') else 'default'
    if dev_key in PARTITION_CACHE:
        return PARTITION_CACHE[dev_key]
    
    partitions = []
    
    print("[*] Phase 1: SOC identification...")
    soc_info = identify_soc(dev)
    
    print("[*] Phase 2: Partition table detection...")
    
    # Try multiple detection methods
    detection_methods = [
        detect_gpt_partitions,
        detect_mbr_partitions,
        detect_android_partitions,
        detect_apple_partitions,
        detect_custom_partitions
    ]
    
    for method in detection_methods:
        try:
            detected = method(dev, soc_info)
            if detected:
                partitions.extend(detected)
                print(f"[+] Found {len(detected)} partitions via {method.__name__}")
        except Exception as e:
            print(f"[!] {method.__name__} failed: {e}")
            continue
    
    # If no partitions found, use SOC-specific fallback
    if not partitions:
        partitions = get_soc_fallback_partitions(soc_info)
        print(f"[*] Using SOC-specific fallback: {len(partitions)} partitions")
    
    # Remove duplicates and sort
    partitions = deduplicate_partitions(partitions)
    partitions.sort(key=lambda x: x['offset'])
    
    print(f"[+] Total unique partitions detected: {len(partitions)}")
    PARTITION_CACHE[dev_key] = partitions
    return partitions

def identify_soc(dev):
    """Identify SOC type and characteristics - FIXED version"""
    soc_info = {
        'vendor': 'UNKNOWN',
        'family': 'UNKNOWN',
        'model': 'UNKNOWN',
        'architecture': 'UNKNOWN',
        'endianness': 'little',
        'sector_size': 512
    }
    
    try:
        # Query SOC information via QSLCL
        soc_payload = struct.pack("<B", 0x10)  # SOC_INFO command
        resp = qslcl_dispatch(dev, "GETINFO", soc_payload)
        
        if resp and len(resp) >= 64:
            soc_info['vendor'] = resp[0:16].decode('ascii', errors='ignore').rstrip('\x00')
            soc_info['family'] = resp[16:32].decode('ascii', errors='ignore').rstrip('\x00')
            soc_info['model'] = resp[32:48].decode('ascii', errors='ignore').rstrip('\x00')
            soc_info['architecture'] = resp[48:56].decode('ascii', errors='ignore').rstrip('\x00')
            soc_info['sector_size'] = struct.unpack("<H", resp[56:58])[0]
            
            # Detect Apple SOCs
            if 'APPLE' in soc_info['vendor'].upper() or soc_info['family'].startswith('A'):
                soc_info['vendor'] = 'APPLE'
                soc_info['partition_schema'] = 'APPLE'
            # Detect Qualcomm SOCs
            elif 'QUALCOMM' in soc_info['vendor'].upper() or soc_info['family'].startswith('SD'):
                soc_info['vendor'] = 'QUALCOMM'
                soc_info['partition_schema'] = 'QCOM'
            # Detect Samsung SOCs
            elif 'SAMSUNG' in soc_info['vendor'].upper() or 'EXYNOS' in soc_info['family'].upper():
                soc_info['vendor'] = 'SAMSUNG'
                soc_info['partition_schema'] = 'EXYNOS'
            # Detect MediaTek SOCs
            elif 'MEDIATEK' in soc_info['vendor'].upper() or 'MT' in soc_info['family']:
                soc_info['vendor'] = 'MEDIATEK'
                soc_info['partition_schema'] = 'MTK'
    
    except Exception as e:
        print(f"[!] SOC identification failed: {e}")
    
    return soc_info

def detect_gpt_partitions(dev, soc_info):
    """Detect GPT partition table (universal) - FIXED version"""
    partitions = []
    
    # GPT header locations (common across SOCs)
    gpt_locations = [
        0x0,                    # Primary GPT
        0x200,                  # Alternative
        0x400,                  # Common offset
        0x1000,                 # Apple GPT offset
        0x2000,                 # Large sector devices
        soc_info['sector_size'], # First sector
    ]
    
    for location in gpt_locations:
        try:
            # Read GPT header
            header_payload = struct.pack("<II", location, 512)
            resp = qslcl_dispatch(dev, "READ", header_payload)
            
            if resp and len(resp) >= 512:
                header = resp[:512]
                # Check GPT signature
                if header[0:8] == b'EFI PART':
                    print(f"[+] GPT detected at 0x{location:08X}")
                    partitions.extend(parse_gpt_table(dev, location, header, soc_info))
                    break
        except Exception as e:
            continue
    
    return partitions

def parse_gpt_table(dev, gpt_offset, header, soc_info):
    """Parse GPT partition table - FIXED version"""
    partitions = []
    
    try:
        # Parse GPT header
        header_size = struct.unpack("<I", header[12:16])[0]
        lba_table = struct.unpack("<Q", header[72:80])[0]
        num_partitions = struct.unpack("<I", header[80:84])[0]
        part_entry_size = struct.unpack("<I", header[84:88])[0]
        
        # Calculate partition table location
        table_offset = lba_table * soc_info['sector_size']
        
        # Read partition entries
        table_size = num_partitions * part_entry_size
        table_payload = struct.pack("<II", table_offset, table_size)
        resp = qslcl_dispatch(dev, "READ", table_payload)
        
        if resp and len(resp) >= table_size:
            pos = 0
            for i in range(num_partitions):
                if pos + part_entry_size <= len(resp):
                    entry = resp[pos:pos + part_entry_size]
                    
                    # Parse partition entry
                    part_type_guid = entry[0:16]
                    part_guid = entry[16:32]
                    first_lba = struct.unpack("<Q", entry[32:40])[0]
                    last_lba = struct.unpack("<Q", entry[40:48])[0]
                    attributes = struct.unpack("<Q", entry[48:56])[0]
                    name = entry[56:128].decode('utf-16le', errors='ignore').rstrip('\x00')
                    
                    if first_lba > 0 and last_lba >= first_lba:
                        offset = first_lba * soc_info['sector_size']
                        size = (last_lba - first_lba + 1) * soc_info['sector_size']
                        
                        # Generate friendly name if needed
                        if not name or name.strip() == '':
                            name = generate_partition_name(part_type_guid, i)
                        
                        partitions.append({
                            'name': name,
                            'offset': offset,
                            'size': size,
                            'type': 'GPT',
                            'guid': part_guid.hex(),
                            'type_guid': part_type_guid.hex(),
                            'attributes': attributes
                        })
                    
                    pos += part_entry_size
    except Exception as e:
        print(f"[!] GPT parsing error: {e}")
    
    return partitions

def generate_partition_name(guid, index):
    """Generate friendly partition name from GUID"""
    guid_str = guid.hex()
    
    # Common GUIDs
    guid_map = {
        "c12a7328f81f11d2ba4b00a0c93ec93b": "efi_system",
        "024dee41-33e7-11d3-9d69-0008c781f39f": "mbr",
        "0fc63daf-8483-4772-8e79-3d69d8477de4": "linux_filesystem",
        "0657fd6da4ab43c484e50933c84b4f4f": "linux_swap",
        "e3c9e3160b5c4db8817df92df00215ae": "microsoft_reserved",
        "ebd0a0a2b9e5443387c068b6b72699c7": "microsoft_basic",
        "de94bba4061d4d40a01611f1fd03adac": "microsoft_recovery",
    }
    
    if guid_str in guid_map:
        return guid_map[guid_str]
    
    return f"part_{index}"

def detect_mbr_partitions(dev, soc_info):
    """Detect MBR partition table - FIXED version"""
    partitions = []
    
    try:
        # Read MBR sector
        mbr_payload = struct.pack("<II", 0, 512)
        resp = qslcl_dispatch(dev, "READ", mbr_payload)
        
        if resp and len(resp) >= 512:
            mbr = resp[:512]
            # Check MBR signature
            if mbr[510:512] == b'\x55\xAA':
                print("[+] MBR detected")
                
                # Parse partition entries (4 primary partitions)
                for i in range(4):
                    entry_offset = 446 + (i * 16)
                    if entry_offset + 16 <= 512:
                        entry = mbr[entry_offset:entry_offset + 16]
                        
                        # Check if partition is active
                        if entry[0] != 0 or entry[8:12] != b'\x00\x00\x00\x00':  # Boot indicator or LBA start
                            lba_start = struct.unpack("<I", entry[8:12])[0]
                            num_sectors = struct.unpack("<I", entry[12:16])[0]
                            
                            if lba_start > 0 and num_sectors > 0:
                                offset = lba_start * soc_info['sector_size']
                                size = num_sectors * soc_info['sector_size']
                                
                                # Determine partition type
                                part_type = entry[4]
                                type_name = mbr_partition_type(part_type)
                                
                                partitions.append({
                                    'name': f"mbr_part{i}_{type_name.lower()}",
                                    'offset': offset,
                                    'size': size,
                                    'type': 'MBR',
                                    'part_type': part_type,
                                    'type_name': type_name
                                })
    except Exception as e:
        print(f"[!] MBR detection error: {e}")
    
    return partitions

def mbr_partition_type(type_byte):
    """Map MBR partition type byte to name"""
    types = {
        0x00: "Empty",
        0x01: "FAT12",
        0x04: "FAT16",
        0x05: "Extended",
        0x06: "FAT16B",
        0x07: "NTFS",
        0x0B: "FAT32",
        0x0C: "FAT32LBA",
        0x0E: "FAT16LBA",
        0x0F: "ExtendedLBA",
        0x11: "HiddenFAT12",
        0x14: "HiddenFAT16",
        0x16: "HiddenFAT16B",
        0x17: "HiddenNTFS",
        0x1B: "HiddenFAT32",
        0x1C: "HiddenFAT32LBA",
        0x1E: "HiddenFAT16LBA",
        0x42: "MBR",
        0x82: "LinuxSwap",
        0x83: "Linux",
        0x85: "LinuxExtended",
        0x8E: "LinuxLVM",
        0xEE: "GPT",
        0xEF: "EFI",
    }
    return types.get(type_byte, f"Unknown_{type_byte:02X}")

def detect_android_partitions(dev, soc_info):
    """Detect Android partition layout - FIXED version"""
    partitions = []
    
    # Common Android partition offsets
    android_layouts = {
        'BOOT': 0x00000000,
        'SYSTEM': 0x10000000,
        'RECOVERY': 0x20000000,
        'CACHE': 0x30000000,
        'USERDATA': 0x40000000,
        'MISC': 0x50000000,
        'PERSIST': 0x60000000,
        'MODEM': 0x70000000,
    }
    
    for name, base_offset in android_layouts.items():
        try:
            # Try to detect partition by reading header
            for offset_mult in [0x0, 0x1000, 0x2000, 0x4000, 0x8000]:
                offset = base_offset + offset_mult
                test_payload = struct.pack("<II", offset, 512)
                resp = qslcl_dispatch(dev, "READ", test_payload)
                
                if resp and len(resp) >= 512:
                    # Check for common Android headers
                    if is_android_partition(resp[:512], name):
                        # Determine size by scanning
                        size = estimate_partition_size(dev, offset, soc_info)
                        
                        partitions.append({
                            'name': name.lower(),
                            'offset': offset,
                            'size': size,
                            'type': 'ANDROID',
                            'detected_by': 'signature'
                        })
                        break
        except Exception:
            continue
    
    return partitions

def is_android_partition(data, name):
    """Check if data indicates Android partition"""
    if len(data) < 512:
        return False
    
    # Check for common Android signatures
    if name == "BOOT" and data[:8] == b"ANDROID!":
        return True
    elif name == "SYSTEM" and b"ext" in data[:32].lower():
        return True
    elif name == "RECOVERY" and b"recovery" in data[:64].lower():
        return True
    
    # Check for filesystem signatures
    if data[:2] == b'\x53\xEF':  # ext filesystem
        return True
    
    return False

def detect_apple_partitions(dev, soc_info):
    """Detect Apple partitions (APFS, HFS+, etc.) - FIXED version"""
    partitions = []
    
    # Apple-specific partition locations
    apple_offsets = [
        0x0,                    # Boot ROM
        0x1000,                 # LLB
        0x4000,                 # iBoot
        0x8000,                 # Kernel
        0x20000,                # Filesystem
        0x100000,               # Large partitions
    ]
    
    for offset in apple_offsets:
        try:
            # Read potential partition header
            header_payload = struct.pack("<II", offset, 1024)
            resp = qslcl_dispatch(dev, "READ", header_payload)
            
            if resp and len(resp) >= 1024:
                # Check for Apple filesystem signatures
                if b'APFS' in resp[:512] or b'HFS' in resp[:512] or b'MBR' in resp[:512]:
                    # Try to determine partition type
                    part_type = 'APFS' if b'APFS' in resp[:512] else 'HFS+' if b'HFS' in resp[:512] else 'MBR'
                    
                    # Estimate size
                    size = estimate_partition_size(dev, offset, soc_info)
                    
                    partitions.append({
                        'name': f"apple_{part_type.lower()}_{offset:08x}",
                        'offset': offset,
                        'size': size,
                        'type': part_type,
                        'vendor': 'APPLE'
                    })
        except Exception:
            continue
    
    return partitions

def detect_custom_partitions(dev, soc_info):
    """Detect custom/unknown partitions"""
    partitions = []
    
    # Scan common memory regions for partitions
    scan_regions = [
        (0x00000000, 0x01000000),  # Boot area
        (0x10000000, 0x20000000),  # System area
        (0x80000000, 0xC0000000),  # Main memory
    ]
    
    for start, end in scan_regions:
        try:
            # Scan in 1MB chunks
            for offset in range(start, end, 0x100000):
                test_payload = struct.pack("<II", offset, 512)
                resp = qslcl_dispatch(dev, "READ", test_payload)
                
                if resp and len(resp) >= 512:
                    # Look for partition signatures
                    if is_partition_signature(resp[:512]):
                        size = estimate_partition_size(dev, offset, soc_info)
                        partitions.append({
                            'name': f"custom_{offset:08x}",
                            'offset': offset,
                            'size': size,
                            'type': 'CUSTOM',
                            'signature': resp[:8].hex()
                        })
        except Exception:
            continue
    
    return partitions

def is_partition_signature(data):
    """Check if data contains partition signature"""
    if len(data) < 8:
        return False
    
    # Common partition signatures
    signatures = [
        b'ANDROID!',  # Android boot
        b'\x7fELF',   # ELF executable
        b'APFS',      # Apple filesystem
        b'HFS',       # HFS filesystem
        b'NTFS',      # NTFS
        b'FAT',       # FAT filesystem
        b'ext',       # ext filesystem
    ]
    
    for sig in signatures:
        if sig in data[:64]:
            return True
    
    return False

def estimate_partition_size(dev, start_offset, soc_info):
    """Estimate partition size by scanning"""
    max_scan = 256 * 1024 * 1024  # 256MB max scan
    step = soc_info['sector_size'] * 1024  # 1MB steps
    
    for offset in range(start_offset + step, start_offset + max_scan, step):
        try:
            test_payload = struct.pack("<II", offset, 512)
            resp = qslcl_dispatch(dev, "READ", test_payload)
            
            if not resp or len(resp) < 512:
                # End of readable area
                return offset - start_offset
                
            # Check for pattern indicating end of partition
            if is_partition_boundary(resp[:512]):
                return offset - start_offset
                
        except Exception:
            break
    
    return step  # Default to 1MB if can't determine

def is_partition_boundary(data):
    """Check if data indicates partition boundary"""
    # All zeros often indicates unallocated space
    if data == b'\x00' * 512:
        return True
    
    # Common partition boundary patterns
    boundary_patterns = [
        b'\x00\x00\x00\x00\x00\x00\x00\x00',  # Null pattern
        b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',  # All ones
        b'\xDE\xAD\xBE\xEF',  # Common marker
    ]
    
    for pattern in boundary_patterns:
        if pattern in data:
            return True
    
    return False

def deduplicate_partitions(partitions):
    """Remove duplicate partitions and merge overlapping ones"""
    unique = {}
    
    for part in partitions:
        key = (part['offset'], part['size'])
        if key not in unique:
            unique[key] = part
        else:
            # Merge names if same partition detected multiple ways
            existing = unique[key]
            if 'detected_by' in part and 'detected_by' in existing:
                existing['detected_by'] = f"{existing['detected_by']}+{part['detected_by']}"
    
    return list(unique.values())

def get_soc_fallback_partitions(soc_info):
    """Get SOC-specific fallback partitions"""
    soc_type = soc_info.get('vendor', 'GENERIC')
    
    fallbacks = {
        'APPLE': [
            {"name": "bootrom", "offset": 0x0, "size": 0x100000},
            {"name": "llb", "offset": 0x1000, "size": 0x4000},
            {"name": "iboot", "offset": 0x4000, "size": 0x4000},
            {"name": "kernel", "offset": 0x8000, "size": 0x20000},
            {"name": "filesystem", "offset": 0x20000, "size": 0x1000000},
        ],
        'QUALCOMM': [
            {"name": "sbl1", "offset": 0x0, "size": 0x100000},
            {"name": "aboot", "offset": 0x100000, "size": 0x100000},
            {"name": "boot", "offset": 0x200000, "size": 0x2000000},
            {"name": "system", "offset": 0x4000000, "size": 0x40000000},
            {"name": "userdata", "offset": 0x80000000, "size": 0x80000000},
        ],
        'GENERIC': [
            {"name": "boot", "offset": 0x880000, "size": 0x400000},
            {"name": "system", "offset": 0xC80000, "size": 0x8000000},
            {"name": "recovery", "offset": 0x88C80000, "size": 0x400000},
            {"name": "cache", "offset": 0x90C80000, "size": 0x4000000},
            {"name": "userdata", "offset": 0x94C80000, "size": 0x40000000},
        ]
    }
    
    return fallbacks.get(soc_type, fallbacks['GENERIC'])

def detect_memory_regions(dev):
    """Detect memory regions and ranges - FIXED version"""
    global MEMORY_REGION_CACHE
    
    dev_key = dev.serial if hasattr(dev, 'serial') else 'default'
    if dev_key in MEMORY_REGION_CACHE:
        return MEMORY_REGION_CACHE[dev_key]
    
    regions = []
    
    try:
        # Query memory map via QSLCL
        mem_payload = struct.pack("<B", 0x20)  # MEMORY_MAP command
        resp = qslcl_dispatch(dev, "GETINFO", mem_payload)
        
        if resp and len(resp) >= 32:
            pos = 0
            while pos + 32 <= len(resp):
                start = struct.unpack("<Q", resp[pos:pos+8])[0]
                end = struct.unpack("<Q", resp[pos+8:pos+16])[0]
                perms = resp[pos+16:pos+20].decode('ascii', errors='ignore')
                name = resp[pos+20:pos+32].decode('ascii', errors='ignore').rstrip('\x00')
                
                if start > 0 and end > start:
                    regions.append({
                        'name': name or f"region_{start:016x}",
                        'start': start,
                        'end': end,
                        'size': end - start,
                        'permissions': perms
                    })
                
                pos += 32
        
        # Fallback: Common memory regions
        if not regions:
            regions = [
                {'name': 'boot_rom', 'start': 0x00000000, 'end': 0x00100000, 'size': 0x00100000, 'permissions': 'r-x'},
                {'name': 'sram', 'start': 0x10000000, 'end': 0x11000000, 'size': 0x01000000, 'permissions': 'rwx'},
                {'name': 'ddr', 'start': 0x80000000, 'end': 0xC0000000, 'size': 0x40000000, 'permissions': 'rwx'},
                {'name': 'io', 'start': 0xC0000000, 'end': 0xE0000000, 'size': 0x20000000, 'permissions': 'rw-'},
            ]
    
    except Exception as e:
        print(f"[!] Memory region detection error: {e}")
    
    MEMORY_REGION_CACHE[dev_key] = regions
    return regions

# =============================================================================
# FIXED: TARGET RESOLUTION FUNCTIONS
# =============================================================================
def resolve_target(target, partitions, memory_regions, dev):
    """Resolve target string to address, size, and metadata - FIXED version"""
    target = str(target).strip().lower()
    
    # Case 1: Direct partition name
    for part in partitions:
        if part['name'].lower() == target:
            return {
                'address': part['offset'],
                'size': part['size'],
                'partition_info': part,
                'region_info': None,
                'is_partition': True
            }
    
    # Case 2: Memory region name
    for region in memory_regions:
        if region['name'].lower() == target:
            return {
                'address': region['start'],
                'size': region['size'],
                'partition_info': None,
                'region_info': region,
                'is_partition': False
            }
    
    # Case 3: Partition+offset format (e.g., "boot+0x1000")
    if '+' in target:
        try:
            part_name, offset_str = target.split('+', 1)
            offset = parse_address(offset_str)
            
            for part in partitions:
                if part['name'].lower() == part_name.lower():
                    address = part['offset'] + offset
                    # Check if offset is within partition
                    if 0 <= offset <= part['size']:
                        remaining_size = part['size'] - offset
                        return {
                            'address': address,
                            'size': remaining_size,
                            'partition_info': part,
                            'region_info': None,
                            'is_partition': True
                        }
                    else:
                        print(f"[!] Offset 0x{offset:08X} is outside partition {part_name}")
                        return None
        except Exception as e:
            print(f"[!] Failed to parse partition+offset: {e}")
            return None
    
    # Case 4: Memory region+offset
    if ':' in target:
        try:
            region_name, offset_str = target.split(':', 1)
            offset = parse_address(offset_str)
            
            for region in memory_regions:
                if region['name'].lower() == region_name.lower():
                    address = region['start'] + offset
                    if 0 <= offset <= region['size']:
                        remaining_size = region['size'] - offset
                        return {
                            'address': address,
                            'size': remaining_size,
                            'partition_info': None,
                            'region_info': region,
                            'is_partition': False
                        }
        except Exception:
            pass
    
    # Case 5: Raw address
    try:
        address = parse_address(target)
        
        # Find containing partition
        partition_info = None
        for part in partitions:
            if part['offset'] <= address < part['offset'] + part['size']:
                partition_info = part
                remaining_size = part['offset'] + part['size'] - address
                return {
                    'address': address,
                    'size': remaining_size,
                    'partition_info': part,
                    'region_info': None,
                    'is_partition': True
                }
        
        # Find containing memory region
        region_info = None
        for region in memory_regions:
            if region['start'] <= address < region['end']:
                region_info = region
                remaining_size = region['end'] - address
                return {
                    'address': address,
                    'size': remaining_size,
                    'partition_info': None,
                    'region_info': region,
                    'is_partition': False
                }
        
        # No container found, use default size
        return {
            'address': address,
            'size': 0x1000,  # Default 4KB
            'partition_info': None,
            'region_info': None,
            'is_partition': False
        }
        
    except ValueError as e:
        print(f"[!] Invalid address format: {target} - {e}")
        return None

def parse_address(addr_str):
    """Enhanced address parsing"""
    addr_str = str(addr_str).strip().lower()
    
    # Remove whitespace
    addr_str = ''.join(addr_str.split())
    
    # Handle common formats
    if addr_str.startswith('0x'):
        return int(addr_str[2:], 16)
    elif addr_str.startswith('$'):
        return int(addr_str[1:], 16)
    elif addr_str.startswith('&h'):
        return int(addr_str[2:], 16)
    elif ':' in addr_str:  # Segment:offset format
        segment, offset = addr_str.split(':', 1)
        return (int(segment, 16) << 4) + int(offset, 16)
    else:
        # Try decimal, then hex
        try:
            return int(addr_str)
        except ValueError:
            return int(addr_str, 16)

def parse_size_string(size_str):
    """Parse size string with support for units and expressions"""
    size_str = str(size_str).strip().upper()
    
    # Remove whitespace
    size_str = ''.join(size_str.split())
    
    # Handle expressions
    if '+' in size_str:
        parts = size_str.split('+')
        return sum(parse_size_string(p) for p in parts)
    elif '-' in size_str:
        parts = size_str.split('-')
        return parse_size_string(parts[0]) - parse_size_string(parts[1])
    
    # Handle units
    units = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024*1024,
        'MB': 1024*1024,
        'G': 1024*1024*1024,
        'GB': 1024*1024*1024,
        'T': 1024*1024*1024*1024,
        'TB': 1024*1024*1024*1024,
    }
    
    # Check for unit at end
    for unit, multiplier in units.items():
        if size_str.endswith(unit):
            number = size_str[:-len(unit)]
            return int(float(number)) * multiplier
    
    # Hex format
    if size_str.startswith('0X'):
        return int(size_str[2:], 16)
    
    # Assume decimal
    return int(size_str)

# =============================================================================
# CONTINUE WITH EXISTING FUNCTIONS (UPDATED FOR STRUCTURED FORMAT)
# =============================================================================

def qslcl_decode_rtf(resp):
    """
    Decode QSLCL Runtime Fault Frame
    """
    if not resp:
        return {"severity": "ERROR", "name": "NO_RESPONSE", "extra": b""}
    
    # Simple implementation - reuse existing decode_runtime_result logic
    return decode_runtime_result(resp)

def qslclidx_get_cmd(cmd_name):
    """
    Find IDX entry by command name
    """
    for name, entry in QSLCLIDX_DB.items():
        if name.upper() == cmd_name.upper():
            return entry
    return None

def qslclidx_get_cert(idx):
    """
    IDX → certificate or certificate-related entry.
    """
    mapping = {
        0x10: "QSLCCERT",
        0x11: "QSLCHMAC",
        0x12: "QSLCSHA2",
        0x13: "QSLCHASH",
        0x14: "QSLCSIGS",
        0x15: "QSLCFPRT",
        0x16: "QSLCHWAN",
        0x17: "QSLCMETA",
        0x18: "QSLCMERK"
    }

    if idx not in mapping:
        return None

    name = mapping[idx]
    return QSLCLHDR_DB.get(name, None)

# =============================================================================
# DEVICE MANAGEMENT FUNCTIONS
# =============================================================================
def wait_for_device(timeout=None, interval=0.5):
    """
    Waits for any valid QSLCL-capable device to appear.
    No VID/PID hardcoding. Uses universal class-based validation.
    """

    start = time.time()

    while True:
        devs = scan_all()

        # Pick highest-ranked device
        if devs:
            dev = devs[0]
            if validate_device(dev):
                return dev

        if timeout is not None and (time.time() - start) >= timeout:
            return None

        time.sleep(interval)

def validate_device(dev: QSLCLDevice):
    """
    FIXED: More permissive device validation for development
    """
    # Only block clearly incompatible devices
    if dev.usb_class in (0x03, 0x09):  # HID and hubs
        return False

    # Allow everything else for development
    return True

# =============================================================================
# SCANNERS - FIXED: Added error handling
# =============================================================================
def scan_serial():
    if not SERIAL_SUPPORT:
        return []

    devs = []

    try:
        for p in list_ports.comports():
            # VID/PID extracted automatically from USB-CDC
            vid = getattr(p, "vid", None)
            pid = getattr(p, "pid", None)

            devs.append(QSLCLDevice(
                transport="serial",
                identifier=p.device,
                vendor=p.manufacturer or "Unknown",
                product=p.description or "Serial",
                vid=vid,
                pid=pid,
                serial=p.serial_number or "default",
                handle=None  # Don't store the path here, will open later
            ))
    except Exception as e:
        print(f"[!] Serial scan error: {e}")

    return devs

def scan_usb():
    if not USB_SUPPORT:
        return []

    devs = []

    try:
        for d in usb.core.find(find_all=True):
            try:
                # Must be able to open config
                try:
                    cfg = d.get_active_configuration()
                except usb.core.USBError:
                    continue

                intf = cfg[(0, 0)]

                # ----------------------------------------------
                #  AUTO FILTER:
                #  Reject HID, Audio, Mass Storage automatically
                # ----------------------------------------------
                if intf.bInterfaceClass in (0x01, 0x02, 0x03, 0x07, 0x08, 0x0A):
                    # Audio / CommCtrl / HID / Printer / Mass Storage / CDC Data
                    continue

                # ----------------------------------------------
                # VALID QSLCL DEVICE RULE:
                # Must have at least one Bulk endpoint
                # ----------------------------------------------
                ep_in  = None
                ep_out = None

                for ep in intf.endpoints():
                    if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                        if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                            ep_in = ep
                    else:
                        if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                            ep_out = ep

                # Must have both bulk IN and OUT
                if not ep_in or not ep_out:
                    continue

                # ----------------------------------------------
                # Get product name (optional)
                # ----------------------------------------------
                try:
                    product = usb.util.get_string(d, d.iProduct) or "USB Device"
                except:
                    product = "USB Device"
                
                # Get serial number if available
                try:
                    serial = usb.util.get_string(d, d.iSerialNumber) or "default"
                except:
                    serial = "default"

                devs.append(QSLCLDevice(
                    transport="usb",
                    identifier=f"bus={d.bus},addr={d.address}",
                    vendor=f"VID_{d.idVendor:04X}",
                    product=product,
                    vid=d.idVendor,
                    pid=d.idProduct,
                    usb_class=intf.bInterfaceClass,
                    usb_subclass=intf.bInterfaceSubClass,
                    usb_protocol=intf.bInterfaceProtocol,
                    serial=serial,
                    handle=d,
                    serial_mode=False
                ))

            except Exception:
                continue
    except Exception as e:
        print(f"[!] USB scan error: {e}")

    return devs

def scan_all():
    devs = scan_usb() + scan_serial()

    # Smart sorting by likelihood
    def score(d):
        s = 0

        # Vendor-specific interface => highest (bootloaders, edl, fastboot)
        if d.usb_class == 0xFF:
            s += 100

        # USB CDC / diagnostic / modem classes
        if d.usb_class in (0x0A, 0x02):
            s += 70

        # Recognizable product name
        if d.product and d.product not in ("USB Device", "Serial", "Unknown"):
            s += 30

        # Serial devices with VID/PID
        if d.vid and d.pid:
            s += 20

        # USB transport wins over serial in general
        if d.transport == "usb":
            s += 10

        return -s  # sort descending

    devs.sort(key=score)
    return devs

# =============================================================================
# ENCODERS
# =============================================================================
def encode_cmd(cmd: str, extra: bytes = b""):
    payload = cmd.encode() + (b" " + extra if extra else b"")
    return b"QSLCLCMD" + len(payload).to_bytes(4, "little") + payload

def encode_resp_request():
    p = b"RESPONSE"
    return b"QSLCLCMD" + len(p).to_bytes(4, "little") + p

# =============================================================================
# FRAME PARSER - FIXED: Added proper magic length checking
# =============================================================================
def parse_frame(buff: bytes):
    if len(buff) < 14:  # Minimum frame size
        return None, None
        
    if buff.startswith(b"QSLCLRESP"):
        try:
            size = int.from_bytes(buff[9:13], "little")  # Fixed index: 9-13 not 10-14
            if 14 + size <= len(buff):
                return "RESP", buff[14:14+size]
        except:
            pass

    if buff.startswith(b"QSLCLCMD"):
        try:
            size = int.from_bytes(buff[9:13], "little")  # Fixed index
            if 14 + size <= len(buff):
                return "CMD", buff[14:14+size]
        except:
            pass

    return None, None

def decode_runtime_result(resp, origin="DISPATCH"):
    """
    Fully compliant QSLCL Runtime Fault-Frame decoder (RTF v5.1)
    Returns a structured dict:
        {
            "severity": "...",
            "code": int,
            "name": "...",
            "extra": bytes,
            "origin": "DISPATCH/ENGINE/PAR/NANO/IDX"
        }
    """

    # ======================================================
    # 0. Basic safety
    # ======================================================
    if not resp or len(resp) < 2:
        return {
            "severity": "ERROR",
            "code": 0xFFFF,
            "name": "NO_RESPONSE",
            "extra": b"",
            "origin": origin
        }

    # ======================================================
    # 1. Extract 2-byte runtime code
    # ======================================================
    try:
        code = int.from_bytes(resp[0:2], "little")
    except:
        return {
            "severity": "ERROR",
            "code": 0xFFFE,
            "name": "PARSE_FAIL",
            "extra": resp,
            "origin": origin
        }

    # Remaining payload is "extra"
    extra = resp[2:] if len(resp) > 2 else b""

    # ======================================================
    # 2. Lookup in QSLCLRTF_DB
    # ======================================================
    if code in QSLCLRTF_DB:
        entry = QSLCLRTF_DB[code]
        level = entry.get("level", 0)
        name  = entry.get("msg", "UNKNOWN")

        level_name = {
            0: "SUCCESS",
            1: "WARNING",
            2: "ERROR",
            3: "CRITICAL",
            4: "FATAL",
        }.get(level, f"LVL{level}")

        return {
            "severity": level_name,
            "code": code,
            "name": name,
            "extra": extra,
            "origin": origin,
        }

    # ======================================================
    # 3. Fallback codes
    # ======================================================
    if code == 0:
        return {
            "severity": "SUCCESS",
            "code": 0x0000,
            "name": "OK",
            "extra": extra,
            "origin": origin
        }

    return {
        "severity": "UNKNOWN",
        "code": code,
        "name": f"UNDEFINED_RTF_0x{code:04X}",
        "extra": extra,
        "origin": origin
    }

# =============================================================================
# FIXED: IMPROVED TRANSPORT FUNCTIONS
# =============================================================================
def open_transport(dev):
    """Improved device opening with better error handling"""
    if dev.transport == "serial":
        try:
            h = serial.Serial(dev.identifier, 115200, timeout=1)
            dev.handle = h
            return h, True
        except Exception as e:
            print(f"[!] Failed to open serial port {dev.identifier}: {e}")
            return None, True
    else:
        # USB device - improved handling
        try:
            # Reset device first to ensure clean state
            try:
                dev.handle.reset()
            except:
                pass  # Ignore reset errors
                
            # Set configuration with error handling
            try:
                dev.handle.set_configuration()
            except usb.core.USBError as e:
                if e.errno != 16:  # Ignore "Resource busy" if already configured
                    print(f"[!] USB configuration failed: {e}")
                    return None, False
                    
            # Claim interface with error handling  
            try:
                usb.util.claim_interface(dev.handle, 0)
            except usb.core.USBError as e:
                if e.errno != 16:  # Ignore "Resource busy"
                    print(f"[!] USB interface claim failed: {e}")
                    return None, False
                    
            return dev.handle, False
            
        except Exception as e:
            print(f"[!] Failed to configure USB device: {e}")
            # Try to find the device again
            try:
                if dev.vid and dev.pid:
                    new_dev = usb.core.find(idVendor=dev.vid, idProduct=dev.pid)
                    if new_dev:
                        dev.handle = new_dev
                        print("[*] Retrying with fresh device handle...")
                        return open_transport(dev)  # Retry with new handle
            except Exception as retry_e:
                print(f"[!] Device retry failed: {retry_e}")
            return None, False

def send(handle, payload, serial_mode):
    """
    Safe universal packet writer for:
        - Serial (UART/USB-CDC)
        - USB bulk (pyusb) device (EP_OUT)
    """
    if serial_mode:
        try:
            handle.write(payload)
            return len(payload)
        except Exception as e:
            print("[!] SERIAL WRITE ERROR:", e)
            return 0
    else:
        # USB mode (handle is a usb.core.Device)
        try:
            # Find the correct OUT endpoint
            cfg = handle.get_active_configuration()
            intf = cfg[(0,0)]
            ep_out = None
            for ep in intf.endpoints():
                if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                    usb.util.ENDPOINT_OUT and
                    usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                    ep_out = ep
                    break
            
            if ep_out:
                return handle.write(ep_out.bEndpointAddress, payload, timeout=2000)
            else:
                # Fallback to control transfer
                return handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, payload)
        except Exception as e:
            print("[!] USB WRITE ERROR:", e)
            return 0

def recv(handle, serial_mode, timeout=3.0):
    """
    Enhanced response receiver with better USB handling
    """
    deadline = time.time() + timeout
    buff = bytearray()

    # Protocol constants
    RESP_MAGIC = b"QSLCLRESP"
    CMD_MAGIC  = b"QSLCLCMD"

    RESP_HEADER = len(RESP_MAGIC)     # 9 bytes
    CMD_HEADER  = len(CMD_MAGIC)      # 9 bytes

    # Minimum structure:
    #   MAGIC (9) + VER(1) + SIZE(4) + PAYLOAD(size)
    #   total header = 14 bytes
    MIN_FRAME = 14

    while time.time() < deadline:
        # ------------------------------------------------------
        # Read chunk with improved error handling
        # ------------------------------------------------------
        try:
            if serial_mode:
                chunk = handle.read(64)
            else:
                # Improved USB endpoint detection
                chunk = b""
                try:
                    cfg = handle.get_active_configuration()
                    intf = cfg[(0,0)]
                    
                    # Try all IN endpoints
                    for ep in intf.endpoints():
                        if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                            usb.util.ENDPOINT_IN):
                            try:
                                chunk = handle.read(ep.bEndpointAddress, 64, timeout=500)
                                if chunk:
                                    break
                            except usb.core.USBError as e:
                                if e.errno != 110:  # Ignore timeout errors
                                    print(f"[!] USB endpoint read error: {e}")
                except Exception as e:
                    print(f"[!] USB configuration error in recv: {e}")
                    
            if chunk:
                buff.extend(chunk)

        except Exception as e:
            print(f"[!] Receive read error: {e}")
            break

        # ------------------------------------------------------
        # Scan for RESP frames
        # ------------------------------------------------------
        idx = buff.find(RESP_MAGIC)
        if idx >= 0 and len(buff) >= idx + MIN_FRAME:
            # Extract length from: MAGIC(9) + VER(1) + SIZE(4)
            try:
                size = struct.unpack("<I", buff[idx+10:idx+14])[0]
            except:
                size = -1

            end = idx + 14 + size
            if size >= 0 and len(buff) >= end:
                payload = bytes(buff[idx+14:end])
                del buff[:end]
                return "RESP", payload

        # ------------------------------------------------------
        # Scan for CMD frames
        # ------------------------------------------------------
        jdx = buff.find(CMD_MAGIC)
        if jdx >= 0 and len(buff) >= jdx + MIN_FRAME:
            try:
                size = struct.unpack("<I", buff[jdx+10:jdx+14])[0]
            except:
                size = -1

            end = jdx + 14 + size
            if size >= 0 and len(buff) >= end:
                payload = bytes(buff[jdx+14:end])
                del buff[:end]
                return "CMD", payload

        # ------------------------------------------------------
        # Avoid burning CPU
        # ------------------------------------------------------
        time.sleep(0.002)

    return None, None

def detect_device_type(handle):
    """
    Universal hybrid detection:
    - MTK BootROM    : handshake 0xA0 or 'BOOTROM'
    - Qualcomm EDL   : response 'OKAY', 'INFO', or sahara/edl signatures
    - DFU Apple      : static DFU signatures or DFU mode via USB interface
    - Generic USB    : fallback to QSLCL universal packets
    """
    try:
        # Non-blocking peek
        data = handle.read(64)
    except:
        return "GENERIC"

    if not data:
        return "GENERIC"

    text = data.decode(errors="ignore").upper()

    if "BOOTROM" in text or "BR" in text or data.startswith(b"\xA0"):
        return "MTK"

    if "EDL" in text or "SAHARA" in text or "FIREHOSE" in text:
        return "QUALCOMM"

    if "DFU" in text or b"\x12\x01" in data[:4]:
        return "APPLE_DFU"

    return "GENERIC"

# =============================================================================
# UPDATED COMMAND DISPATCH FOR QSLCLCMD
# =============================================================================
def qslcl_dispatch(dev, cmd_name, payload=b"", timeout=1.0):
    """
    Unified dispatcher using QSLCLCMD database
    """
    cmd_upper = cmd_name.upper()

    # Single source: QSLCLCMD (supports both name and opcode lookup)
    if cmd_upper in QSLCLCMD_DB:
        cmd_entry = QSLCLCMD_DB[cmd_upper]
        print(f"[*] QSLCLCMD dispatch → {cmd_upper} (opcode: 0x{cmd_entry['opcode']:02X})")
        
        # Build execution packet using QSLCLCMD format
        # The command data contains the micro-VM code from generate_command_code
        pkt = b"QSLCLCMD" + struct.pack("<B", cmd_entry['opcode']) + cmd_entry['data'] + payload
        return exec_universal(dev, cmd_upper, pkt)

    # Numeric opcode fallback
    try:
        opcode = int(cmd_name, 0)
        if opcode in QSLCLCMD_DB:
            cmd_entry = QSLCLCMD_DB[opcode]
            print(f"[*] QSLCLCMD dispatch → opcode 0x{opcode:02X} ({cmd_entry['name']})")
            pkt = b"QSLCLCMD" + struct.pack("<B", opcode) + cmd_entry['data'] + payload
            return exec_universal(dev, cmd_entry['name'], pkt)
    except (ValueError, KeyError):
        pass

    # Final fallback to direct command
    print(f"[*] Fallback dispatch → {cmd_upper}")
    return exec_universal(dev, cmd_upper, payload)

def exec_universal(dev, cmd_name, payload):
    """
    Enhanced universal command executor with retry mechanism
    """
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            # Ensure device is open
            if dev.handle is None:
                dev.handle, dev.serial_mode = open_transport(dev)
                if dev.handle is None:
                    raise RuntimeError("Failed to open device transport")

            # Send the command
            dev.write(payload)
            
            # Wait for response with increasing timeout
            response_timeout = 2.0 + (attempt * 1.0)  # 2s, 3s, 4s
            response = dev.read(timeout=response_timeout)
            
            if response is not None:
                return response
                
            if attempt < max_retries:
                print(f"[!] No response on attempt {attempt + 1}, retrying...")
                time.sleep(0.5)
                
        except Exception as e:
            if attempt < max_retries:
                print(f"[!] Command execution failed on attempt {attempt + 1}: {e}")
                print(f"[*] Retrying...")
                time.sleep(1.0)
            else:
                print(f"[!] Command execution failed after {max_retries + 1} attempts: {e}")
                
    return None

# =============================================================================
# SECTOR SIZE DETECTOR - UPDATED FOR STRUCTURED FORMAT
# =============================================================================
def detect_sector_size(dev):
    """
    Ultra-robust sector/page size detector for QSLCL-based devices.
    Updated for QSLCLCMD system.
    """
    VALID_SIZES = {512, 1024, 2048, 4096, 8192, 16384}

    h, serial_mode = open_transport(dev)

    # ============================================================
    # 1. QSLCLCMD GETSECTOR handler (primary method)
    # ============================================================
    if "GETSECTOR" in QSLCLCMD_DB:
        try:
            resp = qslcl_dispatch(dev, "GETSECTOR", b"")
            if resp:
                status = decode_runtime_result(resp)
                if status["extra"] and len(status["extra"]) >= 4:
                    v = int.from_bytes(status["extra"][:4], "little")
                    if v in VALID_SIZES:
                        print("[*] Sector size via QSLCLCMD/GETSECTOR =", v)
                        return v
        except:
            pass

    # ============================================================
    # 2. QSLCLIDX GETSECTOR override
    # ============================================================
    for entry_id, e in QSLCLIDX_DB.items():
        if isinstance(e, dict) and e.get("name") == "GETSECTOR":
            try:
                resp = qslcl_dispatch(dev, "GETSECTOR", b"")
                if resp:
                    status = decode_runtime_result(resp)
                    if status["extra"] and len(status["extra"]) >= 4:
                        v = int.from_bytes(status["extra"][:4], "little")
                        if v in VALID_SIZES:
                            print("[*] Sector size via QSLCLIDX/GETSECTOR =", v)
                            return v
            except:
                pass

    # ============================================================
    # 3. GETVAR("SECTOR_SIZE")
    # ============================================================
    try:
        pkt = encode_cmd("GETVAR", b"SECTOR_SIZE")
        send(h, pkt, serial_mode)
        t, data = recv(h, serial_mode)
        if t == "RESP" and data:
            try:
                v = int(data.decode(errors="ignore"), 0)
                if v in VALID_SIZES:
                    print("[*] Sector size via GETVAR(SECTOR_SIZE) =", v)
                    return v
            except:
                pass
    except:
        pass

    # ============================================================
    # 4. GETINFO structured field scanning (RTF)
    # ============================================================
    try:
        resp = qslcl_dispatch(dev, "GETINFO")
        if resp:
            status = decode_runtime_result(resp)
            extra = status["extra"]

            # Common offsets where page size appears
            for offs in (0x10, 0x14, 0x18, 0x1C, 0x20, 0x24):
                if offs + 4 <= len(extra):
                    v = int.from_bytes(extra[offs:offs+4], "little")
                    if v in VALID_SIZES:
                        print("[*] Sector size via GETINFO field =", v)
                        return v
    except:
        pass

    # ============================================================
    # 5. HELLO RTF frame
    # ============================================================
    try:
        resp = qslcl_dispatch(dev, "HELLO")
        if resp:
            status = decode_runtime_result(resp)
            extra = status["extra"]
            if len(extra) >= 4:
                v = int.from_bytes(extra[:4], "little")
                if v in VALID_SIZES:
                    print("[*] Sector size via HELLO RTF =", v)
                    return v
    except:
        pass

    # ============================================================
    # 6. Qualcomm Firehose XML
    # ============================================================
    dtype = detect_device_type(h)
    if dtype == "QUALCOMM":
        try:
            h.write(b"<data>getstorageinfo</data>")
            ans = h.read(2048)
            if ans:
                m = re.search(rb"<pagesize>(\d+)</pagesize>", ans)
                if m:
                    v = int(m.group(1))
                    if v in VALID_SIZES:
                        print("[*] Sector size via Firehose XML =", v)
                        return v
        except:
            pass

    # ============================================================
    # 7. MTK BootROM (PageSize=XXXX)
    # ============================================================
    if dtype == "MTK":
        try:
            h.write(b"\x00\x00\xA0\x0AINFO")
            ans = h.read(256)
            if ans:
                m = re.search(rb"PageSize=(\d+)", ans)
                if m:
                    v = int(m.group(1))
                    if v in VALID_SIZES:
                        print("[*] Sector size via MTK BootROM =", v)
                        return v
        except:
            pass

    # ============================================================
    # 8. Apple DFU fixed size
    # ============================================================
    if dtype == "APPLE_DFU":
        print("[*] Sector size via Apple DFU = 4096")
        return 4096

    # ============================================================
    # 9. Safe fallback
    # ============================================================
    print("[!] Fallback sector size = 4096")
    return 4096

def get_sector_size(dev):
    """
    Cached wrapper. Ensures we only detect once.
    """
    global _DETECTED_SECTOR_SIZE
    if _DETECTED_SECTOR_SIZE:
        return _DETECTED_SECTOR_SIZE

    sz = detect_sector_size(dev)
    print(f"[*] SECTOR SIZE DETECTED = {sz}")
    _DETECTED_SECTOR_SIZE = sz
    return sz

# =============================================================================
# UPDATED LOADER SENDER WITH STRUCTURED FORMAT SUPPORT
# =============================================================================
def send_packets(handle, data, serial_mode, chunk=4096):
    """Send QSLCL binary with proper framing"""
    total = len(data)
    sent = 0
    
    # Check if data starts with QSLCLBIN magic (structured format)
    if total >= 20:
        try:
            bin_struct = decode_qslcl_structure(data)
            if bin_struct['magic'] == b"QSLCLBIN":
                print("[*] Sending structured QSLCL binary...")
                print(f"[+] Structured binary: size={bin_struct['size']}, flags=0x{bin_struct['flags']:08X}")
        except:
            pass
    
    for off in range(0, total, chunk):
        blk = data[off:off+chunk]
        
        # Use QSLCL framing: [QSLCL][size][data]
        header = b"QSLCL" + len(blk).to_bytes(4, "little")
        pkt = header + blk
        
        if serial_mode:
            handle.write(pkt)
        else:
            try:
                # Find the correct OUT endpoint for USB
                cfg = handle.get_active_configuration()
                intf = cfg[(0,0)]
                ep_out = None
                for ep in intf.endpoints():
                    if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                        usb.util.ENDPOINT_OUT and
                        usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                        ep_out = ep
                        break
                
                if ep_out:
                    handle.write(ep_out.bEndpointAddress, pkt, timeout=2000)
                else:
                    handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, pkt)
            except Exception as e:
                print(f"[!] Packet send error: {e}")
        
        sent += len(blk)
        print(f"\r[*] Transfer progress... {sent*100/total:5.1f}%", end="")
        time.sleep(0.01)
    
    print("\n[+] Transfer complete.")

def handle_authentication(args):
    if not getattr(args, "auth", False):
        return True

    devs = scan_all()
    if not devs:
        print("[!] No device connected for authentication.")
        return False

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    print("[*] Authenticating loader…")

    # ---------------------------------------------------------------
    # Step 1: Confirm QSLCLHDR exists
    # ---------------------------------------------------------------
    if not QSLCLHDR_DB:
        print("[!] No QSLCLHDR block loaded. Authentication not possible.")
        return False

    # ---------------------------------------------------------------
    # Step 2: Extract certificate + optional metadata
    # ---------------------------------------------------------------
    cert = QSLCLHDR_DB.get("QSLCCERT")
    hmac_tag = QSLCLHDR_DB.get("QSLCHMAC")
    fingerprint = QSLCLHDR_DB.get("QSLCSHA2")

    if not cert:
        print("[!] QSLCCERT not found. Cannot authenticate.")
        return False

    print(f"[*] Certificate detected: {len(cert)} bytes")
    if hmac_tag:
        print("[*] HMAC detected (short 16-byte tag)")
    if fingerprint:
        print("[*] SHA-256 fingerprint detected")

    # ---------------------------------------------------------------
    # Step 3: Build payload
    # ---------------------------------------------------------------
    payload = b"QSLCCERT" + cert
    if hmac_tag:
        payload += b"QSLCHMAC" + hmac_tag
    if fingerprint:
        payload += b"QSLCSHA2" + fingerprint

    # ---------------------------------------------------------------
    # Step 4: Dispatch to available handler priority
    # ---------------------------------------------------------------
    # Priority 1 — QSLCLCMD AUTHENTICATE command
    if "AUTHENTICATE" in QSLCLCMD_DB:
        print("[*] AUTH via QSLCLCMD AUTHENTICATE command")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", payload)

    # Priority 2 — VM5 nano-service AUTHENTICATE
    elif "AUTHENTICATE" in QSLCLVM5_DB:
        print("[*] AUTH via QSLCLVM5 nano-service")
        raw = QSLCLVM5_DB["AUTHENTICATE"]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)

    # Priority 3 — opcode A5 (if exists in QSLCLCMD)
    elif 0xA5 in QSLCLCMD_DB:
        print("[*] AUTH via QSLCLCMD opcode A5")
        resp = qslcl_dispatch(dev, "0xA5", payload)

    # Priority 4 — fallback dispatcher
    else:
        print("[*] AUTH fallback mode")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", payload)

    # ---------------------------------------------------------------
    # Step 5: Decode via RTF
    # ---------------------------------------------------------------
    if resp:
        status = qslcl_decode_rtf(resp)
        print(f"[AUTH] {status}")

        if status.get("severity") != "SUCCESS":
            print("[!] Authentication failed. Stopping.")
            return False

        print("[✓] Authentication OK. Continuing…")
        return True
    
    print("[!] No authentication response")
    return False

def auto_loader_if_needed(args, dev):
    """
    Loads qslcl.bin only when --loader is specified.
    Updated for QSLCLCMD format.
    """
    if not getattr(args, "loader", None):
        return

    loader_path = args.loader
    print(f"[*] Loading loader: {loader_path}")

    # ============================================================
    # 1. Read loader safely
    # ============================================================
    try:
        with open(loader_path, "rb") as f:
            blob = f.read()
    except Exception as e:
        print(f"[!] Cannot read loader: {e}")
        return

    if len(blob) < 0x100:
        print("[!] Loader appears too small — aborting.")
        return

    # ============================================================
    # 2. Parse internal modules BEFORE sending
    # ============================================================
    print("[*] Parsing loader structures…")

    try:
        loader = QSLCLLoader()
        ok = loader.parse_loader(blob)
        if not ok:
            print("[!] Loader parsing failed.")
            # Don't abort here, just continue with warning

        print("[*] Detected modules:")
        print(f"    QSLCLCMD: {len(loader.CMD)//2} commands")  # Count unique commands
        print(f"    QSLCLIDX: {len(loader.IDX)} indices")
        print(f"    QSLCLVM5: {len(loader.VM5)} microsvcs")
        print(f"    QSLCLUSB: {len(loader.USB)} blocks")
        print(f"    QSLCLSPT: {len(loader.SPT)} blocks")
        print(f"    QSLCLHDR: {len(loader.HDR)} blocks")
        print()

    except Exception as e:
        print("[!] Loader parsing failed:", e)
        # Don't return, continue anyway

    # ============================================================
    # 3. Verify loader contains minimum required segments
    # ============================================================
    required = ["QSLCLCMD"]  # QSLCLCMD is required now
    missing = [r for r in required if not getattr(loader, r, {})]

    if missing:
        print(f"[!] Loader missing critical module: {missing}")
        print("[!] But continuing anyway - some commands may not work")
        # Don't abort here, just warn

    # ============================================================
    # 4. Open transport
    # ============================================================
    try:
        handle, serial_mode = open_transport(dev)
    except Exception as e:
        print("[!] Cannot open transport:", e)
        return

    # ============================================================
    # 5. Send loader into device
    # ============================================================
    print("[*] Uploading loader to device…")

    try:
        send_packets(handle, blob, serial_mode)
    except Exception as e:
        print("[!] Loader upload failed:", e)
    finally:
        if serial_mode and handle:
            handle.close()
        elif handle:
            usb.util.dispose_resources(handle)

    print("[+] Loader uploaded successfully.\n")

# =============================================================================
# COMMAND WRAPPERS
# =============================================================================
def cmd_hello(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]

    print("[*] Sending HELLO...")

    # Use QSLCLCMD system
    if "HELLO" in QSLCLCMD_DB:
        print("[*] Using QSLCLCMD HELLO command")
        resp = qslcl_dispatch(dev, "HELLO", b"")
    else:
        # Fallback
        resp = qslcl_dispatch(dev, "HELLO", b"")

    if not resp:
        return print("[!] HELLO: No response from device.")

    status = decode_runtime_result(resp)
    print("[*] HELLO Response:", status)

    # Display module summary
    print("[*] Loader Modules Detected:")
    unique_commands = len([name for name in QSLCLCMD_DB.keys() if isinstance(name, str) and name.isalpha()])
    print(f"  CMD commands : {unique_commands}")
    print(f"  DISP entries : {len(QSLCLDISP_DB)}")
    print(f"  RTF entries  : {len(QSLCLRTF_DB)}")

def cmd_ping(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    dev = devs[0]

    payload = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)

    # Use QSLCLCMD system
    if "PING" in QSLCLCMD_DB:
        print("[*] Using QSLCLCMD PING command")
        t0 = time.time()
        resp = qslcl_dispatch(dev, "PING", payload)
    else:
        t0 = time.time()
        resp = qslcl_dispatch(dev, "PING", payload)

    dt = (time.time() - t0) * 1000

    if not resp:
        return print("[!] PING: No response.")

    print(f"[*] RTT: {dt:.2f} ms")

    status = decode_runtime_result(resp)
    print(f"[*] RUNTIME: {status}")

    if dt > 150:
        print("[!] Warning: High latency (runtime engine or cable?)")

def cmd_getinfo(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    dev = devs[0]

    print("[*] Requesting device information…")

    # Use QSLCLCMD system
    if "GETINFO" in QSLCLCMD_DB:
        print("[*] Using QSLCLCMD GETINFO command")
        resp = qslcl_dispatch(dev, "GETINFO")
    else:
        resp = qslcl_dispatch(dev, "GETINFO")

    if resp:
        decoded = decode_runtime_result(resp)
        print("   Runtime:", decoded)
        try:
            info = parse_device_info(resp)
            print_device_info(info)
            return
        except Exception as e:
            print(f"[!] GETINFO parse failed: {e}")

    print("[!] GETINFO: no valid response.")

def cmd_partitions(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    parts = load_partitions(dev)

    if not parts:
        print("[!] No partitions detected or partition loading failed.")
        return

    print(f"[*] {len(parts)} partitions detected:\n")
    for p in parts:
        print(f"  {p['name']:<12}  off=0x{p['offset']:08X}  size=0x{p['size']:08X}")

# =============================================================================
# HELPER FUNCTIONS FOR ANALYSIS (IMPORTED FROM READ.PY)
# =============================================================================
def extract_strings(data, min_length=4):
    """Extract ASCII strings from binary data"""
    strings = []
    current = bytearray()
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode('ascii', errors='ignore'))
            current = bytearray()
    
    if len(current) >= min_length:
        strings.append(current.decode('ascii', errors='ignore'))
    
    return strings

def detect_magic_numbers(data):
    """Detect known file signatures/magic numbers"""
    magics = {
        b'\x7fELF': "ELF executable",
        b'MZ': "Windows executable",
        b'ANDROID!': "Android boot image",
        b'APFS': "Apple File System",
        b'HFS': "Hierarchical File System",
        b'\x89PNG': "PNG image",
        b'\xFF\xD8\xFF': "JPEG image",
        b'PK\x03\x04': "ZIP archive",
        b'\x1F\x8B\x08': "GZIP compressed",
        b'BM': "BMP image",
        b'RIFF': "RIFF container (WAV, AVI)",
        b'<?xml': "XML document",
        b'\x00\x00\x01\xBA': "MPEG program stream",
        b'\x00\x00\x01\xB3': "MPEG video",
    }
    
    detected = []
    for magic, desc in magics.items():
        if data.startswith(magic):
            detected.append((magic, desc))
    
    return detected

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    byte_counts = [0] * 256
    
    for byte in data:
        byte_counts[byte] += 1
    
    total = len(data)
    
    for count in byte_counts:
        if count > 0:
            probability = count / total
            entropy -= probability * (probability and math.log2(probability))
    
    return entropy

# =============================================================================
# UPDATED MAIN FUNCTION
# =============================================================================
def main():
    # -----------------------------------------------
    # CLEAN HELP FORMATTER
    # -----------------------------------------------
    class QSLCLHelp(argparse.HelpFormatter):
        def __init__(self, prog):
            # Wider width & nice indent for Android terminals
            super().__init__(prog, max_help_position=36, width=140)

    # -----------------------------------------------
    # GLOBAL PARSER
    # -----------------------------------------------
    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.2.5",
        add_help=True,
        formatter_class=QSLCLHelp
    )

    # Global arguments
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")
    p.add_argument("--wait", type=int, default=0, help="Wait N seconds for device to appear")

    # -----------------------------------------------
    # SUBPARSER WRAPPER
    # -----------------------------------------------
    sub = p.add_subparsers(
        dest="cmd",
        metavar="",        # <== prevents ugly wrapping in usage
        required=False
    )

    def new_cmd(name, *args, **kwargs):
        sp = sub.add_parser(
            name,
            *args,
            **kwargs,
            formatter_class=QSLCLHelp
        )
        sp.add_argument("--loader", help="Inject qslcl.bin before executing command")
        sp.add_argument("--auth", action="store_true")
        sp.add_argument("--wait", type=int, default=0, help="Wait time before executing")
        return sp

    # -----------------------------------------------
    # COMMAND DEFINITIONS
    # -----------------------------------------------
    new_cmd("hello").set_defaults(func=cmd_hello)
    new_cmd("ping").set_defaults(func=cmd_ping)
    new_cmd("getinfo").set_defaults(func=cmd_getinfo)
    new_cmd("partitions").set_defaults(func=cmd_partitions)

    # READ command with all options from read.py
    r = new_cmd("read", help="Read from partition, address, or storage device")
    r.add_argument("target", help=(
        "Target can be:\n"
        "  • Partition name (boot, system, etc.)\n"
        "  • Raw address (0x880000, 123456)\n" 
        "  • Partition+offset (boot+0x1000)\n"
        "  • Storage device (emmc:userdata, ufs:0:boot)"
    ))
    r.add_argument("arg2", nargs="?", help=(
        "Output filename OR size in bytes (auto-detected if not provided)\n"
        "Examples:\n"
        "  read boot boot.img      # Save to boot.img\n"
        "  read 0x880000 4096      # Read 4096 bytes from address\n"
        "  read boot+0x1000 dump.bin # Read from offset and save"
    ))
    r.add_argument("-o", "--output", help="Output filename")
    r.add_argument("--size", type=lambda x: int(x, 0), help="Size in bytes (hex: 0x1000, decimal: 4096)")
    r.add_argument("--chunk-size", type=lambda x: int(x, 0), default=131072, 
                  help="Read chunk size in bytes (default: 128KB)")
    r.add_argument("--no-verify", action="store_true", help="Skip write verification")
    r.add_argument("--format", choices=['raw', 'hex', 'disasm', 'json'], default='raw', 
                  help="Output format (default: raw)")
    r.add_argument("--resume", action="store_true", help="Resume interrupted read")
    r.add_argument("--scan", action="store_true", help="Scan mode for exploration")
    r.add_argument("--auto-detect", action="store_true", default=True, 
                  help="Auto-detect partitions (default: True)")
    r.set_defaults(func=cmd_read)

    # ENHANCED WRITE COMMAND  
    w = new_cmd("write", help="Write data to partition, address, or storage device")
    w.add_argument("target", help=(
        "Target can be:\n"
        "  • Partition name (boot, system, etc.)\n"
        "  • Raw address (0x880000, 123456)\n"
        "  • Partition+offset (boot+0x1000)\n"
        "  • Storage device (emmc:userdata, ufs:0:boot)"
    ))
    w.add_argument("data", help=(
        "Data source can be:\n"
        "  • File path (firmware.bin)\n"
        "  • Hex string (AABBCCDDEEFF)\n"
        "  • Pattern (00FF*100 for 100 repeats)\n"
        "  • Fill pattern (FF:4096 for 4096 bytes of 0xFF)"
    ))
    w.add_argument("--chunk-size", type=lambda x: int(x, 0), default=65536,
                  help="Write chunk size in bytes (default: 64KB)")
    w.add_argument("--max-file-size", type=lambda x: int(x, 0), default=1073741824,
                  help="Maximum file size in bytes (default: 1GB)")
    w.add_argument("--no-verify", action="store_true", help="Skip write verification")
    w.add_argument("--force", action="store_true", help="Skip safety checks (DANGEROUS)")
    w.set_defaults(func=cmd_write)

    # ENHANCED ERASE COMMAND
    e = new_cmd("erase", help="Erase partition, address range, or storage region")
    e.add_argument("target", help=(
        "Target can be:\n"
        "  • Partition name (boot, system, etc.)\n"
        "  • Raw address (0x880000, 123456)\n"
        "  • Partition+offset (boot+0x1000)\n"
        "  • Storage device (emmc:userdata, ufs:0:boot)"
    ))
    e.add_argument("arg2", nargs="?", help=(
        "Erase size in bytes (auto-detected for partitions)\n"
        "Examples:\n"
        "  erase boot           # Erase entire boot partition\n"
        "  erase 0x880000 4096  # Erase 4096 bytes from address\n"
        "  erase cache          # Erase cache partition"
    ))
    e.add_argument("--size", type=lambda x: int(x, 0), help="Size in bytes (hex: 0x1000, decimal: 4096)")
    e.add_argument("--chunk-size", type=lambda x: int(x, 0), default=1048576,
                  help="Erase chunk size in bytes (default: 1MB)")
    e.add_argument("--force", action="store_true", help="Skip safety checks (DANGEROUS)")
    e.set_defaults(func=cmd_erase)

    peek_parser = new_cmd("peek", help="Read memory with advanced addressing and data interpretation")
    peek_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression)")
    peek_parser.add_argument("-s", "--size", type=int, default=4, help="Number of bytes to read (default: 4)")
    peek_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'string'], default='auto', help="Data type interpretation")
    peek_parser.add_argument("-c", "--count", type=int, default=1, help="Number of elements for array types")
    peek_parser.set_defaults(func=cmd_peek)

    poke_parser = new_cmd("poke", help="Write memory with advanced addressing and data types")
    poke_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression")
    poke_parser.add_argument("value", help="Value to write (supports multiple data types)")
    poke_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'hex', 'string'], default='auto', help="Data type of value")
    poke_parser.add_argument("-s", "--size", type=int, default=4, help="Size of write in bytes (for hex/string types)")
    poke_parser.set_defaults(func=cmd_poke)

    rawmode_parser = new_cmd("rawmode", help="Raw mode access and privilege escalation commands")
    rawmode_parser.add_argument("rawmode_subcommand", help="Rawmode subcommand (list, set, status, unlock, lock, configure, escalate, monitor, audit, reset)")
    rawmode_parser.add_argument("rawmode_args", nargs="*", help="Additional arguments for rawmode command")
    rawmode_parser.set_defaults(func=cmd_rawmode)

    dump_parser = new_cmd("dump", help="Advanced memory dumping with multiple modes")
    dump_parser.add_argument("address", help="Address, partition name, or region to dump")
    dump_parser.add_argument("size", nargs="?", help="Size to dump (bytes, K, M, G, or hex with 0x)")
    dump_parser.add_argument("output", nargs="?", help="Output file or directory path")
    dump_parser.add_argument("--chunk-size", type=int, default=4096, help="Read chunk size (default: 4096)")
    dump_parser.add_argument("--verify", action="store_true", help="Verify dump integrity with SHA256")
    dump_parser.add_argument("--compress", action="store_true", help="Compress dump with gzip")
    dump_parser.add_argument("--resume", action="store_true", help="Resume interrupted dump")
    dump_parser.add_argument("--retries", type=int, default=3, help="Max retries for failed reads")
    dump_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    dump_parser.set_defaults(func=cmd_dump)

    reset_parser = new_cmd("reset", help="System reset and restart commands")
    reset_parser.add_argument("reset_subcommand", help="Reset subcommand (list, soft, hard, force, domain, recovery, factory, bootloader, edl, pmic, watchdog, custom, sequence)")
    reset_parser.add_argument("reset_args", nargs="*", help="Additional arguments for reset command")
    reset_parser.add_argument("--force-reset", action="store_true", help="Bypass confirmation prompts")
    reset_parser.set_defaults(func=cmd_reset)

    bruteforce_parser = new_cmd("bruteforce", help="Advanced brute-force and system exploration")
    bruteforce_parser.add_argument("bruteforce_subcommand", nargs="?", help="Bruteforce subcommand (list, scan, pattern, fuzz, dictionary, replay, analyze, continue)")
    bruteforce_parser.add_argument("pattern", nargs="?", help="Legacy pattern (e.g., 0x00-0xFFFF)")
    bruteforce_parser.add_argument("--threads", type=int, default=8, help="Number of threads")
    bruteforce_parser.add_argument("--rawmode", action="store_true", help="Enable raw mode")
    bruteforce_parser.add_argument("--output", help="Output filename")
    bruteforce_parser.add_argument("--strategy", choices=["basic", "smart", "aggressive"], default="basic", help="Bruteforce strategy")
    bruteforce_parser.add_argument("bruteforce_args", nargs="*", help="Additional arguments")
    bruteforce_parser.set_defaults(func=cmd_bruteforce)

    config_parser = new_cmd("config", help="Configuration management commands")
    config_parser.add_argument("config_subcommand", help="Config subcommand (get, set, list, delete, backup, restore, reset, import, export, validate, info)")
    config_parser.add_argument("config_args", nargs="*", help="Additional arguments for config command")
    config_parser.add_argument("--verify", action="store_true", help="Verify configuration after setting")
    config_parser.set_defaults(func=cmd_config)

    config_list_parser = new_cmd("config-list", help="List configuration capabilities")
    config_list_parser.set_defaults(func=cmd_config_list)

    glitch_parser = new_cmd("glitch", help="Hardware glitch injection")
    glitch_parser.add_argument("glitch_subcommand")
    glitch_parser.add_argument("glitch_args", nargs="*")
    glitch_parser.add_argument("--level", type=int)
    glitch_parser.add_argument("--iter", type=int)
    glitch_parser.add_argument("--window", type=int)
    glitch_parser.add_argument("--sweep", type=int)
    glitch_parser.set_defaults(func=cmd_glitch)

    footer_parser = new_cmd("footer", help="Footer analysis")
    footer_parser.add_argument("--type", dest="footer_type", default="STANDARD",
                              choices=["STANDARD","EXTENDED","SECURITY","BOOT","LOADER","DEBUG","AUDIT","ALL"])
    footer_parser.add_argument("--raw", action="store_true")
    footer_parser.add_argument("--extended", action="store_true")
    footer_parser.add_argument("--verbose", action="store_true")
    footer_parser.add_argument("--crc", action="store_true")
    footer_parser.add_argument("--metadata", action="store_true")
    footer_parser.add_argument("--all", action="store_true")
    footer_parser.add_argument("--validate", action="store_true")
    footer_parser.add_argument("--hex", action="store_true")
    footer_parser.add_argument("--structured", action="store_true")
    footer_parser.add_argument("--json", action="store_true")
    footer_parser.add_argument("--save", metavar="FILE")
    footer_parser.add_argument("footer_args", nargs="*")
    footer_parser.set_defaults(func=cmd_footer)

    patch_parser = new_cmd("patch", help="Advanced binary patching")
    patch_parser.add_argument("patch_args", nargs="+", help=(
        "Patch specification:\n"
        "  <target> <patch_data>\n"
        "Target: address, partition, symbol, range\n"
        "Patch data: file, hex, pattern, replace, instruction"
    ))
    patch_parser.add_argument("--patch-type", choices=['file', 'hex', 'pattern', 'replace', 'instruction', 'auto'], 
                            default='auto', help="Explicit patch type")
    patch_parser.add_argument("--no-verify", action="store_true", help="Skip patch verification")
    patch_parser.add_argument("--chunk-size", type=lambda x: int(x, 0), default=4096,
                            help="Patch chunk size in bytes")
    patch_parser.add_argument("--retries", type=int, default=3, help="Max retry attempts")
    patch_parser.set_defaults(func=cmd_patch)

    oem_parser = new_cmd("oem", help="OEM commands")
    oem_parser.add_argument("oem_subcommand")
    oem_parser.add_argument("oem_args", nargs="*")
    oem_parser.set_defaults(func=cmd_oem)

    odm_parser = new_cmd("odm", help="ODM commands")
    odm_parser.add_argument("odm_subcommand")
    odm_parser.add_argument("odm_args", nargs="*")
    odm_parser.set_defaults(func=cmd_odm)

    mode_parser = new_cmd("mode", help="Mode control")
    mode_parser.add_argument("mode_subcommand")
    mode_parser.add_argument("mode_args", nargs="*")
    mode_parser.set_defaults(func=cmd_mode)

    new_cmd("mode-status", help="Check current mode").set_defaults(func=cmd_mode_status)

    crash_parser = new_cmd("crash", help="Crash simulation")
    crash_parser.add_argument("crash_subcommand")
    crash_parser.add_argument("crash_args", nargs="*")
    crash_parser.set_defaults(func=cmd_crash)

    new_cmd("crash-test", help="Crash test").set_defaults(func=cmd_crash_test)

    bypass_parser = new_cmd("bypass", help="Security bypass engine")
    bypass_parser.add_argument("bypass_subcommand")
    bypass_parser.add_argument("bypass_args", nargs="*")
    bypass_parser.set_defaults(func=cmd_bypass)

    voltage_parser = new_cmd("voltage", help="Voltage control")
    voltage_parser.add_argument("voltage_subcommand")
    voltage_parser.add_argument("voltage_args", nargs="*")
    voltage_parser.set_defaults(func=cmd_voltage)

    power_parser = new_cmd("power", help="Power management")
    power_parser.add_argument("power_subcommand")
    power_parser.add_argument("power_args", nargs="*")
    power_parser.set_defaults(func=cmd_power)

    verify_parser = new_cmd("verify", help="System verification")
    verify_parser.add_argument("verify_subcommand")
    verify_parser.add_argument("verify_args", nargs="*")
    verify_parser.set_defaults(func=cmd_verify)

    rawstate_parser = new_cmd("rawstate", help="Low-level state inspection")
    rawstate_parser.add_argument("rawstate_subcommand")
    rawstate_parser.add_argument("rawstate_args", nargs="*")
    rawstate_parser.set_defaults(func=cmd_rawstate)

    # -----------------------------------------------
    # PARSE ARGS WITH PROPER ERROR HANDLING
    # -----------------------------------------------
    args = p.parse_args()

    # FIXED: Validate device BEFORE command execution
    if (args.wait or 0) > 0:
        print(f"[*] Waiting up to {args.wait}s for device...")
        dev = wait_for_device(timeout=args.wait)
        if not dev:
            print("[!] No device found within timeout.")
            return 1  # Exit with error code
    else:
        devs = scan_all()
        if not devs:
            print("[!] No valid QSLCL-compatible device detected.")
            return 1
            
        dev = devs[0]
        # Validate immediately
        if not validate_device(dev):
            print(f"[!] Device '{dev.product}' is not suitable for QSLCL operations.")
            return 1

    # Now safe to proceed with commands
    if args.loader:
        auto_loader_if_needed(args, dev)
        
    if hasattr(args, "func"):
        try:
            result = args.func(args)
            # Clean up device handle
            if dev and hasattr(dev, 'close'):
                dev.close()
            return result if result is not None else 0
        except Exception as e:
            print(f"[!] Command execution failed: {e}")
            traceback.print_exc()
            return 1
    else:
        p.print_help()
        
    return 0  # Success

if __name__ == "__main__":
    sys.exit(main())