#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v2.0.1 
# Author: Sharif — QSLCL Creator
# Works on all SOC
# Fixed: Frame parsing, CRC validation, QSLCLBIN header parsing, error handling

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

def universal_dfu_detection(dev):
    """
    Detect ANY DFU mode device (not just Apple)
    Based on USB DFU Class Specification
    """
    try:
        # DFU Class specification (USB.org)
        # Interface Class 0xFE = Application Specific
        # Interface Subclass 0x01 = Device Firmware Upgrade
        # Interface Protocol 0x01/0x02 = DFU mode
        
        cfg = dev.get_active_configuration()
        
        for intf in cfg:
            if (intf.bInterfaceClass == 0xFE and 
                intf.bInterfaceSubClass == 0x01):
                
                # DFU mode detected!
                protocol_map = {
                    0x01: "DFU Mode (Runtime)",
                    0x02: "DFU Mode (Download)",
                }
                protocol = protocol_map.get(intf.bInterfaceProtocol, "DFU Mode")
                
                # Get vendor name
                vendor_name = "Unknown"
                try:
                    vendor_name = usb.util.get_string(dev, dev.iManufacturer)
                except:
                    pass
                
                return {
                    'mode': 'DFU',
                    'protocol': protocol,
                    'vendor': vendor_name,
                    'vid': dev.idVendor,
                    'pid': dev.idProduct
                }
        
        return None
        
    except Exception as e:
        if _DEBUG:
            print(f"[!] DFU detection error: {e}")
        return None

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

# Global databases for each block type
QSLCLBIN_DB = {}  # NEW: Main binary header database
QSLCLHDR_DB = {}
QSLCLCMD_DB = {}  
QSLCLVM5_DB  = {}
QSLCLUSB_DB  = {}
QSLCLSPT_DB  = {}
QSLCLDISP_DB = {}
QSLCLIDX_DB  = {}
QSLCLRTF_DB  = {}
QSLCLBST_DB  = {}  # Dynamic Bootstrap Database
QSLCLEND_DB  = {}  # Endpoint Database for QSLCLEND blocks
QSLCLENC_DB  = {}  

# Global debug flag
_DEBUG = False

def set_debug(enabled: bool = True):
    """Enable/disable debug output"""
    global _DEBUG
    _DEBUG = enabled

def align_up(x, block):
    return (x + block - 1) & ~(block - 1)

# =============================================================================
# HELPER FUNCTIONS FOR QSLCLENC
# =============================================================================

def has_encryption_layer() -> bool:
    """Check if QSLCL binary has encryption layer"""
    return bool(QSLCLENC_DB)

def get_encryption_info() -> dict:
    """Get encryption layer information"""
    return QSLCLENC_DB.get('encryption', {})

def encryption_supports_chacha20() -> bool:
    """Check if ChaCha20-Poly1305 is supported"""
    enc_info = get_encryption_info()
    return enc_info.get('features', {}).get('chacha20_poly1305', False)

def encryption_supports_aes256() -> bool:
    """Check if AES-256-GCM is supported"""
    enc_info = get_encryption_info()
    return enc_info.get('features', {}).get('aes256_gcm', False)

def encryption_integrity_valid() -> bool:
    """Check if encryption block integrity is valid"""
    enc_info = get_encryption_info()
    return enc_info.get('integrity_valid', False)

# =============================================================================
# FIXED: STANDARD HEADER PARSING - Matches build.py's create_standard_header()
# =============================================================================
def parse_standard_header(data):
    """
    Parse QSLCL standard header format:
    [MAGIC(8)][size(4)][flags(4)][crc(4)][body]
    
    FIXED: Proper offset handling with CRC validation
    """
    if len(data) < 20:
        return None
    
    try:
        magic = data[:8].rstrip(b'\x00')
        # FIXED: size is at bytes 8-12, flags at 12-16, crc at 16-20
        size, flags, stored_crc = struct.unpack("<III", data[8:20])
        
        # Validate size (prevent insane values)
        if size > 1024 * 1024 * 100:  # Max 100MB body
            if _DEBUG:
                print(f"[!] parse_standard_header: Size too large: {size}")
            return None
            
        if 20 + size > len(data):
            if _DEBUG:
                print(f"[!] parse_standard_header: Insufficient data: need {20+size}, have {len(data)}")
            return None
            
        body = data[20:20+size]
        calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
        
        crc_valid = (stored_crc == calculated_crc)
        if not crc_valid and _DEBUG:
            print(f"[!] parse_standard_header: CRC mismatch for {magic.decode('ascii', errors='ignore')}: "
                  f"stored=0x{stored_crc:08X}, calculated=0x{calculated_crc:08X}")
        
        return {
            "magic": magic,
            "size": size,
            "flags": flags,
            "stored_crc": stored_crc,
            "calculated_crc": calculated_crc,
            "crc_valid": crc_valid,
            "body": body,
            "total_size": 20 + size,
            "header_size": 20
        }
    except Exception as e:
        if _DEBUG:
            print(f"[!] parse_standard_header: Exception: {e}")
        return None

def scan_for_structured_blocks(data):
    """
    Scan entire binary for structured blocks with standard headers.
    Returns dict mapping magic -> list of (offset, header_info)
    """
    blocks = {}
    i = 0
    data_len = len(data)
    
    while i <= data_len - 20:
        # Look for any 8-byte magic that starts with QSLCL
        magic_candidate = data[i:i+8]
        
        # Check if this looks like a QSLCL magic (starts with QSLCL or QSLCHDR variants)
        if (magic_candidate.startswith(b'QSLCL') or magic_candidate.startswith(b'QSLCHDR')):
            try:
                header = parse_standard_header(data[i:])
                if header and header['magic']:
                    magic_str = header['magic'].decode('ascii', errors='ignore')
                    
                    if magic_str not in blocks:
                        blocks[magic_str] = []
                    
                    blocks[magic_str].append({
                        'offset': i,
                        'header': header,
                        'body': header['body']
                    })
                    
                    # Skip to after this block
                    i += header['total_size']
                    continue
            except Exception as e:
                if _DEBUG:
                    print(f"[!] scan_for_structured_blocks: Error at offset 0x{i:X}: {e}")
        
        i += 1
    
    return blocks

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
    magic = magic.rstrip(b'\x00')
    
    # Validate size
    if size > 1024 * 1024 * 100:  # 100MB max
        raise ValueError(f"Size too large: {size}")
        
    if 20 + size > len(data):
        raise ValueError(f"Insufficient data: header claims {size} bytes body, but only {len(data)-20} bytes available")
    
    # Extract body
    body = data[20:20+size]
    
    # Calculate CRC32
    calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
    
    crc_valid = (stored_crc == calculated_crc)
    
    return {
        'magic': magic,
        'size': size,
        'flags': flags,
        'stored_crc': stored_crc,
        'calculated_crc': calculated_crc,
        'crc_valid': crc_valid,
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
# FIXED: QSLCLCMD PARSER with CRC validation
# =============================================================================
class EndpointInfo:
    """USB Endpoint information wrapper"""
    def __init__(self, name, direction, address, ep_type, max_packet, flags=0, extra=None):
        self.name = name
        self.direction = direction  # "IN", "OUT", or "BIDIR"
        self.address = address
        self.type = ep_type  # "CTRL", "BULK", "INT", "ISO"
        self.max_packet = max_packet
        self.flags = flags
        self.extra = extra or {}
        
    def to_dict(self):
        return {
            "name": self.name,
            "direction": self.direction,
            "address": self.address,
            "type": self.type,
            "max_packet": self.max_packet,
            "flags": self.flags,
            "extra": self.extra
        }
    
    def __repr__(self):
        return f"Endpoint({self.name}, {self.direction}, 0x{self.address:02X}, {self.type}, {self.max_packet})"

def load_qslclbin(blob):
    """
    QSLCLBIN parser - Main Binary Header
    NEW: Parses the main binary header created by build.py
    """
    global QSLCLBIN_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLBIN' in structured_blocks:
        for block in structured_blocks['QSLCLBIN']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLBIN main header at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLBIN header CRC mismatch!")
            
            if len(body) >= 40:
                try:
                    bin_size, timestamp, build_hash = struct.unpack("<QQ8s", body[:24])
                    arch = body[24:40].decode("ascii", errors="ignore").rstrip('\x00')
                    
                    # Read bootstrap pointer if available
                    bootstrap_ptr = 0
                    bootstrap_size = 0
                    bootstrap_crc = 0
                    if len(body) >= 60:
                        bootstrap_ptr, bootstrap_size, bootstrap_crc = struct.unpack("<III", body[40:52])
                    
                    out['main'] = {
                        "target_size": bin_size,
                        "timestamp": timestamp,
                        "build_hash": build_hash.hex(),
                        "architecture": arch,
                        "bootstrap_ptr": bootstrap_ptr,
                        "bootstrap_size": bootstrap_size,
                        "bootstrap_crc": bootstrap_crc,
                        "crc_valid": header['crc_valid'],
                        "offset": block['offset']
                    }
                    
                    print(f"[*] QSLCLBIN: {arch} architecture")
                    print(f"[*] QSLCLBIN: Target size: {bin_size} bytes ({bin_size/1024:.1f} KB)")
                    print(f"[*] QSLCLBIN: Build timestamp: {time.ctime(timestamp/1000)}")
                    
                    if bootstrap_ptr:
                        print(f"[*] QSLCLBIN: Bootstrap at 0x{bootstrap_ptr:X} ({bootstrap_size} bytes)")
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] QSLCLBIN parse error: {e}")
    
    QSLCLBIN_DB = out
    return out

def load_qslclend(blob):
    """
    QSLCLEND parser - USB Endpoint Database
    FIXED: Added CRC validation for endpoint entries
    """
    global QSLCLEND_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    for magic_name in ['QSLCLEND', 'QSLCLBLK']:
        if magic_name in structured_blocks:
            for block in structured_blocks[magic_name]:
                body = block['body']
                header = block['header']
                
                print(f"[*] Found {magic_name} structured block at 0x{block['offset']:X} ({len(body)} bytes)")
                
                if not header['crc_valid']:
                    print(f"[!] WARNING: {magic_name} header CRC mismatch!")
                
                if len(body) >= 2:
                    entry_count = struct.unpack("<H", body[:2])[0]
                    print(f"[*] {magic_name}: {entry_count} endpoint entries")
                    
                    pos = 2
                    for i in range(entry_count):
                        if pos + 32 <= len(body):
                            entry = body[pos:pos+32]
                            
                            try:
                                name = entry[:12].decode('ascii', errors='ignore').rstrip('\x00')
                                direction_byte = entry[12]
                                address = entry[13]
                                ep_type_byte = entry[14]
                                max_packet_decoded = entry[15]
                                # entry[16:20] - reserved/index
                                # entry[20:24] - features
                                # entry[24:28] - max_packet actual
                                # entry[28:32] - CRC32 of name
                                
                                actual_max_packet = struct.unpack("<I", entry[24:28])[0] if len(entry) >= 28 else (max_packet_decoded * 8)
                                stored_name_crc = struct.unpack("<I", entry[28:32])[0] if len(entry) >= 32 else 0
                                
                                # FIXED: Validate endpoint name CRC
                                calculated_name_crc = zlib.crc32(entry[:12]) & 0xFFFFFFFF
                                if stored_name_crc and stored_name_crc != calculated_name_crc:
                                    if _DEBUG:
                                        print(f"[!] Endpoint {name} CRC mismatch: stored=0x{stored_name_crc:08X}, calc=0x{calculated_name_crc:08X}")
                                    pos += 32
                                    continue
                                
                                direction_map = {0: "OUT", 1: "IN", 2: "BIDIR"}
                                direction = direction_map.get(direction_byte, "UNKNOWN")
                                
                                type_map = {0: "CTRL", 1: "BULK", 2: "INT", 3: "ISO"}
                                ep_type = type_map.get(ep_type_byte, "UNKNOWN")
                                
                                if name and name.strip() and name != "\x00" * 12:
                                    endpoint = EndpointInfo(
                                        name=name.strip(),
                                        direction=direction,
                                        address=address,
                                        type=ep_type,
                                        max_packet=actual_max_packet,
                                        flags=struct.unpack("<I", entry[20:24])[0] if len(entry) >= 24 else 0
                                    )
                                    out[name.upper()] = endpoint
                                    out[f"addr_0x{address:02X}"] = endpoint
                                    
                            except Exception as e:
                                if _DEBUG:
                                    print(f"[!] Endpoint entry {i} parse error at pos {pos}: {e}")
                        
                        pos += 32
    
    QSLCLEND_DB = out
    return out

def load_qslclenc(blob):
    """
    QSLCLENC parser - Encryption Layer for USB Communication
    Parses ChaCha20-Poly1305 and AES-256-GCM encryption blocks
    
    Structure:
    - capabilities (4 bytes): Feature bitmap
    - version (4 bytes): Format version
    - timestamp (4 bytes): Build time
    - key_exchange_routine (variable)
    - encrypt_routine (variable)
    - decrypt_routine (variable)
    - aes_fallback_routine (variable)
    - routine_offsets (4 bytes each)
    - default_key (32 bytes)
    - integrity_footer (16 bytes)
    """
    global QSLCLENC_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLENC' in structured_blocks:
        for block in structured_blocks['QSLCLENC']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLENC structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLENC header CRC mismatch!")
            
            if len(body) >= 12:
                try:
                    # Parse encryption capabilities
                    capabilities = struct.unpack("<I", body[0:4])[0]
                    version = struct.unpack("<I", body[4:8])[0]
                    timestamp = struct.unpack("<I", body[8:12])[0]
                    
                    # Parse feature flags
                    enc_info = {
                        "offset": block['offset'],
                        "size": len(body),
                        "crc_valid": header['crc_valid'],
                        "capabilities": capabilities,
                        "version": f"{(version >> 16) & 0xFFFF}.{(version >> 8) & 0xFF}.{version & 0xFF}",
                        "timestamp": timestamp,
                        "timestamp_str": time.ctime(timestamp) if timestamp else "Unknown",
                        "features": {
                            "chacha20_poly1305": bool(capabilities & 0x01),
                            "aes256_gcm": bool(capabilities & 0x02),
                            "key_negotiation": bool(capabilities & 0x04),
                            "perfect_forward_secrecy": bool(capabilities & 0x08),
                            "anti_replay": bool(capabilities & 0x10),
                        }
                    }
                    
                    # Find routine offsets (after the 12-byte header)
                    # The 4 routines are at positions 12, then after each routine
                    pos = 12
                    
                    # Parse key exchange routine
                    if pos + 4 <= len(body):
                        key_ex_off = struct.unpack("<I", body[pos:pos+4])[0] if pos + 4 <= len(body) else 0
                        pos += 4
                    else:
                        key_ex_off = 0
                    
                    # Parse encrypt routine offset
                    if pos + 4 <= len(body):
                        enc_off = struct.unpack("<I", body[pos:pos+4])[0]
                        pos += 4
                    else:
                        enc_off = 0
                    
                    # Parse decrypt routine offset
                    if pos + 4 <= len(body):
                        dec_off = struct.unpack("<I", body[pos:pos+4])[0]
                        pos += 4
                    else:
                        dec_off = 0
                    
                    # Parse AES fallback routine offset
                    if pos + 4 <= len(body):
                        aes_off = struct.unpack("<I", body[pos:pos+4])[0]
                        pos += 4
                    else:
                        aes_off = 0
                    
                    # Default key is at pos (should be 32 bytes)
                    default_key = body[pos:pos+32] if pos + 32 <= len(body) else b""
                    pos += 32
                    
                    # Integrity footer (16 bytes SHA256 hash)
                    integrity_footer = body[pos:pos+16] if pos + 16 <= len(body) else b""
                    
                    enc_info["routines"] = {
                        "key_exchange_offset": key_ex_off,
                        "encrypt_offset": enc_off,
                        "decrypt_offset": dec_off,
                        "aes_fallback_offset": aes_off,
                    }
                    
                    enc_info["default_key"] = default_key.hex() if default_key else "None"
                    enc_info["integrity_footer"] = integrity_footer.hex() if integrity_footer else "None"
                    
                    # Verify integrity of encryption block
                    if integrity_footer:
                        # Calculate hash of body without footer
                        body_without_footer = body[:-16] if len(body) >= 16 else body
                        calculated_hash = hashlib.sha256(body_without_footer).digest()[:16]
                        enc_info["integrity_valid"] = (calculated_hash == integrity_footer)
                    else:
                        enc_info["integrity_valid"] = False
                    
                    out['encryption'] = enc_info
                    
                    print(f"[*] QSLCLENC: Encryption layer v{enc_info['version']}")
                    print(f"    Capabilities: 0x{capabilities:08X}")
                    print(f"      - ChaCha20-Poly1305: {'✓' if enc_info['features']['chacha20_poly1305'] else '✗'}")
                    print(f"      - AES-256-GCM: {'✓' if enc_info['features']['aes256_gcm'] else '✗'}")
                    print(f"      - Key negotiation: {'✓' if enc_info['features']['key_negotiation'] else '✗'}")
                    print(f"    Integrity: {'✓ Valid' if enc_info['integrity_valid'] else '✗ Invalid'}")
                    print(f"    Build time: {enc_info['timestamp_str']}")
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] QSLCLENC parse error: {e}")
                        traceback.print_exc()
    
    QSLCLENC_DB = out
    return out

def load_qslclcmd(blob):
    """
    QSLCLCMD parser - Unified command system
    FIXED: Added CRC validation for command payloads
    """
    global QSLCLCMD_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLCMD' in structured_blocks:
        for block in structured_blocks['QSLCLCMD']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLCMD structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLCMD header CRC mismatch!")
            
            pos = 0
            entries_found = 0
            corrupted_entries = 0
            
            while pos + 40 <= len(body):
                try:
                    cmd_hdr = body[pos:pos+40]
                    name_field, opcode, cmd_flags, tier, family_hash, length, stored_crc, timestamp = \
                        struct.unpack("<16sBBBBHII", cmd_hdr)
                    
                    name = name_field.decode("ascii", errors="ignore").rstrip('\x00')
                    
                    # Validate command name
                    if not name or len(name) < 2 or not name.isprintable():
                        pos += 1
                        continue
                    
                    # Validate length
                    if length > 4096:
                        if _DEBUG:
                            print(f"[!] Command {name}: invalid length {length}")
                        pos += 1
                        continue
                    
                    # Check if we have enough data
                    if pos + 40 + length > len(body):
                        if _DEBUG:
                            print(f"[!] Command {name}: insufficient data (need {pos+40+length}, have {len(body)})")
                        break
                    
                    cmd_data = body[pos+40:pos+40+length]
                    
                    # FIXED: Validate command payload CRC
                    calculated_crc = zlib.crc32(cmd_data) & 0xFFFFFFFF
                    if stored_crc != calculated_crc:
                        if _DEBUG:
                            print(f"[!] Command {name}: CRC mismatch (stored=0x{stored_crc:08X}, calc=0x{calculated_crc:08X})")
                        corrupted_entries += 1
                        pos += 40 + length
                        continue
                    
                    command_entry = {
                        "name": name,
                        "opcode": opcode,
                        "flags": cmd_flags,
                        "tier": tier,
                        "family_hash": family_hash,
                        "length": length,
                        "crc": stored_crc,
                        "crc_valid": True,
                        "timestamp": timestamp,
                        "data": cmd_data,
                        "offset": block['offset'] + pos
                    }
                    
                    out[name] = command_entry
                    out[opcode] = command_entry
                    entries_found += 1
                    
                    pos += 40 + length
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] Command parse error at pos {pos}: {e}")
                    pos += 1
            
            if entries_found > 0:
                print(f"[*] QSLCLCMD: Found {entries_found} valid commands")
                if corrupted_entries > 0:
                    print(f"[!] QSLCLCMD: {corrupted_entries} corrupted commands skipped")
                
                # Show first few commands
                cmd_names = [k for k in out.keys() if isinstance(k, str) and k.isalpha()]
                for name in sorted(cmd_names)[:10]:
                    print(f"    - {name}")
                if len(cmd_names) > 10:
                    print(f"    ... and {len(cmd_names) - 10} more")
    
    QSLCLCMD_DB = out
    return out

def load_qslclbst(blob):
    """
    QSLCLBST parser - Dynamic Bootstrap
    FIXED: Proper CRC validation
    """
    global QSLCLBST_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLBST' in structured_blocks:
        for block in structured_blocks['QSLCLBST']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLBST structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLBST header CRC mismatch!")
            
            if len(body) >= 32:
                try:
                    arch_name = body[:16].decode("ascii", errors="ignore").rstrip('\x00')
                    entry_point, code_size, timestamp = struct.unpack("<III", body[16:28])
                    
                    bootstrap_info = {
                        "arch_name": arch_name,
                        "entry_point": entry_point,
                        "code_size": code_size,
                        "timestamp": timestamp,
                        "offset": block['offset'],
                        "secure_mode": bool(header['flags'] & 0x01),
                        "crc_valid": header['crc_valid']
                    }
                    
                    out[arch_name] = bootstrap_info
                    print(f"[*] QSLCLBST: Bootstrap for {arch_name}")
                    print(f"    Entry: 0x{entry_point:X}, Size: {code_size} bytes")
                    print(f"    Secure: {bootstrap_info['secure_mode']}")
                    
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] QSLCLBST parse error: {e}")
    
    QSLCLBST_DB = out
    return out

def load_qslcldisp(blob):
    """
    QSLCLDISP parser - Command Dispatch Table
    FIXED: Added CRC validation
    """
    global QSLCLDISP_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLDIS' in structured_blocks:
        for block in structured_blocks['QSLCLDIS']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLDISP structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLDISP header CRC mismatch!")
            
            if len(body) >= 2:
                count = struct.unpack("<H", body[:2])[0]
                print(f"[*] QSLCLDISP: {count} dispatch entries")
                
                pos = 2
                entries_parsed = 0
                for i in range(count):
                    if pos + 12 <= len(body):
                        try:
                            cmd_hash, handler_addr = struct.unpack("<8sI", body[pos:pos+12])
                            out[f"entry_{i:04X}"] = {
                                "hash": cmd_hash.hex(),
                                "handler_addr": handler_addr
                            }
                            entries_parsed += 1
                        except Exception as e:
                            if _DEBUG:
                                print(f"[!] Dispatch entry {i} parse error: {e}")
                        pos += 12
                
                print(f"[*] QSLCLDISP: {entries_parsed}/{count} entries parsed successfully")
    
    QSLCLDISP_DB = out
    return out

def load_qslclrtf(blob):
    """
    QSLCLRTF parser - Runtime Fault Table
    FIXED: Proper entry parsing with validation
    """
    global QSLCLRTF_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLRTF' in structured_blocks:
        for block in structured_blocks['QSLCLRTF']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLRTF structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLRTF header CRC mismatch!")
            
            if len(body) >= 2:
                count = struct.unpack("<H", body[:2])[0]
                print(f"[*] QSLCLRTF: {count} fault entries")
                
                pos = 2
                entries_parsed = 0
                for i in range(count):
                    if pos + 20 <= len(body):
                        try:
                            # build.py format: code(4) + severity(1) + category(1) + retry(2) + msg_hash(4) + name(8) = 20 bytes
                            code = struct.unpack("<I", body[pos:pos+4])[0]
                            severity = body[pos+4]
                            category = body[pos+5]
                            retry_count = struct.unpack("<H", body[pos+6:pos+8])[0]
                            msg_hash = struct.unpack("<I", body[pos+8:pos+12])[0]
                            name = body[pos+12:pos+20].decode("ascii", errors="ignore").rstrip('\x00')
                            
                            if name and code != 0:
                                severity_names = {0: "SUCCESS", 1: "WARNING", 2: "ERROR", 3: "CRITICAL", 4: "FATAL"}
                                out[code] = {
                                    "level": severity,
                                    "severity_name": severity_names.get(severity, f"LVL{severity}"),
                                    "msg": name,
                                    "category": category,
                                    "retry_count": retry_count,
                                    "hash": msg_hash
                                }
                                entries_parsed += 1
                        except Exception as e:
                            if _DEBUG:
                                print(f"[!] RTF entry {i} parse error: {e}")
                        pos += 20
                
                print(f"[*] QSLCLRTF: {entries_parsed}/{count} entries parsed successfully")
    
    QSLCLRTF_DB = out
    return out

def load_qslclidx(blob):
    """QSLCLIDX parser - Index Table"""
    global QSLCLIDX_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLIDX' in structured_blocks:
        for block in structured_blocks['QSLCLIDX']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLIDX structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLIDX header CRC mismatch!")
            
            if len(body) >= 2:
                count = struct.unpack("<H", body[:2])[0]
                print(f"[*] QSLCLIDX: {count} index entries")
    
    QSLCLIDX_DB = out
    return out

def load_qslclvm5(blob):
    """QSLCLVM5 parser - Nano-Kernel Microservices"""
    global QSLCLVM5_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLVM5' in structured_blocks:
        for block in structured_blocks['QSLCLVM5']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLVM5 structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLVM5 header CRC mismatch!")
    
    QSLCLVM5_DB = out
    return out

def load_qslclusb(blob):
    """QSLCLUSB parser - USB Routines"""
    global QSLCLUSB_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLUSB' in structured_blocks:
        for block in structured_blocks['QSLCLUSB']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLUSB structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLUSB header CRC mismatch!")
    
    QSLCLUSB_DB = out
    return out

def load_qslclspt(blob):
    """QSLCLSPT parser - Setup Packets"""
    global QSLCLSPT_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    if 'QSLCLSPT' in structured_blocks:
        for block in structured_blocks['QSLCLSPT']:
            body = block['body']
            header = block['header']
            
            print(f"[*] Found QSLCLSPT structured block at 0x{block['offset']:X} ({len(body)} bytes)")
            
            if not header['crc_valid']:
                print(f"[!] WARNING: QSLCLSPT header CRC mismatch!")
    
    QSLCLSPT_DB = out
    return out

def load_qslclhdr(blob):
    """QSLCLHDR parser - Certificate Block"""
    global QSLCLHDR_DB
    out = {}
    
    structured_blocks = scan_for_structured_blocks(blob)
    
    for magic_name in ['QSLCHDR2', 'QSLCHDR1', 'QSLCLHDR']:
        if magic_name in structured_blocks:
            for block in structured_blocks[magic_name]:
                body = block['body']
                header = block['header']
                
                print(f"[*] Found {magic_name} structured block at 0x{block['offset']:X} ({len(body)} bytes)")
                
                if not header['crc_valid']:
                    print(f"[!] WARNING: {magic_name} header CRC mismatch!")
                
                out[magic_name] = body
    
    QSLCLHDR_DB = out
    return out

# =============================================================================
# FIXED: QSLCLLoader Class with updated parsing
# =============================================================================
class QSLCLLoader:
    def __init__(self):
        self.BIN  = {}  # QSLCLBIN main header
        self.CMD  = {}  # QSLCLCMD commands
        self.IDX  = {}
        self.VM5  = {}
        self.USB  = {}
        self.SPT  = {}
        self.DISP = {}
        self.HDR  = {}
        self.RTF  = {}
        self.ENG  = {}  # Alias for CMD
        self.BST  = {}  # Bootstrap storage
        self.END  = {}  # Endpoint storage
        self.ENC = {}
    def parse_loader(self, blob):
        """Parse QSLCL binary with structured format support"""
        print(f"[*] Parsing loader ({len(blob)} bytes)...")
        
        # First, scan for all structured blocks
        structured_blocks = scan_for_structured_blocks(blob)
        
        if structured_blocks:
            print(f"[+] Found {len(structured_blocks)} structured block types:")
            for magic, blocks in sorted(structured_blocks.items()):
                total_size = sum(b['header']['total_size'] for b in blocks)
                crc_status = "✓" if all(b['header']['crc_valid'] for b in blocks) else "✗"
                print(f"    {magic:12s}: {len(blocks)} block(s), {total_size} bytes total [CRC: {crc_status}]")
        else:
            print("[!] No structured blocks found with standard headers")
            return self._parse_loader_legacy(blob)
        
        # Parse each block type in priority order
        parse_order = [
            ('QSLCLBIN', load_qslclbin),
            ('QSLCLCMD', load_qslclcmd),
            ('QSLCLEND', load_qslclend),
            ('QSLCLBLK', load_qslclend),  # Endpoint block alias
            ('QSLCLBST', load_qslclbst),
            ('QSLCLDIS', load_qslcldisp),
            ('QSLCLRTF', load_qslclrtf),
            ('QSLCLHDR', load_qslclhdr),
            ('QSLCHDR2', load_qslclhdr),
            ('QSLCHDR1', load_qslclhdr),
            ('QSLCLUSB', load_qslclusb),
            ('QSLCLVM5', load_qslclvm5),
            ('QSLCLSPT', load_qslclspt),
            ('QSLCLIDX', load_qslclidx),
            ('QSLCLENC', load_qslclenc), 
        ]
        
        for magic, loader_func in parse_order:
            if magic in structured_blocks:
                try:
                    loader_func(blob)
                except Exception as e:
                    print(f"[!] {magic} parse error: {e}")
                    if _DEBUG:
                        traceback.print_exc()
        
        # Update class attributes
        self.BIN = QSLCLBIN_DB
        self.CMD = QSLCLCMD_DB
        self.END = QSLCLEND_DB
        self.BST = QSLCLBST_DB
        self.DISP = QSLCLDISP_DB
        self.RTF = QSLCLRTF_DB
        self.HDR = QSLCLHDR_DB
        self.IDX = QSLCLIDX_DB
        self.VM5 = QSLCLVM5_DB
        self.USB = QSLCLUSB_DB
        self.SPT = QSLCLSPT_DB
        self.ENG = QSLCLCMD_DB
        
        # Print summary
        print(f"\n[*] Parsing Summary:")
        found_modules = []
        if self.BIN: 
            bin_info = self.BIN.get('main', {})
            found_modules.append(f"BIN({bin_info.get('architecture', 'unknown')})")
        if self.CMD: 
            cmd_count = len([k for k in self.CMD.keys() if isinstance(k, str) and k.isalpha()])
            found_modules.append(f"CMD({cmd_count})")
        if self.END: 
            ep_count = len([k for k in self.END.keys() if isinstance(k, EndpointInfo)])
            found_modules.append(f"END({ep_count})")
        if self.BST: found_modules.append(f"BST({len(self.BST)})")
        if self.DISP: found_modules.append(f"DISP({len(self.DISP)})")
        if self.RTF: found_modules.append(f"RTF({len(self.RTF)})")
        if self.HDR: found_modules.append(f"HDR({len(self.HDR)})")
        
        if found_modules:
            print(f"[+] Detected modules: {', '.join(found_modules)}")
            return True
        
        return False
    
    def _parse_loader_legacy(self, blob):
        """Legacy parser for non-structured binaries"""
        print("[*] Trying legacy parsing...")
        
        magics = [b'QSLCLCMD', b'QSLCLEND', b'QSLCLBST', b'QSLCLDIS', 
                  b'QSLCLRTF', b'QSLCLHDR', b'QSLCHDR2', b'QSLCLBIN']
        
        found_any = False
        for magic in magics:
            pos = blob.find(magic)
            if pos != -1:
                print(f"[+] Found {magic.decode()} at 0x{pos:X}")
                found_any = True
                
                if magic == b'QSLCLCMD':
                    load_qslclcmd(blob[pos:])
                elif magic == b'QSLCLEND':
                    load_qslclend(blob[pos:])
                elif magic == b'QSLCLBST':
                    load_qslclbst(blob[pos:])
                elif magic == b'QSLCLBIN':
                    load_qslclbin(blob[pos:])
        
        self.BIN = QSLCLBIN_DB
        self.CMD = QSLCLCMD_DB
        self.END = QSLCLEND_DB
        self.BST = QSLCLBST_DB
        self.ENC = QSLCLENC_DB

        return found_any or bool(self.CMD)

# =============================================================================
# Helper functions for endpoint access
# =============================================================================
def get_endpoint_by_name(name):
    """Get endpoint information by name"""
    return QSLCLEND_DB.get(name.upper())

def get_endpoint_by_address(address):
    """Get endpoint information by USB address"""
    return QSLCLEND_DB.get(f"addr_0x{address:02X}")

def list_endpoints():
    """List all available endpoints"""
    endpoints = []
    seen_names = set()
    for key, value in QSLCLEND_DB.items():
        if isinstance(value, EndpointInfo) and not key.startswith("addr_"):
            if value.name not in seen_names:
                endpoints.append(value)
                seen_names.add(value.name)
    return endpoints

def get_endpoint_summary():
    """Get summary of available endpoints by type"""
    summary = {"CTRL": [], "BULK": [], "INT": [], "ISO": [], "UNKNOWN": []}
    for ep in list_endpoints():
        if ep.type in summary:
            summary[ep.type].append(ep)
        else:
            summary["UNKNOWN"].append(ep)
    return summary

# =============================================================================
# DEVICE STRUCT
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
    serial: str = "default"

    handle: any = None
    serial_mode: bool = False

    def get(self, key, default=None):
        return getattr(self, key, default)

    def write(self, data: bytes):
        if self.handle is None:
            self.handle, self.serial_mode = open_transport(self)
            if self.handle is None:
                raise RuntimeError("Failed to open device transport")

        if not self.serial_mode:
            try:
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
                    return self.handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, data)
            except Exception as e:
                raise RuntimeError(f"USB write failed: {e}")
        else:
            try:
                return self.handle.write(data)
            except Exception as e:
                raise RuntimeError(f"Serial write failed: {e}")

    def read(self, size=None, timeout=1.0):
        if self.handle is None:
            self.handle, self.serial_mode = open_transport(self)
            if self.handle is None:
                raise RuntimeError("Failed to open device transport")

        try:
            if self.serial_mode:
                if size:
                    return self.handle.read(size)
                else:
                    return self.handle.read_all()
            else:
                typ, payload = recv(self.handle, False, timeout=timeout)
                return payload
        except Exception as e:
            raise RuntimeError(f"Read failed: {e}")

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
        print()
        
    def update(self, progress):
        if self.total <= 0:
            return
        self.current += progress
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.current / float(self.total)))
        filled_length = int(self.length * self.current // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end='', flush=True)
        if self.current >= self.total:
            print()

# =============================================================================
# ENCODERS AND DECODERS
# =============================================================================
def qslcl_decode_rtf(resp):
    """Decode QSLCL Runtime Fault Frame"""
    if not resp:
        return {"severity": "ERROR", "name": "NO_RESPONSE", "extra": b""}
    return decode_runtime_result(resp)

def qslclidx_get_cmd(cmd_name):
    """Find IDX entry by command name"""
    for name, entry in QSLCLIDX_DB.items():
        if name.upper() == cmd_name.upper():
            return entry
    return None

def qslclidx_get_cert(idx):
    """IDX → certificate entry"""
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
    start = time.time()
    while True:
        devs = scan_all()
        if devs:
            dev = devs[0]
            if validate_device(dev):
                return dev
        if timeout is not None and (time.time() - start) >= timeout:
            return None
        time.sleep(interval)

def validate_device(dev: QSLCLDevice):
    """More permissive device validation"""
    if dev.usb_class in (0x03, 0x09):  # HID and hubs
        return False
    return True

# =============================================================================
# SCANNERS
# =============================================================================
def scan_serial():
    if not SERIAL_SUPPORT:
        return []
    devs = []
    try:
        for p in list_ports.comports():
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
                handle=None
            ))
    except Exception as e:
        if _DEBUG:
            print(f"[!] Serial scan error: {e}")
    return devs

def scan_usb():
    if not USB_SUPPORT:
        return []
    devs = []
    try:
        for d in usb.core.find(find_all=True):
            try:
                # ============================================================
                # DYNAMIC DFU DETECTION - Check for any DFU mode device first
                # ============================================================
                dfu_info = universal_dfu_detection(d)
                if dfu_info:
                    # This is a DFU device! Add it with proper info
                    try:
                        product = usb.util.get_string(d, d.iProduct) or f"DFU Device ({dfu_info['protocol']})"
                    except:
                        product = f"DFU Device ({dfu_info['protocol']})"
                    
                    try:
                        serial = usb.util.get_string(d, d.iSerialNumber) or "dfu_mode"
                    except:
                        serial = "dfu_mode"
                    
                    devs.append(QSLCLDevice(
                        transport="usb",
                        identifier=f"bus={d.bus},addr={d.address}",
                        vendor=dfu_info['vendor'],
                        product=product,
                        vid=d.idVendor,
                        pid=d.idProduct,
                        usb_class=0xFE,  # DFU class
                        usb_subclass=0x01,
                        usb_protocol=0x01 if "Download" in dfu_info['protocol'] else 0x02,
                        serial=serial,
                        handle=d,
                        serial_mode=False
                    ))
                    
                    if _DEBUG:
                        print(f"[*] DFU device detected: {dfu_info['vendor']} (0x{d.idVendor:04X}:0x{d.idProduct:04X}) - {dfu_info['protocol']}")
                    
                    continue  # Skip normal USB processing for DFU devices
                
                # ============================================================
                # NORMAL USB DEVICE SCANNING (Original logic)
                # ============================================================
                try:
                    cfg = d.get_active_configuration()
                except usb.core.USBError:
                    continue
                
                # Get the first interface (index 0)
                intf = cfg[(0, 0)]
                
                # Skip HID and hub class devices
                if intf.bInterfaceClass in (0x01, 0x02, 0x03, 0x07, 0x08, 0x0A):
                    continue
                
                # Find bulk IN and OUT endpoints
                ep_in = None
                ep_out = None
                for ep in intf.endpoints():
                    if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                        if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                            ep_in = ep
                    else:
                        if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                            ep_out = ep
                
                # Need both IN and OUT endpoints for communication
                if not ep_in or not ep_out:
                    continue
                
                # Get device strings
                try:
                    product = usb.util.get_string(d, d.iProduct) or "USB Device"
                except:
                    product = "USB Device"
                
                try:
                    serial = usb.util.get_string(d, d.iSerialNumber) or "default"
                except:
                    serial = "default"
                
                # Create device object
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
                
            except Exception as e:
                if _DEBUG:
                    print(f"[!] USB device scan error for device: {e}")
                continue
                
    except Exception as e:
        if _DEBUG:
            print(f"[!] USB scan error: {e}")
    
    return devs

def scan_all():
    devs = scan_usb() + scan_serial()
    def score(d):
        s = 0
        if d.usb_class == 0xFF:
            s += 100
        if d.usb_class in (0x0A, 0x02):
            s += 70
        if d.product and d.product not in ("USB Device", "Serial", "Unknown"):
            s += 30
        if d.vid and d.pid:
            s += 20
        if d.transport == "usb":
            s += 10
        return -s
    devs.sort(key=score)
    return devs

# =============================================================================
# FIXED: FRAME PARSER with correct offsets and CRC validation
# =============================================================================
def parse_frame(buff: bytes):
    """
    Parse QSLCL frame with standard header format:
    [MAGIC(8)][size(4)][flags(4)][crc(4)][body]
    
    FIXED: Correct size offset at bytes 8-12
    FIXED: Added CRC validation
    """
    MIN_FRAME_SIZE = 20  # Minimum frame: magic(8) + size(4) + flags(4) + crc(4)
    
    if len(buff) < MIN_FRAME_SIZE:
        return None, None
    
    # Check for response frame
    if buff.startswith(b"QSLCLRESP"):
        try:
            # FIXED: size is at bytes 8-12
            size, flags, stored_crc = struct.unpack("<III", buff[8:20])
            
            if size > 1024 * 1024:  # Sanity check: max 1MB payload
                if _DEBUG:
                    print(f"[!] parse_frame: RESP size too large: {size}")
                return None, None
                
            if MIN_FRAME_SIZE + size > len(buff):
                return None, None  # Incomplete frame
            
            body = buff[MIN_FRAME_SIZE:MIN_FRAME_SIZE + size]
            
            # FIXED: Validate CRC
            calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
            if stored_crc != calculated_crc:
                if _DEBUG:
                    print(f"[!] parse_frame: RESP CRC mismatch: stored=0x{stored_crc:08X}, calc=0x{calculated_crc:08X}")
                return None, None  # Drop corrupted frame
            
            return "RESP", body
            
        except Exception as e:
            if _DEBUG:
                print(f"[!] parse_frame: RESP parse error: {e}")
            return None, None
    
    # Check for command frame
    if buff.startswith(b"QSLCLCMD"):
        try:
            # FIXED: size is at bytes 8-12
            size, flags, stored_crc = struct.unpack("<III", buff[8:20])
            
            if size > 1024 * 1024:
                if _DEBUG:
                    print(f"[!] parse_frame: CMD size too large: {size}")
                return None, None
                
            if MIN_FRAME_SIZE + size > len(buff):
                return None, None
            
            body = buff[MIN_FRAME_SIZE:MIN_FRAME_SIZE + size]
            
            # FIXED: Validate CRC
            calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
            if stored_crc != calculated_crc:
                if _DEBUG:
                    print(f"[!] parse_frame: CMD CRC mismatch: stored=0x{stored_crc:08X}, calc=0x{calculated_crc:08X}")
                return None, None
            
            return "CMD", body
            
        except Exception as e:
            if _DEBUG:
                print(f"[!] parse_frame: CMD parse error: {e}")
            return None, None
    
    return None, None

def decode_runtime_result(resp, origin="DISPATCH"):
    if not resp or len(resp) < 2:
        return {"severity": "ERROR", "code": 0xFFFF, "name": "NO_RESPONSE", "extra": b"", "origin": origin}
    try:
        code = int.from_bytes(resp[0:2], "little")
    except:
        return {"severity": "ERROR", "code": 0xFFFE, "name": "PARSE_FAIL", "extra": resp, "origin": origin}
    extra = resp[2:] if len(resp) > 2 else b""
    if code in QSLCLRTF_DB:
        entry = QSLCLRTF_DB[code]
        level = entry.get("level", 0)
        name = entry.get("msg", "UNKNOWN")
        severity_name = entry.get("severity_name", 
                                   {0: "SUCCESS", 1: "WARNING", 2: "ERROR", 3: "CRITICAL", 4: "FATAL"}.get(level, f"LVL{level}"))
        return {"severity": severity_name, "code": code, "name": name, "extra": extra, "origin": origin}
    if code == 0:
        return {"severity": "SUCCESS", "code": 0x0000, "name": "OK", "extra": extra, "origin": origin}
    return {"severity": "UNKNOWN", "code": code, "name": f"UNDEFINED_RTF_0x{code:04X}", "extra": extra, "origin": origin}

# =============================================================================
# TRANSPORT FUNCTIONS
# =============================================================================
def open_transport(dev):
    if dev.transport == "serial":
        try:
            h = serial.Serial(dev.identifier, 115200, timeout=1)
            dev.handle = h
            return h, True
        except Exception as e:
            print(f"[!] Failed to open serial port {dev.identifier}: {e}")
            return None, True
    else:
        try:
            try:
                dev.handle.reset()
            except:
                pass
            try:
                dev.handle.set_configuration()
            except usb.core.USBError as e:
                if e.errno != 16:
                    print(f"[!] USB configuration failed: {e}")
                    return None, False
            try:
                usb.util.claim_interface(dev.handle, 0)
            except usb.core.USBError as e:
                if e.errno != 16:
                    print(f"[!] USB interface claim failed: {e}")
                    return None, False
            return dev.handle, False
        except Exception as e:
            print(f"[!] Failed to configure USB device: {e}")
            try:
                if dev.vid and dev.pid:
                    new_dev = usb.core.find(idVendor=dev.vid, idProduct=dev.pid)
                    if new_dev:
                        dev.handle = new_dev
                        return open_transport(dev)
            except:
                pass
            return None, False

def send(handle, payload, serial_mode):
    if serial_mode:
        try:
            handle.write(payload)
            return len(payload)
        except Exception as e:
            print("[!] SERIAL WRITE ERROR:", e)
            return 0
    else:
        try:
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
                return handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, payload)
        except Exception as e:
            print("[!] USB WRITE ERROR:", e)
            return 0

def recv(handle, serial_mode, timeout=3.0):
    """
    Receive and parse QSLCL frames
    FIXED: Correct size offset at bytes 8-12
    FIXED: Added CRC validation for received frames
    """
    deadline = time.time() + timeout
    buff = bytearray()
    RESP_MAGIC = b"QSLCLRESP"
    CMD_MAGIC = b"QSLCLCMD"
    MIN_FRAME = 20  # Full header size
    
    while time.time() < deadline:
        try:
            if serial_mode:
                chunk = handle.read(64)
            else:
                chunk = b""
                try:
                    cfg = handle.get_active_configuration()
                    intf = cfg[(0,0)]
                    for ep in intf.endpoints():
                        if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                            usb.util.ENDPOINT_IN):
                            try:
                                chunk = handle.read(ep.bEndpointAddress, 64, timeout=500)
                                if chunk:
                                    break
                            except usb.core.USBError as e:
                                if e.errno != 110:
                                    pass
                except:
                    pass
            if chunk:
                buff.extend(chunk)
        except Exception as e:
            if _DEBUG:
                print(f"[!] recv: read error: {e}")
            break
        
        # Try to parse complete frames
        while len(buff) >= MIN_FRAME:
            # Check for response
            idx = buff.find(RESP_MAGIC)
            if idx == 0 and len(buff) >= MIN_FRAME:
                try:
                    # FIXED: size is at bytes 8-12
                    size, flags, stored_crc = struct.unpack("<III", buff[8:20])
                except:
                    size = -1
                
                if size >= 0 and size <= 1024 * 1024 and len(buff) >= MIN_FRAME + size:
                    body = bytes(buff[MIN_FRAME:MIN_FRAME + size])
                    
                    # FIXED: CRC validation
                    calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
                    if stored_crc == calculated_crc:
                        del buff[:MIN_FRAME + size]
                        return "RESP", body
                    else:
                        if _DEBUG:
                            print(f"[!] recv: RESP CRC mismatch, discarding frame")
                        del buff[:MIN_FRAME]  # Remove corrupted header
                        continue
            
            # Check for command
            jdx = buff.find(CMD_MAGIC)
            if jdx == 0 and len(buff) >= MIN_FRAME:
                try:
                    # FIXED: size is at bytes 8-12
                    size, flags, stored_crc = struct.unpack("<III", buff[8:20])
                except:
                    size = -1
                
                if size >= 0 and size <= 1024 * 1024 and len(buff) >= MIN_FRAME + size:
                    body = bytes(buff[MIN_FRAME:MIN_FRAME + size])
                    
                    # FIXED: CRC validation
                    calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
                    if stored_crc == calculated_crc:
                        del buff[:MIN_FRAME + size]
                        return "CMD", body
                    else:
                        if _DEBUG:
                            print(f"[!] recv: CMD CRC mismatch, discarding frame")
                        del buff[:MIN_FRAME]
                        continue
            
            # Remove any garbage before the next magic
            if idx > 0:
                if _DEBUG:
                    print(f"[!] recv: Discarding {idx} bytes of garbage before frame")
                del buff[:idx]
            elif jdx > 0:
                if _DEBUG:
                    print(f"[!] recv: Discarding {jdx} bytes of garbage before frame")
                del buff[:jdx]
            else:
                break  # No magic found, need more data
        
        time.sleep(0.002)
    
    return None, None

def detect_device_type(handle):
    try:
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
# COMMAND DISPATCH
# =============================================================================
def qslcl_dispatch(dev, cmd_name, payload=b"", timeout=1.0):
    cmd_upper = cmd_name.upper()
    if cmd_upper in QSLCLCMD_DB:
        cmd_entry = QSLCLCMD_DB[cmd_upper]
        print(f"[*] QSLCLCMD dispatch → {cmd_upper} (opcode: 0x{cmd_entry['opcode']:02X})")
        # Build proper frame with standard header
        cmd_body = struct.pack("<B", cmd_entry['opcode']) + cmd_entry['data'] + payload
        flags = cmd_entry.get('flags', 0x01)
        pkt = encode_qslcl_structure(b"QSLCLCMD", cmd_body, flags)
        return exec_universal(dev, cmd_upper, pkt)
    try:
        opcode = int(cmd_name, 0)
        if opcode in QSLCLCMD_DB:
            cmd_entry = QSLCLCMD_DB[opcode]
            print(f"[*] QSLCLCMD dispatch → opcode 0x{opcode:02X} ({cmd_entry['name']})")
            cmd_body = struct.pack("<B", opcode) + cmd_entry['data'] + payload
            flags = cmd_entry.get('flags', 0x01)
            pkt = encode_qslcl_structure(b"QSLCLCMD", cmd_body, flags)
            return exec_universal(dev, cmd_entry['name'], pkt)
    except (ValueError, KeyError):
        pass
    print(f"[*] Fallback dispatch → {cmd_upper}")
    return exec_universal(dev, cmd_upper, payload)

def exec_universal(dev, cmd_name, payload):
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            if dev.handle is None:
                dev.handle, dev.serial_mode = open_transport(dev)
                if dev.handle is None:
                    raise RuntimeError("Failed to open device transport")
            dev.write(payload)
            response_timeout = 2.0 + (attempt * 1.0)
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
# SECTOR SIZE DETECTOR
# =============================================================================
def detect_sector_size(dev):
    VALID_SIZES = {512, 1024, 2048, 4096, 8192, 16384}
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
    print("[!] Fallback sector size = 4096")
    return 4096

def get_sector_size(dev):
    global _DETECTED_SECTOR_SIZE
    if _DETECTED_SECTOR_SIZE:
        return _DETECTED_SECTOR_SIZE
    sz = detect_sector_size(dev)
    print(f"[*] SECTOR SIZE DETECTED = {sz}")
    _DETECTED_SECTOR_SIZE = sz
    return sz

# =============================================================================
# LOADER FUNCTIONS
# =============================================================================
def send_packets(handle, data, serial_mode, chunk=4096):
    total = len(data)
    sent = 0
    for off in range(0, total, chunk):
        blk = data[off:off+chunk]
        # Use proper standard header format
        pkt = encode_qslcl_structure(b"QSLCLDATA", blk, 0x00)
        if serial_mode:
            handle.write(pkt)
        else:
            try:
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
    if not QSLCLHDR_DB:
        print("[!] No QSLCLHDR block loaded. Authentication not possible.")
        return False
    cert = QSLCLHDR_DB.get("QSLCHDR2") or QSLCLHDR_DB.get("QSLCHDR1") or QSLCLHDR_DB.get("QSLCLHDR")
    if not cert:
        print("[!] Certificate not found. Cannot authenticate.")
        return False
    print(f"[*] Certificate detected: {len(cert)} bytes")
    if "AUTHENTICATE" in QSLCLCMD_DB:
        print("[*] AUTH via QSLCLCMD AUTHENTICATE command")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", cert)
    else:
        print("[*] AUTH fallback mode")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", cert)
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
    if not getattr(args, "loader", None):
        return
    loader_path = args.loader
    print(f"[*] Loading loader: {loader_path}")
    try:
        with open(loader_path, "rb") as f:
            blob = f.read()
    except Exception as e:
        print(f"[!] Cannot read loader: {e}")
        return
    if len(blob) < 0x100:
        print("[!] Loader appears too small — aborting.")
        return
    print("[*] Parsing loader structures…")
    try:
        loader = QSLCLLoader()
        ok = loader.parse_loader(blob)
        if not ok:
            print("[!] Loader parsing failed.")
        else:
            print(f"[*] Detected modules:")
            if loader.BIN:
                bin_info = loader.BIN.get('main', {})
                print(f"    QSLCLBIN: {bin_info.get('architecture', 'unknown')} arch, "
                      f"CRC {'✓' if bin_info.get('crc_valid', False) else '✗'}")
            
            cmd_count = len([k for k in loader.CMD.keys() if isinstance(k, str) and k.isalpha()])
            print(f"    QSLCLCMD: {cmd_count} commands")
            
            ep_count = len([k for k in loader.END.keys() if isinstance(k, EndpointInfo)])
            print(f"    QSLCLEND: {ep_count} endpoints")
            
            print(f"    QSLCLBST: {len(loader.BST)} bootstrap configs")
            print(f"    QSLCLDISP: {len(loader.DISP)} dispatch entries")
            print(f"    QSLCLRTF: {len(loader.RTF)} fault codes")
        print()
    except Exception as e:
        print("[!] Loader parsing failed:", e)
        if _DEBUG:
            traceback.print_exc()
    try:
        handle, serial_mode = open_transport(dev)
    except Exception as e:
        print("[!] Cannot open transport:", e)
        return
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
    if "HELLO" in QSLCLCMD_DB:
        print("[*] Using QSLCLCMD HELLO command")
        resp = qslcl_dispatch(dev, "HELLO", b"")
    else:
        resp = qslcl_dispatch(dev, "HELLO", b"")
    if not resp:
        return print("[!] HELLO: No response from device.")
    status = decode_runtime_result(resp)
    print("[*] HELLO Response:", status)
    print("[*] Loader Modules Detected:")
    
    # Main binary info
    if QSLCLBIN_DB:
        bin_info = QSLCLBIN_DB.get('main', {})
        if bin_info:
            print(f"  Architecture : {bin_info.get('architecture', 'unknown')}")
            print(f"  Target Size  : {bin_info.get('target_size', 0)} bytes")
    
    unique_commands = len([name for name in QSLCLCMD_DB.keys() if isinstance(name, str) and name.isalpha()])
    print(f"  CMD commands : {unique_commands}")
    
    ep_count = len([k for k in QSLCLEND_DB.keys() if isinstance(k, EndpointInfo)])
    print(f"  END endpoints: {ep_count}")
    print(f"  DISP entries : {len(QSLCLDISP_DB)}")
    print(f"  RTF entries  : {len(QSLCLRTF_DB)}")
    print(f"  BST configs  : {len(QSLCLBST_DB)}")

def cmd_ping(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    dev = devs[0]
    payload = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)
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

def cmd_endpoints(args=None):
    """List USB endpoints from QSLCL binary"""
    if not QSLCLEND_DB:
        print("[!] No endpoint database (QSLCLEND) found in loader")
        return
    endpoints = list_endpoints()
    print(f"\n[*] USB Endpoints ({len(endpoints)} total):\n")
    print(f"  {'Name':<12} {'Direction':<10} {'Address':<10} {'Type':<8} {'Max Packet':<12}")
    print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*8} {'-'*12}")
    for ep in endpoints:
        print(f"  {ep.name:<12} {ep.direction:<10} 0x{ep.address:02X}{'':<7} {ep.type:<8} {ep.max_packet:<12}")
    print(f"\n[*] Summary by type:")
    ep_summary = get_endpoint_summary()
    for ep_type, eps in ep_summary.items():
        if eps:
            print(f"    {ep_type}: {len(eps)} endpoints")

def cmd_encryption(args=None):
    """Display QSLCLENC encryption layer information"""
    if not QSLCLENC_DB:
        print("[!] No encryption layer (QSLCLENC) found in loader")
        print("[*] Build with: python build.py qslcl.bin --encrypt")
        return
    
    enc_info = QSLCLENC_DB.get('encryption', {})
    
    if not enc_info:
        print("[!] Encryption layer found but failed to parse")
        return
    
    print("\n[*] QSLCLENC Encryption Layer Information")
    print("=" * 60)
    print(f"    Version:        {enc_info.get('version', 'Unknown')}")
    print(f"    Build Time:     {enc_info.get('timestamp_str', 'Unknown')}")
    print(f"    CRC Valid:      {'✓' if enc_info.get('crc_valid', False) else '✗'}")
    print(f"    Integrity:      {'✓ Valid' if enc_info.get('integrity_valid', False) else '✗ Invalid'}")
    
    print(f"\n[*] Supported Ciphers:")
    features = enc_info.get('features', {})
    print(f"    ChaCha20-Poly1305: {'✓ YES' if features.get('chacha20_poly1305') else '✗ NO'}")
    print(f"    AES-256-GCM:       {'✓ YES' if features.get('aes256_gcm') else '✗ NO'}")
    print(f"    Key Negotiation:   {'✓ YES' if features.get('key_negotiation') else '✗ NO'}")
    print(f"    Perfect Forward:   {'✓ YES' if features.get('perfect_forward_secrecy') else '✗ NO'}")
    print(f"    Anti-Replay:       {'✓ YES' if features.get('anti_replay') else '✗ NO'}")
    
    routines = enc_info.get('routines', {})
    if routines:
        print(f"\n[*] Micro-VM Routines:")
        for name, offset in routines.items():
            if offset:
                print(f"    {name}: 0x{offset:04X}")
    
    if enc_info.get('default_key'):
        print(f"\n[*] Default Key: {enc_info['default_key'][:16]}...")
    
    print("\n[*] This device supports encrypted USB communication")
    print("    QSLCL commands will be encrypted before transmission")

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def extract_strings(data, min_length=4):
    strings = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode('ascii', errors='ignore'))
            current = bytearray()
    if len(current) >= min_length:
        strings.append(current.decode('ascii', errors='ignore'))
    return strings

def detect_magic_numbers(data):
    magics = {
        b'\x7fELF': "ELF executable",
        b'MZ': "Windows executable",
        b'ANDROID!': "Android boot image",
        b'APFS': "Apple File System",
    }
    detected = []
    for magic, desc in magics.items():
        if data.startswith(magic):
            detected.append((magic, desc))
    return detected

def calculate_entropy(data):
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

def parse_device_info(resp):
    info = {
        "version": "Unknown",
        "architecture": "Unknown",
        "sector_size": "Unknown",
        "capabilities": [],
        "loader_version": "Unknown",
        "bootstrap_available": False,
        "bootstrap_architectures": [],
        "endpoints": []
    }
    if not resp:
        return info
    try:
        if isinstance(resp, bytes):
            if b"QSLCL" in resp:
                idx = resp.find(b"QSLCL")
                if idx + 16 <= len(resp):
                    version_part = resp[idx:idx+16]
                    version_match = re.search(rb'v?(\d+\.\d+\.\d+)', version_part)
                    if version_match:
                        info["version"] = version_match.group(1).decode()
        if isinstance(resp, bytes):
            arch_patterns = [(b"ARM", "ARM"), (b"x86", "x86"), (b"x64", "x86_64"), 
                           (b"RISCV", "RISC-V"), (b"MIPS", "MIPS"), (b"AARCH64", "ARM64")]
            for pattern, arch_name in arch_patterns:
                if pattern in resp:
                    info["architecture"] = arch_name
                    break
        info["bootstrap_available"] = bool(QSLCLBST_DB)
        if QSLCLBST_DB:
            bootstrap_archs = [arch for arch in QSLCLBST_DB.keys() if not arch.startswith('offset_')]
            info["bootstrap_architectures"] = bootstrap_archs
        info["endpoints"] = list_endpoints()
        
        # Add main binary info if available
        if QSLCLBIN_DB:
            bin_info = QSLCLBIN_DB.get('main', {})
            if bin_info:
                info["architecture"] = bin_info.get('architecture', info["architecture"])
    except Exception as e:
        if _DEBUG:
            print(f"[!] Device info parsing error: {e}")
    return info

def print_device_info(info):
    print("\n   Device Information:")
    print(f"     Version:      {info['version']}")
    print(f"     Architecture: {info['architecture']}")
    print(f"     Sector Size:  {info['sector_size']}")
    if info['capabilities']:
        print(f"     Capabilities: {', '.join(info['capabilities'])}")
    if info['bootstrap_available']:
        print(f"     Bootstrap:    AVAILABLE ({len(info['bootstrap_architectures'])} architectures)")
        if info['bootstrap_architectures']:
            print(f"                   {', '.join(info['bootstrap_architectures'])}")
    else:
        print("     Bootstrap:    NOT AVAILABLE")
    if info['endpoints']:
        print(f"     Endpoints:    {len(info['endpoints'])} total")

def load_partitions(dev):
    global PARTITION_CACHE
    dev_key = dev.serial if hasattr(dev, 'serial') else 'default'
    if dev_key in PARTITION_CACHE:
        return PARTITION_CACHE[dev_key]
    partitions = []
    try:
        partitions = detect_all_partitions(dev)
        PARTITION_CACHE[dev_key] = partitions
    except Exception as e:
        print(f"[!] Partition loading failed: {e}")
        partitions = [
            {"name": "boot", "offset": 0x880000, "size": 0x400000},
            {"name": "system", "offset": 0xC80000, "size": 0x8000000},
            {"name": "recovery", "offset": 0x88C80000, "size": 0x400000},
            {"name": "cache", "offset": 0x90C80000, "size": 0x4000000},
            {"name": "userdata", "offset": 0x94C80000, "size": 0x40000000},
        ]
        PARTITION_CACHE[dev_key] = partitions
    return partitions

def detect_all_partitions(dev):
    """Detect partitions - simplified version"""
    partitions = []
    try:
        resp = qslcl_dispatch(dev, "GETPARTITIONS", b"")
        if resp:
            pass
    except:
        pass
    return partitions

# =============================================================================
# MAIN FUNCTION
# =============================================================================
def main():
    class QSLCLHelp(argparse.HelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=36, width=140)

    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.2.10 (FIXED)",
        add_help=True,
        formatter_class=QSLCLHelp
    )

    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")
    p.add_argument("--wait", type=int, default=0, help="Wait N seconds for device to appear")
    p.add_argument("--debug", action="store_true", help="Enable debug output")

    sub = p.add_subparsers(dest="cmd", metavar="", required=False)

    def new_cmd(name, *args, **kwargs):
        sp = sub.add_parser(name, *args, **kwargs, formatter_class=QSLCLHelp)
        sp.add_argument("--loader", help="Inject qslcl.bin before executing command")
        sp.add_argument("--auth", action="store_true")
        sp.add_argument("--wait", type=int, default=0, help="Wait time before executing")
        return sp

    new_cmd("hello").set_defaults(func=cmd_hello)
    new_cmd("ping").set_defaults(func=cmd_ping)
    new_cmd("getinfo").set_defaults(func=cmd_getinfo)
    new_cmd("partitions").set_defaults(func=cmd_partitions)
    new_cmd("endpoints", help="List USB endpoints from QSLCL binary").set_defaults(func=cmd_endpoints)

    # READ command
    r = new_cmd("read", help="Read from partition, address, or storage device")
    r.add_argument("target", help="Target (partition name, address, partition+offset, storage device)")
    r.add_argument("arg2", nargs="?", help="Output filename OR size in bytes")
    r.add_argument("-o", "--output", help="Output filename")
    r.add_argument("--size", type=lambda x: int(x, 0), help="Size in bytes")
    r.add_argument("--chunk-size", type=lambda x: int(x, 0), default=131072, help="Read chunk size (default: 128KB)")
    r.add_argument("--no-verify", action="store_true", help="Skip write verification")
    r.add_argument("--format", choices=['raw', 'hex', 'disasm', 'json'], default='raw', help="Output format")
    r.add_argument("--resume", action="store_true", help="Resume interrupted read")
    r.add_argument("--scan", action="store_true", help="Scan mode for exploration")
    r.add_argument("--auto-detect", action="store_true", default=True, help="Auto-detect partitions")
    r.set_defaults(func=cmd_read)

    # WRITE command
    w = new_cmd("write", help="Write data to partition, address, or storage device")
    w.add_argument("target", help="Target (partition name, address, partition+offset, storage device)")
    w.add_argument("data", help="Data source (file path, hex string, pattern)")
    w.add_argument("--chunk-size", type=lambda x: int(x, 0), default=65536, help="Write chunk size (default: 64KB)")
    w.add_argument("--max-file-size", type=lambda x: int(x, 0), default=1073741824, help="Maximum file size")
    w.add_argument("--no-verify", action="store_true", help="Skip write verification")
    w.add_argument("--force", action="store_true", help="Skip safety checks (DANGEROUS)")
    w.add_argument("--protection", choices=['strict', 'normal', 'permissive', 'off'], default='normal', help="Protection level")
    w.add_argument("--no-protection-checks", action="store_true", help="DISABLE ALL PROTECTION CHECKS")
    w.add_argument("--test-readonly", action="store_true", help="Test if target region is read-only")
    w.set_defaults(func=cmd_write)

    # ERASE command
    e = new_cmd("erase", help="Erase partition, address range, or storage region")
    e.add_argument("target", help="Target (partition name, address, partition+offset, storage device)")
    e.add_argument("arg2", nargs="?", help="Erase size in bytes")
    e.add_argument("--size", type=lambda x: int(x, 0), help="Size in bytes")
    e.add_argument("--chunk-size", type=lambda x: int(x, 0), default=1048576, help="Erase chunk size (default: 1MB)")
    e.add_argument("--force", action="store_true", help="Skip safety checks (DANGEROUS)")
    e.set_defaults(func=cmd_erase)

    # PEEK command
    peek_parser = new_cmd("peek", help="Read memory with advanced addressing and data interpretation")
    peek_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression)")
    peek_parser.add_argument("-s", "--size", type=int, default=4, help="Number of bytes to read (default: 4)")
    peek_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'string'], default='auto', help="Data type interpretation")
    peek_parser.add_argument("-c", "--count", type=int, default=1, help="Number of elements for array types")
    peek_parser.set_defaults(func=cmd_peek)

    # POKE command
    poke_parser = new_cmd("poke", help="Write memory with advanced addressing and data types")
    poke_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression")
    poke_parser.add_argument("value", help="Value to write (supports multiple data types)")
    poke_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'hex', 'string'], default='auto', help="Data type of value")
    poke_parser.add_argument("-s", "--size", type=int, default=4, help="Size of write in bytes (for hex/string types)")
    poke_parser.set_defaults(func=cmd_poke)

    # RAWMODE command
    rawmode_parser = new_cmd("rawmode", help="Raw mode access and privilege escalation commands")
    rawmode_parser.add_argument("rawmode_subcommand", help="Rawmode subcommand (list, set, status, unlock, lock, configure, escalate, monitor, audit, reset)")
    rawmode_parser.add_argument("rawmode_args", nargs="*", help="Additional arguments for rawmode command")
    rawmode_parser.set_defaults(func=cmd_rawmode)

    # DUMP command
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

    # RESET command
    reset_parser = new_cmd("reset", help="System reset and restart commands")
    reset_parser.add_argument("reset_subcommand", help="Reset subcommand (list, soft, hard, force, domain, recovery, factory, bootloader, edl, pmic, watchdog, custom, sequence)")
    reset_parser.add_argument("reset_args", nargs="*", help="Additional arguments for reset command")
    reset_parser.add_argument("--force-reset", action="store_true", help="Bypass confirmation prompts")
    reset_parser.set_defaults(func=cmd_reset)

    # BRUTEFORCE command
    bruteforce_parser = new_cmd("bruteforce", help="Advanced brute-force and system exploration")
    bruteforce_parser.add_argument("bruteforce_subcommand", nargs="?", help="Bruteforce subcommand (list, scan, pattern, fuzz, dictionary, replay, analyze, continue)")
    bruteforce_parser.add_argument("pattern", nargs="?", help="Legacy pattern (e.g., 0x00-0xFFFF)")
    bruteforce_parser.add_argument("--threads", type=int, default=8, help="Number of threads")
    bruteforce_parser.add_argument("--rawmode", action="store_true", help="Enable raw mode")
    bruteforce_parser.add_argument("--output", help="Output filename")
    bruteforce_parser.add_argument("--strategy", choices=["basic", "smart", "aggressive"], default="basic", help="Bruteforce strategy")
    bruteforce_parser.add_argument("bruteforce_args", nargs="*", help="Additional arguments")
    bruteforce_parser.set_defaults(func=cmd_bruteforce)

    # CONFIG command
    config_parser = new_cmd("config", help="Configuration management commands")
    config_parser.add_argument("config_subcommand", help="Config subcommand (get, set, list, delete, backup, restore, reset, import, export, validate, info)")
    config_parser.add_argument("config_args", nargs="*", help="Additional arguments for config command")
    config_parser.add_argument("--verify", action="store_true", help="Verify configuration after setting")
    config_parser.set_defaults(func=cmd_config)

    new_cmd("config-list", help="List configuration capabilities").set_defaults(func=cmd_config_list)

    # GLITCH command
    glitch_parser = new_cmd("glitch", help="Hardware glitch injection")
    glitch_parser.add_argument("glitch_subcommand", help="Glitch subcommand")
    glitch_parser.add_argument("glitch_args", nargs="*", help="Additional arguments")
    glitch_parser.add_argument("--level", type=int, help="Glitch level")
    glitch_parser.add_argument("--iter", type=int, help="Iterations")
    glitch_parser.add_argument("--window", type=int, help="Timing window")
    glitch_parser.add_argument("--sweep", type=int, help="Sweep range")
    glitch_parser.set_defaults(func=cmd_glitch)

    # FOOTER command
    footer_parser = new_cmd("footer", help="Footer analysis")
    footer_parser.add_argument("--type", dest="footer_type", default="STANDARD", choices=["STANDARD","EXTENDED","SECURITY","BOOT","LOADER","DEBUG","AUDIT","ALL"])
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

    # PATCH command
    patch_parser = new_cmd("patch", help="Advanced binary patching")
    patch_parser.add_argument("patch_args", nargs="+", help="Patch specification: <target> <patch_data>")
    patch_parser.add_argument("--patch-type", choices=['file', 'hex', 'pattern', 'replace', 'instruction', 'auto'], default='auto', help="Explicit patch type")
    patch_parser.add_argument("--no-verify", action="store_true", help="Skip patch verification")
    patch_parser.add_argument("--chunk-size", type=lambda x: int(x, 0), default=4096, help="Patch chunk size in bytes")
    patch_parser.add_argument("--retries", type=int, default=3, help="Max retry attempts")
    patch_parser.set_defaults(func=cmd_patch)

    # OEM command
    oem_parser = new_cmd("oem", help="OEM commands")
    oem_parser.add_argument("oem_subcommand", help="OEM subcommand")
    oem_parser.add_argument("oem_args", nargs="*", help="Additional arguments")
    oem_parser.set_defaults(func=cmd_oem)

    # ODM command
    odm_parser = new_cmd("odm", help="ODM commands")
    odm_parser.add_argument("odm_subcommand", help="ODM subcommand")
    odm_parser.add_argument("odm_args", nargs="*", help="Additional arguments")
    odm_parser.set_defaults(func=cmd_odm)

    # MODE command
    mode_parser = new_cmd("mode", help="Mode control")
    mode_parser.add_argument("mode_subcommand", help="Mode subcommand")
    mode_parser.add_argument("mode_args", nargs="*", help="Additional arguments")
    mode_parser.set_defaults(func=cmd_mode)

    new_cmd("mode-status", help="Check current mode").set_defaults(func=cmd_mode_status)

    # CRASH command
    crash_parser = new_cmd("crash", help="Crash simulation")
    crash_parser.add_argument("crash_subcommand", help="Crash subcommand")
    crash_parser.add_argument("crash_args", nargs="*", help="Additional arguments")
    crash_parser.set_defaults(func=cmd_crash)

    new_cmd("crash-test", help="Crash test").set_defaults(func=cmd_crash_test)

    # BYPASS command
    bypass_parser = new_cmd("bypass", help="Security bypass engine")
    bypass_parser.add_argument("bypass_subcommand", help="Bypass subcommand")
    bypass_parser.add_argument("bypass_args", nargs="*", help="Additional arguments")
    bypass_parser.set_defaults(func=cmd_bypass)

    # VOLTAGE command
    voltage_parser = new_cmd("voltage", help="Voltage control")
    voltage_parser.add_argument("voltage_subcommand", help="Voltage subcommand")
    voltage_parser.add_argument("voltage_args", nargs="*", help="Additional arguments")
    voltage_parser.set_defaults(func=cmd_voltage)

    # POWER command
    power_parser = new_cmd("power", help="Power management")
    power_parser.add_argument("power_subcommand", help="Power subcommand")
    power_parser.add_argument("power_args", nargs="*", help="Additional arguments")
    power_parser.set_defaults(func=cmd_power)

    # VERIFY command
    verify_parser = new_cmd("verify", help="System verification")
    verify_parser.add_argument("verify_subcommand", help="Verify subcommand")
    verify_parser.add_argument("verify_args", nargs="*", help="Additional arguments")
    verify_parser.set_defaults(func=cmd_verify)

    # RAWSTATE command
    rawstate_parser = new_cmd("rawstate", help="Low-level state inspection")
    rawstate_parser.add_argument("rawstate_subcommand", help="Rawstate subcommand")
    rawstate_parser.add_argument("rawstate_args", nargs="*", help="Additional arguments")
    rawstate_parser.set_defaults(func=cmd_rawstate)

    enc_parser = new_cmd("encryption", help="Display encryption layer information")
    enc_parser.set_defaults(func=cmd_encryption)

    args = p.parse_args()

    # Set debug mode
    if args.debug:
        set_debug(True)
        print("[*] Debug mode enabled")

    if (args.wait or 0) > 0:
        print(f"[*] Waiting up to {args.wait}s for device...")
        dev = wait_for_device(timeout=args.wait)
        if not dev:
            print("[!] No device found within timeout.")
            return 1
    else:
        devs = scan_all()
        if not devs:
            print("[!] No valid QSLCL-compatible device detected.")
            return 1
        dev = devs[0]
        if not validate_device(dev):
            print(f"[!] Device '{dev.product}' is not suitable for QSLCL operations.")
            return 1

    if args.loader:
        auto_loader_if_needed(args, dev)
        
    if hasattr(args, "func"):
        try:
            result = args.func(args)
            if dev and hasattr(dev, 'close'):
                dev.close()
            return result if result is not None else 0
        except Exception as e:
            print(f"[!] Command execution failed: {e}")
            if _DEBUG:
                traceback.print_exc()
            return 1
    else:
        p.print_help()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())