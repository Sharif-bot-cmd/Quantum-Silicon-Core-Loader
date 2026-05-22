#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v2.1.4
# Author: Sharif — QSLCL Creator
# Works on all SOC architectures
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
except ImportError:
    SERIAL_SUPPORT = False
    
try:
    import usb.core
    import usb.util
    USB_SUPPORT = True
except ImportError:
    USB_SUPPORT = False

# =============================================================================
# GLOBAL DATABASES
# =============================================================================
QSLCLBIN_DB = {}  # Main binary header
QSLCLCMD_DB = {}  # Command database
QSLCLVM5_DB = {}  # Nano-kernel microservices
QSLCLUSB_DB = {}  # USB micro-engine
QSLCLSPT_DB = {}  # USB setup packet table
QSLCLDISP_DB = {}  # Command dispatch table
QSLCLRTF_DB = {}  # Runtime fault table
QSLCLBST_DB = {}  # Bootstrap database
QSLCLEND_DB = {}  # Endpoint database
QSLCLENC_DB = {}  # Encryption layer
QSLCLDAT_DB = {}  # Data transfer protocol
QSLCLSYN_DB = {}  # Synchronization block
QSLCLHDR_DB = {}  # Certificate/header blocks
QSLCLUSB4_DB = {}  

_DETECTED_SECTOR_SIZE = None
PARTITION_CACHE = {}
_DEBUG = False

def set_debug(enabled: bool = True):
    global _DEBUG
    _DEBUG = enabled

# =============================================================================
# STANDARD HEADER PARSING
# =============================================================================
def parse_standard_header(data: bytes) -> Optional[dict]:
    """Parse QSLCL standard header: [MAGIC(8)][size(4)][flags(4)][crc(4)][body]"""
    if len(data) < 20:
        return None
    
    try:
        magic = data[:8].rstrip(b'\x00')
        size, flags, stored_crc = struct.unpack("<III", data[8:20])
        
        if size > 100 * 1024 * 1024:  # 100MB max
            return None
            
        if 20 + size > len(data):
            return None
            
        body = data[20:20+size]
        calculated_crc = zlib.crc32(body) & 0xFFFFFFFF
        
        return {
            "magic": magic,
            "size": size,
            "flags": flags,
            "stored_crc": stored_crc,
            "calculated_crc": calculated_crc,
            "crc_valid": (stored_crc == calculated_crc),
            "body": body,
            "total_size": 20 + size
        }
    except Exception as e:
        if _DEBUG:
            print(f"[!] parse_standard_header: {e}")
        return None

def encode_qslcl_structure(magic: bytes, body: bytes, flags: int = 0) -> bytes:
    """Encode QSLCL standard structure"""
    if len(magic) != 8:
        magic = magic.ljust(8, b'\x00')[:8]
    size = len(body)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack("<8sIII", magic, size, flags, crc) + body

def scan_for_blocks(data: bytes) -> dict:
    """Scan binary for all QSLCL structured blocks"""
    blocks = {}
    i = 0
    while i <= len(data) - 20:
        if data[i:i+5] == b'QSLCL':
            header = parse_standard_header(data[i:])
            if header:
                magic_str = header['magic'].decode('ascii', errors='ignore')
                if magic_str not in blocks:
                    blocks[magic_str] = []
                blocks[magic_str].append({
                    'offset': i,
                    'header': header,
                    'body': header['body']
                })
                i += header['total_size']
                continue
        i += 1
    return blocks

# =============================================================================
# BLOCK PARSERS
# =============================================================================

def load_qslclbin(blob: bytes):
    """Parse QSLCLBIN - Main binary header"""
    global QSLCLBIN_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLBIN' in blocks:
        for block in blocks['QSLCLBIN']:
            body = block['body']
            header = block['header']
            
            if len(body) >= 40:
                try:
                    bin_size, timestamp, build_hash = struct.unpack("<QQ8s", body[:24])
                    arch = body[24:40].decode('ascii', errors='ignore').rstrip('\x00')
                    
                    # Pointer table at offset 0x28
                    ptrs = {}
                    if len(body) >= 0x80:
                        ptrs['bootstrap'] = struct.unpack("<III", body[0x28:0x34])
                        ptrs['cmd_table'] = struct.unpack("<I", body[0x34:0x38])[0]
                        ptrs['disp_table'] = struct.unpack("<I", body[0x38:0x3C])[0]
                        ptrs['usb_table'] = struct.unpack("<I", body[0x3C:0x40])[0]
                        ptrs['vm5_table'] = struct.unpack("<I", body[0x40:0x44])[0]
                        ptrs['spt_table'] = struct.unpack("<I", body[0x44:0x48])[0]
                        ptrs['rtf_table'] = struct.unpack("<I", body[0x48:0x4C])[0]
                        ptrs['sync_table'] = struct.unpack("<I", body[0x4C:0x50])[0]
                        ptrs['cert_table'] = struct.unpack("<I", body[0x50:0x54])[0]
                        ptrs['encryption'] = struct.unpack("<I", body[0x60:0x64])[0]
                        ptrs['data_proto'] = struct.unpack("<I", body[0x64:0x68])[0]
                    
                    QSLCLBIN_DB['main'] = {
                        'target_size': bin_size,
                        'timestamp': timestamp,
                        'build_hash': build_hash.hex(),
                        'architecture': arch,
                        'crc_valid': header['crc_valid'],
                        'offset': block['offset'],
                        'pointers': ptrs
                    }
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] QSLCLBIN parse: {e}")

def load_qslclcmd(blob: bytes):
    """Parse QSLCLCMD - Command database with CRC validation"""
    global QSLCLCMD_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLCMD' in blocks:
        for block in blocks['QSLCLCMD']:
            body = block['body']
            pos = 0
            
            while pos + 40 <= len(body):
                try:
                    name_field, opcode, flags, tier, family_hash, length, stored_crc, timestamp = \
                        struct.unpack("<16sBBBBHII", body[pos:pos+40])
                    
                    name = name_field.decode('ascii', errors='ignore').rstrip('\x00')
                    if not name or length > 4096:
                        pos += 1
                        continue
                    
                    if pos + 40 + length > len(body):
                        break
                    
                    cmd_data = body[pos+40:pos+40+length]
                    calculated_crc = zlib.crc32(cmd_data) & 0xFFFFFFFF
                    
                    QSLCLCMD_DB[name] = {
                        'name': name,
                        'opcode': opcode,
                        'flags': flags,
                        'tier': tier,
                        'length': length,
                        'crc_valid': (stored_crc == calculated_crc),
                        'data': cmd_data,
                        'offset': block['offset'] + pos
                    }
                    pos += 40 + length
                except:
                    pos += 1

def load_qslclbst(blob: bytes):
    """Parse QSLCLBST - Bootstrap engine"""
    global QSLCLBST_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLBST' in blocks:
        for block in blocks['QSLCLBST']:
            body = block['body']
            if len(body) >= 28:
                try:
                    arch = body[:16].decode('ascii', errors='ignore').rstrip('\x00')
                    entry, code_size, timestamp = struct.unpack("<III", body[16:28])
                    
                    QSLCLBST_DB[arch] = {
                        'arch_name': arch,
                        'entry_point': entry,
                        'code_size': code_size,
                        'timestamp': timestamp,
                        'offset': block['offset'],
                        'secure_mode': bool(block['header']['flags'] & 0x01),
                        'crc_valid': block['header']['crc_valid']
                    }
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] QSLCLBST parse: {e}")

def load_qslclend(blob: bytes):
    """Parse QSLCLEND/BLK - USB endpoint database"""
    global QSLCLEND_DB
    blocks = scan_for_blocks(blob)
    
    for magic in ['QSLCLEND', 'QSLCLBLK']:
        if magic in blocks:
            for block in blocks[magic]:
                body = block['body']
                if len(body) >= 2:
                    count = struct.unpack("<H", body[:2])[0]
                    pos = 2
                    for i in range(count):
                        if pos + 32 <= len(body):
                            try:
                                entry = body[pos:pos+32]
                                name = entry[:12].decode('ascii', errors='ignore').rstrip('\x00')
                                direction = {0: "OUT", 1: "IN", 2: "BIDIR"}.get(entry[12], "UNKNOWN")
                                addr = entry[13]
                                ep_type = {0: "CTRL", 1: "BULK", 2: "INT", 3: "ISO"}.get(entry[14], "UNKNOWN")
                                max_pkt = struct.unpack("<I", entry[24:28])[0]
                                
                                if name.strip():
                                    QSLCLEND_DB[name.upper()] = {
                                        'name': name, 'direction': direction,
                                        'address': addr, 'type': ep_type,
                                        'max_packet': max_pkt
                                    }
                            except:
                                pass
                            pos += 32

def load_qslclrtf(blob: bytes):
    """Parse QSLCLRTF - Runtime fault table"""
    global QSLCLRTF_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLRTF' in blocks:
        for block in blocks['QSLCLRTF']:
            body = block['body']
            if len(body) >= 2:
                count = struct.unpack("<H", body[:2])[0]
                pos = 2
                for i in range(count):
                    if pos + 20 <= len(body):
                        code = struct.unpack("<I", body[pos:pos+4])[0]
                        sev = body[pos+4]
                        cat = body[pos+5]
                        retry = struct.unpack("<H", body[pos+6:pos+8])[0]
                        msg_hash = struct.unpack("<I", body[pos+8:pos+12])[0]
                        name = body[pos+12:pos+20].decode('ascii', errors='ignore').rstrip('\x00')
                        
                        sev_names = {0: "SUCCESS", 1: "WARNING", 2: "ERROR", 3: "CRITICAL", 4: "FATAL"}
                        if name and code != 0:
                            QSLCLRTF_DB[code] = {
                                'severity': sev, 'severity_name': sev_names.get(sev, f"LVL{sev}"),
                                'category': cat, 'retry': retry, 'msg': name, 'hash': msg_hash
                            }
                        pos += 20

def load_qslcldisp(blob: bytes):
    """Parse QSLCLDIS - Command dispatch table"""
    global QSLCLDISP_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLDIS' in blocks:
        for block in blocks['QSLCLDIS']:
            body = block['body']
            if len(body) >= 2:
                count = struct.unpack("<H", body[:2])[0]
                pos = 2
                for i in range(count):
                    if pos + 12 <= len(body):
                        cmd_hash, addr = struct.unpack("<8sI", body[pos:pos+12])
                        QSLCLDISP_DB[f"entry_{i:04X}"] = {'hash': cmd_hash.hex(), 'addr': addr}
                        pos += 12

def load_qslclenc(blob: bytes):
    """Parse QSLCLENC - Encryption layer"""
    global QSLCLENC_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLENC' in blocks:
        for block in blocks['QSLCLENC']:
            body = block['body']
            if len(body) >= 12:
                caps = struct.unpack("<I", body[0:4])[0]
                ver = struct.unpack("<I", body[4:8])[0]
                ts = struct.unpack("<I", body[8:12])[0]
                
                QSLCLENC_DB['encryption'] = {
                    'offset': block['offset'],
                    'capabilities': caps,
                    'version': f"{(ver>>16)&0xFFFF}.{(ver>>8)&0xFF}.{ver&0xFF}",
                    'timestamp': ts,
                    'features': {
                        'chacha20': bool(caps & 0x01),
                        'aes256': bool(caps & 0x02),
                        'key_negotiation': bool(caps & 0x04),
                        'pfs': bool(caps & 0x08),
                        'anti_replay': bool(caps & 0x10)
                    },
                    'crc_valid': block['header']['crc_valid']
                }

def load_qslcldat(blob: bytes):
    """Parse QSLCLDAT - Data transfer protocol"""
    global QSLCLDAT_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLDAT' in blocks:
        for block in blocks['QSLCLDAT']:
            body = block['body']
            if len(body) >= 8:
                ver, caps = struct.unpack("<II", body[:8])
                QSLCLDAT_DB['data_proto'] = {
                    'offset': block['offset'],
                    'version': ver,
                    'capabilities': caps,
                    'crc_valid': block['header']['crc_valid']
                }

def load_qslclsyn(blob: bytes):
    """Parse QSLCLSYN - Synchronization block"""
    global QSLCLSYN_DB
    blocks = scan_for_blocks(blob)
    
    if 'QSLCLSYN' in blocks:
        for block in blocks['QSLCLSYN']:
            body = block['body']
            if len(body) >= 20:
                sync_magic = body[:8]
                proto_ver = struct.unpack("<I", body[8:12])[0]
                frame_count = struct.unpack("<H", body[12:14])[0]
                
                QSLCLSYN_DB['sync'] = {
                    'offset': block['offset'],
                    'sync_magic': sync_magic.decode('ascii', errors='ignore'),
                    'proto_version': proto_ver,
                    'frame_types': frame_count,
                    'crc_valid': block['header']['crc_valid']
                }

def load_usb4v2mc(blob: bytes):
    """Parse USB4V2MC - USB4 v2.0 Microcode block"""
    global QSLCLUSB4_DB
    blocks = scan_for_blocks(blob)
    
    if 'USB4V2MC' in blocks:
        for block in blocks['USB4V2MC']:
            body = block['body']
            if len(body) >= 16:
                try:
                    version, caps, max_bw, tunnels = struct.unpack("<IIII", body[:16])
                    
                    QSLCLUSB4_DB['usb4_v2'] = {
                        'offset': block['offset'],
                        'version': f"{(version>>16)&0xFFFF}.{(version>>8)&0xFF}.{version&0xFF}",
                        'capabilities': caps,
                        'max_bandwidth': max_bw,
                        'tunnels': {
                            'pcie': bool(tunnels & 0x01),
                            'dp': bool(tunnels & 0x02),
                            'usb3': bool(tunnels & 0x04)
                        },
                        'has_microcode': len(body) > 16,
                        'has_security': bool(block['header']['flags'] & 0x02),
                        'crc_valid': block['header']['crc_valid']
                    }
                    
                    # Parse tunnel configuration if present
                    if len(body) >= 28:
                        pcie_id, dp_id, usb3_id = struct.unpack("<III", body[16:28])
                        QSLCLUSB4_DB['usb4_v2']['tunnel_ids'] = {
                            'pcie': pcie_id,
                            'dp': dp_id,
                            'usb3': usb3_id
                        }
                except Exception as e:
                    if _DEBUG:
                        print(f"[!] USB4V2MC parse: {e}")

def load_remaining_blocks(blob: bytes):
    """Parse remaining block types (VM5, USB, SPT, HDR)"""
    global QSLCLVM5_DB, QSLCLUSB_DB, QSLCLSPT_DB, QSLCLHDR_DB
    blocks = scan_for_blocks(blob)
    
    for magic, block_list in blocks.items():
        for block in block_list:
            if magic == 'QSLCLVM5':
                QSLCLVM5_DB['vm5'] = {'offset': block['offset'], 'size': len(block['body'])}
            elif magic == 'QSLCLUSB':
                QSLCLUSB_DB['usb'] = {'offset': block['offset'], 'size': len(block['body'])}
            elif magic == 'QSLCLSPT':
                QSLCLSPT_DB['spt'] = {'offset': block['offset'], 'size': len(block['body'])}
            elif magic in ('QSLCHDR2', 'QSLCHDR1', 'QSLCLHDR'):
                QSLCLHDR_DB[magic] = block['body']

# =============================================================================
# UNIFIED LOADER
# =============================================================================
class QSLCLLoader:
    """Unified QSLCL binary parser"""
    
    def __init__(self):
        self.BIN = {}
        self.CMD = {}
        self.END = {}
        self.BST = {}
        self.DISP = {}
        self.RTF = {}
        self.ENC = {}
        self.DAT = {}
        self.SYN = {}
        self.VM5 = {}
        self.USB = {}
        self.SPT = {}
        self.HDR = {}
        self.USB4 = {}

    def parse(self, blob: bytes) -> bool:
        """Parse QSLCL binary with all block types"""
        blocks = scan_for_blocks(blob)
        
        if not blocks:
            return False
        
        # Parse known block types
        load_qslclbin(blob)
        load_qslclcmd(blob)
        load_qslclbst(blob)
        load_qslclend(blob)
        load_qslclrtf(blob)
        load_qslcldisp(blob)
        load_qslclenc(blob)
        load_qslcldat(blob)
        load_qslclsyn(blob)
        load_usb4v2mc(blob) 
        load_remaining_blocks(blob)
        
        # Update instance attributes
        self.BIN = QSLCLBIN_DB
        self.CMD = QSLCLCMD_DB
        self.END = QSLCLEND_DB
        self.BST = QSLCLBST_DB
        self.DISP = QSLCLDISP_DB
        self.RTF = QSLCLRTF_DB
        self.ENC = QSLCLENC_DB
        self.DAT = QSLCLDAT_DB
        self.SYN = QSLCLSYN_DB
        self.VM5 = QSLCLVM5_DB
        self.USB = QSLCLUSB_DB
        self.SPT = QSLCLSPT_DB
        self.HDR = QSLCLHDR_DB
        self.USB4 = QSLCLUSB4_DB

        return True

# =============================================================================
# DEVICE STRUCTURE
# =============================================================================
@dataclass
class QSLCLDevice:
    transport: str
    identifier: str
    vendor: str = "Unknown"
    product: str = "Unknown"
    vid: int = None
    pid: int = None
    usb_class: int = None
    usb_subclass: int = None
    usb_protocol: int = None
    serial: str = "default"
    handle: any = None
    serial_mode: bool = False

    def write(self, data: bytes):
        if self.handle is None:
            self.handle, self.serial_mode = open_transport(self)
        if not self.serial_mode:
            cfg = self.handle.get_active_configuration()
            intf = cfg[(0, 0)]
            for ep in intf.endpoints():
                if (usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT and
                    usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                    return self.handle.write(ep.bEndpointAddress, data, timeout=2000)
            return self.handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, data)
        else:
            return self.handle.write(data)

    def read(self, timeout=1.0):
        if self.handle is None:
            self.handle, self.serial_mode = open_transport(self)
        return recv(self.handle, self.serial_mode, timeout=timeout)

    def close(self):
        if self.handle:
            try:
                if self.serial_mode:
                    self.handle.close()
                else:
                    usb.util.dispose_resources(self.handle)
            except:
                pass

# =============================================================================
# iOS DEVICE DETECTION & RECOVERY MODE BOOT (Like palera1n)
# =============================================================================

def detect_ios_normal_mode(dev: QSLCLDevice) -> dict:
    """
    Detect if device is an iOS device in NORMAL mode (not DFU).
    Returns dict with device info if iOS device found.
    """
    result = {
        "is_ios": False,
        "device_type": None,
        "product_type": None,
        "ios_version": None,
        "udid": None,
        "model": None
    }
    
    if dev.handle is None or dev.serial_mode:
        return result
    
    try:
        # Check for Apple VID
        if dev.vid != 0x05AC:  # Apple Vendor ID
            return result
        
        # Try to get iProduct string
        try:
            product_str = usb.util.get_string(dev.handle, dev.handle.iProduct)
            if product_str and ("iPhone" in product_str or "iPad" in product_str or "iPod" in product_str):
                result["is_ios"] = True
                result["device_type"] = "iOS"
                result["product_type"] = product_str
        except:
            pass
        
        # Try to get iSerial (often contains UDID for iOS devices)
        try:
            if dev.handle.iSerialNumber:
                serial = usb.util.get_string(dev.handle, dev.handle.iSerialNumber)
                # iOS UDID is 40 characters (SHA1 hash)
                if serial and len(serial) == 40 and all(c in "0123456789ABCDEF" for c in serial.upper()):
                    result["udid"] = serial.upper()
        except:
            pass
        
        # Check configuration for iOS-specific descriptors
        try:
            cfg = dev.handle.get_active_configuration()
            for intf in cfg:
                # iOS devices have specific interface classes
                if intf.bInterfaceClass in (0x0A, 0xFF):  # CDC Data or Vendor
                    if not result["is_ios"]:
                        result["is_ios"] = True
                        result["device_type"] = "iOS (Likely)"
        except:
            pass
        
        # If we have an Apple device with USB, it's likely iOS
        if dev.vid == 0x05AC and not result["is_ios"]:
            result["is_ios"] = True
            result["device_type"] = "Apple Device (iOS likely)"
            
    except Exception as e:
        if _DEBUG:
            print(f"[!] iOS detection failed: {e}")
    
    return result


def get_ios_device_list() -> list:
    """
    Scan for iOS devices in NORMAL mode (not DFU).
    Returns list of devices with UDID and model info.
    """
    ios_devices = []
    
    if not USB_SUPPORT:
        return ios_devices
    
    try:
        for dev in usb.core.find(find_all=True):
            if dev.idVendor == 0x05AC:  # Apple VID
                device_info = {
                    "vid": dev.idVendor,
                    "pid": dev.idProduct,
                    "bus": dev.bus,
                    "address": dev.address,
                    "is_dfu": False,
                    "is_recovery": False,
                    "is_normal": True,
                    "product": None,
                    "serial": None,
                    "udid": None
                }
                
                # Check if in DFU mode (class 0xFE, subclass 0x01)
                try:
                    cfg = dev.get_active_configuration()
                    for intf in cfg:
                        if intf.bInterfaceClass == 0xFE and intf.bInterfaceSubClass == 0x01:
                            device_info["is_dfu"] = True
                            device_info["is_normal"] = False
                except:
                    pass
                
                # Get product string
                try:
                    device_info["product"] = usb.util.get_string(dev, dev.iProduct)
                except:
                    pass
                
                # Get serial/UDID
                try:
                    serial = usb.util.get_string(dev, dev.iSerialNumber)
                    if serial and len(serial) == 40:
                        device_info["udid"] = serial.upper()
                    device_info["serial"] = serial
                except:
                    pass
                
                # Only include normal mode devices (not DFU)
                if not device_info["is_dfu"]:
                    ios_devices.append(device_info)
                    
    except Exception as e:
        if _DEBUG:
            print(f"[!] iOS device scan failed: {e}")
    
    return ios_devices


def send_recovery_mode_command(dev: QSLCLDevice, udid: str = None) -> bool:
    """
    Send command to iOS device to reboot into recovery mode.
    Uses lockdownd or usbmuxd protocol.
    """
    if dev.handle is None:
        return False
    
    try:
        # Method 1: Try to send via usbmuxd (if available)
        # This is the standard way palera1n/checkra1n does it
        
        # First, try to get lockdownd service
        try:
            # Send lockdownd query
            lockdown_req = struct.pack("<I", 0x6C646E64)  # "ldnd"
            dev.handle.ctrl_transfer(
                bmRequestType=0xC0,
                bRequest=0x01,
                wValue=0x0000,
                wIndex=0x0000,
                data_or_wLength=lockdown_req,
                timeout=1000
            )
        except:
            pass
        
        # Method 2: Send iOS recovery mode trigger via vendor request
        # This is the actual command that tells iOS to enter recovery
        try:
            # Recovery mode trigger (0x52 = 'R' for Recovery)
            recovery_trigger = dev.handle.ctrl_transfer(
                bmRequestType=0x40,
                bRequest=0x52,
                wValue=0x0001,
                wIndex=0x0000,
                data_or_wLength=b"\x00" * 8,
                timeout=1000
            )
            return True
        except:
            pass
        
        # Method 3: Use libusb reset to trigger recovery
        try:
            dev.handle.reset()
            return True
        except:
            pass
            
    except Exception as e:
        if _DEBUG:
            print(f"[!] Recovery mode command failed: {e}")
    
    return False

def boot_to_dfu_with_confirm(device_info: dict, timeout: int = 10) -> bool:
    """
    Display instructions for user to boot into DFU mode (like palera1n).
    Shows button press sequence and waits for device to enter DFU.
    
    Args:
        device_info: Dictionary with device information
        timeout: Timeout in seconds for DFU mode detection (default: 10)
    
    Returns:
        True if device entered DFU mode, False otherwise
    """
    print("\n" + "=" * 60)
    print("                   ENTER DFU MODE")
    print("=" * 60)
    print()
    print(f"Device Detected: {device_info.get('product', 'iOS Device')}")
    if device_info.get('udid'):
        print(f"UDID: {device_info['udid']}")
    print()
    print("To enter DFU mode, follow these steps EXACTLY:")
    print()
    print("  1. Press and HOLD the POWER button for 5 seconds")
    print("  2. While still holding POWER, also HOLD the VOLUME DOWN button (if screen goes black)")
    print("  3. Keep holding BOTH buttons for exactly 5 seconds")
    print("  4. RELEASE the POWER button but KEEP holding VOLUME DOWN")
    print("  5. Wait 5-10 seconds - device should enter DFU mode")
    print()
    print("The screen will remain BLACK in DFU mode.")
    print("If you see the Apple logo or recovery screen, you waited too long.")
    print()
    print("-" * 60)
    
    response = input("Ready to boot into DFU mode? (y/N): ").strip().lower()
    
    if response != 'y' and response != 'yes':
        print("[*] Cancelled.")
        return False
    
    print()
    print("[*] Starting DFU mode sequence...")
    print("[*] Follow the button instructions above EXACTLY")
    print(f"[*] Waiting up to {timeout} seconds for device to enter DFU...")
    print()
    
    # Show countdown for button press
    for i in range(3, 0, -1):
        print(f"  Get ready... {i}")
        time.sleep(1)
    
    print("  NOW! Follow the button sequence above!")
    print()
    
    # Wait for device to re-appear in DFU mode
    start_time = time.time()
    last_print = 0
    
    while time.time() - start_time < timeout:
        # Scan for DFU devices
        dfu_devices = []
        try:
            for dev in usb.core.find(find_all=True):
                if dev.idVendor == 0x05AC:
                    try:
                        cfg = dev.get_active_configuration()
                        for intf in cfg:
                            if (hasattr(intf, 'bInterfaceClass') and 
                                intf.bInterfaceClass == 0xFE and 
                                hasattr(intf, 'bInterfaceSubClass') and 
                                intf.bInterfaceSubClass == 0x01):
                                dfu_devices.append(dev)
                                break
                    except:
                        pass
        except:
            pass
        
        if dfu_devices:
            print("\n[+] Device entered DFU mode successfully!")
            return True
        
        # Print progress every 2 seconds
        elapsed = int(time.time() - start_time)
        if elapsed != last_print and elapsed < timeout:
            last_print = elapsed
            print(f"  Waiting for DFU mode... ({elapsed}s)")
        
        time.sleep(0.5)
    
    print(f"\n[!] Timeout: Device did not enter DFU mode after {timeout} seconds.")
    print("[*] Try again, making sure to follow the button timing exactly.")
    return False

def auto_dfu_boot(args, dev: QSLCLDevice) -> Optional[QSLCLDevice]:
    """
    Main function: Auto-detect iOS device in normal mode,
    offer to boot into DFU mode (like palera1n), then reconnect.
    Returns new DFU device or None.
    """
    print("[*] Scanning for iOS devices in normal mode...")
    
    # Get list of iOS devices (non-DFU)
    ios_devices = get_ios_device_list()
    
    if not ios_devices:
        print("[!] No iOS devices found in normal mode.")
        print("[*] Make sure your iOS device is connected and unlocked.")
        print("[*] Trust this computer if prompted on device.")
        return None
    
    print(f"[+] Found {len(ios_devices)} iOS device(s) in normal mode:")
    for i, device in enumerate(ios_devices):
        print(f"    {i+1}. {device.get('product', 'iOS Device')}")
        if device.get('udid'):
            print(f"       UDID: {device['udid']}")
        print(f"       USB: Bus {device['bus']}, Addr {device['address']}")
    
    print()
    
    # Select device if multiple
    selected = None
    if len(ios_devices) == 1:
        selected = ios_devices[0]
        print(f"[*] Selected: {selected.get('product', 'iOS Device')}")
    else:
        choice = input(f"Select device (1-{len(ios_devices)}) or 'q' to quit: ").strip()
        if choice.lower() == 'q':
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(ios_devices):
                selected = ios_devices[idx]
        except:
            print("[!] Invalid selection.")
            return None
    
    if not selected:
        return None
    
    # Ask for confirmation to boot to DFU
    print()
    print("[*] This will boot your device into DFU mode.")
    print("[*] Your device screen will go BLACK (this is normal).")
    print()
    
    confirm = input("Continue? (y/N): ").strip().lower()
    if confirm != 'y' and confirm != 'yes':
        print("[*] Cancelled.")
        return None
    
    # Send recovery command (optional - device will still enter DFU manually)
    try:
        # Try to open the device to send command
        handle, _ = open_transport(dev)
        if handle:
            send_recovery_mode_command(dev, selected.get('udid'))
            dev.close()
    except:
        pass
    
    # Show DFU button instructions and wait
    success = boot_to_dfu_with_confirm(selected, timeout=30)
    
    if not success:
        print("[!] Failed to enter DFU mode.")
        print("[*] You can still manually put device in DFU mode and re-run.")
        return None
    
    # Wait a bit for device to stabilize
    time.sleep(2)
    
    # Scan for DFU device
    print("[*] Looking for device in DFU mode...")
    dfu_dev = None
    
    for _ in range(5):  # Try up to 5 times
        all_devs = scan_all()
        for d in all_devs:
            if d.transport == "usb" and d.vid == 0x05AC:
                # Check if in DFU mode
                try:
                    handle, _ = open_transport(d)
                    if handle:
                        # Try to identify DFU mode
                        try:
                            cfg = handle.get_active_configuration()
                            for intf in cfg:
                                if intf.bInterfaceClass == 0xFE and intf.bInterfaceSubClass == 0x01:
                                    dfu_dev = d
                                    break
                        except:
                            pass
                        d.close()
                except:
                    pass
            if dfu_dev:
                break
        if dfu_dev:
            break
        time.sleep(1)
    
    if dfu_dev:
        print("[+] Device now in DFU mode!")
        print(f"    VID:PID = {dfu_dev.vid:04X}:{dfu_dev.pid:04X}")
        return dfu_dev
    else:
        print("[!] Could not find device in DFU mode.")
        print("[*] Please manually enter DFU mode and run the command again.")
        return None

# =============================================================================
# DEVICE SCANNING
# =============================================================================
def universal_dfu_detection(dev):
    """Detect any DFU mode device via USB DFU class specification"""
    try:
        cfg = dev.get_active_configuration()
        for intf in cfg:
            if intf.bInterfaceClass == 0xFE and intf.bInterfaceSubClass == 0x01:
                protocol_map = {0x01: "DFU Runtime", 0x02: "DFU Download"}
                protocol = protocol_map.get(intf.bInterfaceProtocol, "DFU Mode")
                try:
                    vendor = usb.util.get_string(dev, dev.iManufacturer)
                except:
                    vendor = "Unknown"
                return {'mode': 'DFU', 'protocol': protocol, 'vendor': vendor,
                        'vid': dev.idVendor, 'pid': dev.idProduct}
        return None
    except:
        return None

def scan_usb():
    if not USB_SUPPORT:
        return []
    devs = []
    try:
        for d in usb.core.find(find_all=True):
            try:
                dfu = universal_dfu_detection(d)
                if dfu:
                    devs.append(QSLCLDevice(
                        transport="usb",
                        identifier=f"bus={d.bus},addr={d.address}",
                        vendor=dfu['vendor'],
                        product=f"DFU Device ({dfu['protocol']})",
                        vid=d.idVendor, pid=d.idProduct,
                        usb_class=0xFE, usb_subclass=0x01,
                        serial="dfu_mode", handle=d
                    ))
                    continue
                
                cfg = d.get_active_configuration()
                intf = cfg[(0, 0)]
                if intf.bInterfaceClass in (0x01, 0x02, 0x03, 0x07, 0x08, 0x0A):
                    continue
                
                has_in = has_out = False
                for ep in intf.endpoints():
                    if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                        if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                            has_in = True
                        else:
                            has_out = True
                
                if not (has_in and has_out):
                    continue
                
                try:
                    product = usb.util.get_string(d, d.iProduct) or "USB Device"
                except:
                    product = "USB Device"
                
                devs.append(QSLCLDevice(
                    transport="usb",
                    identifier=f"bus={d.bus},addr={d.address}",
                    vendor=f"VID_{d.idVendor:04X}",
                    product=product,
                    vid=d.idVendor, pid=d.idProduct,
                    usb_class=intf.bInterfaceClass,
                    usb_subclass=intf.bInterfaceSubClass,
                    serial="default", handle=d
                ))
            except:
                continue
    except:
        pass
    return devs

def scan_serial():
    if not SERIAL_SUPPORT:
        return []
    devs = []
    try:
        for p in list_ports.comports():
            devs.append(QSLCLDevice(
                transport="serial",
                identifier=p.device,
                vendor=p.manufacturer or "Unknown",
                product=p.description or "Serial",
                vid=getattr(p, 'vid', None),
                pid=getattr(p, 'pid', None),
                serial=p.serial_number or "default"
            ))
    except:
        pass
    return devs

def scan_all(auto_dfu: bool = False, dfu_timeout: int = 30):
    """
    Scan all devices. If auto_dfu=True and no DFU device found,
    automatically offer to boot iOS device into DFU mode (like palera1n).
    
    Args:
        auto_dfu: If True, automatically offer to boot iOS device into DFU mode
        dfu_timeout: Timeout in seconds for DFU mode detection (default: 30)
    
    Returns:
        List of QSLCLDevice objects
    """
    # Initial scan
    devs = scan_usb() + scan_serial()
    
    # Check if we already have a DFU device (Apple DFU class 0xFE, subclass 0x01)
    has_dfu = False
    for d in devs:
        if d.transport == "usb" and d.vid == 0x05AC:
            try:
                handle, _ = open_transport(d)
                if handle:
                    cfg = handle.get_active_configuration()
                    for intf in cfg:
                        if (hasattr(intf, 'bInterfaceClass') and 
                            intf.bInterfaceClass == 0xFE and 
                            hasattr(intf, 'bInterfaceSubClass') and 
                            intf.bInterfaceSubClass == 0x01):
                            has_dfu = True
                            break
                    d.close()
            except:
                pass
    
    # If no DFU device and auto_dfu is enabled, try to boot into DFU
    if not has_dfu and auto_dfu:
        print("[*] No DFU device detected.")
        print("[*] Checking for iOS device in normal mode...")
        
        # Create a dummy device for the auto-boot function
        dummy_dev = QSLCLDevice(transport="usb", identifier="auto")
        
        # Call auto_dfu_boot with timeout
        dfu_dev = auto_dfu_boot(None, dummy_dev, timeout=dfu_timeout)
        
        if dfu_dev:
            print("[*] DFU mode detected! Re-scanning...")
            time.sleep(1)  # Give device time to stabilize
            # Re-scan after DFU boot
            devs = scan_usb() + scan_serial()
            
            # Verify we got a DFU device
            dfu_verified = False
            for d in devs:
                if d.transport == "usb" and d.vid == 0x05AC:
                    try:
                        handle, _ = open_transport(d)
                        if handle:
                            cfg = handle.get_active_configuration()
                            for intf in cfg:
                                if (hasattr(intf, 'bInterfaceClass') and 
                                    intf.bInterfaceClass == 0xFE and 
                                    hasattr(intf, 'bInterfaceSubClass') and 
                                    intf.bInterfaceSubClass == 0x01):
                                    dfu_verified = True
                                    print(f"[+] Confirmed: Device in DFU mode (VID:PID={d.vid:04X}:{d.pid:04X})")
                                    break
                            d.close()
                    except:
                        pass
                if dfu_verified:
                    break
            
            if not dfu_verified:
                print("[!] Warning: Could not verify DFU mode after boot")
        else:
            print("[!] Auto-DFU boot failed or was cancelled")
    
    # Scoring function for device prioritization
    def score(d):
        s = 0
        
        # Highest priority: DFU mode devices (Apple DFU class)
        if d.transport == "usb" and d.vid == 0x05AC:
            try:
                handle, _ = open_transport(d)
                if handle:
                    cfg = handle.get_active_configuration()
                    for intf in cfg:
                        if (hasattr(intf, 'bInterfaceClass') and 
                            intf.bInterfaceClass == 0xFE and 
                            hasattr(intf, 'bInterfaceSubClass') and 
                            intf.bInterfaceSubClass == 0x01):
                            s += 200  # DFU mode highest priority
                            break
                    d.close()
            except:
                pass
        
        # Vendor-specific priority
        if d.usb_class == 0xFF:  # Vendor-specific class
            s += 100
        if d.usb_class in (0x0A, 0x02):  # CDC Data or Communications
            s += 70
        
        # Product name priority
        if d.product and d.product not in ("USB Device", "Serial", "Unknown"):
            s += 30
            # Extra points for QSLCL identification
            if "QSLCL" in d.product:
                s += 50
        
        # VID/PID present
        if d.vid and d.pid:
            s += 20
        
        # USB transport preferred over serial
        if d.transport == "usb":
            s += 10
        
        return -s  # Negative for descending sort
    
    devs.sort(key=score)
    
    # Print debug info if enabled
    if _DEBUG and devs:
        print(f"[*] Found {len(devs)} device(s):")
        for i, d in enumerate(devs[:3]):  # Show first 3 only
            print(f"    {i+1}. {d.transport.upper()}: {d.product} (VID:PID={d.vid:04X}:{d.pid:04X})")
        if len(devs) > 3:
            print(f"    ... and {len(devs) - 3} more")
    
    return devs

def wait_for_device(timeout=None, interval=0.5):
    start = time.time()
    while True:
        devs = scan_all()
        if devs:
            return devs[0]
        if timeout and (time.time() - start) >= timeout:
            return None
        time.sleep(interval)

# =============================================================================
# TRANSPORT FUNCTIONS
# =============================================================================
def open_transport(dev: QSLCLDevice):
    if dev.transport == "serial":
        try:
            h = serial.Serial(dev.identifier, 115200, timeout=1)
            return h, True
        except Exception as e:
            print(f"[!] Serial open failed: {e}")
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
                    print(f"[!] USB config failed: {e}")
                    return None, False
            try:
                usb.util.claim_interface(dev.handle, 0)
            except usb.core.USBError as e:
                if e.errno != 16:
                    print(f"[!] USB claim failed: {e}")
                    return None, False
            return dev.handle, False
        except Exception as e:
            print(f"[!] USB open failed: {e}")
            return None, False

def recv(handle, serial_mode, timeout=3.0):
    """Receive and parse QSLCL frames with CRC validation"""
    deadline = time.time() + timeout
    buff = bytearray()
    
    while time.time() < deadline:
        try:
            if serial_mode:
                chunk = handle.read(64)
            else:
                chunk = b""
                try:
                    cfg = handle.get_active_configuration()
                    intf = cfg[(0, 0)]
                    for ep in intf.endpoints():
                        if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                            try:
                                chunk = handle.read(ep.bEndpointAddress, 64, timeout=500)
                                if chunk:
                                    break
                            except:
                                pass
                except:
                    pass
            if chunk:
                buff.extend(chunk)
        except:
            break
        
        # Parse complete frames
        while len(buff) >= 20:
            header = parse_standard_header(buff)
            if header and header['crc_valid']:
                magic = header['magic'].decode('ascii', errors='ignore')
                total = header['total_size']
                del buff[:total]
                return magic, header['body']
            
            # Try to find next magic
            idx = buff.find(b'QSLCL')
            if idx > 0:
                del buff[:idx]
            elif idx == -1:
                break
            else:
                # At start but invalid, skip one byte
                del buff[:1]
        
        time.sleep(0.002)
    
    return None, None

def detect_usb4_v2_device(dev: QSLCLDevice) -> dict:
    """
    Detect if device supports USB4 v2.0 80Gbps mode.
    Returns capabilities dictionary.
    """
    result = {
        "usb4_v2_supported": False,
        "max_bandwidth": 0,
        "tunnels": [],
        "pam_encoding": None,
        "security": False
    }
    
    if dev.handle is None or dev.serial_mode:
        return result
    
    try:
        # Try to query USB4 v2.0 capability via vendor request
        # This is USB4 v2.0 standard request 0xFA (Capability Query)
        try:
            resp = dev.handle.ctrl_transfer(
                bmRequestType=0xC0,  # Device to host, vendor
                bRequest=0xFA,       # USB4 v2.0 capability query
                wValue=0x0000,
                wIndex=0x0000,
                data_or_wLength=16,
                timeout=500
            )
            
            if len(resp) >= 8:
                caps = struct.unpack("<II", resp[:8])
                result["usb4_v2_supported"] = True
                result["max_bandwidth"] = caps[0]
                
                # Parse tunnel support
                if caps[1] & 0x01:
                    result["tunnels"].append("PCIe")
                if caps[1] & 0x02:
                    result["tunnels"].append("DisplayPort")
                if caps[1] & 0x04:
                    result["tunnels"].append("USB3")
                    
                # PAM encoding from response
                if len(resp) >= 12:
                    encoding = struct.unpack("<I", resp[8:12])[0]
                    encoding_map = {1: "PAM3", 2: "PAM4", 3: "PAM3/4 Auto"}
                    result["pam_encoding"] = encoding_map.get(encoding, "Unknown")
                    
                # Security support
                if len(resp) >= 16:
                    result["security"] = bool(resp[12] & 0x01)
                    
        except:
            pass
            
        # Also check USB4 v2.0 capability descriptor
        try:
            # Check device qualifier for SuperSpeed Plus
            # USB4 v2.0 devices report bcdUSB >= 0x0400
            if hasattr(dev.handle, 'bcdUSB'):
                bcd_usb = dev.handle.bcdUSB
                if bcd_usb >= 0x0400:  # USB4 or higher
                    result["usb4_v2_supported"] = True
                    if result["max_bandwidth"] == 0:
                        result["max_bandwidth"] = 80000  # Assume 80Gbps
        except:
            pass
            
    except Exception as e:
        if _DEBUG:
            print(f"[!] USB4 v2.0 detection failed: {e}")
    
    return result

# =============================================================================
# COMMAND DISPATCH
# =============================================================================
def qslcl_dispatch(dev: QSLCLDevice, cmd_name: str, payload: bytes = b"", timeout: float = 2.0):
    cmd_upper = cmd_name.upper()
    
    if cmd_upper in QSLCLCMD_DB:
        cmd_entry = QSLCLCMD_DB[cmd_upper]
        cmd_body = struct.pack("<B", cmd_entry['opcode']) + cmd_entry['data'] + payload
        pkt = encode_qslcl_structure(b"QSLCLCMD", cmd_body, cmd_entry.get('flags', 0x01))
    else:
        pkt = encode_qslcl_structure(b"QSLCLCMD", payload, 0x01)
    
    for attempt in range(3):
        try:
            if dev.handle is None:
                dev.handle, dev.serial_mode = open_transport(dev)
            dev.write(pkt)
            typ, resp = dev.read(timeout=timeout + attempt)
            if resp is not None:
                return resp
        except Exception as e:
            if _DEBUG:
                print(f"[!] Dispatch attempt {attempt+1}: {e}")
        time.sleep(0.5)
    
    return None

def decode_runtime_result(resp, origin="DISPATCH"):
    """Decode response using runtime fault table"""
    if not resp or len(resp) < 2:
        return {"severity": "ERROR", "code": 0xFFFF, "name": "NO_RESPONSE"}
    
    code = int.from_bytes(resp[:2], "little")
    extra = resp[2:] if len(resp) > 2 else b""
    
    if code in QSLCLRTF_DB:
        entry = QSLCLRTF_DB[code]
        return {"severity": entry['severity_name'], "code": code, "name": entry['msg'], "extra": extra}
    if code == 0:
        return {"severity": "SUCCESS", "code": 0, "name": "OK", "extra": extra}
    return {"severity": "UNKNOWN", "code": code, "name": f"0x{code:04X}", "extra": extra}

# =============================================================================
# AUTOMATIC USB QSLCL EXPOSURE (Device Configuration)
# =============================================================================

def expose_qslcl_usb_string(dev: QSLCLDevice, force_refresh: bool = False):
    """
    Automatically expose "QSLCL" in USB device configuration when qslcl.bin is executed.
    Similar to MediaTek DA (Download Agent) or Qualcomm Sahara protocol.
    
    This writes QSLCL identifier to:
    - iProduct string descriptor (visible in lsusb)
    - iSerial string descriptor (unique identifier)
    - USB device qualifier (for super-speed detection)
    """
    if dev.handle is None or dev.serial_mode:
        return False
    
    try:
        # Check if QSLCL is already exposed
        if not force_refresh:
            try:
                current_product = usb.util.get_string(dev.handle, dev.handle.iProduct)
                if current_product and "QSLCL" in current_product:
                    return True  # Already exposed
            except:
                pass
        
        # ============================================================
        # METHOD 1: Set iProduct string descriptor to "QSLCL Loader"
        # ============================================================
        qslcl_product = "QSLCL Loader v2.1.1"
        qslcl_serial = f"QSLCL-{dev.vid:04X}-{dev.pid:04X}-{int(time.time()):08X}"
        
        # Try standard SET_DESCRIPTOR request (not all devices support)
        try:
            # iProduct index is usually 2 or 3
            product_desc = qslcl_product.encode('utf-16le')
            desc_header = struct.pack("<BB", len(product_desc) + 2, 0x03)  # String descriptor type
            full_desc = desc_header + product_desc
            
            # Attempt to set string descriptor (vendor request 0x40)
            dev.handle.ctrl_transfer(
                bmRequestType=0x40,  # Host to device, vendor request
                bRequest=0x06,       # SET_DESCRIPTOR
                wValue=0x0302,       # String descriptor index 2
                wIndex=0x0409,       # English (US)
                data_or_wLength=full_desc,
                timeout=1000
            )
        except:
            pass  # Not all devices support runtime descriptor changes
        
        # ============================================================
        # METHOD 2: Set iSerial to QSLCL identifier (more reliable)
        # ============================================================
        try:
            serial_desc = qslcl_serial.encode('utf-16le')
            desc_header = struct.pack("<BB", len(serial_desc) + 2, 0x03)
            full_serial = desc_header + serial_desc
            
            dev.handle.ctrl_transfer(
                bmRequestType=0x40,
                bRequest=0x06,
                wValue=0x0303,       # iSerial index 3
                wIndex=0x0409,
                data_or_wLength=full_serial,
                timeout=1000
            )
        except:
            pass
        
        # ============================================================
        # METHOD 3: Vendor-specific QSLCL identifier (most reliable)
        # ============================================================
        # This writes to a custom USB register that identifies QSLCL
        QSLCL_USB_MAGIC = 0x51534C43  # "QSLC" in hex
        
        try:
            # Try vendor-specific control transfer to identify QSLCL
            dev.handle.ctrl_transfer(
                bmRequestType=0xC0,  # Device to host, vendor request
                bRequest=0xF0,       # QSLCL identification request
                wValue=QSLCL_USB_MAGIC,
                wIndex=0x0000,
                data_or_wLength=8,
                timeout=500
            )
        except:
            pass
        
        # ============================================================
        # METHOD 4: Expose via USB device qualifier (SuperSpeed)
        # ============================================================
        # Set bcdUSB to indicate QSLCL capability (3.0+)
        try:
            # Device qualifier descriptor (for high/super speed)
            qualifier = struct.pack("<BBHBBBBBB",
                0x0A,       # bLength
                0x06,       # bDescriptorType (DEVICE_QUALIFIER)
                0x0300,     # bcdUSB 3.0
                0xFF,       # bDeviceClass (vendor)
                0x00,       # bDeviceSubClass
                0x53,       # bDeviceProtocol (0x53 = 'S' for QSLCL)
                512,        # bMaxPacketSize0
                1,          # bNumConfigurations
                0           # bReserved
            )
            # Note: This requires re-enumeration, may not work live
        except:
            pass
        
        # ============================================================
        # METHOD 5: Add QSLCL to active configuration descriptor
        # ============================================================
        try:
            # Read current configuration descriptor
            cfg = dev.handle.get_active_configuration()
            
            # Modify bInterfaceProtocol to 0x51 ('Q' for QSLCL)
            # This requires libusb 1.0.22+ and device support
            for intf in cfg:
                if intf.bInterfaceProtocol != 0x51:
                    # Try to set custom protocol
                    try:
                        dev.handle.ctrl_transfer(
                            bmRequestType=0x41,
                            bRequest=0x0B,
                            wValue=intf.bAlternateSetting,
                            wIndex=intf.bInterfaceNumber,
                            data_or_wLength=b"\x51",
                            timeout=1000
                        )
                    except:
                        pass
        except:
            pass
        
        # ============================================================
        # METHOD 6: Auto-detect and print exposed identifiers
        # ============================================================
        if _DEBUG:
            print(f"[*] QSLCL USB identifiers exposed:")
            print(f"    Product: {qslcl_product}")
            print(f"    Serial: {qslcl_serial}")
            print(f"    Magic: 0x{QSLCL_USB_MAGIC:08X}")
        
        return True
        
    except Exception as e:
        if _DEBUG:
            print(f"[!] USB exposure failed: {e}")
        return False


def auto_expose_qslcl_on_connect(dev: QSLCLDevice):
    """
    Automatically called when device connects.
    Exposes QSLCL in USB configuration without user intervention.
    """
    if dev is None or dev.handle is None:
        return False
    
    # Only expose on USB devices (not serial)
    if dev.serial_mode:
        return False
    
    # Try up to 3 times
    for attempt in range(3):
        if expose_qslcl_usb_string(dev, force_refresh=(attempt > 0)):
            if _DEBUG:
                print(f"[*] QSLCL exposed in USB config (attempt {attempt + 1})")
            return True
        time.sleep(0.1)
    
    return False


def verify_qslcl_usb_exposure(dev: QSLCLDevice) -> dict:
    """
    Verify if QSLCL is properly exposed in USB configuration.
    Returns dict with exposure status and details.
    """
    result = {
        "exposed": False,
        "product_string": None,
        "serial_string": None,
        "protocol": None,
        "vendor_magic": None
    }
    
    if dev.handle is None or dev.serial_mode:
        return result
    
    try:
        # Check product string
        if dev.handle.iProduct:
            result["product_string"] = usb.util.get_string(dev.handle, dev.handle.iProduct)
            if result["product_string"] and "QSLCL" in result["product_string"]:
                result["exposed"] = True
        
        # Check serial string
        if dev.handle.iSerialNumber:
            result["serial_string"] = usb.util.get_string(dev.handle, dev.handle.iSerialNumber)
            if result["serial_string"] and "QSLCL" in result["serial_string"]:
                result["exposed"] = True
        
        # Check vendor magic
        try:
            magic_resp = dev.handle.ctrl_transfer(
                bmRequestType=0xC0,
                bRequest=0xF0,
                wValue=0x0000,
                wIndex=0x0000,
                data_or_wLength=8,
                timeout=500
            )
            if len(magic_resp) >= 4:
                result["vendor_magic"] = int.from_bytes(magic_resp[:4], 'little')
                if result["vendor_magic"] == 0x51534C43:  # "QSLC"
                    result["exposed"] = True
        except:
            pass
        
        # Check protocol
        try:
            cfg = dev.handle.get_active_configuration()
            for intf in cfg:
                if intf.bInterfaceProtocol == 0x51:  # 'Q'
                    result["protocol"] = 0x51
                    result["exposed"] = True
        except:
            pass
        
    except Exception as e:
        if _DEBUG:
            print(f"[!] Verification failed: {e}")
    
    return result

# =============================================================================
# AUTOMATIC WATCHDOG DISABLER (Runs on every connection)
# =============================================================================
# Watchdog register offsets for different SoCs
WATCHDOG_DATABASE = {
    # Qualcomm
    "qualcomm": {
        "offsets": [0x02000000, 0x02000004, 0x02000008, 0x0200000C, 0x02000010],
        "magic_values": [0x00000001, 0x00000000, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32", "write32", "write32"]
    },
    # MediaTek
    "mediatek": {
        "offsets": [0x10000000, 0x10000004, 0x10000008, 0x1000000C, 0x10000010,
                    0x1C000000, 0x1C000004, 0x1C000008, 0x1C00000C, 0x1C000010],
        "magic_values": [0x00000005, 0x00000001, 0x22000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32", "write32", "write32", "write16"]
    },
    # Apple (A series)
    "apple": {
        "offsets": [0x20E00000, 0x20E00004, 0x20E00008, 0x20E0000C,
                    0x20E01000, 0x20E01004, 0x20E01008, 0x20E0100C,
                    0x20E02000, 0x20E02004],
        "magic_values": [0x00000000, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Samsung Exynos
    "samsung": {
        "offsets": [0x10060000, 0x10060004, 0x10060008, 0x1006000C,
                    0x10070000, 0x10070004],
        "magic_values": [0x00000001, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Broadcom (BCM)
    "broadcom": {
        "offsets": [0x18000000, 0x18000004, 0x18000008, 0x1800000C,
                    0x18001000, 0x18001004],
        "magic_values": [0x00000000, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Rockchip
    "rockchip": {
        "offsets": [0x20000000, 0x20000004, 0x20000008, 0x2000000C,
                    0x20004000, 0x20004004],
        "magic_values": [0x00000001, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Allwinner
    "allwinner": {
        "offsets": [0x01C20000, 0x01C20004, 0x01C20008, 0x01C20CA0, 0x01C20CA4],
        "magic_values": [0x00000000, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Amlogic
    "amlogic": {
        "offsets": [0xC1100000, 0xC1100004, 0xC1100008, 0xC110000C,
                    0xC1108000, 0xC1108004],
        "magic_values": [0x00000001, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # NVIDIA Tegra
    "nvidia": {
        "offsets": [0x60005000, 0x60005004, 0x60005008, 0x6000500C,
                    0x60005100, 0x60005104],
        "magic_values": [0x00000001, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
    # Generic ARM
    "generic_arm": {
        "offsets": [0x40000000, 0x40000004, 0x40000008, 0x4000000C,
                    0x40001000, 0x40001004, 0x40001008, 0x4000100C],
        "magic_values": [0x00000000, 0x00000000],
        "disable_value": 0x00000000,
        "write_methods": ["write32"]
    },
}

# Watchdog disable sequences (different methods)
WATCHDOG_DISABLE_SEQUENCES = {
    "write_zero": {
        "value": 0x00000000,
        "method": "write"
    },
    "write_ones": {
        "value": 0xFFFFFFFF,
        "method": "write"
    },
    "write_magic": {
        "value": 0xDEADBEEF,
        "method": "write"
    },
    "write_sequence": {
        "values": [0x12345678, 0x87654321, 0x5A5A5A5A],
        "method": "sequence"
    },
    "clear_bit": {
        "bit": 0,
        "method": "bit_clear"
    },
    "set_bit": {
        "bit": 31,
        "method": "bit_set"
    }
}

def detect_watchdog_offset(dev: QSLCLDevice, base_offset: int, debug: bool = False) -> int:
    """
    Detect watchdog offset by reading memory and checking for magic values.
    Returns offset if found, None otherwise.
    """
    if dev.handle is None or dev.serial_mode:
        return None
    
    # Try to read from candidate offset
    for offset_try in range(0, 0x1000, 0x100):  # Try sub-offsets
        addr = base_offset + offset_try
        
        try:
            # Try to read 4 bytes from this address
            # Use QSLCL dispatch to read memory
            payload = struct.pack("<II", addr, 4)
            resp = qslcl_dispatch(dev, "READ", payload, timeout=1.0)
            
            if resp and len(resp) >= 4:
                value = int.from_bytes(resp[:4], 'little')
                
                # Check if this looks like a watchdog register
                # Watchdog registers often have specific patterns
                if value in [0x00000000, 0x00000001, 0xDEADBEEF, 0x12345678]:
                    if debug:
                        print(f"[*] Possible watchdog register at 0x{addr:08X} = 0x{value:08X}")
                    return addr
                    
        except Exception as e:
            if debug:
                print(f"[!] Read failed at 0x{addr:08X}: {e}")
            continue
    
    return None

def disable_watchdog_at_offset(dev: QSLCLDevice, offset: int, soc_type: str = None, debug: bool = False) -> bool:
    """
    Disable watchdog at specific offset using appropriate method.
    Returns True if successful.
    """
    if dev.handle is None:
        return False
    
    # Get disable sequence for this SoC type
    soc_info = WATCHDOG_DATABASE.get(soc_type, WATCHDOG_DATABASE.get("generic_arm"))
    
    if soc_info:
        disable_val = soc_info.get("disable_value", 0x00000000)
        write_methods = soc_info.get("write_methods", ["write32"])
    else:
        disable_val = 0x00000000
        write_methods = ["write32"]
    
    success_count = 0
    
    for method in write_methods:
        try:
            if method == "write32" or method == "write":
                # Write 32-bit disable value
                payload = struct.pack("<III", offset, 4, disable_val)
                resp = qslcl_dispatch(dev, "WRITE", payload, timeout=1.0)
                success_count += 1
                
            elif method == "write16":
                # Write 16-bit disable value
                payload = struct.pack("<IIH", offset, 2, disable_val & 0xFFFF)
                resp = qslcl_dispatch(dev, "WRITE", payload, timeout=1.0)
                success_count += 1
                
            elif method == "bit_clear":
                # Read, clear bit, write back
                read_payload = struct.pack("<II", offset, 4)
                resp = qslcl_dispatch(dev, "READ", read_payload, timeout=1.0)
                if resp and len(resp) >= 4:
                    current = int.from_bytes(resp[:4], 'little')
                    bit = WATCHDOG_DISABLE_SEQUENCES["clear_bit"]["bit"]
                    new_val = current & ~(1 << bit)
                    write_payload = struct.pack("<III", offset, 4, new_val)
                    qslcl_dispatch(dev, "WRITE", write_payload, timeout=1.0)
                    success_count += 1
                    
        except Exception as e:
            if debug:
                print(f"[!] Disable method {method} failed: {e}")
    
    # Also try common disable sequences
    for seq_name, seq in WATCHDOG_DISABLE_SEQUENCES.items():
        try:
            if seq["method"] == "write":
                payload = struct.pack("<III", offset, 4, seq["value"])
                qslcl_dispatch(dev, "WRITE", payload, timeout=0.5)
                success_count += 1
            elif seq["method"] == "sequence":
                for val in seq["values"]:
                    payload = struct.pack("<III", offset, 4, val)
                    qslcl_dispatch(dev, "WRITE", payload, timeout=0.5)
                success_count += len(seq["values"])
        except:
            pass
    
    if debug and success_count > 0:
        print(f"[*] Watchdog disabled at 0x{offset:08X} ({success_count} operations)")
    
    return success_count > 0

def auto_detect_and_disable_watchdog(dev: QSLCLDevice, debug: bool = False) -> dict:
    """
    Automatically detect and disable watchdog on connected device.
    Runs without any user intervention.
    
    Returns dict with detection results.
    """
    result = {
        "watchdog_detected": False,
        "watchdog_disabled": False,
        "soc_type": None,
        "offsets_tried": [],
        "successful_offset": None,
        "method_used": None
    }
    
    if dev.handle is None or dev.serial_mode:
        if debug:
            print("[!] Cannot disable watchdog: No USB device or serial mode")
        return result
    
    if debug:
        print("[*] Auto-detecting watchdog registers...")
    
    # Try to identify SoC type from device info
    soc_type = None
    if dev.vid:
        # VID to SoC mapping
        vid_map = {
            0x05AC: "apple",      # Apple
            0x05C6: "qualcomm",   # Qualcomm
            0x0E8D: "mediatek",   # MediaTek
            0x04E8: "samsung",    # Samsung
            0x14E4: "broadcom",   # Broadcom
            0x2207: "rockchip",   # Rockchip
            0x1F3A: "allwinner",  # Allwinner
            0x10DE: "nvidia",     # NVIDIA
        }
        soc_type = vid_map.get(dev.vid, None)
        result["soc_type"] = soc_type
        if debug and soc_type:
            print(f"[*] Detected SoC type: {soc_type.upper()}")
    
    # Get candidate offsets for this SoC
    candidate_offsets = []
    
    if soc_type and soc_type in WATCHDOG_DATABASE:
        candidate_offsets = WATCHDOG_DATABASE[soc_type]["offsets"]
    else:
        # Try all known offsets
        for soc, info in WATCHDOG_DATABASE.items():
            candidate_offsets.extend(info["offsets"])
        candidate_offsets = list(set(candidate_offsets))  # Remove duplicates
    
    if debug:
        print(f"[*] Checking {len(candidate_offsets)} candidate offsets...")
    
    # Try each candidate offset
    for offset in candidate_offsets:
        result["offsets_tried"].append(offset)
        
        # Try to detect watchdog at this offset
        try:
            # Read current value
            payload = struct.pack("<II", offset, 4)
            resp = qslcl_dispatch(dev, "READ", payload, timeout=1.0)
            
            if resp and len(resp) >= 4:
                current_val = int.from_bytes(resp[:4], 'little')
                
                # Watchdog registers often have non-zero values
                if current_val != 0xFFFFFFFF and current_val != 0x00000000:
                    result["watchdog_detected"] = True
                    
                    if debug:
                        print(f"[*] Watchdog detected at 0x{offset:08X} = 0x{current_val:08X}")
                    
                    # Try to disable it
                    success = disable_watchdog_at_offset(dev, offset, soc_type, debug)
                    
                    if success:
                        result["watchdog_disabled"] = True
                        result["successful_offset"] = offset
                        
                        # Verify it's disabled (read back)
                        try:
                            verify_resp = qslcl_dispatch(dev, "READ", payload, timeout=1.0)
                            if verify_resp and len(verify_resp) >= 4:
                                new_val = int.from_bytes(verify_resp[:4], 'little')
                                if debug:
                                    print(f"[*] Verification: 0x{offset:08X} now = 0x{new_val:08X}")
                        except:
                            pass
                        
                        break  # Success, stop trying
                        
        except Exception as e:
            if debug:
                print(f"[!] Check failed at 0x{offset:08X}: {e}")
            continue
    
    # If no specific offset found, try brute force detection
    if not result["watchdog_detected"] and soc_type is None:
        if debug:
            print("[*] No specific watchdog detected, trying generic detection...")
        
        # Try common ARM watchdog ranges
        generic_ranges = [
            (0x40000000, 0x40001000),  # Generic ARM
            (0x60000000, 0x60001000),  # Another range
            (0x80000000, 0x80001000),  # Another range
        ]
        
        for start, end in generic_ranges:
            for offset in range(start, end, 0x1000):
                if offset in result["offsets_tried"]:
                    continue
                    
                result["offsets_tried"].append(offset)
                detected = detect_watchdog_offset(dev, offset, debug)
                
                if detected:
                    result["watchdog_detected"] = True
                    success = disable_watchdog_at_offset(dev, detected, None, debug)
                    
                    if success:
                        result["watchdog_disabled"] = True
                        result["successful_offset"] = detected
                        break
            
            if result["watchdog_disabled"]:
                break
    
    # Final status message
    if result["watchdog_disabled"]:
        if debug:
            print(f"[+] Watchdog successfully disabled at 0x{result['successful_offset']:08X}")
    elif result["watchdog_detected"]:
        if debug:
            print("[!] Watchdog detected but could not be disabled")
    else:
        if debug:
            print("[*] No watchdog detected (or device has no watchdog)")
    
    return result

# =============================================================================
# AUTO-RUN ON CONNECTION (Integrate into existing code)
# =============================================================================
def auto_disable_watchdog_on_connect(dev: QSLCLDevice, debug: bool = False) -> bool:
    """
    Automatically called when device connects.
    Detects and disables watchdog without any user intervention.
    """
    if dev is None or dev.handle is None:
        return False
    
    # Only run on USB devices
    if dev.serial_mode:
        return False
    
    # Wait a moment for device to stabilize
    time.sleep(0.5)
    
    # Run watchdog disabler
    result = auto_detect_and_disable_watchdog(dev, debug)
    
    return result["watchdog_disabled"]

# =============================================================================
# AUTO LOADER
# =============================================================================
def auto_loader_if_needed(args, dev: QSLCLDevice):
    """Inject qslcl.bin if --loader specified"""
    if not getattr(args, "loader", None):
        return
    
    loader_path = args.loader
    print(f"[*] Loading: {loader_path}")
    
    try:
        with open(loader_path, "rb") as f:
            blob = f.read()
    except Exception as e:
        print(f"[!] Cannot read: {e}")
        return
    
    # Parse and display info
    loader = QSLCLLoader()
    loader.parse(blob)
    print_loader_info(loader)
    
    # Upload
    handle, smode = open_transport(dev)
    if handle is None:
        return
    
    print("[*] Uploading loader...")
    chunk = 4096
    total = len(blob)
    for off in range(0, total, chunk):
        blk = blob[off:off+chunk]
        pkt = encode_qslcl_structure(b"QSLCLDAT", blk)
        if smode:
            handle.write(pkt)
        else:
            cfg = handle.get_active_configuration()
            intf = cfg[(0, 0)]
            for ep in intf.endpoints():
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                    handle.write(ep.bEndpointAddress, pkt, timeout=2000)
                    break
        print(f"\r[*] Progress: {min(off+chunk,total)*100//total}%", end='')
        time.sleep(0.01)
    print("\n[+] Loader uploaded.")

    if not smode:  # Only for USB devices
        print("[*] Auto-disabling watchdog...")
        watchdog_result = auto_detect_and_disable_watchdog(dev, debug=_DEBUG)
        
        if watchdog_result["watchdog_disabled"]:
            print(f"[+] Watchdog disabled at offset 0x{watchdog_result['successful_offset']:08X}")
        elif watchdog_result["watchdog_detected"]:
            print("[!] Watchdog detected but could not be disabled")
        else:
            print("[*] No watchdog detected")

    usb4_enabled = getattr(args, "usb4", False)
    
    if not smode and usb4_enabled:  # Only for USB devices with --usb4 flag
        print("[*] Checking USB4 v2.0 80Gbps support...")
        
        # Detect USB4 v2.0 capabilities
        usb4_caps = detect_usb4_v2_device(dev)
        
        if usb4_caps["usb4_v2_supported"]:
            print(f"[+] USB4 v2.0 device detected:")
            print(f"    Max Bandwidth: {usb4_caps['max_bandwidth']} Mbps ({usb4_caps['max_bandwidth']//1000} Gbps)")

            if usb4_caps["tunnels"]:
                print(f"    Supported Tunnels: {', '.join(usb4_caps['tunnels'])}")
            if usb4_caps["pam_encoding"]:
                print(f"    PAM Encoding: {usb4_caps['pam_encoding']}")
            if usb4_caps["security"]:
                print(f"    Security: CMA + DPP enabled")
            
            # Check if loader has USB4 microcode
            if loader.USB4 and loader.USB4.get('usb4_v2'):
                print("[*] USB4 v2.0 microcode present in loader")

                try:
                    # Send USB4 v2.0 initialization request
                    init_resp = dev.handle.ctrl_transfer(
                        bmRequestType=0x40,  # Host to device
                        bRequest=0xFB,       # USB4 v2.0 init
                        wValue=0x0001,       # Enable 80Gbps
                        wIndex=0x0000,
                        data_or_wLength=b"\x00"*8,
                        timeout=2000
                    )
                    print("[*] USB4 v2.0 80Gbps mode initialized")
                except:
                    print("[!] Could not initialize 80Gbps mode (may require re-enumeration)")
            else:
                print("[!] USB4 v2.0 microcode not found in loader (rebuild with --usb4-v2)")
        else:
            print("[*] Device does not support USB4 v2.0 (standard USB mode)")
    
    # ========== NEW: Auto-expose QSLCL in USB ==========
    if not smode:  # Only for USB devices
        print("[*] Exposing QSLCL in USB configuration...")
        auto_expose_qslcl_on_connect(dev)
        
        # Verify exposure
        exposure = verify_qslcl_usb_exposure(dev)
        if exposure["exposed"]:
            print(f"[+] QSLCL identified in USB:")
            if exposure["product_string"]:
                print(f"    Product: {exposure['product_string']}")
            if exposure["serial_string"]:
                print(f"    Serial: {exposure['serial_string']}")
            if exposure["protocol"]:
                print(f"    Protocol: 0x{exposure['protocol']:02X} ('Q')")
            if exposure["vendor_magic"]:
                print(f"    Vendor Magic: 0x{exposure['vendor_magic']:08X}")
        else:
            print("[!] Could not expose QSLCL (device may not support runtime changes)")
            if _DEBUG:
                print(f"    Debug info: {exposure}")

def print_loader_info(loader: QSLCLLoader):
    """Print detected loader modules"""
    print("\n[*] QSLCL Loader Modules Detected:")
    
    if loader.BIN:
        main = loader.BIN.get('main', {})
        print(f"  ├─ QSLCLBIN: {main.get('architecture', '?')} arch, {main.get('target_size', 0)} bytes")
    
    cmd_count = len([k for k in loader.CMD if isinstance(k, str) and k.isalpha()])
    if cmd_count:
        print(f"  ├─ QSLCLCMD: {cmd_count} commands")
    
    if loader.END:
        ep_count = len(loader.END)
        print(f"  ├─ QSLCLEND: {ep_count} endpoints")
        print(f"  │   Types: CTRL={sum(1 for e in loader.END.values() if isinstance(e, dict) and e.get('type')=='CTRL')}, "
              f"BULK={sum(1 for e in loader.END.values() if isinstance(e, dict) and e.get('type')=='BULK')}, "
              f"INT={sum(1 for e in loader.END.values() if isinstance(e, dict) and e.get('type')=='INT')}")
    
    if loader.BST:
        print(f"  ├─ QSLCLBST: {len(loader.BST)} architectures")
    
    if loader.DISP:
        print(f"  ├─ QSLCLDISP: {len(loader.DISP)} dispatch entries")
    
    if loader.RTF:
        print(f"  ├─ QSLCLRTF: {len(loader.RTF)} fault codes")
    
    if loader.ENC:
        enc = loader.ENC.get('encryption', {})
        feats = enc.get('features', {})
        print(f"  ├─ QSLCLENC: v{enc.get('version', '?')}")
        print(f"  │   ChaCha20={'✓' if feats.get('chacha20') else '✗'}, AES-GCM={'✓' if feats.get('aes256') else '✗'}")
    
    if loader.DAT:
        print(f"  ├─ QSLCLDAT: Data protocol v{loader.DAT.get('data_proto', {}).get('version', '?')}")
    
    if loader.SYN:
        syn = loader.SYN.get('sync', {})
        print(f"  ├─ QSLCLSYN: Sync block, {syn.get('frame_types', 0)} frame types")

    if loader.USB4:
        usb4 = loader.USB4.get('usb4_v2', {})
        if usb4:
            print(f"  ├─ USB4V2MC: USB4 v2.0 80Gbps microcode")
            print(f"  │   Version: {usb4.get('version', '?')}")
            print(f"  │   Max Bandwidth: {usb4.get('max_bandwidth', 0)} Mbps ({usb4.get('max_bandwidth', 0)//1000} Gbps)")
            tunnels = usb4.get('tunnels', {})
            tunnel_list = []
            if tunnels.get('pcie'): tunnel_list.append("PCIe")
            if tunnels.get('dp'): tunnel_list.append("DP")
            if tunnels.get('usb3'): tunnel_list.append("USB3")
            if tunnel_list:
                print(f"  │   Tunnels: {', '.join(tunnel_list)}")
            if usb4.get('has_security'):
                print(f"  │   Security: CMA + DPP + Attestation")

    if loader.HDR:
        print(f"  └─ QSLCLHDR: {len(loader.HDR)} certificate blocks")
    
    print()

# =============================================================================
# SECTOR SIZE DETECTION
# =============================================================================
VALID_SECTOR_SIZES = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072}

def detect_sector_size(dev: QSLCLDevice, force=False):
    global _DETECTED_SECTOR_SIZE
    if _DETECTED_SECTOR_SIZE and not force:
        return _DETECTED_SECTOR_SIZE
    
    # Try GETSECTOR
    if "GETSECTOR" in QSLCLCMD_DB:
        try:
            resp = qslcl_dispatch(dev, "GETSECTOR", b"", timeout=2.0)
            if resp and len(resp) >= 4:
                sz = int.from_bytes(resp[:4], 'little')
                if sz in VALID_SECTOR_SIZES:
                    _DETECTED_SECTOR_SIZE = sz
                    return sz
        except:
            pass
    
    # Default
    _DETECTED_SECTOR_SIZE = 4096
    return 4096

# =============================================================================
# PARTITION DETECTION
# =============================================================================
def load_partitions(dev: QSLCLDevice):
    global PARTITION_CACHE
    
    key = getattr(dev, 'serial', 'default')
    if key in PARTITION_CACHE:
        return PARTITION_CACHE[key]
    
    partitions = []
    sector_size = detect_sector_size(dev)
    
    # Try MBR
    try:
        payload = struct.pack("<QI", 0, sector_size)
        resp = qslcl_dispatch(dev, "READ", payload, timeout=2.0)
        if resp and len(resp) >= 512:
            if resp[510] == 0x55 and resp[511] == 0xAA:
                for i in range(4):
                    off = 446 + i * 16
                    entry = resp[off:off+16]
                    if entry[0] != 0:
                        start = int.from_bytes(entry[8:12], 'little') * sector_size
                        size = int.from_bytes(entry[12:16], 'little') * sector_size
                        type_names = {0x0C: "fat32", 0x83: "linux", 0x07: "ntfs", 0xEE: "gpt", 0xEF: "efi", 0x84: "hfs"}
                        name = type_names.get(entry[4], f"part_{i}")
                        if size > 0:
                            partitions.append({"name": name, "offset": start, "size": size})
    except:
        pass
    
    # Fallback
    if not partitions:
        partitions = [
            {"name": "boot", "offset": 0x880000, "size": 0x400000},
            {"name": "system", "offset": 0xC80000, "size": 0x8000000},
        ]
    
    PARTITION_CACHE[key] = partitions
    return partitions

# =============================================================================
# BUILT-IN COMMANDS (No external module needed)
# =============================================================================
def cmd_hello(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    
    resp = qslcl_dispatch(dev, "HELLO")
    if not resp:
        return print("[!] No response.")
    
    status = decode_runtime_result(resp)
    print(f"[*] HELLO: {status['severity']} - {status['name']}")
    print(f"[*] Commands: {len([k for k in QSLCLCMD_DB if isinstance(k, str) and k.isalpha()])}")
    print(f"[*] Bootstrap: {'Yes' if QSLCLBST_DB else 'No'}")
    print(f"[*] Encryption: {'Yes' if QSLCLENC_DB else 'No'}")
    print(f"[*] Data Protocol: {'Yes' if QSLCLDAT_DB else 'No'}")

def cmd_ping(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    
    payload = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)
    t0 = time.time()
    resp = qslcl_dispatch(dev, "PING", payload)
    dt = (time.time() - t0) * 1000
    
    if not resp:
        return print("[!] No response.")
    print(f"[*] RTT: {dt:.2f} ms")
    print(f"[*] Status: {decode_runtime_result(resp)['severity']}")

def cmd_getinfo(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    
    resp = qslcl_dispatch(dev, "GETINFO")
    if resp:
        status = decode_runtime_result(resp)
        print(f"[*] Runtime: {status}")
        if QSLCLBIN_DB:
            main = QSLCLBIN_DB.get('main', {})
            print(f"[*] Arch: {main.get('architecture', '?')}")
            print(f"[*] Size: {main.get('target_size', 0)} bytes")
    else:
        print("[!] No response.")

def cmd_partitions(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    parts = load_partitions(dev)
    for p in parts:
        print(f"  {p['name']:<12}  off=0x{p['offset']:08X}  size=0x{p['size']:08X}")

# =============================================================================
# MAIN
# =============================================================================
def main():
    class QSLCLHelp(argparse.HelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=36, width=140)

    p = argparse.ArgumentParser(
        description="QSLCL Tool v2.1.4 - Universal SOC Tool",
        formatter_class=QSLCLHelp
    )

    p.add_argument("--loader", help="Inject qslcl.bin before command")
    p.add_argument("--auth", action="store_true", help="Authenticate first")
    p.add_argument("--wait", type=int, default=0, help="Wait for device (seconds)")
    p.add_argument("--debug", action="store_true", help="Debug output")
    p.add_argument("--usb4", action="store_true", help="Enable USB4 v2.0 80Gbps mode") 
    p.add_argument("--dfu-boot", action="store_true", help="Auto-boot iOS device into DFU mode (like palera1n)")

    sub = p.add_subparsers(dest="cmd", metavar="")

    def new_cmd(name, **kwargs):
        sp = sub.add_parser(name, **kwargs, formatter_class=QSLCLHelp)
        sp.add_argument("--loader", help="Inject qslcl.bin")
        sp.add_argument("--auth", action="store_true")
        sp.add_argument("--wait", type=int, default=0)
        return sp

    # Core commands
    new_cmd("hello", help="Device handshake").set_defaults(func=cmd_hello)
    new_cmd("ping", help="Latency test").set_defaults(func=cmd_ping)
    new_cmd("getinfo", help="Device info").set_defaults(func=cmd_getinfo)
    new_cmd("partitions", help="List partitions").set_defaults(func=cmd_partitions)

    # READ
    r = new_cmd("read", help="Read from device")
    r.add_argument("target", help="Target (partition/address)")
    r.add_argument("arg2", nargs="?", help="Output file or size")
    r.add_argument("-o", "--output", help="Output file")
    r.add_argument("--size", type=lambda x: int(x, 0), help="Bytes to read")
    r.add_argument("--chunk-size", type=lambda x: int(x, 0), default=131072)
    r.add_argument("--resume", action="store_true", help="Resume interrupted read")
    r.set_defaults(func=cmd_read)

    # WRITE
    w = new_cmd("write", help="Write to device")
    w.add_argument("target", help="Target (partition/address)")
    w.add_argument("data", help="Data source (file/hex)")
    w.add_argument("--chunk-size", type=lambda x: int(x, 0), default=65536)
    w.add_argument("--no-verify", action="store_true", help="Skip verification")
    w.add_argument("--force", action="store_true", help="Skip safety checks")
    w.set_defaults(func=cmd_write)

    # ERASE
    e = new_cmd("erase", help="Erase region")
    e.add_argument("target", help="Target (partition/address)")
    e.add_argument("arg2", nargs="?", help="Size in bytes")
    e.add_argument("--size", type=lambda x: int(x, 0), help="Bytes to erase")
    e.add_argument("--force", action="store_true", help="Skip safety checks")
    e.set_defaults(func=cmd_erase)

    # PEEK / POKE
    pk = new_cmd("peek", help="Read memory")
    pk.add_argument("address", help="Memory address")
    pk.add_argument("-s", "--size", type=int, default=4, help="Bytes to read")
    pk.add_argument("-t", "--data-type", default='auto', help="Data type interpretation")
    pk.set_defaults(func=cmd_peek)

    po = new_cmd("poke", help="Write memory")
    po.add_argument("address", help="Memory address")
    po.add_argument("value", help="Value to write")
    po.add_argument("-t", "--data-type", default='auto', help="Data type")
    po.set_defaults(func=cmd_poke)

    # DUMP
    d = new_cmd("dump", help="Memory dump")
    d.add_argument("address", help="Address/partition")
    d.add_argument("size", nargs="?", help="Size to dump")
    d.add_argument("output", nargs="?", help="Output file")
    d.add_argument("--verify", action="store_true", help="SHA256 verification")
    d.add_argument("--compress", action="store_true", help="Gzip compress")
    d.add_argument("--resume", action="store_true", help="Resume interrupted dump")
    d.set_defaults(func=cmd_dump)

    # RAWMODE
    rw = new_cmd("rawmode", help="Raw mode access")
    rw.add_argument("subcmd", help="Subcommand")
    rw.add_argument("args", nargs="*", help="Arguments")
    rw.set_defaults(func=cmd_rawmode)

    # RESET
    rst = new_cmd("reset", help="System reset")
    rst.add_argument("subcmd", help="Reset type")
    rst.add_argument("args", nargs="*")
    rst.add_argument("--force-reset", action="store_true")
    rst.set_defaults(func=cmd_reset)

    # BRUTEFORCE
    bf = new_cmd("bruteforce", help="Brute-force attack")
    bf.add_argument("subcmd", nargs="?", help="Subcommand")
    bf.add_argument("pattern", nargs="?", help="Pattern")
    bf.add_argument("--threads", type=int, default=8)
    bf.add_argument("--output", help="Output file")
    bf.add_argument("args", nargs="*")
    bf.set_defaults(func=cmd_bruteforce)

    # CONFIG
    cfg = new_cmd("config", help="Configuration")
    cfg.add_argument("subcmd", help="Subcommand")
    cfg.add_argument("args", nargs="*")
    cfg.set_defaults(func=cmd_config)
    new_cmd("config-list", help="List config").set_defaults(func=cmd_config_list)

    # GLITCH
    gl = new_cmd("glitch", help="Glitch injection")
    gl.add_argument("subcmd", help="Subcommand")
    gl.add_argument("args", nargs="*")
    gl.add_argument("--level", type=int, help="Glitch level")
    gl.add_argument("--iter", type=int, help="Iterations")
    gl.set_defaults(func=cmd_glitch)

    # BYPASS
    bp = new_cmd("bypass", help="Security bypass")
    bp.add_argument("subcmd", help="Subcommand")
    bp.add_argument("args", nargs="*")
    bp.set_defaults(func=cmd_bypass)

    # MODE
    md = new_cmd("mode", help="Mode control")
    md.add_argument("subcmd", help="Subcommand")
    md.add_argument("args", nargs="*")
    md.set_defaults(func=cmd_mode)
    new_cmd("mode-status", help="Mode status").set_defaults(func=cmd_mode_status)

    # CRASH
    cr = new_cmd("crash", help="Crash simulation")
    cr.add_argument("subcmd", help="Subcommand")
    cr.add_argument("args", nargs="*")
    cr.set_defaults(func=cmd_crash)
    new_cmd("crash-test", help="Crash test").set_defaults(func=cmd_crash_test)

    # OEM / ODM
    oem = new_cmd("oem", help="OEM commands")
    oem.add_argument("subcmd", help="Subcommand")
    oem.add_argument("args", nargs="*")
    oem.set_defaults(func=cmd_oem)

    odm = new_cmd("odm", help="ODM commands")
    odm.add_argument("subcmd", help="Subcommand")
    odm.add_argument("args", nargs="*")
    odm.set_defaults(func=cmd_odm)

    # FOOTER
    ft = new_cmd("footer", help="Footer analysis")
    ft.add_argument("--type", dest="footer_type", default="STANDARD")
    ft.add_argument("--verbose", action="store_true")
    ft.add_argument("--json", action="store_true")
    ft.add_argument("args", nargs="*")
    ft.set_defaults(func=cmd_footer)

    # VOLTAGE / POWER / VERIFY / RAWSTATE / PATCH
    v = new_cmd("voltage", help="Voltage control")
    v.add_argument("subcmd", help="Subcommand")
    v.add_argument("args", nargs="*")
    v.set_defaults(func=cmd_voltage)

    pw = new_cmd("power", help="Power management")
    pw.add_argument("subcmd", help="Subcommand")
    pw.add_argument("args", nargs="*")
    pw.set_defaults(func=cmd_power)

    vf = new_cmd("verify", help="System verification")
    vf.add_argument("subcmd", help="Subcommand")
    vf.add_argument("args", nargs="*")
    vf.set_defaults(func=cmd_verify)

    rs = new_cmd("rawstate", help="Low-level state")
    rs.add_argument("subcmd", help="Subcommand")
    rs.add_argument("args", nargs="*")
    rs.set_defaults(func=cmd_rawstate)

    pt = new_cmd("patch", help="Binary patching")
    pt.add_argument("args", nargs="+", help="Target and patch data")
    pt.add_argument("--no-verify", action="store_true")
    pt.set_defaults(func=cmd_patch)

    args = p.parse_args()

    if args.debug:
        set_debug(True)

    if args.wait:
        print(f"[*] Waiting {args.wait}s for device...")
        dev = wait_for_device(timeout=args.wait)
        if not dev:
            print("[!] No device found.")
            return 1
    else:
        # Scan with auto-DFU if requested
        devs = scan_all(auto_dfu=args.dfu_boot)
        if not devs:
            print("[!] No device detected.")
            if args.dfu_boot:
                print("[*] Auto-DFU boot was attempted but no device was found.")
                print("[*] Make sure your iOS device is connected and unlocked.")
            return 1
        dev = devs[0]

    if args.dfu_boot and dev.vid == 0x05AC:
        # Check if in DFU mode
        is_dfu = False
        try:
            handle, _ = open_transport(dev)
            if handle:
                cfg = handle.get_active_configuration()
                for intf in cfg:
                    if intf.bInterfaceClass == 0xFE and intf.bInterfaceSubClass == 0x01:
                        is_dfu = True
                dev.close()
        except:
            pass
    
        if is_dfu:
            print("[*] Device is in DFU mode - ready for QSLCL!")
        else:
            print("[*] Device detected but not in DFU mode.")
            print("[*] Use --dfu-boot to enter DFU mode.")

    # Auto-load if specified
    if args.loader:
        auto_loader_if_needed(args, dev)

    if hasattr(args, "func"):
        try:
            result = args.func(args)
            if dev:
                dev.close()
            return result if result is not None else 0
        except Exception as e:
            print(f"[!] Command failed: {e}")
            if args.debug:
                traceback.print_exc()
            return 1
    else:
        p.print_help()

    return 0

if __name__ == "__main__":
    sys.exit(main())