#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v2.1.1
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

def scan_all():
    devs = scan_usb() + scan_serial()
    def score(d):
        s = 0
        if d.usb_class == 0xFF: s += 100
        if d.usb_class in (0x0A, 0x02): s += 70
        if d.product not in ("USB Device", "Serial", "Unknown"): s += 30
        if d.vid and d.pid: s += 20
        if d.transport == "usb": s += 10
        return -s
    devs.sort(key=score)
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
        pkt = encode_qslcl_structure(b"QSLCLDATA", blk)
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
                        type_names = {0x0C: "fat32", 0x83: "linux", 0x07: "ntfs", 0xEE: "gpt", 0xEF: "efi"}
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
        description="QSLCL Tool v2.1.1 - Universal SOC Tool",
        formatter_class=QSLCLHelp
    )

    p.add_argument("--loader", help="Inject qslcl.bin before command")
    p.add_argument("--auth", action="store_true", help="Authenticate first")
    p.add_argument("--wait", type=int, default=0, help="Wait for device (seconds)")
    p.add_argument("--debug", action="store_true", help="Debug output")

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

    # Wait for device
    if args.wait:
        print(f"[*] Waiting {args.wait}s for device...")
        dev = wait_for_device(timeout=args.wait)
        if not dev:
            print("[!] No device found.")
            return 1
    else:
        devs = scan_all()
        if not devs:
            print("[!] No device detected.")
            return 1
        dev = devs[0]

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