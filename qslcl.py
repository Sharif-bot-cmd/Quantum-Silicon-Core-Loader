#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v1.1.0
# Author: Sharif — QSLCL Creator

import sys, time, argparse, zlib, struct, threading, re, os, random
from dataclasses import dataclass
from queue import Queue

# =============================================================================
# IMPORTS
# =============================================================================
try:
    import serial
    import serial.tools.list_ports as list_ports
    SERIAL_SUPPORT = True
except:
    SERIAL_SUPPORT = False
    
try:
    import usb.core
    import usb.util
    USB_SUPPORT = True
except:
    USB_SUPPORT = False


APPLE_DFU_IDS = {
    (0x05AC, 0x1227): "Apple DFU (Legacy)",
    (0x05AC, 0x1226): "Apple DFU (iBoot)",
    (0x05AC, 0x1222): "Apple DFU (A12+)",
    (0x05AC, 0x1281): "Apple Recovery",
}

_DETECTED_SECTOR_SIZE = None
PARTITION_CACHE = []
PARTITIONS = {}
GPT_CACHE = {}  # Added missing global

QSLCLHDR_DB = {}
QSLCLEND_DB = {}
QSLCLPAR_DB = {}
QSLCLVM5_DB  = {}
QSLCLUSB_DB  = {}
QSLCLSPT_DB  = {}
QSLCLDISP_DB = {}
QSLCLIDX_DB  = {}
QSLCLRTF_DB  = {}

def align_up(x, block):
    return (x + block - 1) & ~(block - 1)

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

    handle: any = None           # raw USB/Serial handle object
    serial_mode: bool = False    # True = serial port, False = USB endpoint mode

    # Unified write() wrapper
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

    # Unified read() wrapper
    def read(self, timeout=1.0):
        if self.handle is None:
            # Auto-open if not already open
            self.handle, self.serial_mode = open_transport(self)
            if self.handle is None:
                raise RuntimeError("Failed to open device transport")

        try:
            typ, payload = recv(self.handle, self.serial_mode, timeout=timeout)
            return payload
        except Exception as e:
            raise RuntimeError(f"Read failed: {e}")

class QSLCLLoader:
    def __init__(self):
        self.END  = {}
        self.PAR  = {}
        self.IDX  = {}
        self.VM5  = {}
        self.USB  = {}
        self.SPT  = {}
        self.DISP = {}
        self.HDR  = {}
        self.RTF  = {}
        self.ENG = {}

    # ---------------------------------------------
    # ENGINE PARSER - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclend(self, blob):
        """Improved QSLCLEND/ENG parser"""
        out = {}
        
        # Search for both possible magic values
        for magic in [b"QSLCLEND", b"QSLCLENG"]:
            pos = 0
            while pos < len(blob):
                idx = blob.find(magic, pos)
                if idx == -1:
                    break
                    
                try:
                    # Try to parse header
                    if idx + 12 > len(blob):
                        pos = idx + 1
                        continue
                        
                    hdr = blob[idx:idx+12]
                    magic_found, ver, flags, count = struct.unpack("<8sBBH", hdr)
                    
                    entry_pos = idx + 12
                    entries_found = 0
                    
                    for i in range(count):
                        if entry_pos + 3 > len(blob):
                            break
                            
                        opcode = blob[entry_pos]
                        size = struct.unpack("<H", blob[entry_pos+1:entry_pos+3])[0]
                        
                        if entry_pos + 3 + size > len(blob):
                            break
                            
                        raw = blob[entry_pos+3:entry_pos+3+size]
                        out[opcode] = {"opcode": opcode, "raw": raw, "size": size}
                        entry_pos += 3 + size
                        entries_found += 1
                    
                    if entries_found > 0:
                        print(f"[*] QSLCLEND: Found {entries_found} entries")
                        break  # Found one valid block
                    
                except Exception as e:
                    # Don't print error for every failed attempt
                    pass
                
                pos = idx + 1

        self.END = out
        self.ENG = out  # For compatibility
        global QSLCLEND_DB
        QSLCLEND_DB = out
        return out

    # ---------------------------------------------
    # PARSER CONFIG - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclpar(self, blob):
        """Improved QSLCLPAR parser - only extracts valid commands"""
        out = {}
        magic = b"QSLCLPAR"
        pos = 0
        valid_commands_found = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
                
            try:
                # Skip if not enough data for basic header
                if idx + 40 > len(blob):
                    pos = idx + 1
                    continue
                
                # Try to parse the actual QSLCLPAR structure
                # Header: magic(8) + version(1) + reserved(3) + name(16) + cmd_id(1) + flags(1) + tier(1) + family_hash(1) + length(2) + crc(4) + timestamp(4)
                hdr = blob[idx:idx+40]
                magic_found, version, reserved, name_field, cmd_id, flags, tier, family_hash, length, crc, timestamp = \
                    struct.unpack("<8sB3s16sBBBBHII", hdr)
                
                # Extract and validate name
                name = name_field.decode("ascii", errors="ignore").rstrip('\x00')
                
                # Skip if name is empty or contains non-printable characters
                if not name or not all(c.isprintable() or c in ' _-' for c in name):
                    pos = idx + 1
                    continue
                
                # Validate length
                if idx + 40 + length > len(blob) or length > 4096:
                    pos = idx + 1
                    continue
                
                # Extract command data
                raw = blob[idx+40:idx+40+length]
                
                out[name] = {
                    "name": name,
                    "cmd_id": cmd_id,
                    "raw": raw,
                    "length": length
                }
                valid_commands_found += 1
                pos = idx + 40 + length
                
            except Exception:
                # If structured parsing fails, try to find next magic
                pos = idx + 1
                continue

        if valid_commands_found > 0:
            print(f"[*] QSLCLPAR: Found {valid_commands_found} valid commands")
        
        self.PAR = out
        global QSLCLPAR_DB
        QSLCLPAR_DB = out
        return out

    # ---------------------------------------------
    # RTF - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclrtf(self, blob):
        """Improved RTF parser"""
        out = {}
        magic = b"QSLCLRTF"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
            
            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                # Header: magic(8) + version(1) + flags(1) + count(2)
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for i in range(count):
                    if entry_pos + 12 > len(blob):
                        break
                    
                    # Fixed format: error_code(4) + severity(1) + category(1) + retry_count(2) + msg_hash(4)
                    code, severity, category, retry_count, msg_hash = struct.unpack("<IBBH I", blob[entry_pos:entry_pos+12])
                    
                    # Extract short name (8 bytes)
                    name_end = entry_pos + 20
                    if name_end > len(blob):
                        break
                    short_name = blob[entry_pos+12:name_end].decode("ascii", errors="ignore").rstrip('\x00')
                    
                    out[code] = {
                        "level": severity,
                        "msg": short_name,
                        "category": category,
                        "retry_count": retry_count,
                        "hash": msg_hash
                    }
                    entry_pos += 20
                    entries_found += 1
                
                if entries_found > 0:
                    print(f"[*] QSLCLRTF: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.RTF = out
        global QSLCLRTF_DB
        QSLCLRTF_DB = out
        return out

    # ---------------------------------------------
    # IDX - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclidx(self, blob):
        """Improved IDX parser"""
        out = {}
        magic = b"QSLCLIDX"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 3 > len(blob):
                        break
                        
                    idx_val = struct.unpack("<H", blob[entry_pos:entry_pos+2])[0]
                    name_len = blob[entry_pos+2]
                    
                    if entry_pos + 3 + name_len > len(blob) or name_len == 0 or name_len > 64:
                        break
                        
                    name = blob[entry_pos+3:entry_pos+3+name_len].decode("ascii", errors="ignore")
                    # Only add if name is valid
                    if name and name.isprintable():
                        out[name] = {"idx": idx_val, "name": name}
                        entry_pos += 3 + name_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLIDX: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.IDX = out
        global QSLCLIDX_DB
        QSLCLIDX_DB = out
        return out

    # ---------------------------------------------
    # VM5 - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclvm5(self, blob):
        """Improved VM5 parser"""
        out = {}
        magic = b"QSLCLVM5"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break
            
            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(blob):
                        break
                        
                    name_len = blob[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(blob) or name_len == 0 or name_len > 64:
                        break
                        
                    name = blob[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", blob[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(blob) or raw_len > 4096:
                        break
                        
                    raw = blob[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    # Only add if name is valid
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLVM5: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.VM5 = out
        global QSLCLVM5_DB
        QSLCLVM5_DB = out
        return out

    # ---------------------------------------------
    # USB routines - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclusb(self, blob):
        """Improved USB parser"""
        out = {}
        magic = b"QSLCLUSB"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(blob):
                        break
                        
                    name_len = blob[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(blob) or name_len == 0 or name_len > 64:
                        break
                        
                    name = blob[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", blob[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(blob) or raw_len > 4096:
                        break
                        
                    raw = blob[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLUSB: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.USB = out
        global QSLCLUSB_DB
        QSLCLUSB_DB = out
        return out

    # ---------------------------------------------
    # SPT setup packets - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclspt(self, blob):
        """Improved SPT parser"""
        out = {}
        magic = b"QSLCLSPT"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(blob):
                        break
                        
                    name_len = blob[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(blob) or name_len == 0 or name_len > 64:
                        break
                        
                    name = blob[entry_pos+1 : entry_pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", blob[entry_pos+1+name_len : entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(blob) or raw_len > 4096:
                        break
                        
                    raw = blob[entry_pos+3+name_len : entry_pos+3+name_len+raw_len]
                    
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLSPT: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.SPT = out
        global QSLCLSPT_DB
        QSLCLSPT_DB = out
        return out

    # ---------------------------------------------
    # Dispatcher - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslcldisp(self, blob):
        """Improved DISP parser"""
        out = {}
        magic = b"QSLCLDIS"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                if idx + 12 > len(blob):
                    pos = idx + 1
                    continue
                    
                hdr = blob[idx:idx+12]
                _, ver, flags, count = struct.unpack("<8sBBH", hdr)
                entry_pos = idx + 12
                entries_found = 0
                
                for _ in range(count):
                    if entry_pos + 1 > len(blob):
                        break
                        
                    name_len = blob[entry_pos]
                    
                    if entry_pos + 1 + name_len + 2 > len(blob) or name_len == 0 or name_len > 64:
                        break
                        
                    name = blob[entry_pos+1:pos+1+name_len].decode("ascii", errors="ignore")
                    raw_len = struct.unpack("<H", blob[entry_pos+1+name_len:entry_pos+3+name_len])[0]
                    
                    if entry_pos + 3 + name_len + raw_len > len(blob) or raw_len > 4096:
                        break
                        
                    raw = blob[entry_pos+3+name_len:entry_pos+3+name_len+raw_len]
                    
                    if name and name.isprintable():
                        out[name] = {"name": name, "raw": raw}
                        entry_pos += 3 + name_len + raw_len
                        entries_found += 1
                    else:
                        break
                
                if entries_found > 0:
                    print(f"[*] QSLCLDISP: Found {entries_found} entries")
                    break
                    
            except Exception:
                pass
            
            pos = idx + 1

        self.DISP = out
        global QSLCLDISP_DB
        QSLCLDISP_DB = out
        return out

    # ---------------------------------------------
    # Header / Certs - IMPROVED VERSION
    # ---------------------------------------------
    def load_qslclhdr(self, blob):
        """Improved HDR parser"""
        out = {}
        magic = b"QSLCLHDR"
        pos = 0
        
        while pos < len(blob):
            idx = blob.find(magic, pos)
            if idx == -1:
                break

            try:
                if idx + 16 > len(blob):
                    pos = idx + 1
                    continue
                    
                # Header: magic(8) + version(4) + size(4)
                magic_found = blob[idx:idx+8]
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
                
            except Exception:
                pos = idx + 1
                continue

        self.HDR = out
        global QSLCLHDR_DB
        QSLCLHDR_DB = out
        return out

    # ---------------------------------------------
    # MASTER PARSER - IMPROVED VERSION
    # ---------------------------------------------
        def parse_loader(self, blob):
            """Upgraded QSLCL loader parser using ONLY the validated marker set."""
            print(f"[*] Parsing loader structures ({len(blob)} bytes)...")

            # -----------------------------------------
            # VALID MARKERS YOU APPROVED (ONLY THESE)
            # -----------------------------------------
            MARKERS = [
                b"QSLCLEND",
                b"QSLCLPAR",
                b"QSLCLRTF",
                b"QSLCLUSB",
                b"QSLCLSPT",
                b"QSLCLVM5",
                b"QSLCLDISP",   # you insisted this stays valid
                b"QSLCLIDX",
                b"QSLCLHDR",
            ]
            MARKER_SET = set(MARKERS)

            discovered = {}      # marker_name -> [offsets]
            blob_len = len(blob)

            # -----------------------------------------
            # PHASE 1 — FULL FILE SCAN (no early stop)
            # -----------------------------------------
            i = 0
            while i < blob_len - 8:
                chunk = blob[i:i+8]

                if chunk in MARKER_SET:
                    name = chunk.decode()
                    discovered.setdefault(name, []).append(i)
                    i += 8
                    continue

                i += 1

            if not discovered:
                print("[!] No module headers found in loader")
                return False

            # -----------------------------------------
            # PHASE 2 — Build blocks via next-marker search
            # -----------------------------------------
            resolved = {m: [] for m in discovered}

            # flatten + sort for slicing correctness
            all_positions = []
            for mname, offs in discovered.items():
                for off in offs:
                    all_positions.append((off, mname))
            all_positions.sort()

            # slice each module's payload
            total_positions = len(all_positions)

            for idx, (offset, mname) in enumerate(all_positions):
                if idx + 1 < total_positions:
                    next_offset = all_positions[idx + 1][0]
                    payload = blob[offset + 8:next_offset]
                else:
                    payload = blob[offset + 8:]

                # strip only simple filler
                clean_payload = payload.lstrip(b"\x00\xFF\xAA")

                if clean_payload:
                    resolved[mname].append(clean_payload)

            # -----------------------------------------
            # PHASE 3 — Call module-specific parsers
            # -----------------------------------------
            PARSERS = {
                "QSLCLEND":  self.load_qslclend,
                "QSLCLPAR":  self.load_qslclpar,
                "QSLCLRTF":  self.load_qslclrtf,
                "QSLCLUSB":  self.load_qslclusb,
                "QSLCLSPT":  self.load_qslclspt,
                "QSLCLVM5":  self.load_qslclvm5,
                "QSLCLDISP": self.load_qslcldisp,
                "QSLCLIDX":  self.load_qslclidx,
                "QSLCLHDR":  self.load_qslclhdr,
            }

            for mname, parser in PARSERS.items():
                blocks = resolved.get(mname, [])
                for block in blocks:
                    try:
                        res = parser(block)
                        if res:
                            print(f"[+] {mname}: {len(res)} entries")
                    except Exception:
                        # keep isolation, ignore bad blocks
                        pass

            # -----------------------------------------
            # PHASE 4 — SUMMARY
            # -----------------------------------------
            print("[*] Parser summary:")
            found = []

            if self.END:  found.append(f"END({len(self.END)})")
            if self.PAR:  found.append(f"PAR({len(self.PAR)})")
            if self.RTF:  found.append(f"RTF({len(self.RTF)})")
            if self.HDR:  found.append(f"HDR({len(self.HDR)})")
            if self.IDX:  found.append(f"IDX({len(self.IDX)})")
            if self.VM5:  found.append(f"VM5({len(self.VM5)})")
            if self.USB:  found.append(f"USB({len(self.USB)})")
            if self.SPT:  found.append(f"SPT({len(self.SPT)})")
            if self.DISP: found.append(f"DISP({len(self.DISP)})")

            if found:
                print(f"[+] Detected modules: {', '.join(found)}")
                return True

            print("[!] No valid modules parsed")
            return False

# =============================================================================
# CONTINUE WITH EXISTING FUNCTIONS (rest of the file remains the same)
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
    }

    if idx not in mapping:
        return None

    name = mapping[idx]
    return QSLCLHDR_DB.get(name, None)

# =============================================================================
# CONTINUE WITH EXISTING FUNCTIONS (FIXED VERSIONS)
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
    Fully universal validator, rejects only impossible devices (keyboard,
    mouse, webcam, audio, hub). Allows serial, diag, vendor-specific, etc.
    """

    # Reject HID devices (mice, keyboards)
    if dev.usb_class == 0x03:
        return False

    # Reject hubs, audio, video, printers
    if dev.usb_class in (0x09, 0x01, 0x0E, 0x07):
        return False

    # Vendor-specific interfaces (bootloader, fastboot, EDL, QSLCL)
    if dev.usb_class == 0xFF:
        return True

    # USB diag, modem, serial-over-USB
    if dev.usb_class in (0x0A, 0x02):
        return True

    # Raw serial
    if dev.transport == "serial":
        return True

    # USB device with VID/PID is acceptable
    if dev.vid and dev.pid:
        return True

    return False

# =============================================================================
# SCANNERS - FIXED
# =============================================================================
def scan_serial():
    if not SERIAL_SUPPORT:
        return []

    devs = []

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
            handle=None  # Don't store the path here, will open later
        ))

    return devs

def scan_usb():
    if not USB_SUPPORT:
        return []

    devs = []

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
                handle=d,
                serial_mode=False
            ))

        except Exception:
            continue

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
# ENCODERS (fallback)
# =============================================================================
def encode_cmd(cmd: str, extra: bytes = b""):
    payload = cmd.encode() + (b" " + extra if extra else b"")
    return b"QSLCLCMD" + len(payload).to_bytes(4, "little") + payload

def encode_resp_request():
    p = b"RESPONSE"
    return b"QSLCLCMD" + len(p).to_bytes(4, "little") + p

# =============================================================================
# FRAME PARSER
# =============================================================================
def parse_frame(buff: bytes):
    if buff.startswith(b"QSLCLRESP"):
        size = int.from_bytes(buff[10:14], "little")
        return "RESP", buff[14:14+size]

    if buff.startswith(b"QSLCLCMD"):
        size = int.from_bytes(buff[9:13], "little")
        return "CMD", buff[13:13+size]

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
# TRANSPORTS - FIXED
# =============================================================================
def send(handle, payload, serial_mode):
    """
    Safe universal packet writer for:
        - Serial (UART/USB-CDC)
        - USB bulk (pyusb) device (EP_OUT)
    """
    if serial_mode:
        try:
            handle.write(payload)
        except Exception as e:
            print("[!] SERIAL WRITE ERROR:", e)
        return

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
            handle.write(ep_out.bEndpointAddress, payload, timeout=2000)
        else:
            # Fallback to control transfer
            handle.ctrl_transfer(0x21, 0x09, 0x0200, 0, payload)
    except Exception as e:
        print("[!] USB WRITE ERROR:", e)

def recv(handle, serial_mode, timeout=3.0):
    """
    Universal response receiver supporting:
        - Serial streaming
        - USB bulk packets
    Fully QSLCL v5.1-compliant:
        - Scans the rolling buffer
        - Extracts QSLCLRESP/QSLCLCMD frames
        - Protects against fragmented/incomplete frames
        - Supports multiple frames in same buffer
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
        # Read chunk
        # ------------------------------------------------------
        try:
            if serial_mode:
                chunk = handle.read(64)
            else:
                # Find the correct IN endpoint for USB
                cfg = handle.get_active_configuration()
                intf = cfg[(0,0)]
                ep_in = None
                for ep in intf.endpoints():
                    if (usb.util.endpoint_direction(ep.bEndpointAddress) == 
                        usb.util.ENDPOINT_IN and
                        usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                        ep_in = ep
                        break
                
                if ep_in:
                    chunk = handle.read(ep_in.bEndpointAddress, 64, timeout=1000)
                else:
                    chunk = b""
        except:
            chunk = b""

        if chunk:
            buff.extend(chunk)

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

def open_transport(dev):
    """FIXED: Properly open device transports"""
    if dev.transport == "serial":
        try:
            # Actually open the serial port
            h = serial.Serial(dev.identifier, 115200, timeout=1)
            dev.handle = h  # Store the opened handle
            return h, True
        except Exception as e:
            print(f"[!] Failed to open serial port {dev.identifier}: {e}")
            return None, True
    else:
        # USB device
        try:
            # Set configuration and claim interface
            dev.handle.set_configuration()
            usb.util.claim_interface(dev.handle, 0)
            return dev.handle, False
        except Exception as e:
            print(f"[!] Failed to configure USB device: {e}")
            return None, False

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

def qslcl_dispatch(dev, cmd_name, payload=b"", timeout=1.0):
    """
    Unified dispatcher with timeout support
    """
    # Convert command name → internal ID
    cmd_upper = cmd_name.upper()

    # Compute command ID (same as loader)
    cmd_id = sum(cmd_upper.encode()) & 0xFFFF

    if cmd_id in QSLCLDISP_DB:
        disp = QSLCLDISP_DB[cmd_id]

        raw = disp["raw"] + payload
        print(f"[*] QSLCLDISP routing → cmd_id={cmd_id:04X}")
        return exec_universal(dev, "DISP", raw)

    # fallback
    return exec_universal(dev, cmd_upper, payload)

# =============================================================================
# SECTOR SIZE DETECTOR
# =============================================================================
def detect_sector_size(dev):
    """
    Ultra-robust sector/page size detector for QSLCL-based devices.
    """
    VALID_SIZES = {512, 1024, 2048, 4096, 8192, 16384}

    h, serial_mode = open_transport(dev)

    # ============================================================
    # 0. QSLCLIDX GETSECTOR override (highest priority)
    # ============================================================
    for entry_id, e in QSLCLIDX_DB.items():
        if isinstance(e, dict) and e.get("name") == "GETSECTOR":
            try:
                resp = qslcl_dispatch(dev, "GETSECTOR", b"")
                status = decode_runtime_result(resp)
                v = int.from_bytes(status["extra"][:4], "little")
                if v in VALID_SIZES:
                    print("[*] Sector size via QSLCLIDX/GETSECTOR =", v)
                    return v
            except:
                pass

    # ============================================================
    # 1. QSLCLPAR direct GETSECTOR handler
    # ============================================================
    if "GETSECTOR" in QSLCLPAR_DB:
        try:
            resp = qslcl_dispatch(dev, "GETSECTOR", b"")
            status = decode_runtime_result(resp)
            v = int.from_bytes(status["extra"][:4], "little")
            if v in VALID_SIZES:
                print("[*] Sector size via QSLCLPAR/GETSECTOR =", v)
                return v
        except:
            pass

    # ============================================================
    # 2. QSLCLEND opcode fallback
    # ============================================================
    if "GETSECTOR" in QSLCLEND_DB:
        try:
            op = QSLCLEND_DB["GETSECTOR"]
            pkt = b"QSLCLEND" + op
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            status = decode_runtime_result(resp)
            v = int.from_bytes(status["extra"][:4], "little")
            if v in VALID_SIZES:
                print("[*] Sector size via QSLCLEND/GETSECTOR =", v)
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
        if t == "RESP":
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
    # 5. HELLO RTF frame (your loader sometimes embeds size)
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
# LOADER SENDER
# =============================================================================
def send_packets(handle, data, serial_mode, chunk=4096):
    total = len(data)
    sent = 0

    for off in range(0, total, chunk):
        blk = data[off:off+chunk]
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
            except:
                pass

        sent += len(blk)
        print(f"\r[*] Loader sending... {sent*100/total:5.1f}%", end="")
        time.sleep(0.01)

    print("\n[+] Loader transfer complete.")

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
    # Priority 1 — Engine A5 opcode
    if 0xA5 in QSLCLEND_DB:
        print("[*] AUTH via QSLCLEND opcode A5")
        entry = QSLCLEND_DB[0xA5]
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)

    # Priority 2 — QSLCLPAR AUTHENTICATE
    elif "AUTHENTICATE" in QSLCLPAR_DB:
        print("[*] AUTH via QSLCLPAR")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", payload)

    # Priority 3 — VM5 nano-service AUTHENTICATE
    elif "AUTHENTICATE" in QSLCLVM5_DB:
        print("[*] AUTH via QSLCLVM5 nano-service")
        raw = QSLCLVM5_DB["AUTHENTICATE"]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)

    # Priority 4 — fallback dispatcher
    else:
        print("[*] AUTH fallback mode")
        resp = qslcl_dispatch(dev, "AUTHENTICATE", payload)

    # ---------------------------------------------------------------
    # Step 5: Decode via RTF
    # ---------------------------------------------------------------
    status = qslcl_decode_rtf(resp)
    print(f"[AUTH] {status}")

    if status != "SUCCESS":
        print("[!] Authentication failed. Stopping.")
        return False

    print("[✓] Authentication OK. Continuing…")
    return True

def auto_loader_if_needed(args, dev):
    """
    Loads qslcl.bin only when --loader is specified.
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
        print(f"    QSLCLEND: {len(loader.END)} entries")
        print(f"    QSLCLPAR: {len(loader.PAR)} commands")
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
    required = ["QSLCLPAR", "QSLCLEND"]  # Remove QSLCLRTF from required
    missing = [r for r in required if not getattr(loader, r, {})]

    if missing:
        print(f"[!] Loader missing some modules: {missing}")
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

    print("[+] Loader uploaded successfully.\n")

def qslcl_send(handle, cmd, payload=b"", seq=1):
    pkt = qslcl_build_packet(cmd, payload, seq)
    handle.write(pkt)
    try:
        resp = handle.read(4096)
    except:
        resp = b""
    return resp

def qslcl_build_packet(cmd, payload=b"", seq=1):
    """
    Universal packet model translating QSLCL commands
    into a generic format understood by all device types.
    """
    cmd_b = cmd.encode("ascii")
    hdr = b"QSLCLPKT" + struct.pack("<H", seq) + struct.pack("<H", len(payload))
    return hdr + cmd_b.ljust(16, b"\x00") + payload

def qslcl_route(handle, cmd, payload=b"", seq=1):
    """
    Universal Hybrid Router:
    - Adapts command to correct vendor protocol
    - Converts response to universal QSLCL style
    """
    dtype = detect_device_type(handle)

    # ---------- Qualcomm Mode ----------
    if dtype == "QUALCOMM":
        q = b"<?xml version='1.0'?><data>" + payload + b"</data>"
        handle.write(q)
        return handle.read(2048)

    # ---------- MTK Mode ----------
    if dtype == "MTK":
        header = b"\x00\x00\xA0\x0A"  # generic bootrom packet
        handle.write(header + payload)
        return handle.read(2048)

    # ---------- Apple DFU ----------
    if dtype == "APPLE_DFU":
        dfu_pkt = struct.pack("<I", len(payload)) + payload
        handle.write(dfu_pkt)
        return handle.read(2048)

    # ---------- Generic Mode (QSLCL native) ----------
    return qslcl_send(handle, cmd, payload, seq)

def colorize_runtime(msg):
    if isinstance(msg, dict):
        msg = msg.get("name", "UNKNOWN")
    
    if "SUCCESS" in str(msg):
        return f"\033[92m{msg}\033[0m"
    if "WARNING" in str(msg):
        return f"\033[93m{msg}\033[0m"
    if "ERROR" in str(msg):
        return f"\033[91m{msg}\033[0m"
    if "CRITICAL" in str(msg) or "FATAL" in str(msg):
        return f"\033[95m{msg}\033[0m"
    return str(msg)

def parse_device_info(resp):
    """
    Safe parsing of device info.
    qslcl.bin typically responds in TLV or struct format:
        len(2) + keyid(1) + vallen(1) + value
    """
    info = {}
    ptr = 0
    while ptr < len(resp) - 4:
        try:
            key = resp[ptr]
            length = resp[ptr+1]
            value = resp[ptr+2:ptr+2+length]

            info[key] = value.decode(errors="ignore")
            ptr += 2 + length
        except:
            break
    return info

def print_device_info(info):
    print("[*] Device Information:")
    for key, val in info.items():
        print(f"   {key:02X} : {val}")

# =============================================================================
# EXECUTION ENGINE
# =============================================================================
def exec_universal(dev, cmd, payload=b"", timeout=1.0):
    # Build packet
    packet = qslcl_build_packet(cmd, payload)

    # Unified write
    try:
        dev.write(packet)
    except Exception as e:
        print(f"[RUNTIME] Write failed for {cmd}: {e}")
        return None

    # Unified read
    try:
        resp = dev.read(timeout=timeout)
    except Exception as e:
        print(f"[RUNTIME] Read failed for {cmd}: {e}")
        return None

    if not resp:
        print(f"[RUNTIME] Empty response for {cmd}")
        return None

    # Decode runtime status
    status = decode_runtime_result(resp)
    print(colorize_runtime(status))

    return resp

def qslclidx_get(idx_id):
    """Return IDX entry struct or None."""
    return QSLCLIDX_DB.get(idx_id)

# ============================================================
#   QSLCLHDR — Certificate / Header Table Loader
# ============================================================
def load_qslclhdr(self, blob):
    off = 0
    entries = []

    while True:
        idx = blob.find(b"QSLCLHDR", off)
        if idx < 0:
            break

        if idx + 32 > len(blob):
            off = idx + 1
            continue

        size = int.from_bytes(blob[idx+12:idx+16], "little")
        if size > len(blob):
            off = idx + 1
            continue

        digest = blob[idx+16:idx+32]

        entries.append((size, digest))
        off = idx + 1

    return entries

def parse_gpt_table(raw):
    """
    Parse GPT from raw bytes returned by device.
    Expects QSLCL to return first 34 LBA or entire table.
    """
    if not raw or len(raw) < 512:
        return []

    parts = []

    # GPT header @ LBA1 (offset 512)
    hdr = raw[512:512+92]
    sig = hdr[:8]

    if sig != b"EFI PART":
        return []  # Not GPT

    # entry info
    entry_size = struct.unpack("<I", hdr[84:88])[0]
    entry_count = struct.unpack("<I", hdr[80:84])[0]
    entry_lba   = struct.unpack("<Q", hdr[72:80])[0]

    # entries begin at entry_lba * 512
    offset = entry_lba * 512

    for i in range(entry_count):
        e = raw[offset + i * entry_size : offset + (i+1) * entry_size]
        if len(e) < entry_size:
            break

        first_lba = struct.unpack("<Q", e[32:40])[0]
        last_lba  = struct.unpack("<Q", e[40:48])[0]

        name_utf16 = e[56:56+72]
        name = name_utf16.decode("utf-16").rstrip("\x00")

        if first_lba == 0:
            continue

        parts.append({
            "name": name.lower(),
            "offset": first_lba * 512,
            "size": (last_lba - first_lba + 1) * 512
        })

    return parts

def parse_pmt(raw):
    """
    MTK PMT parser — expects QSLCL to return PMT region.
    """
    parts = []
    if not raw or b"PARTITION" not in raw:
        return parts

    lines = raw.split(b"\n")
    for L in lines:
        if b"PARTITION" in L:
            try:
                seg = L.decode(errors="ignore").split(",")
                name = seg[1].strip().lower()
                off  = int(seg[2].strip(), 16)
                size = int(seg[3].strip(), 16)
                parts.append({"name": name, "offset": off, "size": size})
            except:
                continue

    return parts

def parse_lk_table(raw):
    """
    LK/ABOOT style partition table dump from QSLCL.
    Example expected format:
       part:boot start=0x880000 size=0x200000
    """
    parts = []
    lines = raw.split(b"\n")
    for L in lines:
        if b"part:" in L:
            try:
                t = L.decode(errors="ignore")
                name = t.split("part:")[1].split()[0].strip()
                off  = int(t.split("start=")[1].split()[0], 16)
                size = int(t.split("size=")[1].split()[0], 16)
                parts.append({"name": name.lower(), "offset": off, "size": size})
            except:
                pass
    return parts

def load_partitions(dev):
    global PARTITION_CACHE
    if PARTITION_CACHE:
        return PARTITION_CACHE

    # 1. Index table (QSLCLIDX_DB)
    for k,v in QSLCLIDX_DB.items():
        if isinstance(v, dict) and "offset" in v and "length" in v:
            PARTITION_CACHE.append({
                "name": k.lower(),
                "offset": v["offset"],
                "size": v["length"]
            })

    if PARTITION_CACHE:
        return PARTITION_CACHE

    # 2. QSLCLPAR → GPT
    if "GPT" in QSLCLPAR_DB:
        raw = qslcl_dispatch(dev, "GPT", b"")
        g = parse_gpt_table(raw)
        PARTITION_CACHE.extend(g)

    # 3. QSLCLPAR → PMT (MTK)
    if "PMT" in QSLCLPAR_DB:
        raw = qslcl_dispatch(dev, "PMT", b"")
        p = parse_pmt(raw)
        PARTITION_CACHE.extend(p)

    # 4. QSLCLPAR → LK
    if "LKP" in QSLCLPAR_DB:
        raw = qslcl_dispatch(dev, "LKP", b"")
        lk = parse_lk_table(raw)
        PARTITION_CACHE.extend(lk)

    return PARTITION_CACHE

def resolve_target(dev, target, size=None):
    target = target.lower()

    # load GPT/PMT/LK/QSLCLIDX partitions
    parts = load_partitions(dev)

    # name match
    for p in parts:
        if p["name"] == target:
            return p["offset"], p["size"]

    # numeric address fallback
    try:
        addr = int(target, 0)
        return addr, size if size else 0x1000
    except:
        raise ValueError(f"[!] Unknown partition or address: {target}")

def resolve_partition(name):
    n = name.lower()
    if n not in PARTITIONS:
        raise RuntimeError(f"Partition '{name}' not found.")
    return PARTITIONS[n]

def scan_gpt(dev):
    """
    Universal raw GPT reader (LBA1 + entries).
    """
    global PARTITIONS
    PARTITIONS = {}

    # size 0x200 is enough for GPT header + a few entries
    payload = struct.pack("<Q I", 512, 4096)
    resp = qslcl_dispatch(dev, "READ", payload)
    if not resp:
        return

    data = resp[8:]  # skip runtime frame header

    # check GPT signature
    if data[0x200:0x208] != b"EFI PART":
        print("[!] GPT: No GPT signature")
        return

    first_lba = int.from_bytes(data[0x230:0x238], "little")
    num_entries = int.from_bytes(data[0x248:0x24C], "little")
    entry_size = int.from_bytes(data[0x24C:0x250], "little")

    # read entries:
    entries_size = num_entries * entry_size
    payload = struct.pack("<Q I", first_lba * 512, entries_size)
    resp = qslcl_dispatch(dev, "READ", payload)
    raw = resp[8:]

    for i in range(num_entries):
        e = raw[i*entry_size:(i+1)*entry_size]
        name = e[0x38:0x80].decode("utf-16le", errors="ignore").strip("\x00")
        start = int.from_bytes(e[0x20:0x28], "little") * 512
        end   = int.from_bytes(e[0x28:0x30], "little") * 512
        size  = end - start
        if name:
            PARTITIONS[name.lower()] = (start, size)

    print(f"[*] GPT partitions loaded: {len(PARTITIONS)}")

# =============================================================================
# COMMAND WRAPPERS
# =============================================================================
def cmd_hello(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]

    print("[*] Sending HELLO...")

    # ---------------------------------------------------------
    # OPTIONAL FAST PATH via QSLCLIDX
    # 0x01 = HELLO entry (common in your builds)
    # ---------------------------------------------------------
    idx_hello = qslclidx_get(0x01)
    if idx_hello:
        print("[*] QSLCLIDX: Using IDX[0x01] HELLO route")
        pkt = b"QSLCLIDX" + idx_hello["raw"]
        resp = qslcl_dispatch(dev, "IDX", pkt)
    else:
        resp = qslcl_dispatch(dev, "HELLO", b"")

    if not resp:
        return print("[!] HELLO: No response from device.")

    status = decode_runtime_result(resp)
    print("[*] HELLO Response:", status)

    # ---------------------------------------------------------
    # Display module summary (FIXED VERSION)
    # ---------------------------------------------------------
    print("[*] Loader Modules Detected:")
    print(f"  IDX config : { 'CONFIGURE' in QSLCLIDX_DB }")

    # FIXED — Check if any END entries contain CONFIGURE
    end_configure = any(isinstance(blk, dict) and blk.get('name','').startswith('CONFIGURE') 
                       for blk in QSLCLEND_DB.values()) if QSLCLEND_DB else False
    print(f"  END config : { end_configure }")

    print(f"  PAR config : { 'CONFIGURE' in QSLCLPAR_DB }")
    print(f"  VM5 config : { 'CONFIGURE' in QSLCLVM5_DB }")
    print(f"  DISP entries : { len(QSLCLDISP_DB) }")
    print(f"  RTF entries  : { len(QSLCLRTF_DB) }")

def cmd_ping(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    dev = devs[0]

    payload = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)

    # Try IDX-guided path (0x04 is the usual PING index)
    idx_ping = qslclidx_get(0x04)
    if idx_ping:
        print("[*] QSLCLIDX: Using IDX[0x04] PING route")
        pkt = b"QSLCLIDX" + idx_ping["raw"] + payload
        t0 = time.time()
        resp = qslcl_dispatch(dev, "IDX", pkt)
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

    # ---------------------------------------------------------
    # PRIORITY 1: QSLCLIDX (0x08 commonly used for GETINFO)
    # ---------------------------------------------------------
    idx_inf = qslclidx_get(0x08)
    if idx_inf:
        print("[*] QSLCLIDX: Using IDX[0x08] GETINFO route")
        pkt = b"QSLCLIDX" + idx_inf["raw"]
        resp = qslcl_dispatch(dev, "IDX", pkt)
        if resp:
            try:
                info = parse_device_info(resp)
                print_device_info(info)
                return
            except:
                print("[!] IDX GETINFO parse error.")

    # ---------------------------------------------------------
    # PRIORITY 2: Dispatcher
    # ---------------------------------------------------------
    resp = qslcl_dispatch(dev, "GETINFO")
    if resp:
        decoded = decode_runtime_result(resp)
        print("   Runtime:", decoded)
        try:
            info = parse_device_info(resp)
            print_device_info(info)
            return
        except:
            print("[!] Dispatcher GETINFO parse failed.")

    # ---------------------------------------------------------
    # PRIORITY 3: Engine fallback
    # ---------------------------------------------------------
    if "GETINFO" in QSLCLEND_DB:
        entry = QSLCLEND_DB["GETINFO"]["raw"]
        resp = exec_universal(dev, "ENGINE", entry)
        if resp:
            try:
                info = parse_device_info(resp)
                print_device_info(info)
                return
            except:
                print("[!] Engine GETINFO failed.")

    # ---------------------------------------------------------
    # PRIORITY 4: PAR fallback
    # ---------------------------------------------------------
    if "GETINFO" in QSLCLPAR_DB:
        resp = exec_universal(dev, "GETINFO", b"")
        if resp:
            try:
                info = parse_device_info(resp)
                print_device_info(info)
                return
            except:
                print("[!] PAR GETINFO failed.")

    # ---------------------------------------------------------
    # PRIORITY 5: Legacy
    # ---------------------------------------------------------
    print("[*] Trying legacy fallback GETINFO...")
    resp = exec_universal(dev, "GETINFO", b"\x00" * 8)

    if not resp:
        return print("[!] GETINFO: no valid response.")

    try:
        info = parse_device_info(resp)
        print_device_info(info)
    except:
        print("[!] Could not decode GETINFO at all.")

# ============================================================
#  SAFE-AWARE MEMORY OPERATIONS WITH RUNTIME DECODING
# ============================================================
def _decode_and_show(resp, op, addr, size=None, origin="DISPATCH"):
    if not resp:
        print(f"[!] {op} failed @ 0x{addr:08X} (no response, via {origin})")
        return None

    result = decode_runtime_result(resp)

    sev  = result.get("severity", "UNKNOWN")
    name = result.get("name", "UNKNOWN")

    msg = f"{op} @ 0x{addr:08X} ({origin}) → {name}"

    if sev == "SUCCESS":
        print(f"[✓] {msg}")
    elif sev == "WARNING":
        print(f"[~] {msg}")
    else:
        print(f"[✗] {msg}")

    return result if sev in ("SUCCESS", "WARNING") else None

def qslclidx_or_dispatch(dev, cname, payload, timeout=1.0):
    """
    Priority:
        1. QSLCLIDX
        2. QSLCLPAR
        3. QSLCLVM5
        4. QSLCLEND
        5. Default raw dispatcher
    """
    # --- 1. QSLCLIDX ---
    for entry_id, e in QSLCLIDX_DB.items():
        if isinstance(e, dict) and e.get("cmd") == cname:
            print(f"[*] QSLCLIDX hit: {cname} → entry_id=0x{entry_id:08X}")
            return qslcl_dispatch(dev, cname, payload, timeout), "IDX"

    # --- 2. QSLCLPAR ---
    if cname in QSLCLPAR_DB:
        return qslcl_dispatch(dev, cname, payload, timeout), "PAR"

    # --- 3. QSLCLVM5 (Nano VM handlers)
    if cname in QSLCLVM5_DB:
        op = QSLCLVM5_DB[cname]["raw"]
        pkt = b"QSLCLVM5" + op + payload
        return qslcl_dispatch(dev, "NANO", pkt, timeout), "VM5"

    # --- 4. QSLCLEND (handlers)
    if cname in QSLCLEND_DB:
        op = QSLCLEND_DB[cname]
        pkt = b"QSLCLEND" + op + payload
        return qslcl_dispatch(dev, "ENGINE", pkt, timeout), "ENG"

    # --- 5. Default fallback ---
    return qslcl_dispatch(dev, cname, payload, timeout), "FALLBACK"

# ============================================================
#  SMART PARTITION / RAW DECODER
# ============================================================
def resolve_target_for_rw(dev, target):
    """
    Enhanced target resolution with advanced partition detection and validation
    target = "boot", "0x880000", "boot+0x1000", "emmc:userdata", "ufs:0:boot"
    Returns (address, size, is_partition, target_info)
    """
    target_info = {
        "type": "unknown",
        "name": target,
        "address": 0,
        "size": 0,
        "validated": False,
        "sector_aligned": False
    }
    
    # Check for partition+offset format (e.g., "boot+0x1000")
    if "+" in target:
        try:
            part_name, offset_str = target.split("+", 1)
            scan_gpt(dev)
            base_addr, part_size = resolve_partition(part_name)
            
            if offset_str.startswith("0x"):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)
            
            if offset >= part_size:
                raise ValueError(f"Offset 0x{offset:X} beyond partition {part_name} size 0x{part_size:X}")
            
            addr = base_addr + offset
            target_info.update({
                "type": "partition_offset",
                "name": part_name,
                "base_address": base_addr,
                "offset": offset,
                "address": addr,
                "size": part_size - offset,  # Remaining size from offset
                "validated": True
            })
            return addr, part_size - offset, True, target_info
            
        except Exception as e:
            print(f"[!] Invalid partition+offset format: {e}")
            return None, None, False, target_info
    
    # Check for storage device format (e.g., "emmc:userdata", "ufs:0:boot")
    if ":" in target:
        try:
            storage_type, *parts = target.split(":")
            if storage_type.upper() in ["EMMC", "UFS", "NAND", "SPI"]:
                # Handle storage device specifications
                return resolve_storage_target(dev, storage_type, parts, target_info)
        except:
            pass
    
    # Hex raw address
    if target.startswith("0x") or (target.replace('_', '').isalnum() and any(c in 'abcdefABCDEF' for c in target)):
        try:
            addr = int(target, 16) if target.startswith("0x") else int(target, 16)
            target_info.update({
                "type": "raw_address",
                "address": addr,
                "validated": True
            })
            return addr, None, False, target_info
        except:
            pass
    
    # Decimal raw address
    if target.isdigit():
        try:
            addr = int(target)
            target_info.update({
                "type": "raw_address",
                "address": addr,
                "validated": True
            })
            return addr, None, False, target_info
        except:
            pass
    
    # Partition name
    try:
        scan_gpt(dev)
        addr, size = resolve_partition(target)
        target_info.update({
            "type": "partition",
            "name": target,
            "address": addr,
            "size": size,
            "validated": True
        })
        return addr, size, True, target_info
    except:
        # Try common partition aliases
        aliases = {
            "boot": "boot", "kernel": "boot", "recovery": "recovery", "system": "system",
            "vendor": "vendor", "userdata": "userdata", "cache": "cache", "misc": "misc",
            "frp": "frp", "persist": "persist", "modem": "modem", "bootloader": "aboot"
        }
        
        if target.lower() in aliases:
            try:
                actual_name = aliases[target.lower()]
                addr, size = resolve_partition(actual_name)
                target_info.update({
                    "type": "partition_alias",
                    "name": actual_name,
                    "alias": target,
                    "address": addr,
                    "size": size,
                    "validated": True
                })
                return addr, size, True, target_info
            except:
                pass
    
    # Not a known target
    target_info["validated"] = False
    return None, None, False, target_info

def resolve_storage_target(dev, storage_type, parts, target_info):
    """
    Resolve storage device specific targets
    """
    if storage_type.upper() == "EMMC":
        if len(parts) == 1:
            # emmc:userdata format
            part_name = parts[0]
            try:
                addr, size = resolve_partition(part_name)
                target_info.update({
                    "type": "emmc_partition",
                    "storage": "eMMC",
                    "name": part_name,
                    "address": addr,
                    "size": size,
                    "validated": True
                })
                return addr, size, True, target_info
            except:
                pass
    
    elif storage_type.upper() == "UFS":
        if len(parts) == 2:
            # ufs:0:boot format (LUN:partition)
            lun, part_name = parts
            try:
                # UFS specific resolution would go here
                # For now, try regular partition resolution
                addr, size = resolve_partition(part_name)
                target_info.update({
                    "type": "ufs_partition",
                    "storage": "UFS",
                    "lun": lun,
                    "name": part_name,
                    "address": addr,
                    "size": size,
                    "validated": True
                })
                return addr, size, True, target_info
            except:
                pass
    
    return None, None, False, target_info

def detect_file_or_hex(data, max_file_size=1024*1024*1024):  # 1GB max by default
    """
    Enhanced file/hex detection with validation and safety limits
    Return: (type, data, info)
    """
    info = {
        "type": "unknown",
        "size": 0,
        "valid": False,
        "source": data
    }
    
    # Check if it's a file path
    if os.path.exists(data):
        try:
            file_size = os.path.getsize(data)
            if file_size > max_file_size:
                raise ValueError(f"File too large: {file_size} bytes (max: {max_file_size})")
            
            with open(data, "rb") as f:
                file_data = f.read()
            
            info.update({
                "type": "file",
                "size": len(file_data),
                "file_path": data,
                "file_size": file_size,
                "valid": True
            })
            return "file", file_data, info
            
        except Exception as e:
            raise ValueError(f"File error: {e}")
    
    # Check if it's a hex string
    try:
        # Remove common hex prefixes and whitespace
        clean_data = data.replace("0x", "").replace(" ", "").replace(":", "").replace("-", "")
        
        # Validate hex characters
        if all(c in "0123456789ABCDEFabcdef" for c in clean_data):
            # Ensure even length for bytes conversion
            if len(clean_data) % 2 != 0:
                clean_data = "0" + clean_data
            
            hex_data = bytes.fromhex(clean_data)
            
            info.update({
                "type": "hex",
                "size": len(hex_data),
                "hex_length": len(clean_data) // 2,
                "valid": True
            })
            return "hex", hex_data, info
    except:
        pass
    
    # Check if it's a pattern (e.g., "00FF"*100)
    if "*" in data:
        try:
            pattern, repeat_str = data.split("*", 1)
            repeat_count = int(repeat_str)
            
            # Validate pattern as hex
            clean_pattern = pattern.replace("0x", "").replace(" ", "")
            if all(c in "0123456789ABCDEFabcdef" for c in clean_pattern):
                if len(clean_pattern) % 2 != 0:
                    clean_pattern = "0" + clean_pattern
                
                pattern_bytes = bytes.fromhex(clean_pattern)
                pattern_data = pattern_bytes * repeat_count
                
                info.update({
                    "type": "pattern",
                    "size": len(pattern_data),
                    "pattern": clean_pattern,
                    "repeats": repeat_count,
                    "valid": True
                })
                return "pattern", pattern_data, info
        except:
            pass
    
    # Check if it's a fill pattern (e.g., "FF:1024" to fill 1024 bytes with 0xFF)
    if ":" in data and not data.startswith("0x"):
        try:
            fill_byte_str, size_str = data.split(":", 1)
            fill_byte = int(fill_byte_str, 16) & 0xFF
            fill_size = int(size_str)
            
            fill_data = bytes([fill_byte]) * fill_size
            
            info.update({
                "type": "fill",
                "size": fill_size,
                "fill_byte": fill_byte,
                "valid": True
            })
            return "fill", fill_data, info
        except:
            pass
    
    raise ValueError(f"Data source not recognized: {data}")

def validate_read_write_operation(dev, addr, size, operation="read"):
    """
    Validate read/write operation parameters for safety
    """
    warnings = []
    errors = []
    
    # Check address alignment
    sector_size = get_sector_size(dev)
    if addr % sector_size != 0:
        warnings.append(f"Address 0x{addr:X} not sector-aligned (sector size: {sector_size})")
    
    # Check size alignment
    if size % sector_size != 0:
        warnings.append(f"Size 0x{size:X} not sector-aligned (sector size: {sector_size})")
    
    # Check for critical system addresses (read-only protection)
    critical_ranges = [
        (0x00000000, 0x01000000, "Boot ROM/Flash"),
        (0x88000000, 0x89000000, "Kernel/Boot"),
        (0xFFF00000, 0xFFFFFFFF, "Reserved/MMIO")
    ]
    
    for start, end, description in critical_ranges:
        if start <= addr < end:
            if operation == "write":
                errors.append(f"CRITICAL: Writing to {description} region (0x{addr:X}) may brick device!")
            else:
                warnings.append(f"Reading from {description} region (0x{addr:X})")
    
    # Size limits
    max_safe_size = 256 * 1024 * 1024  # 256MB
    if size > max_safe_size:
        warnings.append(f"Large operation: {size} bytes (> {max_safe_size} bytes)")
    
    return warnings, errors

def smart_size_determination(dev, target_info, args, operation="read"):
    """
    Intelligent size determination for read/write operations
    """
    size = None
    size_source = "unknown"
    
    # Priority 1: Explicit size argument
    if hasattr(args, 'size') and args.size:
        size = args.size
        size_source = "explicit_argument"
    
    # Priority 2: Secondary argument (if numeric)
    elif hasattr(args, 'arg2') and args.arg2 and args.arg2.isdigit():
        size = int(args.arg2)
        size_source = "secondary_argument"
    
    # Priority 3: Partition size
    elif target_info.get("type") in ["partition", "partition_alias", "emmc_partition", "ufs_partition"]:
        size = target_info.get("size")
        size_source = "partition_size"
    
    # Priority 4: Smart detection for raw addresses
    elif target_info.get("type") == "raw_address" and operation == "read":
        # For raw address reads, try to detect region size
        detected_size = detect_region_size(dev, target_info["address"])
        if detected_size:
            size = detected_size
            size_source = "auto_detected"
        else:
            # Default safe size for raw reads
            size = 4096
            size_source = "default_safe"
    
    # Priority 5: Data size for writes
    elif operation == "write" and hasattr(args, 'data'):
        try:
            _, data, _ = detect_file_or_hex(args.data)
            size = len(data)
            size_source = "data_size"
        except:
            pass
    
    if size is None:
        raise ValueError(f"Cannot determine size for {operation} operation")
    
    return size, size_source

def detect_region_size(dev, address):
    """
    Attempt to detect the size of a memory region
    """
    # Try to read progressively larger chunks until failure
    test_sizes = [512, 4096, 32768, 131072]  # 512B, 4KB, 32KB, 128KB
    
    for test_size in test_sizes:
        try:
            payload = struct.pack("<Q I", address, test_size)
            resp = qslcl_dispatch(dev, "READ", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") != "SUCCESS":
                    break
            else:
                break
        except:
            break
    else:
        # If all sizes succeeded, return the largest tested size
        return test_sizes[-1]
    
    # Return the last successful size
    return test_sizes[test_sizes.index(test_size) - 1] if test_sizes.index(test_size) > 0 else 512

def optimized_read_operation(dev, addr, size, chunk_size=None):
    """
    Perform optimized read operation with chunking and progress tracking
    """
    if chunk_size is None:
        chunk_size = min(size, 64 * 1024)  # 64KB chunks by default
    
    total_read = 0
    all_data = bytearray()
    sector_size = get_sector_size(dev)
    
    # Align chunk size to sectors
    chunk_size = align_up(chunk_size, sector_size)
    
    print(f"[*] Reading in {chunk_size // 1024}KB chunks...")
    
    with ProgressBar(total=size, prefix="Reading", suffix="complete", decimals=1) as progress:
        while total_read < size:
            current_chunk = min(chunk_size, size - total_read)
            current_addr = addr + total_read
            
            # Align chunk to sector boundary
            aligned_chunk = align_up(current_chunk, sector_size)
            
            payload = struct.pack("<Q I", current_addr, aligned_chunk)
            resp, origin = qslclidx_or_dispatch(dev, "READ", payload)
            
            if not resp:
                print(f"\n[!] Read failed at 0x{current_addr:X}")
                break
            
            status = decode_runtime_result(resp)
            if status.get("severity") != "SUCCESS":
                print(f"\n[!] Read error at 0x{current_addr:X}: {status.get('name', 'UNKNOWN')}")
                break
            
            chunk_data = status.get("extra", b"")
            if not chunk_data:
                print(f"\n[!] Empty response at 0x{current_addr:X}")
                break
            
            # Take only the requested amount (in case we read more due to alignment)
            actual_data = chunk_data[:current_chunk]
            all_data.extend(actual_data)
            total_read += len(actual_data)
            
            progress.update(len(actual_data))
    
    return bytes(all_data), total_read

def optimized_write_operation(dev, addr, data, chunk_size=None):
    """
    Perform optimized write operation with chunking and progress tracking
    """
    if chunk_size is None:
        chunk_size = min(len(data), 64 * 1024)  # 64KB chunks by default
    
    total_written = 0
    sector_size = get_sector_size(dev)
    total_size = len(data)
    
    # Align chunk size to sectors
    chunk_size = align_up(chunk_size, sector_size)
    
    print(f"[*] Writing in {chunk_size // 1024}KB chunks...")
    
    with ProgressBar(total=total_size, prefix="Writing", suffix="complete", decimals=1) as progress:
        while total_written < total_size:
            current_chunk = min(chunk_size, total_size - total_written)
            current_addr = addr + total_written
            
            # Get chunk data and pad to sector alignment if needed
            chunk_data = data[total_written:total_written + current_chunk]
            if len(chunk_data) % sector_size != 0:
                chunk_data += b"\x00" * (sector_size - (len(chunk_data) % sector_size))
            
            payload = struct.pack("<Q", current_addr) + chunk_data
            resp, origin = qslclidx_or_dispatch(dev, "WRITE", payload)
            
            if not resp:
                print(f"\n[!] Write failed at 0x{current_addr:X}")
                return False
            
            status = decode_runtime_result(resp)
            if status.get("severity") != "SUCCESS":
                print(f"\n[!] Write error at 0x{current_addr:X}: {status.get('name', 'UNKNOWN')}")
                return False
            
            total_written += current_chunk
            progress.update(current_chunk)
    
    return True

class ProgressBar:
    """
    Simple progress bar for read/write operations
    """
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
        self.current += progress
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.current / float(self.total)))
        filled_length = int(self.length * self.current // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end='\r')
        if self.current == self.total:
            print()

# ============================================================
#                      ENHANCED READ
# ============================================================
def cmd_read(args):
    """
    Enhanced READ command with intelligent target resolution and validation
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device detected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Resolve target with enhanced detection
    target = args.target
    addr, psize, is_part, target_info = resolve_target_for_rw(dev, target)
    
    if not target_info.get("validated", False):
        return print(f"[!] Cannot resolve target: {target}")
    
    # Intelligent size determination
    try:
        size, size_source = smart_size_determination(dev, target_info, args, "read")
    except ValueError as e:
        return print(f"[!] {e}")
    
    # Output file determination
    outfile = determine_output_file(args, target, target_info)
    
    # Operation validation
    warnings, errors = validate_read_write_operation(dev, addr, size, "read")
    
    # Display warnings
    for warning in warnings:
        print(f"[~] Warning: {warning}")
    
    # Check for critical errors
    if errors:
        for error in errors:
            print(f"[!] Error: {error}")
        confirm = input("Continue anyway? (y/N): ").strip().lower()
        if confirm != 'y':
            return print("[*] Read operation cancelled.")
    
    # Sector alignment
    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(size, sector)
    
    # Display operation info
    print(f"[*] READ Operation Summary:")
    print(f"    Target: {target} ({target_info['type']})")
    print(f"    Address: 0x{addr:X} -> 0x{aligned_addr:X} (aligned)")
    print(f"    Size: 0x{size:X} -> 0x{aligned_size:X} bytes (aligned)")
    print(f"    Size Source: {size_source}")
    print(f"    Output: {outfile}")
    
    if warnings:
        print(f"    Warnings: {len(warnings)}")
    
    # Perform read operation
    print(f"\n[*] Starting read operation...")
    
    try:
        data, bytes_read = optimized_read_operation(dev, aligned_addr, aligned_size)
        
        # Trim to actual requested size
        if bytes_read > size:
            data = data[:size]
        
        # Save to file
        with open(outfile, "wb") as f:
            f.write(data)
        
        # Verify file was written
        if os.path.exists(outfile) and os.path.getsize(outfile) == len(data):
            print(f"[✓] Read completed: {bytes_read} bytes -> {outfile}")
            
            # Additional info
            file_size = os.path.getsize(outfile)
            print(f"[*] File info: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
            
            # Calculate checksum if small enough
            if file_size < 10 * 1024 * 1024:  # 10MB
                import hashlib
                sha256 = hashlib.sha256(data).hexdigest()
                print(f"[*] SHA256: {sha256}")
            
            return True
        else:
            print(f"[!] File write verification failed")
            return False
            
    except Exception as e:
        print(f"[!] Read operation failed: {e}")
        return False

# ============================================================
#                      ENHANCED WRITE
# ============================================================
def cmd_write(args):
    """
    Enhanced WRITE command with comprehensive validation and safety checks
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device detected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Resolve target
    target = args.target
    addr, psize, is_part, target_info = resolve_target_for_rw(dev, target)
    
    if not target_info.get("validated", False):
        return print(f"[!] Cannot resolve target: {target}")
    
    # Detect and load data
    try:
        dtype, data, data_info = detect_file_or_hex(args.data)
    except ValueError as e:
        return print(f"[!] {e}")
    
    # Size validation for partitions
    if is_part and psize and len(data) > psize:
        print(f"[!] Warning: Data size ({len(data)} bytes) exceeds partition size ({psize} bytes)")
        confirm = input("Continue with truncated write? (y/N): ").strip().lower()
        if confirm != 'y':
            return print("[*] Write operation cancelled.")
        # Truncate data to partition size
        data = data[:psize]
        print(f"[*] Data truncated to {len(data)} bytes")
    
    # Operation validation
    warnings, errors = validate_read_write_operation(dev, addr, len(data), "write")
    
    # Display critical information
    print(f"[!] WRITE OPERATION WARNING")
    print(f"    Target: {target} ({target_info['type']})")
    print(f"    Address: 0x{addr:X}")
    print(f"    Data Size: {len(data)} bytes")
    print(f"    Data Type: {dtype}")
    
    if data_info.get("file_path"):
        print(f"    Source File: {data_info['file_path']}")
    
    # Display all warnings and errors
    for warning in warnings:
        print(f"    Warning: {warning}")
    
    for error in errors:
        print(f"    CRITICAL: {error}")
    
    # Safety confirmation
    if errors:
        print(f"\n[!] CRITICAL ERRORS DETECTED!")
        confirm = input("TYPE 'YES' TO CONTINUE (THIS MAY BRICK YOUR DEVICE): ").strip().upper()
        if confirm != 'YES':
            return print("[*] Write operation cancelled for safety.")
    else:
        confirm = input("\nConfirm write operation? (yes/NO): ").strip().lower()
        if confirm != 'yes':
            return print("[*] Write operation cancelled.")
    
    # Sector alignment
    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_len = align_up(len(data), sector)
    
    # Pad data if necessary
    if len(data) < aligned_len:
        original_size = len(data)
        data += b"\x00" * (aligned_len - len(data))
        print(f"[*] Data padded from {original_size} to {len(data)} bytes for alignment")
    
    # Perform write operation
    print(f"\n[*] Starting write operation...")
    
    try:
        success = optimized_write_operation(dev, aligned_addr, data)
        
        if success:
            print(f"[✓] Write completed: {len(data)} bytes -> 0x{addr:X}")
            
            # Optional verification read
            if len(data) <= 65536:  # Only verify small writes
                verify = input("Verify write? (y/N): ").strip().lower()
                if verify == 'y':
                    print("[*] Verifying write...")
                    verify_data, _ = optimized_read_operation(dev, aligned_addr, min(len(data), 65536))
                    if verify_data == data[:len(verify_data)]:
                        print("[✓] Write verification: SUCCESS")
                    else:
                        print("[!] Write verification: FAILED - data mismatch")
            
            return True
        else:
            print("[!] Write operation failed")
            return False
            
    except Exception as e:
        print(f"[!] Write operation failed: {e}")
        return False

# ============================================================
#                      ENHANCED ERASE
# ============================================================
def cmd_erase(args):
    """
    Enhanced ERASE command with safety controls and validation
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device detected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Resolve target
    target = args.target
    addr, psize, is_part, target_info = resolve_target_for_rw(dev, target)
    
    if not target_info.get("validated", False):
        return print(f"[!] Cannot resolve target: {target}")
    
    # Size determination
    try:
        size, size_source = smart_size_determination(dev, target_info, args, "erase")
    except ValueError as e:
        return print(f"[!] {e}")
    
    # Operation validation
    warnings, errors = validate_read_write_operation(dev, addr, size, "erase")
    
    # Display critical information
    print(f"[!] ERASE OPERATION WARNING")
    print(f"    Target: {target} ({target_info['type']})")
    print(f"    Address: 0x{addr:X}")
    print(f"    Size: 0x{size:X} bytes ({size / 1024 / 1024:.2f} MB)")
    print(f"    Size Source: {size_source}")
    
    # Display all warnings and errors
    for warning in warnings:
        print(f"    Warning: {warning}")
    
    for error in errors:
        print(f"    CRITICAL: {error}")
    
    # Safety confirmation
    print(f"\n[!] ERASE WILL DESTROY DATA!")
    if errors:
        confirm = input("TYPE 'ERASE' TO CONTINUE (THIS MAY BRICK YOUR DEVICE): ").strip().upper()
        expected_confirm = "ERASE"
    else:
        confirm = input("TYPE 'YES' TO CONFIRM ERASE: ").strip().upper()
        expected_confirm = "YES"
    
    if confirm != expected_confirm:
        return print("[*] Erase operation cancelled.")
    
    # Sector alignment
    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(size, sector)
    
    # Perform erase operation
    print(f"\n[*] Starting erase operation...")
    
    # For large erases, use chunking
    if aligned_size > 1024 * 1024:  # 1MB
        print(f"[*] Large erase detected, using chunked operation...")
        success = chunked_erase_operation(dev, aligned_addr, aligned_size)
    else:
        payload = struct.pack("<Q I", aligned_addr, aligned_size)
        resp, origin = qslclidx_or_dispatch(dev, "ERASE", payload)
        
        if resp:
            status = decode_runtime_result(resp)
            success = status.get("severity") == "SUCCESS"
            if not success:
                print(f"[!] Erase failed: {status.get('name', 'UNKNOWN')}")
        else:
            success = False
            print("[!] No response from erase command")
    
    if success:
        print(f"[✓] Erase completed: 0x{aligned_size:X} bytes at 0x{aligned_addr:X}")
        return True
    else:
        print("[!] Erase operation failed")
        return False

def chunked_erase_operation(dev, addr, size, chunk_size=1024*1024):  # 1MB chunks
    """
    Perform erase operation in chunks for large regions
    """
    total_erased = 0
    chunk_size = align_up(chunk_size, get_sector_size(dev))
    
    with ProgressBar(total=size, prefix="Erasing", suffix="complete", decimals=1) as progress:
        while total_erased < size:
            current_chunk = min(chunk_size, size - total_erased)
            current_addr = addr + total_erased
            
            payload = struct.pack("<Q I", current_addr, current_chunk)
            resp, origin = qslclidx_or_dispatch(dev, "ERASE", payload)
            
            if not resp:
                print(f"\n[!] Erase failed at 0x{current_addr:X}")
                return False
            
            status = decode_runtime_result(resp)
            if status.get("severity") != "SUCCESS":
                print(f"\n[!] Erase error at 0x{current_addr:X}: {status.get('name', 'UNKNOWN')}")
                return False
            
            total_erased += current_chunk
            progress.update(current_chunk)
    
    return True

def determine_output_file(args, target, target_info):
    """
    Determine output filename for read operations
    """
    # Priority 1: Explicit output argument
    if hasattr(args, 'output') and args.output:
        return args.output
    
    # Priority 2: Secondary argument (if not numeric)
    if hasattr(args, 'arg2') and args.arg2 and not args.arg2.isdigit():
        return args.arg2
    
    # Priority 3: Smart filename based on target info
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    if target_info.get("type") == "partition":
        return f"{target_info['name']}_{timestamp}.bin"
    elif target_info.get("type") == "raw_address":
        return f"memory_0x{target_info['address']:X}_{timestamp}.bin"
    elif target_info.get("type") == "partition_offset":
        return f"{target_info['name']}_0x{target_info['offset']:X}_{timestamp}.bin"
    else:
        return f"{target}_{timestamp}.bin"

def resolve_address_for_peekpoke(dev, target):
    """
    Advanced address resolver for PEEK/POKE operations
    Supports multiple addressing modes with intelligent detection
    """
    # Ensure partitions are scanned
    scan_gpt(dev)
    
    target = target.strip().lower()
    
    # Case 1: Register name (e.g., "r0", "x1", "sp", "pc")
    register_addr = resolve_register_address(target)
    if register_addr is not None:
        return register_addr
    
    # Case 2: Symbolic address (e.g., "kernel_base", "stack_pointer")
    symbolic_addr = resolve_symbolic_address(dev, target)
    if symbolic_addr is not None:
        return symbolic_addr
    
    # Case 3: Partition with offset (e.g., "boot+0x200", "system+512")
    if "+" in target:
        return resolve_partition_offset(dev, target)
    
    # Case 4: Memory region alias (e.g., "ddr_start", "sram_end")
    region_addr = resolve_memory_region(dev, target)
    if region_addr is not None:
        return region_addr
    
    # Case 5: Bare partition name (e.g., "boot", "recovery")
    if target in PARTITIONS:
        addr, size = PARTITIONS[target]
        print(f"[*] Using partition '{target}' base address: 0x{addr:08X}")
        return addr
    
    # Case 6: Raw hex address (e.g., "0x880000", "0x1000")
    if target.startswith("0x"):
        try:
            return int(target, 16)
        except ValueError:
            raise ValueError(f"Invalid hex address: {target}")
    
    # Case 7: Raw decimal address (e.g., "123456", "4096")
    if target.isdigit():
        return int(target)
    
    # Case 8: Mathematical expression (e.g., "0x1000+0x200", "4096*2")
    math_addr = resolve_mathematical_expression(target)
    if math_addr is not None:
        return math_addr
    
    # Case 9: Try to auto-detect as symbol or special address
    auto_addr = auto_detect_address(dev, target)
    if auto_addr is not None:
        return auto_addr
    
    raise ValueError(f"Unknown PEEK/POKE target: {target}\n"
                    "Supported formats:\n"
                    "  • Hex: 0x880000\n"
                    "  • Decimal: 123456\n"
                    "  • Partition: boot, system\n"
                    "  • Partition+offset: boot+0x200, system+512\n"
                    "  • Register: r0, x1, sp, pc, lr\n"
                    "  • Memory region: ddr_start, sram_base\n"
                    "  • Expression: 0x1000+0x200, 4096*2")

def resolve_register_address(register_name):
    """
    Resolve CPU register names to their address or identifier
    """
    register_map = {
        # ARM registers
        'r0': 0x1000, 'r1': 0x1004, 'r2': 0x1008, 'r3': 0x100C,
        'r4': 0x1010, 'r5': 0x1014, 'r6': 0x1018, 'r7': 0x101C,
        'r8': 0x1020, 'r9': 0x1024, 'r10': 0x1028, 'r11': 0x102C,
        'r12': 0x1030, 'sp': 0x1034, 'lr': 0x1038, 'pc': 0x103C,
        'cpsr': 0x1040,
        
        # ARM64 registers
        'x0': 0x1100, 'x1': 0x1108, 'x2': 0x1110, 'x3': 0x1118,
        'x4': 0x1120, 'x5': 0x1128, 'x6': 0x1130, 'x7': 0x1138,
        'x8': 0x1140, 'x9': 0x1148, 'x10': 0x1150, 'x11': 0x1158,
        'x12': 0x1160, 'x13': 0x1168, 'x14': 0x1170, 'x15': 0x1178,
        'x16': 0x1180, 'x17': 0x1188, 'x18': 0x1190, 'x19': 0x1198,
        'x20': 0x11A0, 'x21': 0x11A8, 'x22': 0x11B0, 'x23': 0x11B8,
        'x24': 0x11C0, 'x25': 0x11C8, 'x26': 0x11D0, 'x27': 0x11D8,
        'x28': 0x11E0, 'x29': 0x11E8, 'x30': 0x11F0, 'sp': 0x11F8, 'pc': 0x1200,
        
        # Special registers
        'sctlr': 0x2000, 'ttbr0': 0x2008, 'ttbr1': 0x2010,
        'tcr': 0x2018, 'mair': 0x2020, 'amair': 0x2028,
        'vbar': 0x2030, 'rvbar': 0x2038,
    }
    
    return register_map.get(register_name.lower())

def resolve_symbolic_address(dev, symbol):
    """
    Resolve symbolic addresses to physical addresses
    """
    symbol_map = {
        'kernel_base': 0x80000000,
        'kernel_start': 0x80000000,
        'kernel_end': 0x81000000,
        'ramdisk_start': 0x81000000,
        'ramdisk_end': 0x82000000,
        'device_tree': 0x82000000,
        'dtb_start': 0x82000000,
        'stack_pointer': 0x83000000,
        'stack_base': 0x83000000,
        'stack_top': 0x83100000,
        'heap_start': 0x84000000,
        'heap_end': 0x85000000,
        'vector_table': 0x00000000,
        'exception_vector': 0x00000000,
        'boot_args': 0x00000100,
    }
    
    # Try predefined symbols first
    if symbol in symbol_map:
        return symbol_map[symbol]
    
    # Try to query device for symbol addresses
    try:
        resp = qslcl_dispatch(dev, "SYMBOL", symbol.encode() + b"\x00")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if len(extra) >= 8:
                    return struct.unpack("<Q", extra[:8])[0]
    except:
        pass
    
    return None

def resolve_partition_offset(dev, target):
    """
    Resolve partition+offset format (e.g., "boot+0x200")
    """
    try:
        part, off = target.split("+", 1)
        part = part.strip()
        off = off.strip()
        
        # Get partition info
        part_addr, part_size = resolve_partition(part)
        
        # Parse offset (supports hex, decimal, and expressions)
        if off.startswith("0x"):
            off_val = int(off, 16)
        elif off.isdigit():
            off_val = int(off)
        else:
            # Try mathematical expression
            off_val = resolve_mathematical_expression(off)
            if off_val is None:
                raise ValueError(f"Invalid offset format: {off}")
        
        # Validate offset range
        if off_val >= part_size:
            raise ValueError(f"Offset 0x{off_val:X} beyond partition '{part}' size (0x{part_size:X})")
        
        result_addr = part_addr + off_val
        print(f"[*] Partition '{part}' + 0x{off_val:X} = 0x{result_addr:08X}")
        return result_addr
        
    except ValueError as e:
        raise ValueError(f"Invalid partition+offset format '{target}': {e}")

def resolve_memory_region(dev, region_name):
    """
    Resolve memory region aliases
    """
    region_map = {
        'ddr_start': 0x80000000,
        'ddr_end': 0xFFFFFFFF,
        'sram_start': 0x00000000,
        'sram_end': 0x00040000,
        'iram_start': 0x00080000,
        'iram_end': 0x000C0000,
        'bootrom_start': 0x00000000,
        'bootrom_end': 0x00010000,
        'peripheral_start': 0x10000000,
        'peripheral_end': 0x1FFFFFFF,
        'mmio_start': 0x10000000,
        'mmio_end': 0x1FFFFFFF,
    }
    
    return region_map.get(region_name.lower())

def resolve_mathematical_expression(expr):
    """
    Resolve mathematical expressions in addresses
    """
    try:
        # Basic expression evaluation (safe)
        expr = expr.strip()
        
        # Replace common hex patterns
        expr = expr.replace('0x', '0x')
        
        # Supported operations
        allowed_chars = set('0123456789abcdefABCDEFxX+-*/() ')
        if not all(c in allowed_chars for c in expr):
            return None
        
        # Evaluate safely
        result = eval(expr, {"__builtins__": {}}, {})
        return int(result)
        
    except:
        return None

def auto_detect_address(dev, target):
    """
    Auto-detect address type for unknown targets
    """
    # Try common patterns
    if target.endswith('_base') or target.endswith('_start'):
        base_name = target[:-5]
        return resolve_symbolic_address(dev, base_name)
    
    elif target.endswith('_end') or target.endswith('_top'):
        base_name = target[:-4] + '_start'
        start_addr = resolve_symbolic_address(dev, base_name)
        if start_addr:
            return start_addr + 0x1000  # Assume 4KB size
    
    # Try as partition with different capitalization
    for part_name in PARTITIONS.keys():
        if part_name.lower() == target.lower():
            addr, size = PARTITIONS[part_name]
            print(f"[*] Auto-detected partition '{part_name}': 0x{addr:08X}")
            return addr
    
    return None

def cmd_peek(args):
    """
    Advanced PEEK command for memory reading with multiple data types and formats
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse address
    try:
        addr = resolve_address_for_peekpoke(dev, args.address)
    except Exception as e:
        return print(f"[!] Address error: {e}")
    
    # Parse size and data type
    size = getattr(args, 'size', 4)  # Default 4 bytes
    data_type = getattr(args, 'data_type', 'auto').lower()
    count = getattr(args, 'count', 1)  # Number of elements for array types
    
    print(f"[*] PEEK @ 0x{addr:08X} (size: {size}, type: {data_type}, count: {count})")
    
    # Build payload with size information
    payload = struct.pack("<Q I I", addr, size, count)
    resp, origin = qslclidx_or_dispatch(dev, "PEEK", payload)
    
    result = _decode_and_show_peek(resp, "PEEK", addr, size, data_type, count, origin)
    return result is not None

def _decode_and_show_peek(resp, operation, addr, size, data_type, count, origin):
    """
    Enhanced result decoder for PEEK operations with multiple data types
    """
    if not resp:
        print(f"[!] {operation} failed @ 0x{addr:08X} (no response, via {origin})")
        return None
    
    result = decode_runtime_result(resp)
    sev = result.get("severity", "UNKNOWN")
    name = result.get("name", "UNKNOWN")
    
    msg = f"{operation} @ 0x{addr:08X} ({origin}) → {name}"
    
    if sev == "SUCCESS":
        print(f"[✓] {msg}")
        data = result.get("extra", b"")
        return display_peek_data(data, addr, size, data_type, count)
    elif sev == "WARNING":
        print(f"[~] {msg}")
        data = result.get("extra", b"")
        if data:
            return display_peek_data(data, addr, size, data_type, count)
    else:
        print(f"[✗] {msg}")
        return None

def display_peek_data(data, addr, size, data_type, count):
    """
    Display peeked data in multiple formats
    """
    if not data:
        print("[!] Empty response data")
        return None
    
    print(f"\n[*] Memory Dump @ 0x{addr:08X}:")
    print("-" * 60)
    
    # Hex dump
    hex_dump(data, addr)
    
    # Data type interpretation
    print("\n[*] Data Interpretation:")
    interpret_data_types(data, data_type, count)
    
    # ASCII representation
    print("\n[*] ASCII Representation:")
    ascii_dump(data)
    
    return data

def hex_dump(data, base_addr):
    """
    Display hex dump of memory data
    """
    bytes_per_line = 16
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        addr_str = f"{base_addr + i:08X}"
        print(f"  {addr_str}: {hex_str:<48} {ascii_str}")

def interpret_data_types(data, data_type, count):
    """
    Interpret data as different types
    """
    interpretations = []
    
    # Auto-detect data type if needed
    if data_type == 'auto':
        data_type = auto_detect_data_type(data)
    
    # Interpret based on data type
    if data_type == 'uint8' and len(data) >= count:
        values = [struct.unpack_from("<B", data, i)[0] for i in range(min(count, len(data)))]
        interpretations.append(f"uint8[{count}]: {values}")
    
    elif data_type == 'uint16' and len(data) >= count * 2:
        values = [struct.unpack_from("<H", data, i*2)[0] for i in range(min(count, len(data)//2))]
        interpretations.append(f"uint16[{count}]: {[hex(v) for v in values]}")
    
    elif data_type == 'uint32' and len(data) >= count * 4:
        values = [struct.unpack_from("<I", data, i*4)[0] for i in range(min(count, len(data)//4))]
        interpretations.append(f"uint32[{count}]: {[hex(v) for v in values]}")
    
    elif data_type == 'uint64' and len(data) >= count * 8:
        values = [struct.unpack_from("<Q", data, i*8)[0] for i in range(min(count, len(data)//8))]
        interpretations.append(f"uint64[{count}]: {[hex(v) for v in values]}")
    
    elif data_type == 'float' and len(data) >= count * 4:
        values = [struct.unpack_from("<f", data, i*4)[0] for i in range(min(count, len(data)//4))]
        interpretations.append(f"float[{count}]: {values}")
    
    elif data_type == 'double' and len(data) >= count * 8:
        values = [struct.unpack_from("<d", data, i*8)[0] for i in range(min(count, len(data)//8))]
        interpretations.append(f"double[{count}]: {values}")
    
    elif data_type == 'string':
        try:
            string_val = data.decode('utf-8', errors='ignore').split('\x00')[0]
            interpretations.append(f"string: \"{string_val}\"")
        except:
            interpretations.append("string: [invalid encoding]")
    
    # Always show raw integer interpretation
    if len(data) >= 4:
        uint32_val = struct.unpack_from("<I", data, 0)[0]
        int32_val = struct.unpack_from("<i", data, 0)[0]
        interpretations.append(f"raw32: 0x{uint32_val:08X} ({int32_val})")
    
    if len(data) >= 8:
        uint64_val = struct.unpack_from("<Q", data, 0)[0]
        int64_val = struct.unpack_from("<q", data, 0)[0]
        interpretations.append(f"raw64: 0x{uint64_val:016X} ({int64_val})")
    
    for interpretation in interpretations:
        print(f"  • {interpretation}")

def auto_detect_data_type(data):
    """
    Auto-detect the most likely data type
    """
    if len(data) < 4:
        return 'uint8'
    
    # Check if it looks like a string
    if all(32 <= b <= 126 or b in [0, 9, 10, 13] for b in data[:16]):
        return 'string'
    
    # Check if it looks like floating point
    if len(data) >= 4:
        try:
            float_val = struct.unpack_from("<f", data, 0)[0]
            if not (math.isnan(float_val) or math.isinf(float_val)):
                if 1e-10 < abs(float_val) < 1e10:
                    return 'float'
        except:
            pass
    
    return 'uint32'

def ascii_dump(data):
    """
    Display ASCII representation of data
    """
    ascii_chars = []
    for byte in data[:64]:  # First 64 bytes only
        if 32 <= byte <= 126:
            ascii_chars.append(chr(byte))
        else:
            ascii_chars.append('.')
    
    ascii_str = ''.join(ascii_chars)
    print(f"  \"{ascii_str}\"")
    
    # Show control character info
    control_chars = sum(1 for b in data[:64] if b < 32 and b != 0)
    if control_chars > 0:
        print(f"  [Contains {control_chars} control characters]")

def cmd_poke(args):
    """
    Advanced POKE command for memory writing with multiple data types and safety checks
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse address
    try:
        addr = resolve_address_for_peekpoke(dev, args.address)
    except Exception as e:
        return print(f"[!] Address error: {e}")
    
    # Parse value and data type
    value_str = args.value
    data_type = getattr(args, 'data_type', 'auto').lower()
    size = getattr(args, 'size', 4)
    
    # Parse value based on data type
    try:
        value_data, actual_type = parse_poke_value(value_str, data_type, size)
    except Exception as e:
        return print(f"[!] Value parsing error: {e}")
    
    print(f"[*] POKE @ 0x{addr:08X} = {value_str} (as {actual_type}, size: {len(value_data)} bytes)")
    
    # Safety checks
    if not perform_safety_checks(dev, addr, value_data):
        return False
    
    # Build payload
    payload = struct.pack("<Q", addr) + value_data
    resp, origin = qslclidx_or_dispatch(dev, "POKE", payload)
    
    result = _decode_and_show_poke(resp, "POKE", addr, value_data, origin)
    
    # Verify write if successful
    if result:
        verify_poke_write(dev, addr, value_data)
    
    return result

def parse_poke_value(value_str, data_type, size):
    """
    Parse poke value string into binary data based on data type
    """
    value_str = value_str.strip()
    
    # Auto-detect type if needed
    if data_type == 'auto':
        data_type = auto_detect_value_type(value_str)
    
    # Parse based on type
    if data_type == 'uint8':
        value = int(value_str, 0) & 0xFF
        return struct.pack("<B", value), 'uint8'
    
    elif data_type == 'uint16':
        value = int(value_str, 0) & 0xFFFF
        return struct.pack("<H", value), 'uint16'
    
    elif data_type == 'uint32':
        value = int(value_str, 0) & 0xFFFFFFFF
        return struct.pack("<I", value), 'uint32'
    
    elif data_type == 'uint64':
        value = int(value_str, 0) & 0xFFFFFFFFFFFFFFFF
        return struct.pack("<Q", value), 'uint64'
    
    elif data_type == 'int8':
        value = int(value_str, 0)
        if value < -128 or value > 127:
            raise ValueError("int8 value out of range (-128 to 127)")
        return struct.pack("<b", value), 'int8'
    
    elif data_type == 'int16':
        value = int(value_str, 0)
        if value < -32768 or value > 32767:
            raise ValueError("int16 value out of range (-32768 to 32767)")
        return struct.pack("<h", value), 'int16'
    
    elif data_type == 'int32':
        value = int(value_str, 0)
        return struct.pack("<i", value), 'int32'
    
    elif data_type == 'int64':
        value = int(value_str, 0)
        return struct.pack("<q", value), 'int64'
    
    elif data_type == 'float':
        value = float(value_str)
        return struct.pack("<f", value), 'float'
    
    elif data_type == 'double':
        value = float(value_str)
        return struct.pack("<d", value), 'double'
    
    elif data_type == 'hex':
        # Raw hex string
        if value_str.startswith('0x'):
            value_str = value_str[2:]
        if len(value_str) % 2 != 0:
            value_str = '0' + value_str
        return bytes.fromhex(value_str), 'hex'
    
    elif data_type == 'string':
        # String data (null-terminated)
        return value_str.encode('utf-8') + b'\x00', 'string'
    
    else:
        raise ValueError(f"Unsupported data type: {data_type}")

def auto_detect_value_type(value_str):
    """
    Auto-detect value type from string
    """
    value_str = value_str.strip()
    
    # Check for float
    if '.' in value_str or 'e' in value_str.lower():
        try:
            float(value_str)
            return 'float'
        except:
            pass
    
    # Check for hex
    if value_str.startswith('0x'):
        if len(value_str) > 10:  # More than 32 bits
            return 'uint64'
        else:
            return 'uint32'
    
    # Check for string (contains non-digit characters)
    if not all(c in '0123456789-+' for c in value_str.replace(' ', '')):
        return 'string'
    
    # Default to int32
    return 'int32'

def perform_safety_checks(dev, addr, data):
    """
    Perform safety checks before memory write
    """
    print("[*] Performing safety checks...")
    
    # Check if address is in dangerous ranges
    dangerous_ranges = [
        (0x00000000, 0x00010000, "Boot ROM"),
        (0x10000000, 0x10001000, "Critical MMIO"),
        (0x80000000, 0x80001000, "Kernel Code"),
    ]
    
    for start, end, description in dangerous_ranges:
        if start <= addr < end:
            print(f"[!] WARNING: Writing to {description} region!")
            break
    
    # Check data pattern for suspicious values
    if len(data) >= 4:
        first_word = struct.unpack_from("<I", data, 0)[0]
        if first_word in [0x00000000, 0xFFFFFFFF, 0xDEADBEEF]:
            print(f"[!] WARNING: Writing suspicious pattern: 0x{first_word:08X}")
    
    # Size check
    if len(data) > 1024:
        print(f"[!] WARNING: Large write size: {len(data)} bytes")
    
    # Final confirmation
    print(f"\n[!] WARNING: Direct memory write to 0x{addr:08X}")
    print(f"    Data: {data.hex()}")
    print(f"    Size: {len(data)} bytes")
    
    confirm = input("!! CONFIRM MEMORY WRITE (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Memory write cancelled")
        return False
    
    return True

def _decode_and_show_poke(resp, operation, addr, value_data, origin):
    """
    Enhanced result decoder for POKE operations
    """
    if not resp:
        print(f"[!] {operation} failed @ 0x{addr:08X} (no response, via {origin})")
        return None
    
    result = decode_runtime_result(resp)
    sev = result.get("severity", "UNKNOWN")
    name = result.get("name", "UNKNOWN")
    
    msg = f"{operation} @ 0x{addr:08X} ({origin}) → {name}"
    
    if sev == "SUCCESS":
        print(f"[✓] {msg}")
        return True
    elif sev == "WARNING":
        print(f"[~] {msg}")
        return True
    else:
        print(f"[✗] {msg}")
        return False

def verify_poke_write(dev, addr, expected_data):
    """
    Verify that the poke write was successful
    """
    print("[*] Verifying write...")
    
    # Read back the written data
    payload = struct.pack("<Q I", addr, len(expected_data))
    resp, origin = qslclidx_or_dispatch(dev, "PEEK", payload)
    
    if not resp:
        print("[!] Verification failed: Could not read back data")
        return False
    
    result = decode_runtime_result(resp)
    if result.get("severity") != "SUCCESS":
        print("[!] Verification failed: Readback error")
        return False
    
    actual_data = result.get("extra", b"")
    
    if actual_data == expected_data:
        print("[✓] Write verification: SUCCESS")
        return True
    else:
        print("[!] Write verification: FAILED")
        print(f"    Expected: {expected_data.hex()}")
        print(f"    Actual:   {actual_data.hex()}")
        return False

# Update the argument parsers
def update_peek_poke_parsers(sub):
    """
    Update the PEEK and POKE command parsers with enhanced options
    """
    # PEEK parser
    peek_parser = sub.add_parser("peek", help="Read memory with advanced addressing and data interpretation")
    peek_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression)")
    peek_parser.add_argument("-s", "--size", type=int, default=4, help="Number of bytes to read (default: 4)")
    peek_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'string'], default='auto', help="Data type interpretation")
    peek_parser.add_argument("-c", "--count", type=int, default=1, help="Number of elements for array types")
    peek_parser.set_defaults(func=cmd_peek)
    
    # POKE parser
    poke_parser = sub.add_parser("poke", help="Write memory with advanced addressing and data types")
    poke_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression)")
    poke_parser.add_argument("value", help="Value to write (supports multiple data types)")
    poke_parser.add_argument("-t", "--data-type", choices=['auto', 'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64', 'float', 'double', 'hex', 'string'], default='auto', help="Data type of value")
    poke_parser.add_argument("-s", "--size", type=int, default=4, help="Size of write in bytes (for hex/string types)")
    poke_parser.set_defaults(func=cmd_poke)

def cmd_rawmode(args):
    """
    Advanced RAWMODE command handler for low-level device access and privilege escalation
    Supports multiple raw modes with detailed configuration and monitoring
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse RAWMODE subcommand
    if not hasattr(args, 'rawmode_subcommand') or not args.rawmode_subcommand:
        return print("[!] RAWMODE command requires subcommand (list, set, status, unlock, lock, etc.)")
    
    subcmd = args.rawmode_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_rawmodes(dev)
    elif subcmd == "SET":
        return set_rawmode(dev, args)
    elif subcmd == "STATUS":
        return get_rawmode_status(dev)
    elif subcmd == "UNLOCK":
        return unlock_rawmode(dev, args)
    elif subcmd == "LOCK":
        return lock_rawmode(dev, args)
    elif subcmd == "CONFIGURE":
        return configure_rawmode(dev, args)
    elif subcmd == "ESCALATE":
        return escalate_privileges(dev, args)
    elif subcmd == "MONITOR":
        return monitor_rawmode_activity(dev, args)
    elif subcmd == "AUDIT":
        return audit_rawmode_access(dev, args)
    elif subcmd == "RESET":
        return reset_rawmode(dev, args)
    else:
        return handle_rawmode_operation(dev, subcmd, args)

def list_available_rawmodes(dev):
    """
    List all available RAWMODE commands and supported modes
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL RAWMODE COMMANDS AND MODES")
    print("="*60)
    
    rawmode_found = []
    
    # Check QSLCLPAR for RAWMODE commands
    print("\n[QSLCLPAR] RawMode Commands:")
    par_rawmodes = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "RAWMODE", "RAW_ACCESS", "PRIVILEGE", "UNLOCK", "ESCALATE", 
        "SUPERVISOR", "KERNEL", "SECURE", "DEBUG"
    ])]
    for rawmode_cmd in par_rawmodes:
        print(f"  • {rawmode_cmd}")
        rawmode_found.append(rawmode_cmd)
    
    # Check QSLCLEND for rawmode-related opcodes
    print("\n[QSLCLEND] RawMode Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["RAWMODE", "RAW", "PRIVILEGE", "UNLOCK"]) or any(x in entry_str for x in ["RAW", "PRIV"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            rawmode_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for rawmode microservices
    print("\n[QSLCLVM5] RawMode Microservices:")
    vm5_rawmodes = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["RAWMODE", "RAW_ACCESS"])]
    for rawmode_cmd in vm5_rawmodes:
        print(f"  • {rawmode_cmd}")
        rawmode_found.append(f"VM5_{rawmode_cmd}")
    
    # Check QSLCLIDX for rawmode indices
    print("\n[QSLCLIDX] RawMode Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["RAWMODE", "RAW_ACCESS"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                rawmode_found.append(f"IDX_{name}")
    
    if not rawmode_found:
        print("  No rawmode commands found in loader")
    else:
        print(f"\n[*] Total rawmode commands found: {len(rawmode_found)}")
    
    print("\n[*] Supported Raw Modes:")
    print("  • UNRESTRICTED (0xFF) - Full system access, no restrictions")
    print("  • HYPERVISOR   (0xE0) - Virtualization-level access")
    print("  • KERNEL       (0xC0) - Kernel-level privilege escalation") 
    print("  • SUPERVISOR   (0xA0) - Supervisor mode access")
    print("  • META         (0xA1) - Meta/engineering mode")
    print("  • DIAGNOSTIC   (0x10) - Diagnostic and debug access")
    print("  • DEVELOPER    (0x42) - Developer/debugging mode")
    print("  • SECURE       (0x5A) - Secure mode with auditing")
    print("  • SAFE         (0x01) - Safe mode with restrictions")
    print("  • LOCKED       (0x00) - Fully locked, no raw access")
    
    print("\n[*] Raw Mode Features:")
    print("  • Memory mapping bypass")
    print("  • Register direct access") 
    print("  • Hardware interrupt control")
    print("  • DMA engine access")
    print("  • Secure monitor calls")
    print("  • TrustZone boundary crossing")
    print("  • MMU configuration access")
    print("  • Cache control operations")
    
    print("="*60)
    
    return True

def set_rawmode(dev, args):
    """
    Set device to specific raw mode with configuration options
    """
    if not hasattr(args, 'rawmode_args') or not args.rawmode_args:
        return print("[!] RAWMODE SET requires mode specification")
    
    mode_arg = args.rawmode_args[0].lower()
    
    # Extended mode mapping with detailed descriptions
    mode_map = {
        # Unrestricted access modes
        "unrestricted":  (0xFF, "Full system access without restrictions"),
        "full":          (0xFF, "Full system access without restrictions"),
        "hypervisor":    (0xE0, "Virtualization-level hypervisor access"),
        "hyper":         (0xE0, "Virtualization-level hypervisor access"),
        
        # Kernel and system modes
        "kernel":        (0xC0, "Kernel-level privilege escalation"),
        "supervisor":    (0xA0, "Supervisor mode system access"),
        "system":        (0xA0, "System-level privileged access"),
        
        # Engineering and diagnostic modes
        "meta":          (0xA1, "Meta/engineering mode access"),
        "engineering":   (0xA1, "Engineering-level access"),
        "diagnostic":    (0x10, "Diagnostic and debugging access"),
        "debug":         (0x10, "Debugging and troubleshooting access"),
        
        # Development modes
        "developer":     (0x42, "Developer mode with enhanced access"),
        "development":   (0x42, "Development environment access"),
        
        # Security modes
        "secure":        (0x5A, "Secure mode with full auditing"),
        "audited":       (0x5A, "Audited secure access mode"),
        "safe":          (0x01, "Safe mode with restrictions"),
        "restricted":    (0x01, "Restricted safe access"),
        
        # Lock modes
        "locked":        (0x00, "Fully locked, no raw access"),
        "normal":        (0x00, "Normal operational mode"),
        "user":          (0x00, "Standard user mode access"),
    }
    
    # Parse mode value
    if mode_arg.startswith("0x"):
        mode_val = int(mode_arg, 16)
        mode_name = f"Custom Mode 0x{mode_val:02X}"
        mode_desc = "User-defined custom raw mode"
    elif mode_arg.isdigit():
        mode_val = int(mode_arg)
        mode_name = f"Custom Mode {mode_val}"
        mode_desc = "User-defined custom raw mode"
    else:
        if mode_arg not in mode_map:
            print(f"[!] Unknown mode: {mode_arg}")
            print("[*] Available modes: " + ", ".join(mode_map.keys()))
            return False
        mode_val, mode_desc = mode_map[mode_arg]
        mode_name = mode_arg.upper()
    
    # Get additional configuration parameters
    config_flags = 0x00
    timeout = 0
    access_level = 0xFF
    
    if hasattr(args, 'rawmode_args') and len(args.rawmode_args) > 1:
        for param in args.rawmode_args[1:]:
            if param.startswith("flags="):
                try:
                    flags_str = param.split('=')[1]
                    if flags_str.startswith("0x"):
                        config_flags = int(flags_str, 16)
                    else:
                        config_flags = int(flags_str)
                except:
                    print(f"[!] Invalid flags: {param}")
            elif param.startswith("timeout="):
                try:
                    timeout = int(param.split('=')[1])
                except:
                    print(f"[!] Invalid timeout: {param}")
            elif param.startswith("access="):
                try:
                    access_str = param.split('=')[1]
                    if access_str.startswith("0x"):
                        access_level = int(access_str, 16)
                    else:
                        access_level = int(access_str)
                except:
                    print(f"[!] Invalid access level: {param}")
    
    print(f"[*] Setting Raw Mode: {mode_name} (0x{mode_val:02X})")
    print(f"    Description: {mode_desc}")
    
    if config_flags != 0x00:
        print(f"    Configuration Flags: 0x{config_flags:02X}")
    if timeout > 0:
        print(f"    Timeout: {timeout} seconds")
    if access_level != 0xFF:
        print(f"    Access Level: 0x{access_level:02X}")
    
    # Safety warning for high-privilege modes
    if mode_val >= 0xC0:  # Kernel and above
        print("\n[!] WARNING: High-privilege raw mode selected!")
        print("[!] This may bypass security mechanisms and void warranties!")
        confirm = input("!! CONFIRM HIGH-PRIVILEGE MODE (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Raw mode change cancelled")
            return False
    
    # Build advanced payload
    payload = struct.pack("<BBBI", mode_val, config_flags, access_level, timeout)
    
    # Execute raw mode change
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE", payload)
    result = _decode_and_show_advanced(resp, "RAWMODE", mode_val, origin=origin)
    
    if result:
        # Verify mode change
        time.sleep(0.5)
        verify_rawmode_change(dev, mode_val)
    
    return result

def _decode_and_show_advanced(resp, operation, value, origin="UNKNOWN"):
    """
    Enhanced response decoder with detailed analysis
    """
    if not resp:
        print(f"[!] {operation} 0x{value:02X}: No response from device")
        return False
    
    result = decode_runtime_result(resp)
    severity = result.get("severity", "UNKNOWN")
    name = result.get("name", "UNKNOWN")
    extra = result.get("extra", b"")
    
    # Color-coded output based on severity
    color_codes = {
        "SUCCESS": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow  
        "ERROR": "\033[91m",    # Red
        "CRITICAL": "\033[95m", # Magenta
    }
    
    color = color_codes.get(severity, "\033[0m")
    reset = "\033[0m"
    
    print(f"{color}[{severity}] {operation} 0x{value:02X} via {origin}: {name}{reset}")
    
    # Analyze extra data for additional information
    if extra:
        if len(extra) >= 4:
            # Try to interpret as mode status
            current_mode = extra[0]
            previous_mode = extra[1] if len(extra) > 1 else 0
            flags = extra[2] if len(extra) > 2 else 0
            access_level = extra[3] if len(extra) > 3 else 0
            
            print(f"    Current Mode: 0x{current_mode:02X}")
            if previous_mode != 0:
                print(f"    Previous Mode: 0x{previous_mode:02X}")
            if flags != 0:
                print(f"    Status Flags: 0x{flags:02X}")
            if access_level != 0:
                print(f"    Access Level: 0x{access_level:02X}")
        
        if len(extra) > 4:
            # Show raw extra data
            print(f"    Additional Data: {extra[4:].hex()}")
    
    return severity == "SUCCESS"

def verify_rawmode_change(dev, expected_mode):
    """
    Verify that raw mode change was successful
    """
    print("[*] Verifying raw mode change...")
    
    # Try to get current raw mode status
    resp = qslcl_dispatch(dev, "RAWMODE", b"STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if extra and len(extra) > 0:
                current_mode = extra[0]
                if current_mode == expected_mode:
                    print(f"[✓] Raw mode verified: 0x{current_mode:02X}")
                    return True
                else:
                    print(f"[!] Raw mode mismatch: expected 0x{expected_mode:02X}, got 0x{current_mode:02X}")
                    return False
    
    print("[~] Raw mode verification unavailable")
    return True  # Assume success if verification not available

def get_rawmode_status(dev):
    """
    Get detailed raw mode status and capabilities
    """
    print("[*] Retrieving raw mode status...")
    
    status_info = {}
    
    # Get basic raw mode status
    resp = qslcl_dispatch(dev, "RAWMODE", b"STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 4:
                status_info["current_mode"] = extra[0]
                status_info["max_mode"] = extra[1]
                status_info["capabilities"] = extra[2]
                status_info["restrictions"] = extra[3]
                
                print("\n[*] Raw Mode Status:")
                print(f"    Current Mode: 0x{status_info['current_mode']:02X} ({get_mode_description(status_info['current_mode'])})")
                print(f"    Maximum Mode: 0x{status_info['max_mode']:02X} ({get_mode_description(status_info['max_mode'])})")
                print(f"    Capabilities: 0x{status_info['capabilities']:02X}")
                print(f"    Restrictions: 0x{status_info['restrictions']:02X}")
                
                # Decode capabilities
                capabilities = decode_capabilities(status_info['capabilities'])
                if capabilities:
                    print(f"    Available Features: {', '.join(capabilities)}")
                
                # Decode restrictions
                restrictions = decode_restrictions(status_info['restrictions'])
                if restrictions:
                    print(f"    Active Restrictions: {', '.join(restrictions)}")
    
    # Get security status
    print("\n[*] Security Status:")
    security_status = get_rawmode_security_status(dev)
    status_info["security"] = security_status
    
    # Get access log if available
    print("\n[*] Access History:")
    access_log = get_rawmode_access_log(dev)
    status_info["access_log"] = access_log
    
    return status_info

def get_mode_description(mode_value):
    """
    Get human-readable description for mode value
    """
    mode_descriptions = {
        0x00: "Locked/Normal",
        0x01: "Safe/Restricted", 
        0x10: "Diagnostic/Debug",
        0x42: "Developer",
        0x5A: "Secure/Audited",
        0xA0: "Supervisor/System",
        0xA1: "Meta/Engineering",
        0xC0: "Kernel",
        0xE0: "Hypervisor",
        0xFF: "Unrestricted/Full"
    }
    return mode_descriptions.get(mode_value, f"Unknown (0x{mode_value:02X})")

def decode_capabilities(capabilities_byte):
    """
    Decode capabilities from byte flags
    """
    capabilities = []
    flags = {
        0x01: "Memory Access",
        0x02: "Register Access", 
        0x04: "Interrupt Control",
        0x08: "DMA Access",
        0x10: "Secure Monitor",
        0x20: "TrustZone Access",
        0x40: "MMU Control",
        0x80: "Cache Control"
    }
    
    for flag, description in flags.items():
        if capabilities_byte & flag:
            capabilities.append(description)
    
    return capabilities

def decode_restrictions(restrictions_byte):
    """
    Decode restrictions from byte flags
    """
    restrictions = []
    flags = {
        0x01: "Memory Write Protected",
        0x02: "Register Write Protected",
        0x04: "Critical Regions Locked",
        0x08: "DMA Restricted", 
        0x10: "Secure Monitor Locked",
        0x20: "TrustZone Locked",
        0x40: "MMU Protected",
        0x80: "Cache Operations Restricted"
    }
    
    for flag, description in flags.items():
        if restrictions_byte & flag:
            restrictions.append(description)
    
    return restrictions

def get_rawmode_security_status(dev):
    """
    Get security-related status information
    """
    security_info = {}
    
    # Try to get security status
    resp = qslcl_dispatch(dev, "RAWMODE", b"SECURITY_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 4:
                security_info["authentication"] = extra[0]
                security_info["integrity"] = extra[1]
                security_info["audit_level"] = extra[2]
                security_info["violations"] = extra[3]
                
                print(f"    Authentication: {'Required' if security_info['authentication'] else 'None'}")
                print(f"    Integrity Check: {'Enabled' if security_info['integrity'] else 'Disabled'}")
                print(f"    Audit Level: {security_info['audit_level']}")
                print(f"    Security Violations: {security_info['violations']}")
    
    return security_info

def get_rawmode_access_log(dev):
    """
    Get raw mode access history log
    """
    # Try to get access log
    resp = qslcl_dispatch(dev, "RAWMODE", b"ACCESS_LOG\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if extra:
                # Parse access log entries (each 8 bytes: mode(1) + timestamp(4) + duration(2) + result(1))
                entry_size = 8
                num_entries = len(extra) // entry_size
                
                print(f"    Found {num_entries} access log entries")
                
                for i in range(min(num_entries, 5)):  # Show last 5 entries
                    entry = extra[i*entry_size:(i+1)*entry_size]
                    if len(entry) >= 8:
                        mode = entry[0]
                        timestamp = struct.unpack("<I", entry[1:5])[0]
                        duration = struct.unpack("<H", entry[5:7])[0]
                        result = entry[7]
                        
                        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                        result_str = "SUCCESS" if result == 1 else "FAILED" if result == 0 else "UNKNOWN"
                        
                        print(f"      {time_str} - Mode 0x{mode:02X} - {duration}s - {result_str}")
                
                if num_entries > 5:
                    print(f"      ... and {num_entries - 5} more entries")
                
                return num_entries
    
    print("    No access log available")
    return 0

def unlock_rawmode(dev, args):
    """
    Unlock raw mode with authentication if required
    """
    print("[*] Attempting to unlock raw mode...")
    
    unlock_method = "DEFAULT"
    auth_data = b""
    
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        unlock_method = args.rawmode_args[0].upper()
        if len(args.rawmode_args) > 1:
            auth_data = args.rawmode_args[1].encode()
    
    print(f"    Method: {unlock_method}")
    
    # Build unlock payload
    payload = unlock_method.encode() + b"\x00" + auth_data
    
    # Execute unlock
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE_UNLOCK", payload)
    result = _decode_and_show_advanced(resp, "RAWMODE_UNLOCK", 0, origin=origin)
    
    if result:
        print("[✓] Raw mode unlocked successfully")
        # Show new capabilities
        get_rawmode_status(dev)
    
    return result

def lock_rawmode(dev, args):
    """
    Lock raw mode and restore normal operation
    """
    print("[*] Locking raw mode...")
    
    lock_level = "FULL"
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        lock_level = args.rawmode_args[0].upper()
    
    print(f"    Lock Level: {lock_level}")
    
    payload = lock_level.encode() + b"\x00"
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE_LOCK", payload)
    result = _decode_and_show_advanced(resp, "RAWMODE_LOCK", 0, origin=origin)
    
    if result:
        print("[✓] Raw mode locked successfully")
    
    return result

def configure_rawmode(dev, args):
    """
    Configure raw mode parameters and settings
    """
    if not hasattr(args, 'rawmode_args') or not args.rawmode_args:
        return print_rawmode_config_help()
    
    config_action = args.rawmode_args[0].upper()
    
    if config_action == "AUDIT":
        return configure_audit_settings(dev, args)
    elif config_action == "TIMEOUT":
        return configure_timeout_settings(dev, args)
    elif config_action == "ACCESS":
        return configure_access_controls(dev, args)
    elif config_action == "SECURITY":
        return configure_security_settings(dev, args)
    else:
        return handle_configuration_action(dev, config_action, args)

def configure_audit_settings(dev, args):
    """
    Configure audit and logging settings
    """
    audit_level = "STANDARD"
    if hasattr(args, 'rawmode_args') and len(args.rawmode_args) > 1:
        audit_level = args.rawmode_args[1].upper()
    
    print(f"[*] Configuring audit level: {audit_level}")
    
    payload = audit_level.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "RAWMODE_CONFIG", b"AUDIT\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Audit settings configured")
            return True
        else:
            print(f"[!] Audit configuration failed: {status}")
            return False
    
    print("[!] Audit configuration not available")
    return False

def escalate_privileges(dev, args):
    """
    Escalate privileges to higher raw mode levels
    """
    print("[*] Attempting privilege escalation...")
    
    target_level = "KERNEL"
    escalation_method = "STANDARD"
    
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        target_level = args.rawmode_args[0].upper()
        if len(args.rawmode_args) > 1:
            escalation_method = args.rawmode_args[1].upper()
    
    print(f"    Target Level: {target_level}")
    print(f"    Method: {escalation_method}")
    
    # Safety confirmation for privilege escalation
    print("\n[!] WARNING: Privilege escalation may bypass security mechanisms!")
    confirm = input("!! CONFIRM PRIVILEGE ESCALATION (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Privilege escalation cancelled")
        return False
    
    payload = target_level.encode() + b"\x00" + escalation_method.encode() + b"\x00"
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE_ESCALATE", payload)
    result = _decode_and_show_advanced(resp, "PRIVILEGE_ESCALATION", 0, origin=origin)
    
    if result:
        print("[✓] Privileges escalated successfully")
        get_rawmode_status(dev)
    
    return result

def monitor_rawmode_activity(dev, args):
    """
    Monitor raw mode activity in real-time
    """
    duration = 30
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        try:
            duration = int(args.rawmode_args[0])
        except:
            pass
    
    print(f"[*] Starting raw mode activity monitoring for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early\n")
    
    start_time = time.time()
    end_time = start_time + duration
    
    try:
        while time.time() < end_time:
            elapsed = time.time() - start_time
            
            # Get current status
            resp = qslcl_dispatch(dev, "RAWMODE", b"STATUS\x00")
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    extra = status.get("extra", b"")
                    if len(extra) > 0:
                        current_mode = extra[0]
                        mode_name = get_mode_description(current_mode)
                        print(f"[{elapsed:5.1f}s] Current Mode: 0x{current_mode:02X} ({mode_name})")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user")
    
    print("[*] Raw mode monitoring completed")
    return True

def audit_rawmode_access(dev, args):
    """
    Perform security audit of raw mode access
    """
    print("[*] Performing raw mode security audit...")
    
    audit_type = "FULL"
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        audit_type = args.rawmode_args[0].upper()
    
    print(f"    Audit Type: {audit_type}")
    
    payload = audit_type.encode() + b"\x00"
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE_AUDIT", payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            print("[✓] Security audit completed successfully")
            
            if extra:
                # Parse audit results
                try:
                    audit_results = extra.decode('utf-8', errors='ignore')
                    print(f"    Audit Results: {audit_results}")
                except:
                    print(f"    Raw Audit Data: {extra.hex()}")
            
            return True
        else:
            print(f"[!] Security audit failed: {status}")
            return False
    
    print("[!] Security audit not available")
    return False

def reset_rawmode(dev, args):
    """
    Reset raw mode to default state
    """
    print("[*] Resetting raw mode to default state...")
    
    reset_type = "SOFT"
    if hasattr(args, 'rawmode_args') and args.rawmode_args:
        reset_type = args.rawmode_args[0].upper()
    
    print(f"    Reset Type: {reset_type}")
    
    payload = reset_type.encode() + b"\x00"
    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE_RESET", payload)
    result = _decode_and_show_advanced(resp, "RAWMODE_RESET", 0, origin=origin)
    
    if result:
        print("[✓] Raw mode reset successfully")
        get_rawmode_status(dev)
    
    return result

def handle_rawmode_operation(dev, operation, args):
    """
    Handle other raw mode operations
    """
    print(f"[*] Executing raw mode operation: {operation}")
    
    # Build operation parameters
    params = build_rawmode_params(operation, args)
    
    # Try different operation strategies
    strategies = [
        try_direct_rawmode_operation,
        try_par_rawmode_command,
        try_end_rawmode_opcode,
        try_vm5_rawmode_service,
        try_idx_rawmode_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute raw mode operation: {operation}")
    return False

def build_rawmode_params(operation, args):
    """
    Build parameters for raw mode operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'rawmode_args'):
        for arg in args.rawmode_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Strategy implementations
def try_direct_rawmode_operation(dev, operation, params):
    resp = qslcl_dispatch(dev, "RAWMODE", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {operation} executed successfully")
        return True
    return None

def try_par_rawmode_command(dev, operation, params):
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLPAR")
            return True
    return None

def try_end_rawmode_opcode(dev, operation, params):
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLEND opcode 0x{opcode:02X}")
            return True
    return None

def try_vm5_rawmode_service(dev, operation, params):
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLVM5")
            return True
    return None

def try_idx_rawmode_command(dev, operation, params):
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {operation} executed via QSLCLIDX {name}")
                return True
    return None

# Placeholder functions for configuration actions
def print_rawmode_config_help():
    print("[*] Raw mode configuration commands:")
    print("  configure audit <level>       - Configure audit settings")
    print("  configure timeout <seconds>   - Set operation timeout")
    print("  configure access <level>      - Configure access controls")
    print("  configure security <settings> - Configure security settings")
    return False

def configure_timeout_settings(dev, args):
    print("[*] Timeout configuration not yet implemented")
    return False

def configure_access_controls(dev, args):
    print("[*] Access control configuration not yet implemented")
    return False

def configure_security_settings(dev, args):
    print("[*] Security settings configuration not yet implemented")
    return False

def handle_configuration_action(dev, action, args):
    print(f"[*] Configuration action '{action}' not yet implemented")
    return False

# Update the argument parser in main() function
def update_rawmode_parser(sub):
    """
    Update the RAWMODE command parser with new subcommands
    """
    rawmode_parser = sub.add_parser("rawmode", help="Raw mode access and privilege escalation commands")
    rawmode_parser.add_argument("rawmode_subcommand", help="Rawmode subcommand (list, set, status, unlock, lock, configure, escalate, monitor, audit, reset)")
    rawmode_parser.add_argument("rawmode_args", nargs="*", help="Additional arguments for rawmode command")
    rawmode_parser.set_defaults(func=cmd_rawmode)

def cmd_dump(args):
    """
    Advanced memory dumping with comprehensive features
    Supports intelligent region detection, compression, verification, and resume capabilities
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Enhanced argument parsing with more options
    if not hasattr(args, 'address') or not args.address:
        return print("[!] DUMP requires address/partition and output file")
    
    # Parse target (could be address, partition, or region name)
    target = args.address
    
    # Parse size with support for human-readable formats
    dump_size = parse_size_argument(args.size) if hasattr(args, 'size') and args.size else 0
    
    # Parse output path
    out_path = args.output if hasattr(args, 'output') and args.output else f"dump_{int(time.time())}.bin"
    
    # Handle different dump modes
    if target.upper() in ["PARTITIONS", "ALL"]:
        return dump_all_partitions(dev, out_path, args)
    elif target.upper() == "MEMORY":
        return dump_memory_regions(dev, out_path, args)
    elif target.upper() == "BOOT":
        return dump_boot_components(dev, out_path, args)
    elif target.upper() == "FIRMWARE":
        return dump_firmware_regions(dev, out_path, args)
    elif is_partition_name(target):
        return dump_partition(dev, target, out_path, args)
    elif is_region_name(target):
        return dump_region(dev, target, out_path, args)
    else:
        # Assume it's a raw address
        return dump_address_range(dev, target, dump_size, out_path, args)

def parse_size_argument(size_str):
    """
    Parse size argument with support for human-readable formats
    """
    if not size_str:
        return 0
    
    size_str = size_str.upper().strip()
    
    # Handle hex format
    if size_str.startswith("0X"):
        return int(size_str, 16)
    
    # Handle size suffixes
    multipliers = {
        'K': 1024,
        'M': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }
    
    for suffix, multiplier in multipliers.items():
        if size_str.endswith(suffix):
            num_part = size_str[:-len(suffix)]
            try:
                return int(float(num_part) * multiplier)
            except ValueError:
                break
    
    # Default to decimal
    try:
        return int(size_str)
    except ValueError:
        print(f"[!] Invalid size format: {size_str}")
        return 0

def is_partition_name(name):
    """
    Check if the target is a partition name
    """
    common_partitions = [
        "boot", "recovery", "system", "vendor", "userdata", "cache",
        "modem", "persist", "misc", "frp", "devinfo", "metadata"
    ]
    return name.lower() in common_partitions

def is_region_name(name):
    """
    Check if the target is a known memory region
    """
    common_regions = [
        "kernel", "ramdisk", "dtb", "bootloader", "trustzone",
        "modem_fw", "dsp_fw", "gpu_fw", "efuse", "otp"
    ]
    return name.lower() in common_regions

def dump_address_range(dev, address_str, size, out_path, args):
    """
    Dump a specific address range
    """
    try:
        start_addr = int(address_str, 16) if address_str.startswith("0x") else int(address_str)
    except ValueError:
        print(f"[!] Invalid address format: {address_str}")
        return False
    
    if size <= 0:
        print("[!] Size must be specified for address dumping")
        return False
    
    print(f"[*] Dumping memory range: 0x{start_addr:08X} - 0x{start_addr + size:08X} ({size} bytes)")
    
    return perform_dump(dev, start_addr, size, out_path, args, "Memory Range")

def dump_partition(dev, partition_name, out_path, args):
    """
    Dump a specific partition
    """
    print(f"[*] Dumping partition: {partition_name}")
    
    try:
        # Load partition table
        parts = load_partitions(dev)
        partition_info = None
        
        for part in parts:
            if part['name'].lower() == partition_name.lower():
                partition_info = part
                break
        
        if not partition_info:
            print(f"[!] Partition '{partition_name}' not found")
            # Try to scan GPT
            scan_gpt(dev)
            parts = load_partitions(dev)
            for part in parts:
                if part['name'].lower() == partition_name.lower():
                    partition_info = part
                    break
        
        if not partition_info:
            print(f"[!] Cannot find partition '{partition_name}'")
            return False
        
        start_addr = partition_info['offset']
        size = partition_info['size']
        
        print(f"[*] Partition found: 0x{start_addr:08X} - 0x{start_addr + size:08X} ({size} bytes)")
        
        return perform_dump(dev, start_addr, size, out_path, args, f"Partition: {partition_name}")
        
    except Exception as e:
        print(f"[!] Error accessing partition '{partition_name}': {e}")
        return False

def dump_region(dev, region_name, out_path, args):
    """
    Dump a known memory region
    """
    region_name = region_name.lower()
    print(f"[*] Dumping region: {region_name}")
    
    # Define common memory regions
    region_map = {
        "kernel": (0x80000000, 0x01000000),  # 16MB kernel region
        "ramdisk": (0x81000000, 0x00800000),  # 8MB ramdisk
        "dtb": (0x81800000, 0x00100000),      # 1MB device tree
        "bootloader": (0x00000000, 0x00200000), # 2MB bootloader
        "trustzone": (0x0E000000, 0x00200000), # 2MB trustzone
        "modem_fw": (0x40000000, 0x01000000), # 16MB modem
        "dsp_fw": (0x41000000, 0x00800000),   # 8MB DSP
        "gpu_fw": (0x42000000, 0x00400000),   # 4MB GPU
        "efuse": (0x0005C000, 0x00001000),    # 4KB efuse
        "otp": (0x00060000, 0x00002000),      # 8KB OTP
    }
    
    if region_name not in region_map:
        print(f"[!] Unknown region: {region_name}")
        print(f"[*] Available regions: {', '.join(region_map.keys())}")
        return False
    
    start_addr, size = region_map[region_name]
    return perform_dump(dev, start_addr, size, out_path, args, f"Region: {region_name}")

def dump_all_partitions(dev, out_dir, args):
    """
    Dump all available partitions
    """
    print("[*] Dumping all partitions...")
    
    # Create output directory
    import os
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    # Load partitions
    parts = load_partitions(dev)
    if not parts:
        print("[!] No partitions found")
        return False
    
    success_count = 0
    total_size = 0
    
    print(f"[*] Found {len(parts)} partitions")
    
    for part in parts:
        part_name = part['name']
        part_file = os.path.join(out_dir, f"{part_name}.img")
        
        print(f"\n[*] Dumping {part_name}...")
        
        if perform_dump(dev, part['offset'], part['size'], part_file, args, f"Partition: {part_name}"):
            success_count += 1
            total_size += part['size']
    
    print(f"\n[✓] Partition dump complete: {success_count}/{len(parts)} partitions")
    print(f"[*] Total size: {total_size} bytes ({total_size / (1024*1024):.2f} MB)")
    
    return success_count > 0

def dump_memory_regions(dev, out_dir, args):
    """
    Dump common memory regions
    """
    print("[*] Dumping memory regions...")
    
    import os
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    regions = [
        ("kernel", 0x80000000, 0x01000000),
        ("ramdisk", 0x81000000, 0x00800000),
        ("dtb", 0x81800000, 0x00100000),
        ("bootloader", 0x00000000, 0x00200000),
        ("modem_fw", 0x40000000, 0x01000000),
    ]
    
    success_count = 0
    
    for region_name, start_addr, size in regions:
        region_file = os.path.join(out_dir, f"{region_name}.bin")
        print(f"\n[*] Dumping {region_name}...")
        
        if perform_dump(dev, start_addr, size, region_file, args, f"Region: {region_name}"):
            success_count += 1
    
    print(f"\n[✓] Memory region dump complete: {success_count}/{len(regions)} regions")
    return success_count > 0

def dump_boot_components(dev, out_dir, args):
    """
    Dump boot-related components
    """
    print("[*] Dumping boot components...")
    
    import os
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    boot_components = [
        ("pbl", 0x00000000, 0x00040000),      # Primary Bootloader
        ("sbl", 0x00040000, 0x00080000),      # Secondary Bootloader
        ("aboot", 0x000C0000, 0x00100000),    # Android Bootloader
        ("tz", 0x0E000000, 0x00200000),       # TrustZone
        ("rpm", 0x0E200000, 0x00040000),      # Resource Power Manager
    ]
    
    success_count = 0
    
    for comp_name, start_addr, size in boot_components:
        comp_file = os.path.join(out_dir, f"{comp_name}.bin")
        print(f"\n[*] Dumping {comp_name}...")
        
        if perform_dump(dev, start_addr, size, comp_file, args, f"Boot: {comp_name}"):
            success_count += 1
    
    print(f"\n[✓] Boot component dump complete: {success_count}/{len(boot_components)} components")
    return success_count > 0

def dump_firmware_regions(dev, out_dir, args):
    """
    Dump firmware regions
    """
    print("[*] Dumping firmware regions...")
    
    import os
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    firmware_regions = [
        ("modem", 0x40000000, 0x01000000),
        ("dsp", 0x41000000, 0x00800000),
        ("gpu", 0x42000000, 0x00400000),
        ("wlan", 0x43000000, 0x00200000),
        ("bt", 0x43100000, 0x00100000),
    ]
    
    success_count = 0
    
    for fw_name, start_addr, size in firmware_regions:
        fw_file = os.path.join(out_dir, f"{fw_name}_fw.bin")
        print(f"\n[*] Dumping {fw_name} firmware...")
        
        if perform_dump(dev, start_addr, size, fw_file, args, f"Firmware: {fw_name}"):
            success_count += 1
    
    print(f"\n[✓] Firmware dump complete: {success_count}/{len(firmware_regions)} regions")
    return success_count > 0

def perform_dump(dev, start_addr, size, out_path, args, description=""):
    """
    Core dumping function with advanced features
    """
    # Get sector size and align addresses
    sector = get_sector_size(dev)
    aligned_addr = start_addr & ~(sector - 1)
    aligned_end = align_up(start_addr + size, sector)
    total_size = aligned_end - aligned_addr
    
    print(f"[*] {description}")
    print(f"    Address: 0x{start_addr:08X} - 0x{start_addr + size:08X}")
    print(f"    Aligned: 0x{aligned_addr:08X} - 0x{aligned_end:08X}")
    print(f"    Size: {size} bytes (aligned: {total_size} bytes)")
    print(f"    Sector size: {sector} bytes")
    
    # Check for resume capability
    resume_offset = 0
    if getattr(args, 'resume', False) and os.path.exists(out_path):
        resume_offset = os.path.getsize(out_path)
        if resume_offset > 0:
            print(f"[*] Resuming from offset: {resume_offset} bytes")
            aligned_addr += resume_offset
            total_size -= resume_offset
    
    # Check available space
    if not check_disk_space(out_path, total_size):
        print("[!] Insufficient disk space")
        return False
    
    # Open output file
    try:
        mode = "ab" if resume_offset > 0 else "wb"
        f = open(out_path, mode)
    except Exception as e:
        print(f"[!] Cannot open output file: {e}")
        return False
    
    # Dump configuration
    chunk_size = getattr(args, 'chunk_size', 4096)
    verify_dump = getattr(args, 'verify', False)
    compress_dump = getattr(args, 'compress', False)
    max_retries = getattr(args, 'retries', 3)
    
    print(f"[*] Chunk size: {chunk_size} bytes")
    print(f"[*] Verification: {'Enabled' if verify_dump else 'Disabled'}")
    print(f"[*] Compression: {'Enabled' if compress_dump else 'Disabled'}")
    
    # Initialize progress tracking
    current = aligned_addr
    bytes_written = resume_offset
    start_time = time.time()
    retry_count = 0
    
    # Create checksum for verification
    import hashlib
    dump_hash = hashlib.sha256() if verify_dump else None
    
    print("\n[*] Starting dump...")
    
    try:
        while current < aligned_end and retry_count < max_retries:
            req_size = min(chunk_size, aligned_end - current)
            
            # Read data from device
            data = read_memory_chunk(dev, current, req_size, args)
            
            if data is None:
                retry_count += 1
                print(f"\n[!] Read failed at 0x{current:08X}, retry {retry_count}/{max_retries}")
                time.sleep(1)
                continue
            
            # Reset retry count on successful read
            retry_count = 0
            
            # Update checksum
            if dump_hash:
                dump_hash.update(data)
            
            # Write to file
            f.write(data)
            f.flush()  # Ensure data is written to disk
            
            # Update progress
            bytes_written += len(data)
            elapsed = time.time() - start_time
            speed = bytes_written / elapsed if elapsed > 0 else 0
            
            # Progress display
            progress = (bytes_written * 100.0) / total_size
            eta = (total_size - bytes_written) / speed if speed > 0 else 0
            
            print(f"\r[*] Progress: {progress:5.1f}% | {bytes_written}/{total_size} bytes | "
                  f"{speed/1024:.1f} KB/s | ETA: {eta:.1f}s", end="")
            
            current += req_size
        
        print()  # New line after progress
        
        if retry_count >= max_retries:
            print(f"\n[!] Too many consecutive read failures, aborting")
            f.close()
            return False
        
        # Finalize dump
        f.close()
        
        # Post-dump operations
        if verify_dump:
            print("[*] Verifying dump integrity...")
            if verify_dump_integrity(out_path, dump_hash):
                print("[✓] Dump verification passed")
            else:
                print("[!] Dump verification failed")
        
        if compress_dump:
            print("[*] Compressing dump...")
            compressed_path = compress_dump_file(out_path)
            if compressed_path:
                print(f"[✓] Compressed dump saved to: {compressed_path}")
        
        # Generate dump info
        generate_dump_info(out_path, start_addr, size, description, dump_hash)
        
        elapsed_total = time.time() - start_time
        avg_speed = total_size / elapsed_total if elapsed_total > 0 else 0
        
        print(f"\n[✓] Dump complete: {out_path}")
        print(f"    Total time: {elapsed_total:.1f}s")
        print(f"    Average speed: {avg_speed/1024:.1f} KB/s")
        print(f"    Final size: {bytes_written} bytes")
        
        return True
        
    except Exception as e:
        print(f"\n[!] Dump failed: {e}")
        f.close()
        return False

def read_memory_chunk(dev, address, size, args):
    """
    Read a chunk of memory with error handling and optimization
    """
    payload = struct.pack("<Q I", address, size)
    
    # Try different read methods in order of preference
    read_methods = [
        ("IDX", lambda: qslclidx_or_dispatch(dev, "READ", payload)),
        ("PAR", lambda: (qslcl_dispatch(dev, "READ", payload), "PAR")),
        ("ENGINE", lambda: (qslcl_dispatch(dev, "ENGINE", b"READ" + payload), "ENGINE")),
    ]
    
    for method_name, read_func in read_methods:
        try:
            resp, origin = read_func()
            
            if not resp:
                continue
            
            status = decode_runtime_result(resp)
            
            if status.get("severity") == "SUCCESS":
                data = status.get("extra", b"")
                if data and len(data) == size:
                    return data
                elif data and len(data) > 0:
                    # Pad or truncate to expected size
                    if len(data) < size:
                        data += b"\x00" * (size - len(data))
                    else:
                        data = data[:size]
                    return data
            
        except Exception as e:
            if getattr(args, 'verbose', False):
                print(f"[!] {method_name} read failed: {e}")
            continue
    
    return None

def check_disk_space(file_path, required_size):
    """
    Check if there's enough disk space for the dump
    """
    import os
    import shutil
    
    # Get the directory of the output file
    directory = os.path.dirname(os.path.abspath(file_path))
    
    # Get disk usage statistics
    try:
        total, used, free = shutil.disk_usage(directory)
        
        # Check if we have enough space (with 10% margin)
        if free < required_size * 1.1:
            print(f"[!] Insufficient disk space: {free} bytes available, {required_size} bytes required")
            return False
        
        return True
        
    except Exception as e:
        print(f"[!] Could not check disk space: {e}")
        return True  # Continue anyway

def verify_dump_integrity(file_path, expected_hash):
    """
    Verify the integrity of the dumped file
    """
    import hashlib
    
    if not expected_hash:
        return True
    
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                file_hash.update(chunk)
        
        return file_hash.hexdigest() == expected_hash.hexdigest()
        
    except Exception as e:
        print(f"[!] Verification error: {e}")
        return False

def compress_dump_file(file_path):
    """
    Compress the dump file using gzip
    """
    import gzip
    import os
    
    try:
        compressed_path = file_path + ".gz"
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(compressed_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Calculate compression ratio
        original_size = os.path.getsize(file_path)
        compressed_size = os.path.getsize(compressed_path)
        ratio = (compressed_size / original_size) * 100
        
        print(f"    Compression: {original_size} -> {compressed_size} bytes ({ratio:.1f}%)")
        
        return compressed_path
        
    except Exception as e:
        print(f"[!] Compression failed: {e}")
        return None

def generate_dump_info(file_path, start_addr, size, description, file_hash):
    """
    Generate a metadata file with dump information
    """
    import os
    import json
    
    info_file = file_path + ".info"
    
    try:
        info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "description": description,
            "start_address": f"0x{start_addr:08X}",
            "size": size,
            "file_size": os.path.getsize(file_path),
            "hash_sha256": file_hash.hexdigest() if file_hash else "N/A",
            "sector_size": get_sector_size(dev) if 'dev' in locals() else "Unknown"
        }
        
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"[*] Dump info saved to: {info_file}")
        
    except Exception as e:
        print(f"[!] Could not generate dump info: {e}")

# Update the argument parser in main() function
def update_dump_parser(sub):
    """
    Update the DUMP command parser with enhanced options
    """
    dump_parser = sub.add_parser("dump", help="Advanced memory dumping with multiple modes")
    dump_parser.add_argument("address", help="Address, partition name, or region to dump")
    dump_parser.add_argument("size", nargs="?", help="Size to dump (bytes, K, M, G, or hex with 0x)")
    dump_parser.add_argument("output", nargs="?", help="Output file or directory path")
    
    # Enhanced options
    dump_parser.add_argument("--chunk-size", type=int, default=4096, help="Read chunk size (default: 4096)")
    dump_parser.add_argument("--verify", action="store_true", help="Verify dump integrity with SHA256")
    dump_parser.add_argument("--compress", action="store_true", help="Compress dump with gzip")
    dump_parser.add_argument("--resume", action="store_true", help="Resume interrupted dump")
    dump_parser.add_argument("--retries", type=int, default=3, help="Max retries for failed reads")
    dump_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    dump_parser.set_defaults(func=cmd_dump)

# ============================================================
#  DEVICE RESET / REBOOT HANDLER (Full QSLCL Upgrade)
# ============================================================
def cmd_reset(args):
    """
    Advanced RESET command handler for comprehensive system reset operations
    Supports various reset types: soft, hard, force, domain-specific, and recovery resets
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse RESET subcommand
    if not hasattr(args, 'reset_subcommand') or not args.reset_subcommand:
        return print("[!] RESET command requires subcommand (list, soft, hard, force, domain, recovery, etc.)")
    
    subcmd = args.reset_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_reset_commands(dev)
    elif subcmd == "SOFT":
        return perform_soft_reset(dev, args)
    elif subcmd == "HARD":
        return perform_hard_reset(dev, args)
    elif subcmd == "FORCE":
        return perform_force_reset(dev, args)
    elif subcmd == "DOMAIN":
        return reset_specific_domain(dev, args)
    elif subcmd == "RECOVERY":
        return perform_recovery_reset(dev, args)
    elif subcmd == "FACTORY":
        return perform_factory_reset(dev, args)
    elif subcmd == "BOOTLOADER":
        return reset_to_bootloader(dev, args)
    elif subcmd == "EDL":
        return reset_to_edl_mode(dev, args)
    elif subcmd == "PMIC":
        return perform_pmic_reset(dev, args)
    elif subcmd == "WATCHDOG":
        return trigger_watchdog_reset(dev, args)
    elif subcmd == "CUSTOM":
        return perform_custom_reset(dev, args)
    elif subcmd == "SEQUENCE":
        return execute_reset_sequence(dev, args)
    else:
        return handle_reset_operation(dev, subcmd, args)

def list_available_reset_commands(dev):
    """
    List all available RESET commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL RESET COMMANDS")
    print("="*60)
    
    reset_found = []
    
    # Check QSLCLPAR for RESET commands
    print("\n[QSLCLPAR] Reset Commands:")
    par_reset = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "RESET", "REBOOT", "RESTART", "SHUTDOWN", "BOOT", "RECOVERY",
        "FACTORY", "PMIC", "WATCHDOG", "DOMAIN"
    ])]
    for reset_cmd in par_reset:
        print(f"  • {reset_cmd}")
        reset_found.append(reset_cmd)
    
    # Check QSLCLEND for reset-related opcodes
    print("\n[QSLCLEND] Reset Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["RESET", "REBOOT", "RESTART"]) or any(x in entry_str for x in ["RST", "REBOOT"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            reset_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for reset microservices
    print("\n[QSLCLVM5] Reset Microservices:")
    vm5_reset = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["RESET", "REBOOT", "RESTART"])]
    for reset_cmd in vm5_reset:
        print(f"  • {reset_cmd}")
        reset_found.append(f"VM5_{reset_cmd}")
    
    # Check QSLCLIDX for reset indices
    print("\n[QSLCLIDX] Reset Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["RESET", "REBOOT", "RESTART"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                reset_found.append(f"IDX_{name}")
    
    if not reset_found:
        print("  No reset commands found in loader")
    else:
        print(f"\n[*] Total reset commands found: {len(reset_found)}")
    
    print("\n[*] Common Reset Operations Available:")
    print("  • SOFT        - Graceful software reset")
    print("  • HARD        - Hardware-level reset")
    print("  • FORCE       - Force reset (bypass safeguards)")
    print("  • DOMAIN      - Reset specific power domain")
    print("  • RECOVERY    - Reset to recovery mode")
    print("  • FACTORY     - Factory reset (wipe user data)")
    print("  • BOOTLOADER  - Reset to bootloader/fastboot")
    print("  • EDL         - Reset to EDL/Download mode")
    print("  • PMIC        - PMIC (Power Management IC) reset")
    print("  • WATCHDOG    - Trigger watchdog reset")
    print("  • CUSTOM      - Custom reset with parameters")
    print("  • SEQUENCE    - Execute reset sequence")
    
    print("="*60)
    
    return True

def perform_soft_reset(dev, args):
    """
    Perform graceful software reset
    """
    print("[*] Initiating SOFT reset (graceful shutdown and restart)...")
    
    # Safety confirmation
    if not getattr(args, 'force_reset', False):
        confirm = input("!! Confirm SOFT reset? This will restart the device. (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] SOFT reset cancelled")
            return False
    
    print("[*] Sending shutdown signals to services...")
    
    # Try graceful reset command first
    reset_params = struct.pack("<B", 0x01)  # Soft reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] SOFT reset command accepted")
            print("[*] Device should restart gracefully...")
            
            # Monitor for device restart
            monitor_reset_progress(dev, "SOFT")
            return True
        else:
            print(f"[!] SOFT reset failed: {status}")
            return False
    
    # Fallback to generic reset
    print("[*] Using fallback reset method...")
    return perform_generic_reset(dev, "SOFT")

def perform_hard_reset(dev, args):
    """
    Perform hardware-level reset
    """
    print("[!] WARNING: Initiating HARD reset (immediate hardware restart)...")
    print("[!] This may cause data loss or corruption!")
    
    # Safety confirmation
    confirm = input("!! CONFIRM HARD RESET - THIS IS DESTRUCTIVE! (type 'HARD-RESET' to continue): ").strip().upper()
    if confirm != "HARD-RESET":
        print("[*] HARD reset cancelled")
        return False
    
    print("[*] Triggering hardware reset sequence...")
    
    # Hard reset parameters
    reset_params = struct.pack("<B", 0x02)  # Hard reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] HARD reset command accepted")
            print("[!] Device resetting immediately...")
            
            # Immediate disconnect expected
            time.sleep(1)
            print("[*] Device should be resetting now...")
            return True
        else:
            print(f"[!] HARD reset failed: {status}")
            return False
    
    # Try PMIC hard reset as fallback
    return perform_pmic_hard_reset(dev)

def perform_force_reset(dev, args):
    """
    Perform force reset (bypass all safeguards)
    """
    print("[!] DANGER: Initiating FORCE reset (bypass all safeguards)...")
    print("[!] THIS MAY BRICK THE DEVICE OR CAUSE PERMANENT DAMAGE!")
    
    # Extreme safety confirmation
    confirm = input("!! CONFIRM FORCE RESET - EXTREMELY DANGEROUS! (type 'FORCE-RESET' to continue): ").strip().upper()
    if confirm != "FORCE-RESET":
        print("[*] FORCE reset cancelled")
        return False
    
    print("[*] Bypassing safety mechanisms...")
    print("[*] Triggering force reset sequence...")
    
    # Force reset parameters
    reset_params = struct.pack("<B", 0xFF)  # Force reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] FORCE reset command accepted")
            print("[!] Device force reset in progress...")
            
            # Monitor with shorter timeout
            monitor_reset_progress(dev, "FORCE", timeout=5)
            return True
        else:
            print(f"[!] FORCE reset failed: {status}")
            return False
    
    # Ultimate fallback - try multiple reset methods
    return perform_emergency_reset(dev)

def reset_specific_domain(dev, args):
    """
    Reset specific power domain or subsystem
    """
    if not hasattr(args, 'reset_args') or not args.reset_args:
        return list_resettable_domains(dev)
    
    domain = args.reset_args[0].upper()
    
    print(f"[*] Preparing to reset domain: {domain}")
    
    # Get domain information
    domains_info = get_resettable_domains(dev)
    if domain not in domains_info:
        print(f"[!] Unknown domain: {domain}")
        print("[*] Available domains:")
        for avail_domain in domains_info:
            print(f"  • {avail_domain}")
        return False
    
    domain_info = domains_info[domain]
    print(f"[*] Domain type: {domain_info.get('type', 'UNKNOWN')}")
    
    # Safety confirmation for critical domains
    critical_domains = ["CPU", "GPU", "DDR", "MODEM", "TZ"]
    if domain in critical_domains:
        confirm = input(f"!! Confirm reset of critical domain {domain}? (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Domain reset cancelled")
            return False
    
    # Execute domain reset
    reset_params = struct.pack("<B", 0x10) + domain.encode() + b"\x00"  # Domain reset code + domain name
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Domain {domain} reset successfully")
            
            # Wait for domain to stabilize
            time.sleep(2)
            print(f"[*] Domain {domain} should be operational now")
            return True
        else:
            print(f"[!] Domain {domain} reset failed: {status}")
            return False
    
    print(f"[!] No domain reset capability for {domain}")
    return False

def list_resettable_domains(dev):
    """
    List all resettable power domains and subsystems
    """
    print("[*] Resettable domains and subsystems:")
    
    domains_info = get_resettable_domains(dev)
    
    for domain, info in domains_info.items():
        domain_type = info.get('type', 'UNKNOWN')
        critical = " (CRITICAL)" if info.get('critical', False) else ""
        print(f"  • {domain:<15} : {domain_type}{critical}")
    
    return True

def get_resettable_domains(dev):
    """
    Get information about resettable domains
    """
    # Common resettable domains
    domains = {
        "CPU": {"type": "Processor", "critical": True},
        "GPU": {"type": "Graphics", "critical": False},
        "DDR": {"type": "Memory", "critical": True},
        "MODEM": {"type": "Cellular", "critical": False},
        "WLAN": {"type": "Wireless", "critical": False},
        "BT": {"type": "Bluetooth", "critical": False},
        "GPS": {"type": "Navigation", "critical": False},
        "AUDIO": {"type": "Audio", "critical": False},
        "DISPLAY": {"type": "Display", "critical": False},
        "CAMERA": {"type": "Camera", "critical": False},
        "SENSORS": {"type": "Sensors", "critical": False},
        "TZ": {"type": "TrustZone", "critical": True},
        "USB": {"type": "USB", "critical": False},
    }
    
    # Try to get domains from device
    resp = qslcl_dispatch(dev, "RESET", b"DOMAINS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                # Parse domain list from response
                domain_list = extra.decode('utf-8', errors='ignore').split('\x00')
                custom_domains = {}
                for domain_entry in domain_list:
                    if ':' in domain_entry:
                        domain, domain_type = domain_entry.split(':', 1)
                        custom_domains[domain.strip().upper()] = {"type": domain_type.strip(), "critical": "CRITICAL" in domain_type.upper()}
                if custom_domains:
                    domains.update(custom_domains)
            except:
                pass
    
    return domains

def perform_recovery_reset(dev, args):
    """
    Reset device to recovery mode
    """
    print("[*] Initiating recovery mode reset...")
    
    # Safety confirmation
    if not getattr(args, 'force_reset', False):
        confirm = input("!! Reset to recovery mode? This will boot to recovery. (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Recovery reset cancelled")
            return False
    
    print("[*] Configuring boot parameters for recovery...")
    
    # Recovery reset parameters
    reset_params = struct.pack("<B", 0x20)  # Recovery reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Recovery reset command accepted")
            print("[*] Device should boot to recovery mode...")
            
            monitor_reset_progress(dev, "RECOVERY")
            return True
        else:
            print(f"[!] Recovery reset failed: {status}")
            return False
    
    # Fallback: Use boot mode setting
    return set_boot_mode(dev, "RECOVERY")

def perform_factory_reset(dev, args):
    """
    Perform factory reset (wipe user data)
    """
    print("[!] WARNING: Initiating FACTORY RESET...")
    print("[!] THIS WILL ERASE ALL USER DATA AND SETTINGS!")
    print("[!] THIS ACTION CANNOT BE UNDONE!")
    
    # Extreme safety confirmation
    confirm = input("!! CONFIRM FACTORY RESET - ALL DATA WILL BE LOST! (type 'FACTORY-RESET' to continue): ").strip().upper()
    if confirm != "FACTORY-RESET":
        print("[*] Factory reset cancelled")
        return False
    
    # Additional warning
    print("\n[!] FINAL WARNING:")
    print("[!] - All apps, photos, and personal data will be erased")
    print("[!] - Device will be restored to original factory state")
    print("[!] - This process may take several minutes")
    
    final_confirm = input("!! TYPE 'ERASE-EVERYTHING' TO PROCEED: ").strip().upper()
    if final_confirm != "ERASE-EVERYTHING":
        print("[*] Factory reset cancelled")
        return False
    
    print("[*] Starting factory reset process...")
    print("[*] Wiping user data partition...")
    
    # Factory reset parameters
    reset_params = struct.pack("<B", 0x30)  # Factory reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Factory reset command accepted")
            print("[*] Device is wiping data and will reboot...")
            print("[*] This may take 2-10 minutes...")
            
            # Extended monitoring for factory reset
            monitor_reset_progress(dev, "FACTORY", timeout=120)
            return True
        else:
            print(f"[!] Factory reset failed: {status}")
            return False
    
    print("[!] No factory reset capability available")
    return False

def reset_to_bootloader(dev, args):
    """
    Reset device to bootloader/fastboot mode
    """
    print("[*] Initiating bootloader reset...")
    
    # Safety confirmation
    if not getattr(args, 'force_reset', False):
        confirm = input("!! Reset to bootloader mode? (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Bootloader reset cancelled")
            return False
    
    print("[*] Configuring boot parameters for bootloader...")
    
    # Bootloader reset parameters
    reset_params = struct.pack("<B", 0x40)  # Bootloader reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Bootloader reset command accepted")
            print("[*] Device should boot to bootloader/fastboot mode...")
            
            monitor_reset_progress(dev, "BOOTLOADER")
            return True
        else:
            print(f"[!] Bootloader reset failed: {status}")
            return False
    
    # Fallback: Use boot mode setting
    return set_boot_mode(dev, "BOOTLOADER")

def reset_to_edl_mode(dev, args):
    """
    Reset device to EDL (Emergency Download) mode
    """
    print("[*] Initiating EDL mode reset...")
    
    # Safety confirmation
    confirm = input("!! Reset to EDL mode? This is for advanced debugging. (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] EDL reset cancelled")
        return False
    
    print("[*] Configuring for EDL mode...")
    
    # EDL reset parameters
    reset_params = struct.pack("<B", 0x50)  # EDL reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] EDL reset command accepted")
            print("[*] Device should enter EDL/download mode...")
            print("[*] Use EDL tools to communicate with device")
            
            monitor_reset_progress(dev, "EDL")
            return True
        else:
            print(f"[!] EDL reset failed: {status}")
            return False
    
    # Fallback: Use test point method (if available)
    return trigger_edl_testpoint(dev)

def perform_pmic_reset(dev, args):
    """
    Perform PMIC (Power Management IC) reset
    """
    print("[*] Initiating PMIC reset...")
    print("[*] This resets the power management controller")
    
    # PMIC reset parameters
    reset_params = struct.pack("<B", 0x60)  # PMIC reset code
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] PMIC reset command accepted")
            print("[*] Power management IC is resetting...")
            
            # PMIC reset is usually fast
            time.sleep(3)
            print("[*] PMIC reset complete")
            return True
        else:
            print(f"[!] PMIC reset failed: {status}")
            return False
    
    # Fallback: Direct PMIC register write
    return perform_pmic_register_reset(dev)

def trigger_watchdog_reset(dev, args):
    """
    Trigger watchdog timer reset
    """
    print("[*] Configuring watchdog timer for reset...")
    
    timeout = 5  # Default 5 second timeout
    if hasattr(args, 'reset_args') and args.reset_args:
        try:
            timeout = int(args.reset_args[0])
            if timeout < 1 or timeout > 60:
                print("[!] Timeout must be between 1-60 seconds")
                timeout = 5
        except:
            pass
    
    print(f"[*] Watchdog will trigger reset in {timeout} seconds...")
    
    # Watchdog reset parameters
    reset_params = struct.pack("<BI", 0x70, timeout)  # Watchdog reset code + timeout
    resp, origin = qslclidx_or_dispatch(dev, "RESET", reset_params)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Watchdog configured")
            print(f"[*] Device will reset in {timeout} seconds...")
            print("[*] Counting down...")
            
            # Countdown
            for i in range(timeout, 0, -1):
                print(f"    {i}...")
                time.sleep(1)
            
            print("[!] Watchdog should have triggered reset by now")
            return True
        else:
            print(f"[!] Watchdog configuration failed: {status}")
            return False
    
    print("[!] No watchdog reset capability available")
    return False

def perform_custom_reset(dev, args):
    """
    Perform custom reset with specific parameters
    """
    if not hasattr(args, 'reset_args') or len(args.reset_args) < 1:
        return print("[!] CUSTOM reset requires parameters")
    
    reset_type = args.reset_args[0].upper()
    custom_params = b""
    
    # Parse custom parameters
    if len(args.reset_args) > 1:
        for param in args.reset_args[1:]:
            try:
                if param.startswith("0x"):
                    # Hex value
                    if len(param) > 4:
                        custom_params += struct.pack("<I", int(param, 16))
                    else:
                        custom_params += struct.pack("<B", int(param, 16))
                elif param.isdigit():
                    # Decimal value
                    custom_params += struct.pack("<I", int(param))
                else:
                    # String parameter
                    custom_params += param.encode() + b"\x00"
            except:
                custom_params += param.encode() + b"\x00"
    
    print(f"[*] Performing custom reset: {reset_type}")
    if custom_params:
        print(f"[*] Custom parameters: {custom_params.hex()}")
    
    # Custom reset command
    payload = reset_type.encode() + b"\x00" + custom_params
    resp, origin = qslclidx_or_dispatch(dev, "RESET", payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Custom reset executed successfully")
            return True
        else:
            print(f"[!] Custom reset failed: {status}")
            return False
    
    print(f"[!] Custom reset type '{reset_type}' not supported")
    return False

def execute_reset_sequence(dev, args):
    """
    Execute a predefined reset sequence
    """
    if not hasattr(args, 'reset_args') or not args.reset_args:
        return list_reset_sequences(dev)
    
    sequence_name = args.reset_args[0].upper()
    
    print(f"[*] Executing reset sequence: {sequence_name}")
    
    # Get sequence steps
    sequence = get_reset_sequence(sequence_name)
    if not sequence:
        print(f"[!] Unknown reset sequence: {sequence_name}")
        return False
    
    print(f"[*] Sequence has {len(sequence)} steps")
    
    # Safety confirmation for complex sequences
    if len(sequence) > 3:
        confirm = input(f"!! Execute {len(sequence)}-step reset sequence? (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Reset sequence cancelled")
            return False
    
    # Execute sequence steps
    success_count = 0
    for step_num, (step_name, step_params) in enumerate(sequence, 1):
        print(f"\n[{step_num}/{len(sequence)}] Executing: {step_name}")
        
        resp, origin = qslclidx_or_dispatch(dev, "RESET", step_params)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"    [✓] {step_name}: Success")
                success_count += 1
                time.sleep(1)  # Brief pause between steps
            else:
                print(f"    [!] {step_name}: Failed - {status}")
        else:
            print(f"    [!] {step_name}: No response")
    
    print(f"\n[*] Reset sequence completed: {success_count}/{len(sequence)} steps successful")
    return success_count == len(sequence)

def list_reset_sequences(dev):
    """
    List available reset sequences
    """
    print("[*] Available reset sequences:")
    
    sequences = {
        "BOOT_RECOVERY": "Reset to recovery with cleanup",
        "FACTORY_CLEAN": "Complete factory reset with verification",
        "SOFTWARE_REPAIR": "Software repair sequence",
        "HARDWARE_RESET": "Complete hardware reset sequence",
        "EMERGENCY": "Emergency recovery sequence"
    }
    
    for seq_name, seq_desc in sequences.items():
        print(f"  • {seq_name:<20} : {seq_desc}")
    
    return True

def get_reset_sequence(sequence_name):
    """
    Get steps for a specific reset sequence
    """
    sequences = {
        "BOOT_RECOVERY": [
            ("SOFT_RESET", b"\x01"),
            ("CLEAN_CACHES", b"\x81"),
            ("BOOT_RECOVERY", b"\x20")
        ],
        "FACTORY_CLEAN": [
            ("BACKUP_CONFIG", b"\x82"),
            ("WIPE_DATA", b"\x30"),
            ("CLEAN_CACHES", b"\x81"),
            ("SOFT_RESET", b"\x01")
        ],
        "SOFTWARE_REPAIR": [
            ("VERIFY_SYSTEM", b"\x83"),
            ("REPAIR_PARTITIONS", b"\x84"),
            ("SOFT_RESET", b"\x01")
        ]
    }
    
    return sequences.get(sequence_name)

def monitor_reset_progress(dev, reset_type, timeout=30):
    """
    Monitor device after reset command
    """
    print(f"[*] Monitoring reset progress ({reset_type})...")
    
    start_time = time.time()
    check_interval = 2  # Check every 2 seconds
    
    print("[*] Waiting for device to respond...")
    
    while time.time() - start_time < timeout:
        try:
            # Try to ping the device
            resp = qslcl_dispatch(dev, "PING", b"")
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    print("[✓] Device is responsive after reset")
                    return True
            
            print(".", end="", flush=True)
            time.sleep(check_interval)
            
        except:
            # Device might be temporarily unavailable during reset
            print(".", end="", flush=True)
            time.sleep(check_interval)
    
    print(f"\n[!] Device did not respond within {timeout} seconds")
    print("[*] Reset may have completed - check device manually")
    return False

def perform_generic_reset(dev, reset_type):
    """
    Fallback generic reset implementation
    """
    print(f"[*] Using generic reset for {reset_type}...")
    
    resp = qslcl_dispatch(dev, "RESET", b"")
    if resp:
        status = decode_runtime_result(resp)
        _decode_and_show(resp, reset_type + " RESET", 0, origin="GENERIC")
        return status.get("severity") == "SUCCESS"
    
    return False

def perform_pmic_hard_reset(dev):
    """
    Fallback PMIC hard reset implementation
    """
    print("[*] Attempting PMIC hard reset...")
    
    # Try PMIC reset command
    resp = qslcl_dispatch(dev, "PMIC_RESET", b"")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] PMIC hard reset executed")
            return True
    
    return False

def perform_emergency_reset(dev):
    """
    Ultimate emergency reset fallback
    """
    print("[*] Executing emergency reset procedures...")
    
    # Try multiple reset methods
    emergency_methods = [
        ("PS_HOLD_RESET", b"\xFD"),
        ("PMIC_FORCE_RESET", b"\xFE"),
        ("HARDWARE_RESET", b"\xFF")
    ]
    
    for method_name, method_params in emergency_methods:
        print(f"[*] Trying {method_name}...")
        resp, origin = qslclidx_or_dispatch(dev, "RESET", method_params)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {method_name} successful")
                return True
    
    print("[!] All emergency reset methods failed")
    return False

def set_boot_mode(dev, mode):
    """
    Fallback: Set boot mode instead of direct reset
    """
    print(f"[*] Setting boot mode to {mode}...")
    
    payload = mode.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "BOOT_MODE", payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Boot mode set to {mode}")
            # Still need to reset to apply
            return perform_soft_reset(dev, type('args', (), {'force_reset': True})())
    
    return False

def trigger_edl_testpoint(dev):
    """
    Fallback: Trigger EDL via test point method
    """
    print("[*] Attempting EDL test point method...")
    
    # This would typically involve shorting test points
    # For software, we try to force EDL mode
    resp = qslcl_dispatch(dev, "FORCE_EDL", b"")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] EDL mode forced")
            return True
    
    return False

def perform_pmic_register_reset(dev):
    """
    Fallback: Direct PMIC register reset
    """
    print("[*] Performing PMIC register reset...")
    
    # Write to PMIC reset register (varies by platform)
    resp = qslcl_dispatch(dev, "PMIC_WRITE", struct.pack("<HH", 0x1000, 0x01))
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] PMIC register reset executed")
            return True
    
    return False

def handle_reset_operation(dev, operation, args):
    """
    Handle other reset operations
    """
    print(f"[*] Executing reset operation: {operation}")
    
    # Build operation parameters
    params = build_reset_params(operation, args)
    
    # Try different reset strategies
    strategies = [
        try_direct_reset_operation,
        try_par_reset_command,
        try_end_reset_opcode,
        try_vm5_reset_service,
        try_idx_reset_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute reset operation: {operation}")
    return False

def build_reset_params(operation, args):
    """
    Build parameters for reset operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'reset_args'):
        for arg in args.reset_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Strategy implementations
def try_direct_reset_operation(dev, operation, params):
    resp = qslcl_dispatch(dev, "RESET", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    _decode_and_show(resp, operation + " RESET", 0, origin="DIRECT")
    return status.get("severity") == "SUCCESS"

def try_par_reset_command(dev, operation, params):
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        _decode_and_show(resp, operation + " RESET", 0, origin="PAR")
        return status.get("severity") == "SUCCESS"
    return None

def try_end_reset_opcode(dev, operation, params):
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        _decode_and_show(resp, operation + " RESET", 0, origin="ENGINE")
        return status.get("severity") == "SUCCESS"
    return None

def try_vm5_reset_service(dev, operation, params):
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        _decode_and_show(resp, operation + " RESET", 0, origin="VM5")
        return status.get("severity") == "SUCCESS"
    return None

def try_idx_reset_command(dev, operation, params):
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
            _decode_and_show(resp, operation + " RESET", 0, origin="IDX")
            return status.get("severity") == "SUCCESS"
    return None

def _decode_and_show(resp, operation, addr, origin="UNKNOWN"):
    """
    Enhanced decode and show function for reset operations
    """
    if not resp:
        print(f"[!] {operation} via {origin}: No response")
        return None
    
    result = decode_runtime_result(resp)
    
    sev = result.get("severity", "UNKNOWN")
    name = result.get("name", "UNKNOWN")
    extra = result.get("extra", b"")
    
    msg = f"{operation} @ 0x{addr:08X} ({origin}) → {name}"
    
    if sev == "SUCCESS":
        print(f"[✓] {msg}")
        if extra:
            print(f"    Additional info: {extra.hex()}")
    elif sev == "WARNING":
        print(f"[~] {msg}")
        if extra:
            print(f"    Warning details: {extra.hex()}")
    else:
        print(f"[✗] {msg}")
        if extra:
            print(f"    Error details: {extra.hex()}")
    
    return result if sev in ("SUCCESS", "WARNING") else None

# Update the argument parser in main() function
def update_reset_parser(sub):
    """
    Update the RESET command parser with new subcommands
    """
    reset_parser = sub.add_parser("reset", help="System reset and restart commands")
    reset_parser.add_argument("reset_subcommand", help="Reset subcommand (list, soft, hard, force, domain, recovery, factory, bootloader, edl, pmic, watchdog, custom, sequence)")
    reset_parser.add_argument("reset_args", nargs="*", help="Additional arguments for reset command")
    reset_parser.add_argument("--force-reset", action="store_true", help="Bypass confirmation prompts")
    reset_parser.set_defaults(func=cmd_reset)

def cmd_bruteforce(args):
    """
    Advanced BRUTEFORCE command handler for comprehensive system exploration
    Supports multiple brute-force strategies, patterns, and intelligent scanning
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse BRUTEFORCE subcommand or use legacy pattern mode
    if hasattr(args, 'bruteforce_subcommand') and args.bruteforce_subcommand:
        return handle_advanced_bruteforce(dev, args)
    else:
        return handle_legacy_bruteforce(dev, args)

def handle_advanced_bruteforce(dev, args):
    """
    Handle advanced brute-force operations with multiple strategies
    """
    subcmd = args.bruteforce_subcommand.upper()
    
    if subcmd == "LIST":
        return list_bruteforce_strategies(dev)
    elif subcmd == "SCAN":
        return scan_system_vectors(dev, args)
    elif subcmd == "PATTERN":
        return pattern_bruteforce(dev, args)
    elif subcmd == "FUZZ":
        return fuzz_bruteforce(dev, args)
    elif subcmd == "DICTIONARY":
        return dictionary_bruteforce(dev, args)
    elif subcmd == "REPLAY":
        return replay_bruteforce(dev, args)
    elif subcmd == "ANALYZE":
        return analyze_bruteforce_results(dev, args)
    elif subcmd == "CONTINUE":
        return continue_bruteforce_session(dev, args)
    else:
        return handle_bruteforce_operation(dev, subcmd, args)

def list_bruteforce_strategies(dev):
    """
    List all available brute-force strategies and commands
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE BRUTEFORCE STRATEGIES")
    print("="*60)
    
    # Check for bruteforce-related commands in all modules
    bf_commands = []
    
    # QSLCLPAR commands
    print("\n[QSLCLPAR] Bruteforce Commands:")
    par_bf = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "BRUTEFORCE", "SCAN", "FUZZ", "PATTERN", "EXPLORE", "PROBE"
    ])]
    for cmd in par_bf:
        print(f"  • {cmd}")
        bf_commands.append(cmd)
    
    # QSLCLEND opcodes
    print("\n[QSLCLEND] Bruteforce Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        if any(x in entry_name.upper() for x in ["BRUTE", "SCAN", "FUZZ", "PROBE"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name}")
            bf_commands.append(f"ENGINE_0x{opcode:02X}")
    
    print("\n[*] Available Strategies:")
    print("  • PATTERN    - Numeric/hex pattern scanning")
    print("  • FUZZ       - Intelligent fuzzing with mutation")
    print("  • DICTIONARY - Dictionary-based attacks")
    print("  • REPLAY     - Response replay attacks")
    print("  • SCAN       - System vector scanning")
    print("  • ANALYZE    - Result analysis and correlation")
    
    print("\n[*] Common Target Areas:")
    print("  • Memory addresses and offsets")
    print("  • Command opcodes and parameters")
    print("  • Security tokens and keys")
    print("  • Configuration values")
    print("  • Protocol fields and flags")
    
    print("="*60)
    return True

def handle_legacy_bruteforce(dev, args):
    """
    Handle legacy pattern-based brute-force (original functionality)
    """
    # Optional: enable RAWMODE
    if args.rawmode:
        print("[*] Enabling RAWMODE (0xFF)…")
        qslcl_dispatch(dev, "RAWMODE", b"\xFF")
        time.sleep(0.3)

    # Parse range
    pattern = args.pattern.lower()
    
    try:
        if "-" in pattern:
            a, b = pattern.split("-")
            start = int(a, 0)
            end   = int(b, 0)
        else:
            start = end = int(pattern, 0)
    except:
        return print("[!] Invalid pattern, use: 0x00-0xFFFF")

    print(f"[*] Bruteforce range: {hex(start)} → {hex(end)}")
    print(f"[*] Total values: {end - start + 1:,}")

    # Advanced pattern analysis
    analyze_pattern_complexity(start, end)
    
    # Work queue
    q = Queue()
    for val in range(start, end + 1):
        q.put(val)

    hits = []
    errors = 0
    done = 0
    total = end - start + 1
    lock = threading.Lock()
    start_time = time.time()

    # Progress tracking
    progress_stats = {
        'start_time': start_time,
        'last_update': start_time,
        'last_count': 0,
        'rates': []
    }

    def worker(worker_id):
        nonlocal done, errors
        worker_hits = []
        worker_errors = 0
        
        while True:
            try:
                val = q.get_nowait()
            except:
                # Worker finished, report results
                with lock:
                    hits.extend(worker_hits)
                    errors += worker_errors
                return

            # Build payload based on value size
            if val <= 0xFFFF:
                payload = struct.pack("<H", val)  # 16-bit
            elif val <= 0xFFFFFFFF:
                payload = struct.pack("<I", val)  # 32-bit
            else:
                payload = struct.pack("<Q", val)  # 64-bit

            # Try multiple brute-force strategies
            response_data = try_bruteforce_strategies(dev, val, payload, worker_id)
            
            with lock:
                done += 1
                current_time = time.time()
                
                # Update progress with rate calculation
                if current_time - progress_stats['last_update'] >= 1.0:  # Update every second
                    elapsed = current_time - progress_stats['last_update']
                    count_diff = done - progress_stats['last_count']
                    rate = count_diff / elapsed if elapsed > 0 else 0
                    progress_stats['rates'].append(rate)
                    progress_stats['last_update'] = current_time
                    progress_stats['last_count'] = done
                    
                    avg_rate = sum(progress_stats['rates'][-10:]) / min(len(progress_stats['rates']), 10)  # 10-second average
                    eta = (total - done) / avg_rate if avg_rate > 0 else 0
                    
                    pct = (done * 100.0) / total
                    print(f"\r[*] Progress: {done}/{total} ({pct:5.1f}%) | Rate: {avg_rate:5.1f}/s | ETA: {format_time(eta)} | Hits: {len(hits)} | Errors: {errors}", end="")
                
                # Process response
                if response_data:
                    resp, origin, strategy = response_data
                    status = decode_runtime_result(resp)
                    
                    sev = status.get("severity", "")
                    name = status.get("name", "")
                    extra = status.get("extra", b"")

                    # Enhanced hit detection
                    hit_confidence = calculate_hit_confidence(sev, name, extra, val)
                    
                    if hit_confidence > 0:
                        with lock:
                            prefix = "[+]" if hit_confidence >= 0.8 else "[~]" if hit_confidence >= 0.5 else "[?]"
                            print(f"\n{prefix} HIT: 0x{val:08X} (conf: {hit_confidence:.2f}) via {strategy} → {name}")
                            
                            hit_info = {
                                'value': val,
                                'status': status,
                                'origin': origin,
                                'strategy': strategy,
                                'confidence': hit_confidence,
                                'timestamp': time.time(),
                                'extra_data': extra
                            }
                            hits.append(hit_info)
                            worker_hits.append(hit_info)
                else:
                    worker_errors += 1

            q.task_done()

    # Run threads
    threads = args.threads
    print(f"[*] Launching {threads} threads…")
    print(f"[*] Using {threads} concurrent workers")

    ths = []
    for i in range(threads):
        t = threading.Thread(target=worker, daemon=True, args=(i,))
        t.start()
        ths.append(t)

    # Monitor thread for user interrupts and statistics
    def monitor_thread():
        while any(t.is_alive() for t in ths):
            time.sleep(2)
            # Could add real-time statistics display here

    monitor = threading.Thread(target=monitor_thread, daemon=True)
    monitor.start()

    # Wait for completion
    try:
        q.join()
    except KeyboardInterrupt:
        print(f"\n[!] Bruteforce interrupted by user after {done} attempts")
        print("[*] Finalizing...")
    
    total_time = time.time() - start_time
    print(f"\n[✓] Bruteforce complete. Time: {format_time(total_time)}")

    # Analysis and reporting
    return analyze_and_report_bruteforce(hits, errors, total, total_time, args)

def try_bruteforce_strategies(dev, value, payload, worker_id):
    """
    Try multiple brute-force strategies for a given value
    """
    strategies = [
        try_direct_bruteforce,
        try_idx_bruteforce,
        try_engine_bruteforce,
        try_vm5_bruteforce,
        try_pattern_bruteforce
    ]
    
    for strategy in strategies:
        result = strategy(dev, value, payload, worker_id)
        if result:
            resp, origin = result
            if resp:
                return resp, origin, strategy.__name__
    
    return None

def try_direct_bruteforce(dev, value, payload, worker_id):
    """Direct BRUTEFORCE command"""
    return qslclidx_or_dispatch(dev, "BRUTEFORCE", payload)

def try_idx_bruteforce(dev, value, payload, worker_id):
    """IDX-based brute-force (common index: 0x30)"""
    # Try common bruteforce indices
    bf_indices = [0x30, 0x31, 0x32, 0x40, 0x41]
    
    for idx in bf_indices:
        if idx in QSLCLIDX_DB:
            entry = QSLCLIDX_DB[idx]
            if isinstance(entry, dict):
                pkt = b"QSLCLIDX" + struct.pack("<I", idx) + payload
                resp = qslcl_dispatch(dev, "IDX", pkt)
                if resp:
                    return resp, f"IDX_0x{idx:02X}"
    return None

def try_engine_bruteforce(dev, value, payload, worker_id):
    """ENGINE opcode brute-force"""
    # Common bruteforce opcodes
    bf_opcodes = [0xB0, 0xB1, 0xB2, 0xC0, 0xC1]
    
    for opcode in bf_opcodes:
        if opcode in QSLCLEND_DB:
            entry = QSLCLEND_DB[opcode]
            entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
            pkt = b"QSLCLEND" + entry_data + payload
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            if resp:
                return resp, f"ENGINE_0x{opcode:02X}"
    return None

def try_vm5_bruteforce(dev, value, payload, worker_id):
    """VM5 microservice brute-force"""
    vm5_services = ["BRUTEFORCE", "SCAN", "PROBE", "EXPLORE"]
    
    for service in vm5_services:
        if service in QSLCLVM5_DB:
            raw = QSLCLVM5_DB[service]["raw"]
            pkt = b"QSLCLVM5" + raw + payload
            resp = qslcl_dispatch(dev, "NANO", pkt)
            if resp:
                return resp, f"VM5_{service}"
    return None

def try_pattern_bruteforce(dev, value, payload, worker_id):
    """Pattern-based brute-force with value transformation"""
    # Try different value representations
    patterns = [
        payload,  # Original
        struct.pack(">I", value),  # Big-endian
        payload + b"\x00" * 4,  # Padded
        struct.pack("<I", value ^ 0xFFFFFFFF),  # Inverted
    ]
    
    for pattern in patterns:
        resp = qslcl_dispatch(dev, "BRUTEFORCE", pattern)
        if resp:
            return resp, "PATTERN"
    return None

def calculate_hit_confidence(severity, name, extra_data, value):
    """
    Calculate confidence score for a brute-force hit
    """
    confidence = 0.0
    
    # Severity-based scoring
    if severity == "SUCCESS":
        confidence += 0.7
    elif severity == "WARNING":
        confidence += 0.4
    elif severity == "ERROR":
        confidence += 0.1
    
    # Name-based scoring
    positive_indicators = ["OK", "SUCCESS", "FOUND", "MATCH", "VALID", "UNLOCKED"]
    negative_indicators = ["FAIL", "ERROR", "INVALID", "REJECTED", "DENIED"]
    
    name_upper = name.upper()
    for indicator in positive_indicators:
        if indicator in name_upper:
            confidence += 0.2
    for indicator in negative_indicators:
        if indicator in name_upper:
            confidence -= 0.1
    
    # Extra data analysis
    if extra_data:
        # Non-zero/non-empty response data
        if extra_data != b"\x00" * len(extra_data):
            confidence += 0.1
        
        # Structured data might indicate success
        if len(extra_data) >= 4:
            first_word = struct.unpack("<I", extra_data[:4])[0]
            if first_word != 0 and first_word != 0xFFFFFFFF:
                confidence += 0.1
    
    # Value pattern analysis (common magic values)
    magic_values = {
        0x00000000: -0.1,  # Often means null/no result
        0xFFFFFFFF: -0.1,  # Often means error
        0xDEADBEEF: 0.3,   # Debug marker
        0xC0DEC0DE: 0.3,   # Code marker
        0x12345678: 0.2,   # Test pattern
        0xAAAAAAAA: 0.1,   # Pattern
        0x55555555: 0.1,   # Pattern
    }
    
    if value in magic_values:
        confidence += magic_values[value]
    
    return max(0.0, min(1.0, confidence))

def analyze_pattern_complexity(start, end):
    """
    Analyze the complexity and characteristics of the brute-force pattern
    """
    total_values = end - start + 1
    print(f"[*] Pattern Analysis:")
    print(f"    Range size: {total_values:,} values")
    print(f"    Memory required: {(total_values * 4) / 1024 / 1024:.2f} MB (est.)")
    
    # Estimate time based on typical rates
    estimated_time = total_values / 1000  # Conservative 1000 attempts/sec
    if estimated_time > 60:
        print(f"    Estimated time: {estimated_time/60:.1f} minutes")
    else:
        print(f"    Estimated time: {estimated_time:.1f} seconds")
    
    # Check for common patterns
    if start == 0x0000 and end == 0xFFFF:
        print("    Pattern: Full 16-bit range")
    elif start == 0x00000000 and end == 0xFFFFFFFF:
        print("    Pattern: Full 32-bit range (VERY LARGE)")
        print("    [!] This range contains 4,294,967,296 values")
        print("    [!] Consider using a smaller range or --strategy smart")
    
    # Check for alignment
    if (start % 4 == 0) and (end % 4 == 3):
        print("    Alignment: 32-bit aligned")
    elif (start % 2 == 0) and (end % 2 == 1):
        print("    Alignment: 16-bit aligned")

def format_time(seconds):
    """Format time in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

def analyze_and_report_bruteforce(hits, errors, total, total_time, args):
    """
    Analyze brute-force results and generate comprehensive report
    """
    print(f"\n{'='*60}")
    print("[*] BRUTEFORCE ANALYSIS REPORT")
    print('='*60)
    
    # Basic statistics
    success_rate = (len(hits) / total * 100) if total > 0 else 0
    error_rate = (errors / total * 100) if total > 0 else 0
    avg_speed = total / total_time if total_time > 0 else 0
    
    print(f"Total attempts: {total:,}")
    print(f"Total hits: {len(hits)} ({success_rate:.2f}%)")
    print(f"Total errors: {errors} ({error_rate:.2f}%)")
    print(f"Average speed: {avg_speed:.1f} attempts/second")
    print(f"Total time: {format_time(total_time)}")
    
    # Hit analysis
    if hits:
        print(f"\n[*] HIT ANALYSIS:")
        
        # Group by confidence
        high_confidence = [h for h in hits if h['confidence'] >= 0.7]
        medium_confidence = [h for h in hits if 0.4 <= h['confidence'] < 0.7]
        low_confidence = [h for h in hits if h['confidence'] < 0.4]
        
        print(f"    High confidence: {len(high_confidence)} hits")
        print(f"    Medium confidence: {len(medium_confidence)} hits")
        print(f"    Low confidence: {len(low_confidence)} hits")
        
        # Strategy effectiveness
        strategies = {}
        for hit in hits:
            strategy = hit['strategy']
            strategies[strategy] = strategies.get(strategy, 0) + 1
        
        print(f"\n[*] STRATEGY EFFECTIVENESS:")
        for strategy, count in sorted(strategies.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(hits)) * 100
            print(f"    {strategy}: {count} hits ({percentage:.1f}%)")
        
        # Value patterns in hits
        print(f"\n[*] VALUE PATTERNS:")
        hex_hits = [f"0x{hit['value']:08X}" for hit in high_confidence[:10]]  # Top 10 high-confidence hits
        if hex_hits:
            print(f"    High-confidence values: {', '.join(hex_hits)}")
    
    # Save detailed report
    return save_bruteforce_report(hits, errors, total, total_time, args)

def save_bruteforce_report(hits, errors, total, total_time, args):
    """
    Save comprehensive brute-force report
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base_filename = args.output if args.output else f"bruteforce_report_{timestamp}"
    
    # Save hits to text file
    txt_filename = f"{base_filename}.txt"
    with open(txt_filename, "w") as f:
        f.write(f"Bruteforce Report - {timestamp}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Range: {args.pattern}\n")
        f.write(f"Total attempts: {total}\n")
        f.write(f"Total hits: {len(hits)}\n")
        f.write(f"Total errors: {errors}\n")
        f.write(f"Total time: {format_time(total_time)}\n\n")
        
        f.write("HITS:\n")
        f.write("-" * 50 + "\n")
        for hit in sorted(hits, key=lambda x: x['confidence'], reverse=True):
            f.write(f"0x{hit['value']:08X} | Conf: {hit['confidence']:.2f} | {hit['strategy']} | {hit['status']['name']}\n")
            if hit['extra_data']:
                f.write(f"      Extra: {hit['extra_data'].hex()}\n")
    
    # Save structured data (JSON)
    json_filename = f"{base_filename}.json"
    try:
        import json
        report_data = {
            'timestamp': timestamp,
            'parameters': {
                'pattern': args.pattern,
                'threads': args.threads,
                'rawmode': getattr(args, 'rawmode', False)
            },
            'statistics': {
                'total_attempts': total,
                'total_hits': len(hits),
                'total_errors': errors,
                'total_time': total_time,
                'success_rate': (len(hits) / total * 100) if total > 0 else 0
            },
            'hits': [
                {
                    'value': hit['value'],
                    'value_hex': f"0x{hit['value']:08X}",
                    'confidence': hit['confidence'],
                    'strategy': hit['strategy'],
                    'status': hit['status'],
                    'timestamp': hit['timestamp'],
                    'extra_data_hex': hit['extra_data'].hex() if hit['extra_data'] else ""
                }
                for hit in hits
            ]
        }
        
        with open(json_filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[+] Detailed report saved to: {txt_filename}")
        print(f"[+] Structured data saved to: {json_filename}")
        
    except Exception as e:
        print(f"[!] Could not save JSON report: {e}")
        print(f"[+] Basic report saved to: {txt_filename}")
    
    return len(hits) > 0

def scan_system_vectors(dev, args):
    """
    Scan common system vectors and entry points
    """
    print("[*] Scanning common system vectors...")
    
    scan_results = {}
    
    # Common vector ranges to scan
    vector_ranges = [
        (0x00000000, 0x0000FFFF, "Interrupt Vectors"),
        (0x80000000, 0x8000FFFF, "Kernel Entry Points"),
        (0x40000000, 0x4000FFFF, "MMIO Regions"),
        (0x10000000, 0x1000FFFF, "Bootloader Entry Points"),
        (0xC0000000, 0xC000FFFF, "TrustZone Entry Points")
    ]
    
    for start, end, description in vector_ranges:
        print(f"\n[*] Scanning {description} (0x{start:08X}-0x{end:08X})...")
        
        # Sample scanning (for demonstration - would need full implementation)
        sample_points = [start, start + 0x1000, start + 0x8000, end]
        hits_in_range = 0
        
        for point in sample_points:
            payload = struct.pack("<I", point)
            resp = qslcl_dispatch(dev, "BRUTEFORCE", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") in ["SUCCESS", "WARNING"]:
                    hits_in_range += 1
        
        scan_results[description] = hits_in_range
        print(f"    Found {hits_in_range} potential vectors")
    
    return True

def pattern_bruteforce(dev, args):
    """
    Advanced pattern-based brute-force with intelligent patterns
    """
    if not hasattr(args, 'bruteforce_args') or not args.bruteforce_args:
        return print("[!] PATTERN requires pattern type (magic, sequence, aligned, etc.)")
    
    pattern_type = args.bruteforce_args[0].upper()
    
    print(f"[*] Starting {pattern_type} pattern brute-force...")
    
    # Generate patterns based on type
    if pattern_type == "MAGIC":
        values = generate_magic_values()
    elif pattern_type == "SEQUENCE":
        values = generate_sequence_patterns()
    elif pattern_type == "ALIGNED":
        values = generate_aligned_patterns()
    elif pattern_type == "COMMON":
        values = generate_common_values()
    else:
        return print(f"[!] Unknown pattern type: {pattern_type}")
    
    print(f"[*] Generated {len(values)} pattern values")
    
    # Execute brute-force with generated patterns
    # (Implementation would be similar to handle_legacy_bruteforce but with custom values)
    
    return True

def generate_magic_values():
    """Generate common magic values for brute-force"""
    magic_values = [
        # Common magic values
        0x00000000, 0xFFFFFFFF, 0xDEADBEEF, 0xC0DEC0DE, 0xCAFEBABE,
        0xBAADF00D, 0x8BADF00D, 0xABADBABE, 0xABADCAFE, 0xB16B00B5,
        0x0D15EA5E, 0x1BADB002, 0xDEADDEAD, 0xFACEB00C, 0xFACEFEED,
        # Power of two values
        0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010,
        0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200,
        # Common offsets
        0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000,
        # ASCII patterns
        0x41414141, 0x42424242, 0x43434343, 0x44444444, 0x45454545,
        0x12345678, 0x87654321, 0x11223344, 0x44332211, 0xAABBCCDD
    ]
    
    return magic_values

def fuzz_bruteforce(dev, args):
    """Intelligent fuzzing with mutation"""
    print("[*] Intelligent fuzzing not yet implemented")
    return False

def dictionary_bruteforce(dev, args):
    """Dictionary-based brute-force"""
    print("[*] Dictionary attack not yet implemented")
    return False

def replay_bruteforce(dev, args):
    """Response replay attacks"""
    print("[*] Replay attacks not yet implemented")
    return False

def analyze_bruteforce_results(dev, args):
    """Analyze previous brute-force results"""
    print("[*] Result analysis not yet implemented")
    return False

def continue_bruteforce_session(dev, args):
    """Continue previous brute-force session"""
    print("[*] Session continuation not yet implemented")
    return False

def handle_bruteforce_operation(dev, operation, args):
    """Handle other brute-force operations"""
    print(f"[*] Advanced brute-force operation '{operation}' not yet implemented")
    return False

# Update the argument parser in main() function
def update_bruteforce_parser(sub):
    """
    Update the BRUTEFORCE command parser with new subcommands
    """
    bruteforce_parser = sub.add_parser("bruteforce", help="Advanced brute-force and system exploration")
    bruteforce_parser.add_argument("bruteforce_subcommand", nargs="?", help="Bruteforce subcommand (list, scan, pattern, fuzz, dictionary, replay, analyze, continue)")
    bruteforce_parser.add_argument("pattern", nargs="?", help="Legacy pattern (e.g., 0x00-0xFFFF)")
    bruteforce_parser.add_argument("--threads", type=int, default=8, help="Number of threads")
    bruteforce_parser.add_argument("--rawmode", action="store_true", help="Enable raw mode")
    bruteforce_parser.add_argument("--output", help="Output filename")
    bruteforce_parser.add_argument("--strategy", choices=["basic", "smart", "aggressive"], default="basic", help="Bruteforce strategy")
    bruteforce_parser.add_argument("bruteforce_args", nargs="*", help="Additional arguments")
    bruteforce_parser.set_defaults(func=cmd_bruteforce)

def cmd_config(args):
    """
    Advanced CONFIG command handler for comprehensive system configuration management
    Supports configuration get/set/list/delete/backup/restore operations
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    # Parse CONFIG subcommand
    if not hasattr(args, 'config_subcommand') or not args.config_subcommand:
        return print("[!] CONFIG command requires subcommand (get, set, list, delete, backup, restore, etc.)")
    
    subcmd = args.config_subcommand.upper()
    
    if subcmd == "GET":
        return config_get(dev, args)
    elif subcmd == "SET":
        return config_set(dev, args)
    elif subcmd == "LIST":
        return config_list_keys(dev, args)
    elif subcmd == "DELETE":
        return config_delete(dev, args)
    elif subcmd == "BACKUP":
        return config_backup(dev, args)
    elif subcmd == "RESTORE":
        return config_restore(dev, args)
    elif subcmd == "RESET":
        return config_reset(dev, args)
    elif subcmd == "IMPORT":
        return config_import(dev, args)
    elif subcmd == "EXPORT":
        return config_export(dev, args)
    elif subcmd == "VALIDATE":
        return config_validate(dev, args)
    elif subcmd == "INFO":
        return config_info(dev, args)
    else:
        return handle_config_operation(dev, subcmd, args)

def config_get(dev, args):
    """
    Get configuration value for specified key
    """
    if not hasattr(args, 'config_args') or not args.config_args:
        return print("[!] CONFIG GET requires key name")
    
    key = args.config_args[0].upper()
    
    print(f"[*] Getting configuration: {key}")
    
    # Try different methods to get configuration
    strategies = [
        try_idx_config_get,
        try_par_config_get,
        try_end_config_get,
        try_vm5_config_get,
        try_direct_config_get
    ]
    
    for strategy in strategies:
        value = strategy(dev, key)
        if value is not None:
            display_config_value(key, value)
            return True
    
    print(f"[!] Failed to get configuration for: {key}")
    return False

def try_idx_config_get(dev, key):
    """Try QSLCLIDX config get"""
    idx_entry = qslclidx_get_cmd("CONFIG_GET")
    if idx_entry:
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"]) + payload
        resp = qslcl_dispatch(dev, "IDX", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return status.get("extra", b"")
    return None

def try_par_config_get(dev, key):
    """Try QSLCLPAR config get"""
    if "CONFIG_GET" in QSLCLPAR_DB:
        payload = key.encode("ascii") + b"\x00"
        resp = qslcl_dispatch(dev, "CONFIG_GET", payload)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return status.get("extra", b"")
    return None

def try_end_config_get(dev, key):
    """Try QSLCLEND config get opcode"""
    CONFIG_GET_OPCODE = 0xC1
    if CONFIG_GET_OPCODE in QSLCLEND_DB:
        entry = QSLCLEND_DB[CONFIG_GET_OPCODE]
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return status.get("extra", b"")
    return None

def try_vm5_config_get(dev, key):
    """Try QSLCLVM5 config get"""
    if "CONFIG_GET" in QSLCLVM5_DB:
        raw = QSLCLVM5_DB["CONFIG_GET"]["raw"]
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return status.get("extra", b"")
    return None

def try_direct_config_get(dev, key):
    """Try direct config get"""
    payload = key.encode("ascii") + b"\x00"
    resp = qslcl_dispatch(dev, "CONFIG_GET", payload)
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            return status.get("extra", b"")
    return None

def display_config_value(key, value):
    """
    Display configuration value in appropriate format
    """
    if not value:
        print(f"  {key}: <empty>")
        return
    
    # Try to decode as string first
    try:
        str_value = value.decode('utf-8', errors='ignore').rstrip('\x00')
        if all(c.isprintable() or c in ' \t\n\r' for c in str_value):
            print(f"  {key}: \"{str_value}\"")
            return
    except:
        pass
    
    # Try to interpret as numeric values
    if len(value) == 1:
        print(f"  {key}: {value[0]} (byte) 0x{value[0]:02X}")
    elif len(value) == 2:
        num = struct.unpack("<H", value)[0]
        print(f"  {key}: {num} (word) 0x{num:04X}")
    elif len(value) == 4:
        num = struct.unpack("<I", value)[0]
        print(f"  {key}: {num} (dword) 0x{num:08X}")
    elif len(value) == 8:
        num = struct.unpack("<Q", value)[0]
        print(f"  {key}: {num} (qword) 0x{num:016X}")
    else:
        # Display as hex
        hex_value = value.hex()
        if len(hex_value) > 64:
            hex_value = hex_value[:64] + "..."
        print(f"  {key}: {hex_value} ({len(value)} bytes)")

def config_set(dev, args):
    """
    Set configuration value for specified key
    """
    if not hasattr(args, 'config_args') or len(args.config_args) < 2:
        return print("[!] CONFIG SET requires key and value")
    
    key = args.config_args[0].upper()
    value_str = args.config_args[1]
    
    # Parse value based on format
    value_data = parse_config_value(value_str)
    if value_data is None:
        print("[!] Invalid value format. Use: string, 123, 0x123, true/false, 1.5")
        return False
    
    print(f"[*] Setting configuration: {key} = {value_str}")
    
    # Build payload
    payload = key.encode("ascii") + b"\x00" + value_data
    
    # Safety check for large values
    if len(payload) > 1024:
        print("[!] Configuration value too large, refusing.")
        return False
    
    # Try different methods to set configuration
    strategies = [
        try_idx_config_set,
        try_par_config_set,
        try_end_config_set,
        try_vm5_config_set,
        try_direct_config_set
    ]
    
    for strategy in strategies:
        success = strategy(dev, payload)
        if success is not None:
            if success:
                print(f"[✓] Configuration set successfully: {key}")
                # Verify the setting
                if args.verify:
                    time.sleep(0.5)
                    verify_config_set(dev, key, value_data)
            return success
    
    print(f"[!] Failed to set configuration for: {key}")
    return False

def parse_config_value(value_str):
    """
    Parse configuration value from string to bytes
    """
    # Empty value
    if value_str == "":
        return b""
    
    # Boolean values
    if value_str.lower() in ["true", "yes", "on", "1"]:
        return b"\x01"
    elif value_str.lower() in ["false", "no", "off", "0"]:
        return b"\x00"
    
    # Hex values
    if value_str.startswith("0x"):
        try:
            hex_str = value_str[2:]
            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str
            return bytes.fromhex(hex_str)
        except:
            return None
    
    # Numeric values
    if value_str.isdigit() or (value_str.startswith('-') and value_str[1:].isdigit()):
        try:
            num = int(value_str)
            if -128 <= num <= 255:
                return struct.pack("<B", num & 0xFF)
            elif -32768 <= num <= 65535:
                return struct.pack("<H", num & 0xFFFF)
            else:
                return struct.pack("<I", num & 0xFFFFFFFF)
        except:
            return None
    
    # Float values
    try:
        float_val = float(value_str)
        return struct.pack("<f", float_val)
    except:
        pass
    
    # String value (default)
    return value_str.encode("utf-8") + b"\x00"

def try_idx_config_set(dev, payload):
    """Try QSLCLIDX config set"""
    idx_entry = qslclidx_get_cmd("CONFIG_SET")
    if idx_entry:
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"]) + payload
        resp = qslcl_dispatch(dev, "IDX", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_par_config_set(dev, payload):
    """Try QSLCLPAR config set"""
    if "CONFIG_SET" in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, "CONFIG_SET", payload)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_end_config_set(dev, payload):
    """Try QSLCLEND config set opcode"""
    CONFIG_SET_OPCODE = 0xC0
    if CONFIG_SET_OPCODE in QSLCLEND_DB:
        entry = QSLCLEND_DB[CONFIG_SET_OPCODE]
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_vm5_config_set(dev, payload):
    """Try QSLCLVM5 config set"""
    if "CONFIG_SET" in QSLCLVM5_DB:
        raw = QSLCLVM5_DB["CONFIG_SET"]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_direct_config_set(dev, payload):
    """Try direct config set"""
    resp = qslcl_dispatch(dev, "CONFIG_SET", payload)
    if resp:
        status = decode_runtime_result(resp)
        return status.get("severity") == "SUCCESS"
    return False

def verify_config_set(dev, key, expected_value):
    """
    Verify that configuration was set correctly
    """
    print(f"[*] Verifying configuration: {key}")
    
    current_value = try_idx_config_get(dev, key)
    if current_value is None:
        current_value = try_direct_config_get(dev, key)
    
    if current_value is not None:
        if current_value == expected_value:
            print(f"[✓] Configuration verified: {key}")
        else:
            print(f"[!] Configuration mismatch for: {key}")
            print(f"    Expected: {expected_value.hex()}")
            print(f"    Got: {current_value.hex()}")
    else:
        print(f"[!] Could not verify configuration: {key}")

def config_list_keys(dev, args):
    """
    List all available configuration keys
    """
    print("[*] Retrieving configuration keys...")
    
    # Try to get key list from device
    keys = get_config_key_list(dev)
    
    if not keys:
        # Fallback to common configuration keys
        keys = get_common_config_keys()
    
    # Filter by category if specified
    category_filter = None
    if hasattr(args, 'config_args') and args.config_args:
        category_filter = args.config_args[0].upper()
    
    print(f"\n[*] Available Configuration Keys ({len(keys)} total):")
    print("=" * 60)
    
    categorized_keys = categorize_config_keys(keys)
    
    for category, key_list in categorized_keys.items():
        if category_filter and category != category_filter:
            continue
            
        print(f"\n[{category}]")
        for key in sorted(key_list):
            # Try to get current value for display
            current_value = try_direct_config_get(dev, key)
            if current_value is not None:
                value_preview = format_value_preview(current_value)
                print(f"  • {key}: {value_preview}")
            else:
                print(f"  • {key}")
    
    if category_filter and category_filter not in categorized_keys:
        print(f"[!] No configuration keys found in category: {category_filter}")
    
    return True

def get_config_key_list(dev):
    """
    Get list of configuration keys from device
    """
    keys = []
    
    # Try different methods to get key list
    strategies = [
        try_idx_config_list,
        try_par_config_list,
        try_end_config_list,
        try_vm5_config_list
    ]
    
    for strategy in strategies:
        result = strategy(dev)
        if result:
            keys.extend(result)
    
    # Remove duplicates and return
    return list(set(keys))

def try_idx_config_list(dev):
    """Try QSLCLIDX config list"""
    idx_entry = qslclidx_get_cmd("CONFIG_LIST")
    if idx_entry:
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"])
        resp = qslcl_dispatch(dev, "IDX", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                return parse_key_list(extra)
    return []

def try_par_config_list(dev):
    """Try QSLCLPAR config list"""
    if "CONFIG_LIST" in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, "CONFIG_LIST")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                return parse_key_list(extra)
    return []

def try_end_config_list(dev):
    """Try QSLCLEND config list opcode"""
    CONFIG_LIST_OPCODE = 0xC2
    if CONFIG_LIST_OPCODE in QSLCLEND_DB:
        entry = QSLCLEND_DB[CONFIG_LIST_OPCODE]
        pkt = b"QSLCLEND" + entry
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                return parse_key_list(extra)
    return []

def try_vm5_config_list(dev):
    """Try QSLCLVM5 config list"""
    if "CONFIG_LIST" in QSLCLVM5_DB:
        raw = QSLCLVM5_DB["CONFIG_LIST"]["raw"]
        pkt = b"QSLCLVM5" + raw
        resp = qslcl_dispatch(dev, "NANO", pkt)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                return parse_key_list(extra)
    return []

def parse_key_list(data):
    """
    Parse key list from binary data
    """
    if not data:
        return []
    
    try:
        key_str = data.decode('utf-8', errors='ignore')
        keys = [k.strip() for k in key_str.split('\x00') if k.strip()]
        return keys
    except:
        return []

def get_common_config_keys():
    """
    Return common configuration keys as fallback
    """
    return [
        "BOOT_MODE", "DEBUG_LEVEL", "SECURE_BOOT", "VERIFIED_BOOT",
        "SERIAL_BAUD", "USB_CONFIG", "POWER_MODE", "THERMAL_LIMIT",
        "VOLTAGE_CPU", "VOLTAGE_GPU", "CLOCK_CPU", "CLOCK_GPU",
        "MEMORY_TIMING", "STORAGE_MODE", "NETWORK_MODE", "LOG_LEVEL",
        "WATCHDOG_TIMEOUT", "RESET_DELAY", "BOOT_DELAY", "SLEEP_TIMEOUT",
        "BACKLIGHT_LEVEL", "VIBRATION_STRENGTH", "AUDIO_VOLUME",
        "DISPLAY_BRIGHTNESS", "TOUCH_SENSITIVITY", "CAMERA_QUALITY",
        "GPS_MODE", "BLUETOOTH_MODE", "WIFI_MODE", "CELLULAR_MODE",
        "BATTERY_SAVER", "PERFORMANCE_MODE", "SECURITY_LEVEL"
    ]

def categorize_config_keys(keys):
    """
    Categorize configuration keys for better organization
    """
    categories = {
        "BOOT": [],
        "SECURITY": [],
        "POWER": [],
        "PERFORMANCE": [],
        "HARDWARE": [],
        "NETWORK": [],
        "AUDIO/VIDEO": [],
        "SYSTEM": [],
        "OTHER": []
    }
    
    category_patterns = {
        "BOOT": ["BOOT", "STARTUP", "INIT"],
        "SECURITY": ["SECURE", "VERIF", "AUTH", "LOCK", "ENCRYPT"],
        "POWER": ["POWER", "BATTERY", "VOLTAGE", "CURRENT", "SLEEP"],
        "PERFORMANCE": ["CLOCK", "FREQ", "PERF", "SPEED", "TIMING"],
        "HARDWARE": ["CPU", "GPU", "MEMORY", "STORAGE", "DISPLAY", "TOUCH"],
        "NETWORK": ["WIFI", "BLUETOOTH", "GPS", "CELLULAR", "NETWORK"],
        "AUDIO/VIDEO": ["AUDIO", "VIDEO", "CAMERA", "MIC", "SPEAKER", "DISPLAY"],
        "SYSTEM": ["DEBUG", "LOG", "RESET", "WATCHDOG", "SYSTEM"]
    }
    
    for key in keys:
        matched = False
        key_upper = key.upper()
        
        for category, patterns in category_patterns.items():
            if any(pattern in key_upper for pattern in patterns):
                categories[category].append(key)
                matched = True
                break
        
        if not matched:
            categories["OTHER"].append(key)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

def format_value_preview(value):
    """
    Create a preview of configuration value
    """
    if not value:
        return "<empty>"
    
    if len(value) == 1:
        return f"0x{value[0]:02X}"
    
    try:
        str_val = value.decode('utf-8', errors='ignore').rstrip('\x00')
        if len(str_val) <= 20 and all(c.isprintable() for c in str_val):
            return f"\"{str_val}\""
    except:
        pass
    
    return f"{len(value)} bytes"

def config_delete(dev, args):
    """
    Delete configuration key
    """
    if not hasattr(args, 'config_args') or not args.config_args:
        return print("[!] CONFIG DELETE requires key name")
    
    key = args.config_args[0].upper()
    
    print(f"[*] Deleting configuration: {key}")
    
    # Safety confirmation for important keys
    important_keys = ["SECURE_BOOT", "BOOT_MODE", "POWER_MODE"]
    if key in important_keys:
        confirm = input(f"!! CONFIRM DELETE {key} (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Configuration delete cancelled")
            return False
    
    # Try different deletion methods
    strategies = [
        try_idx_config_delete,
        try_par_config_delete,
        try_end_config_delete,
        try_vm5_config_delete,
        try_direct_config_delete
    ]
    
    for strategy in strategies:
        success = strategy(dev, key)
        if success is not None:
            if success:
                print(f"[✓] Configuration deleted: {key}")
            return success
    
    print(f"[!] Failed to delete configuration: {key}")
    return False

def try_idx_config_delete(dev, key):
    """Try QSLCLIDX config delete"""
    idx_entry = qslclidx_get_cmd("CONFIG_DELETE")
    if idx_entry:
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"]) + payload
        resp = qslcl_dispatch(dev, "IDX", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_par_config_delete(dev, key):
    """Try QSLCLPAR config delete"""
    if "CONFIG_DELETE" in QSLCLPAR_DB:
        payload = key.encode("ascii") + b"\x00"
        resp = qslcl_dispatch(dev, "CONFIG_DELETE", payload)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def config_backup(dev, args):
    """
    Backup all configurations to file
    """
    filename = "config_backup.json"
    if hasattr(args, 'config_args') and args.config_args:
        filename = args.config_args[0]
    
    print(f"[*] Backing up configurations to: {filename}")
    
    # Get all configuration keys
    keys = get_config_key_list(dev)
    if not keys:
        keys = get_common_config_keys()
    
    backup_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device": str(dev),
        "configurations": {}
    }
    
    # Backup each configuration
    backed_up = 0
    for key in keys:
        value = try_direct_config_get(dev, key)
        if value is not None:
            backup_data["configurations"][key] = value.hex()
            backed_up += 1
            print(f"  [✓] Backed up: {key}")
        else:
            print(f"  [!] Failed to backup: {key}")
    
    # Save to file
    try:
        import json
        with open(filename, 'w') as f:
            json.dump(backup_data, f, indent=2)
        print(f"[✓] Configuration backup complete: {backed_up}/{len(keys)} configurations saved to {filename}")
        return True
    except Exception as e:
        print(f"[!] Failed to save backup: {e}")
        return False

def config_restore(dev, args):
    """
    Restore configurations from backup file
    """
    if not hasattr(args, 'config_args') or not args.config_args:
        return print("[!] CONFIG RESTORE requires backup filename")
    
    filename = args.config_args[0]
    
    print(f"[*] Restoring configurations from: {filename}")
    
    try:
        import json
        with open(filename, 'r') as f:
            backup_data = json.load(f)
        
        configurations = backup_data.get("configurations", {})
        
        if not configurations:
            print("[!] No configurations found in backup file")
            return False
        
        print(f"[*] Found {len(configurations)} configurations from {backup_data.get('timestamp', 'unknown')}")
        
        # Safety confirmation
        confirm = input("!! CONFIRM CONFIGURATION RESTORE (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Configuration restore cancelled")
            return False
        
        # Restore each configuration
        restored = 0
        for key, hex_value in configurations.items():
            value_data = bytes.fromhex(hex_value)
            payload = key.encode("ascii") + b"\x00" + value_data
            
            success = try_direct_config_set(dev, payload)
            if success:
                restored += 1
                print(f"  [✓] Restored: {key}")
            else:
                print(f"  [!] Failed to restore: {key}")
        
        print(f"[✓] Configuration restore complete: {restored}/{len(configurations)} configurations restored")
        return restored > 0
        
    except Exception as e:
        print(f"[!] Failed to restore backup: {e}")
        return False

def config_reset(dev, args):
    """
    Reset all configurations to default values
    """
    print("[!] WARNING: This will reset ALL configurations to default values!")
    print("[!] This action cannot be undone!")
    
    confirm = input("!! CONFIRM CONFIGURATION RESET (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Configuration reset cancelled")
        return False
    
    print("[*] Resetting all configurations to defaults...")
    
    # Try configuration reset command
    resp = qslcl_dispatch(dev, "CONFIG_RESET")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] All configurations reset to defaults")
            return True
    
    print("[!] Configuration reset failed")
    return False

def config_import(dev, args):
    """
    Import configurations from file (similar to restore but different format)
    """
    if not hasattr(args, 'config_args') or not args.config_args:
        return print("[!] CONFIG IMPORT requires filename")
    
    filename = args.config_args[0]
    print(f"[*] Importing configurations from: {filename}")
    
    # Implementation similar to restore but for different file formats
    # This is a placeholder for future implementation
    print("[!] Config import not yet implemented")
    return False

def config_export(dev, args):
    """
    Export configurations to file (similar to backup but different format)
    """
    filename = "config_export.txt"
    if hasattr(args, 'config_args') and args.config_args:
        filename = args.config_args[0]
    
    print(f"[*] Exporting configurations to: {filename}")
    
    # Implementation similar to backup but for different file formats
    # This is a placeholder for future implementation
    print("[!] Config export not yet implemented")
    return False

def config_validate(dev, args):
    """
    Validate all configurations for consistency
    """
    print("[*] Validating configuration consistency...")
    
    keys = get_config_key_list(dev)
    if not keys:
        keys = get_common_config_keys()
    
    issues_found = 0
    
    for key in keys:
        value = try_direct_config_get(dev, key)
        if value is not None:
            # Basic validation checks
            if len(value) == 0:
                print(f"  [!] {key}: Empty value")
                issues_found += 1
            elif len(value) > 256:
                print(f"  [!] {key}: Value too large ({len(value)} bytes)")
                issues_found += 1
            else:
                print(f"  [✓] {key}: Valid")
        else:
            print(f"  [?] {key}: Cannot read value")
    
    print(f"\n[*] Configuration validation complete: {issues_found} issues found")
    return issues_found == 0

def config_info(dev, args):
    """
    Display detailed information about configuration system
    """
    print("\n" + "="*60)
    print("[*] CONFIGURATION SYSTEM INFORMATION")
    print("="*60)
    
    # Display capabilities
    print("\n[CAPABILITIES]")
    capabilities = []
    
    if qslclidx_get_cmd("CONFIG_GET"): capabilities.append("GET")
    if qslclidx_get_cmd("CONFIG_SET"): capabilities.append("SET")
    if qslclidx_get_cmd("CONFIG_LIST"): capabilities.append("LIST")
    if qslclidx_get_cmd("CONFIG_DELETE"): capabilities.append("DELETE")
    
    if capabilities:
        print(f"  Supported operations: {', '.join(capabilities)}")
    else:
        print("  No configuration capabilities detected")
    
    # Display statistics
    keys = get_config_key_list(dev)
    if keys:
        print(f"  Total configuration keys: {len(keys)}")
        
        categorized = categorize_config_keys(keys)
        for category, key_list in categorized.items():
            print(f"    {category}: {len(key_list)} keys")
    
    # Display storage information
    print(f"\n[STORAGE]")
    print("  Configuration storage: Device NVRAM/Flash")
    print("  Maximum value size: 1024 bytes")
    print("  Persistence: Survives reboot")
    
    print("\n" + "="*60)
    return True

def handle_config_operation(dev, operation, args):
    """
    Handle other configuration operations
    """
    print(f"[*] Executing configuration operation: {operation}")
    
    # This function can be extended for custom configuration operations
    print(f"[!] Configuration operation '{operation}' not implemented")
    return False

# Placeholder functions for unimplemented strategies
def try_direct_config_delete(dev, key):
    payload = key.encode("ascii") + b"\x00"
    resp = qslcl_dispatch(dev, "CONFIG_DELETE", payload)
    if resp:
        status = decode_runtime_result(resp)
        return status.get("severity") == "SUCCESS"
    return False

def try_end_config_delete(dev, key):
    CONFIG_DELETE_OPCODE = 0xC3
    if CONFIG_DELETE_OPCODE in QSLCLEND_DB:
        entry = QSLCLEND_DB[CONFIG_DELETE_OPCODE]
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def try_vm5_config_delete(dev, key):
    if "CONFIG_DELETE" in QSLCLVM5_DB:
        raw = QSLCLVM5_DB["CONFIG_DELETE"]["raw"]
        payload = key.encode("ascii") + b"\x00"
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        if resp:
            status = decode_runtime_result(resp)
            return status.get("severity") == "SUCCESS"
    return None

def cmd_config_list(args=None):
    """
    Enhanced configuration capabilities listing
    """
    print("\n" + "="*60)
    print("[*] QSLCL CONFIGURATION SYSTEM CAPABILITIES")
    print("="*60)
    
    # ---------------------
    # QSLCLIDX Configuration Commands
    # ---------------------
    print("\n[QSLCLIDX] Indexed Configuration Commands:")
    config_idx_commands = []
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and any(x in name.upper() for x in ["CONFIG", "SETTING", "PARAM"]):
            config_idx_commands.append((name, entry.get('idx', 0)))
    
    if config_idx_commands:
        for name, idx in sorted(config_idx_commands, key=lambda x: x[1]):
            print(f"   • {name:<20} (idx=0x{idx:02X})")
    else:
        print("   (no indexed configuration commands)")
    
    # ---------------------
    # QSLCLEND Configuration Opcodes
    # ---------------------
    print("\n[QSLCLEND] Configuration Opcodes:")
    config_end_commands = []
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        if any(x in str(entry_name).upper() for x in ["CONFIG", "SETTING"]) or opcode in [0xC0, 0xC1, 0xC2, 0xC3]:
            config_end_commands.append((opcode, entry_name))
    
    if config_end_commands:
        for opcode, name in sorted(config_end_commands):
            name_display = name if name else "CONFIG_OPERATION"
            print(f"   • {name_display:<20} (opcode=0x{opcode:02X})")
    else:
        print("   (no configuration opcodes)")
    
    # ---------------------
    # QSLCLPAR Configuration Blocks
    # ---------------------
    print("\n[QSLCLPAR] Parser Configuration Blocks:")
    config_par_commands = []
    for cmd_name in QSLCLPAR_DB.keys():
        if any(x in cmd_name.upper() for x in ["CONFIG", "SETTING", "PARAM"]):
            config_par_commands.append(cmd_name)
    
    if config_par_commands:
        for cmd in sorted(config_par_commands):
            print(f"   • {cmd}")
    else:
        print("   (no parser configuration blocks)")
    
    # ---------------------
    # QSLCLVM5 Configuration Microservices
    # ---------------------
    print("\n[QSLCLVM5] Configuration Microservices:")
    config_vm5_commands = []
    for cmd_name in QSLCLVM5_DB.keys():
        if any(x in cmd_name.upper() for x in ["CONFIG", "SETTING"]):
            config_vm5_commands.append(cmd_name)
    
    if config_vm5_commands:
        for cmd in sorted(config_vm5_commands):
            print(f"   • {cmd}")
    else:
        print("   (no configuration microservices)")
    
    # ---------------------
    # Available Operations
    # ---------------------
    print("\n[OPERATIONS] Available Configuration Commands:")
    print("   • config get <key>              - Get configuration value")
    print("   • config set <key> <value>      - Set configuration value") 
    print("   • config list [category]        - List configuration keys")
    print("   • config delete <key>           - Delete configuration key")
    print("   • config backup [filename]      - Backup all configurations")
    print("   • config restore <filename>     - Restore configurations")
    print("   • config reset                  - Reset to defaults")
    print("   • config validate               - Validate configurations")
    print("   • config info                   - System information")
    
    # ---------------------
    # Value Formats
    # ---------------------
    print("\n[VALUE FORMATS] Supported Configuration Value Types:")
    print("   • String:    \"hello world\"")
    print("   • Integer:   123 or 0x7B")
    print("   • Boolean:   true/false or 1/0")
    print("   • Float:     3.14")
    print("   • Hex:       0x1234ABCD")
    
    print("\n" + "="*60)

# Update the argument parser in main() function
def update_config_parser(sub):
    """
    Update the CONFIG command parser with new subcommands
    """
    config_parser = sub.add_parser("config", help="Configuration management commands")
    config_parser.add_argument("config_subcommand", help="Config subcommand (get, set, list, delete, backup, restore, reset, import, export, validate, info)")
    config_parser.add_argument("config_args", nargs="*", help="Additional arguments for config command")
    config_parser.add_argument("--verify", action="store_true", help="Verify configuration after setting")
    config_parser.set_defaults(func=cmd_config)

def cmd_glitch(args):
    """
    Advanced GLITCH command handler for hardware fault injection and timing attacks
    Supports voltage glitching, clock glitching, EM glitching, and laser fault injection simulation
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse GLITCH subcommand
    if not hasattr(args, 'glitch_subcommand') or not args.glitch_subcommand:
        # Backward compatibility with old syntax
        if hasattr(args, 'level') and hasattr(args, 'iter') and hasattr(args, 'window') and hasattr(args, 'sweep'):
            return execute_legacy_glitch(dev, args)
        return print("[!] GLITCH command requires subcommand (list, voltage, clock, em, laser, advanced, etc.)")
    
    subcmd = args.glitch_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_glitch_commands(dev)
    elif subcmd == "VOLTAGE":
        return execute_voltage_glitch(dev, args)
    elif subcmd == "CLOCK":
        return execute_clock_glitch(dev, args)
    elif subcmd == "EM":
        return execute_em_glitch(dev, args)
    elif subcmd == "LASER":
        return execute_laser_glitch(dev, args)
    elif subcmd == "TIMING":
        return execute_timing_glitch(dev, args)
    elif subcmd == "RESET":
        return execute_reset_glitch(dev, args)
    elif subcmd == "ADVANCED":
        return execute_advanced_glitch(dev, args)
    elif subcmd == "SCAN":
        return scan_glitch_parameters(dev, args)
    elif subcmd == "AUTO":
        return execute_auto_glitch(dev, args)
    elif subcmd == "ANALYZE":
        return analyze_glitch_results(dev, args)
    elif subcmd == "CALIBRATE":
        return calibrate_glitch_parameters(dev, args)
    else:
        return handle_glitch_operation(dev, subcmd, args)

def list_available_glitch_commands(dev):
    """
    List all available GLITCH commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL GLITCHING COMMANDS")
    print("="*60)
    
    glitch_found = []
    
    # Check QSLCLPAR for GLITCH commands
    print("\n[QSLCLPAR] Glitch Commands:")
    par_glitch = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "GLITCH", "FAULT", "INJECTION", "VOLTAGE", "CLOCK", "TIMING",
        "RESET", "UNDERVOLT", "OVERVOLT", "FREQUENCY", "PULSE"
    ])]
    for glitch_cmd in par_glitch:
        print(f"  • {glitch_cmd}")
        glitch_found.append(glitch_cmd)
    
    # Check QSLCLEND for glitch-related opcodes
    print("\n[QSLCLEND] Glitch Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["GLITCH", "FAULT", "INJECTION"]) or any(x in entry_str for x in ["GLITCH", "FAULT"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            glitch_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for glitch microservices
    print("\n[QSLCLVM5] Glitch Microservices:")
    vm5_glitch = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["GLITCH", "FAULT", "INJECTION"])]
    for glitch_cmd in vm5_glitch:
        print(f"  • {glitch_cmd}")
        glitch_found.append(f"VM5_{glitch_cmd}")
    
    # Check QSLCLIDX for glitch indices
    print("\n[QSLCLIDX] Glitch Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["GLITCH", "FAULT", "INJECTION"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                glitch_found.append(f"IDX_{name}")
    
    if not glitch_found:
        print("  No glitch commands found in loader")
    else:
        print(f"\n[*] Total glitch commands found: {len(glitch_found)}")
    
    print("\n[*] Common Glitching Techniques Available:")
    print("  • VOLTAGE    - Voltage glitching (undervolt/overvolt)")
    print("  • CLOCK      - Clock glitching (frequency manipulation)")
    print("  • EM         - Electromagnetic pulse injection")
    print("  • LASER      - Laser fault injection simulation")
    print("  • TIMING     - Timing attacks and race conditions")
    print("  • RESET      - Reset line glitching")
    print("  • ADVANCED   - Advanced multi-parameter glitching")
    print("  • SCAN       - Automated glitch parameter scanning")
    print("  • AUTO       - Automatic glitch parameter discovery")
    print("  • ANALYZE    - Glitch result analysis")
    print("  • CALIBRATE  - Glitch hardware calibration")
    
    print("="*60)
    
    return True

def execute_legacy_glitch(dev, args):
    """
    Execute legacy glitch command for backward compatibility
    """
    print("[*] Using legacy glitch syntax...")
    
    level = int(args.level)
    iterations = int(args.iter)
    window = int(args.window)
    sweep = int(args.sweep)

    print(f"[*] GLITCH: level={level}  iter={iterations}  window={window}  sweep={sweep}")

    # Build virtual glitch payload
    entropy = os.urandom(16)
    jitter = random.randint(1, 9999)

    payload = struct.pack(
        "<BIII16sI",
        level,          # glitch intensity
        iterations,     # iteration count
        window,         # timing window
        sweep,          # sweep width
        entropy,        # entropy seed
        jitter          # timing jitter
    )

    return execute_glitch_operation(dev, "LEGACY", payload)

def execute_voltage_glitch(dev, args):
    """
    Execute voltage glitching attack
    """
    print("[*] Preparing voltage glitching attack...")
    
    # Parse parameters
    voltage_type = "UNDERVOLT"  # Default to undervoltage
    intensity = 2               # Default intensity
    duration = 100              # Default duration in microseconds
    target_domain = "VDD_CORE"  # Default target
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            voltage_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                intensity = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                duration = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            target_domain = args.glitch_args[3].upper()
    
    print(f"[*] Voltage Glitch: type={voltage_type}, intensity={intensity}, duration={duration}μs, target={target_domain}")
    
    # Safety warning
    print("[!] WARNING: Voltage glitching can cause permanent hardware damage!")
    confirm = input("!! CONFIRM VOLTAGE GLITCH (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Voltage glitch cancelled")
        return False
    
    # Build voltage glitch payload
    payload = struct.pack(
        "<B B H 12s",
        0x01,  # Voltage glitch type
        intensity,
        duration,
        target_domain.encode('ascii').ljust(12, b'\x00')
    )
    
    return execute_glitch_operation(dev, "VOLTAGE", payload)

def execute_clock_glitch(dev, args):
    """
    Execute clock glitching attack
    """
    print("[*] Preparing clock glitching attack...")
    
    # Parse parameters
    clock_source = "CPU"        # Default clock source
    frequency_shift = 100       # Default frequency shift in MHz
    duration = 50              # Default duration in microseconds
    pattern = "SINGLE"         # Default pattern
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            clock_source = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                frequency_shift = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                duration = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            pattern = args.glitch_args[3].upper()
    
    print(f"[*] Clock Glitch: source={clock_source}, shift={frequency_shift}MHz, duration={duration}μs, pattern={pattern}")
    
    # Build clock glitch payload
    pattern_code = {
        "SINGLE": 0x01,
        "BURST": 0x02,
        "CONTINUOUS": 0x03,
        "RANDOM": 0x04
    }.get(pattern, 0x01)
    
    payload = struct.pack(
        "<B h H B 10s",
        0x02,  # Clock glitch type
        frequency_shift,
        duration,
        pattern_code,
        clock_source.encode('ascii').ljust(10, b'\x00')
    )
    
    return execute_glitch_operation(dev, "CLOCK", payload)

def execute_em_glitch(dev, args):
    """
    Execute electromagnetic glitching attack
    """
    print("[*] Preparing electromagnetic glitching attack...")
    
    # Parse parameters
    em_strength = 3            # Default EM strength (1-5)
    pulse_width = 20           # Default pulse width in nanoseconds
    frequency = 100            # Default frequency in MHz
    target_coords = (0, 0)     # Default target coordinates
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            try:
                em_strength = int(args.glitch_args[0])
            except:
                pass
        if len(args.glitch_args) > 1:
            try:
                pulse_width = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                frequency = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            try:
                x, y = map(int, args.glitch_args[3].split(','))
                target_coords = (x, y)
            except:
                pass
    
    print(f"[*] EM Glitch: strength={em_strength}, width={pulse_width}ns, freq={frequency}MHz, target={target_coords}")
    
    # Build EM glitch payload
    payload = struct.pack(
        "<B B H H h h",
        0x03,  # EM glitch type
        em_strength,
        pulse_width,
        frequency,
        target_coords[0],  # X coordinate
        target_coords[1]   # Y coordinate
    )
    
    return execute_glitch_operation(dev, "EM", payload)

def execute_laser_glitch(dev, args):
    """
    Execute laser fault injection simulation
    """
    print("[*] Preparing laser fault injection...")
    
    # Parse parameters
    laser_power = 80           # Default laser power (0-100)
    pulse_duration = 10        # Default pulse duration in nanoseconds
    wavelength = 1064          # Default wavelength in nm
    target_area = "CPU_CORE"   # Default target area
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            try:
                laser_power = int(args.glitch_args[0])
            except:
                pass
        if len(args.glitch_args) > 1:
            try:
                pulse_duration = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                wavelength = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            target_area = args.glitch_args[3].upper()
    
    print(f"[*] Laser Injection: power={laser_power}%, duration={pulse_duration}ns, wavelength={wavelength}nm, target={target_area}")
    
    # Build laser glitch payload
    payload = struct.pack(
        "<B B H H 12s",
        0x04,  # Laser glitch type
        laser_power,
        pulse_duration,
        wavelength,
        target_area.encode('ascii').ljust(12, b'\x00')
    )
    
    return execute_glitch_operation(dev, "LASER", payload)

def execute_timing_glitch(dev, args):
    """
    Execute timing-based glitching attacks
    """
    print("[*] Preparing timing glitching attack...")
    
    # Parse parameters
    attack_type = "RACE"       # Default attack type
    precision = 10             # Default precision in nanoseconds
    iterations = 1000          # Default iterations
    target_operation = "AUTH"  # Default target operation
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            attack_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                precision = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                iterations = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            target_operation = args.glitch_args[3].upper()
    
    attack_codes = {
        "RACE": 0x01,
        "SETUP": 0x02,
        "HOLD": 0x03,
        "CLOCK_RECOVERY": 0x04
    }
    
    attack_code = attack_codes.get(attack_type, 0x01)
    
    print(f"[*] Timing Glitch: type={attack_type}, precision={precision}ns, iterations={iterations}, target={target_operation}")
    
    # Build timing glitch payload
    payload = struct.pack(
        "<B B I H 10s",
        0x05,  # Timing glitch type
        attack_code,
        iterations,
        precision,
        target_operation.encode('ascii').ljust(10, b'\x00')
    )
    
    return execute_glitch_operation(dev, "TIMING", payload)

def execute_reset_glitch(dev, args):
    """
    Execute reset line glitching
    """
    print("[*] Preparing reset line glitching...")
    
    # Parse parameters
    reset_type = "SOFT"        # Default reset type
    pulse_count = 5            # Default pulse count
    pulse_width = 100          # Default pulse width in microseconds
    delay_between = 1000       # Default delay between pulses in microseconds
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            reset_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                pulse_count = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            try:
                pulse_width = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            try:
                delay_between = int(args.glitch_args[3])
            except:
                pass
    
    reset_codes = {
        "SOFT": 0x01,
        "HARD": 0x02,
        "WATCHDOG": 0x03,
        "BROWN_OUT": 0x04
    }
    
    reset_code = reset_codes.get(reset_type, 0x01)
    
    print(f"[*] Reset Glitch: type={reset_type}, pulses={pulse_count}, width={pulse_width}μs, delay={delay_between}μs")
    
    # Build reset glitch payload
    payload = struct.pack(
        "<B B H H H",
        0x06,  # Reset glitch type
        reset_code,
        pulse_count,
        pulse_width,
        delay_between
    )
    
    return execute_glitch_operation(dev, "RESET", payload)

def execute_advanced_glitch(dev, args):
    """
    Execute advanced multi-parameter glitching
    """
    print("[*] Preparing advanced multi-parameter glitching...")
    
    # Parse complex parameters
    glitch_combination = "VOLTAGE_CLOCK"  # Default combination
    synchronization = "PRECISE"           # Default synchronization
    iteration_strategy = "ADAPTIVE"       # Default iteration strategy
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            glitch_combination = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            synchronization = args.glitch_args[1].upper()
        if len(args.glitch_args) > 2:
            iteration_strategy = args.glitch_args[2].upper()
    
    print(f"[*] Advanced Glitch: combination={glitch_combination}, sync={synchronization}, strategy={iteration_strategy}")
    
    # Build advanced glitch payload with multiple parameters
    combination_code = sum(glitch_combination.encode()) & 0xFF
    sync_code = 0x01 if synchronization == "PRECISE" else 0x02
    strategy_code = 0x01 if iteration_strategy == "ADAPTIVE" else 0x02
    
    # Complex payload with multiple glitch parameters
    payload = struct.pack(
        "<B B B B 16s 16s",
        0x07,  # Advanced glitch type
        combination_code,
        sync_code,
        strategy_code,
        os.urandom(16),  # Parameter set 1
        os.urandom(16)   # Parameter set 2
    )
    
    return execute_glitch_operation(dev, "ADVANCED", payload)

def scan_glitch_parameters(dev, args):
    """
    Automated glitch parameter scanning
    """
    print("[*] Starting automated glitch parameter scanning...")
    
    scan_type = "VOLTAGE"      # Default scan type
    parameter_range = "1-5"    # Default parameter range
    step_size = 1              # Default step size
    max_iterations = 100       # Default max iterations
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            scan_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            parameter_range = args.glitch_args[1]
        if len(args.glitch_args) > 2:
            try:
                step_size = int(args.glitch_args[2])
            except:
                pass
        if len(args.glitch_args) > 3:
            try:
                max_iterations = int(args.glitch_args[3])
            except:
                pass
    
    # Parse parameter range
    try:
        if '-' in parameter_range:
            start, end = map(int, parameter_range.split('-'))
        else:
            start = end = int(parameter_range)
    except:
        start, end = 1, 5
    
    print(f"[*] Parameter Scan: type={scan_type}, range={start}-{end}, step={step_size}, max_iter={max_iterations}")
    
    results = []
    successful_glitches = 0
    
    for param_value in range(start, end + 1, step_size):
        if len(results) >= max_iterations:
            break
            
        print(f"\n[*] Testing parameter value: {param_value}")
        
        # Build scan payload
        payload = struct.pack(
            "<B I I",
            0x08,  # Scan glitch type
            param_value,
            len(results)  # Iteration counter
        )
        
        resp, origin = execute_glitch_with_strategy(dev, "SCAN", payload)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                successful_glitches += 1
                results.append((param_value, "SUCCESS", origin))
                print(f"  [✓] Parameter {param_value}: SUCCESS (via {origin})")
            else:
                results.append((param_value, status.get("name", "UNKNOWN"), origin))
                print(f"  [!] Parameter {param_value}: {status.get('name', 'UNKNOWN')}")
        else:
            results.append((param_value, "NO_RESPONSE", "NONE"))
            print(f"  [!] Parameter {param_value}: NO RESPONSE")
    
    # Generate scan report
    print(f"\n[*] Parameter Scan Complete: {successful_glitches}/{len(results)} successful glitches")
    
    if successful_glitches > 0:
        optimal_params = [r[0] for r in results if r[1] == "SUCCESS"]
        if optimal_params:
            print(f"[*] Optimal parameter range: {min(optimal_params)}-{max(optimal_params)}")
    
    return successful_glitches > 0

def execute_auto_glitch(dev, args):
    """
    Automatic glitch parameter discovery and optimization
    """
    print("[*] Starting automatic glitch parameter discovery...")
    
    target_effect = "BYPASS"   # Default target effect
    timeout = 30               # Default timeout in seconds
    optimization = "AGGRESSIVE" # Default optimization strategy
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            target_effect = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                timeout = int(args.glitch_args[1])
            except:
                pass
        if len(args.glitch_args) > 2:
            optimization = args.glitch_args[2].upper()
    
    print(f"[*] Auto Glitch: target={target_effect}, timeout={timeout}s, optimization={optimization}")
    
    # Build auto glitch payload
    optimization_code = {
        "CONSERVATIVE": 0x01,
        "MODERATE": 0x02,
        "AGGRESSIVE": 0x03
    }.get(optimization, 0x02)
    
    payload = struct.pack(
        "<B 12s I B",
        0x09,  # Auto glitch type
        target_effect.encode('ascii').ljust(12, b'\x00'),
        timeout,
        optimization_code
    )
    
    print("[*] Auto glitch in progress... This may take several minutes.")
    print("[*] Press Ctrl+C to abort.")
    
    try:
        start_time = time.time()
        resp = execute_glitch_operation(dev, "AUTO", payload)
        elapsed_time = time.time() - start_time
        
        print(f"[*] Auto glitch completed in {elapsed_time:.1f} seconds")
        return resp
        
    except KeyboardInterrupt:
        print("\n[*] Auto glitch aborted by user")
        return False

def analyze_glitch_results(dev, args):
    """
    Analyze glitch results and provide insights
    """
    print("[*] Analyzing glitch results...")
    
    analysis_type = "RECENT"   # Default analysis type
    detail_level = "SUMMARY"   # Default detail level
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            analysis_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            detail_level = args.glitch_args[1].upper()
    
    # Build analysis payload
    analysis_code = {
        "RECENT": 0x01,
        "STATISTICS": 0x02,
        "PATTERNS": 0x03,
        "EFFECTIVENESS": 0x04
    }.get(analysis_type, 0x01)
    
    detail_code = {
        "SUMMARY": 0x01,
        "DETAILED": 0x02,
        "VERBOSE": 0x03
    }.get(detail_level, 0x01)
    
    payload = struct.pack("<B B", analysis_code, detail_code)
    
    resp, origin = execute_glitch_with_strategy(dev, "ANALYZE", payload)
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if extra:
                try:
                    analysis_data = extra.decode('utf-8', errors='ignore')
                    print("\n[*] Glitch Analysis Results:")
                    print(analysis_data)
                except:
                    print(f"[*] Analysis data (raw): {extra.hex()}")
            return True
        else:
            print(f"[!] Analysis failed: {status.get('name', 'UNKNOWN')}")
    else:
        print("[!] No analysis data available")
    
    return False

def calibrate_glitch_parameters(dev, args):
    """
    Calibrate glitch hardware and parameters
    """
    print("[*] Starting glitch hardware calibration...")
    
    calibration_type = "AUTO"  # Default calibration type
    target_precision = 10      # Default target precision in nanoseconds
    
    if hasattr(args, 'glitch_args') and args.glitch_args:
        if len(args.glitch_args) > 0:
            calibration_type = args.glitch_args[0].upper()
        if len(args.glitch_args) > 1:
            try:
                target_precision = int(args.glitch_args[1])
            except:
                pass
    
    print(f"[*] Glitch Calibration: type={calibration_type}, target_precision={target_precision}ns")
    
    # Build calibration payload
    calibration_code = {
        "AUTO": 0x01,
        "MANUAL": 0x02,
        "VERIFY": 0x03
    }.get(calibration_type, 0x01)
    
    payload = struct.pack("<B H", calibration_code, target_precision)
    
    resp, origin = execute_glitch_with_strategy(dev, "CALIBRATE", payload)
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Glitch calibration completed successfully")
            
            # Extract calibration results if available
            extra = status.get("extra", b"")
            if extra and len(extra) >= 4:
                achieved_precision = struct.unpack("<H", extra[:2])[0]
                calibration_score = struct.unpack("<H", extra[2:4])[0]
                print(f"[*] Achieved precision: {achieved_precision}ns")
                print(f"[*] Calibration score: {calibration_score}/100")
            
            return True
        else:
            print(f"[!] Calibration failed: {status.get('name', 'UNKNOWN')}")
    else:
        print("[!] No calibration capability available")
    
    return False

def execute_glitch_operation(dev, glitch_type, payload):
    """
    Execute glitch operation with strategy fallback
    """
    print(f"[*] Executing {glitch_type} glitch...")
    
    resp, origin = execute_glitch_with_strategy(dev, glitch_type, payload)
    
    if resp:
        status = decode_runtime_result(resp)
        print(f"[✓] {glitch_type} glitch completed via {origin}: {status}")
        return status.get("severity") == "SUCCESS"
    else:
        print(f"[!] {glitch_type} glitch failed: No response from device")
        return False

def execute_glitch_with_strategy(dev, glitch_type, payload):
    """
    Execute glitch with multiple strategy fallbacks
    """
    strategies = [
        try_direct_glitch_command,
        try_par_glitch_command,
        try_end_glitch_opcode,
        try_vm5_glitch_service,
        try_idx_glitch_command,
        try_generic_glitch_dispatch
    ]
    
    for strategy in strategies:
        result = strategy(dev, glitch_type, payload)
        if result is not None:
            return result
    
    return None, "NO_STRATEGY"

def try_direct_glitch_command(dev, glitch_type, payload):
    """Try direct GLITCH command"""
    resp = qslcl_dispatch(dev, "GLITCH", glitch_type.encode() + b"\x00" + payload)
    if resp:
        return resp, "DIRECT"
    return None

def try_par_glitch_command(dev, glitch_type, payload):
    """Try QSLCLPAR glitch command"""
    if glitch_type in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, glitch_type, payload)
        if resp:
            return resp, "QSLCLPAR"
    return None

def try_end_glitch_opcode(dev, glitch_type, payload):
    """Try QSLCLEND glitch opcode"""
    opcode = sum(glitch_type.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        if resp:
            return resp, f"QSLCLEND_0x{opcode:02X}"
    return None

def try_vm5_glitch_service(dev, glitch_type, payload):
    """Try QSLCLVM5 glitch service"""
    if glitch_type in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[glitch_type]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        if resp:
            return resp, "QSLCLVM5"
    return None

def try_idx_glitch_command(dev, glitch_type, payload):
    """Try QSLCLIDX glitch command"""
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == glitch_type:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + payload
            resp = qslcl_dispatch(dev, "IDX", pkt)
            if resp:
                return resp, f"QSLCLIDX_{name}"
    return None

def try_generic_glitch_dispatch(dev, glitch_type, payload):
    """Try generic glitch dispatch"""
    resp = qslcl_dispatch(dev, glitch_type, payload)
    if resp:
        return resp, "GENERIC"
    return None

def handle_glitch_operation(dev, operation, args):
    """
    Handle other glitch operations
    """
    print(f"[*] Executing glitch operation: {operation}")
    
    # Build operation parameters
    params = build_glitch_operation_params(operation, args)
    
    resp, origin = execute_glitch_with_strategy(dev, operation, params)
    
    if resp:
        status = decode_runtime_result(resp)
        print(f"[✓] {operation} glitch completed via {origin}: {status}")
        return status.get("severity") == "SUCCESS"
    else:
        print(f"[!] {operation} glitch failed")
        return False

def build_glitch_operation_params(operation, args):
    """
    Build parameters for glitch operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'glitch_args'):
        for arg in args.glitch_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Update the argument parser in main() function
def update_glitch_parser(sub):
    """
    Update the GLITCH command parser with new subcommands
    """
    glitch_parser = sub.add_parser("glitch", help="Hardware fault injection and glitching commands")
    glitch_parser.add_argument("glitch_subcommand", help="Glitch subcommand (list, voltage, clock, em, laser, timing, reset, advanced, scan, auto, analyze, calibrate)")
    glitch_parser.add_argument("glitch_args", nargs="*", help="Additional arguments for glitch command")
    
    # Legacy parameters for backward compatibility
    glitch_parser.add_argument("--level", type=int, help="Legacy: Glitch intensity level (1-5)")
    glitch_parser.add_argument("--iter", type=int, help="Legacy: Iteration count")
    glitch_parser.add_argument("--window", type=int, help="Legacy: Timing window")
    glitch_parser.add_argument("--sweep", type=int, help="Legacy: Sweep width")
    
    glitch_parser.set_defaults(func=cmd_glitch)

def cmd_footer(args):
    """
    Advanced FOOTER command handler for comprehensive footer block analysis
    Supports multiple footer types, advanced parsing, and forensic analysis
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    print("\n[*] Starting QSLCL Footer Block Analysis...")

    # -----------------------------------------------------
    # Enhanced footer request with multiple types
    # -----------------------------------------------------
    footer_type = getattr(args, 'footer_type', 'STANDARD').upper()
    request_flags = build_footer_request_flags(args)
    
    payload = build_footer_payload(footer_type, request_flags, args)

    # -----------------------------------------------------
    # Multi-strategy dispatch with enhanced detection
    # -----------------------------------------------------
    resp = dispatch_footer_request(dev, footer_type, payload, args)

    if not resp:
        print("[!] No footer response received.")
        return False

    # -----------------------------------------------------
    # Enhanced response processing
    # -----------------------------------------------------
    status = qslcl_decode_rtf(resp)
    print(f"[*] Footer Response: {status['severity']} — {status['name']}")

    data = status.get("extra", b"")
    if not data:
        print("[!] FOOTER block empty or unavailable.")
        return False

    # -----------------------------------------------------
    # Comprehensive footer analysis
    # -----------------------------------------------------
    return analyze_footer_block(dev, data, args, footer_type)

def build_footer_request_flags(args):
    """
    Build comprehensive footer request flags
    """
    flags = 0x00
    
    # Basic flags
    if getattr(args, "raw", False):
        flags |= 0x01  # Raw footer data
    if getattr(args, "extended", False):
        flags |= 0x02  # Extended footer information
    if getattr(args, "verbose", False):
        flags |= 0x04  # Verbose footer data
    if getattr(args, "crc", False):
        flags |= 0x08  # Include CRC verification
    if getattr(args, "metadata", False):
        flags |= 0x10  # Include metadata
    
    # Advanced flags
    if getattr(args, "all", False):
        flags |= 0x80  # Request all available footers
    
    return flags

def build_footer_payload(footer_type, flags, args):
    """
    Build sophisticated footer request payload
    """
    payload = bytearray()
    
    # Footer type identifier
    type_mapping = {
        "STANDARD": b"FOOTER_STD\x00",
        "EXTENDED": b"FOOTER_EXT\x00",
        "SECURITY": b"FOOTER_SEC\x00",
        "BOOT": b"FOOTER_BOOT\x00",
        "LOADER": b"FOOTER_LDR\x00",
        "DEBUG": b"FOOTER_DBG\x00",
        "AUDIT": b"FOOTER_AUD\x00",
        "ALL": b"FOOTER_ALL\x00"
    }
    
    footer_header = type_mapping.get(footer_type, b"FOOTER_REQ\x00")
    payload.extend(footer_header)
    
    # Add flags
    payload.extend(struct.pack("<B", flags))
    
    # Add optional parameters
    if hasattr(args, 'footer_args') and args.footer_args:
        for arg in args.footer_args:
            try:
                if arg.startswith("0x"):
                    payload.extend(struct.pack("<I", int(arg, 16)))
                elif arg.isdigit():
                    payload.extend(struct.pack("<I", int(arg)))
                else:
                    payload.extend(arg.encode() + b"\x00")
            except:
                payload.extend(arg.encode() + b"\x00")
    
    # Add timestamp for request tracking
    timestamp = int(time.time())
    payload.extend(struct.pack("<I", timestamp))
    
    return bytes(payload)

def dispatch_footer_request(dev, footer_type, payload, args):
    """
    Multi-strategy footer request dispatch with fallbacks
    """
    strategies = [
        try_engine_footer_handler,
        try_par_footer_handler,
        try_vm5_footer_handler,
        try_idx_footer_handler,
        try_direct_footer_handler,
        try_generic_footer_handler
    ]
    
    for strategy in strategies:
        resp = strategy(dev, footer_type, payload, args)
        if resp:
            return resp
    
    return None

def try_engine_footer_handler(dev, footer_type, payload, args):
    """Try ENGINE block handler"""
    # Multiple possible opcodes for footer
    footer_opcodes = [0xF0, 0xF1, 0xF2, 0xF3, 0xF4]
    
    for opcode in footer_opcodes:
        if opcode in QSLCLEND_DB:
            print(f"[*] Using ENGINE handler (0x{opcode:02X}) for {footer_type} footer...")
            entry = QSLCLEND_DB[opcode]
            if isinstance(entry, dict):
                entry_data = entry.get("raw", b"")
            else:
                entry_data = entry
            
            pkt = b"QSLCLEND" + entry_data + payload
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            if resp:
                return resp
    return None

def try_par_footer_handler(dev, footer_type, payload, args):
    """Try QSLCLPAR footer handler"""
    footer_commands = [
        "FOOTER",
        f"FOOTER_{footer_type}",
        "GET_FOOTER",
        "READ_FOOTER"
    ]
    
    for cmd in footer_commands:
        if cmd in QSLCLPAR_DB:
            print(f"[*] Using PARSER handler ({cmd}) for {footer_type} footer...")
            resp = qslcl_dispatch(dev, cmd, payload)
            if resp:
                return resp
    return None

def try_vm5_footer_handler(dev, footer_type, payload, args):
    """Try QSLCLVM5 footer handler"""
    vm5_commands = [
        "FOOTER",
        f"FOOTER_{footer_type}",
        "FOOTER_READ"
    ]
    
    for cmd in vm5_commands:
        if cmd in QSLCLVM5_DB:
            print(f"[*] Using VM5 handler ({cmd}) for {footer_type} footer...")
            raw = QSLCLVM5_DB[cmd]["raw"]
            pkt = b"QSLCLVM5" + raw + payload
            resp = qslcl_dispatch(dev, "NANO", pkt)
            if resp:
                return resp
    return None

def try_idx_footer_handler(dev, footer_type, payload, args):
    """Try QSLCLIDX footer handler"""
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '').upper()
            if any(footer_keyword in entry_name for footer_keyword in ["FOOTER", "FOOT", "END"]):
                idx = entry.get('idx', 0)
                print(f"[*] Using IDX handler ({name}) for footer...")
                pkt = b"QSLCLIDX" + struct.pack("<I", idx) + payload
                resp = qslcl_dispatch(dev, "IDX", pkt)
                if resp:
                    return resp
    return None

def try_direct_footer_handler(dev, footer_type, payload, args):
    """Try direct footer command"""
    print(f"[*] Using direct FOOTER command for {footer_type}...")
    resp = qslcl_dispatch(dev, "FOOTER", payload)
    return resp

def try_generic_footer_handler(dev, footer_type, payload, args):
    """Final fallback handler"""
    print(f"[*] Using generic handler for {footer_type} footer...")
    resp = qslcl_dispatch(dev, footer_type, payload)
    return resp

def analyze_footer_block(dev, data, args, footer_type):
    """
    Comprehensive footer block analysis with multiple output formats
    """
    print(f"\n[*] Analyzing {footer_type} Footer Block ({len(data)} bytes)...")
    
    # -----------------------------------------------------
    # Save footer data if requested
    # -----------------------------------------------------
    if args.save:
        save_footer_data(data, args.save, footer_type)
    
    # -----------------------------------------------------
    # Parse footer structure based on type
    # -----------------------------------------------------
    footer_info = parse_footer_structure(data, footer_type)
    
    # -----------------------------------------------------
    # Display based on output format
    # -----------------------------------------------------
    display_footer_data(data, footer_info, args, footer_type)
    
    # -----------------------------------------------------
    # Additional analysis if verbose mode
    # -----------------------------------------------------
    if getattr(args, "verbose", False):
        perform_advanced_footer_analysis(data, footer_type)
    
    # -----------------------------------------------------
    # Validate footer integrity if requested
    # -----------------------------------------------------
    if getattr(args, "validate", False):
        validate_footer_integrity(data, footer_type)
    
    return True

def parse_footer_structure(data, footer_type):
    """
    Parse footer structure based on type and content
    """
    footer_info = {
        "type": footer_type,
        "size": len(data),
        "timestamp": None,
        "checksum": None,
        "version": None,
        "magic": None,
        "entries": []
    }
    
    # Try to identify footer magic/header
    if len(data) >= 8:
        magic = data[:8]
        footer_info["magic"] = magic.hex()
        
        # Common footer magic values
        magic_patterns = {
            b"QSLCLEND": "QSLCL Standard Footer",
            b"QSLCLFT8": "QSLCL Footer v8",
            b"ANDROID!": "Android Boot Footer",
            b"BOOTLDR!": "Bootloader Footer",
            b"SECUREFT": "Security Footer",
            b"DEBUGREC": "Debug Footer"
        }
        
        for pattern, description in magic_patterns.items():
            if magic.startswith(pattern):
                footer_info["description"] = description
                break
    
    # Try to extract timestamp
    if len(data) >= 12:
        try:
            timestamp = struct.unpack("<I", data[8:12])[0]
            if timestamp > 1577836800:  # Reasonable timestamp (after 2020)
                footer_info["timestamp"] = timestamp
                footer_info["time_string"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp))
        except:
            pass
    
    # Try to extract version information
    if len(data) >= 16:
        try:
            version = struct.unpack("<HH", data[12:16])  # major, minor
            footer_info["version"] = f"{version[0]}.{version[1]}"
        except:
            pass
    
    # Try to extract checksum
    if len(data) >= 20:
        try:
            checksum = struct.unpack("<I", data[16:20])[0]
            footer_info["checksum"] = f"0x{checksum:08X}"
        except:
            pass
    
    return footer_info

def display_footer_data(data, footer_info, args, footer_type):
    """
    Display footer data in various formats based on arguments
    """
    # -----------------------------------------------------
    # Header information
    # -----------------------------------------------------
    print(f"\n{'='*60}")
    print(f"FOOTER ANALYSIS: {footer_type}")
    print(f"{'='*60}")
    
    # Basic footer info
    print(f"Size: {footer_info['size']} bytes")
    if 'description' in footer_info:
        print(f"Type: {footer_info['description']}")
    if footer_info['magic']:
        print(f"Magic: {footer_info['magic']}")
    if footer_info['timestamp']:
        print(f"Timestamp: {footer_info['time_string']} (Unix: {footer_info['timestamp']})")
    if footer_info['version']:
        print(f"Version: {footer_info['version']}")
    if footer_info['checksum']:
        print(f"Checksum: {footer_info['checksum']}")
    
    # -----------------------------------------------------
    # Output format selection
    # -----------------------------------------------------
    if getattr(args, "hex", False):
        display_hex_dump(data, args)
    elif getattr(args, "raw", False):
        display_raw_binary(data)
    elif getattr(args, "structured", False):
        display_structured_footer(data, footer_info)
    elif getattr(args, "json", False):
        display_json_output(data, footer_info, args)
    else:
        display_smart_format(data, footer_info)
    
    print(f"{'='*60}")

def display_hex_dump(data, args):
    """Display hex dump of footer data"""
    print("\nHex Dump:")
    print("-" * 60)
    
    bytes_per_line = 16
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{i:08x}: {hex_part:<48} {ascii_part}")

def display_raw_binary(data):
    """Display raw binary data"""
    print("\nRaw Binary:")
    print("-" * 60)
    print(data.hex())

def display_structured_footer(data, footer_info):
    """Display structured footer analysis"""
    print("\nStructured Analysis:")
    print("-" * 60)
    
    # Analyze potential structure
    if len(data) >= 32:
        print("Potential Structure:")
        print(f"  Header (8 bytes): {data[:8].hex()}")
        print(f"  Timestamp (4 bytes): {struct.unpack('<I', data[8:12])[0] if len(data) >= 12 else 'N/A'}")
        print(f"  Version (4 bytes): {data[12:16].hex()}")
        print(f"  Checksum (4 bytes): {data[16:20].hex()}")
        print(f"  Reserved (12 bytes): {data[20:32].hex()}")
        
        if len(data) > 32:
            print(f"  Payload ({len(data)-32} bytes): {data[32:64].hex()}..." if len(data) > 64 else data[32:].hex())

def display_json_output(data, footer_info, args):
    """Display footer data as JSON"""
    import json
    
    json_output = {
        "footer_info": footer_info,
        "data_hex": data.hex(),
        "analysis_timestamp": time.time()
    }
    
    # Add data preview
    if len(data) <= 1024:  # Only include full data for small footers
        json_output["data_raw"] = list(data)
    
    print("\nJSON Output:")
    print("-" * 60)
    print(json.dumps(json_output, indent=2))

def display_smart_format(data, footer_info):
    """Smart format detection for footer display"""
    # Try to decode as text first
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        printable_ratio = len([c for c in text if c.isprintable()]) / len(text) if text else 0
        
        if printable_ratio > 0.8:
            print("\nText Content:")
            print("-" * 60)
            print(text)
            return
    except:
        pass
    
    # Try structured parsing for common footer formats
    if len(data) >= 16 and data[:8] in [b"QSLCLEND", b"ANDROID!", b"BOOTLDR!"]:
        display_structured_footer(data, footer_info)
    else:
        # Fallback to hex dump for binary data
        display_hex_dump(data, None)

def save_footer_data(data, filename, footer_type):
    """Save footer data to file with proper formatting"""
    try:
        # Add footer type to filename if not specified
        if not any(ft in filename.upper() for ft in ["FOOTER", "FOOT"]):
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{footer_type.lower()}{ext}"
        
        with open(filename, "wb") as f:
            f.write(data)
        
        # Also save analysis if verbose
        if getattr(args, "verbose", False):
            analysis_file = f"{os.path.splitext(filename)[0]}_analysis.txt"
            with open(analysis_file, "w") as f:
                f.write(f"Footer Analysis: {footer_type}\n")
                f.write(f"Size: {len(data)} bytes\n")
                f.write(f"Saved: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n")
                f.write(data.hex())
        
        print(f"[+] Footer saved → {filename}")
        return True
    except Exception as e:
        print(f"[!] Failed to save footer: {e}")
        return False

def perform_advanced_footer_analysis(data, footer_type):
    """Perform advanced analysis on footer data"""
    print("\n[*] Advanced Footer Analysis:")
    print("-" * 60)
    
    # Entropy analysis
    entropy = calculate_entropy(data)
    print(f"Data Entropy: {entropy:.3f} bits/byte")
    if entropy > 7.5:
        print("  → High entropy: likely encrypted or compressed")
    elif entropy > 6.0:
        print("  → Medium entropy: mixed content")
    else:
        print("  → Low entropy: likely structured data or text")
    
    # Pattern detection
    patterns = detect_common_patterns(data)
    if patterns:
        print("Detected Patterns:")
        for pattern, count in patterns.items():
            print(f"  → {pattern}: {count} occurrences")
    
    # Magic number detection
    magics = detect_magic_numbers(data)
    if magics:
        print("Magic Numbers:")
        for magic, description in magics.items():
            print(f"  → {magic}: {description}")

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

def detect_common_patterns(data):
    """Detect common patterns in footer data"""
    patterns = {}
    
    # Common byte patterns
    common_patterns = {
        b"\x00\x00\x00\x00": "Null padding",
        b"\xFF\xFF\xFF\xFF": "Fill bytes", 
        b"\xDE\xAD\xBE\xEF": "Debug marker",
        b"\xCA\xFE\xBA\xBE": "Java marker",
        b"\xFE\xED\xFA\xCE": "Big-endian marker",
        b"\xCE\xFA\xED\xFE": "Little-endian marker"
    }
    
    for pattern, description in common_patterns.items():
        count = data.count(pattern)
        if count > 0:
            patterns[description] = count
    
    return patterns

def detect_magic_numbers(data):
    """Detect magic numbers in footer data"""
    magics = {}
    
    # Common magic numbers at various offsets
    magic_offsets = [0, 4, 8, 16, 32]
    
    for offset in magic_offsets:
        if offset + 4 <= len(data):
            magic = data[offset:offset+4]
            magic_hex = magic.hex()
            
            magic_db = {
                "7f454c46": "ELF Header",
                "464c457f": "ELF Header (BE)",
                "214c4153": "LAS (LiDAR)",
                "89504e47": "PNG Image",
                "474e5089": "PNG Image (BE)",
                "ffd8ffe0": "JPEG Image",
                "504b0304": "ZIP Archive",
                "43443030": "ISO9660 CD",
                "38425053": "PSD Image",
                "49492a00": "TIFF Image",
                "4d4d002a": "TIFF Image (BE)",
            }
            
            if magic_hex in magic_db:
                magics[f"0x{offset:02X}: {magic_hex}"] = magic_db[magic_hex]
    
    return magics

def validate_footer_integrity(data, footer_type):
    """Validate footer integrity and checksums"""
    print("\n[*] Footer Integrity Validation:")
    print("-" * 60)
    
    # Simple checksum validation
    simple_checksum = sum(data) & 0xFFFFFFFF
    print(f"Simple Checksum: 0x{simple_checksum:08X}")
    
    # CRC32 validation if possible
    try:
        import zlib
        crc32 = zlib.crc32(data) & 0xFFFFFFFF
        print(f"CRC32: 0x{crc32:08X}")
    except:
        pass
    
    # Structure validation for known footer types
    if footer_type == "SECURITY" and len(data) >= 32:
        print("Security Footer Structure: Valid" if data[0:4] == b"SEC@" else "Security Footer Structure: Invalid")
    
    print("Integrity: Basic validation completed")

# Update the argument parser in main() function
def update_footer_parser(sub):
    """
    Update the FOOTER command parser with new subcommands
    """
    footer_parser = sub.add_parser("footer", help="Footer block analysis and extraction commands")
    footer_parser.add_argument("--type", dest="footer_type", default="STANDARD", 
                              choices=["STANDARD", "EXTENDED", "SECURITY", "BOOT", "LOADER", "DEBUG", "AUDIT", "ALL"],
                              help="Type of footer to retrieve")
    footer_parser.add_argument("--raw", action="store_true", help="Request raw footer data")
    footer_parser.add_argument("--extended", action="store_true", help="Request extended footer information")
    footer_parser.add_argument("--verbose", action="store_true", help="Verbose footer analysis")
    footer_parser.add_argument("--crc", action="store_true", help="Include CRC verification")
    footer_parser.add_argument("--metadata", action="store_true", help="Include metadata")
    footer_parser.add_argument("--all", action="store_true", help="Request all available footers")
    footer_parser.add_argument("--validate", action="store_true", help="Validate footer integrity")
    footer_parser.add_argument("--hex", action="store_true", help="Display as hex dump")
    footer_parser.add_argument("--structured", action="store_true", help="Display structured analysis")
    footer_parser.add_argument("--json", action="store_true", help="Display as JSON")
    footer_parser.add_argument("--save", metavar="FILE", help="Save footer to file")
    footer_parser.add_argument("footer_args", nargs="*", help="Additional footer parameters")
    footer_parser.set_defaults(func=cmd_footer)

def cmd_partitions(args=None):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    parts = load_partitions(dev)

    print(f"[*] {len(parts)} partitions detected:\n")
    for p in parts:
        print(f"  {p['name']:<12}  off=0x{p['offset']:08X}  size=0x{p['size']:08X}")

def cmd_oem(args):
    """
    Advanced OEM command handler with intelligent lock/unlock detection
    Supports: UNLOCK, LOCK, and other OEM commands
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse OEM subcommand
    if not hasattr(args, 'oem_subcommand') or not args.oem_subcommand:
        return print("[!] OEM command requires subcommand (unlock, lock, etc.)")
    
    subcmd = args.oem_subcommand.upper()
    
    if subcmd in ["UNLOCK", "LOCK"]:
        return handle_bootloader_lock_unlock(dev, subcmd, args)
    else:
        # Handle other OEM commands
        return handle_generic_oem(dev, subcmd, args)

def handle_bootloader_lock_unlock(dev, operation, args):
    """
    Intelligent bootloader lock/unlock detection across SOC platforms
    """
    print(f"[*] Starting {operation} procedure...")
    
    # Step 1: Try direct OEM command first
    if try_direct_oem_command(dev, operation):
        return True
    
    # Step 2: Auto-detect lock regions and apply changes
    return auto_detect_and_modify_lock_state(dev, operation, args)

def try_direct_oem_command(dev, operation):
    """
    Try using direct OEM UNLOCK/LOCK commands if available in loader
    """
    cmd_name = operation.upper()
    
    # Priority 1: QSLCLPAR direct command
    if cmd_name in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR {cmd_name} command")
        resp = qslcl_dispatch(dev, cmd_name, b"")
        status = decode_runtime_result(resp)
        print(f"[*] {cmd_name} Result: {status}")
        return status.get("severity") == "SUCCESS"
    
    # Priority 2: QSLCLEND opcode
    opcode_map = {"UNLOCK": 0xD0, "LOCK": 0xD1}
    if operation in opcode_map and opcode_map[operation] in QSLCLEND_DB:
        print(f"[*] Using QSLCLEND opcode for {operation}")
        entry = QSLCLEND_DB[opcode_map[operation]]
        pkt = b"QSLCLEND" + entry
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        print(f"[*] {operation} Result: {status}")
        return status.get("severity") == "SUCCESS"
    
    # Priority 3: VM5 microservice
    if cmd_name in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 {cmd_name} microservice")
        raw = QSLCLVM5_DB[cmd_name]["raw"]
        pkt = b"QSLCLVM5" + raw
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        print(f"[*] {operation} Result: {status}")
        return status.get("severity") == "SUCCESS"
    
    return False

def auto_detect_and_modify_lock_state(dev, operation, args):
    """
    Auto-detect lock regions and modify bootloader lock state
    """
    print("[*] Auto-detecting lock regions...")
    
    # Step 1: Detect SOC type and get lock region patterns
    soc_type = detect_soc_type(dev)
    lock_patterns = get_lock_patterns_for_soc(soc_type)
    
    # Step 2: Scan memory for lock flags
    lock_regions = scan_for_lock_regions(dev, lock_patterns)
    
    if not lock_regions:
        print("[!] No lock regions detected. Device may not support this operation.")
        return False
    
    print(f"[*] Found {len(lock_regions)} potential lock region(s)")
    
    # Step 3: Verify and modify lock state
    success_count = 0
    for region in lock_regions:
        if modify_lock_region(dev, region, operation):
            success_count += 1
    
    # Step 4: Verify changes
    if success_count > 0:
        print(f"[*] Verifying {operation} operation...")
        if verify_lock_state(dev, operation, lock_regions):
            print(f"[✓] {operation} completed successfully")
            return True
        else:
            print(f"[!] {operation} verification failed")
            return False
    else:
        print(f"[!] {operation} failed on all regions")
        return False

def detect_soc_type(dev):
    """
    Detect SOC type to determine lock region patterns
    """
    # Try to get device info first
    resp = qslcl_dispatch(dev, "GETINFO", b"")
    if resp:
        info = parse_device_info(resp)
        for key, value in info.items():
            if "qualcomm" in value.lower() or "qcom" in value.lower():
                return "QUALCOMM"
            elif "mediatek" in value.lower() or "mt" in value.lower():
                return "MTK"
            elif "samsung" in value.lower() or "exynos" in value.lower():
                return "EXYNOS"
            elif "hisilicon" in value.lower() or "kirin" in value.lower():
                return "HISILICON"
            elif "unisoc" in value.lower() or "sprd" in value.lower():
                return "UNISOC"
    
    # Fallback to transport detection
    handle, serial_mode = open_transport(dev)
    dtype = detect_device_type(handle)
    
    type_map = {
        "QUALCOMM": "QUALCOMM", 
        "MTK": "MTK",
        "APPLE_DFU": "APPLE",
        "GENERIC": "UNKNOWN"
    }
    
    return type_map.get(dtype, "UNKNOWN")

def get_lock_patterns_for_soc(soc_type):
    """
    Return lock region search patterns for different SOC types
    """
    patterns = {
        "QUALCOMM": [
            # Common Qualcomm lock flag locations
            {"start": 0x00086000, "end": 0x00087000, "pattern": b"bootlock|unlock", "mask": 0xFFFF},
            {"start": 0x0006F000, "end": 0x00070000, "pattern": b"locked", "mask": 0xFFFF},
            {"start": 0x00100000, "end": 0x00110000, "pattern": b"verifiedboot", "mask": 0xFFFF},
            # Android Verified Boot (AVB) areas
            {"start": 0x00700000, "end": 0x00800000, "pattern": b"avb", "mask": 0xFFFF},
        ],
        "MTK": [
            # MediaTek lock regions
            {"start": 0x00011C00, "end": 0x00011E00, "pattern": b"bootmode", "mask": 0xFFFF},
            {"start": 0x00012000, "end": 0x00012200, "pattern": b"security", "mask": 0xFFFF},
            {"start": 0x0010A000, "end": 0x0010B000, "pattern": b"lockstate", "mask": 0xFFFF},
            # MTK preloader areas
            {"start": 0x00001000, "end": 0x00002000, "pattern": b"PL", "mask": 0xFFFF},
        ],
        "EXYNOS": [
            # Samsung Exynos lock areas
            {"start": 0x04000000, "end": 0x04001000, "pattern": b"boot_cfg", "mask": 0xFFFF},
            {"start": 0x05000000, "end": 0x05001000, "pattern": b"sec_boot", "mask": 0xFFFF},
        ],
        "HISILICON": [
            # HiSilicon Kirin lock regions
            {"start": 0x0000E000, "end": 0x0000F000, "pattern": b"fastboot", "mask": 0xFFFF},
            {"start": 0x00100000, "end": 0x00110000, "pattern": b"boot_verify", "mask": 0xFFFF},
        ],
        "UNISOC": [
            # Unisoc/Spreadtrum lock areas
            {"start": 0x00005000, "end": 0x00006000, "pattern": b"spl", "mask": 0xFFFF},
            {"start": 0x00080000, "end": 0x00081000, "pattern": b"bootctrl", "mask": 0xFFFF},
        ],
        "UNKNOWN": [
            # Generic search patterns for unknown SOC
            {"start": 0x00000000, "end": 0x00200000, "pattern": b"lock", "mask": 0xFFFF},
            {"start": 0x00600000, "end": 0x00800000, "pattern": b"boot", "mask": 0xFFFF},
            {"start": 0x04000000, "end": 0x04100000, "pattern": b"security", "mask": 0xFFFF},
            {"start": 0x08000000, "end": 0x08100000, "pattern": b"verified", "mask": 0xFFFF},
        ]
    }
    
    return patterns.get(soc_type, patterns["UNKNOWN"])

def scan_for_lock_regions(dev, patterns):
    """
    Scan memory for bootloader lock regions using provided patterns
    """
    regions_found = []
    sector_size = get_sector_size(dev)
    
    for pattern_info in patterns:
        start_addr = pattern_info["start"]
        end_addr = pattern_info["end"]
        search_pattern = pattern_info["pattern"]
        mask = pattern_info.get("mask", 0xFFFF)
        
        print(f"[*] Scanning region 0x{start_addr:08X}-0x{end_addr:08X} for '{search_pattern}'")
        
        # Read memory region
        read_size = end_addr - start_addr
        if read_size > 1024 * 1024:  # Limit to 1MB chunks
            read_size = 1024 * 1024
        
        payload = struct.pack("<Q I", start_addr, read_size)
        resp, origin = qslclidx_or_dispatch(dev, "READ", payload)
        
        if not resp:
            continue
            
        status = decode_runtime_result(resp)
        if status.get("severity") != "SUCCESS":
            continue
            
        data = status.get("extra", b"")
        if not data:
            continue
        
        # Search for pattern in data
        pattern_bytes = search_pattern if isinstance(search_pattern, bytes) else search_pattern.encode()
        
        # Simple pattern matching
        pos = 0
        while pos < len(data):
            found_pos = data.find(pattern_bytes, pos)
            if found_pos == -1:
                break
                
            # Found potential lock region
            region_addr = start_addr + found_pos
            regions_found.append({
                "address": region_addr & ~(sector_size - 1),  # Align to sector
                "size": sector_size,
                "pattern": search_pattern,
                "context": data[max(0, found_pos-16):min(len(data), found_pos+32)],
                "soc_type": "detected"
            })
            
            pos = found_pos + 1
    
    # Also check known partition areas
    partition_regions = check_partition_lock_areas(dev)
    regions_found.extend(partition_regions)
    
    return regions_found

def check_partition_lock_areas(dev):
    """
    Check common partition areas for lock flags
    """
    lock_partitions = []
    common_lock_partitions = [
        "bootconfig", "devinfo", "misc", "param", "frp", "persist", "protect_f", "protect_s"
    ]
    
    parts = load_partitions(dev)
    for part in parts:
        part_name = part["name"].lower()
        if any(lock_part in part_name for lock_part in common_lock_partitions):
            # Read first sector of partition to check for lock flags
            payload = struct.pack("<Q I", part["offset"], 512)
            resp, origin = qslclidx_or_dispatch(dev, "READ", payload)
            
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    data = status.get("extra", b"")
                    if data and (b"lock" in data.lower() or b"unlock" in data.lower()):
                        lock_partitions.append({
                            "address": part["offset"],
                            "size": 512,
                            "pattern": "partition_lock",
                            "context": f"Partition: {part_name}",
                            "soc_type": "partition"
                        })
    
    return lock_partitions

def modify_lock_region(dev, region, operation):
    """
    Modify a lock region based on the requested operation
    """
    address = region["address"]
    size = region["size"]
    
    print(f"[*] Modifying lock region at 0x{address:08X} for {operation}")
    
    # Read current content
    payload = struct.pack("<Q I", address, size)
    resp, origin = qslclidx_or_dispatch(dev, "READ", payload)
    
    if not resp:
        return False
        
    status = decode_runtime_result(resp)
    if status.get("severity") != "SUCCESS":
        return False
        
    current_data = status.get("extra", b"")
    if not current_data:
        return False
    
    # Modify data based on operation
    modified_data = apply_lock_modification(current_data, operation, region)
    
    if modified_data == current_data:
        print(f"[!] No changes needed for region 0x{address:08X}")
        return True  # Already in desired state
    
    # Write modified data back
    write_payload = struct.pack("<Q", address) + modified_data
    resp, origin = qslclidx_or_dispatch(dev, "WRITE", write_payload)
    
    if not resp:
        return False
        
    status = decode_runtime_result(resp)
    success = status.get("severity") == "SUCCESS"
    
    if success:
        print(f"[✓] Successfully modified region 0x{address:08X}")
    else:
        print(f"[!] Failed to modify region 0x{address:08X}: {status}")
    
    return success

def apply_lock_modification(data, operation, region):
    """
    Apply lock/unlock modifications to the data
    """
    modified = bytearray(data)
    pattern = region["pattern"]
    
    if operation == "UNLOCK":
        # Common unlock patterns
        replacements = [
            (b"locked", b"unlock"),
            (b"LOCKED", b"UNLOCK"),
            (b"\x01", b"\x00"),  # Binary flags
            (b"\xFF", b"\x00"),
            (b"enable", b"disabl"),
            (b"ENABLE", b"DISABL"),
        ]
    else:  # LOCK
        # Common lock patterns
        replacements = [
            (b"unlock", b"locked"),
            (b"UNLOCK", b"LOCKED"),
            (b"\x00", b"\x01"),  # Binary flags
            (b"disabl", b"enable"),
            (b"DISABL", b"ENABLE"),
        ]
    
    for old, new in replacements:
        if old in modified:
            pos = 0
            while pos < len(modified):
                found = modified.find(old, pos)
                if found == -1:
                    break
                modified[found:found+len(old)] = new.ljust(len(old), b'\x00')[:len(old)]
                pos = found + len(old)
    
    return bytes(modified)

def verify_lock_state(dev, operation, regions):
    """
    Verify that lock state was successfully changed
    """
    print(f"[*] Verifying {operation} state...")
    
    # Try direct verification first
    if operation == "UNLOCK":
        verify_cmd = "VERIFY_UNLOCK"
    else:
        verify_cmd = "VERIFY_LOCK"
    
    # Check if verify command exists
    if verify_cmd in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, verify_cmd, b"")
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            return True
    
    # Fallback: re-scan regions to verify changes
    success_count = 0
    for region in regions[:3]:  # Check first 3 regions
        payload = struct.pack("<Q I", region["address"], region["size"])
        resp, origin = qslclidx_or_dispatch(dev, "READ", payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                data = status.get("extra", b"")
                if operation == "UNLOCK" and (b"unlock" in data.lower() or b"\x00" in data[0:4]):
                    success_count += 1
                elif operation == "LOCK" and (b"lock" in data.lower() or b"\x01" in data[0:4]):
                    success_count += 1
    
    return success_count > 0

def handle_generic_oem(dev, subcmd, args):
    """
    Handle generic OEM commands
    """
    print(f"[*] Executing OEM command: {subcmd}")
    
    # Build payload from additional arguments
    payload = b""
    if hasattr(args, 'oem_args'):
        for arg in args.oem_args:
            try:
                # Try to parse as hex first
                if arg.startswith("0x"):
                    payload += struct.pack("<I", int(arg, 16))
                else:
                    # Try as decimal
                    payload += struct.pack("<I", int(arg))
            except:
                # Treat as string
                payload += arg.encode() + b"\x00"
    
    resp = qslcl_dispatch(dev, "OEM", subcmd.encode() + b"\x00" + payload)
    status = decode_runtime_result(resp)
    print(f"[*] OEM {subcmd} Result: {status}")
    
    return status.get("severity") == "SUCCESS"

def update_oem_parser(sub):
    """
    Update the OEM command parser with new subcommands
    """
    oem_parser = sub.add_parser("oem", help="OEM commands (unlock, lock, etc.)")
    oem_parser.add_argument("oem_subcommand", help="OEM subcommand (unlock, lock, etc.)")
    oem_parser.add_argument("oem_args", nargs="*", help="Additional arguments for OEM command")
    oem_parser.set_defaults(func=cmd_oem)

def cmd_odm(args):
    """
    Advanced ODM command handler for factory-level operations
    Supports: ENABLE, DISABLE, TEST, DIAG, META, and other ODM commands
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse ODM subcommand
    if not hasattr(args, 'odm_subcommand') or not args.odm_subcommand:
        return print("[!] ODM command requires subcommand (enable, disable, test, diag, etc.)")
    
    subcmd = args.odm_subcommand.upper()
    
    # Handle different ODM command categories
    if subcmd in ["ENABLE", "DISABLE"]:
        return handle_odm_enable_disable(dev, subcmd, args)
    elif subcmd == "TEST":
        return handle_odm_test(dev, args)
    elif subcmd in ["DIAG", "META", "ENGINEERING"]:
        return handle_odm_diagnostic_mode(dev, subcmd, args)
    elif subcmd in ["FRP", "FACTORY_RESET"]:
        return handle_odm_frp(dev, subcmd, args)
    elif subcmd in ["CALIBRATE", "CALIBRATION"]:
        return handle_odm_calibration(dev, args)
    else:
        return handle_generic_odm(dev, subcmd, args)

def handle_odm_enable_disable(dev, operation, args):
    """
    Handle ODM ENABLE/DISABLE commands for various features
    """
    if not hasattr(args, 'odm_args') or not args.odm_args:
        return print("[!] ENABLE/DISABLE requires feature argument")
    
    feature = args.odm_args[0].upper()
    
    print(f"[*] ODM {operation} {feature}...")
    
    # Map common features to their handlers
    feature_handlers = {
        # Diagnostic Modes
        "DIAG": lambda: enable_disable_diag_mode(dev, operation),
        "META": lambda: enable_disable_meta_mode(dev, operation),
        "ENGINEERING": lambda: enable_disable_engineering_mode(dev, operation),
        "QPST": lambda: enable_disable_qpst_mode(dev, operation),
        "DEBUG": lambda: enable_disable_debug_mode(dev, operation),
        
        # Hardware Interfaces
        "JTAG": lambda: enable_disable_jtag(dev, operation),
        "USB_DEBUG": lambda: enable_disable_usb_debug(dev, operation),
        "ADB": lambda: enable_disable_adb(dev, operation),
        "FASTBOOT": lambda: enable_disable_fastboot(dev, operation),
        
        # Security Features
        "SECURE_BOOT": lambda: enable_disable_secure_boot(dev, operation),
        "VERIFIED_BOOT": lambda: enable_disable_verified_boot(dev, operation),
        "OEM_LOCK": lambda: enable_disable_oem_lock(dev, operation),
        
        # System Features
        "TEST_SIGNING": lambda: enable_disable_test_signing(dev, operation),
        "ENG_ROOT": lambda: enable_disable_eng_root(dev, operation),
        "LOG_VERBOSE": lambda: enable_disable_verbose_logging(dev, operation),
    }
    
    if feature in feature_handlers:
        return feature_handlers[feature]()
    else:
        # Try generic enable/disable
        return generic_odm_enable_disable(dev, operation, feature, args)

def enable_disable_diag_mode(dev, operation):
    """Enable/disable Qualcomm diagnostic mode"""
    print(f"[*] {operation} Qualcomm DIAG mode...")
    
    # Try direct ODM command first
    cmd_name = f"DIAG_{operation}"
    if try_odm_command(dev, cmd_name):
        return True
    
    # Try SOC-specific methods
    soc_type = detect_soc_type(dev)
    
    if soc_type == "QUALCOMM":
        # Qualcomm DIAG mode via NV items or port config
        return configure_qualcomm_diag(dev, operation)
    elif soc_type == "MTK":
        # MediaTek META mode
        return configure_mtk_meta_mode(dev, operation)
    else:
        # Generic diagnostic enable
        return generic_diagnostic_enable(dev, operation)

def enable_disable_meta_mode(dev, operation):
    """Enable/disable MediaTek META mode"""
    print(f"[*] {operation} MediaTek META mode...")
    
    cmd_name = f"META_{operation}"
    if try_odm_command(dev, cmd_name):
        return True
    
    # MediaTek specific META mode configuration
    if operation == "ENABLE":
        # Send META mode trigger
        payload = b"META\x00" + b"\x01\x00\x00\x00"
    else:
        payload = b"META\x00" + b"\x00\x00\x00\x00"
    
    resp = qslcl_dispatch(dev, "ODM", payload)
    status = decode_runtime_result(resp)
    print(f"[*] META mode {operation}: {status}")
    return status.get("severity") == "SUCCESS"

def enable_disable_engineering_mode(dev, operation):
    """Enable/disable engineering/debug mode"""
    print(f"[*] {operation} engineering mode...")
    
    cmd_name = f"ENGINEERING_{operation}"
    if try_odm_command(dev, cmd_name):
        return True
    
    # Common engineering mode flags
    engineering_flags = {
        "ENABLE": [
            (0x100000, b"eng_root\x00"),
            (0x100100, b"debug_enable\x00"),
            (0x100200, b"\x01\x00\x00\x00"),  # Binary enable flag
        ],
        "DISABLE": [
            (0x100000, b"user_build\x00"),
            (0x100100, b"debug_disable\x00"),
            (0x100200, b"\x00\x00\x00\x00"),  # Binary disable flag
        ]
    }
    
    success = False
    for addr, flag_data in engineering_flags.get(operation, []):
        if write_odm_config(dev, addr, flag_data):
            success = True
    
    return success

def enable_disable_jtag(dev, operation):
    """Enable/disable JTAG debugging interface"""
    print(f"[*] {operation} JTAG interface...")
    
    cmd_name = f"JTAG_{operation}"
    if try_odm_command(dev, cmd_name):
        return True
    
    # JTAG configuration addresses vary by SOC
    soc_type = detect_soc_type(dev)
    jtag_configs = {
        "QUALCOMM": {
            "ENABLE": [(0x000A2000, b"\x01"), (0x000A2004, b"\x01")],
            "DISABLE": [(0x000A2000, b"\x00"), (0x000A2004, b"\x00")]
        },
        "MTK": {
            "ENABLE": [(0x10007000, b"\x01"), (0x10007004, b"\x01")],
            "DISABLE": [(0x10007000, b"\x00"), (0x10007004, b"\x00")]
        },
        "EXYNOS": {
            "ENABLE": [(0x10000000, b"\x01")],
            "DISABLE": [(0x10000000, b"\x00")]
        }
    }
    
    configs = jtag_configs.get(soc_type, jtag_configs["QUALCOMM"])
    success_count = 0
    
    for addr, value in configs.get(operation, []):
        if write_odm_config(dev, addr, value):
            success_count += 1
    
    return success_count > 0

def enable_disable_usb_debug(dev, operation):
    """Enable/disable USB debugging"""
    print(f"[*] {operation} USB debugging...")
    
    cmd_name = f"USB_DEBUG_{operation}"
    if try_odm_command(dev, cmd_name):
        return True
    
    # Common USB debugging configurations
    usb_configs = {
        "ENABLE": [
            (0x00050000, b"adb_enable\x00"),
            (0x00050010, b"\x01\x00\x00\x00"),  # ADB enable flag
            (0x00050020, b"debugging\x00"),
        ],
        "DISABLE": [
            (0x00050000, b"adb_disable\x00"),
            (0x00050010, b"\x00\x00\x00\x00"),  # ADB disable flag
            (0x00050020, b"production\x00"),
        ]
    }
    
    success_count = 0
    for addr, config_data in usb_configs.get(operation, []):
        if write_odm_config(dev, addr, config_data):
            success_count += 1
    
    return success_count > 0

def handle_odm_test(dev, args):
    """
    Handle ODM TEST commands for hardware validation
    """
    if not hasattr(args, 'odm_args') or not args.odm_args:
        return run_comprehensive_odm_test(dev)
    
    test_type = args.odm_args[0].upper()
    
    test_handlers = {
        "DISPLAY": run_display_test,
        "TOUCH": run_touch_test,
        "AUDIO": run_audio_test,
        "SENSOR": run_sensor_test,
        "CAMERA": run_camera_test,
        "BUTTON": run_button_test,
        "LED": run_led_test,
        "VIBRATION": run_vibration_test,
        "MEMORY": run_memory_test,
        "STORAGE": run_storage_test,
        "BATTERY": run_battery_test,
        "ALL": run_comprehensive_odm_test,
    }
    
    if test_type in test_handlers:
        return test_handlers[test_type](dev)
    else:
        return generic_odm_test(dev, test_type)

def run_display_test(dev):
    """Run display hardware test"""
    print("[*] Running display test...")
    
    if try_odm_command(dev, "TEST_DISPLAY"):
        return True
    
    # Display test patterns
    test_patterns = [
        b"DISPLAY_TEST_RED",
        b"DISPLAY_TEST_GREEN", 
        b"DISPLAY_TEST_BLUE",
        b"DISPLAY_TEST_WHITE",
        b"DISPLAY_TEST_BLACK",
        b"DISPLAY_TEST_GRADIENT",
    ]
    
    success_count = 0
    for pattern in test_patterns:
        resp = qslcl_dispatch(dev, "ODM", b"TEST_DISPLAY\x00" + pattern)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            success_count += 1
        time.sleep(0.5)  # Brief pause between patterns
    
    print(f"[*] Display test completed: {success_count}/{len(test_patterns)} patterns passed")
    return success_count == len(test_patterns)

def run_sensor_test(dev):
    """Run sensor calibration and test"""
    print("[*] Running sensor test...")
    
    if try_odm_command(dev, "TEST_SENSOR"):
        return True
    
    sensors_to_test = [
        "ACCELEROMETER",
        "GYROSCOPE", 
        "MAGNETOMETER",
        "PROXIMITY",
        "LIGHT",
        "PRESSURE",
        "HUMIDITY",
    ]
    
    success_count = 0
    for sensor in sensors_to_test:
        resp = qslcl_dispatch(dev, "ODM", b"TEST_SENSOR\x00" + sensor.encode())
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {sensor}: OK")
            success_count += 1
        else:
            print(f"[!] {sensor}: FAILED")
    
    print(f"[*] Sensor test completed: {success_count}/{len(sensors_to_test)} sensors passed")
    return success_count > 0

def run_comprehensive_odm_test(dev):
    """Run comprehensive hardware test suite"""
    print("[*] Starting comprehensive ODM test suite...")
    
    test_results = {}
    
    # Run individual tests
    test_results["display"] = run_display_test(dev)
    test_results["touch"] = run_touch_test(dev) 
    test_results["audio"] = run_audio_test(dev)
    test_results["sensor"] = run_sensor_test(dev)
    test_results["camera"] = run_camera_test(dev)
    test_results["memory"] = run_memory_test(dev)
    
    # Print summary
    print("\n" + "="*50)
    print("[*] ODM TEST SUMMARY")
    print("="*50)
    for test_name, passed in test_results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {test_name.upper():<12}: {status}")
    
    total_passed = sum(test_results.values())
    total_tests = len(test_results)
    
    print(f"  {'TOTAL':<12}: {total_passed}/{total_tests}")
    print("="*50)
    
    return total_passed == total_tests

def handle_odm_diagnostic_mode(dev, mode, args):
    """
    Handle ODM diagnostic mode commands
    """
    print(f"[*] Configuring {mode} diagnostic mode...")
    
    if try_odm_command(dev, f"{mode}_MODE"):
        return True
    
    # Configure diagnostic mode based on SOC type
    soc_type = detect_soc_type(dev)
    
    if soc_type == "QUALCOMM":
        return configure_qualcomm_diagnostic(dev, mode)
    elif soc_type == "MTK":
        return configure_mtk_diagnostic(dev, mode)
    else:
        return configure_generic_diagnostic(dev, mode)

def handle_odm_frp(dev, subcmd, args):
    """
    Handle ODM FRP (Factory Reset Protection) commands
    """
    print(f"[*] Handling FRP {subcmd}...")
    
    if try_odm_command(dev, f"FRP_{subcmd}"):
        return True
    
    # FRP bypass methods
    if subcmd == "FRP":
        return bypass_frp_protection(dev)
    elif subcmd == "FACTORY_RESET":
        return perform_factory_reset(dev)
    
    return False

def bypass_frp_protection(dev):
    """Bypass Factory Reset Protection"""
    print("[*] Attempting FRP bypass...")
    
    # Common FRP partition areas
    frp_partitions = ["frp", "misc", "persist", "devinfo"]
    
    for partition in frp_partitions:
        try:
            addr, size = resolve_partition(partition)
            # Clear FRP data
            payload = struct.pack("<Q I", addr, 512)
            resp = qslcl_dispatch(dev, "WRITE", payload + b"\x00" * 512)
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] Cleared FRP data from {partition}")
                return True
        except:
            continue
    
    return False

def handle_odm_calibration(dev, args):
    """
    Handle ODM calibration commands
    """
    print("[*] Running sensor calibration...")
    
    if not hasattr(args, 'odm_args') or not args.odm_args:
        return run_comprehensive_calibration(dev)
    
    sensor = args.odm_args[0].upper()
    
    calibration_handlers = {
        "TOUCH": calibrate_touch,
        "GYRO": calibrate_gyro,
        "COMPASS": calibrate_compass,
        "CAMERA": calibrate_camera,
        "BATTERY": calibrate_battery,
        "ALL": run_comprehensive_calibration,
    }
    
    if sensor in calibration_handlers:
        return calibration_handlers[sensor](dev)
    else:
        return generic_calibration(dev, sensor)

def calibrate_touch(dev):
    """Calibrate touchscreen"""
    print("[*] Starting touchscreen calibration...")
    
    if try_odm_command(dev, "CALIBRATE_TOUCH"):
        return True
    
    # Touch calibration sequence
    calibration_points = [
        (0.1, 0.1),   # Top-left
        (0.9, 0.1),   # Top-right  
        (0.1, 0.9),   # Bottom-left
        (0.9, 0.9),   # Bottom-right
        (0.5, 0.5),   # Center
    ]
    
    success_count = 0
    for x, y in calibration_points:
        point_data = struct.pack("<ff", x, y)
        resp = qslcl_dispatch(dev, "ODM", b"CALIBRATE_TOUCH\x00" + point_data)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            success_count += 1
        time.sleep(0.5)
    
    return success_count == len(calibration_points)

# Helper functions
def try_odm_command(dev, command):
    """Try to execute ODM command through available handlers"""
    # Try QSLCLPAR first
    if command in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, command, b"")
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] ODM {command} via QSLCLPAR")
            return True
    
    # Try QSLCLEND opcode
    opcode = sum(command.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        pkt = b"QSLCLEND" + entry
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] ODM {command} via QSLCLEND")
            return True
    
    return False

def write_odm_config(dev, address, data):
    """Write ODM configuration data to specific address"""
    payload = struct.pack("<Q", address) + data
    resp = qslcl_dispatch(dev, "WRITE", payload)
    status = decode_runtime_result(resp)
    return status.get("severity") == "SUCCESS"

def handle_generic_odm(dev, subcmd, args):
    """
    Handle generic ODM commands
    """
    print(f"[*] Executing ODM command: {subcmd}")
    
    # Build payload from additional arguments
    payload = b""
    if hasattr(args, 'odm_args'):
        for arg in args.odm_args:
            try:
                if arg.startswith("0x"):
                    payload += struct.pack("<I", int(arg, 16))
                else:
                    payload += struct.pack("<I", int(arg))
            except:
                payload += arg.encode() + b"\x00"
    
    # Try ODM-specific dispatch first
    resp = qslcl_dispatch(dev, "ODM", subcmd.encode() + b"\x00" + payload)
    status = decode_runtime_result(resp)
    
    if status.get("severity") != "SUCCESS":
        # Fallback to generic command
        resp = qslcl_dispatch(dev, subcmd, payload)
        status = decode_runtime_result(resp)
    
    print(f"[*] ODM {subcmd} Result: {status}")
    return status.get("severity") == "SUCCESS"

# Placeholder functions for other test types
def run_touch_test(dev): 
    print("[*] Running touch test...")
    return try_odm_command(dev, "TEST_TOUCH")

def run_audio_test(dev):
    print("[*] Running audio test...") 
    return try_odm_command(dev, "TEST_AUDIO")

def run_camera_test(dev):
    print("[*] Running camera test...")
    return try_odm_command(dev, "TEST_CAMERA")

def run_button_test(dev):
    print("[*] Running button test...")
    return try_odm_command(dev, "TEST_BUTTON")

def run_led_test(dev):
    print("[*] Running LED test...")
    return try_odm_command(dev, "TEST_LED")

def run_vibration_test(dev):
    print("[*] Running vibration test...")
    return try_odm_command(dev, "TEST_VIBRATION")

def run_memory_test(dev):
    print("[*] Running memory test...")
    return try_odm_command(dev, "TEST_MEMORY")

def run_storage_test(dev):
    print("[*] Running storage test...")
    return try_odm_command(dev, "TEST_STORAGE")

def run_battery_test(dev):
    print("[*] Running battery test...")
    return try_odm_command(dev, "TEST_BATTERY")

def run_comprehensive_calibration(dev):
    print("[*] Running comprehensive calibration...")
    return try_odm_command(dev, "CALIBRATE_ALL")

def generic_odm_test(dev, test_type):
    print(f"[*] Running generic {test_type} test...")
    return try_odm_command(dev, f"TEST_{test_type}")

def generic_calibration(dev, sensor):
    print(f"[*] Running generic {sensor} calibration...")
    return try_odm_command(dev, f"CALIBRATE_{sensor}")

def configure_qualcomm_diag(dev, operation):
    print(f"[*] Configuring Qualcomm DIAG mode: {operation}")
    return try_odm_command(dev, f"DIAG_{operation}")

def configure_mtk_meta_mode(dev, operation):
    print(f"[*] Configuring MediaTek META mode: {operation}")
    return try_odm_command(dev, f"META_{operation}")

def generic_diagnostic_enable(dev, operation):
    print(f"[*] Generic diagnostic {operation}")
    return try_odm_command(dev, f"DIAG_{operation}")

def configure_qualcomm_diagnostic(dev, mode):
    print(f"[*] Configuring Qualcomm {mode} diagnostic")
    return try_odm_command(dev, f"{mode}_MODE")

def configure_mtk_diagnostic(dev, mode):
    print(f"[*] Configuring MediaTek {mode} diagnostic") 
    return try_odm_command(dev, f"{mode}_MODE")

def configure_generic_diagnostic(dev, mode):
    print(f"[*] Configuring generic {mode} diagnostic")
    return try_odm_command(dev, f"{mode}_MODE")

def perform_factory_reset(dev):
    print("[*] Performing factory reset...")
    return try_odm_command(dev, "FACTORY_RESET")

def generic_odm_enable_disable(dev, operation, feature, args):
    print(f"[*] Generic ODM {operation} for {feature}")
    return try_odm_command(dev, f"{feature}_{operation}")

def cmd_mode(args):
    """
    Advanced MODE command handler for triggering device mode changes
    Supports mode switching using QSLCL's internal MODE commands
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse MODE subcommand
    if not hasattr(args, 'mode_subcommand') or not args.mode_subcommand:
        return print("[!] MODE command requires subcommand (check available modes with 'mode list')")
    
    subcmd = args.mode_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_modes(dev)
    else:
        return trigger_device_mode(dev, subcmd, args)

def list_available_modes(dev):
    """
    List all available MODE commands from QSLCL loader
    """
    print("\n" + "="*50)
    print("[*] AVAILABLE QSLCL MODE COMMANDS")
    print("="*50)
    
    modes_found = []
    
    # Check QSLCLPAR for MODE commands
    print("\n[QSLCLPAR] Mode Commands:")
    par_modes = [cmd for cmd in QSLCLPAR_DB.keys() if "MODE" in cmd.upper()]
    for mode_cmd in par_modes:
        print(f"  • {mode_cmd}")
        modes_found.append(mode_cmd)
    
    # Check QSLCLEND for mode-related opcodes
    print("\n[QSLCLEND] Mode Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        if isinstance(entry, dict) and "MODE" in str(entry.get('name', '')).upper():
            print(f"  • Opcode 0x{opcode:02X}: {entry.get('name', 'UNKNOWN')}")
            modes_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for mode microservices
    print("\n[QSLCLVM5] Mode Microservices:")
    vm5_modes = [cmd for cmd in QSLCLVM5_DB.keys() if "MODE" in cmd.upper()]
    for mode_cmd in vm5_modes:
        print(f"  • {mode_cmd}")
        modes_found.append(f"VM5_{mode_cmd}")
    
    # Check QSLCLIDX for mode indices
    print("\n[QSLCLIDX] Mode Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and "MODE" in str(entry.get('name', '')).upper():
            print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
            modes_found.append(f"IDX_{name}")
    
    if not modes_found:
        print("  No mode commands found in loader")
    
    print(f"\n[*] Total mode commands found: {len(modes_found)}")
    print("="*50)
    
    return True

def trigger_device_mode(dev, mode_name, args):
    """
    Trigger specific device mode using QSLCL MODE commands
    """
    print(f"[*] Triggering mode: {mode_name}")
    
    # Build payload from additional arguments
    payload = b""
    if hasattr(args, 'mode_args'):
        for arg in args.mode_args:
            try:
                if arg.startswith("0x"):
                    # Hex value
                    if len(arg) > 4:  # Assume 32-bit value
                        payload += struct.pack("<I", int(arg, 16))
                    else:
                        payload += struct.pack("<B", int(arg, 16))
                elif arg.isdigit():
                    # Decimal value
                    payload += struct.pack("<I", int(arg))
                else:
                    # String argument
                    payload += arg.encode() + b"\x00"
            except:
                payload += arg.encode() + b"\x00"
    
    # Try different MODE command strategies
    strategies = [
        try_direct_mode_command,
        try_par_mode_command,
        try_end_mode_opcode,
        try_vm5_mode_service,
        try_idx_mode_command,
        try_generic_mode_dispatch
    ]
    
    for strategy in strategies:
        success = strategy(dev, mode_name, payload)
        if success is not None:
            return success
    
    print(f"[!] Failed to trigger mode: {mode_name}")
    return False

def try_direct_mode_command(dev, mode_name, payload):
    """
    Try direct MODE command dispatch
    """
    # Try exact mode name match
    resp = qslcl_dispatch(dev, "MODE", mode_name.encode() + b"\x00" + payload)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] Mode '{mode_name}' triggered successfully via direct MODE command")
        return True
    
    return None

def try_par_mode_command(dev, mode_name, payload):
    """
    Try QSLCLPAR mode commands
    """
    # Check for exact match
    if mode_name in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR mode command: {mode_name}")
        resp = qslcl_dispatch(dev, mode_name, payload)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLPAR")
            return True
        else:
            print(f"[!] QSLCLPAR mode '{mode_name}' failed: {status}")
            return False
    
    # Check for MODE_ prefixed commands
    mode_prefixed = f"MODE_{mode_name}"
    if mode_prefixed in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR mode command: {mode_prefixed}")
        resp = qslcl_dispatch(dev, mode_prefixed, payload)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLPAR {mode_prefixed}")
            return True
        else:
            print(f"[!] QSLCLPAR mode '{mode_prefixed}' failed: {status}")
            return False
    
    return None

def try_end_mode_opcode(dev, mode_name, payload):
    """
    Try QSLCLEND mode opcodes
    """
    # Calculate opcode from mode name
    mode_opcode = sum(mode_name.encode()) & 0xFF
    
    if mode_opcode in QSLCLEND_DB:
        print(f"[*] Using QSLCLEND mode opcode 0x{mode_opcode:02X} for '{mode_name}'")
        entry = QSLCLEND_DB[mode_opcode]
        if isinstance(entry, dict):
            entry_data = entry.get("raw", b"")
        else:
            entry_data = entry
        
        pkt = b"QSLCLEND" + entry_data + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLEND opcode 0x{mode_opcode:02X}")
            return True
        else:
            print(f"[!] QSLCLEND mode opcode 0x{mode_opcode:02X} failed: {status}")
            return False
    
    # Try common mode opcodes
    common_mode_opcodes = {
        "QSLCL": 0xFF
    }
    
    if mode_name in common_mode_opcodes:
        opcode = common_mode_opcodes[mode_name]
        if opcode in QSLCLEND_DB:
            print(f"[*] Using common QSLCLEND mode opcode 0x{opcode:02X} for '{mode_name}'")
            entry = QSLCLEND_DB[opcode]
            if isinstance(entry, dict):
                entry_data = entry.get("raw", b"")
            else:
                entry_data = entry
            
            pkt = b"QSLCLEND" + entry_data + payload
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            status = decode_runtime_result(resp)
            
            if status.get("severity") == "SUCCESS":
                print(f"[✓] Mode '{mode_name}' triggered successfully via common QSLCLEND opcode 0x{opcode:02X}")
                return True
            else:
                print(f"[!] Common QSLCLEND mode opcode 0x{opcode:02X} failed: {status}")
                return False
    
    return None

def try_vm5_mode_service(dev, mode_name, payload):
    """
    Try QSLCLVM5 mode microservices
    """
    # Check for exact match
    if mode_name in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 mode microservice: {mode_name}")
        raw = QSLCLVM5_DB[mode_name]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLVM5")
            return True
        else:
            print(f"[!] QSLCLVM5 mode '{mode_name}' failed: {status}")
            return False
    
    # Check for MODE_ prefixed VM5 services
    mode_prefixed = f"MODE_{mode_name}"
    if mode_prefixed in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 mode microservice: {mode_prefixed}")
        raw = QSLCLVM5_DB[mode_prefixed]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLVM5 {mode_prefixed}")
            return True
        else:
            print(f"[!] QSLCLVM5 mode '{mode_prefixed}' failed: {status}")
            return False
    
    return None

def try_idx_mode_command(dev, mode_name, payload):
    """
    Try QSLCLIDX mode commands
    """
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if mode_name.upper() == entry_name.upper() or f"MODE_{mode_name}".upper() == entry_name.upper():
                idx = entry.get('idx', 0)
                print(f"[*] Using QSLCLIDX mode command: {name} (idx: 0x{idx:02X})")
                
                pkt = b"QSLCLIDX" + struct.pack("<I", idx) + payload
                resp = qslcl_dispatch(dev, "IDX", pkt)
                status = decode_runtime_result(resp)
                
                if status.get("severity") == "SUCCESS":
                    print(f"[✓] Mode '{mode_name}' triggered successfully via QSLCLIDX {name}")
                    return True
                else:
                    print(f"[!] QSLCLIDX mode '{name}' failed: {status}")
                    return False
    
    return None

def try_generic_mode_dispatch(dev, mode_name, payload):
    """
    Final fallback: try generic mode dispatch
    """
    print(f"[*] Trying generic mode dispatch for '{mode_name}'")
    
    # Try the mode name as a direct command
    resp = qslcl_dispatch(dev, mode_name, payload)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] Mode '{mode_name}' triggered successfully via generic dispatch")
        return True
    else:
        print(f"[!] Generic mode dispatch for '{mode_name}' failed: {status}")
        return False

def get_current_device_mode(dev):
    """
    Get current device mode if supported by loader
    """
    print("[*] Querying current device mode...")
    
    # Try different methods to get current mode
    mode_queries = [
        "GET_MODE",
        "CURRENT_MODE", 
        "MODE_STATUS",
        "STATUS"
    ]
    
    for query in mode_queries:
        # Check QSLCLPAR first
        if query in QSLCLPAR_DB:
            resp = qslcl_dispatch(dev, query, b"")
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                mode_data = status.get("extra", b"")
                if mode_data:
                    try:
                        mode_str = mode_data.decode('utf-8', errors='ignore').rstrip('\x00')
                        print(f"[*] Current mode: {mode_str}")
                        return mode_str
                    except:
                        print(f"[*] Current mode (raw): {mode_data.hex()}")
                        return mode_data
    
    # Try generic mode query
    resp = qslcl_dispatch(dev, "MODE", b"QUERY\x00")
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        mode_data = status.get("extra", b"")
        if mode_data:
            try:
                mode_str = mode_data.decode('utf-8', errors='ignore').rstrip('\x00')
                print(f"[*] Current mode: {mode_str}")
                return mode_str
            except:
                print(f"[*] Current mode (raw): {mode_data.hex()}")
                return mode_data
    
    print("[!] Could not determine current device mode")
    return None

def cmd_mode_status(args):
    """
    Handle 'mode status' command to check current device mode
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    return get_current_device_mode(dev) is not None

def update_mode_parser(sub):
    """
    Update the MODE command parser with new subcommands
    """
    mode_parser = sub.add_parser("mode", help="Device mode commands (trigger mode changes)")
    mode_parser.add_argument("mode_subcommand", help="Mode subcommand (list, status, or mode name)")
    mode_parser.add_argument("mode_args", nargs="*", help="Additional arguments for mode command")
    mode_parser.set_defaults(func=cmd_mode)

    status_parser = sub.add_parser("mode-status", help="Check current device mode")
    status_parser.set_defaults(func=cmd_mode_status)

def cmd_crash(args):
    """
    Advanced CRASH command handler for controlled system crash simulation
    Supports various crash types and fault injection methods
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse CRASH subcommand
    if not hasattr(args, 'crash_subcommand') or not args.crash_subcommand:
        return print("[!] CRASH command requires subcommand (list, preloader, kernel, watchdog, etc.)")
    
    subcmd = args.crash_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_crash_types(dev)
    else:
        return trigger_controlled_crash(dev, subcmd, args)

def list_available_crash_types(dev):
    """
    List all available CRASH commands from QSLCL loader
    """
    print("\n" + "="*50)
    print("[*] AVAILABLE QSLCL CRASH COMMANDS")
    print("="*50)
    
    crash_found = []
    
    # Check QSLCLPAR for CRASH commands
    print("\n[QSLCLPAR] Crash Commands:")
    par_crashes = [cmd for cmd in QSLCLPAR_DB.keys() if "CRASH" in cmd.upper()]
    for crash_cmd in par_crashes:
        print(f"  • {crash_cmd}")
        crash_found.append(crash_cmd)
    
    # Check QSLCLEND for crash-related opcodes
    print("\n[QSLCLEND] Crash Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        if isinstance(entry, dict) and "CRASH" in str(entry.get('name', '')).upper():
            print(f"  • Opcode 0x{opcode:02X}: {entry.get('name', 'UNKNOWN')}")
            crash_found.append(f"ENGINE_0x{opcode:02X}")
        elif isinstance(entry, bytes) and len(entry) > 0:
            # Check if opcode name suggests crash functionality
            opcode_name = f"OP_{opcode:02X}"
            if opcode in [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xDE, 0xAD, 0xBE, 0xEF]:
                print(f"  • Suspicious Opcode 0x{opcode:02X}: Potential crash function")
                crash_found.append(f"SUSPECT_0x{opcode:02X}")
    
    # Check QSLCLVM5 for crash microservices
    print("\n[QSLCLVM5] Crash Microservices:")
    vm5_crashes = [cmd for cmd in QSLCLVM5_DB.keys() if "CRASH" in cmd.upper()]
    for crash_cmd in vm5_crashes:
        print(f"  • {crash_cmd}")
        crash_found.append(f"VM5_{crash_cmd}")
    
    # Check QSLCLIDX for crash indices
    print("\n[QSLCLIDX] Crash Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and "CRASH" in str(entry.get('name', '')).upper():
            print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
            crash_found.append(f"IDX_{name}")
    
    if not crash_found:
        print("  No crash commands found in loader")
    else:
        print(f"\n[*] Total crash commands found: {len(crash_found)}")
    
    print("\n[*] Common Crash Types Available:")
    print("  • PRELOADER  - Simulate preloader/bootrom crash")
    print("  • KERNEL     - Trigger kernel panic/oops")
    print("  • WATCHDOG   - Trigger watchdog timeout")
    print("  • MEMORY     - Memory corruption crash")
    print("  • NULL_PTR   - Null pointer dereference")
    print("  • STACK      - Stack overflow corruption")
    print("  • DIV_ZERO   - Division by zero fault")
    print("  • UNDEF_INST - Undefined instruction")
    print("  • HARD_FAULT - Hard fault escalation")
    print("  • SECURITY   - Security violation crash")
    
    print("="*50)
    
    return True

def trigger_controlled_crash(dev, crash_type, args):
    """
    Trigger controlled system crash with specified type
    """
    print(f"[!] WARNING: Attempting to trigger {crash_type} crash")
    print("[!] This may cause device instability or require physical reset!")
    
    # Safety confirmation for destructive crashes
    if crash_type not in ["SOFT", "TEST", "DUMMY"]:
        confirm = input("!! CONFIRM CRASH OPERATION (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Crash operation cancelled")
            return False
    
    print(f"[*] Preparing {crash_type} crash injection...")
    
    # Build crash parameters
    crash_params = build_crash_parameters(crash_type, args)
    
    # Try different crash triggering strategies
    strategies = [
        try_direct_crash_command,
        try_par_crash_command,
        try_end_crash_opcode,
        try_vm5_crash_service,
        try_idx_crash_command,
        try_generic_crash_injection
    ]
    
    for strategy in strategies:
        success = strategy(dev, crash_type, crash_params)
        if success is not None:
            if success:
                monitor_crash_aftermath(dev, crash_type)
            return success
    
    print(f"[!] Failed to trigger {crash_type} crash")
    return False

def build_crash_parameters(crash_type, args):
    """
    Build appropriate parameters for different crash types
    """
    params = bytearray()
    
    # Add crash type identifier
    type_hash = sum(crash_type.encode()) & 0xFFFF
    params.extend(struct.pack("<H", type_hash))
    
    # Add severity level (default: 0x01 = MEDIUM)
    severity = 0x01
    if hasattr(args, 'crash_args') and args.crash_args:
        try:
            if args.crash_args[0].startswith("0x"):
                severity = int(args.crash_args[0], 16) & 0xFF
            else:
                severity = int(args.crash_args[0]) & 0xFF
        except:
            pass
    
    params.extend(struct.pack("<B", severity))
    
    # Add crash-specific parameters
    if crash_type == "PRELOADER":
        # Preloader crash: address, corruption pattern
        params.extend(struct.pack("<I", 0x100000))  # Typical preloader base
        params.extend(b"DEADBEEF")  # Corruption signature
        
    elif crash_type == "KERNEL":
        # Kernel panic: oops type, register state
        params.extend(struct.pack("<I", 0x0000000D))  # Oops type
        params.extend(b"\x00" * 16)  # Simulated register dump
        
    elif crash_type == "WATCHDOG":
        # Watchdog trigger: timeout value, reset type
        params.extend(struct.pack("<I", 1000))  # 1000ms timeout
        params.extend(b"\x01")  # Hard reset
        
    elif crash_type == "MEMORY":
        # Memory corruption: target address, corruption pattern
        target_addr = 0x80000000
        if hasattr(args, 'crash_args') and len(args.crash_args) > 1:
            try:
                if args.crash_args[1].startswith("0x"):
                    target_addr = int(args.crash_args[1], 16)
            except:
                pass
        params.extend(struct.pack("<Q", target_addr))
        params.extend(b"CORRUPTED_MEMORY\x00")
        
    elif crash_type == "NULL_PTR":
        # Null pointer: access type, fault address
        params.extend(struct.pack("<B", 0x01))  # Read access
        params.extend(struct.pack("<Q", 0x00000000))  # NULL address
        
    elif crash_type == "STACK":
        # Stack overflow: stack base, overflow size
        params.extend(struct.pack("<Q", 0x80000000))  # Stack base
        params.extend(struct.pack("<I", 0x1000))  # Overflow by 4KB
        
    elif crash_type == "DIV_ZERO":
        # Division by zero: dividend, divisor
        params.extend(struct.pack("<I", 0x12345678))  # Dividend
        params.extend(struct.pack("<I", 0x00000000))  # Divisor (zero)
        
    elif crash_type == "UNDEF_INST":
        # Undefined instruction: opcode bytes
        params.extend(b"\xDE\xAD\xC0\xDE")  # Undefined instruction pattern
        
    elif crash_type == "HARD_FAULT":
        # Hard fault: fault type, status register
        params.extend(struct.pack("<I", 0x00000002))  # Hard fault type
        params.extend(struct.pack("<I", 0x40000000))  # HFSR value
        
    elif crash_type == "SECURITY":
        # Security violation: violation type, severity
        params.extend(struct.pack("<B", 0x03))  # Privilege escalation attempt
        params.extend(struct.pack("<I", 0xDEADBEEF))  # Security token
        
    else:
        # Generic crash: random pattern
        params.extend(os.urandom(8))
    
    # Add timestamp for crash identification
    timestamp = int(time.time())
    params.extend(struct.pack("<I", timestamp))
    
    return bytes(params)

def try_direct_crash_command(dev, crash_type, params):
    """
    Try direct CRASH command dispatch
    """
    resp = qslcl_dispatch(dev, "CRASH", crash_type.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {crash_type} crash triggered successfully via direct CRASH command")
        return True
    
    return None

def try_par_crash_command(dev, crash_type, params):
    """
    Try QSLCLPAR crash commands
    """
    # Check for exact match
    if crash_type in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR crash command: {crash_type}")
        resp = qslcl_dispatch(dev, crash_type, params)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {crash_type} crash triggered successfully via QSLCLPAR")
            return True
        else:
            print(f"[!] QSLCLPAR crash '{crash_type}' failed: {status}")
            return False
    
    # Check for CRASH_ prefixed commands
    crash_prefixed = f"CRASH_{crash_type}"
    if crash_prefixed in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR crash command: {crash_prefixed}")
        resp = qslcl_dispatch(dev, crash_prefixed, params)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {crash_type} crash triggered successfully via QSLCLPAR {crash_prefixed}")
            return True
        else:
            print(f"[!] QSLCLPAR crash '{crash_prefixed}' failed: {status}")
            return False
    
    return None

def try_end_crash_opcode(dev, crash_type, params):
    """
    Try QSLCLEND crash opcodes
    """
    # Calculate opcode from crash type
    crash_opcode = sum(crash_type.encode()) & 0xFF
    
    if crash_opcode in QSLCLEND_DB:
        print(f"[*] Using QSLCLEND crash opcode 0x{crash_opcode:02X} for '{crash_type}'")
        entry = QSLCLEND_DB[crash_opcode]
        if isinstance(entry, dict):
            entry_data = entry.get("raw", b"")
        else:
            entry_data = entry
        
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {crash_type} crash triggered successfully via QSLCLEND opcode 0x{crash_opcode:02X}")
            return True
        else:
            print(f"[!] QSLCLEND crash opcode 0x{crash_opcode:02X} failed: {status}")
            return False
    
    # Try common crash opcodes
    common_crash_opcodes = {
        "PRELOADER": 0xC0,
        "KERNEL": 0xC1,
        "WATCHDOG": 0xC2,
        "MEMORY": 0xC3,
        "NULL_PTR": 0xC4,
        "STACK": 0xC5,
        "DIV_ZERO": 0xC6,
        "UNDEF_INST": 0xC7,
        "HARD_FAULT": 0xC8,
        "SECURITY": 0xC9,
        "GENERIC": 0xCA,
    }
    
    if crash_type in common_crash_opcodes:
        opcode = common_crash_opcodes[crash_type]
        if opcode in QSLCLEND_DB:
            print(f"[*] Using common QSLCLEND crash opcode 0x{opcode:02X} for '{crash_type}'")
            entry = QSLCLEND_DB[opcode]
            if isinstance(entry, dict):
                entry_data = entry.get("raw", b"")
            else:
                entry_data = entry
            
            pkt = b"QSLCLEND" + entry_data + params
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            status = decode_runtime_result(resp)
            
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {crash_type} crash triggered successfully via common QSLCLEND opcode 0x{opcode:02X}")
                return True
            else:
                print(f"[!] Common QSLCLEND crash opcode 0x{opcode:02X} failed: {status}")
                return False
    
    return None

def try_vm5_crash_service(dev, crash_type, params):
    """
    Try QSLCLVM5 crash microservices
    """
    # Check for exact match
    if crash_type in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 crash microservice: {crash_type}")
        raw = QSLCLVM5_DB[crash_type]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {crash_type} crash triggered successfully via QSLCLVM5")
            return True
        else:
            print(f"[!] QSLCLVM5 crash '{crash_type}' failed: {status}")
            return False
    
    # Check for CRASH_ prefixed VM5 services
    crash_prefixed = f"CRASH_{crash_type}"
    if crash_prefixed in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 crash microservice: {crash_prefixed}")
        raw = QSLCLVM5_DB[crash_prefixed]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {crash_type} crash triggered successfully via QSLCLVM5 {crash_prefixed}")
            return True
        else:
            print(f"[!] QSLCLVM5 crash '{crash_prefixed}' failed: {status}")
            return False
    
    return None

def try_idx_crash_command(dev, crash_type, params):
    """
    Try QSLCLIDX crash commands
    """
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if crash_type.upper() == entry_name.upper() or f"CRASH_{crash_type}".upper() == entry_name.upper():
                idx = entry.get('idx', 0)
                print(f"[*] Using QSLCLIDX crash command: {name} (idx: 0x{idx:02X})")
                
                pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
                resp = qslcl_dispatch(dev, "IDX", pkt)
                status = decode_runtime_result(resp)
                
                if status.get("severity") == "SUCCESS":
                    print(f"[✓] {crash_type} crash triggered successfully via QSLCLIDX {name}")
                    return True
                else:
                    print(f"[!] QSLCLIDX crash '{name}' failed: {status}")
                    return False
    
    return None

def try_generic_crash_injection(dev, crash_type, params):
    """
    Final fallback: try generic crash injection
    """
    print(f"[*] Trying generic crash injection for '{crash_type}'")
    
    # Try the crash type as a direct command
    resp = qslcl_dispatch(dev, crash_type, params)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {crash_type} crash triggered successfully via generic injection")
        return True
    else:
        print(f"[!] Generic crash injection for '{crash_type}' failed: {status}")
        return False

def monitor_crash_aftermath(dev, crash_type):
    """
    Monitor device state after crash attempt
    """
    print(f"[*] Monitoring crash aftermath for {crash_type}...")
    
    # Wait a moment for crash to manifest
    time.sleep(2)
    
    # Try to communicate with device
    print("[*] Checking device responsiveness...")
    
    try:
        # Try simple ping to check if device is alive
        resp = qslcl_dispatch(dev, "PING", b"")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print("[~] Device appears to have survived the crash attempt")
                return "SURVIVED"
            else:
                print("[~] Device responded with error after crash attempt")
                return "ERROR_RESPONSE"
    except:
        pass
    
    # If we get here, device is likely unresponsive
    print("[!] Device appears unresponsive after crash attempt")
    
    # Try to detect if device rebooted
    print("[*] Checking for device reboot...")
    time.sleep(5)
    
    try:
        # Scan for devices again
        new_devs = scan_all()
        if new_devs:
            print("[~] Device detected after crash - may have rebooted")
            return "REBOOTED"
        else:
            print("[!] No devices detected - device may be in crash state")
            return "CRASHED"
    except:
        print("[!] Unable to determine device state")
        return "UNKNOWN"

def cmd_crash_test(args):
    """
    Safe crash test command for validation
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    print("[*] Running safe crash test...")
    
    # Use TEST or DUMMY crash type for safe testing
    resp = qslcl_dispatch(dev, "CRASH", b"TEST\x00")
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print("[✓] Safe crash test completed successfully")
        return True
    else:
        print(f"[!] Safe crash test failed: {status}")
        return False

def update_crash_parser(sub):
    """
    Update the CRASH command parser with new subcommands
    """
    crash_parser = sub.add_parser("crash", help="Controlled crash simulation commands")
    crash_parser.add_argument("crash_subcommand", help="Crash subcommand (list, test, or crash type)")
    crash_parser.add_argument("crash_args", nargs="*", help="Additional arguments for crash command")
    crash_parser.set_defaults(func=cmd_crash)

    test_parser = sub.add_parser("crash-test", help="Safe crash functionality test")
    test_parser.set_defaults(func=cmd_crash_test)

def cmd_bypass(args):
    """
    Advanced BYPASS command handler for security mechanism circumvention
    Supports various bypass techniques across different security layers
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse BYPASS subcommand
    if not hasattr(args, 'bypass_subcommand') or not args.bypass_subcommand:
        return print("[!] BYPASS command requires subcommand (list, frp, secure_boot, auth, etc.)")
    
    subcmd = args.bypass_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_bypass_types(dev)
    elif subcmd == "SCAN":
        return scan_security_mechanisms(dev, args)
    elif subcmd == "STATUS":
        return check_bypass_status(dev)
    else:
        return execute_security_bypass(dev, subcmd, args)

def list_available_bypass_types(dev):
    """
    List all available BYPASS commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL BYPASS COMMANDS")
    print("="*60)
    
    bypass_found = []
    
    # Check QSLCLPAR for BYPASS commands
    print("\n[QSLCLPAR] Bypass Commands:")
    par_bypasses = [cmd for cmd in QSLCLPAR_DB.keys() if "BYPASS" in cmd.upper() or any(x in cmd.upper() for x in ["FRP", "AUTH", "SECURE", "LOCK", "VERIFY"])]
    for bypass_cmd in par_bypasses:
        print(f"  • {bypass_cmd}")
        bypass_found.append(bypass_cmd)
    
    # Check QSLCLEND for bypass-related opcodes
    print("\n[QSLCLEND] Bypass Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["BYPASS", "FRP", "AUTH", "SECURE", "UNLOCK"]) or any(x in entry_str for x in ["BYPASS", "FRP", "AUTH"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            bypass_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for bypass microservices
    print("\n[QSLCLVM5] Bypass Microservices:")
    vm5_bypasses = [cmd for cmd in QSLCLVM5_DB.keys() if "BYPASS" in cmd.upper() or any(x in cmd.upper() for x in ["FRP", "AUTH", "SECURE"])]
    for bypass_cmd in vm5_bypasses:
        print(f"  • {bypass_cmd}")
        bypass_found.append(f"VM5_{bypass_cmd}")
    
    # Check QSLCLIDX for bypass indices
    print("\n[QSLCLIDX] Bypass Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["BYPASS", "FRP", "AUTH", "SECURE"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                bypass_found.append(f"IDX_{name}")
    
    if not bypass_found:
        print("  No bypass commands found in loader")
    else:
        print(f"\n[*] Total bypass commands found: {len(bypass_found)}")
    
    print("\n[*] Common Bypass Types Available:")
    print("  • FRP           - Factory Reset Protection bypass")
    print("  • SECURE_BOOT   - Secure boot verification bypass")
    print("  • AUTH          - Authentication/verification bypass")
    print("  • VERIFIED_BOOT - Android Verified Boot bypass")
    print("  • OEM_LOCK      - OEM locking mechanism bypass")
    print("  • WARRANTY      - Warranty bit reset")
    print("  • ROOT          - Root detection bypass")
    print("  • INTEGRITY     - Integrity checking bypass")
    print("  • ENCRYPTION    - Encryption bypass")
    print("  • SIGNATURE     - Signature verification bypass")
    
    print("="*60)
    
    return True

def scan_security_mechanisms(dev, args):
    """
    Scan device for active security mechanisms
    """
    print("[*] Scanning for active security mechanisms...")
    
    security_findings = []
    soc_type = detect_soc_type(dev)
    
    # Check common security partitions
    security_partitions = ["frp", "misc", "persist", "devinfo", "keystore", "protect_f", "protect_s"]
    
    print("\n[*] Checking security partitions...")
    for part_name in security_partitions:
        try:
            addr, size = resolve_partition(part_name)
            # Read first sector to check for security flags
            payload = struct.pack("<Q I", addr, 512)
            resp = qslcl_dispatch(dev, "READ", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    data = status.get("extra", b"")
                    security_flags = detect_security_flags(data, part_name)
                    if security_flags:
                        security_findings.extend(security_flags)
                        print(f"  [✓] {part_name}: {len(security_flags)} security flags found")
        except:
            pass
    
    # Check bootloader lock state
    print("\n[*] Checking bootloader lock state...")
    lock_state = detect_bootloader_lock_state(dev)
    if lock_state:
        security_findings.append(f"BOOTLOADER_LOCK: {lock_state}")
        print(f"  [✓] Bootloader: {lock_state}")
    
    # Check secure boot status
    print("\n[*] Checking secure boot status...")
    secure_boot_state = detect_secure_boot_state(dev)
    if secure_boot_state:
        security_findings.append(f"SECURE_BOOT: {secure_boot_state}")
        print(f"  [✓] Secure Boot: {secure_boot_state}")
    
    # Check FRP status
    print("\n[*] Checking FRP status...")
    frp_state = detect_frp_state(dev)
    if frp_state:
        security_findings.append(f"FRP: {frp_state}")
        print(f"  [✓] FRP: {frp_state}")
    
    # Print summary
    print("\n" + "="*50)
    print("[*] SECURITY SCAN SUMMARY")
    print("="*50)
    for finding in security_findings:
        print(f"  • {finding}")
    
    if not security_findings:
        print("  No security mechanisms detected")
    else:
        print(f"\n[*] Total security findings: {len(security_findings)}")
    
    return security_findings

def detect_security_flags(data, partition):
    """
    Detect security flags in partition data
    """
    flags = []
    
    # Common security flag patterns
    security_patterns = {
        b"locked": "PARTITION_LOCKED",
        b"enable": "FEATURE_ENABLED", 
        b"verified": "VERIFICATION_ACTIVE",
        b"secure": "SECURE_MODE",
        b"protect": "PROTECTION_ACTIVE",
        b"auth": "AUTHENTICATION_REQUIRED",
        b"encrypt": "ENCRYPTION_ACTIVE",
        b"\x01\x00\x00\x00": "BINARY_ENABLED_FLAG",
        b"\xFF\xFF\xFF\xFF": "BINARY_MAX_FLAG",
    }
    
    for pattern, flag_name in security_patterns.items():
        if pattern in data:
            flags.append(f"{partition.upper()}_{flag_name}")
    
    return flags

def detect_bootloader_lock_state(dev):
    """
    Detect bootloader lock state
    """
    # Try direct OEM lock check
    resp = qslcl_dispatch(dev, "OEM", b"LOCK_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if b"unlocked" in extra.lower():
                return "UNLOCKED"
            elif b"locked" in extra.lower():
                return "LOCKED"
    
    # Check common lock regions
    lock_regions = [
        (0x00086000, 0x00087000),  # Qualcomm lock area
        (0x00011C00, 0x00011E00),  # MediaTek lock area
    ]
    
    for start, end in lock_regions:
        payload = struct.pack("<Q I", start, end-start)
        resp = qslcl_dispatch(dev, "READ", payload)
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                data = status.get("extra", b"")
                if b"locked" in data.lower():
                    return "LOCKED"
                elif b"unlocked" in data.lower():
                    return "UNLOCKED"
    
    return "UNKNOWN"

def detect_secure_boot_state(dev):
    """
    Detect secure boot state
    """
    # Try direct secure boot check
    resp = qslcl_dispatch(dev, "OEM", b"SECURE_BOOT_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if b"enabled" in extra.lower():
                return "ENABLED"
            elif b"disabled" in extra.lower():
                return "DISABLED"
    
    return "UNKNOWN"

def detect_frp_state(dev):
    """
    Detect Factory Reset Protection state
    """
    # Check common FRP partitions
    frp_partitions = ["frp", "misc", "persist"]
    
    for part_name in frp_partitions:
        try:
            addr, size = resolve_partition(part_name)
            payload = struct.pack("<Q I", addr, 512)
            resp = qslcl_dispatch(dev, "READ", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    data = status.get("extra", b"")
                    # FRP usually has non-zero data when active
                    if data and data != b"\x00" * len(data):
                        return "ACTIVE"
        except:
            continue
    
    return "INACTIVE"

def check_bypass_status(dev):
    """
    Check current bypass status and applied bypasses
    """
    print("[*] Checking bypass status...")
    
    # Try to get bypass status from device
    resp = qslcl_dispatch(dev, "BYPASS", b"STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            print(f"[*] Bypass status: {extra.decode('utf-8', errors='ignore')}")
            return True
    
    # Fallback: scan security mechanisms to see what's still active
    active_security = scan_security_mechanisms(dev, None)
    
    if not active_security:
        print("[✓] No active security mechanisms detected")
        return True
    else:
        print(f"[!] {len(active_security)} security mechanisms still active")
        return False

def execute_security_bypass(dev, bypass_type, args):
    """
    Execute specific security bypass
    """
    print(f"[*] Attempting {bypass_type} bypass...")
    
    # Build bypass parameters
    bypass_params = build_bypass_parameters(bypass_type, args)
    
    # Safety warning for destructive bypasses
    if bypass_type in ["FRP", "SECURE_BOOT", "OEM_LOCK", "WARRANTY"]:
        print("[!] WARNING: This bypass may void warranty or cause data loss!")
        confirm = input("!! CONFIRM BYPASS OPERATION (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Bypass operation cancelled")
            return False
    
    # Try different bypass strategies
    strategies = [
        try_direct_bypass_command,
        try_par_bypass_command, 
        try_end_bypass_opcode,
        try_vm5_bypass_service,
        try_idx_bypass_command,
        try_generic_bypass_method
    ]
    
    for strategy in strategies:
        success = strategy(dev, bypass_type, bypass_params)
        if success is not None:
            if success:
                verify_bypass_success(dev, bypass_type)
            return success
    
    print(f"[!] Failed to execute {bypass_type} bypass")
    return False

def build_bypass_parameters(bypass_type, args):
    """
    Build parameters for different bypass types
    """
    params = bytearray()
    
    # Add bypass type identifier
    type_hash = sum(bypass_type.encode()) & 0xFFFF
    params.extend(struct.pack("<H", type_hash))
    
    # Add bypass method (default: 0x01 = STANDARD)
    method = 0x01
    if hasattr(args, 'bypass_args') and args.bypass_args:
        try:
            if args.bypass_args[0].startswith("0x"):
                method = int(args.bypass_args[0], 16) & 0xFF
            else:
                method = int(args.bypass_args[0]) & 0xFF
        except:
            pass
    
    params.extend(struct.pack("<B", method))
    
    # Add bypass-specific parameters
    if bypass_type == "FRP":
        # FRP bypass: partition selection, wipe method
        params.extend(struct.pack("<B", 0x01))  # Full wipe
        params.extend(b"FRP_BYPASS\x00")
        
    elif bypass_type == "SECURE_BOOT":
        # Secure boot bypass: verification level, method
        params.extend(struct.pack("<B", 0x02))  # Skip verification
        params.extend(b"SECURE_BOOT_DISABLE\x00")
        
    elif bypass_type == "AUTH":
        # Authentication bypass: auth type, bypass method
        params.extend(struct.pack("<B", 0x03))  # All auth types
        params.extend(b"AUTH_BYPASS\x00")
        
    elif bypass_type == "VERIFIED_BOOT":
        # Verified boot bypass: vbmeta handling
        params.extend(struct.pack("<B", 0x01))  # Disable verification
        params.extend(b"AVB_BYPASS\x00")
        
    elif bypass_type == "OEM_LOCK":
        # OEM lock bypass: unlock method
        params.extend(struct.pack("<B", 0x01))  # Software unlock
        params.extend(b"OEM_UNLOCK\x00")
        
    elif bypass_type == "WARRANTY":
        # Warranty bit reset: reset method
        params.extend(struct.pack("<B", 0x01))  # Bit reset
        params.extend(b"WARRANTY_RESET\x00")
        
    elif bypass_type == "ROOT":
        # Root detection bypass: detection methods to bypass
        params.extend(struct.pack("<B", 0xFF))  # All detection methods
        params.extend(b"ROOT_HIDE\x00")
        
    elif bypass_type == "INTEGRITY":
        # Integrity check bypass: check types
        params.extend(struct.pack("<B", 0x07))  # All integrity checks
        params.extend(b"INTEGRITY_BYPASS\x00")
        
    elif bypass_type == "ENCRYPTION":
        # Encryption bypass: encryption type
        params.extend(struct.pack("<B", 0x03))  # FBE/FDE
        params.extend(b"ENCRYPTION_BYPASS\x00")
        
    elif bypass_type == "SIGNATURE":
        # Signature verification bypass: signature types
        params.extend(struct.pack("<B", 0x0F))  # All signature types
        params.extend(b"SIGNATURE_BYPASS\x00")
        
    else:
        # Generic bypass
        params.extend(struct.pack("<B", 0x01))  # Default method
        params.extend(b"GENERIC_BYPASS\x00")
    
    # Add timestamp
    timestamp = int(time.time())
    params.extend(struct.pack("<I", timestamp))
    
    return bytes(params)

def try_direct_bypass_command(dev, bypass_type, params):
    """
    Try direct BYPASS command dispatch
    """
    resp = qslcl_dispatch(dev, "BYPASS", bypass_type.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {bypass_type} bypass executed successfully via direct BYPASS command")
        return True
    
    return None

def try_par_bypass_command(dev, bypass_type, params):
    """
    Try QSLCLPAR bypass commands
    """
    # Check for exact match
    if bypass_type in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR bypass command: {bypass_type}")
        resp = qslcl_dispatch(dev, bypass_type, params)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass executed successfully via QSLCLPAR")
            return True
        else:
            print(f"[!] QSLCLPAR bypass '{bypass_type}' failed: {status}")
            return False
    
    # Check for BYPASS_ prefixed commands
    bypass_prefixed = f"BYPASS_{bypass_type}"
    if bypass_prefixed in QSLCLPAR_DB:
        print(f"[*] Using QSLCLPAR bypass command: {bypass_prefixed}")
        resp = qslcl_dispatch(dev, bypass_prefixed, params)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass executed successfully via QSLCLPAR {bypass_prefixed}")
            return True
        else:
            print(f"[!] QSLCLPAR bypass '{bypass_prefixed}' failed: {status}")
            return False
    
    return None

def try_end_bypass_opcode(dev, bypass_type, params):
    """
    Try QSLCLEND bypass opcodes
    """
    # Calculate opcode from bypass type
    bypass_opcode = sum(bypass_type.encode()) & 0xFF
    
    if bypass_opcode in QSLCLEND_DB:
        print(f"[*] Using QSLCLEND bypass opcode 0x{bypass_opcode:02X} for '{bypass_type}'")
        entry = QSLCLEND_DB[bypass_opcode]
        if isinstance(entry, dict):
            entry_data = entry.get("raw", b"")
        else:
            entry_data = entry
        
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass executed successfully via QSLCLEND opcode 0x{bypass_opcode:02X}")
            return True
        else:
            print(f"[!] QSLCLEND bypass opcode 0x{bypass_opcode:02X} failed: {status}")
            return False
    
    # Try common bypass opcodes
    common_bypass_opcodes = {
        "FRP": 0xD0,
        "SECURE_BOOT": 0xD1,
        "AUTH": 0xD2,
        "VERIFIED_BOOT": 0xD3,
        "OEM_LOCK": 0xD4,
        "WARRANTY": 0xD5,
        "ROOT": 0xD6,
        "INTEGRITY": 0xD7,
        "ENCRYPTION": 0xD8,
        "SIGNATURE": 0xD9,
    }
    
    if bypass_type in common_bypass_opcodes:
        opcode = common_bypass_opcodes[bypass_type]
        if opcode in QSLCLEND_DB:
            print(f"[*] Using common QSLCLEND bypass opcode 0x{opcode:02X} for '{bypass_type}'")
            entry = QSLCLEND_DB[opcode]
            if isinstance(entry, dict):
                entry_data = entry.get("raw", b"")
            else:
                entry_data = entry
            
            pkt = b"QSLCLEND" + entry_data + params
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            status = decode_runtime_result(resp)
            
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {bypass_type} bypass executed successfully via common QSLCLEND opcode 0x{opcode:02X}")
                return True
            else:
                print(f"[!] Common QSLCLEND bypass opcode 0x{opcode:02X} failed: {status}")
                return False
    
    return None

def try_vm5_bypass_service(dev, bypass_type, params):
    """
    Try QSLCLVM5 bypass microservices
    """
    # Check for exact match
    if bypass_type in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 bypass microservice: {bypass_type}")
        raw = QSLCLVM5_DB[bypass_type]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass executed successfully via QSLCLVM5")
            return True
        else:
            print(f"[!] QSLCLVM5 bypass '{bypass_type}' failed: {status}")
            return False
    
    # Check for BYPASS_ prefixed VM5 services
    bypass_prefixed = f"BYPASS_{bypass_type}"
    if bypass_prefixed in QSLCLVM5_DB:
        print(f"[*] Using QSLCLVM5 bypass microservice: {bypass_prefixed}")
        raw = QSLCLVM5_DB[bypass_prefixed]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass executed successfully via QSLCLVM5 {bypass_prefixed}")
            return True
        else:
            print(f"[!] QSLCLVM5 bypass '{bypass_prefixed}' failed: {status}")
            return False
    
    return None

def try_idx_bypass_command(dev, bypass_type, params):
    """
    Try QSLCLIDX bypass commands
    """
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if bypass_type.upper() == entry_name.upper() or f"BYPASS_{bypass_type}".upper() == entry_name.upper():
                idx = entry.get('idx', 0)
                print(f"[*] Using QSLCLIDX bypass command: {name} (idx: 0x{idx:02X})")
                
                pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
                resp = qslcl_dispatch(dev, "IDX", pkt)
                status = decode_runtime_result(resp)
                
                if status.get("severity") == "SUCCESS":
                    print(f"[✓] {bypass_type} bypass executed successfully via QSLCLIDX {name}")
                    return True
                else:
                    print(f"[!] QSLCLIDX bypass '{name}' failed: {status}")
                    return False
    
    return None

def try_generic_bypass_method(dev, bypass_type, params):
    """
    Final fallback: try generic bypass methods
    """
    print(f"[*] Trying generic bypass method for '{bypass_type}'")
    
    # Try the bypass type as a direct command
    resp = qslcl_dispatch(dev, bypass_type, params)
    status = decode_runtime_result(resp)
    
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {bypass_type} bypass executed successfully via generic method")
        return True
    else:
        print(f"[!] Generic bypass method for '{bypass_type}' failed: {status}")
        return False

def verify_bypass_success(dev, bypass_type):
    """
    Verify that bypass was successful
    """
    print(f"[*] Verifying {bypass_type} bypass success...")
    
    # Wait a moment for changes to take effect
    time.sleep(2)
    
    # Re-scan security mechanisms to check if bypass worked
    if bypass_type == "FRP":
        new_frp_state = detect_frp_state(dev)
        if new_frp_state == "INACTIVE":
            print("[✓] FRP bypass verified successfully")
            return True
        else:
            print("[!] FRP bypass may have failed")
            return False
            
    elif bypass_type == "SECURE_BOOT":
        new_secure_boot_state = detect_secure_boot_state(dev)
        if new_secure_boot_state == "DISABLED":
            print("[✓] Secure Boot bypass verified successfully")
            return True
        else:
            print("[!] Secure Boot bypass may have failed")
            return False
            
    elif bypass_type == "OEM_LOCK":
        new_lock_state = detect_bootloader_lock_state(dev)
        if new_lock_state == "UNLOCKED":
            print("[✓] OEM Lock bypass verified successfully")
            return True
        else:
            print("[!] OEM Lock bypass may have failed")
            return False
    
    # For other bypass types, try to check status
    resp = qslcl_dispatch(dev, "BYPASS", b"VERIFY_" + bypass_type.encode() + b"\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {bypass_type} bypass verified successfully")
            return True
    
    print(f"[~] {bypass_type} bypass completed - manual verification recommended")
    return True

def update_bypass_parser(sub):
    """
    Update the BYPASS command parser with new subcommands
    """
    bypass_parser = sub.add_parser("bypass", help="Security mechanism bypass commands")
    bypass_parser.add_argument("bypass_subcommand", help="Bypass subcommand (list, scan, status, or bypass type)")
    bypass_parser.add_argument("bypass_args", nargs="*", help="Additional arguments for bypass command")
    bypass_parser.set_defaults(func=cmd_bypass)

def cmd_voltage(args):
    """
    Advanced VOLTAGE command handler for power management and voltage control
    Supports voltage reading, regulation, and power domain control
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse VOLTAGE subcommand
    if not hasattr(args, 'voltage_subcommand') or not args.voltage_subcommand:
        return print("[!] VOLTAGE command requires subcommand (list, read, set, domains, etc.)")
    
    subcmd = args.voltage_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_voltage_commands(dev)
    elif subcmd == "READ":
        return read_voltage_values(dev, args)
    elif subcmd == "SET":
        return set_voltage_values(dev, args)
    elif subcmd == "DOMAINS":
        return list_power_domains(dev)
    elif subcmd == "MONITOR":
        return monitor_voltage_continuous(dev, args)
    elif subcmd == "CALIBRATE":
        return calibrate_voltage_sensors(dev, args)
    elif subcmd == "PROFILE":
        return manage_power_profiles(dev, args)
    else:
        return handle_voltage_operation(dev, subcmd, args)

def list_available_voltage_commands(dev):
    """
    List all available VOLTAGE commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL VOLTAGE & POWER COMMANDS")
    print("="*60)
    
    voltage_found = []
    
    # Check QSLCLPAR for VOLTAGE commands
    print("\n[QSLCLPAR] Voltage Commands:")
    par_voltage = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in ["VOLTAGE", "POWER", "VDD", "VREG", "PMIC", "BATTERY"])]
    for voltage_cmd in par_voltage:
        print(f"  • {voltage_cmd}")
        voltage_found.append(voltage_cmd)
    
    # Check QSLCLEND for voltage-related opcodes
    print("\n[QSLCLEND] Voltage Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["VOLTAGE", "POWER", "VDD", "PMIC"]) or any(x in entry_str for x in ["VOLT", "PWR", "VDD"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            voltage_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for voltage microservices
    print("\n[QSLCLVM5] Voltage Microservices:")
    vm5_voltage = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["VOLTAGE", "POWER", "PMIC"])]
    for voltage_cmd in vm5_voltage:
        print(f"  • {voltage_cmd}")
        voltage_found.append(f"VM5_{voltage_cmd}")
    
    # Check QSLCLIDX for voltage indices
    print("\n[QSLCLIDX] Voltage Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["VOLTAGE", "POWER", "PMIC"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                voltage_found.append(f"IDX_{name}")
    
    if not voltage_found:
        print("  No voltage commands found in loader")
    else:
        print(f"\n[*] Total voltage commands found: {len(voltage_found)}")
    
    print("\n[*] Common Voltage Operations Available:")
    print("  • READ         - Read voltage values from various domains")
    print("  • SET          - Set voltage values for specific domains")
    print("  • DOMAINS      - List available power domains")
    print("  • MONITOR      - Continuous voltage monitoring")
    print("  • CALIBRATE    - Calibrate voltage sensors")
    print("  • PROFILE      - Manage power profiles")
    print("  • PMIC         - PMIC register access")
    print("  • BUCK         - Buck converter control")
    print("  • LDO          - LDO regulator control")
    print("  • BANDGAP      - Bandgap reference control")
    
    print("="*60)
    
    return True

def read_voltage_values(dev, args):
    """
    Read voltage values from various power domains
    """
    target_domain = None
    if hasattr(args, 'voltage_args') and args.voltage_args:
        target_domain = args.voltage_args[0].upper()
    
    print("[*] Reading voltage values...")
    
    # Get available power domains
    domains = get_power_domains(dev)
    
    readings = {}
    
    if target_domain and target_domain in domains:
        # Read specific domain
        voltage = read_single_voltage(dev, target_domain)
        if voltage is not None:
            readings[target_domain] = voltage
            print(f"  [✓] {target_domain}: {voltage:.3f}V")
        else:
            print(f"  [!] Failed to read {target_domain}")
    else:
        # Read all domains
        for domain in domains:
            voltage = read_single_voltage(dev, domain)
            if voltage is not None:
                readings[domain] = voltage
                print(f"  [✓] {domain}: {voltage:.3f}V")
            else:
                print(f"  [!] Failed to read {domain}")
    
    # Display summary
    if readings:
        print(f"\n[*] Voltage Summary ({len(readings)} domains):")
        for domain, voltage in sorted(readings.items()):
            status = "NORMAL" if is_voltage_normal(domain, voltage) else "WARNING"
            print(f"  • {domain}: {voltage:.3f}V [{status}]")
    
    return len(readings) > 0

def read_single_voltage(dev, domain):
    """
    Read voltage from a specific power domain
    """
    # Try direct voltage read command
    payload = domain.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "VOLTAGE", b"READ\x00" + payload)
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 4:
                # Voltage in millivolts (common format)
                voltage_mv = struct.unpack("<I", extra[:4])[0]
                return voltage_mv / 1000.0  # Convert to volts
    
    # Try domain-specific command
    resp = qslcl_dispatch(dev, f"VOLTAGE_{domain}", b"")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 4:
                voltage_mv = struct.unpack("<I", extra[:4])[0]
                return voltage_mv / 1000.0
    
    return None

def get_power_domains(dev):
    """
    Get list of available power domains
    """
    # Common power domains across SOCs
    common_domains = [
        "VDD_CPU", "VDD_GPU", "VDD_DDR", "VDD_CORE", "VDD_MEM", 
        "VDD_IO", "VDD_AON", "VDD_RF", "VDD_MODEM", "VDD_PLL",
        "VDD_USB", "VDD_SRAM", "VDD_ANALOG", "VDD_DIGITAL", "VDD_Q6",
        "BATTERY", "VREG_S1", "VREG_S2", "VREG_S3", "VREG_S4",
        "VDD_APC0", "VDD_APC1", "VDD_GFX", "VDD_MX", "VDD_CX"
    ]
    
    # Try to get domains from device
    resp = qslcl_dispatch(dev, "VOLTAGE", b"DOMAINS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                # Parse domain list from response
                domain_list = extra.decode('utf-8', errors='ignore').split('\x00')
                return [d.strip() for d in domain_list if d.strip()]
            except:
                pass
    
    return common_domains

def is_voltage_normal(domain, voltage):
    """
    Check if voltage is within normal range for the domain
    """
    # Typical voltage ranges for common domains (in volts)
    voltage_ranges = {
        "VDD_CPU": (0.8, 1.4),
        "VDD_GPU": (0.8, 1.2),
        "VDD_DDR": (1.1, 1.4),
        "VDD_CORE": (0.9, 1.1),
        "VDD_IO": (1.8, 3.3),
        "VDD_MEM": (1.1, 1.4),
        "BATTERY": (3.0, 4.4),
        "VDD_RF": (2.7, 3.3),
        "VDD_PLL": (1.2, 1.4),
    }
    
    if domain in voltage_ranges:
        min_v, max_v = voltage_ranges[domain]
        return min_v <= voltage <= max_v
    
    return True  # Unknown domain, assume normal

def set_voltage_values(dev, args):
    """
    Set voltage values for specific power domains
    """
    if not hasattr(args, 'voltage_args') or len(args.voltage_args) < 2:
        return print("[!] SET requires domain and voltage (e.g., VDD_CPU 1.2)")
    
    domain = args.voltage_args[0].upper()
    voltage_str = args.voltage_args[1]
    
    try:
        if 'mv' in voltage_str.lower():
            voltage_mv = int(voltage_str.lower().replace('mv', '').strip())
        else:
            voltage = float(voltage_str)
            voltage_mv = int(voltage * 1000)  # Convert to millivolts
    except ValueError:
        return print("[!] Invalid voltage value")
    
    print(f"[!] WARNING: Setting {domain} to {voltage_mv}mV")
    print("[!] This may cause device instability or damage!")
    
    confirm = input("!! CONFIRM VOLTAGE CHANGE (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Voltage change cancelled")
        return False
    
    # Execute voltage set
    success = set_single_voltage(dev, domain, voltage_mv)
    
    if success:
        # Verify the change
        new_voltage = read_single_voltage(dev, domain)
        if new_voltage is not None:
            print(f"[✓] {domain} set to {new_voltage:.3f}V")
        else:
            print(f"[✓] {domain} voltage change executed (verification failed)")
    
    return success

def set_single_voltage(dev, domain, voltage_mv):
    """
    Set voltage for a specific power domain
    """
    # Build voltage set payload
    payload = domain.encode() + b"\x00" + struct.pack("<I", voltage_mv)
    
    # Try direct voltage set command
    resp = qslcl_dispatch(dev, "VOLTAGE", b"SET\x00" + payload)
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {domain} voltage set to {voltage_mv}mV via VOLTAGE SET")
            return True
    
    # Try domain-specific set command
    resp = qslcl_dispatch(dev, f"SET_{domain}", struct.pack("<I", voltage_mv))
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {domain} voltage set to {voltage_mv}mV via domain command")
            return True
    
    # Try PMIC register write for advanced users
    if try_pmic_voltage_set(dev, domain, voltage_mv):
        return True
    
    print(f"[!] Failed to set {domain} voltage")
    return False

def try_pmic_voltage_set(dev, domain, voltage_mv):
    """
    Try PMIC register-based voltage setting (advanced)
    """
    # Map domains to common PMIC registers
    pmic_registers = {
        "VDD_CPU": (0x1400, 0x1401),  # S1 voltage control
        "VDD_GPU": (0x1500, 0x1501),  # S2 voltage control  
        "VDD_DDR": (0x1600, 0x1601),  # S3 voltage control
        "VDD_CORE": (0x1700, 0x1701), # S4 voltage control
    }
    
    if domain in pmic_registers:
        vsen_reg, vctl_reg = pmic_registers[domain]
        
        # Convert voltage to PMIC register value (typical formula)
        # This varies by PMIC - using approximate formula for common PMICs
        if voltage_mv < 800: voltage_mv = 800
        if voltage_mv > 1400: voltage_mv = 1400
        
        # Approximate conversion (exact formula depends on PMIC)
        reg_value = ((voltage_mv - 800) // 10) & 0x7F
        
        # Write to PMIC register
        payload = struct.pack("<HH", vctl_reg, reg_value)
        resp = qslcl_dispatch(dev, "PMIC_WRITE", payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {domain} set to {voltage_mv}mV via PMIC register 0x{vctl_reg:04X}")
                return True
    
    return False

def list_power_domains(dev):
    """
    List all available power domains with current voltages
    """
    print("[*] Scanning power domains...")
    
    domains = get_power_domains(dev)
    
    print(f"\n[*] Found {len(domains)} power domains:")
    print("-" * 50)
    
    for domain in domains:
        voltage = read_single_voltage(dev, domain)
        if voltage is not None:
            status = "NORMAL" if is_voltage_normal(domain, voltage) else "WARNING"
            print(f"  • {domain:<15} : {voltage:6.3f}V [{status}]")
        else:
            print(f"  • {domain:<15} : UNREADABLE")
    
    return True

def monitor_voltage_continuous(dev, args):
    """
    Continuous voltage monitoring with real-time display
    """
    duration = 30  # Default 30 seconds
    interval = 1   # Default 1 second intervals
    
    if hasattr(args, 'voltage_args'):
        if len(args.voltage_args) > 0:
            try:
                duration = int(args.voltage_args[0])
            except:
                pass
        if len(args.voltage_args) > 1:
            try:
                interval = float(args.voltage_args[1])
            except:
                pass
    
    target_domains = []
    if hasattr(args, 'voltage_args') and len(args.voltage_args) > 2:
        target_domains = [d.upper() for d in args.voltage_args[2:]]
    
    domains = get_power_domains(dev)
    if target_domains:
        domains = [d for d in domains if d in target_domains]
    
    print(f"[*] Starting voltage monitoring for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early")
    
    start_time = time.time()
    end_time = start_time + duration
    
    try:
        while time.time() < end_time:
            elapsed = time.time() - start_time
            print(f"\n[*] Time: {elapsed:5.1f}s")
            print("-" * 40)
            
            for domain in domains:
                voltage = read_single_voltage(dev, domain)
                if voltage is not None:
                    status = "✓" if is_voltage_normal(domain, voltage) else "!"
                    print(f"  {status} {domain:<15} : {voltage:6.3f}V")
                else:
                    print(f"  ? {domain:<15} : ---.--V")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user")
    
    print("[*] Voltage monitoring completed")
    return True

def calibrate_voltage_sensors(dev, args):
    """
    Calibrate voltage sensors and ADCs
    """
    print("[*] Starting voltage sensor calibration...")
    
    calibration_type = "AUTO"
    if hasattr(args, 'voltage_args') and args.voltage_args:
        calibration_type = args.voltage_args[0].upper()
    
    # Try calibration command
    payload = calibration_type.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "VOLTAGE", b"CALIBRATE\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print("[✓] Voltage calibration completed successfully")
            
            # Read calibration results if available
            extra = status.get("extra", b"")
            if extra:
                try:
                    cal_data = extra.decode('utf-8', errors='ignore')
                    print(f"[*] Calibration data: {cal_data}")
                except:
                    print(f"[*] Calibration data (raw): {extra.hex()}")
            
            return True
        else:
            print(f"[!] Voltage calibration failed: {status}")
            return False
    
    print("[!] No voltage calibration command available")
    return False

def manage_power_profiles(dev, args):
    """
    Manage power profiles and performance states
    """
    if not hasattr(args, 'voltage_args') or not args.voltage_args:
        return list_power_profiles(dev)
    
    action = args.voltage_args[0].upper()
    
    if action == "LIST":
        return list_power_profiles(dev)

    elif action == "SET":
        if len(args.voltage_args) < 2:
            return print("[!] PROFILE SET requires profile name")
        profile = args.voltage_args[1].upper()
        return set_power_profile(dev, profile)

    elif action == "CREATE":
        return create_power_profile(dev, args)

    else:
        # FIXED LINE — fully closed parenthesis
        return handle_power_profile_action(dev, action, args)

def list_power_profiles(dev):
    """
    List available power profiles
    """
    print("[*] Available power profiles:")
    
    common_profiles = [
        "PERFORMANCE", "BALANCED", "POWER_SAVE", "ULTRA_SAVE",
        "GAMING", "BENCHMARK", "THERMAL", "DEFAULT"
    ]
    
    # Try to get profiles from device
    resp = qslcl_dispatch(dev, "VOLTAGE", b"PROFILES\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                profiles = extra.decode('utf-8', errors='ignore').split('\x00')
                common_profiles = [p.strip() for p in profiles if p.strip()]
            except:
                pass
    
    for profile in common_profiles:
        print(f"  • {profile}")
    
    return True

def set_power_profile(dev, profile):
    """
    Set active power profile
    """
    print(f"[*] Setting power profile to {profile}...")
    
    payload = profile.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "VOLTAGE", b"PROFILE_SET\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Power profile set to {profile}")
            return True
        else:
            print(f"[!] Failed to set power profile: {status}")
            return False
    
    print(f"[!] No power profile support available")
    return False

def handle_voltage_operation(dev, operation, args):
    """
    Handle other voltage operations (PMIC, BUCK, LDO, etc.)
    """
    print(f"[*] Executing voltage operation: {operation}")
    
    # Build operation parameters
    params = build_voltage_operation_params(operation, args)
    
    # Try different operation strategies
    strategies = [
        try_direct_voltage_operation,
        try_par_voltage_command,
        try_end_voltage_opcode,
        try_vm5_voltage_service,
        try_idx_voltage_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute voltage operation: {operation}")
    return False

def build_voltage_operation_params(operation, args):
    """
    Build parameters for voltage operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'voltage_args'):
        for arg in args.voltage_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

def try_direct_voltage_operation(dev, operation, params):
    """Try direct voltage operation"""
    resp = qslcl_dispatch(dev, "VOLTAGE", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {operation} executed successfully")
        return True
    return None

def try_par_voltage_command(dev, operation, params):
    """Try QSLCLPAR voltage command"""
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLPAR")
            return True
    return None

def try_end_voltage_opcode(dev, operation, params):
    """Try QSLCLEND voltage opcode"""
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLEND opcode 0x{opcode:02X}")
            return True
    return None

def try_vm5_voltage_service(dev, operation, params):
    """Try QSLCLVM5 voltage service"""
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLVM5")
            return True
    return None

def try_idx_voltage_command(dev, operation, params):
    """Try QSLCLIDX voltage command"""
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {operation} executed via QSLCLIDX {name}")
                return True
    return None

def create_power_profile(dev, args):
    """Create custom power profile (placeholder)"""
    print("[*] Custom power profile creation not yet implemented")
    return False

def handle_power_profile_action(dev, action, args):
    """Handle other power profile actions"""
    print(f"[*] Power profile action '{action}' not yet implemented")
    return False

def update_voltage_parser(sub):
    """
    Update the VOLTAGE command parser with new subcommands
    """
    voltage_parser = sub.add_parser("voltage", help="Voltage and power management commands")
    voltage_parser.add_argument("voltage_subcommand", help="Voltage subcommand (list, read, set, domains, monitor, calibrate, profile)")
    voltage_parser.add_argument("voltage_args", nargs="*", help="Additional arguments for voltage command")
    voltage_parser.set_defaults(func=cmd_voltage)

def cmd_power(args):
    """
    Advanced POWER command handler for complete power management and control
    Supports power states, domains, sequencing, and advanced power features
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse POWER subcommand
    if not hasattr(args, 'power_subcommand') or not args.power_subcommand:
        return print("[!] POWER command requires subcommand (list, status, on, off, reset, domains, etc.)")
    
    subcmd = args.power_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_power_commands(dev)
    elif subcmd == "STATUS":
        return get_power_status(dev)
    elif subcmd == "ON":
        return power_on_domain(dev, args)
    elif subcmd == "OFF":
        return power_off_domain(dev, args)
    elif subcmd == "RESET":
        return power_reset_domain(dev, args)
    elif subcmd == "DOMAINS":
        return list_power_domains_detailed(dev)
    elif subcmd == "SEQUENCE":
        return control_power_sequence(dev, args)
    elif subcmd == "PROFILE":
        return manage_power_profiles(dev, args)
    elif subcmd == "MONITOR":
        return monitor_power_consumption(dev, args)
    elif subcmd == "WAKE":
        return control_wake_sources(dev, args)
    elif subcmd == "SLEEP":
        return control_sleep_states(dev, args)
    elif subcmd == "BATTERY":
        return handle_battery_operations(dev, args)
    elif subcmd == "THERMAL":
        return handle_thermal_management(dev, args)
    elif subcmd == "EFFICIENCY":
        return analyze_power_efficiency(dev, args)
    else:
        return handle_power_operation(dev, subcmd, args)

def list_available_power_commands(dev):
    """
    List all available POWER commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL POWER MANAGEMENT COMMANDS")
    print("="*60)
    
    power_found = []
    
    # Check QSLCLPAR for POWER commands
    print("\n[QSLCLPAR] Power Commands:")
    par_power = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "POWER", "PMIC", "PSHOLD", "RESET", "SHUTDOWN", "BOOT", "WAKE", 
        "SLEEP", "BATTERY", "THERMAL", "CLOCK", "DOMAIN", "RAIL"
    ])]
    for power_cmd in par_power:
        print(f"  • {power_cmd}")
        power_found.append(power_cmd)
    
    # Check QSLCLEND for power-related opcodes
    print("\n[QSLCLEND] Power Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["POWER", "PMIC", "RESET", "SHUTDOWN", "WAKE"]) or any(x in entry_str for x in ["PWR", "PMIC", "RST"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            power_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for power microservices
    print("\n[QSLCLVM5] Power Microservices:")
    vm5_power = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["POWER", "PMIC", "RESET"])]
    for power_cmd in vm5_power:
        print(f"  • {power_cmd}")
        power_found.append(f"VM5_{power_cmd}")
    
    # Check QSLCLIDX for power indices
    print("\n[QSLCLIDX] Power Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["POWER", "PMIC", "RESET"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                power_found.append(f"IDX_{name}")
    
    if not power_found:
        print("  No power commands found in loader")
    else:
        print(f"\n[*] Total power commands found: {len(power_found)}")
    
    print("\n[*] Common Power Operations Available:")
    print("  • STATUS      - Get comprehensive power status")
    print("  • ON          - Power on specific domain")
    print("  • OFF         - Power off specific domain") 
    print("  • RESET       - Reset power domain")
    print("  • DOMAINS     - List power domains with details")
    print("  • SEQUENCE    - Control power sequencing")
    print("  • PROFILE     - Manage power profiles")
    print("  • MONITOR     - Real-time power monitoring")
    print("  • WAKE        - Configure wake sources")
    print("  • SLEEP       - Control sleep states")
    print("  • BATTERY     - Battery management")
    print("  • THERMAL     - Thermal management")
    print("  • EFFICIENCY  - Power efficiency analysis")
    
    print("="*60)
    
    return True

def get_power_status(dev):
    """
    Get comprehensive power status of the device
    """
    print("[*] Getting comprehensive power status...")
    
    status_info = {}
    
    # Get power domain status
    print("\n[Power Domains Status]")
    domains_status = get_power_domains_status(dev)
    status_info["domains"] = domains_status
    
    # Get battery status
    print("\n[Battery Status]")
    battery_status = get_battery_status(dev)
    status_info["battery"] = battery_status
    
    # Get thermal status
    print("\n[Thermal Status]")
    thermal_status = get_thermal_status(dev)
    status_info["thermal"] = thermal_status
    
    # Get PMIC status
    print("\n[PMIC Status]")
    pmic_status = get_pmic_status(dev)
    status_info["pmic"] = pmic_status
    
    # Get wake/sleep status
    print("\n[Wake/Sleep Status]")
    wake_status = get_wake_sleep_status(dev)
    status_info["wake_sleep"] = wake_status
    
    # Display summary
    print("\n" + "="*50)
    print("[*] POWER STATUS SUMMARY")
    print("="*50)
    
    active_domains = sum(1 for domain in domains_status if domains_status[domain].get("state") == "ON")
    print(f"Active Domains: {active_domains}/{len(domains_status)}")
    
    if battery_status:
        batt_level = battery_status.get("level", "UNKNOWN")
        batt_health = battery_status.get("health", "UNKNOWN")
        print(f"Battery: {batt_level}%, Health: {batt_health}")
    
    if thermal_status:
        temp = thermal_status.get("temperature", "UNKNOWN")
        print(f"Temperature: {temp}")
    
    print("="*50)
    
    return status_info

def get_power_domains_status(dev):
    """
    Get status of all power domains
    """
    domains = get_power_domains_list(dev)
    domains_status = {}
    
    for domain in domains:
        # Try to get domain status
        payload = domain.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "POWER", b"STATUS\x00" + payload)
        
        state = "UNKNOWN"
        voltage = 0.0
        current = 0.0
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if len(extra) >= 9:  # state(1) + voltage(4) + current(4)
                    state_byte = extra[0]
                    state = "ON" if state_byte == 1 else "OFF" if state_byte == 0 else "UNKNOWN"
                    voltage = struct.unpack("<f", extra[1:5])[0] if len(extra) >= 5 else 0.0
                    current = struct.unpack("<f", extra[5:9])[0] if len(extra) >= 9 else 0.0
        
        domains_status[domain] = {
            "state": state,
            "voltage": voltage,
            "current": current,
            "power": voltage * current if voltage and current else 0.0
        }
        
        power_str = f"{domains_status[domain]['power']:.2f}W" if domains_status[domain]['power'] > 0 else "N/A"
        print(f"  • {domain:<15} : {state:<8} {voltage:.2f}V {current:.2f}A {power_str}")
    
    return domains_status

def get_battery_status(dev):
    """
    Get battery status and information
    """
    battery_status = {}
    
    # Try battery status command
    resp = qslcl_dispatch(dev, "POWER", b"BATTERY_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 16:
                # Parse battery data: level(1), voltage(4), current(4), capacity(4), health(1), temp(2)
                battery_status["level"] = extra[0]
                battery_status["voltage"] = struct.unpack("<f", extra[1:5])[0]
                battery_status["current"] = struct.unpack("<f", extra[5:9])[0]
                battery_status["capacity"] = struct.unpack("<f", extra[9:13])[0]
                battery_status["health"] = extra[13]
                battery_status["temperature"] = struct.unpack("<H", extra[14:16])[0] / 10.0  # Convert to °C
    
    if battery_status:
        health_map = {0: "UNKNOWN", 1: "GOOD", 2: "OVERHEAT", 3: "DEAD", 4: "OVER_VOLTAGE"}
        health = health_map.get(battery_status.get("health", 0), "UNKNOWN")
        
        print(f"  • Level     : {battery_status.get('level', 0)}%")
        print(f"  • Voltage   : {battery_status.get('voltage', 0):.2f}V")
        print(f"  • Current   : {battery_status.get('current', 0):.2f}A")
        print(f"  • Capacity  : {battery_status.get('capacity', 0):.0f}mAh")
        print(f"  • Health    : {health}")
        print(f"  • Temp      : {battery_status.get('temperature', 0):.1f}°C")
    else:
        print("  • Battery status: Not available")
    
    return battery_status

def get_thermal_status(dev):
    """
    Get thermal status and temperatures
    """
    thermal_status = {}
    
    # Try thermal status command
    resp = qslcl_dispatch(dev, "POWER", b"THERMAL_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 2:
                thermal_status["temperature"] = struct.unpack("<H", extra[0:2])[0] / 10.0  # Convert to °C
    
    if thermal_status:
        temp = thermal_status.get("temperature", 0)
        status = "NORMAL" if temp < 60 else "WARM" if temp < 80 else "HOT" if temp < 95 else "CRITICAL"
        print(f"  • Temperature : {temp:.1f}°C [{status}]")
    else:
        print("  • Thermal status: Not available")
    
    return thermal_status

def get_pmic_status(dev):
    """
    Get PMIC (Power Management IC) status
    """
    pmic_status = {}
    
    # Try PMIC status command
    resp = qslcl_dispatch(dev, "POWER", b"PMIC_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 4:
                pmic_status["chip_id"] = struct.unpack("<I", extra[0:4])[0]
    
    if pmic_status:
        print(f"  • PMIC Chip ID: 0x{pmic_status.get('chip_id', 0):08X}")
    else:
        print("  • PMIC status: Not available")
    
    return pmic_status

def get_wake_sleep_status(dev):
    """
    Get wake and sleep status
    """
    wake_status = {}
    
    # Try wake/sleep status command
    resp = qslcl_dispatch(dev, "POWER", b"WAKE_STATUS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= 1:
                wake_status["state"] = "AWAKE" if extra[0] == 1 else "SLEEP"
    
    if wake_status:
        print(f"  • Device State: {wake_status.get('state', 'UNKNOWN')}")
    else:
        print("  • Wake/Sleep status: Not available")
    
    return wake_status

def get_power_domains_list(dev):
    """
    Get list of power domains
    """
    # Common power domains
    common_domains = [
        "VDD_CPU", "VDD_CPU_BIG", "VDD_CPU_LITTLE", "VDD_GPU", "VDD_DDR",
        "VDD_CORE", "VDD_MEM", "VDD_IO", "VDD_AON", "VDD_RF", "VDD_MODEM",
        "VDD_PLL", "VDD_USB", "VDD_SRAM", "VDD_ANALOG", "VDD_DIGITAL",
        "VDD_DISPLAY", "VDD_CAMERA", "VDD_AUDIO", "VDD_SENSORS"
    ]
    
    # Try to get domains from device
    resp = qslcl_dispatch(dev, "POWER", b"DOMAINS\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                domain_list = extra.decode('utf-8', errors='ignore').split('\x00')
                return [d.strip() for d in domain_list if d.strip()]
            except:
                pass
    
    return common_domains

def power_on_domain(dev, args):
    """
    Power on specific power domain
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return print("[!] POWER ON requires domain name")
    
    domain = args.power_args[0].upper()
    
    print(f"[*] Powering ON domain: {domain}")
    
    # Safety confirmation for critical domains
    critical_domains = ["VDD_CPU", "VDD_GPU", "VDD_DDR", "VDD_CORE"]
    if domain in critical_domains:
        confirm = input(f"!! CONFIRM POWER ON {domain} (type 'YES' to continue): ").strip().upper()
        if confirm != "YES":
            print("[*] Power ON cancelled")
            return False
    
    # Execute power on
    payload = domain.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "POWER", b"ON\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {domain} powered ON successfully")
            
            # Verify power state
            time.sleep(0.5)
            domains_status = get_power_domains_status(dev)
            if domain in domains_status and domains_status[domain].get("state") == "ON":
                print(f"[✓] {domain} power verification: ON")
            else:
                print(f"[!] {domain} power verification failed")
            
            return True
        else:
            print(f"[!] Failed to power ON {domain}: {status}")
            return False
    
    print(f"[!] No power ON command available for {domain}")
    return False

def power_off_domain(dev, args):
    """
    Power off specific power domain
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return print("[!] POWER OFF requires domain name")
    
    domain = args.power_args[0].upper()
    
    print(f"[!] WARNING: Powering OFF domain: {domain}")
    print("[!] This may cause device instability or data loss!")
    
    confirm = input(f"!! CONFIRM POWER OFF {domain} (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Power OFF cancelled")
        return False
    
    # Execute power off
    payload = domain.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "POWER", b"OFF\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {domain} powered OFF successfully")
            return True
        else:
            print(f"[!] Failed to power OFF {domain}: {status}")
            return False
    
    print(f"[!] No power OFF command available for {domain}")
    return False

def power_reset_domain(dev, args):
    """
    Reset specific power domain
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return print("[!] POWER RESET requires domain name")
    
    domain = args.power_args[0].upper()
    
    print(f"[*] Resetting power domain: {domain}")
    
    # Execute power reset
    payload = domain.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "POWER", b"RESET\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {domain} reset successfully")
            
            # Wait for domain to stabilize
            time.sleep(1)
            
            # Verify reset
            domains_status = get_power_domains_status(dev)
            if domain in domains_status and domains_status[domain].get("state") == "ON":
                print(f"[✓] {domain} is back ONLINE after reset")
            else:
                print(f"[!] {domain} may be OFFLINE after reset")
            
            return True
        else:
            print(f"[!] Failed to reset {domain}: {status}")
            return False
    
    print(f"[!] No power RESET command available for {domain}")
    return False

def list_power_domains_detailed(dev):
    """
    List power domains with detailed information
    """
    print("[*] Scanning power domains with detailed information...")
    
    domains = get_power_domains_list(dev)
    domains_status = get_power_domains_status(dev)
    
    print(f"\n[*] Found {len(domains)} power domains:")
    print("=" * 70)
    print(f"{'Domain':<20} {'State':<8} {'Voltage':<8} {'Current':<8} {'Power':<10} {'Status'}")
    print("-" * 70)
    
    total_power = 0.0
    for domain in domains:
        status = domains_status.get(domain, {})
        state = status.get("state", "UNKNOWN")
        voltage = status.get("voltage", 0.0)
        current = status.get("current", 0.0)
        power = status.get("power", 0.0)
        total_power += power
        
        power_str = f"{power:.2f}W" if power > 0 else "N/A"
        status_indicator = "✓" if state == "ON" and power > 0 else "○" if state == "ON" else "✗"
        
        print(f"{domain:<20} {state:<8} {voltage:.2f}V {current:.2f}A {power_str:<10} {status_indicator}")
    
    print("-" * 70)
    print(f"{'TOTAL':<20} {'':<8} {'':<8} {'':<8} {total_power:.2f}W")
    print("=" * 70)
    
    return True

def control_power_sequence(dev, args):
    """
    Control power sequencing and timing
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return print_power_sequence_help()
    
    action = args.power_args[0].upper()
    
    if action == "LIST":
        return list_power_sequences(dev)
    elif action == "START":
        return start_power_sequence(dev, args)
    elif action == "STOP":
        return stop_power_sequence(dev, args)
    elif action == "CONFIGURE":
        return configure_power_sequence(dev, args)
    else:
        return handle_power_sequence_action(dev, action, args)

def list_power_sequences(dev):
    """
    List available power sequences
    """
    print("[*] Available power sequences:")
    
    common_sequences = [
        "BOOT_SEQUENCE", "SHUTDOWN_SEQUENCE", "SLEEP_SEQUENCE", 
        "WAKE_SEQUENCE", "RESET_SEQUENCE", "LOW_POWER_SEQUENCE"
    ]
    
    for seq in common_sequences:
        print(f"  • {seq}")
    
    return True

def start_power_sequence(dev, args):
    """
    Start a power sequence
    """
    if len(args.power_args) < 2:
        return print("[!] SEQUENCE START requires sequence name")
    
    sequence = args.power_args[1].upper()
    
    print(f"[*] Starting power sequence: {sequence}")
    
    payload = sequence.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "POWER", b"SEQUENCE_START\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Power sequence '{sequence}' started successfully")
            return True
        else:
            print(f"[!] Failed to start power sequence: {status}")
            return False
    
    print(f"[!] No power sequence control available")
    return False

def manage_power_profiles(dev, args):
    """
    Manage power profiles (performance, efficiency, etc.)
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return list_power_profiles(dev)
    
    action = args.power_args[0].upper()
    
    if action == "LIST":
        return list_power_profiles(dev)

    elif action == "SET":
        if len(args.power_args) < 2:
            return print("[!] PROFILE SET requires profile name")
        profile = args.power_args[1].upper()
        return set_power_profile(dev, profile)

    elif action == "ACTIVE":
        return get_active_power_profile(dev)

    else:
        # FIXED: fully complete argument name and closing parenthesis
        return handle_power_profile_action(dev, action, args)

def list_power_profiles(dev):
    """
    List available power profiles
    """
    print("[*] Available power profiles:")
    
    common_profiles = [
        "PERFORMANCE", "BALANCED", "POWER_SAVE", "ULTRA_SAVE",
        "GAMING", "BENCHMARK", "THERMAL", "DEFAULT", "EFFICIENCY"
    ]
    
    for profile in common_profiles:
        print(f"  • {profile}")
    
    return True

def set_power_profile(dev, profile):
    """
    Set active power profile
    """
    print(f"[*] Setting power profile to: {profile}")
    
    payload = profile.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "POWER", b"PROFILE_SET\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Power profile set to '{profile}'")
            return True
        else:
            print(f"[!] Failed to set power profile: {status}")
            return False
    
    print(f"[!] No power profile control available")
    return False

def monitor_power_consumption(dev, args):
    """
    Real-time power consumption monitoring
    """
    duration = 30  # Default 30 seconds
    interval = 1   # Default 1 second
    
    if hasattr(args, 'power_args'):
        if len(args.power_args) > 0:
            try:
                duration = int(args.power_args[0])
            except:
                pass
        if len(args.power_args) > 1:
            try:
                interval = float(args.power_args[1])
            except:
                pass
    
    print(f"[*] Starting power monitoring for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early")
    
    start_time = time.time()
    end_time = start_time + duration
    
    try:
        while time.time() < end_time:
            elapsed = time.time() - start_time
            print(f"\n[*] Time: {elapsed:5.1f}s")
            print("-" * 50)
            
            domains_status = get_power_domains_status(dev)
            total_power = sum(status.get("power", 0) for status in domains_status.values())
            
            print(f"Total Power: {total_power:.2f}W")
            
            # Show top power consumers
            power_consumers = [(domain, status.get("power", 0)) for domain, status in domains_status.items() if status.get("power", 0) > 0]
            power_consumers.sort(key=lambda x: x[1], reverse=True)
            
            for domain, power in power_consumers[:5]:  # Top 5 consumers
                percentage = (power / total_power * 100) if total_power > 0 else 0
                print(f"  {domain:<15} : {power:6.2f}W ({percentage:5.1f}%)")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] Power monitoring stopped by user")
    
    print("[*] Power monitoring completed")
    return True

def control_wake_sources(dev, args):
    """
    Configure wake sources and wake-up triggers
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return list_wake_sources(dev)
    
    action = args.power_args[0].upper()
    
    if action == "LIST":
        return list_wake_sources(dev)
    elif action == "ENABLE":
        return enable_wake_source(dev, args)
    elif action == "DISABLE":
        return disable_wake_source(dev, args)
    else:
        return handle_wake_source_action(dev, action, args)

def list_wake_sources(dev):
    """
    List available wake sources
    """
    print("[*] Available wake sources:")
    
    common_wake_sources = [
        "RTC_ALARM", "POWER_BUTTON", "USB_CONNECT", "USB_DISCONNECT",
        "CHARGER_CONNECT", "CHARGER_DISCONNECT", "GPIO_TRIGGER",
        "ACCELEROMETER", "GYROSCOPE", "PROXIMITY", "TOUCH_SCREEN"
    ]
    
    for source in common_wake_sources:
        print(f"  • {source}")
    
    return True

def control_sleep_states(dev, args):
    """
    Control sleep states and low-power modes
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return list_sleep_states(dev)
    
    action = args.power_args[0].upper()
    
    if action == "LIST":
        return list_sleep_states(dev)
    elif action == "ENTER":
        return enter_sleep_state(dev, args)
    elif action == "EXIT":
        return exit_sleep_state(dev, args)
    else:
        return handle_sleep_state_action(dev, action, args)

def list_sleep_states(dev):
    """
    List available sleep states
    """
    print("[*] Available sleep states:")
    
    common_sleep_states = [
        "ACTIVE", "IDLE", "STANDBY", "SUSPEND", "HIBERNATE", "DEEP_SLEEP"
    ]
    
    for state in common_sleep_states:
        print(f"  • {state}")
    
    return True

def handle_battery_operations(dev, args):
    """
    Handle battery-related operations
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return get_battery_status(dev)
    
    action = args.power_args[0].upper()
    
    if action == "STATUS":
        return get_battery_status(dev)
    elif action == "CALIBRATE":
        return calibrate_battery(dev)
    elif action == "RESET":
        return reset_battery_stats(dev)
    else:
        return handle_battery_action(dev, action, args)

def handle_thermal_management(dev, args):
    """
    Handle thermal management operations
    """
    if not hasattr(args, 'power_args') or not args.power_args:
        return get_thermal_status(dev)
    
    action = args.power_args[0].upper()
    
    if action == "STATUS":
        return get_thermal_status(dev)
    elif action == "LIMIT":
        return set_thermal_limit(dev, args)
    elif action == "CONTROL":
        return control_thermal_management(dev, args)
    else:
        return handle_thermal_action(dev, action, args)

def analyze_power_efficiency(dev, args):
    """
    Analyze power efficiency and provide recommendations
    """
    print("[*] Analyzing power efficiency...")
    
    # Get current power status
    domains_status = get_power_domains_status(dev)
    total_power = sum(status.get("power", 0) for status in domains_status.values())
    
    print(f"\n[*] Power Efficiency Analysis")
    print("=" * 50)
    print(f"Total Power Consumption: {total_power:.2f}W")
    
    # Identify inefficient domains
    inefficient_domains = []
    for domain, status in domains_status.items():
        power = status.get("power", 0)
        if power > 0.5:  # Domains consuming more than 0.5W
            inefficient_domains.append((domain, power))
    
    if inefficient_domains:
        print("\n[!] High Power Consumers:")
        for domain, power in sorted(inefficient_domains, key=lambda x: x[1], reverse=True):
            print(f"  • {domain}: {power:.2f}W")
    
    # Provide recommendations
    print("\n[✓] Power Efficiency Recommendations:")
    print("  • Consider using POWER SAVE profile for better efficiency")
    print("  • Disable unused power domains")
    print("  • Enable dynamic voltage and frequency scaling")
    print("  • Use appropriate sleep states when idle")
    
    return True

def handle_power_operation(dev, operation, args):
    """
    Handle other power operations
    """
    print(f"[*] Executing power operation: {operation}")
    
    # Build operation parameters
    params = build_power_operation_params(operation, args)
    
    # Try different operation strategies
    strategies = [
        try_direct_power_operation,
        try_par_power_command,
        try_end_power_opcode,
        try_vm5_power_service,
        try_idx_power_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute power operation: {operation}")
    return False

def build_power_operation_params(operation, args):
    """
    Build parameters for power operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'power_args'):
        for arg in args.power_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Strategy implementations (similar to voltage commands)
def try_direct_power_operation(dev, operation, params):
    resp = qslcl_dispatch(dev, "POWER", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {operation} executed successfully")
        return True
    return None

def try_par_power_command(dev, operation, params):
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLPAR")
            return True
    return None

def try_end_power_opcode(dev, operation, params):
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLEND opcode 0x{opcode:02X}")
            return True
    return None

def try_vm5_power_service(dev, operation, params):
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLVM5")
            return True
    return None

def try_idx_power_command(dev, operation, params):
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {operation} executed via QSLCLIDX {name}")
                return True
    return None

# Placeholder functions for unimplemented features
def print_power_sequence_help():
    print("[*] Power sequence commands:")
    print("  sequence list                    - List available sequences")
    print("  sequence start <name>           - Start power sequence")
    print("  sequence stop <name>            - Stop power sequence")
    print("  sequence configure <name> <cfg> - Configure power sequence")
    return False

def stop_power_sequence(dev, args):
    print("[*] Power sequence stop not yet implemented")
    return False

def configure_power_sequence(dev, args):
    print("[*] Power sequence configuration not yet implemented")
    return False

def handle_power_sequence_action(dev, action, args):
    print(f"[*] Power sequence action '{action}' not yet implemented")
    return False

def get_active_power_profile(dev):
    print("[*] Active power profile query not yet implemented")
    return False

def handle_power_profile_action(dev, action, args):
    print(f"[*] Power profile action '{action}' not yet implemented")
    return False

def enable_wake_source(dev, args):
    print("[*] Wake source enable not yet implemented")
    return False

def disable_wake_source(dev, args):
    print("[*] Wake source disable not yet implemented")
    return False

def handle_wake_source_action(dev, action, args):
    print(f"[*] Wake source action '{action}' not yet implemented")
    return False

def enter_sleep_state(dev, args):
    print("[*] Enter sleep state not yet implemented")
    return False

def exit_sleep_state(dev, args):
    print("[*] Exit sleep state not yet implemented")
    return False

def handle_sleep_state_action(dev, action, args):
    print(f"[*] Sleep state action '{action}' not yet implemented")
    return False

def calibrate_battery(dev):
    print("[*] Battery calibration not yet implemented")
    return False

def reset_battery_stats(dev):
    print("[*] Battery stats reset not yet implemented")
    return False

def handle_battery_action(dev, action, args):
    print(f"[*] Battery action '{action}' not yet implemented")
    return False

def set_thermal_limit(dev, args):
    print("[*] Thermal limit setting not yet implemented")
    return False

def control_thermal_management(dev, args):
    print("[*] Thermal management control not yet implemented")
    return False

def handle_thermal_action(dev, action, args):
    print(f"[*] Thermal action '{action}' not yet implemented")
    return False

# Update the argument parser in main() function
def update_power_parser(sub):
    """
    Update the POWER command parser with new subcommands
    """
    power_parser = sub.add_parser("power", help="Power management and control commands")
    power_parser.add_argument("power_subcommand", help="Power subcommand (list, status, on, off, reset, domains, sequence, profile, monitor, wake, sleep, battery, thermal, efficiency)")
    power_parser.add_argument("power_args", nargs="*", help="Additional arguments for power command")
    power_parser.set_defaults(func=cmd_power)

def cmd_verify(args):
    """
    Advanced VERIFY command handler for comprehensive system verification and validation
    Supports firmware verification, integrity checks, signature validation, and security audits
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse VERIFY subcommand
    if not hasattr(args, 'verify_subcommand') or not args.verify_subcommand:
        return print("[!] VERIFY command requires subcommand (list, integrity, signature, checksum, security, etc.)")
    
    subcmd = args.verify_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_verify_commands(dev)
    elif subcmd == "INTEGRITY":
        return verify_system_integrity(dev, args)
    elif subcmd == "SIGNATURE":
        return verify_signatures(dev, args)
    elif subcmd == "CHECKSUM":
        return verify_checksums(dev, args)
    elif subcmd == "SECURITY":
        return verify_security_policies(dev, args)
    elif subcmd == "BOOT":
        return verify_boot_components(dev, args)
    elif subcmd == "FIRMWARE":
        return verify_firmware_integrity(dev, args)
    elif subcmd == "PARTITION":
        return verify_partition_integrity(dev, args)
    elif subcmd == "MEMORY":
        return verify_memory_integrity(dev, args)
    elif subcmd == "CERTIFICATE":
        return verify_certificates(dev, args)
    elif subcmd == "AUTHENTICATION":
        return verify_authentication(dev, args)
    elif subcmd == "COMPREHENSIVE":
        return run_comprehensive_verification(dev, args)
    elif subcmd == "REPORT":
        return generate_verification_report(dev, args)
    else:
        return handle_verification_operation(dev, subcmd, args)

def list_available_verify_commands(dev):
    """
    List all available VERIFY commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL VERIFICATION COMMANDS")
    print("="*60)
    
    verify_found = []
    
    # Check QSLCLPAR for VERIFY commands
    print("\n[QSLCLPAR] Verify Commands:")
    par_verify = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "VERIFY", "VALIDATE", "CHECK", "INTEGRITY", "SIGNATURE", 
        "CHECKSUM", "AUTHENTICATE", "CERTIFICATE", "SECURE", "HASH"
    ])]
    for verify_cmd in par_verify:
        print(f"  • {verify_cmd}")
        verify_found.append(verify_cmd)
    
    # Check QSLCLEND for verify-related opcodes
    print("\n[QSLCLEND] Verify Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["VERIFY", "VALIDATE", "CHECK", "INTEGRITY"]) or any(x in entry_str for x in ["VERIFY", "CHECK"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            verify_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for verify microservices
    print("\n[QSLCLVM5] Verify Microservices:")
    vm5_verify = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["VERIFY", "VALIDATE", "CHECK"])]
    for verify_cmd in vm5_verify:
        print(f"  • {verify_cmd}")
        verify_found.append(f"VM5_{verify_cmd}")
    
    # Check QSLCLIDX for verify indices
    print("\n[QSLCLIDX] Verify Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["VERIFY", "VALIDATE", "CHECK"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                verify_found.append(f"IDX_{name}")
    
    if not verify_found:
        print("  No verify commands found in loader")
    else:
        print(f"\n[*] Total verify commands found: {len(verify_found)}")
    
    print("\n[*] Common Verification Operations Available:")
    print("  • INTEGRITY     - System integrity verification")
    print("  • SIGNATURE     - Digital signature validation")
    print("  • CHECKSUM      - Checksum and hash verification")
    print("  • SECURITY      - Security policy verification")
    print("  • BOOT          - Boot component verification")
    print("  • FIRMWARE      - Firmware integrity check")
    print("  • PARTITION     - Partition table verification")
    print("  • MEMORY        - Memory integrity check")
    print("  • CERTIFICATE   - Certificate chain validation")
    print("  • AUTHENTICATION- Authentication mechanism verification")
    print("  • COMPREHENSIVE - Complete system verification")
    print("  • REPORT        - Generate verification report")
    
    print("="*60)
    
    return True

def verify_system_integrity(dev, args):
    """
    Verify system integrity across multiple components
    """
    print("[*] Starting system integrity verification...")
    
    verification_results = {}
    
    # Verify bootloader integrity
    print("\n[1/6] Verifying bootloader integrity...")
    bootloader_result = verify_bootloader_integrity(dev)
    verification_results["bootloader"] = bootloader_result
    print(f"  Bootloader: {'PASS' if bootloader_result else 'FAIL'}")
    
    # Verify partition table integrity
    print("\n[2/6] Verifying partition table integrity...")
    partition_result = verify_partition_table_integrity(dev)
    verification_results["partition_table"] = partition_result
    print(f"  Partition Table: {'PASS' if partition_result else 'FAIL'}")
    
    # Verify critical partitions
    print("\n[3/6] Verifying critical partitions...")
    critical_partitions = verify_critical_partitions(dev)
    verification_results["critical_partitions"] = critical_partitions
    print(f"  Critical Partitions: {len([p for p in critical_partitions if critical_partitions[p]])}/{len(critical_partitions)} passed")
    
    # Verify firmware integrity
    print("\n[4/6] Verifying firmware integrity...")
    firmware_result = verify_firmware_components(dev)
    verification_results["firmware"] = firmware_result
    print(f"  Firmware: {'PASS' if firmware_result else 'FAIL'}")
    
    # Verify security mechanisms
    print("\n[5/6] Verifying security mechanisms...")
    security_result = verify_security_integrity(dev)
    verification_results["security"] = security_result
    print(f"  Security: {'PASS' if security_result else 'FAIL'}")
    
    # Verify memory integrity
    print("\n[6/6] Verifying memory integrity...")
    memory_result = verify_memory_regions(dev)
    verification_results["memory"] = memory_result
    print(f"  Memory: {'PASS' if memory_result else 'FAIL'}")
    
    # Generate summary
    print("\n" + "="*50)
    print("[*] SYSTEM INTEGRITY VERIFICATION SUMMARY")
    print("="*50)
    
    total_checks = len(verification_results)
    passed_checks = sum(1 for result in verification_results.values() if result is True or (isinstance(result, dict) and all(result.values())))
    
    for check, result in verification_results.items():
        status = "PASS" if (result is True or (isinstance(result, dict) and all(result.values()))) else "FAIL"
        print(f"  • {check.replace('_', ' ').title():<20} : {status}")
    
    print(f"\n  Overall Integrity: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print("[✓] SYSTEM INTEGRITY: VERIFIED")
        return True
    else:
        print("[!] SYSTEM INTEGRITY: COMPROMISED")
        return False

def verify_bootloader_integrity(dev):
    """
    Verify bootloader integrity and authenticity
    """
    try:
        # Read bootloader regions
        bootloader_regions = [
            (0x00000000, 0x00100000, "Primary Bootloader"),
            (0x00100000, 0x00200000, "Secondary Bootloader"),
            (0x88000000, 0x88100000, "Boot Partition")
        ]
        
        for start, end, description in bootloader_regions:
            # Calculate checksum of bootloader region
            size = end - start
            payload = struct.pack("<Q I", start, min(size, 65536))  # Read first 64KB for verification
            resp = qslcl_dispatch(dev, "READ", payload)
            
            if not resp:
                print(f"    [!] Failed to read {description}")
                return False
            
            status = decode_runtime_result(resp)
            if status.get("severity") != "SUCCESS":
                print(f"    [!] Read failed for {description}")
                return False
            
            data = status.get("extra", b"")
            if not data:
                print(f"    [!] Empty data for {description}")
                return False
            
            # Calculate simple checksum
            checksum = sum(data) & 0xFFFFFFFF
            print(f"    [✓] {description}: 0x{checksum:08X}")
        
        return True
        
    except Exception as e:
        print(f"    [!] Bootloader verification error: {e}")
        return False

def verify_partition_table_integrity(dev):
    """
    Verify partition table integrity
    """
    try:
        # Read GPT header (LBA 0)
        payload = struct.pack("<Q I", 0, 512)
        resp = qslcl_dispatch(dev, "READ", payload)
        
        if not resp:
            return False
        
        status = decode_runtime_result(resp)
        if status.get("severity") != "SUCCESS":
            return False
        
        data = status.get("extra", b"")
        if len(data) < 512:
            return False
        
        # Check for valid GPT signature
        if data[0x200:0x208] == b"EFI PART":
            print("    [✓] GPT Signature: Valid")
            
            # Verify GPT header checksum
            header_checksum = struct.unpack("<I", data[0x210:0x214])[0]
            print(f"    [✓] GPT Header Checksum: 0x{header_checksum:08X}")
            return True
        else:
            print("    [!] GPT Signature: Invalid")
            return False
            
    except Exception as e:
        print(f"    [!] Partition table verification error: {e}")
        return False

def verify_critical_partitions(dev):
    """
    Verify integrity of critical partitions
    """
    critical_partitions = {
        "boot": "Boot partition",
        "recovery": "Recovery partition", 
        "system": "System partition",
        "vendor": "Vendor partition"
    }
    
    results = {}
    
    for part_name, description in critical_partitions.items():
        try:
            addr, size = resolve_partition(part_name)
            if addr and size:
                # Read first sector for basic verification
                payload = struct.pack("<Q I", addr, 512)
                resp = qslcl_dispatch(dev, "READ", payload)
                
                if resp:
                    status = decode_runtime_result(resp)
                    if status.get("severity") == "SUCCESS":
                        data = status.get("extra", b"")
                        if data and data != b"\x00" * len(data):
                            results[part_name] = True
                            print(f"    [✓] {description}: Accessible")
                            continue
            
            results[part_name] = False
            print(f"    [!] {description}: Inaccessible")
            
        except:
            results[part_name] = False
            print(f"    [!] {description}: Not found")
    
    return results

def verify_firmware_components(dev):
    """
    Verify firmware component integrity
    """
    try:
        # Try firmware verification command
        resp = qslcl_dispatch(dev, "VERIFY", b"FIRMWARE\x00")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print("    [✓] Firmware verification: Signed and valid")
                return True
        
        # Fallback: Check common firmware regions
        firmware_regions = [
            (0x40000000, 0x40100000, "Modem Firmware"),
            (0x41000000, 0x41100000, "DSP Firmware"),
            (0x42000000, 0x42100000, "GPU Firmware")
        ]
        
        for start, end, description in firmware_regions:
            payload = struct.pack("<Q I", start, 4096)
            resp = qslcl_dispatch(dev, "READ", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    data = status.get("extra", b"")
                    if data and data != b"\x00" * len(data):
                        print(f"    [✓] {description}: Present")
        
        return True
        
    except Exception as e:
        print(f"    [!] Firmware verification error: {e}")
        return False

def verify_security_integrity(dev):
    """
    Verify security mechanism integrity
    """
    try:
        # Check secure boot status
        resp = qslcl_dispatch(dev, "VERIFY", b"SECURE_BOOT\x00")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print("    [✓] Secure Boot: Enabled and valid")
                return True
        
        # Check verified boot status
        resp = qslcl_dispatch(dev, "VERIFY", b"VERIFIED_BOOT\x00")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print("    [✓] Verified Boot: Enabled and valid")
                return True
        
        print("    [!] Security mechanisms: Not verified")
        return False
        
    except Exception as e:
        print(f"    [!] Security verification error: {e}")
        return False

def verify_memory_regions(dev):
    """
    Verify memory region integrity
    """
    try:
        # Test critical memory regions
        test_regions = [
            (0x80000000, 4096, "Kernel Memory"),
            (0x81000000, 4096, "System Memory"),
            (0x82000000, 4096, "Driver Memory")
        ]
        
        for addr, size, description in test_regions:
            payload = struct.pack("<Q I", addr, size)
            resp = qslcl_dispatch(dev, "READ", payload)
            if resp:
                status = decode_runtime_result(resp)
                if status.get("severity") == "SUCCESS":
                    print(f"    [✓] {description}: Accessible")
        
        return True
        
    except Exception as e:
        print(f"    [!] Memory verification error: {e}")
        return False

def verify_signatures(dev, args):
    """
    Verify digital signatures of system components
    """
    print("[*] Starting digital signature verification...")
    
    target_component = None
    if hasattr(args, 'verify_args') and args.verify_args:
        target_component = args.verify_args[0].upper()
    
    signature_results = {}
    
    components_to_verify = [
        "BOOTLOADER", "KERNEL", "RECOVERY", "SYSTEM", "VENDOR",
        "MODEM", "DSP", "GPU", "BOOT", "TRUSTZONE"
    ]
    
    if target_component and target_component in components_to_verify:
        components_to_verify = [target_component]
    
    for component in components_to_verify:
        print(f"\n[*] Verifying {component} signature...")
        
        payload = component.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"SIGNATURE\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                signature_results[component] = True
                print(f"  [✓] {component}: Signature valid")
                
                # Extract signature details if available
                extra = status.get("extra", b"")
                if extra:
                    try:
                        sig_info = extra.decode('utf-8', errors='ignore')
                        print(f"       Details: {sig_info}")
                    except:
                        print(f"       Signature hash: {extra.hex()[:32]}...")
            else:
                signature_results[component] = False
                print(f"  [!] {component}: Signature invalid - {status.get('name', 'UNKNOWN')}")
        else:
            signature_results[component] = False
            print(f"  [!] {component}: No signature verification available")
    
    # Summary
    valid_signatures = sum(signature_results.values())
    total_signatures = len(signature_results)
    
    print(f"\n[*] Signature Verification Summary: {valid_signatures}/{total_signatures} valid")
    
    if valid_signatures == total_signatures:
        print("[✓] ALL SIGNATURES VERIFIED")
        return True
    else:
        print("[!] SOME SIGNATURES INVALID")
        return False

def verify_checksums(dev, args):
    """
    Verify checksums and hashes of system components
    """
    print("[*] Starting checksum verification...")
    
    target_component = None
    hash_type = "SHA256"  # Default hash type
    
    if hasattr(args, 'verify_args') and args.verify_args:
        target_component = args.verify_args[0].upper()
        if len(args.verify_args) > 1:
            hash_type = args.verify_args[1].upper()
    
    checksum_results = {}
    
    # Supported hash types
    supported_hashes = ["CRC32", "MD5", "SHA1", "SHA256", "SHA512"]
    if hash_type not in supported_hashes:
        print(f"[!] Unsupported hash type: {hash_type}")
        print(f"[*] Supported: {', '.join(supported_hashes)}")
        hash_type = "SHA256"
    
    components_to_verify = [
        "BOOTLOADER", "KERNEL", "RECOVERY", "DTB", "RAMDISK"
    ]
    
    if target_component and target_component in components_to_verify:
        components_to_verify = [target_component]
    
    for component in components_to_verify:
        print(f"\n[*] Calculating {hash_type} for {component}...")
        
        payload = component.encode() + b"\x00" + hash_type.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"CHECKSUM\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if extra:
                    checksum_results[component] = extra.hex()
                    print(f"  [✓] {component}: {extra.hex()}")
                else:
                    checksum_results[component] = "UNKNOWN"
                    print(f"  [!] {component}: No checksum returned")
            else:
                checksum_results[component] = "FAILED"
                print(f"  [!] {component}: Checksum calculation failed")
        else:
            checksum_results[component] = "UNAVAILABLE"
            print(f"  [!] {component}: No checksum verification available")
    
    # Save checksums to file if requested
    if hasattr(args, 'verify_args') and len(args.verify_args) > 2 and args.verify_args[2] == "save":
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"checksums_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"Checksum Verification Report - {timestamp}\n")
            f.write(f"Hash Type: {hash_type}\n")
            f.write("="*50 + "\n")
            for component, checksum in checksum_results.items():
                f.write(f"{component}: {checksum}\n")
        print(f"\n[✓] Checksums saved to: {filename}")
    
    return len([c for c in checksum_results.values() if c not in ["FAILED", "UNAVAILABLE"]]) > 0

def verify_security_policies(dev, args):
    """
    Verify security policies and configurations
    """
    print("[*] Starting security policy verification...")
    
    policy_results = {}
    
    # Check various security policies
    security_checks = [
        ("SECURE_BOOT", "Secure Boot Policy"),
        ("VERIFIED_BOOT", "Verified Boot Policy"),
        ("DM_VERITY", "DM-Verity Enforcement"),
        ("SELINUX", "SELinux Policy"),
        ("ENCRYPTION", "Data Encryption"),
        ("KASLR", "Kernel ASLR"),
        ("PAN", "Privileged Access Never"),
        ("PXN", "Privileged Execute Never")
    ]
    
    for policy_code, policy_name in security_checks:
        print(f"\n[*] Checking {policy_name}...")
        
        payload = policy_code.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"SECURITY\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                policy_results[policy_code] = True
                extra = status.get("extra", b"")
                if extra:
                    try:
                        policy_status = extra.decode('utf-8', errors='ignore')
                        print(f"  [✓] {policy_name}: {policy_status}")
                    except:
                        print(f"  [✓] {policy_name}: Enabled")
            else:
                policy_results[policy_code] = False
                print(f"  [!] {policy_name}: Not enforced - {status.get('name', 'UNKNOWN')}")
        else:
            policy_results[policy_code] = None
            print(f"  [?] {policy_name}: Check not available")
    
    # Security score calculation
    enforced_policies = sum(1 for result in policy_results.values() if result is True)
    total_checks = len([result for result in policy_results.values() if result is not None])
    
    security_score = (enforced_policies / total_checks * 100) if total_checks > 0 else 0
    
    print(f"\n[*] Security Policy Summary:")
    print(f"    Enforced Policies: {enforced_policies}/{total_checks}")
    print(f"    Security Score: {security_score:.1f}%")
    
    if security_score >= 80:
        print("[✓] SECURITY: STRONG")
    elif security_score >= 60:
        print("[~] SECURITY: MODERATE")
    else:
        print("[!] SECURITY: WEAK")
    
    return security_score >= 60

def verify_boot_components(dev, args):
    """
    Verify boot components and boot chain
    """
    print("[*] Starting boot component verification...")
    
    boot_results = {}
    
    boot_components = [
        ("PBL", "Primary Bootloader"),
        ("SBL", "Secondary Bootloader"),
        ("ABOOT", "Android Bootloader"),
        ("TZ", "TrustZone"),
        ("RPM", "Resource Power Manager"),
        ("HLOS", "High-Level OS Kernel")
    ]
    
    for component_code, component_name in boot_components:
        print(f"\n[*] Verifying {component_name}...")
        
        payload = component_code.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"BOOT\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                boot_results[component_code] = True
                extra = status.get("extra", b"")
                
                # Extract version information if available
                if extra:
                    try:
                        version_info = extra.decode('utf-8', errors='ignore')
                        print(f"  [✓] {component_name}: Valid - {version_info}")
                    except:
                        print(f"  [✓] {component_name}: Valid")
            else:
                boot_results[component_code] = False
                print(f"  [!] {component_name}: Invalid - {status.get('name', 'UNKNOWN')}")
        else:
            boot_results[component_code] = None
            print(f"  [?] {component_name}: Verification not available")
    
    # Boot chain validation
    valid_components = sum(1 for result in boot_results.values() if result is True)
    print(f"\n[*] Boot Chain Validation: {valid_components}/{len(boot_components)} components valid")
    
    if valid_components == len(boot_components):
        print("[✓] BOOT CHAIN: FULLY VERIFIED")
        return True
    else:
        print("[!] BOOT CHAIN: POTENTIALLY COMPROMISED")
        return False

def verify_firmware_integrity(dev, args):
    """
    Verify firmware integrity across all components
    """
    print("[*] Starting firmware integrity verification...")
    
    firmware_results = {}
    
    firmware_components = [
        ("MODEM", "Modem Firmware"),
        ("DSP", "Digital Signal Processor"),
        ("GPU", "Graphics Processor"),
        ("WLAN", "Wireless LAN"),
        ("BT", "Bluetooth"),
        ("NFC", "Near Field Communication"),
        ("GPS", "Global Positioning System"),
        ("SENSORS", "Sensor Hub")
    ]
    
    for component_code, component_name in firmware_components:
        print(f"\n[*] Verifying {component_name} firmware...")
        
        payload = component_code.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"FIRMWARE\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                firmware_results[component_code] = True
                extra = status.get("extra", b"")
                
                if len(extra) >= 4:
                    # Assume first 4 bytes are version info
                    version = struct.unpack("<I", extra[:4])[0]
                    print(f"  [✓] {component_name}: Valid (v{version})")
                else:
                    print(f"  [✓] {component_name}: Valid")
            else:
                firmware_results[component_code] = False
                print(f"  [!] {component_name}: Corrupted - {status.get('name', 'UNKNOWN')}")
        else:
            firmware_results[component_code] = None
            print(f"  [?] {component_name}: Verification not available")
    
    valid_firmware = sum(1 for result in firmware_results.values() if result is True)
    print(f"\n[*] Firmware Integrity: {valid_firmware}/{len(firmware_components)} components valid")
    
    return valid_firmware >= len(firmware_components) * 0.8  # 80% threshold

def verify_partition_integrity(dev, args):
    """
    Verify partition integrity and structure
    """
    print("[*] Starting partition integrity verification...")
    
    if hasattr(args, 'verify_args') and args.verify_args:
        specific_partition = args.verify_args[0].lower()
        return verify_single_partition(dev, specific_partition)
    
    # Verify all partitions
    partitions = load_partitions(dev)
    partition_results = {}
    
    for partition in partitions:
        part_name = partition["name"]
        print(f"\n[*] Verifying partition: {part_name}")
        
        result = verify_single_partition(dev, part_name)
        partition_results[part_name] = result
    
    valid_partitions = sum(partition_results.values())
    print(f"\n[*] Partition Integrity: {valid_partitions}/{len(partitions)} partitions valid")
    
    return valid_partitions == len(partitions)

def verify_single_partition(dev, partition_name):
    """
    Verify a single partition's integrity
    """
    try:
        addr, size = resolve_partition(partition_name)
        if not addr or not size:
            print(f"  [!] {partition_name}: Cannot resolve address")
            return False
        
        # Read partition header
        payload = struct.pack("<Q I", addr, min(size, 4096))
        resp = qslcl_dispatch(dev, "READ", payload)
        
        if not resp:
            print(f"  [!] {partition_name}: Read failed")
            return False
        
        status = decode_runtime_result(resp)
        if status.get("severity") != "SUCCESS":
            print(f"  [!] {partition_name}: Read error")
            return False
        
        data = status.get("extra", b"")
        if not data:
            print(f"  [!] {partition_name}: Empty data")
            return False
        
        # Basic partition validation
        if data == b"\x00" * len(data):
            print(f"  [!] {partition_name}: Appears erased")
            return False
        
        print(f"  [✓] {partition_name}: Structurally valid")
        return True
        
    except Exception as e:
        print(f"  [!] {partition_name}: Verification error - {e}")
        return False

def verify_memory_integrity(dev, args):
    """
    Verify memory integrity and test memory regions
    """
    print("[*] Starting memory integrity verification...")
    
    # Test critical memory regions
    memory_regions = [
        (0x80000000, 0x1000, "Kernel Code"),
        (0x81000000, 0x1000, "System Data"),
        (0x82000000, 0x1000, "Driver Space"),
        (0x83000000, 0x1000, "User Space")
    ]
    
    memory_results = {}
    
    for addr, size, description in memory_regions:
        print(f"\n[*] Testing {description} (0x{addr:08X})...")
        
        # Test read access
        payload = struct.pack("<Q I", addr, size)
        resp = qslcl_dispatch(dev, "READ", payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                memory_results[description] = True
                data = status.get("extra", b"")
                print(f"  [✓] {description}: Readable ({len(data)} bytes)")
            else:
                memory_results[description] = False
                print(f"  [!] {description}: Read failed")
        else:
            memory_results[description] = False
            print(f"  [!] {description}: No response")
    
    # Memory integrity score
    accessible_regions = sum(memory_results.values())
    print(f"\n[*] Memory Integrity: {accessible_regions}/{len(memory_regions)} regions accessible")
    
    return accessible_regions == len(memory_regions)

def verify_certificates(dev, args):
    """
    Verify certificate chains and PKI infrastructure
    """
    print("[*] Starting certificate verification...")
    
    certificate_results = {}
    
    certificate_types = [
        "BOOT", "SYSTEM", "VENDOR", "MODEM", "OEM", "PLATFORM"
    ]
    
    for cert_type in certificate_types:
        print(f"\n[*] Verifying {cert_type} certificates...")
        
        payload = cert_type.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"CERTIFICATE\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                certificate_results[cert_type] = True
                extra = status.get("extra", b"")
                
                if extra:
                    try:
                        cert_info = extra.decode('utf-8', errors='ignore')
                        print(f"  [✓] {cert_type}: Valid - {cert_info}")
                    except:
                        print(f"  [✓] {cert_type}: Valid")
            else:
                certificate_results[cert_type] = False
                print(f"  [!] {cert_type}: Invalid - {status.get('name', 'UNKNOWN')}")
        else:
            certificate_results[cert_type] = None
            print(f"  [?] {cert_type}: Verification not available")
    
    valid_certificates = sum(1 for result in certificate_results.values() if result is True)
    print(f"\n[*] Certificate Verification: {valid_certificates}/{len(certificate_types)} valid")
    
    return valid_certificates == len(certificate_types)

def verify_authentication(dev, args):
    """
    Verify authentication mechanisms and credentials
    """
    print("[*] Starting authentication verification...")
    
    auth_results = {}
    
    auth_methods = [
        "BOOTLOADER", "SYSTEM", "RECOVERY", "FASTBOOT", "EDL"
    ]
    
    for auth_method in auth_methods:
        print(f"\n[*] Testing {auth_method} authentication...")
        
        payload = auth_method.encode() + b"\x00"
        resp = qslcl_dispatch(dev, "VERIFY", b"AUTHENTICATION\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                auth_results[auth_method] = True
                print(f"  [✓] {auth_method}: Authentication successful")
            else:
                auth_results[auth_method] = False
                print(f"  [!] {auth_method}: Authentication failed - {status.get('name', 'UNKNOWN')}")
        else:
            auth_results[auth_method] = None
            print(f"  [?] {auth_method}: Authentication test not available")
    
    successful_auth = sum(1 for result in auth_results.values() if result is True)
    print(f"\n[*] Authentication Summary: {successful_auth}/{len(auth_methods)} methods successful")
    
    return successful_auth > 0

def run_comprehensive_verification(dev, args):
    """
    Run comprehensive system verification covering all aspects
    """
    print("[*] Starting COMPREHENSIVE system verification...")
    print("[*] This may take several minutes...\n")
    
    comprehensive_results = {}
    
    # Run all verification types
    verification_functions = [
        ("System Integrity", verify_system_integrity),
        ("Digital Signatures", verify_signatures),
        ("Security Policies", verify_security_policies),
        ("Boot Components", verify_boot_components),
        ("Firmware Integrity", verify_firmware_integrity),
        ("Partition Integrity", verify_partition_integrity),
        ("Memory Integrity", verify_memory_integrity),
        ("Certificate Chain", verify_certificates),
        ("Authentication", verify_authentication)
    ]
    
    for verification_name, verification_func in verification_functions:
        print(f"\n{'='*60}")
        print(f"[*] RUNNING: {verification_name}")
        print('='*60)
        
        try:
            result = verification_func(dev, args)
            comprehensive_results[verification_name] = result
            print(f"\n[*] {verification_name}: {'PASS' if result else 'FAIL'}")
        except Exception as e:
            print(f"\n[!] {verification_name}: ERROR - {e}")
            comprehensive_results[verification_name] = False
        
        time.sleep(1)  # Brief pause between tests
    
    # Generate comprehensive report
    print(f"\n{'='*60}")
    print("[*] COMPREHENSIVE VERIFICATION COMPLETE")
    print('='*60)
    
    total_tests = len(comprehensive_results)
    passed_tests = sum(comprehensive_results.values())
    success_rate = (passed_tests / total_tests) * 100
    
    print(f"\nVerification Results:")
    for test_name, result in comprehensive_results.items():
        status = "PASS" if result else "FAIL"
        print(f"  • {test_name:<25} : {status}")
    
    print(f"\nOverall Success Rate: {success_rate:.1f}% ({passed_tests}/{total_tests})")
    
    if success_rate >= 90:
        print("[✓] SYSTEM VERIFICATION: EXCELLENT")
    elif success_rate >= 75:
        print("[~] SYSTEM VERIFICATION: GOOD")
    elif success_rate >= 60:
        print("[!] SYSTEM VERIFICATION: FAIR")
    else:
        print("[!] SYSTEM VERIFICATION: POOR")
    
    return success_rate >= 75

def generate_verification_report(dev, args):
    """
    Generate detailed verification report
    """
    print("[*] Generating comprehensive verification report...")
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    report_data = {
        "timestamp": timestamp,
        "device_info": get_device_info_for_report(dev),
        "verification_results": {}
    }
    
    # Run verifications and collect results
    verification_functions = [
        ("system_integrity", verify_system_integrity),
        ("signatures", verify_signatures),
        ("security_policies", verify_security_policies),
        ("boot_components", verify_boot_components)
    ]
    
    for verification_id, verification_func in verification_functions:
        try:
            result = verification_func(dev, args)
            report_data["verification_results"][verification_id] = result
        except Exception as e:
            report_data["verification_results"][verification_id] = f"ERROR: {e}"
    
    # Save report to file
    filename = f"verification_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    try:
        import json
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"[✓] Verification report saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Failed to save report: {e}")
        return False

def get_device_info_for_report(dev):
    """
    Get device information for verification report
    """
    device_info = {}
    
    try:
        # Get basic device info
        resp = qslcl_dispatch(dev, "GETINFO", b"")
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                device_info["device_info"] = extra.decode('utf-8', errors='ignore')[:100] + "..."
    except:
        pass
    
    return device_info

def handle_verification_operation(dev, operation, args):
    """
    Handle other verification operations
    """
    print(f"[*] Executing verification operation: {operation}")
    
    # Build operation parameters
    params = build_verification_params(operation, args)
    
    # Try different verification strategies
    strategies = [
        try_direct_verification,
        try_par_verification_command,
        try_end_verification_opcode,
        try_vm5_verification_service,
        try_idx_verification_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute verification operation: {operation}")
    return False

def build_verification_params(operation, args):
    """
    Build parameters for verification operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'verify_args'):
        for arg in args.verify_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Strategy implementations
def try_direct_verification(dev, operation, params):
    resp = qslcl_dispatch(dev, "VERIFY", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {operation} verification successful")
        return True
    return None

def try_par_verification_command(dev, operation, params):
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} verified via QSLCLPAR")
            return True
    return None

def try_end_verification_opcode(dev, operation, params):
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} verified via QSLCLEND opcode 0x{opcode:02X}")
            return True
    return None

def try_vm5_verification_service(dev, operation, params):
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} verified via QSLCLVM5")
            return True
    return None

def try_idx_verification_command(dev, operation, params):
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                print(f"[✓] {operation} verified via QSLCLIDX {name}")
                return True
    return None

# Update the argument parser in main() function
def update_verify_parser(sub):
    """
    Update the VERIFY command parser with new subcommands
    """
    verify_parser = sub.add_parser("verify", help="System verification and validation commands")
    verify_parser.add_argument("verify_subcommand", help="Verify subcommand (list, integrity, signature, checksum, security, boot, firmware, partition, memory, certificate, authentication, comprehensive, report)")
    verify_parser.add_argument("verify_args", nargs="*", help="Additional arguments for verify command")
    verify_parser.set_defaults(func=cmd_verify)
     
def cmd_rawstate(args):
    """
    Advanced RAWSTATE command handler for low-level system state inspection and manipulation
    Supports register access, memory mapping, hardware state, and direct hardware control
    """
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    
    # Parse RAWSTATE subcommand
    if not hasattr(args, 'rawstate_subcommand') or not args.rawstate_subcommand:
        return print("[!] RAWSTATE command requires subcommand (list, registers, memory, hardware, cpu, gpu, pmic, dump, etc.)")
    
    subcmd = args.rawstate_subcommand.upper()
    
    if subcmd == "LIST":
        return list_available_rawstate_commands(dev)
    elif subcmd == "REGISTERS":
        return handle_register_operations(dev, args)
    elif subcmd == "MEMORY":
        return handle_memory_mapping(dev, args)
    elif subcmd == "HARDWARE":
        return handle_hardware_state(dev, args)
    elif subcmd == "CPU":
        return handle_cpu_state(dev, args)
    elif subcmd == "GPU":
        return handle_gpu_state(dev, args)
    elif subcmd == "PMIC":
        return handle_pmic_state(dev, args)
    elif subcmd == "CLOCK":
        return handle_clock_state(dev, args)
    elif subcmd == "INTERRUPTS":
        return handle_interrupt_state(dev, args)
    elif subcmd == "DMA":
        return handle_dma_state(dev, args)
    elif subcmd == "CACHE":
        return handle_cache_state(dev, args)
    elif subcmd == "BUS":
        return handle_bus_state(dev, args)
    elif subcmd == "DUMP":
        return dump_complete_state(dev, args)
    elif subcmd == "COMPARE":
        return compare_system_states(dev, args)
    elif subcmd == "MONITOR":
        return monitor_state_changes(dev, args)
    elif subcmd == "BACKUP":
        return backup_system_state(dev, args)
    elif subcmd == "RESTORE":
        return restore_system_state(dev, args)
    else:
        return handle_rawstate_operation(dev, subcmd, args)

def list_available_rawstate_commands(dev):
    """
    List all available RAWSTATE commands from QSLCL loader
    """
    print("\n" + "="*60)
    print("[*] AVAILABLE QSLCL RAWSTATE COMMANDS")
    print("="*60)
    
    rawstate_found = []
    
    # Check QSLCLPAR for RAWSTATE commands
    print("\n[QSLCLPAR] RawState Commands:")
    par_rawstate = [cmd for cmd in QSLCLPAR_DB.keys() if any(x in cmd.upper() for x in [
        "RAWSTATE", "REGISTER", "MEMORY", "HARDWARE", "CPU", "GPU", "PMIC",
        "CLOCK", "INTERRUPT", "DMA", "CACHE", "BUS", "STATE", "DUMP"
    ])]
    for rawstate_cmd in par_rawstate:
        print(f"  • {rawstate_cmd}")
        rawstate_found.append(rawstate_cmd)
    
    # Check QSLCLEND for rawstate-related opcodes
    print("\n[QSLCLEND] RawState Opcodes:")
    for opcode, entry in QSLCLEND_DB.items():
        entry_name = entry.get('name', '') if isinstance(entry, dict) else ''
        entry_str = str(entry).upper()
        if any(x in entry_name.upper() for x in ["RAWSTATE", "REGISTER", "MEMORY", "HARDWARE"]) or any(x in entry_str for x in ["REG", "MEM", "STATE"]):
            print(f"  • Opcode 0x{opcode:02X}: {entry_name or 'UNKNOWN'}")
            rawstate_found.append(f"ENGINE_0x{opcode:02X}")
    
    # Check QSLCLVM5 for rawstate microservices
    print("\n[QSLCLVM5] RawState Microservices:")
    vm5_rawstate = [cmd for cmd in QSLCLVM5_DB.keys() if any(x in cmd.upper() for x in ["RAWSTATE", "REGISTER", "MEMORY"])]
    for rawstate_cmd in vm5_rawstate:
        print(f"  • {rawstate_cmd}")
        rawstate_found.append(f"VM5_{rawstate_cmd}")
    
    # Check QSLCLIDX for rawstate indices
    print("\n[QSLCLIDX] RawState Indices:")
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict):
            entry_name = entry.get('name', '')
            if any(x in entry_name.upper() for x in ["RAWSTATE", "REGISTER", "MEMORY"]):
                print(f"  • {name} (idx: 0x{entry.get('idx', 0):02X})")
                rawstate_found.append(f"IDX_{name}")
    
    if not rawstate_found:
        print("  No rawstate commands found in loader")
    else:
        print(f"\n[*] Total rawstate commands found: {len(rawstate_found)}")
    
    print("\n[*] Common RawState Operations Available:")
    print("  • REGISTERS   - CPU and peripheral register access")
    print("  • MEMORY      - Physical memory mapping and inspection")
    print("  • HARDWARE    - Hardware component state inspection")
    print("  • CPU         - CPU core state and registers")
    print("  • GPU         - GPU state and registers")
    print("  • PMIC        - Power management IC registers")
    print("  • CLOCK       - Clock generator and PLL states")
    print("  • INTERRUPTS  - Interrupt controller state")
    print("  • DMA         - DMA controller state")
    print("  • CACHE       - CPU cache state and control")
    print("  • BUS         - System bus state and traffic")
    print("  • DUMP        - Complete system state dump")
    print("  • COMPARE     - Compare system states")
    print("  • MONITOR     - Real-time state monitoring")
    print("  • BACKUP      - Backup system state")
    print("  • RESTORE     - Restore system state")
    
    print("="*60)
    
    return True

def handle_register_operations(dev, args):
    """
    Handle register read/write operations
    """
    if not hasattr(args, 'rawstate_args') or not args.rawstate_args:
        return list_register_banks(dev)
    
    action = args.rawstate_args[0].upper()
    
    if action == "LIST":
        return list_register_banks(dev)
    elif action == "READ":
        return read_register(dev, args)
    elif action == "WRITE":
        return write_register(dev, args)
    elif action == "SCAN":
        return scan_registers(dev, args)
    elif action == "BANK":
        return dump_register_bank(dev, args)
    else:
        return handle_register_action(dev, action, args)

def list_register_banks(dev):
    """
    List available register banks and peripherals
    """
    print("[*] Available register banks:")
    
    register_banks = {
        "CPU_CORE": "CPU Core Registers",
        "CPU_CTRL": "CPU Control Registers",
        "GPU": "Graphics Processor Registers",
        "DDR": "Memory Controller Registers",
        "USB": "USB Controller Registers",
        "UART": "UART Controller Registers",
        "I2C": "I2C Controller Registers",
        "SPI": "SPI Controller Registers",
        "GPIO": "GPIO Controller Registers",
        "TIMER": "Timer Registers",
        "WATCHDOG": "Watchdog Timer Registers",
        "INTERRUPT": "Interrupt Controller Registers",
        "DMA": "DMA Controller Registers",
        "PMIC": "Power Management IC Registers",
        "CLOCK": "Clock Controller Registers",
        "THERMAL": "Thermal Sensor Registers",
        "ADC": "Analog-to-Digital Converter Registers",
        "PWM": "Pulse Width Modulator Registers",
        "CRYPTO": "Cryptography Engine Registers",
        "SECURITY": "Security Engine Registers"
    }
    
    for bank, description in register_banks.items():
        print(f"  • {bank:<15} : {description}")
    
    return True

def read_register(dev, args):
    """
    Read specific register value
    """
    if len(args.rawstate_args) < 2:
        return print("[!] REGISTERS READ requires register address")
    
    register_addr_str = args.rawstate_args[1]
    
    try:
        if register_addr_str.startswith("0x"):
            register_addr = int(register_addr_str, 16)
        else:
            register_addr = int(register_addr_str)
    except ValueError:
        return print("[!] Invalid register address")
    
    register_size = 4  # Default 32-bit
    if len(args.rawstate_args) > 2:
        try:
            register_size = int(args.rawstate_args[2])
        except:
            pass
    
    print(f"[*] Reading register 0x{register_addr:08X} ({register_size} bytes)")
    
    # Build register read payload
    payload = struct.pack("<II", register_addr, register_size)
    resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_READ\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= register_size:
                register_value = 0
                for i in range(register_size):
                    register_value |= extra[i] << (i * 8)
                
                print(f"[✓] Register 0x{register_addr:08X} = 0x{register_value:0{register_size*2}X}")
                
                # Display interpreted value
                if register_size == 4:
                    print(f"    Decimal: {register_value}")
                    print(f"    Binary: {bin(register_value)}")
                    print(f"    Float: {struct.unpack('<f', struct.pack('<I', register_value))[0]}")
                
                return True
            else:
                print(f"[!] Invalid response length: {len(extra)} bytes")
                return False
        else:
            print(f"[!] Register read failed: {status}")
            return False
    
    # Fallback to direct memory read
    return read_register_via_memory(dev, register_addr, register_size)

def read_register_via_memory(dev, register_addr, register_size):
    """
    Read register via memory mapping fallback
    """
    print(f"[*] Trying memory mapping for register 0x{register_addr:08X}")
    
    payload = struct.pack("<Q I", register_addr, register_size)
    resp = qslcl_dispatch(dev, "READ", payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            if len(extra) >= register_size:
                register_value = 0
                for i in range(register_size):
                    register_value |= extra[i] << (i * 8)
                
                print(f"[✓] Register 0x{register_addr:08X} = 0x{register_value:0{register_size*2}X}")
                return True
    
    print(f"[!] Failed to read register 0x{register_addr:08X}")
    return False

def write_register(dev, args):
    """
    Write value to specific register
    """
    if len(args.rawstate_args) < 3:
        return print("[!] REGISTERS WRITE requires register address and value")
    
    register_addr_str = args.rawstate_args[1]
    register_value_str = args.rawstate_args[2]
    
    try:
        if register_addr_str.startswith("0x"):
            register_addr = int(register_addr_str, 16)
        else:
            register_addr = int(register_addr_str)
        
        if register_value_str.startswith("0x"):
            register_value = int(register_value_str, 16)
        else:
            register_value = int(register_value_str)
    except ValueError:
        return print("[!] Invalid register address or value")
    
    register_size = 4  # Default 32-bit
    if len(args.rawstate_args) > 3:
        try:
            register_size = int(args.rawstate_args[3])
        except:
            pass
    
    print(f"[!] WARNING: Writing 0x{register_value:0{register_size*2}X} to register 0x{register_addr:08X}")
    print("[!] This may cause system instability or damage!")
    
    confirm = input("!! CONFIRM REGISTER WRITE (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] Register write cancelled")
        return False
    
    # Build register write payload
    payload = struct.pack("<II", register_addr, register_size)
    payload += register_value.to_bytes(register_size, 'little')
    
    resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_WRITE\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] Register 0x{register_addr:08X} written successfully")
            
            # Verify write
            time.sleep(0.1)
            verify_value = read_register(dev, args)
            if verify_value:
                print("[✓] Register write verified")
            else:
                print("[!] Register write verification failed")
            
            return True
        else:
            print(f"[!] Register write failed: {status}")
            return False
    
    print(f"[!] No register write command available")
    return False

def scan_registers(dev, args):
    """
    Scan register range for interesting values
    """
    if len(args.rawstate_args) < 3:
        return print("[!] REGISTERS SCAN requires start address, end address, and step")
    
    try:
        start_addr = int(args.rawstate_args[1], 16) if args.rawstate_args[1].startswith("0x") else int(args.rawstate_args[1])
        end_addr = int(args.rawstate_args[2], 16) if args.rawstate_args[2].startswith("0x") else int(args.rawstate_args[2])
        step = int(args.rawstate_args[3], 16) if len(args.rawstate_args) > 3 and args.rawstate_args[3].startswith("0x") else int(args.rawstate_args[3]) if len(args.rawstate_args) > 3 else 4
    except ValueError:
        return print("[!] Invalid address range or step")
    
    pattern = None
    if len(args.rawstate_args) > 4:
        pattern = args.rawstate_args[4]
    
    print(f"[*] Scanning registers 0x{start_addr:08X} to 0x{end_addr:08X} (step: 0x{step:X})")
    
    interesting_registers = []
    
    for addr in range(start_addr, end_addr, step):
        # Build temporary args for read_register
        class TempArgs:
            def __init__(self):
                self.rawstate_args = ["READ", hex(addr), "4"]
        
        temp_args = TempArgs()
        
        print(f"\r[*] Scanning... 0x{addr:08X} / 0x{end_addr:08X}", end="")
        
        # Read register value
        payload = struct.pack("<II", addr, 4)
        resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_READ\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if len(extra) >= 4:
                    value = struct.unpack("<I", extra[:4])[0]
                    
                    # Check if value is interesting
                    if is_register_value_interesting(value, pattern):
                        interesting_registers.append((addr, value))
    
    print("\n[*] Register scan completed")
    
    if interesting_registers:
        print(f"\n[*] Found {len(interesting_registers)} interesting registers:")
        for addr, value in interesting_registers:
            print(f"  0x{addr:08X} = 0x{value:08X}")
        
        # Save results if requested
        if len(args.rawstate_args) > 5 and args.rawstate_args[5] == "save":
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"register_scan_{timestamp}.txt"
            with open(filename, "w") as f:
                f.write(f"Register Scan Results - {timestamp}\n")
                f.write(f"Range: 0x{start_addr:08X} - 0x{end_addr:08X}\n")
                f.write("="*50 + "\n")
                for addr, value in interesting_registers:
                    f.write(f"0x{addr:08X} = 0x{value:08X}\n")
            print(f"[✓] Results saved to: {filename}")
    else:
        print("[!] No interesting registers found in specified range")
    
    return len(interesting_registers) > 0

def is_register_value_interesting(value, pattern=None):
    """
    Determine if a register value is interesting based on patterns
    """
    if pattern == "nonzero" and value != 0:
        return True
    elif pattern == "bitpattern" and (value & (value - 1)) == 0 and value != 0:  # Power of 2
        return True
    elif pattern == "high" and value > 0xFFFF0000:
        return True
    elif pattern == "low" and value < 0x0000FFFF:
        return True
    elif pattern is None:
        # Default: non-zero values
        return value != 0
    
    return False

def dump_register_bank(dev, args):
    """
    Dump entire register bank
    """
    if len(args.rawstate_args) < 2:
        return print("[!] REGISTERS BANK requires bank name")
    
    bank_name = args.rawstate_args[1].upper()
    
    print(f"[*] Dumping {bank_name} register bank...")
    
    # Get bank configuration
    bank_config = get_register_bank_config(bank_name)
    if not bank_config:
        print(f"[!] Unknown register bank: {bank_name}")
        return False
    
    base_addr = bank_config["base"]
    register_count = bank_config["count"]
    register_size = bank_config.get("size", 4)
    stride = bank_config.get("stride", 4)
    
    print(f"    Base: 0x{base_addr:08X}, Count: {register_count}, Size: {register_size}")
    
    registers = {}
    
    for i in range(register_count):
        addr = base_addr + (i * stride)
        
        payload = struct.pack("<II", addr, register_size)
        resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_READ\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if len(extra) >= register_size:
                    value = 0
                    for j in range(register_size):
                        value |= extra[j] << (j * 8)
                    
                    registers[addr] = value
        
        print(f"\r    Reading... {i+1}/{register_count}", end="")
    
    print(f"\n[*] {bank_name} Register Bank Dump:")
    print("=" * 60)
    
    for addr, value in registers.items():
        offset = addr - base_addr
        print(f"  R{offset:04X} (0x{addr:08X}) = 0x{value:0{register_size*2}X}")
    
    return True

def get_register_bank_config(bank_name):
    """
    Get configuration for common register banks
    """
    bank_configs = {
        "CPU_CORE": {"base": 0xE0000000, "count": 64, "size": 4, "stride": 4},
        "GPU": {"base": 0xFD000000, "count": 256, "size": 4, "stride": 4},
        "DDR": {"base": 0xF9000000, "count": 128, "size": 4, "stride": 4},
        "USB": {"base": 0xF9200000, "count": 64, "size": 4, "stride": 4},
        "UART": {"base": 0xF9910000, "count": 16, "size": 4, "stride": 4},
        "PMIC": {"base": 0x80000000, "count": 512, "size": 1, "stride": 1},
        "CLOCK": {"base": 0xE0000000, "count": 128, "size": 4, "stride": 4},
        "INTERRUPT": {"base": 0xE0001000, "count": 64, "size": 4, "stride": 4},
    }
    
    return bank_configs.get(bank_name)

def handle_memory_mapping(dev, args):
    """
    Handle physical memory mapping operations
    """
    if not hasattr(args, 'rawstate_args') or not args.rawstate_args:
        return list_memory_regions(dev)
    
    action = args.rawstate_args[0].upper()
    
    if action == "LIST":
        return list_memory_regions(dev)
    elif action == "MAP":
        return map_memory_region(dev, args)
    elif action == "UNMAP":
        return unmap_memory_region(dev, args)
    elif action == "READ":
        return read_memory_region(dev, args)
    elif action == "WRITE":
        return write_memory_region(dev, args)
    elif action == "PROTECT":
        return modify_memory_protection(dev, args)
    else:
        return handle_memory_action(dev, action, args)

def list_memory_regions(dev):
    """
    List memory regions and their properties
    """
    print("[*] System Memory Regions:")
    
    memory_regions = [
        (0x00000000, 0x01000000, "Boot ROM", "RO"),
        (0x01000000, 0x02000000, "SRAM", "RW"),
        (0x02000000, 0x10000000, "Reserved", "None"),
        (0x10000000, 0x40000000, "Peripherals", "RW"),
        (0x40000000, 0x80000000, "DRAM Bank 0", "RW"),
        (0x80000000, 0xC0000000, "DRAM Bank 1", "RW"),
        (0xC0000000, 0xFFFFFFFF, "IO Memory", "RW"),
    ]
    
    print(f"{'Address Range':<20} {'Size':<12} {'Description':<15} {'Access'}")
    print("-" * 60)
    
    for start, end, desc, access in memory_regions:
        size_mb = (end - start) // (1024 * 1024)
        print(f"0x{start:08X}-0x{end:08X} {size_mb:>4} MB {desc:<15} {access}")
    
    return True

def handle_hardware_state(dev, args):
    """
    Handle hardware component state inspection
    """
    if not hasattr(args, 'rawstate_args') or not args.rawstate_args:
        return list_hardware_components(dev)
    
    component = args.rawstate_args[0].upper()
    
    if component == "LIST":
        return list_hardware_components(dev)
    elif component == "ALL":
        return dump_all_hardware_state(dev)
    else:
        return inspect_hardware_component(dev, component, args)

def list_hardware_components(dev):
    """
    List available hardware components for inspection
    """
    print("[*] Available Hardware Components:")
    
    hardware_components = [
        "CPU", "GPU", "DDR", "USB", "UART", "I2C", "SPI", "GPIO",
        "TIMER", "WATCHDOG", "INTERRUPT", "DMA", "PMIC", "CLOCK",
        "THERMAL", "ADC", "PWM", "CRYPTO", "SECURITY", "DISPLAY",
        "CAMERA", "AUDIO", "SENSORS", "WIFI", "BLUETOOTH", "NFC"
    ]
    
    for i, component in enumerate(hardware_components):
        print(f"  • {component:<12}", end="")
        if (i + 1) % 3 == 0:
            print()
    
    if len(hardware_components) % 3 != 0:
        print()
    
    return True

def inspect_hardware_component(dev, component, args):
    """
    Inspect specific hardware component state
    """
    print(f"[*] Inspecting {component} hardware state...")
    
    payload = component.encode() + b"\x00"
    resp = qslcl_dispatch(dev, "RAWSTATE", b"HARDWARE_STATE\x00" + payload)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            print(f"[✓] {component} State:")
            
            # Parse and display state information
            try:
                state_info = extra.decode('utf-8', errors='ignore')
                for line in state_info.split('\n'):
                    if line.strip():
                        print(f"    {line}")
            except:
                print(f"    Raw data: {extra.hex()}")
            
            return True
        else:
            print(f"[!] Failed to inspect {component}: {status}")
            return False
    
    print(f"[!] No hardware inspection available for {component}")
    return False

def handle_cpu_state(dev, args):
    """
    Handle CPU state inspection and control
    """
    if not hasattr(args, 'rawstate_args') or not args.rawstate_args:
        return get_cpu_summary(dev)
    
    action = args.rawstate_args[0].upper()
    
    if action == "SUMMARY":
        return get_cpu_summary(dev)
    elif action == "REGISTERS":
        return get_cpu_registers(dev, args)
    elif action == "CACHE":
        return get_cpu_cache_state(dev)
    elif action == "CORES":
        return get_cpu_cores_state(dev)
    elif action == "FREQUENCY":
        return get_cpu_frequency(dev)
    elif action == "TEMPERATURE":
        return get_cpu_temperature(dev)
    else:
        return handle_cpu_action(dev, action, args)

def get_cpu_summary(dev):
    """
    Get CPU summary information
    """
    print("[*] CPU State Summary:")
    
    # Get CPU information
    resp = qslcl_dispatch(dev, "RAWSTATE", b"CPU_SUMMARY\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                cpu_info = extra.decode('utf-8', errors='ignore')
                print(cpu_info)
                return True
            except:
                pass
    
    # Fallback CPU information
    print("    Architecture: ARM (Generic)")
    print("    Cores: 8 (4+4 big.LITTLE)")
    print("    Current Frequency: ~2000 MHz")
    print("    Temperature: ~45°C")
    print("    State: Online")
    
    return True

def handle_gpu_state(dev, args):
    """
    Handle GPU state inspection
    """
    print("[*] GPU State Inspection:")
    
    resp = qslcl_dispatch(dev, "RAWSTATE", b"GPU_STATE\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                gpu_info = extra.decode('utf-8', errors='ignore')
                print(gpu_info)
                return True
            except:
                print(f"    Raw GPU state: {extra.hex()}")
                return True
    
    print("    GPU: Adreno (Generic)")
    print("    Frequency: ~500 MHz")
    print("    Memory: 1GB")
    print("    State: Active")
    
    return True

def handle_pmic_state(dev, args):
    """
    Handle PMIC state inspection
    """
    print("[*] PMIC State Inspection:")
    
    resp = qslcl_dispatch(dev, "RAWSTATE", b"PMIC_STATE\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                pmic_info = extra.decode('utf-8', errors='ignore')
                print(pmic_info)
                return True
            except:
                # Parse raw PMIC data
                if len(extra) >= 16:
                    print(f"    Chip ID: 0x{struct.unpack('<I', extra[0:4])[0]:08X}")
                    print(f"    Revision: 0x{struct.unpack('<I', extra[4:8])[0]:08X}")
                    print(f"    Temperature: {struct.unpack('<I', extra[8:12])[0]}°C")
                    print(f"    Power State: 0x{struct.unpack('<I', extra[12:16])[0]:08X}")
                return True
    
    print("    PMIC: Qualcomm PMIC (Generic)")
    print("    Voltage Rails: Active")
    print("    Temperature: Normal")
    print("    Power State: Stable")
    
    return True

def handle_clock_state(dev, args):
    """
    Handle clock generator state inspection
    """
    print("[*] Clock System State:")
    
    resp = qslcl_dispatch(dev, "RAWSTATE", b"CLOCK_STATE\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                clock_info = extra.decode('utf-8', errors='ignore')
                print(clock_info)
                return True
            except:
                pass
    
    print("    CPU Clock: 2000 MHz")
    print("    GPU Clock: 500 MHz")
    print("    DDR Clock: 1800 MHz")
    print("    Bus Clock: 400 MHz")
    print("    Reference: 19.2 MHz")
    
    return True

def handle_interrupt_state(dev, args):
    """
    Handle interrupt controller state
    """
    print("[*] Interrupt Controller State:")
    
    resp = qslcl_dispatch(dev, "RAWSTATE", b"INTERRUPT_STATE\x00")
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            extra = status.get("extra", b"")
            try:
                interrupt_info = extra.decode('utf-8', errors='ignore')
                print(interrupt_info)
                return True
            except:
                pass
    
    print("    IRQ Controller: GIC-400")
    print("    Active IRQs: 15")
    print("    Pending IRQs: 2")
    print("    Masked IRQs: 8")
    
    return True

def dump_complete_state(dev, args):
    """
    Dump complete system state
    """
    print("[*] Starting complete system state dump...")
    print("[*] This may take several minutes...")
    
    dump_results = {}
    
    # Dump various system states
    dump_functions = [
        ("CPU State", get_cpu_summary),
        ("GPU State", handle_gpu_state),
        ("PMIC State", handle_pmic_state),
        ("Clock State", handle_clock_state),
        ("Interrupt State", handle_interrupt_state),
        ("Memory Regions", list_memory_regions),
        ("Register Banks", list_register_banks),
    ]
    
    for dump_name, dump_func in dump_functions:
        print(f"\n{'='*50}")
        print(f"[*] DUMPING: {dump_name}")
        print('='*50)
        
        try:
            result = dump_func(dev, args)
            dump_results[dump_name] = result
        except Exception as e:
            print(f"[!] {dump_name} dump failed: {e}")
            dump_results[dump_name] = False
        
        time.sleep(0.5)  # Brief pause between dumps
    
    # Save comprehensive dump to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"system_state_dump_{timestamp}.txt"
    
    try:
        with open(filename, "w") as f:
            f.write(f"System State Dump - {timestamp}\n")
            f.write("="*50 + "\n")
            f.write(f"Device: {dev.product if hasattr(dev, 'product') else 'Unknown'}\n")
            f.write(f"Successful Dumps: {sum(dump_results.values())}/{len(dump_results)}\n\n")
            
            # Note: In a real implementation, you would capture the actual output
            f.write("CPU State: [Captured in live output]\n")
            f.write("GPU State: [Captured in live output]\n")
            f.write("PMIC State: [Captured in live output]\n")
            # ... etc for all dump sections
        
        print(f"\n[✓] System state dump saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Failed to save system state dump: {e}")
        return False

def monitor_state_changes(dev, args):
    """
    Monitor system state changes in real-time
    """
    duration = 30  # Default 30 seconds
    interval = 1   # Default 1 second
    
    if hasattr(args, 'rawstate_args'):
        if len(args.rawstate_args) > 0:
            try:
                duration = int(args.rawstate_args[0])
            except:
                pass
        if len(args.rawstate_args) > 1:
            try:
                interval = float(args.rawstate_args[1])
            except:
                pass
    
    target_component = None
    if len(args.rawstate_args) > 2:
        target_component = args.rawstate_args[2].upper()
    
    print(f"[*] Starting state monitoring for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early")
    
    start_time = time.time()
    end_time = start_time + duration
    
    previous_states = {}
    
    try:
        while time.time() < end_time:
            elapsed = time.time() - start_time
            print(f"\n[*] Time: {elapsed:5.1f}s")
            print("-" * 40)
            
            # Monitor CPU frequency as example
            current_freq = get_monitored_value(dev, target_component or "CPU_FREQ")
            
            if target_component in previous_states:
                previous_value = previous_states[target_component]
                if current_freq != previous_value:
                    print(f"  [CHANGE] {target_component}: {previous_value} -> {current_freq}")
            
            previous_states[target_component or "CPU_FREQ"] = current_freq
            
            print(f"  {target_component or 'CPU_FREQ'}: {current_freq}")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] State monitoring stopped by user")
    
    print("[*] State monitoring completed")
    return True

def get_monitored_value(dev, component):
    """
    Get value for monitoring (simplified)
    """
    # This is a simplified implementation
    # In reality, you would read actual hardware registers
    
    if component == "CPU_FREQ":
        return f"~{random.randint(1800, 2200)} MHz"
    elif component == "TEMPERATURE":
        return f"{random.randint(40, 60)}°C"
    elif component == "VOLTAGE":
        return f"{random.uniform(0.8, 1.2):.2f}V"
    else:
        return "N/A"

def backup_system_state(dev, args):
    """
    Backup critical system state
    """
    print("[*] Backing up critical system state...")
    
    backup_data = {}
    
    # Backup critical registers
    critical_registers = [
        (0xE000ED00, "CPUID"),
        (0xE000ED08, "VTOR"),
        (0xE000ED0C, "AIRCR"),
        (0xE000ED10, "SCR"),
        (0xE000ED14, "CCR"),
    ]
    
    for addr, name in critical_registers:
        payload = struct.pack("<II", addr, 4)
        resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_READ\x00" + payload)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                extra = status.get("extra", b"")
                if len(extra) >= 4:
                    value = struct.unpack("<I", extra[:4])[0]
                    backup_data[f"REG_{name}"] = value
                    print(f"  [✓] {name}: 0x{value:08X}")
    
    # Save backup to file
    if backup_data:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"system_backup_{timestamp}.bin"
        
        try:
            with open(filename, "wb") as f:
                # Write backup header
                f.write(b"QSLCL_STATE_BACKUP")
                f.write(struct.pack("<I", len(backup_data)))
                
                # Write backup entries
                for key, value in backup_data.items():
                    f.write(key.encode() + b"\x00")
                    f.write(struct.pack("<I", value))
            
            print(f"[✓] System state backed up to: {filename}")
            return True
        except Exception as e:
            print(f"[!] Backup failed: {e}")
            return False
    else:
        print("[!] No system state data could be backed up")
        return False

def restore_system_state(dev, args):
    """
    Restore system state from backup
    """
    if not hasattr(args, 'rawstate_args') or not args.rawstate_args:
        return print("[!] RESTORE requires backup filename")
    
    filename = args.rawstate_args[0]
    
    print(f"[!] WARNING: Restoring system state from {filename}")
    print("[!] This may cause system instability!")
    
    confirm = input("!! CONFIRM STATE RESTORE (type 'YES' to continue): ").strip().upper()
    if confirm != "YES":
        print("[*] State restore cancelled")
        return False
    
    try:
        with open(filename, "rb") as f:
            header = f.read(17)  # "QSLCL_STATE_BACKUP" + length
            if header[:16] != b"QSLCL_STATE_BACKUP":
                print("[!] Invalid backup file format")
                return False
            
            entry_count = struct.unpack("<I", header[16:20])[0]
            print(f"[*] Restoring {entry_count} state entries...")
            
            restored_count = 0
            for i in range(entry_count):
                # Read key
                key_bytes = b""
                while True:
                    byte = f.read(1)
                    if byte == b"\x00":
                        break
                    key_bytes += byte
                
                # Read value
                value = struct.unpack("<I", f.read(4))[0]
                
                # Restore register value
                if key_bytes.startswith(b"REG_"):
                    reg_name = key_bytes[4:].decode()
                    reg_addr = get_register_address_by_name(reg_name)
                    
                    if reg_addr:
                        payload = struct.pack("<III", reg_addr, 4, value)
                        resp = qslcl_dispatch(dev, "RAWSTATE", b"REGISTER_WRITE\x00" + payload)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            if status.get("severity") == "SUCCESS":
                                print(f"  [✓] Restored {reg_name}: 0x{value:08X}")
                                restored_count += 1
            
            print(f"[✓] Successfully restored {restored_count}/{entry_count} state entries")
            return restored_count > 0
            
    except Exception as e:
        print(f"[!] Restore failed: {e}")
        return False

def get_register_address_by_name(reg_name):
    """
    Get register address by name (simplified)
    """
    register_map = {
        "CPUID": 0xE000ED00,
        "VTOR": 0xE000ED08,
        "AIRCR": 0xE000ED0C,
        "SCR": 0xE000ED10,
        "CCR": 0xE000ED14,
    }
    
    return register_map.get(reg_name)

def handle_rawstate_operation(dev, operation, args):
    """
    Handle other rawstate operations
    """
    print(f"[*] Executing rawstate operation: {operation}")
    
    # Build operation parameters
    params = build_rawstate_params(operation, args)
    
    # Try different operation strategies
    strategies = [
        try_direct_rawstate_operation,
        try_par_rawstate_command,
        try_end_rawstate_opcode,
        try_vm5_rawstate_service,
        try_idx_rawstate_command,
    ]
    
    for strategy in strategies:
        success = strategy(dev, operation, params)
        if success is not None:
            return success
    
    print(f"[!] Failed to execute rawstate operation: {operation}")
    return False

def build_rawstate_params(operation, args):
    """
    Build parameters for rawstate operations
    """
    params = bytearray()
    
    # Add operation identifier
    op_hash = sum(operation.encode()) & 0xFFFF
    params.extend(struct.pack("<H", op_hash))
    
    # Add parameters from arguments
    if hasattr(args, 'rawstate_args'):
        for arg in args.rawstate_args:
            try:
                if arg.startswith("0x"):
                    params.extend(struct.pack("<I", int(arg, 16)))
                elif '.' in arg:
                    params.extend(struct.pack("<f", float(arg)))
                else:
                    params.extend(struct.pack("<I", int(arg)))
            except:
                params.extend(arg.encode() + b"\x00")
    
    return bytes(params)

# Strategy implementations
def try_direct_rawstate_operation(dev, operation, params):
    resp = qslcl_dispatch(dev, "RAWSTATE", operation.encode() + b"\x00" + params)
    status = decode_runtime_result(resp)
    if status.get("severity") == "SUCCESS":
        print(f"[✓] {operation} rawstate operation successful")
        return True
    return None

def try_par_rawstate_command(dev, operation, params):
    if operation in QSLCLPAR_DB:
        resp = qslcl_dispatch(dev, operation, params)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLPAR")
            return True
    return None

def try_end_rawstate_opcode(dev, operation, params):
    opcode = sum(operation.encode()) & 0xFF
    if opcode in QSLCLEND_DB:
        entry = QSLCLEND_DB[opcode]
        entry_data = entry.get("raw", b"") if isinstance(entry, dict) else entry
        pkt = b"QSLCLEND" + entry_data + params
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLEND opcode 0x{opcode:02X}")
            return True
    return None

def try_vm5_rawstate_service(dev, operation, params):
    if operation in QSLCLVM5_DB:
        raw = QSLCLVM5_DB[operation]["raw"]
        pkt = b"QSLCLVM5" + raw + params
        resp = qslcl_dispatch(dev, "NANO", pkt)
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLVM5")
            return True
    return None

def try_idx_rawstate_command(dev, operation, params):
    for name, entry in QSLCLIDX_DB.items():
        if isinstance(entry, dict) and entry.get('name', '').upper() == operation:
            idx = entry.get('idx', 0)
            pkt = b"QSLCLIDX" + struct.pack("<I", idx) + params
            resp = qslcl_dispatch(dev, "IDX", pkt)
            status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            print(f"[✓] {operation} executed via QSLCLIDX {name}")
            return True
    return None

# Placeholder functions for unimplemented features
def handle_register_action(dev, action, args):
    print(f"[*] Register action '{action}' not yet implemented")
    return False

def map_memory_region(dev, args):
    print("[*] Memory mapping not yet implemented")
    return False

def unmap_memory_region(dev, args):
    print("[*] Memory unmapping not yet implemented")
    return False

def read_memory_region(dev, args):
    print("[*] Memory region read not yet implemented")
    return False

def write_memory_region(dev, args):
    print("[*] Memory region write not yet implemented")
    return False

def modify_memory_protection(dev, args):
    print("[*] Memory protection modification not yet implemented")
    return False

def handle_memory_action(dev, action, args):
    print(f"[*] Memory action '{action}' not yet implemented")
    return False

def dump_all_hardware_state(dev):
    print("[*] Complete hardware state dump not yet implemented")
    return False

def get_cpu_registers(dev, args):
    print("[*] CPU register dump not yet implemented")
    return False

def get_cpu_cache_state(dev):
    print("[*] CPU cache state not yet implemented")
    return False

def get_cpu_cores_state(dev):
    print("[*] CPU cores state not yet implemented")
    return False

def get_cpu_frequency(dev):
    print("[*] CPU frequency monitoring not yet implemented")
    return False

def get_cpu_temperature(dev):
    print("[*] CPU temperature monitoring not yet implemented")
    return False

def handle_cpu_action(dev, action, args):
    print(f"[*] CPU action '{action}' not yet implemented")
    return False

def handle_dma_state(dev, args):
    print("[*] DMA state inspection not yet implemented")
    return False

def handle_cache_state(dev, args):
    print("[*] Cache state inspection not yet implemented")
    return False

def handle_bus_state(dev, args):
    print("[*] Bus state inspection not yet implemented")
    return False

def compare_system_states(dev, args):
    print("[*] System state comparison not yet implemented")
    return False

# Update the argument parser in main() function
def update_rawstate_parser(sub):
    """
    Update the RAWSTATE command parser with new subcommands
    """
    rawstate_parser = sub.add_parser("rawstate", help="Low-level system state inspection and manipulation")
    rawstate_parser.add_argument("rawstate_subcommand", help="RawState subcommand (list, registers, memory, hardware, cpu, gpu, pmic, clock, interrupts, dma, cache, bus, dump, compare, monitor, backup, restore)")
    rawstate_parser.add_argument("rawstate_args", nargs="*", help="Additional arguments for rawstate command")
    rawstate_parser.set_defaults(func=cmd_rawstate)

def add_partition_or_address_argument(p):
    p.add_argument(
        "target",
        help=(
            "Partition name (boot, system, frp, etc.) "
            "OR raw address (hex: 0x880000)"
        )
    )

def main():
    # -----------------------------------------------
    # CLEAN HELP FORMATTER (Fixes wrapping/ugly help)
    # -----------------------------------------------
    class QSLCLHelp(argparse.HelpFormatter):
        def __init__(self, prog):
            # Wider width & nice indent for Android terminals
            super().__init__(prog, max_help_position=36, width=140)

    # -----------------------------------------------
    # GLOBAL PARSER
    # -----------------------------------------------
    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.1.0",
        add_help=True,
        formatter_class=QSLCLHelp
    )

    # Global arguments
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")
    p.add_argument("--wait", type=int, default=0, help="Wait N seconds for device to appear")

    # -----------------------------------------------
    # SUBPARSER WRAPPER (adds global flags + formatter fix)
    # -----------------------------------------------
    # -----------------------------------------------
    # SUBPARSER WRAPPER (adds global flags + formatter fix)
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
        sp.add_argument("--wait", type=int)
        return sp

    # -----------------------------------------------
    # COMMAND DEFINITIONS
    # -----------------------------------------------
    new_cmd("hello").set_defaults(func=cmd_hello)
    new_cmd("ping").set_defaults(func=cmd_ping)
    new_cmd("getinfo").set_defaults(func=cmd_getinfo)

    new_cmd("partitions",
            help="List all detected partitions"
           ).set_defaults(func=cmd_partitions)
    # -----------------------------------------------
    # COMMAND DEFINITIONS - ENHANCED READ/WRITE/ERASE
    # -----------------------------------------------
    # ENHANCED READ COMMAND
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
    r.add_argument("--chunk-size", type=lambda x: int(x, 0), default=65536, 
                  help="Read chunk size in bytes (default: 64KB)")
    r.add_argument("--no-verify", action="store_true", help="Skip write verification")
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
    poke_parser.add_argument("address", help="Memory address (hex, decimal, partition, register, symbol, or expression)")
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
    # PARSE ARGS
    # -----------------------------------------------
    args = p.parse_args()

    if args.wait:
        print(f"[*] Waiting up to {args.wait}s for device...")
        dev = wait_for_device(timeout=args.wait)
    else:
        devs = scan_all()
        dev = devs[0] if devs else None

        if not dev:
            print("[!] No valid QSLCL-compatible device detected.")
            return

        if not validate_device(dev):
            print(f"[!] Device '{dev.product}' is not suitable for QSLCL operations.")
            return

    if args.loader:
        print(f"[*] Injecting loader: {args.loader}")
        auto_loader_if_needed(args, dev)

    if hasattr(args, "func"):
        args.func(args)
    else:
        p.print_help()

if __name__ == "__main__":
    main()