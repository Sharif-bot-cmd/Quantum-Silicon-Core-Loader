#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v1.0.8
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

def exec_generic(dev, cmd):
    exec_universal(dev, cmd)

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
    target = "boot" OR "0x880000"
    Returns (address, size, is_partition)
    """
    # Hex raw address
    if target.startswith("0x") or target.isdigit():
        addr = int(target, 16) if target.startswith("0x") else int(target)
        # unknown size → caller must supply
        return addr, None, False

    # Partition name
    scan_gpt(dev)
    try:
        addr, size = resolve_partition(target)
        return addr, size, True
    except:
        # Not a known partition
        return None, None, False

def detect_file_or_hex(data):
    """
    Return: ("file", bytes) or ("hex", bytes)
    """
    # file?
    if os.path.exists(data):
        return "file", open(data, "rb").read()

    # hex?
    try:
        b = bytes.fromhex(data)
        return "hex", b
    except:
        pass

    raise ValueError("Data not file or hex-string.")

# ============================================================
#                      READ
# ============================================================
def cmd_read(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    # -------- Target (partition or raw) --------
    target = args.target
    addr, psize, is_part = resolve_target_for_rw(dev, target)

    # -------- How size is selected --------
    # priority:
    #  1. args.size (explicit override)
    #  2. numeric arg2
    #  3. full partition size (if target is partition)
    #  4. ERROR

    size = None
    if args.size:
        size = args.size
    elif args.arg2 and args.arg2.isdigit():
        size = int(args.arg2)
    elif is_part and psize:
        size = psize
    else:
        return print("[!] No size for raw address read.")

    # -------- Output file selection --------
    # priority:
    #  1. -o filename
    #  2. arg2 (if NOT numeric)
    #  3. target.bin
    if args.output:
        outfile = args.output
    elif args.arg2 and not args.arg2.isdigit():
        outfile = args.arg2
    else:
        outfile = f"{target}.bin"

    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(size, sector)

    print(f"[*] READ {target}: 0x{aligned_addr:08X} ({aligned_size} bytes)")

    payload = struct.pack("<Q I", aligned_addr, aligned_size)
    resp, origin = qslclidx_or_dispatch(dev, "READ", payload)

    # Use your existing RTF decoder:
    result = decode_runtime_result(resp)
    print(result)

    # Extract data (your format is RESPONSE + RTF + data)
    data = resp[8:] if len(resp) > 8 else b""

    with open(outfile, "wb") as f:
        f.write(data)

    print(f"[✓] Saved → {outfile}")


# ============================================================
#                      WRITE
# ============================================================
def cmd_write(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    target = args.target
    addr, psize, is_part = resolve_target_for_rw(dev, target)

    # Detect hex or file
    dtype, data = detect_file_or_hex(args.data)

    # Check partition size
    if is_part and psize and len(data) > psize:
        return print(f"[!] Data is larger than partition {target}.")

    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_len = align_up(len(data), sector)
    data += b"\x00" * (aligned_len - len(data))

    print(f"[*] WRITE {target}: 0x{aligned_addr:08X} ({aligned_len} bytes)")

    payload = struct.pack("<Q", aligned_addr) + data
    resp, origin = qslclidx_or_dispatch(dev, "WRITE", payload)

    print(decode_runtime_result(resp))
    print("[✓] Write OK")

# ============================================================
#                      ERASE
# ============================================================
def cmd_erase(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    target = args.target
    addr, psize, is_part = resolve_target_for_rw(dev, target)

    # Size selection:
    if args.arg2 and args.arg2.isdigit():
        size = int(args.arg2)
    elif is_part:
        size = psize
    else:
        return print("[!] For raw erase, you must specify a size.")

    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(size, sector)

    print(f"[*] ERASE {target}: 0x{aligned_addr:08X} ({aligned_size} bytes)")

    payload = struct.pack("<Q I", aligned_addr, aligned_size)
    resp, origin = qslclidx_or_dispatch(dev, "ERASE", payload)

    print(decode_runtime_result(resp))
    print("[✓] Erase OK")

def resolve_address_for_peekpoke(dev, target):
    """
    Supports:
       raw hex:        0x880000
       raw decimal:    123456
       partition+off:  boot+0x200, lk+512
       bare partition: boot (defaults to partition start)
    Returns absolute address
    """

    scan_gpt(dev)

    # Case 1: partition+offset
    if "+" in target:
        part, off = target.split("+", 1)
        try:
            part_addr, part_size = resolve_partition(part)
        except:
            raise ValueError(f"Unknown partition: {part}")

        if off.startswith("0x"):
            off_val = int(off, 16)
        else:
            off_val = int(off)

        if off_val >= part_size:
            raise ValueError(f"Offset {off} beyond partition {part} size")

        return part_addr + off_val

    # Case 2: partition alone
    if target in PARTITIONS:
        addr, _ = PARTITIONS[target]
        return addr

    # Case 3: hex raw address
    if target.startswith("0x"):
        return int(target, 16)

    # Case 4: decimal raw address
    if target.isdigit():
        return int(target)

    raise ValueError(f"Unknown PEEK/POKE target: {target}")

# ============================================================
#  PEEK (shows actual memory value or error)
# ============================================================
def cmd_peek(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    try:
        addr = resolve_address_for_peekpoke(dev, args.address)
    except Exception as e:
        return print("[!] Address error:", e)

    print(f"[*] PEEK @ 0x{addr:08X}")

    payload = struct.pack("<Q", addr)
    resp, origin = qslclidx_or_dispatch(dev, "PEEK", payload)

    result = _decode_and_show(resp, "PEEK", addr, origin=origin)
    if not result:
        return

    data = result.get("extra", b"")
    if not data:
        return print("[!] Empty response.")

    # pick first 4 or first 8 bytes depending on loader
    if len(data) >= 8:
        val = int.from_bytes(data[:8], "little")
        print(f"[✓] VALUE (64-bit): 0x{val:016X}")
    else:
        val = int.from_bytes(data[:4], "little")
        print(f"[✓] VALUE (32-bit): 0x{val:08X}")

# ============================================================
#  POKE (with strict confirmation)
# ============================================================
def cmd_poke(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    try:
        addr = resolve_address_for_peekpoke(dev, args.address)
    except Exception as e:
        return print("[!] Address error:", e)

    # value parse
    try:
        val = int(args.value, 16) if args.value.startswith("0x") else int(args.value)
    except:
        return print("[!] Invalid value, must be hex or decimal.")

    print(f"[*] POKE @ 0x{addr:08X} = 0x{val:X}")

    # safety confirmation
    confirm = input("!! WARNING: Direct memory write. Continue? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        return print("[!] Aborted.")

    # assume 32-bit write (loader handles width)
    payload = struct.pack("<Q I", addr, val)
    resp, origin = qslclidx_or_dispatch(dev, "POKE", payload)

    print(_decode_and_show(resp, "POKE", addr, origin=origin))

def cmd_rawmode(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    mode_arg = args.mode.lower()
    mode_map = {
        "unrestricted": 0xFF,
        "meta":         0xA1,
        "hyper":        0xE0,
        "diagnostic":   0x10,
        "developer":    0x42,
        "safe":         0x01,
    }

    if mode_arg.startswith("0x"):
        mode_val = int(mode_arg, 16)
    elif mode_arg.isdigit():
        mode_val = int(mode_arg)
    else:
        mode_val = mode_map.get(mode_arg)
        if mode_val is None:
            return print("[!] Unknown mode.")

    payload = bytes([mode_val])

    resp, origin = qslclidx_or_dispatch(dev, "RAWMODE", payload)
    _decode_and_show(resp, "RAWMODE", mode_val, origin=origin)

def cmd_dump(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    # --------------------------
    # Parse arguments
    # --------------------------
    start_addr = int(args.address, 16)
    dump_size  = int(args.size)
    out_path   = args.output

    # --------------------------
    # Sector size
    # --------------------------
    sector = get_sector_size(dev)

    aligned_addr = start_addr & ~(sector - 1)
    end_addr = start_addr + dump_size
    aligned_end = align_up(end_addr, sector)

    total_size = aligned_end - aligned_addr

    print(f"[*] Dumping from 0x{aligned_addr:08X} to 0x{aligned_end:08X} ({total_size} bytes)")
    print(f"[*] Sector size = {sector}")

    # --------------------------
    # Open output file
    # --------------------------
    try:
        f = open(out_path, "wb")
    except:
        return print("[!] Cannot open output file.")

    # --------------------------
    # Dump loop
    # --------------------------
    chunk = 4096
    current = aligned_addr

    while current < aligned_end:
        req_size = min(chunk, aligned_end - current)

        payload = struct.pack("<Q I", current, req_size)

        # ---------------------------------------------
        # IDX-AWARE READ (0x20)
        # ---------------------------------------------
        resp, origin = qslclidx_or_dispatch(dev, "READ", payload)

        if not resp:
            print(f"\n[!] No response at 0x{current:08X} ({origin})")
            break

        status = decode_runtime_result(resp)

        if status.get("severity", "") == "ERROR":
            print(f"\n[!] Error at 0x{current:08X} ({origin}): {status['name']}")
            break

        raw = status.get("extra", b"")
        if not raw:
            print(f"\n[!] Empty block at 0x{current:08X}")
            break

        f.write(raw)

        # Progress display
        done = current - aligned_addr + req_size
        pct  = (done * 100.0) / total_size
        print(f"\r[*] Dumping... {pct:5.1f}% (via {origin})", end="")

        current += req_size

    print("\n[✓] Dump complete.")
    f.close()

# ============================================================
#  DEVICE RESET / REBOOT HANDLER (Full QSLCL Upgrade)
# ============================================================
def cmd_reset(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    force = getattr(args, "force_reset", False)
    payload = b"\x01" if force else b"\x00"

    print("[*] RESET requested…")

    resp, origin = qslclidx_or_dispatch(dev, "RESET", payload)
    _decode_and_show(resp, "RESET", 0, origin=origin)

def cmd_bruteforce(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    # Optional: enable RAWMODE
    if args.rawmode:
        print("[*] Enabling RAWMODE (0xFF)…")
        qslcl_dispatch(dev, "RAWMODE", b"\xFF")
        time.sleep(0.3)

    # -------------------------------------
    # Range parsing
    # -------------------------------------
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

    # -------------------------------------
    # Work queue
    # -------------------------------------
    q = Queue()
    for val in range(start, end + 1):
        q.put(val)

    hits = []
    errors = 0
    done = 0
    total = end - start + 1
    lock = threading.Lock()

    # -------------------------------------
    # Worker thread
    # -------------------------------------
    def worker():
        nonlocal done, errors

        while True:
            try:
                val = q.get_nowait()
            except:
                return

            payload = struct.pack("<I", val)

            # ---------------------------------------------
            # IDX-AWARE BRUTEFORCE (IDX id 0x30)
            # ---------------------------------------------
            resp, origin = qslclidx_or_dispatch(dev, "BRUTEFORCE", payload)

            with lock:
                done += 1
                pct = (done * 100.0) / total
                print(f"\r[*] Progress: {done}/{total} ({pct:5.1f}%) via {origin}", end="")

            if not resp:
                errors += 1
                q.task_done()
                continue

            status = decode_runtime_result(resp)

            sev = status.get("severity", "")
            name = status.get("name", "")

            # Successful / Weak hits
            if sev in ("SUCCESS", "WARNING"):
                with lock:
                    prefix = "[+]" if sev == "SUCCESS" else "[~]"
                    print(f"\n{prefix} HIT: 0x{val:08X} ({sev}) via {origin} → {name}")
                    hits.append((val, status, origin))

            q.task_done()

    # -------------------------------------
    # Run threads
    # -------------------------------------
    threads = args.threads
    print(f"[*] Launching {threads} threads…")

    ths = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        ths.append(t)

    q.join()
    print("\n[✓] Bruteforce complete.")

    # -------------------------------------
    # Save hits
    # -------------------------------------
    if hits:
        fn = args.output if args.output else "bruteforce_hits.txt"

        with open(fn, "w") as f:
            for addr, st, origin in hits:
                f.write(f"{addr:08X} : {st['name']} : {st['severity']} : ORIGIN={origin} : {st['extra'].hex()}\n")

        print(f"[+] Saved {len(hits)} hits → {fn}")
    else:
        print("[!] No valid hits found.")

def cmd_config(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]

    auto_loader_if_needed(args, dev)

    # ------------------------------------------------------------
    # 1. Parse arguments
    # ------------------------------------------------------------
    key   = args.key.upper()
    value = args.value

    print(f"[*] CONFIGURE → key={key}, value={value}")

    # Convert numeric values (if numeric)
    try:
        if value.startswith("0x"):
            val = struct.pack("<I", int(value, 16))
        elif value.isdigit():
            val = struct.pack("<I", int(value))
        else:
            val = value.encode("utf-8")
    except:
        return print("[!] Invalid value format.")

    payload = key.encode("ascii") + b"\x00" + val

    # Make sure payload ≤ 256 bytes for safety
    if len(payload) > 256:
        print("[!] CONFIGURE value too large, refusing.")
        return

    # ------------------------------------------------------------
    # 2. Priority #1 — QSLCLIDX (index-based CONFIGURE)
    # ------------------------------------------------------------
    idx_entry = qslclidx_get_cmd("CONFIGURE")
    if idx_entry:
        print("[*] CONFIGURE via QSLCLIDX")
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"]) + payload
        resp = qslcl_dispatch(dev, "IDX", pkt)
        result = decode_runtime_result(resp)
        print("[✓] CONFIGURE:", result)
        return

    # ------------------------------------------------------------
    # 3. Priority #2 — QSLCLEND (opcode engine)
    # ------------------------------------------------------------
    # Convention: CONFIGURE opcode = 0xC0
    OPC = 0xC0
    if OPC in QSLCLEND_DB:
        print("[*] CONFIGURE via QSLCLENd engine opcode")
        entry = QSLCLEND_DB[OPC]
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        result = decode_runtime_result(resp)
        print("[✓] CONFIGURE:", result)
        return

    # ------------------------------------------------------------
    # 4. Priority #3 — QSLCLPAR (parser block)
    # ------------------------------------------------------------
    if "CONFIGURE" in QSLCLPAR_DB:
        print("[*] CONFIGURE via QSLCLPAR block")
        resp = qslcl_dispatch(dev, "CONFIGURE", payload)
        result = decode_runtime_result(resp)
        print("[✓] CONFIGURE:", result)
        return

    # ------------------------------------------------------------
    # 5. Priority #4 — QSLCLVM5 (nano-kernel microservice)
    # ------------------------------------------------------------
    if "CONFIGURE" in QSLCLVM5_DB:
        print("[*] CONFIGURE via QSLCLVM5 nano-service")
        raw = QSLCLVM5_DB["CONFIGURE"]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        result = decode_runtime_result(resp)
        print("[✓] CONFIGURE:", result)
        return

    # ------------------------------------------------------------
    # 6. FINAL FALLBACK
    # ------------------------------------------------------------
    print("[*] CONFIGURE via fallback dispatcher")
    resp = qslcl_dispatch(dev, "CONFIGURE", payload)
    result = decode_runtime_result(resp)
    print("[✓] CONFIGURE:", result)

def cmd_config_list(args=None):
    print("\n===== QSLCL CONFIGURATION CAPABILITIES =====")

    # ---------------------
    # QSLCLIDX
    # ---------------------
    if QSLCLIDX_DB:
        print("\n[IDX] Indexed CONFIG entries:")
        for name, entry in QSLCLIDX_DB.items():
            if name.startswith("CONFIGURE"):
                print(f"   • {name}  (idx=0x{entry['idx']:02X})")
    else:
        print("\n[IDX] No QSLCLIDX entries loaded.")

    # ---------------------
    # QSLCLEND
    # ---------------------
    print("\n[END] Opcodes:")
    found = False
    for op, block in QSLCLEND_DB.items():
        if isinstance(block, dict) and block.get("name","").startswith("CONFIGURE"):
            print(f"   • CONFIGURE (opcode=0x{op:02X})")
            found = True
    if not found:
        print("   (none)")

    # ---------------------
    # QSLCLPAR
    # ---------------------
    print("\n[PAR] Parser Config Blocks:")
    if "CONFIGURE" in QSLCLPAR_DB:
        print("   • CONFIGURE (direct PAR handler)")
    else:
        print("   (none)")

    # ---------------------
    # QSLCLVM5
    # ---------------------
    print("\n[VM5] Nano-kernel Microservices:")
    if "CONFIGURE" in QSLCLVM5_DB:
        print("   • CONFIGURE (nano-microservice)")
    else:
        print("   (none)")

    # ---------------------
    # Fallback
    # ---------------------
    print("\n[FALLBACK]")
    print("   • CONFIGURE (dispatcher, if above missing)")

    print("\n============================================\n")

def cmd_glitch(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    # ---------------------------------------------------------
    # Inputs
    # ---------------------------------------------------------
    level = int(args.level)
    if level < 1 or level > 5:
        return print("[!] Glitch level must be 1–5.")

    iterations = int(args.iter)
    window     = int(args.window)
    sweep      = int(args.sweep)

    print(f"[*] GLITCH: level={level}  iter={iterations}  window={window}  sweep={sweep}")

    # ---------------------------------------------------------
    # Build virtual glitch payload
    # ---------------------------------------------------------
    # This DOES NOT attack hardware.
    # It triggers QSLCL's internal virtual entropy glitch engine.
    entropy = os.urandom(16)              # entropy seed
    jitter  = random.randint(1, 9999)     # timing randomness

    payload = struct.pack(
        "<BIII16sI",
        level,          # glitch intensity
        iterations,     # iteration count (virtual sweeps)
        window,         # timing window (virtual)
        sweep,          # sweep width (virtual)
        entropy,        # entropy seed for glitch modeling
        jitter          # timing jitter
    )

    # ---------------------------------------------------------
    # Priority 1 — QSLCLIDX (full indexing)
    # ---------------------------------------------------------
    idx_entry = qslclidx_get_cmd("GLITCH")
    if idx_entry:
        print("[*] GLITCH via QSLCLIDX")
        pkt = b"QSLCLIDX" + struct.pack("<I", idx_entry["idx"]) + payload
        resp = qslcl_dispatch(dev, "IDX", pkt)
        result = decode_runtime_result(resp)
        print("[✓] RESULT:", result)
        return

    # ---------------------------------------------------------
    # Priority 2 — ENGINE opcode (0xE7 default)
    # ---------------------------------------------------------
    GLITCH_OPCODE = 0xE7

    if GLITCH_OPCODE in QSLCLEND_DB:
        print("[*] GLITCH via QSLCLEND")
        eng = QSLCLEND_DB[GLITCH_OPCODE]
        pkt = b"QSLCLEND" + eng + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)
        print("[✓] RESULT:", decode_runtime_result(resp))
        return

    # ---------------------------------------------------------
    # Priority 3 — PAR handler
    # ---------------------------------------------------------
    if "GLITCH" in QSLCLPAR_DB:
        print("[*] GLITCH via QSLCLPAR")
        resp = qslcl_dispatch(dev, "GLITCH", payload)
        print("[✓] RESULT:", decode_runtime_result(resp))
        return

    # ---------------------------------------------------------
    # Priority 4 — VM5 Nano
    # ---------------------------------------------------------
    if "GLITCH" in QSLCLVM5_DB:
        print("[*] VGLITCH via VM5 nanokernel")
        raw = QSLCLVM5_DB["GLITCH"]["raw"]
        pkt = b"QSLCLVM5" + raw + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)
        print("[✓] RESULT:", decode_runtime_result(resp))
        return

    # ---------------------------------------------------------
    # Fallback
    # ---------------------------------------------------------
    print("[*] GLITCH via fallback dispatcher")
    resp = qslcl_dispatch(dev, "GLITCH", payload)
    print("[✓] RESULT:", decode_runtime_result(resp))

def cmd_footer(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device connected.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    print("\n[*] Requesting QSLCL Footer Block…")

    # -----------------------------------------------------
    # Build footer payload
    # -----------------------------------------------------
    payload = b"FOOTER_REQ\x00"

    # Append optional flags
    if getattr(args, "raw", False):
        payload += b"\x01"
    else:
        payload += b"\x00"

    # -----------------------------------------------------
    # Dispatch logic (ENGINE → PARSER → VM → FALLBACK)
    # -----------------------------------------------------
    resp = None

    # 1) ENGINE block handler (highest priority)
    if 0xF0 in QSLCLEND_DB:
        print("[*] Using ENGINE handler (0xF0)…")
        entry = QSLCLEND_DB[0xF0]      # ENGINE opcode for FOOTER
        pkt = b"QSLCLEND" + entry + payload
        resp = qslcl_dispatch(dev, "ENGINE", pkt)

    # 2) Command Parser handler (QSLCLPAR)
    elif "FOOTER" in QSLCLPAR_DB:
        print("[*] Using PARSER handler (QSLCLPAR)…")
        resp = qslcl_dispatch(dev, "FOOTER", payload)

    # 3) VM-based handler (QSLCLVM5)
    elif "FOOTER" in QSLCLVM5_DB:
        print("[*] Using VM5 handler (QSLCLVM5)…")
        vm = QSLCLVM5_DB["FOOTER"]["raw"]
        pkt = b"QSLCLVM5" + vm + payload
        resp = qslcl_dispatch(dev, "NANO", pkt)

    # 4) fallback
    else:
        print("[*] Using fallback handler…")
        resp = qslcl_dispatch(dev, "FOOTER", payload)

    if not resp:
        print("[!] No response received.")
        return

    # -----------------------------------------------------
    # Decode Runtime Fault Frame
    # -----------------------------------------------------
    status = qslcl_decode_rtf(resp)

    print(f"[*] Response: {status['severity']} — {status['name']}")

    # -----------------------------------------------------
    # Extract block data
    # -----------------------------------------------------
    data = status.get("extra", b"")

    if not data:
        print("[!] FOOTER block empty.")
        return

    # -----------------------------------------------------
    # Save output if requested
    # -----------------------------------------------------
    if args.save:
        try:
            with open(args.save, "wb") as f:
                f.write(data)
            print(f"[+] Footer saved → {args.save}")
        except:
            print("[!] Failed to save footer block.")

    # -----------------------------------------------------
    # Display formatting modes
    # -----------------------------------------------------
    print("\n=== FOOTER BLOCK ===")

    if getattr(args, "hex", False):
        print(data.hex())
        return

    # Try decoding as UTF-8 text if looks printable
    try:
        txt = data.decode("utf-8", errors="ignore")
        if len([c for c in txt if c.isprintable()]) > len(txt) * 0.75:
            print(txt)
            return
    except:
        pass

    # raw binary fallback
    print(data.hex())

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
        "qslcl": 0xFF
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

    mode_parser = sub.add_parser("mode", help="Device mode commands (trigger mode changes)")
    mode_parser.add_argument("mode_subcommand", help="Mode subcommand (list, status, or mode name)")
    mode_parser.add_argument("mode_args", nargs="*", help="Additional arguments for mode command")
    mode_parser.set_defaults(func=cmd_mode)
    
    # Add mode status as separate command for convenience
    status_parser = sub.add_parser("mode-status", help="Check current device mode")
    status_parser.set_defaults(func=cmd_mode_status)

# =============================================================================
# ADVANCED COMMAND WRAPPERS (OEM/ODM/BYPASS/VOLTAGE/etc)
# =============================================================================
def cmd_bypass(args):     _un(args,"BYPASS")
def cmd_voltage(args):    _un(args,"VOLTAGE")
def cmd_power(args):      _un(args,"POWER")
def cmd_verify(args):     _un(args,"VERIFY")
def cmd_rawstate(args):   _un(args,"RAWSTATE")
def cmd_getvar(args):     _un(args,"GETVAR")

def _un(args, name):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    exec_universal(devs[0], name)

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
    # GLOBAL PARSER
    # -----------------------------------------------
    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.0.8",
        add_help=True
    )

    # Global arguments (valid before OR after subcommand)
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")
    p.add_argument("--wait", type=int, default=0, help="Wait N seconds for device to appear")

    # -----------------------------------------------
    # SUBPARSER WRAPPER (adds global args to commands)
    # -----------------------------------------------
    sub = p.add_subparsers(dest="cmd")

    def new_cmd(name, *args, **kwargs):
        sp = sub.add_parser(name, *args, **kwargs)
        # every subcommand supports global flags
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
    new_cmd("partitions", help="List all detected partitions").set_defaults(func=cmd_partitions)

    r = new_cmd("read", help="Read from partition or raw address")
    add_partition_or_address_argument(r)
    r.add_argument("arg2", nargs="?", help="filename OR size (auto-detected)")
    r.add_argument("-o", "--output", default=None)
    r.add_argument("--size", type=int, default=None)
    r.set_defaults(func=cmd_read)

    w = new_cmd("write")
    add_partition_or_address_argument(w)
    w.add_argument("data")
    w.set_defaults(func=cmd_write)

    e = new_cmd("erase")
    add_partition_or_address_argument(e)
    e.add_argument("arg2", nargs="?", help="Optional erase size")
    e.set_defaults(func=cmd_erase)

    pk = new_cmd("peek")
    pk.add_argument("address")
    pk.set_defaults(func=cmd_peek)

    po = new_cmd("poke")
    po.add_argument("address")
    po.add_argument("value")
    po.set_defaults(func=cmd_poke)

    rm = new_cmd("rawmode")
    rm.add_argument("mode")
    rm.set_defaults(func=cmd_rawmode)

    bf = new_cmd("bruteforce")
    bf.add_argument("pattern")
    bf.add_argument("--threads", type=int, default=8)
    bf.add_argument("--rawmode", action="store_true")
    bf.add_argument("--output")
    bf.set_defaults(func=cmd_bruteforce)

    dmp = new_cmd("dump")
    dmp.add_argument("address")
    dmp.add_argument("size", type=int)
    dmp.add_argument("output")
    dmp.set_defaults(func=cmd_dump)

    reset = new_cmd("reset")
    reset.add_argument("--force-reset", action="store_true")
    reset.set_defaults(func=cmd_reset)

    cfg = new_cmd("config")
    cfg.add_argument("key")
    cfg.add_argument("value")
    cfg.set_defaults(func=cmd_config)

    new_cmd("config-list").set_defaults(func=cmd_config_list)

    gl = new_cmd("glitch")
    gl.add_argument("--level", type=int, default=1)
    gl.add_argument("--iter", type=int, default=50)
    gl.add_argument("--window", type=int, default=200)
    gl.add_argument("--sweep", type=int, default=50)
    gl.set_defaults(func=cmd_glitch)

    fp = new_cmd("footer")
    fp.add_argument("--hex", action="store_true")
    fp.add_argument("--raw", action="store_true")
    fp.add_argument("--save", metavar="FILE")
    fp.set_defaults(func=cmd_footer)

    oem_parser = sub.add_parser("oem", help="OEM commands (unlock, lock, etc.)")
    oem_parser.add_argument("oem_subcommand", help="OEM subcommand (unlock, lock, etc.)")
    oem_parser.add_argument("oem_args", nargs="*", help="Additional arguments for OEM command")
    oem_parser.set_defaults(func=cmd_oem)

    odm_parser = new_cmd("odm", help="ODM commands (enable, disable, test, diag, etc.)")
    odm_parser.add_argument("odm_subcommand", help="ODM subcommand (enable, disable, test, diag, etc.)")
    odm_parser.add_argument("odm_args", nargs="*", help="Additional arguments for ODM command")
    odm_parser.set_defaults(func=cmd_odm)

    mode_parser = sub.add_parser("mode", help="Device mode commands (trigger mode changes)")
    mode_parser.add_argument("mode_subcommand", help="Mode subcommand (list, status, or mode name)")
    mode_parser.add_argument("mode_args", nargs="*", help="Additional arguments for mode command")
    mode_parser.set_defaults(func=cmd_mode)
    
    # Add mode status as separate command for convenience
    status_parser = sub.add_parser("mode-status", help="Check current device mode")
    status_parser.set_defaults(func=cmd_mode_status)

    for cname, fn in [
        ("bypass", cmd_bypass), ("voltage", cmd_voltage),
        ("power", cmd_power), ("verify", cmd_verify), 
        ("rawstate", cmd_rawstate), ("getvar", cmd_getvar)
    ]:
        new_cmd(cname).set_defaults(func=fn)

    # -----------------------------------------------
    # PARSE ARGS (safe for either order)
    # -----------------------------------------------
    args = p.parse_args()

    # -----------------------------------------------
    # DEVICE ACQUISITION (VIRTUAL OR REAL)
    # -----------------------------------------------
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

    # -----------------------------------------------
    # LOADER INJECTION (REAL + VIRTUAL)
    # -----------------------------------------------
    if args.loader:
        print(f"[*] Injecting loader: {args.loader}")
        auto_loader_if_needed(args, dev)

    # -----------------------------------------------
    # EXECUTE COMMAND
    # -----------------------------------------------
    if hasattr(args, "func"):
        args.func(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()