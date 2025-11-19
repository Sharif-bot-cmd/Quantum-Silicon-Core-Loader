#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v1.0.4
# Author: Sharif — QSLCL Creator

import sys, time, argparse, zlib, struct, threading
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

QSLCLUSB_DB = {}   # name → wire packet
QSLCLSPT_DB = {}   # setup-packet table
QSLCLVM5_DB = {}   # nano-kernel microservices
QSLCLPAR_DB = {}  # cname → encoded wire packet (final version)
QSLCLENG_DB = {}   # opcode → raw engine entry block
QSLCLDISP_DB = {}   # cname → dispatcher entry block
QSLCLRTF_DB = {}   # code → {level, msg, raw}
QSLCLIDX_DB = {}
QSLCLHDR_DB = {}

_DETECTED_SECTOR_SIZE = None
PARTITION_CACHE = []
PARTITIONS = {}

def align_up(x, block):
    return (x + block - 1) & ~(block - 1)

# =============================================================================
# DEVICE STRUCT
# =============================================================================
@dataclass
class QSLCLDevice:
    transport: str
    identifier: str
    vendor: str
    product: str
    vid: int = None
    pid: int = None
    usb_class: int = None
    usb_subclass: int = None
    usb_protocol: int = None
    handle: any = None

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

    # ---------------------------------------------
    # ENGINE PARSER
    # ---------------------------------------------
    def load_qslclend(self, blob):
        out = {}
        magic = b"QSLCLEND"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, ver, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                opcode = blob[pos]
                size = struct.unpack("<H", blob[pos+1:pos+3])[0]
                raw  = blob[pos+3 : pos+3+size]
                out[opcode] = {"opcode": opcode, "raw": raw}
                pos += 3 + size
        except:
            return out

        self.ENG = out
        return out

    # ---------------------------------------------
    # PARSER CONFIG
    # ---------------------------------------------
    def load_qslclpar(self, blob):
        out = {}
        magic = b"QSLCLPAR"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, version, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                name_len = blob[pos]
                name = blob[pos+1 : pos+1+name_len].decode()
                size = struct.unpack("<H", blob[pos+1+name_len : pos+3+name_len])[0]
                raw  = blob[pos+3+name_len : pos+3+name_len+size]
                out[name] = {"name": name, "raw": raw}
                pos += 3 + name_len + size
        except:
            return out

        self.PAR = out
        return out

    # ---------------------------------------------
    # RTF
    # ---------------------------------------------
    def load_qslclrtf(self, blob):
        out = {}
        magic = b"QSLCLRTF"
        off = blob.find(magic)
        if off < 0:
            return out
        
        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                code  = blob[pos]
                lvl   = blob[pos+1]
                msgl  = blob[pos+2]
                msg   = blob[pos+3:pos+3+msgl].decode()
                out[code] = {"level": lvl, "msg": msg}
                pos += 3 + msgl
        except:
            return out

        self.RTF = out
        return out

    # ---------------------------------------------
    # IDX
    # ---------------------------------------------
    def load_qslclidx(self, blob):
        out = {}
        magic = b"QSLCLIDX"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                idx = struct.unpack("<H", blob[pos:pos+2])[0]
                name_len = blob[pos+2]
                name = blob[pos+3:pos+3+name_len].decode()
                out[name] = {"idx": idx, "name": name}
                pos += 3 + name_len
        except:
            return out

        self.IDX = out
        return out

    # ---------------------------------------------
    # VM5
    # ---------------------------------------------
    def load_qslclvm5(self, blob):
        out = {}
        magic = b"QSLCLVM5"
        off = blob.find(magic)
        if off < 0:
            return out
        
        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                name_len = blob[pos]
                name = blob[pos+1 : pos+1+name_len].decode()
                raw_len = struct.unpack("<H", blob[pos+1+name_len : pos+3+name_len])[0]
                raw = blob[pos+3+name_len : pos+3+name_len+raw_len]
                out[name] = {"name": name, "raw": raw}
                pos += 3 + name_len + raw_len
        except:
            return out

        self.VM5 = out
        return out

    # ---------------------------------------------
    # USB routines
    # ---------------------------------------------
    def load_qslclusb(self, blob):
        out = {}
        magic = b"QSLCLUSB"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                name_len = blob[pos]
                name = blob[pos+1 : pos+1+name_len].decode()
                raw_len = struct.unpack("<H", blob[pos+1+name_len : pos+3+name_len])[0]
                raw = blob[pos+3+name_len : pos+3+name_len+raw_len]
                out[name] = {"name": name, "raw": raw}
                pos += 3 + name_len + raw_len
        except:
            return out

        self.USB = out
        return out

    # ---------------------------------------------
    # SPT setup packets
    # ---------------------------------------------
    def load_qslclspt(self, blob):
        out = {}
        magic = b"QSLCLSPT"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                name_len = blob[pos]
                name = blob[pos+1 : pos+1+name_len].decode()
                raw_len = struct.unpack("<H", blob[pos+1+name_len : pos+3+name_len])[0]
                raw = blob[pos+3+name_len : pos+3+name_len+raw_len]
                out[name] = {"name": name, "raw": raw}
                pos += 3 + name_len + raw_len
        except:
            return out

        self.SPT = out
        return out

    # ---------------------------------------------
    # Dispatcher
    # ---------------------------------------------
    def load_qslcldisp(self, blob):
        out = {}
        magic = b"QSLCLDIS"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            hdr = blob[off:off+12]
            _, ver, flags, count = struct.unpack("<8sBBH", hdr)
            pos = off + 12
            for _ in range(count):
                name_len = blob[pos]
                name = blob[pos+1:pos+1+name_len].decode()
                raw_len = struct.unpack("<H", blob[pos+1+name_len:pos+3+name_len])[0]
                raw = blob[pos+3+name_len:pos+3+name_len+raw_len]
                out[name] = {"name": name, "raw": raw}
                pos += 3 + name_len + raw_len
        except:
            return out

        self.DISP = out
        return out

    # ---------------------------------------------
    # Header / Certs
    # ---------------------------------------------
    def load_qslclhdr(self, blob):
        out = {}
        magic = b"QSLCLHDR"
        off = blob.find(magic)
        if off < 0:
            return out

        try:
            magic = blob[off:off+8]
            ver, size = struct.unpack("<II", blob[off+8:off+16])
            digest = blob[off+16:off+32]
            payload = blob[off+32 : off+32+size]
            out[magic.decode(errors='ignore')] = payload
        except:
            return out

        self.HDR = out
        return out

    # ---------------------------------------------
    # MASTER PARSER
    # ---------------------------------------------
    def parse_loader(self, blob):
        self.load_qslcleng(blob)
        self.load_qslclpar(blob)
        self.load_qslclrtf(blob)
        self.load_qslclusb(blob)
        self.load_qslclspt(blob)
        self.load_qslclvm5(blob)
        self.load_qslcldisp(blob)
        self.load_qslclidx(blob)
        self.load_qslclhdr(blob)
        return True

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
# SCANNERS
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
            handle=p.device
        ))

    return devs

def scan_usb():
    if not USB_SUPPORT:
        return []

    devs = []

    try:
        vid, pid = d.idVendor, d.idProduct

        cfg = d.get_active_configuration()
        intf = cfg[(0, 0)]

        usb_class     = intf.bInterfaceClass
        usb_subclass  = intf.bInterfaceSubClass
        usb_protocol  = intf.bInterfaceProtocol

        try:
            product = usb.util.get_string(d, d.iProduct) or "USB Device"
        except:
            product = "USB Device"

        devs.append(QSLCLDevice(
            transport="usb",
            identifier=f"bus={d.bus},addr={d.address}",
            vendor=f"VID_{vid:04X}",
            product=product,
            vid=vid,
            pid=pid,
            usb_class=usb_class,
            usb_subclass=usb_subclass,
            usb_protocol=usb_protocol,
            handle=d
        ))
    except:
        pass

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
# QSLCLPAR ENGINE v2 — Fully Correct, Auto-Repair, Auto-Validate
# =============================================================================
def load_qslclpar(self, blob_or_path):
    """Scan qslcl.bin (either path or in-memory blob), rebuild QSLCLPAR blocks,
       validate them, and store fully wire-encoded packets ready to send.
    """
    global QSLCLPAR_DB
    QSLCLPAR_DB.clear()

    # Accept either bytes blob or filesystem path
    if isinstance(blob_or_path, (bytes, bytearray)):
        blob = bytes(blob_or_path)
    else:
        try:
            with open(blob_or_path, "rb") as f:
                blob = f.read()
        except Exception as e:
            print(f"[!] Cannot read qslcl.bin — QSLCLPAR disabled ({e})")
            return

    off = 0
    found = 0
    L = len(blob)

    while True:
        idx = blob.find(b"QSLCLCMD", off)
        if idx < 0:
            break

        # find next marker or end
        next_idx = blob.find(b"QSLCLCMD", idx + 1)
        block_end = next_idx if next_idx > 0 else L

        full_block = blob[idx:block_end]  # raw internal structure

        # ---------- find QSLCLPAR header ----------
        par_idx = full_block.find(b"QSLCLPAR")
        if par_idx < 0:
            off = idx + 1
            continue

        header = full_block[par_idx:par_idx+64]

        # ---------- validate header ----------
        if len(header) < 64:
            header = header.ljust(64, b"\x00")  # auto-repair short header

        cname = header[12:28].split(b"\x00")[0].decode(errors="ignore").upper()
        if not cname:
            off = idx + 1
            continue

        # Payload offset is a 16-bit little-endian in header at [30:32]
        try:
            payload_off = struct.unpack("<H", header[30:32])[0]
        except:
            payload_off = 64

        if payload_off == 0 or payload_off > len(full_block):
            # auto repair: use 64 as fallback
            payload_off = 64
            header = header[:30] + struct.pack("<H", payload_off) + header[32:]

        # ---------- extract payload safely ----------
        if payload_off < len(full_block):
            payload = full_block[payload_off:]
        else:
            payload = b""

        # ---------- build FINAL wire-encoded packet ----------
        packet = b"QSLCLCMD" + struct.pack("<I", len(full_block)) + full_block

        QSLCLPAR_DB[cname] = packet
        found += 1

        off = idx + 1

    print(f"[+] QSLCLPAR rebuilt & encoded: {found} commands")

def get_par_block(cmd):
    """Return pre-built fully encoded wire packet"""
    return QSLCLPAR_DB.get(cmd.upper(), None)

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
# TRANSPORTS
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
        # EP 1 OUT is typical; device config maps it correctly in open_transport
        handle.write(1, payload, timeout=2000)
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
                chunk = handle.read(1, 64)
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
    if dev.transport == "serial":
        h = serial.Serial(dev.handle, 115200, timeout=1)
        return h, True
    else:
        try:
            dev.handle.set_configuration()
        except:
            pass
        return dev.handle, False

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

def qslcl_dispatch(dev, cmd_name, payload=b""):
    """
    Unified dispatcher:
    If QSLCLDISP has an entry for this command, use it.
    Otherwise fallback to universal routing.
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

    Priority Chain:
      1. QSLCLIDX handler GETSECTOR
      2. QSLCLPAR GETSECTOR
      3. QSLCLENG opcode GETSECTOR
      4. Dispatcher GETVAR("SECTOR_SIZE")
      5. GETINFO structured fields
      6. HELLO RTF frame
      7. Qualcomm Firehose XML
      8. MTK BootROM INFO
      9. Apple DFU fixed (4096)
     10. Safe fallback (4096)
    """

    VALID_SIZES = {512, 1024, 2048, 4096, 8192, 16384}

    h, serial_mode = open_transport(dev)

    # ============================================================
    # 0. QSLCLIDX GETSECTOR override (highest priority)
    # ============================================================
    for entry_id, e in QSLCLIDX_DB.items():
        if e["cmd"] == "GETSECTOR":
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
    # 2. QSLCLENG opcode fallback
    # ============================================================
    if "GETSECTOR" in QSLCLENG_DB:
        try:
            op = QSLCLENG_DB["GETSECTOR"]
            pkt = b"QSLCLENG" + op
            resp = qslcl_dispatch(dev, "ENGINE", pkt)
            status = decode_runtime_result(resp)
            v = int.from_bytes(status["extra"][:4], "little")
            if v in VALID_SIZES:
                print("[*] Sector size via QSLCLENG/GETSECTOR =", v)
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
                handle.write(1, pkt)
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
    if 0xA5 in QSLCLENG_DB:
        print("[*] AUTH via QSLCLENG opcode A5")
        entry = QSLCLENG_DB[0xA5]
        pkt = b"QSLCLENG" + entry + payload
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
    Includes:
      - Safe parsing
      - Marker verification
      - RTF/ENG/PAR/IDX/VM/USB/SPT module loading
      - Transport-safe loader upload
      - Early abort on malformed loader
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
            return

        print("[*] Detected modules:")
        print(f"    QSLCLEND: {len(loader.ENG)} entries")
        print(f"    QSLCLPAR: {len(loader.PAR)} commands")
        print(f"    QSLCLIDX: {len(loader.IDX)} indices")
        print(f"    QSLCLVM5: {len(loader.VM5)} microsvcs")
        print(f"    QSLCLUSB: {len(loader.USB)} blocks")
        print(f"    QSLCLSPT: {len(loader.SPT)} blocks")
        print(f"    QSLCLHDR: {len(loader.HDR)} blocks")
        print()

    except Exception as e:
        print("[!] Loader parsing failed:", e)
        return

    # ============================================================
    # 3. Verify loader contains minimum required segments
    # ============================================================
    required = ["QSLCLPAR", "QSLCLEND", "QSLCLRTF"]
    missing = [r for r in required if eval(f"{r}_DB") == {}]

    if missing:
        print("[!] Loader missing critical modules:", missing)
        print("[!] Aborting loader upload.")
        return

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
        if serial_mode:
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
    if msg.startswith("[SUCCESS]"):
        return f"\033[92m{msg}\033[0m"
    if msg.startswith("[WARNING]"):
        return f"\033[93m{msg}\033[0m"
    if msg.startswith("[ERROR]"):
        return f"\033[91m{msg}\033[0m"
    if msg.startswith("[CRITICAL]") or msg.startswith("[FATAL]"):
        return f"\033[95m{msg}\033[0m"
    return msg

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
    packet = qslcl_build_packet(cmd, payload)
    dev.write(packet)

    try:
        resp = dev.read(timeout=timeout)
    except TimeoutError:
        print(f"[RUNTIME] Timeout waiting for {cmd}")
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

def qslclidx_get_cert(idx):
    """
    IDX → certificate or certificate-related entry.
    We assign:
        0x10 — QSLCCERT
        0x11 — QSLCHMAC
        0x12 — QSLCSHA2
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
        # Standard dispatcher
        resp = qslcl_dispatch(dev, "HELLO", b"")

    if not resp:
        return print("[!] HELLO: No response from device.")

    status = decode_runtime_result(resp)
    print("[*] HELLO Response:", status)

    # ---------------------------------------------------------
    # Display module summary
    # ---------------------------------------------------------
    print("[*] Loader Modules Detected:")
    print(f"  IDX config : { 'CONFIGURE' in QSLCLIDX_DB }")
    print(f"  ENG config : { any(block.get('name','').startswith('CONFIGURE') for block in QSLCLENG_DB.values()) }")
    print(f"  PAR config : {'CONFIGURE' in QSLCLPAR_DB}")
    print(f"  VM5 config : {'CONFIGURE' in QSLCLVM5_DB}")
    print(f"   DISP entries: {len(QSLCLDISP_DB)}")
    print(f"   RTF entries : {len(QSLCLRTF_DB)}")

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
    if "GETINFO" in QSLCLENG_DB:
        entry = QSLCLENG_DB["GETINFO"]["raw"]
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
        4. QSLCLENG
        5. Default raw dispatcher
    """
    # --- 1. QSLCLIDX ---
    for entry_id, e in QSLCLIDX_DB.items():
        if e["cmd"] == cname:
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

    # --- 4. QSLCLENG (Engine handlers)
    if cname in QSLCLENG_DB:
        op = QSLCLENG_DB[cname]
        pkt = b"QSLCLENG" + op + payload
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
    addr, size = resolve_partition(target)
    return addr, size, True


def detect_file_or_hex(data):
    """
    Return: ("file", bytes) or ("hex", bytes)
    """
    import os

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
        part_addr, part_size = resolve_partition(part)

        if off.startswith("0x"):
            off_val = int(off, 16)
        else:
            off_val = int(off)

        if off_val >= part_size:
            raise ValueError(f"Offset {off} beyond partition {part} size")

        return part_addr + off_val

    # Case 2: partition alone
    if target in GPT_CACHE:
        addr, _ = resolve_partition(target)
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
    # 3. Priority #2 — QSLCLENG (opcode engine)
    # ------------------------------------------------------------
    # Convention: CONFIGURE opcode = 0xC0
    OPC = 0xC0
    if OPC in QSLCLENG_DB:
        print("[*] CONFIGURE via QSLCLENG engine opcode")
        entry = QSLCLENG_DB[OPC]
        pkt = b"QSLCLENG" + entry + payload
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
    # QSLCLENG
    # ---------------------
    print("\n[ENG] Engine Opcodes:")
    found = False
    for op, block in QSLCLENG_DB.items():
        if block.get("name","").startswith("CONFIGURE"):
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
    # It triggers QSLCL’s internal virtual entropy glitch engine.
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

    if GLITCH_OPCODE in QSLCLENG_DB:
        print("[*] GLITCH via QSLCLENG")
        eng = QSLCLENG_DB[GLITCH_OPCODE]
        pkt = b"QSLCLENG" + eng + payload
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
    if 0xF0 in QSLCLENG_DB:
        print("[*] Using ENGINE handler (0xF0)…")
        entry = QSLCLENG_DB[0xF0]      # ENGINE opcode for FOOTER
        pkt = b"QSLCLENG" + entry + payload
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

# =============================================================================
# ADVANCED COMMAND WRAPPERS (OEM/ODM/BYPASS/VOLTAGE/etc)
# =============================================================================
def cmd_oem(args):        _un(args,"OEM")
def cmd_odm(args):        _un(args,"ODM")
def cmd_bypass(args):     _un(args,"BYPASS")
def cmd_voltage(args):    _un(args,"VOLTAGE")
def cmd_power(args):      _un(args,"POWER")
def cmd_verify(args):     _un(args,"VERIFY")
def cmd_reboot(args):     _un(args,"REBOOT")
def cmd_test(args):       _un(args,"TEST")
def cmd_rawstate(args):   _un(args,"RAWSTATE")
def cmd_mode(args):       _un(args,"MODE")
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

# =============================================================================
# CLI
# =============================================================================
def main():
    # -----------------------------------------------
    # GLOBAL PARSER
    # -----------------------------------------------
    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.0.5",
        add_help=True
    )

    # Global arguments (valid before OR after subcommand)
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")
    p.add_argument("--wait", type=int, default=0, help="Wait N seconds for device to appear")
    p.add_argument("--virtual", action="store_true", help="Run QSLCL in virtual simulation mode")

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
        sp.add_argument("--virtual", action="store_true")
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

    for cname, fn in [
        ("oem", cmd_oem), ("odm", cmd_odm), ("bypass", cmd_bypass),
        ("voltage", cmd_voltage), ("power", cmd_power),
        ("verify", cmd_verify), ("reboot", cmd_reboot),
        ("test", cmd_test), ("rawstate", cmd_rawstate),
        ("mode", cmd_mode), ("getvar", cmd_getvar)
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
