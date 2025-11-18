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
    handle: any = None

# =============================================================================
# SCANNERS
# =============================================================================
def scan_serial():
    if not SERIAL_SUPPORT:
        return []
    devs = []
    for p in list_ports.comports():
        devs.append(QSLCLDevice(
            transport="serial",
            identifier=p.device,
            vendor=p.manufacturer or "Unknown",
            product=p.description or "Serial",
            handle=p.device
        ))
    return devs

def scan_usb():
    if not USB_SUPPORT:
        return []
    devs = []
    for d in usb.core.find(find_all=True):
        vid, pid = d.idVendor, d.idProduct
        name = APPLE_DFU_IDS.get((vid, pid), "USB Device")
        devs.append(QSLCLDevice(
            transport="usb",
            identifier=f"bus={d.bus} addr={d.address}",
            vendor=f"VID_{vid:04X}",
            product=name,
            vid=vid,
            pid=pid,
            handle=d
        ))
    return devs

def scan_all():
    return scan_serial() + scan_usb()

def exec_generic(dev, cmd):
    exec_universal(dev, cmd)

# =============================================================================
# QSLCLPAR ENGINE v2 — Fully Correct, Auto-Repair, Auto-Validate
# =============================================================================
def load_qslclpar(path):
    """Scan qslcl.bin, rebuild QSLCLPAR blocks, validate them, and store
       fully wire-encoded packets ready to send to device.
    """
    global QSLCLPAR_DB
    QSLCLPAR_DB.clear()

    try:
        blob = open(path, "rb").read()
    except:
        print("[!] Cannot read qslcl.bin — QSLCLPAR disabled")
        return

    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLCMD", off)
        if idx < 0:
            break

        next_idx = blob.find(b"QSLCLCMD", idx + 1)
        block_end = next_idx if next_idx > 0 else len(blob)

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

        payload_off = struct.unpack("<H", header[30:32])[0]

        if payload_off == 0 or payload_off > len(full_block):
            # auto repair: find the next non-zero region
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

def decode_runtime_result(resp):
    """
    Extract runtime status/error code from response
    and decode using QSLCLRTF DB.
    """
    if not resp:
        return "[!] No response"

    # expected: RESPONSE + code(2) + payload...
    try:
        code = int.from_bytes(resp[0:2], "little")
    except:
        return "[!] Unable to parse runtime code"

    if code in QSLCLRTF_DB:
        entry = QSLCLRTF_DB[code]
        level = entry["level"]
        msg   = entry["msg"]

        level_name = {
            0: "SUCCESS",
            1: "WARNING",
            2: "ERROR",
            3: "CRITICAL",
            4: "FATAL",
        }.get(level, f"LVL{level}")

        return f"[{level_name}] 0x{code:04X} – {msg}"

    # fallback if undefined
    if code == 0:
        return "[SUCCESS] 0x0000 – OK"

    return f"[UNKNOWN] 0x{code:04X}"

# =============================================================================
# TRANSPORTS
# =============================================================================
def send(handle, payload, serial_mode):
    if serial_mode:
        handle.write(payload)
    else:
        try:
            handle.write(1, payload)
        except:
            pass

def recv(handle, serial_mode, timeout=3.0):
    end = time.time() + timeout
    buff = b""

    while time.time() < end:
        try:
            chunk = handle.read(64) if serial_mode else handle.read(1, 64)
        except:
            chunk = b""

        if chunk:
            buff += chunk

            # scan everything in buffer
            i = buff.find(b"QSLCLRESP")
            if i >= 0 and len(buff) >= i + 14:
                size = struct.unpack("<I", buff[i+10:i+14])[0]
                if len(buff) >= i + 14 + size:
                    data = buff[i+14:i+14+size]
                    return "RESP", data

            j = buff.find(b"QSLCLCMD")
            if j >= 0 and len(buff) >= j + 13:
                size = struct.unpack("<I", buff[j+9:j+13])[0]
                if len(buff) >= j + 13 + size:
                    data = buff[j+13:j+13+size]
                    return "CMD", data

        time.sleep(0.004)

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

# =============================================================================
# SECTOR SIZE DETECTOR
# =============================================================================
def detect_sector_size(dev):
    """
    Universal sector size detector tuned for your loader:
      1. QSLCLPAR GETSECTOR
      2. GETINFO parsing
      3. HELLO extended runtime
      4. Qualcomm Firehose
      5. MTK BootROM
      6. Apple DFU
      7. Fallback 4096
    """

    h, serial_mode = open_transport(dev)

    # ======================================================
    # 1. QSLCLPAR GETSECTOR (your loader's real handler)
    # ======================================================
    if "GETSECTOR" in QSLCLPAR_DB:
        try:
            resp = qslcl_dispatch(dev, "GETSECTOR", b"")
            if resp:
                status = decode_runtime_result(resp)
                sz = int.from_bytes(status["extra"][:4], "little")
                if sz > 0:
                    print("[*] Sector size via QSLCLPAR/GETSECTOR =", sz)
                    return sz
        except:
            pass

    # ======================================================
    # 2. GETINFO parsing (optional fallback)
    # ======================================================
    try:
        resp = qslcl_dispatch(dev, "GETINFO")
        if resp:
            status = decode_runtime_result(resp)
            extra = status["extra"]

            # UFS/eMMC page sizes often sit around 0x10–0x20
            for offs in (0x10, 0x14, 0x18, 0x1C):
                try:
                    val = int.from_bytes(extra[offs:offs+4], "little")
                    if val in (512, 1024, 2048, 4096, 8192, 16384):
                        print("[*] Sector size via GETINFO =", val)
                        return val
                except:
                    pass
    except:
        pass

    # ======================================================
    # 3. HELLO extended runtime info
    # ======================================================
    try:
        resp = qslcl_dispatch(dev, "HELLO")
        if resp:
            status = decode_runtime_result(resp)
            extra = status["extra"]
            if len(extra) >= 4:
                val = int.from_bytes(extra[:4], "little")
                if val in (512, 1024, 2048, 4096, 8192):
                    print("[*] Sector size via HELLO-RTF =", val)
                    return val
    except:
        pass

    # ======================================================
    # 4. Qualcomm Firehose (flash page size)
    # ======================================================
    dtype = detect_device_type(h)
    if dtype == "QUALCOMM":
        try:
            h.write(b"<data>getstorageinfo</data>")
            ans = h.read(1024)

            import re
            m = re.search(rb"<pagesize>(\d+)</pagesize>", ans)
            if m:
                val = int(m.group(1))
                print("[*] Sector size via Firehose =", val)
                return val
        except:
            pass

    # ======================================================
    # 5. MTK BootROM/NAND
    # ======================================================
    if dtype == "MTK":
        try:
            h.write(b"\x00\x00\xA0\x0AINFO")
            ans = h.read(128)
            import re
            m = re.search(rb"PageSize=(\d+)", ans)
            if m:
                val = int(m.group(1))
                print("[*] Sector size via MTK BootROM =", val)
                return val
        except:
            pass

    # ======================================================
    # 6. Apple DFU fixed block size
    # ======================================================
    if dtype == "APPLE_DFU":
        print("[*] Sector size via Apple DFU = 4096")
        return 4096

    # ======================================================
    # 7. Fallback safe default
    # ======================================================
    print("[!] Using fallback sector size = 4096")
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
    if not args.loader:
        return

    print(f"[*] Loading loader: {args.loader}")

    # --- Read loader once ---
    try:
        data = open(args.loader, "rb").read()
    except:
        print("[!] Loader cannot be read.")
        return

    blob = data  # rename for clarity

    # --- Extract QSLCL engines (PAR, USB, SPT, VM5, etc..) BEFORE sending ---
    try:
        load_qslcleng(blob)
        load_qslclpar(args.loader)   # needs path
        load_qslclrtf(blob)
        load_qslclusb(blob)
        load_qslclspt(blob)
        load_qslclvm5(blob)
        load_qslcldisp(blob)
        load_qslclidx(blob)
    except Exception as e:
        print("[!] Loader parse error:", e)

    # --- Transport open ---
    handle, serial_mode = open_transport(dev)

    # --- Send loader ---
    send_packets(handle, data, serial_mode)

    if serial_mode:
        handle.close()

    print("[+] Loader sent.\n")

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
    packet = build_qslcl_packet(cmd, payload)
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

def load_qslclusb(blob):
    """Scan QSLCLUSB region from qslcl.bin (TX/RX/BULK/CTRL/ENUM/etc)."""
    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLUSB", off)
        if idx < 0:
            break

        # header: MAGIC(8) + ver(1) + flags(1) + count(2) + total_len(4) + reserved(2)
        hdr = blob[idx:idx+18]
        if len(hdr) < 18:
            off = idx + 1
            continue

        count = int.from_bytes(hdr[10:12], "little")

        # routines follow header aligned to 16
        routine_off = (idx + 18 + 15) & ~0xF
        ptr = routine_off

        names = ["TX","RX","BULK","CTRL","INTR","DESC","ENUM","SYNC","VENDOR","FAILSAFE"]

        for i in range(count):
            if i < len(names):
                name = names[i]
            else:
                name = f"EXT{i}"

            # auto-detect routine size = 16 bytes (your routines are fixed)
            routine = blob[ptr:ptr+16]
            QSLCLUSB_DB[name] = routine
            ptr += 16
            found += 1

        off = idx + 1

    print(f"[+] QSLCLUSB routines loaded: {found}")

def load_qslclspt(blob):
    """Load setup packets QSLCLSP4 block (SETUP packet v4)."""
    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLSPT", off)
        if idx < 0:
            break

        # header 16 bytes: MAGIC + count + flags
        hdr = blob[idx:idx+16]
        if len(hdr) < 16:
            off = idx + 1
            continue

        count = hdr[12]

        ptr = idx + 16
        for i in range(count):
            sp = blob[ptr:ptr+8]   # typical SETUP packet = 8 bytes
            QSLCLSP4_DB[f"SETUP{i}"] = sp
            ptr += 8
            found += 1

        off = idx + 1

    print(f"[+] QSLCLSPT setup packets loaded: {found}")

def load_qslclvm5(blob):
    """Load QSLCLVM5 nano-kernel microservices."""
    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLVM5", off)
        if idx < 0:
            break

        hdr = blob[idx:idx+32]
        if len(hdr) < 32:
            off = idx + 1
            continue

        svc_name = hdr[8:24].split(b"\x00")[0].decode(errors="ignore") or f"SVC{found}"
        entry = int.from_bytes(hdr[24:28], "little")
        flags = int.from_bytes(hdr[28:32], "little")

        QSLCLVM5_DB[svc_name.upper()] = {
            "name": svc_name,
            "entry": entry,
            "flags": flags,
            "raw": hdr
        }

        found += 1
        off = idx + 1

    print(f"[+] QSLCLVM5 microservices loaded: {found}")

def load_qslcleng(blob):
    """
    Scan for QSLCLENG blocks.
    Structure:
        MAGIC(8) = 'QSLCLENG'
        ver(1)
        flags(1)
        count(2)
        ... engine entries follow ...
    """
    global QSLCLENG_DB
    QSLCLENG_DB.clear()

    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLENG", off)
        if idx < 0:
            break

        # header: 8-byte magic + 8-byte fields
        hdr = blob[idx:idx+16]

        if len(hdr) < 16:
            off = idx + 1
            continue

        # Extract version, flags, count
        ver   = hdr[8]
        flags = hdr[9]
        count = int.from_bytes(hdr[10:12], "little")

        # Engine entries start at 16
        ptr = idx + 16

        for i in range(count):
            # Each engine entry: opcode(1) + size(1) + payload(size)
            opcode = blob[ptr]
            size   = blob[ptr+1]
            raw    = blob[ptr:ptr+2+size]

            QSLCLENG_DB[opcode] = raw
            ptr += (2 + size)
            found += 1

        off = idx + 1

    print(f"[+] QSLCLENG engine entries loaded: {found}")

def load_qslcldisp(blob):
    """
    Load QSLCLDISP — Dispatcher Table
    Maps command names to dispatch entries.
    """
    global QSLCLDISP_DB
    QSLCLDISP_DB.clear()

    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLDISP", off)
        if idx < 0:
            break

        # Header: MAGIC(10?) or MAGIC(8)
        # Common layout: MAGIC(10) + ver(1) + flags(1) + count(2)
        hdr = blob[idx:idx+16]
        if len(hdr) < 16:
            off = idx + 1
            continue

        ver   = hdr[8]
        flags = hdr[9]
        count = int.from_bytes(hdr[10:12], "little")

        ptr = idx + 16

        for _ in range(count):
            try:
                # 2b cmd_id, 1b opcode, 1b handler_type, 2b size
                cmd_id  = int.from_bytes(blob[ptr:ptr+2],  "little")
                opcode  = blob[ptr+2]
                htype   = blob[ptr+3]
                size    = int.from_bytes(blob[ptr+4:ptr+6], "little")
                raw     = blob[ptr:ptr+6+size]

                # Dispatcher maps using command ID → entry
                QSLCLDISP_DB[cmd_id] = {
                    "cmd_id": cmd_id,
                    "opcode": opcode,
                    "handler_type": htype,
                    "size": size,
                    "raw": raw,
                }

                ptr += (6 + size)
                found += 1

            except:
                break

        off = idx + 1

    print(f"[+] QSLCLDISP dispatcher loaded: {found} entries")

def load_qslclrtf(blob):
    """
    Loads runtime fault handler table (QSLCLRTF).
    Format:
        MAGIC(8) = QSLCLRTF
        ver(1)
        flags(1)
        count(2)
        entries:
            code(2)
            level(1)    # 0=SUCCESS 1=WARNING 2=ERROR 3=CRITICAL ...
            msglen(1)
            msg(msglen bytes)
    """
    global QSLCLRTF_DB
    QSLCLRTF_DB.clear()

    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLRTF", off)
        if idx < 0:
            break

        hdr = blob[idx:idx+12]
        if len(hdr) < 12:
            break

        ver   = hdr[8]
        flags = hdr[9]
        count = int.from_bytes(hdr[10:12], "little")

        ptr = idx + 12
        for _ in range(count):
            try:
                code  = int.from_bytes(blob[ptr:ptr+2], "little")
                level = blob[ptr+2]
                msglen = blob[ptr+3]
                msg = blob[ptr+4:ptr+4+msglen].decode(errors="ignore")

                QSLCLRTF_DB[code] = {
                    "code": code,
                    "level": level,
                    "msg": msg,
                }

                ptr += (4 + msglen)
                found += 1

            except:
                break

        off = idx + 1

    print(f"[+] QSLCLRTF runtime faults loaded: {found}")

def parse_qslclidx_block(blob):
    """
    Parse QSLCLIDX marker block.
    Layout:
       [entry_id:4] [cmd:16] [offset:4] [size:4]
    """
    out = {}
    idx = 0
    while idx + 28 <= len(blob):
        entry_id, = struct.unpack("<I", blob[idx:idx+4])
        cmd = blob[idx+4:idx+20].rstrip(b"\x00").decode(errors="ignore")
        offset, size = struct.unpack("<II", blob[idx+20:idx+28])
        out[entry_id] = {"cmd": cmd, "offset": offset, "size": size}
        idx += 28
    return out

def load_qslclidx(blob):
    global QSLCLIDX_DB
    QSLCLIDX_DB = parse_qslclidx_block(blob)
    print(f"[*] QSLCLIDX loaded ({len(QSLCLIDX_DB)} entries)")

def qslclidx_get(idx_id):
    """Return IDX entry struct or None."""
    return QSLCLIDX_DB.get(idx_id)

# ============================================================
#   QSLCLHDR — Certificate / Header Table Loader
# ============================================================
def parse_qslclhdr_block(blob):
    """
    Parses QSLCLHDR/QSLCCERT blocks.
    Format:
      magic(8) version(4) size(4) digest(16) payload(...)
    """
    out = {}
    if len(blob) < 32:
        return out

    magic = blob[:8]
    ver, size = struct.unpack("<II", blob[8:16])
    digest = blob[16:32]
    payload = blob[32:32+size]

    out[magic.decode(errors='ignore')] = payload
    return out

def load_qslclhdr(blob):
    global QSLCLHDR_DB
    QSLCLHDR_DB.update(parse_qslclhdr_block(blob))
    print(f"[*] QSLCLHDR loaded ({len(QSLCLHDR_DB)}) blocks")

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
#  READ (with real data preview)
# ============================================================
def cmd_read(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)
    scan_gpt(dev)  # load partitions

    part = args.partition
    out  = args.output

    addr, size = resolve_partition(part)
    sector = get_sector_size(dev)

    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(size, sector)

    print(f"[*] READ {part}: 0x{aligned_addr:08X} ({aligned_size} bytes)")

    payload = struct.pack("<Q I", aligned_addr, aligned_size)
    resp, origin = qslclidx_or_dispatch(dev, "READ", payload)

    data = resp[8+0:]  # RTF decode recommended
    open(out, "wb").write(data)
    print(f"[✓] Saved → {out}")


# ============================================================
#  WRITE (with safety + verify optional)
# ============================================================
def cmd_write(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)
    scan_gpt(dev)

    part = args.partition
    path = args.input

    addr, psize = resolve_partition(part)
    data = open(path, "rb").read()

    if len(data) > psize:
        return print("[!] Data larger than partition.")

    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_len  = align_up(len(data), sector)
    data += b"\x00" * (aligned_len - len(data))

    print(f"[*] WRITE {part}: 0x{aligned_addr:08X} ({aligned_len} bytes)")

    payload = struct.pack("<Q", aligned_addr) + data
    resp, origin = qslclidx_or_dispatch(dev, "WRITE", payload)

    print("[✓] Write OK")

# ============================================================
#  ERASE (with range protection)
# ============================================================
def cmd_erase(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)
    scan_gpt(dev)

    part = args.partition
    addr, psize = resolve_partition(part)

    sector = get_sector_size(dev)
    aligned_addr = addr & ~(sector - 1)
    aligned_size = align_up(psize, sector)

    print(f"[*] ERASE {part}: 0x{aligned_addr:08X} ({aligned_size} bytes)")

    payload = struct.pack("<Q I", aligned_addr, aligned_size)
    resp, origin = qslclidx_or_dispatch(dev, "ERASE", payload)

    print("[✓] Erase OK")

# ============================================================
#  PEEK (shows actual memory value or error)
# ============================================================
def cmd_peek(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)

    print(f"[*] PEEK @ 0x{addr:08X}")

    payload = struct.pack("<Q", addr)
    resp, origin = qslclidx_or_dispatch(dev, "PEEK", payload)

    result = _decode_and_show(resp, "PEEK", addr, origin=origin)
    if not result:
        return

    data = result["extra"]
    if data:
        print(f"[✓] VALUE: {data[:4].hex()}")
    else:
        print("[!] Empty response.")

# ============================================================
#  POKE (with strict confirmation)
# ============================================================
def cmd_poke(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    val  = int(args.value, 16)

    print(f"[*] POKE @ 0x{addr:08X} = 0x{val:08X}")

    payload = struct.pack("<Q I", addr, val)
    resp, origin = qslclidx_or_dispatch(dev, "POKE", payload)

    _decode_and_show(resp, "POKE", addr, origin=origin)

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

# =============================================================================
# CLI
# =============================================================================
def main():
    # Global parser for options like --loader
    p = argparse.ArgumentParser(
        description="QSLCL Tool v1.0.4",
        add_help=True
    )
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")
    p.add_argument("--auth", action="store_true", help="Authenticate QSLCL loader before executing command")

    # Subcommands
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("hello").set_defaults(func=cmd_hello)
    sub.add_parser("ping").set_defaults(func=cmd_ping)
    sub.add_parser("getinfo").set_defaults(func=cmd_getinfo)
    sub.add_parser("partitions", help="List all detected partitions")

    r = sub.add_parser("read")
    r.add_argument("address")
    r.add_argument("size", type=int)
    r.set_defaults(func=cmd_read)

    w = sub.add_parser("write")
    w.add_argument("address")
    w.add_argument("data")
    w.set_defaults(func=cmd_write)

    e = sub.add_parser("erase")
    e.add_argument("address")
    e.add_argument("size", type=int)
    e.set_defaults(func=cmd_erase)

    pk = sub.add_parser("peek")
    pk.add_argument("address")
    pk.set_defaults(func=cmd_peek)

    po = sub.add_parser("poke")
    po.add_argument("address")
    po.add_argument("value")
    po.set_defaults(func=cmd_poke)

    rm = sub.add_parser("rawmode")
    rm.add_argument("mode", help="Mode name or value (e.g. unrestricted, meta, 0xFF)")
    rm.set_defaults(func=cmd_rawmode)

    bf = sub.add_parser("bruteforce")
    bf.add_argument("pattern", help="Range: 0x00-0xFFFF or single value")
    bf.add_argument("--threads", type=int, default=8, help="Thread count")
    bf.add_argument("--rawmode", action="store_true", help="Enable RAWMODE 0xFF before bruteforce")
    bf.add_argument("--output", help="Save successful offsets to file")
    bf.set_defaults(func=cmd_bruteforce)

    dmp = sub.add_parser("dump")
    dmp.add_argument("address", help="hex address (start)")
    dmp.add_argument("size", type=int, help="dump size in bytes")
    dmp.add_argument("output", help="output filename")
    dmp.set_defaults(func=cmd_dump)

    reset = sub.add_parser("reset")
    reset.add_argument("--force-reset", action="store_true",
                       help="Force hardware reset instead of soft reset")
    reset.set_defaults(func=cmd_reset)

    cfg = sub.add_parser("config", help="Set or modify device configuration key/value")
    cfg.add_argument("key",   help="Configuration key name")
    cfg.add_argument("value", help="Value to assign")
    cfg.set_defaults(func=cmd_config)

    cfglist = sub.add_parser("config-list", help="List all supported CONFIGURE keys/routes")
    cfglist.set_defaults(func=cmd_config_list)

    gl = sub.add_parser("glitch", help="Virtual glitch engine (ChipWhisperer-style)")
    gl.add_argument("--level", type=int, default=1, help="Glitch level (1–5)")
    gl.add_argument("--iter", type=int, default=50, help="Iteration count")
    gl.add_argument("--window", type=int, default=200, help="Glitch timing window")
    gl.add_argument("--sweep", type=int, default=50, help="Sweep width")
    gl.set_defaults(func=cmd_glitch)

    p = sub.add_parser("footer", help="Read QSLCL footer block")
    p.add_argument("--hex", action="store_true", help="Show hex output")
    p.add_argument("--raw", action="store_true", help="Raw mode")
    p.add_argument("--save", metavar="FILE", help="Save footer to file")
    p.set_defaults(func=cmd_footer)

    # Other subcommands
    for cmd_name, cmd_func in [
        ("oem", cmd_oem), ("odm", cmd_odm), ("bypass", cmd_bypass),
        ("voltage", cmd_voltage), ("power", cmd_power), ("verify", cmd_verify),
        ("reboot", cmd_reboot), ("test", cmd_test), ("footer", cmd_footer), ("rawstate", cmd_rawstate), ("mode", cmd_mode), ("getvar", cmd_getvar)
    ]:
        sub.add_parser(cmd_name).set_defaults(func=cmd_func)

    # ------------------------
    # Parse args
    # ------------------------
# Step 1: parse global options first
    args, remaining = p.parse_known_args()

# Step 2: parse subcommand with the same namespace
    if remaining:
        args = p.parse_args(remaining, namespace=args)

# -------------------------------------------------------
# INSERT AUTO-EXECUTION RIGHT HERE
# -------------------------------------------------------
    devs = scan_all()
    if devs:
        dev = devs[0]

        # Load loader if --loader is used
        auto_loader_if_needed(args, dev)

        # Auto-execute USB routines
        for name in QSLCLUSB_DB:
            exec_usb(dev, name)

        # Auto-execute setup packets
        for name in QSLCLSPT_DB:
            exec_spt(dev, name)

        # Auto-execute nano microservices
        for svc in QSLCLVM5_DB:
            exec_nano(dev, svc)

# -------------------------------------------------------
# Execute subcommand (after auto routines)
    if hasattr(args, "func"):
        args.func(args)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
