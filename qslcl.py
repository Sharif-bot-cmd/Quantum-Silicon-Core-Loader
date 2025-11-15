#!/usr/bin/env python3
# qslcl.py — Universal QSLCL Tool v0.9.0 (Mode A — Full QSLCLPAR Engine)
#
# New in v0.9.0:
#   ✓ Full QSLCLPAR parser (extracts blocks from qslcl.bin)
#   ✓ Dynamic command execution using real QSLCLPAR payloads
#   ✓ Security header (48 bytes) + parser header (64 bytes)
#   ✓ Zero text-based CMD for known commands (uses real binaries)
#   ✓ Auto negotiation when loader is present
#   ✓ Backward fallback encoder for old devices
#
# Author: Sharif — QSLCL Creator

import sys, time, argparse, zlib, struct
from dataclasses import dataclass

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

def exec_generic(dev, name, extra=b"", timeout=5.0):
    auto_loader_if_needed(args, dev)
    exec_cmd(dev, name.upper(), extra, timeout)

# =============================================================================
# QSLCLPAR ENGINE v2 — Fully Correct, Auto-Repair, Auto-Validate
# =============================================================================

QSLCLPAR_DB = {}  # cname → encoded wire packet (final version)

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

    # --- Extract QSLCL engines (PAR, USB, SP4, NKS) BEFORE sending ---
    try:
        load_qslclpar(args.loader)   # needs path
        load_qslclusb(blob)
        load_qslclsp4(blob)
        load_qslclnks(blob)
    except Exception as e:
        print("[!] Loader parse error:", e)

    # --- Transport open ---
    handle, serial_mode = open_transport(dev)

    # --- Send loader ---
    send_packets(handle, data, serial_mode)

    if serial_mode:
        handle.close()

    print("[+] Loader sent.\n")

# =============================================================================
# EXECUTION ENGINE
# =============================================================================
def exec_cmd(dev, cmdname, extra=b"", timeout=5.0):
    h, serial_mode = open_transport(dev)

    par = get_par_block(cmdname)

    if par:
        print(f"[*] Sending QSLCLPAR({cmdname})")
        send(h, par, serial_mode)
    else:
        print(f"[*] Sending fallback CMD: {cmdname}")
        send(h, encode_cmd(cmdname, extra), serial_mode)

    # always issue response request
    send(h, encode_resp_request(), serial_mode)

    # ---- improved receiver ----
    tag, payload = recv(h, serial_mode, timeout)

    if serial_mode:
        h.close()

    if tag == "RESP":
        txt = payload.decode(errors="ignore")
        print(f"[+] {cmdname} OK → {txt}")
    elif tag == "CMD":
        # device returned command (rare but valid)
        txt = payload.decode(errors="ignore")
        print(f"[+] {cmdname} OK (CMD-frame) → {txt}")
    else:
        print(f"[!] {cmdname} no response")

QSLCLUSB_DB = {}   # name → wire packet
QSLCLSP4_DB = {}   # setup-packet table
QSLCLNKS_DB = {}   # nano-kernel microservices


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

def load_qslclsp4(blob):
    """Load setup packets QSLCLSP4 block (SETUP packet v4)."""
    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLSP4", off)
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

    print(f"[+] QSLCLSP4 setup packets loaded: {found}")

def load_qslclnks(blob):
    """Load QSLCLNKS nano-kernel microservices."""
    off = 0
    found = 0

    while True:
        idx = blob.find(b"QSLCLNKS", off)
        if idx < 0:
            break

        hdr = blob[idx:idx+32]
        if len(hdr) < 32:
            off = idx + 1
            continue

        svc_name = hdr[8:24].split(b"\x00")[0].decode(errors="ignore") or f"SVC{found}"
        entry = int.from_bytes(hdr[24:28], "little")
        flags = int.from_bytes(hdr[28:32], "little")

        QSLCLNKS_DB[svc_name.upper()] = {
            "name": svc_name,
            "entry": entry,
            "flags": flags,
            "raw": hdr
        }

        found += 1
        off = idx + 1

    print(f"[+] QSLCLNKS microservices loaded: {found}")

# =============================================================================
# COMMAND WRAPPERS
# =============================================================================
def cmd_hello(args):
    devs = scan_all()
    if not devs:
        print("[!] No device.")
        return
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    exec_cmd(dev, "HELLO")


def cmd_ping(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    exec_cmd(dev, "PING")


def cmd_getinfo(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)
    exec_cmd(dev, "GETINFO")


def cmd_peek(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    exec_cmd(dev, "PEEK", f"{addr:X}".encode())


def cmd_poke(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    val = int(args.value, 16)
    exec_cmd(dev, "POKE", f"{addr:X}:{val:X}".encode())


def cmd_read(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    size = args.size
    exec_cmd(dev, "READ", f"{addr:X}:{size}".encode(), timeout=8.0)


def cmd_write(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    data = bytes.fromhex(args.data)
    payload = f"{addr:X}:".encode() + data

    exec_cmd(dev, "WRITE", payload)


def cmd_erase(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    auto_loader_if_needed(args, dev)

    addr = int(args.address, 16)
    size = args.size
    exec_cmd(dev, "ERASE", f"{addr:X}:{size}".encode())

def cmd_rawmode(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")

    dev = devs[0]
    auto_loader_if_needed(args, dev)

    # mode argument normalized
    mode_arg = args.mode.lower()

    # predefined mapping (you can expand this anytime)
    mode_map = {
        "unrestricted": 0xFF,
        "meta": 0xA1,
        "hyper": 0xE0,
        "diagnostic": 0x10,
        "developer": 0x42,
        "safe": 0x01,
    }

    if mode_arg.startswith("0x"):
        # direct hex
        mode_val = int(mode_arg, 16) & 0xFF
    elif mode_arg.isdigit():
        # decimal
        mode_val = int(mode_arg) & 0xFF
    else:
        # dictionary lookup
        mode_val = mode_map.get(mode_arg, None)
        if mode_val is None:
            print("[!] Unknown mode. Use:")
            for k in mode_map:
                print("   -", k)
            return

    # RAWMODE payload = 1-byte selector
    payload = bytes([mode_val])

    print(f"[*] RAWMODE selector = 0x{mode_val:02X} ({mode_arg})")

    exec_cmd(dev, "RAWMODE", payload)

def exec_usb(dev, routine_name):
    r = QSLCLUSB_DB.get(routine_name.upper(), None)
    if not r:
        print("[!] USB routine not found:", routine_name)
        return

    h, serial_mode = open_transport(dev)

    pkt = b"QSLCLUSB" + struct.pack("<H", len(r)) + r
    send(h, pkt, serial_mode)

    tag, payload = recv(h, serial_mode, 3)
    if tag:
        print(f"[+] USB:{routine_name} →", payload)
    else:
        print(f"[!] USB:{routine_name} no response")


def exec_sp4(dev, name):
    sp = QSLCLSP4_DB.get(name.upper(), None)
    if not sp:
        print("[!] SETUP packet not found:", name)
        return

    h, serial_mode = open_transport(dev)

    pkt = b"QSLCLSP4" + sp
    send(h, pkt, serial_mode)

    tag, payload = recv(h, serial_mode, 3)
    if tag:
        print(f"[+] SP4:{name} →", payload)
    else:
        print(f"[!] SP4:{name} no response")

def exec_nano(dev, svc, extra=b""):
    svc = svc.upper()
    nks = QSLCLNKS_DB.get(svc, None)
    if not nks:
        print("[!] Nano service not found:", svc)
        return

    h, serial_mode = open_transport(dev)

    pkt = b"QSLCLNKS" + nks["raw"] + extra
    send(h, pkt, serial_mode)

    tag, payload = recv(h, serial_mode, 4)
    if tag:
        print(f"[+] NANO:{svc} →", payload)
    else:
        print(f"[!] NANO:{svc} no response")

# =============================================================================
# ADVANCED COMMAND WRAPPERS (OEM/ODM/BYPASS/VOLTAGE/etc)
# =============================================================================
def cmd_oem(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "OEM")

def cmd_odm(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "ODM")

def cmd_bypass(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "BYPASS")

def cmd_spoof(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "SPOOF")

def cmd_glitch(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "GLITCH")

def cmd_voltage(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "VOLTAGE")

def cmd_power(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "POWER")

def cmd_auth(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "AUTHENTICATE")

def cmd_verify(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "VERIFY")

def cmd_config(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "CONFIGURE")

def cmd_meta(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "META")

def cmd_unlock(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "UNLOCK")

def cmd_lock(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "LOCK")

def cmd_reset(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "RESET")

def cmd_reboot(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "REBOOT")

def cmd_open(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "OPEN")

def cmd_close(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "CLOSE")

def cmd_test(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "TEST")

def cmd_checksums(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "CHECKSUMS")

def cmd_dump(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "DUMP")

def cmd_footer(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "FOOTER")

def cmd_rawstate(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "RAWSTATE")

def cmd_mode(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "MODE")

def cmd_getvar(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]
    exec_generic(dev, "GETVAR")

def cmd_bruteforce(args):
    devs = scan_all()
    if not devs:
        return print("[!] No device.")
    dev = devs[0]

    auto_loader_if_needed(args, dev)

    pattern = args.pattern.encode()
    print(f"[*] BRUTEFORCE payload = {pattern!r}")

    exec_cmd(dev, "BRUTEFORCE", pattern, timeout=12.0)

# =============================================================================
# CLI
# =============================================================================
def main():
    # Global parser for options like --loader
    p = argparse.ArgumentParser(
        description="QSLCL Tool v0.9.0 — Full QSLCLPAR Engine",
        add_help=True
    )
    p.add_argument("--loader", help="Inject qslcl.bin before executing command")

    # Subcommands
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("hello").set_defaults(func=cmd_hello)
    sub.add_parser("ping").set_defaults(func=cmd_ping)
    sub.add_parser("getinfo").set_defaults(func=cmd_getinfo)

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

    usb = sub.add_parser("usb")
    usb.add_argument("routine", help="TX, RX, CTRL, BULK, ENUM, SYNC, etc")
    usb.set_defaults(func=lambda a: exec_usb(scan_all()[0], a.routine))

    sp4 = sub.add_parser("sp4")
    sp4.add_argument("name", help="setup packet: SETUP0, SETUP1, etc")
    sp4.set_defaults(func=lambda a: exec_sp4(scan_all()[0], a.name))

    nano = sub.add_parser("nano")
    nano.add_argument("svc", help="NKS microservice name")
    nano.add_argument("extra", nargs="?", default="", help="optional payload")
    nano.set_defaults(func=lambda a: exec_nano(scan_all()[0], a.svc, a.extra.encode()))

    bf = sub.add_parser("bruteforce")
    bf.add_argument("pattern", help="Pattern or range (e.g. 0000-FFFF)")
    bf.set_defaults(func=cmd_bruteforce)

    # Other subcommands
    for cmd_name, cmd_func in [
        ("oem", cmd_oem), ("odm", cmd_odm), ("bypass", cmd_bypass),
        ("spoof", cmd_spoof), ("glitch", cmd_glitch), ("voltage", cmd_voltage),
        ("power", cmd_power), ("auth", cmd_auth), ("verify", cmd_verify),
        ("config", cmd_config), ("meta", cmd_meta), ("unlock", cmd_unlock),
        ("lock", cmd_lock), ("reset", cmd_reset), ("reboot", cmd_reboot),
        ("open", cmd_open), ("close", cmd_close), ("test", cmd_test),
        ("checksums", cmd_checksums), ("dump", cmd_dump), ("footer", cmd_footer),
        ("rawstate", cmd_rawstate), ("mode", cmd_mode), ("getvar", cmd_getvar)
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

    # Execute
    if hasattr(args, "func"):
        args.func(args)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
