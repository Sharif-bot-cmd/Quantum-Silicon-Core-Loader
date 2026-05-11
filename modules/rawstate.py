#!/usr/bin/env python3
"""
rawstate.py - QSLCL RAWSTATE Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, address resolution,
       state read/write, monitoring, field extraction, scan logic
"""

import os
import sys
import re
import struct
import time
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union

# =============================================================================
# FIXED: Proper relative imports with comprehensive fallbacks
# =============================================================================
_use_qslcl = False
_scan_all = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_QSLCLCMD_DB = None
_parse_address_fn = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
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
            auto_loader_if_needed as _qslcl_auto_loader,
            qslcl_dispatch as _qslcl_dispatch_fn,
            decode_runtime_result as _qslcl_decode_runtime,
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _auto_loader_if_needed = _qslcl_auto_loader
        _qslcl_dispatch = _qslcl_dispatch_fn
        _decode_runtime_result = _qslcl_decode_runtime
        _QSLCLCMD_DB = _qslcl_cmd_db
        _DEBUG = _qslcl_debug
        _use_qslcl = True
    except ImportError:
        _use_qslcl = False


# =============================================================================
# FIXED: Standalone mode
# =============================================================================
_STANDALONE_WARNED = False
def _warn_standalone():
    global _STANDALONE_WARNED
    if not _STANDALONE_WARNED:
        print("[!] Running in standalone mode")
        _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
RAWSTATE_TIMEOUT = 10.0
MAX_READ_SIZE = 1024
MAX_DUMP_SIZE = 1024 * 1024  # 1MB
MAX_SCAN_SIZE = 64 * 1024     # 64KB
CHUNK_SIZE = 64

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Named registers database
# =============================================================================
NAMED_REGISTERS: Dict[str, int] = {
    'CPUID': 0x10000000, 'SYSCFG': 0x10000004, 'RST_CTL': 0x10000008,
    'CLK_SRC': 0x1000000C, 'PWR_CTL': 0x20000000, 'PWR_STAT': 0x20000004,
    'VOLT_CTL': 0x20000008, 'PMIC_CFG': 0x2000000C,
    'CLK_CTL': 0x30000000, 'PLL_CTL': 0x30000004, 'DIV_CTL': 0x30000008, 'FREQ_STAT': 0x3000000C,
    'GPIO_DIR': 0x40000000, 'GPIO_DATA': 0x40000004, 'GPIO_SET': 0x40000008, 'GPIO_CLR': 0x4000000C,
    'GPIO_BASE': 0x40000000, 'UART_BASE': 0x50000000,
    'UART_TX': 0x50000000, 'UART_RX': 0x50000004, 'UART_STAT': 0x50000008, 'UART_BAUD': 0x5000000C,
}

CRITICAL_REGISTERS = {0x10000000, 0x10000004, 0x10000008, 0x20000000, 0x30000000}
CRITICAL_RANGES = [
    (0x10000000, 0x10000FFF), (0x20000000, 0x20000FFF), (0x30000000, 0x30000FFF),
    (0x40000000, 0x40000FFF), (0x50000000, 0x50000FFF), (0x60000000, 0x60000FFF),
]

REGISTER_NAMES: Dict[int, str] = {
    0x10000000: "CPUID (Processor ID)", 0x10000004: "SYSCFG (System Config)",
    0x10000008: "RST_CTL (Reset Control)", 0x20000000: "PWR_CTL (Power Control)",
    0x30000000: "CLK_CTL (Clock Control)", 0x40000000: "GPIO_DIR", 0x40000004: "GPIO_DATA",
    0x50000000: "UART_TX", 0x50000004: "UART_RX", 0x50000008: "UART_STAT", 0x5000000C: "UART_BAUD",
}

BIT_OPS = {
    'SET':'SET','1':'SET','HIGH':'SET', 'CLEAR':'CLEAR','0':'CLEAR','LOW':'CLEAR',
    'TOGGLE':'TOGGLE','FLIP':'TOGGLE','XOR':'TOGGLE', 'TEST':'TEST','READ':'TEST',
}

VALID_READ_SIZES = {1,2,4,8}


# =============================================================================
# FIXED: Parse helpers
# =============================================================================
def _parse_address(s: str) -> int:
    s = str(s).strip()
    if s.lower().startswith('0x'): return int(s[2:], 16)
    if s.lower().startswith('0b'): return int(s[2:], 2)
    try: return int(s, 16)
    except: return int(s, 10)

def _parse_size(s: str) -> int:
    s = str(s).strip().upper()
    if s.startswith('0X'): return int(s, 16)
    for sfx, mul in [('GB',1024**3),('G',1024**3),('MB',1024**2),('M',1024**2),
                      ('KB',1024),('K',1024)]:
        if s.endswith(sfx): return int(float(s[:-len(sfx)]) * mul)
    return int(s)

def _parse_value(val: str, size: int) -> Optional[bytes]:
    """Parse value string to bytes of given size."""
    val = val.strip()
    try:
        if ' ' in val:
            parts = [int(p, 16 if all(c in '0123456789ABCDEFabcdef' for c in p) else 10) for p in val.split()]
            result = bytes(parts)
        elif val.lower().startswith('0x'):
            result = int(val[2:], 16).to_bytes(size, 'little')
        elif val.lower().startswith('0b'):
            result = int(val[2:], 2).to_bytes(size, 'little')
        elif len(val) % 2 == 0 and all(c in '0123456789ABCDEFabcdef' for c in val):
            result = int(val, 16).to_bytes(size, 'little')
        else:
            result = int(val).to_bytes(size, 'little')
        
        if len(result) < size: result = result.ljust(size, b'\x00')
        return result[:size]
    except (ValueError, OverflowError):
        return None


# =============================================================================
# FIXED: Address resolution
# =============================================================================
def _resolve_address(target: str, dev) -> Optional[int]:
    """Resolve target to a hardware address."""
    upper = target.upper().strip()
    
    # Named registers
    if upper in NAMED_REGISTERS:
        return NAMED_REGISTERS[upper]
    
    # Try parsing as hex/decimal
    try: return _parse_address(target)
    except: pass
    
    # Try QSLCL target resolution if available
    if _use_qslcl:
        try:
            from qslcl import resolve_target, load_partitions, detect_memory_regions
            parts = load_partitions(dev) if load_partitions else []
            regions = detect_memory_regions(dev) if detect_memory_regions else []
            res = resolve_target(target, parts, regions, dev)
            if res: return res['address']
        except: pass
    
    return None


# =============================================================================
# FIXED: Safety check
# =============================================================================
def _is_critical(address: int) -> bool:
    if address in CRITICAL_REGISTERS: return True
    for s, e in CRITICAL_RANGES:
        if s <= address <= e: return True
    return False

def _get_reg_name(address: int) -> str:
    return REGISTER_NAMES.get(address, f"Unknown (0x{address:08X})")


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.RED}{msg}{C.RESET}")
    try: return input(f"    Type '{req}': ").upper() == req.upper()
    except: return False


# =============================================================================
# FIXED: Dispatch helper
# =============================================================================
def _find_cmd(name: str) -> Optional[Tuple]:
    if not _use_qslcl or not _QSLCLCMD_DB: return None
    u = name.upper()
    for k,v in _QSLCLCMD_DB.items():
        if isinstance(k,str) and k.upper()==u: return ("name",k)
        if isinstance(v,dict) and v.get("name","").upper()==u: return ("opcode",k)
    return None

def _dispatch(dev, cmd: str, payload: bytes, timeout: float=None) -> Tuple[bool,str,bytes]:
    if not _use_qslcl: return False,"NO_QSLCL",b""
    for attempt in range(2):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or RAWSTATE_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or RAWSTATE_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: State read/write
# =============================================================================
def _read_state(dev, address: int, size: int) -> Tuple[Optional[bytes], bool]:
    if size <= 0 or size > MAX_READ_SIZE: return None, False
    payload = struct.pack("<II", address, size)
    
    if _find_cmd("RAWSTATE"):
        ok, _, data = _dispatch(dev, "RAWSTATE", payload)
    else:
        ok, _, data = _dispatch(dev, "READ", payload)
    
    if ok and data:
        return (data[:size] if len(data)>=size else data.ljust(size,b'\x00')), True
    return None, False

def _write_state(dev, address: int, data: bytes) -> bool:
    size = len(data)
    if size <= 0 or size > MAX_READ_SIZE: return False
    payload = struct.pack("<II", address, size) + data
    
    if _find_cmd("RAWSTATE"):
        ok, _, _ = _dispatch(dev, "RAWSTATE", payload)
    else:
        ok, _, _ = _dispatch(dev, "WRITE", payload)
    return ok

def _dump_region(dev, address: int, size: int, verbose: bool) -> bytes:
    result = bytearray()
    for off in range(0, size, CHUNK_SIZE):
        cs = min(CHUNK_SIZE, size - off)
        data, ok = _read_state(dev, address + off, cs)
        if ok and data: result.extend(data)
        else: result.extend(b'\x00' * cs)
        if verbose and (off % 1024 == 0 or off + cs >= size):
            print(f"\r    {off+cs}/{size} bytes ({100*(off+cs)//size}%)", end="", flush=True)
    if verbose: print()
    return bytes(result)


# =============================================================================
# FIXED: Display functions
# =============================================================================
def _display_value(data: bytes, address: int, size: int, target: str):
    if len(data) < size: data = data.ljust(size, b'\x00')
    value = int.from_bytes(data[:size], 'little')
    
    print(f"\n{C.BOLD}[+] State: {target}{C.RESET}")
    print(f"    Address: 0x{address:08X} ({_get_reg_name(address)})")
    print(f"    Size:    {size} bytes ({size*8} bits)")
    print(f"    Hex:     0x{value:0{size*2}X}")
    print(f"    Decimal: {value}")
    
    if size <= 8:
        binary = format(value, f'0{size*8}b')
        grouped = ' '.join(binary[i:i+8] for i in range(0, len(binary), 8))
        print(f"    Binary:  {grouped}")
    
    if size == 4:
        print(f"    High16:  0x{(value>>16)&0xFFFF:04X}  Low16: 0x{value&0xFFFF:04X}")
        for i in range(4):
            print(f"    Byte{i}:  0x{(value>>(i*8))&0xFF:02X}")

def _display_dump(data: bytes, address: int):
    if not data: return
    print(f"\n{C.BOLD}[+] Dump: 0x{address:08X} ({len(data)} bytes){C.RESET}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"    0x{address+i:08x}: {hx:<48} |{asc}|")
    
    zeros = data.count(b'\x00'); ffs = data.count(b'\xff')
    if zeros == len(data): print(f"\n    Note: All zeros")
    elif ffs == len(data): print(f"\n    Note: All 0xFF")


# =============================================================================
# FIXED: Capabilities
# =============================================================================
def _get_capabilities(dev, verbose=False) -> Dict:
    caps = {
        'device_name': 'Generic Hardware',
        'architecture': 'ARMv8',
        'state_access': 'Full',
        'endianness': 'little',
        'register_banks': [
            {'name':'SYSTEM_CTRL','base':0x10000000,'size':0x1000,'access':'RW',
             'description':'System Control','registers':{'CPUID':0,'SYSCFG':4,'RST_CTL':8,'CLK_SRC':12}},
            {'name':'POWER_MGMT','base':0x20000000,'size':0x1000,'access':'RW',
             'description':'Power Management','registers':{'PWR_CTL':0,'PWR_STAT':4,'VOLT_CTL':8,'PMIC_CFG':12}},
            {'name':'CLOCK_CTRL','base':0x30000000,'size':0x1000,'access':'RW',
             'description':'Clock Control','registers':{'CLK_CTL':0,'PLL_CTL':4,'DIV_CTL':8,'FREQ_STAT':12}},
            {'name':'GPIO_BANK0','base':0x40000000,'size':0x1000,'access':'RW',
             'description':'GPIO Bank 0','registers':{'GPIO_DIR':0,'GPIO_DATA':4,'GPIO_SET':8,'GPIO_CLR':12}},
            {'name':'UART0','base':0x50000000,'size':0x1000,'access':'RW',
             'description':'UART Controller','registers':{'UART_TX':0,'UART_RX':4,'UART_STAT':8,'UART_BAUD':12}},
        ],
        'hardware_blocks': [
            {'name':'CPU','description':'Processor core(s)'},
            {'name':'GPU','description':'Graphics Processor'},
            {'name':'DDR','description':'Memory Controller'},
            {'name':'USB','description':'USB Controller'},
            {'name':'EMMC','description':'Storage Controller'},
        ],
        'state_locations': [
            {'name':'CPUID','address':0x10000000,'size':4},
            {'name':'SYSCFG','address':0x10000004,'size':4},
            {'name':'RST_CTL','address':0x10000008,'size':4},
            {'name':'CLK_CTL','address':0x30000000,'size':4},
            {'name':'PWR_CTL','address':0x20000000,'size':4},
        ]
    }
    return caps


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def rawstate_list(dev, args, force=False, verbose=False) -> bool:
    caps = _get_capabilities(dev, verbose)
    print(f"\n{C.BOLD}[+] RAWSTATE Capabilities{C.RESET}")
    print(f"    Device: {caps['device_name']}, Arch: {caps['architecture']}")
    
    banks = caps.get('register_banks', [])
    if banks:
        print(f"\n{C.BOLD}[+] Register Banks ({len(banks)}):{C.RESET}")
        for i, b in enumerate(banks[:20]):
            icon = {'RW':'🟢','RO':'🟡','WO':'🔴'}.get(b.get('access','?'),'❓')
            print(f"    {i:2d}. {icon} {b['name']:<18} 0x{b['base']:08X} ({b['size']}B) - {b.get('description','')}")
    
    locs = caps.get('state_locations', [])
    if locs:
        print(f"\n{C.BOLD}[+] Common Locations ({len(locs)}):{C.RESET}")
        for l in locs[:20]:
            print(f"    {l['name']:<16} 0x{l['address']:08X} ({l['size']}B)")
    return True

def rawstate_read(dev, args, force=False, verbose=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Usage: rawstate read <addr|name> [size]{C.RESET}")
        return False
    
    target = args[0]
    size = 4
    if len(args) > 1:
        try: size = _parse_size(args[1])
        except: size = 4
    if size not in VALID_READ_SIZES and size > 8:
        print(f"[!] Size {size} clamped to {min(size, MAX_READ_SIZE)}")
        size = min(size, MAX_READ_SIZE)
    
    print(f"\n{C.CYAN}[*] Read: {target} ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    data, ok = _read_state(dev, addr, size)
    if ok and data:
        _display_value(data, addr, size, target)
        return True
    print(f"{C.RED}[!] Read failed{C.RESET}")
    return False

def rawstate_write(dev, args, force=False, verbose=False) -> bool:
    if len(args) < 2:
        print(f"{C.RED}[!] Usage: rawstate write <addr|name> <value> [size]{C.RESET}")
        return False
    
    target = args[0]
    val_str = args[1]
    size = 4
    if len(args) > 2:
        try: size = _parse_size(args[2])
        except: pass
    
    print(f"\n{C.CYAN}[*] Write: {target} = {val_str} ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    wdata = _parse_value(val_str, size)
    if wdata is None:
        print(f"{C.RED}[!] Invalid value: {val_str}{C.RESET}"); return False
    
    # Safety
    if _is_critical(addr) and not _confirm(
        f"⚠️  CRITICAL REGISTER: {_get_reg_name(addr)} at 0x{addr:08X}\n"
        f"Writing here may DAMAGE or BRICK the device!", 'YES', force
    ):
        return False
    
    # Read original
    orig, _ = _read_state(dev, addr, min(size, 8))
    if orig:
        print(f"    Original: 0x{int.from_bytes(orig[:min(len(orig),4)], 'little'):08X}")
    
    if _write_state(dev, addr, wdata):
        print(f"{C.GREEN}[+] Write successful{C.RESET}")
        # Verify
        if size <= 8:
            vdata, vok = _read_state(dev, addr, size)
            if vok and vdata[:size] == wdata[:size]:
                print(f"{C.GREEN}[+] Verified{C.RESET}")
            else:
                print(f"{C.YELLOW}[!] Verification mismatch{C.RESET}")
        return True
    
    print(f"{C.RED}[!] Write failed{C.RESET}")
    return False

def rawstate_dump(dev, args, force=False, verbose=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Usage: rawstate dump <addr|name> [size]{C.RESET}")
        return False
    
    target = args[0]
    size = 256
    if len(args) > 1:
        try: size = min(_parse_size(args[1]), MAX_DUMP_SIZE)
        except: pass
    
    print(f"\n{C.CYAN}[*] Dump: {target} ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    data = _dump_region(dev, addr, size, verbose)
    if data:
        _display_dump(data, addr)
        return True
    print(f"{C.RED}[!] Dump failed{C.RESET}")
    return False

def rawstate_compare(dev, args, force=False, verbose=False) -> bool:
    if len(args) < 2:
        print(f"{C.RED}[!] Usage: rawstate compare <addr1> <addr2> [size]{C.RESET}")
        return False
    
    t1, t2 = args[0], args[1]
    size = 4
    if len(args) > 2:
        try: size = _parse_size(args[2])
        except: pass
    
    print(f"\n{C.CYAN}[*] Compare: {t1} vs {t2} ({size}B){C.RESET}")
    
    a1 = _resolve_address(t1, dev)
    a2 = _resolve_address(t2, dev)
    if a1 is None or a2 is None:
        print(f"{C.RED}[!] Cannot resolve{C.RESET}"); return False
    
    d1, ok1 = _read_state(dev, a1, size)
    d2, ok2 = _read_state(dev, a2, size)
    if not ok1 or not ok2:
        print(f"{C.RED}[!] Read failed{C.RESET}"); return False
    
    d1 = d1[:size]; d2 = d2[:size]
    
    if d1 == d2:
        print(f"    {C.GREEN}✅ Identical{C.RESET}")
        val = int.from_bytes(d1, 'little')
        print(f"    Value: 0x{val:0{size*2}X}")
    else:
        print(f"    {C.YELLOW}🔄 Different{C.RESET}")
        diffs = [(i, d1[i], d2[i]) for i in range(min(len(d1),len(d2))) if d1[i]!=d2[i]]
        for i, v1, v2 in diffs[:10]:
            print(f"    Byte{i:3d}: 0x{v1:02X} ≠ 0x{v2:02X} (xor=0x{v1^v2:02X})")
        if len(diffs) > 10:
            print(f"    ... and {len(diffs)-10} more")
    return True

def rawstate_monitor(dev, args, force=False, verbose=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Usage: rawstate monitor <addr|name> [interval] [duration]{C.RESET}")
        return False
    
    target = args[0]
    interval = max(0.05, float(args[1]) if len(args)>1 else 1.0)
    duration = float(args[2]) if len(args)>2 else None
    
    print(f"\n{C.CYAN}[*] Monitor: {target} (every {interval}s){C.RESET}")
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    prev = None
    changes = 0
    start = time.time()
    print(f"[+] Address: 0x{addr:08X}")
    print(f"{'-'*50}")
    
    try:
        while True:
            elapsed = time.time() - start
            if duration and elapsed >= duration:
                print(f"\n[*] Duration reached"); break
            
            data, ok = _read_state(dev, addr, 4)
            if ok and data and len(data)>=4:
                curr = int.from_bytes(data[:4], 'little')
                if prev is None:
                    print(f"[{elapsed:7.3f}s] Initial: 0x{curr:08X}")
                    prev = curr
                elif curr != prev:
                    changes += 1
                    diff = curr ^ prev
                    print(f"[{elapsed:7.3f}s] CHANGE #{changes}: 0x{prev:08X} → 0x{curr:08X} (xor=0x{diff:08X})")
                    prev = curr
                elif verbose:
                    print(f"[{elapsed:7.3f}s] 0x{curr:08X}")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[*] Stopped{C.RESET}")
    
    print(f"{'-'*50}")
    print(f"[+] {changes} changes in {time.time()-start:.1f}s")
    return True

def rawstate_bit(dev, args, force=False, verbose=False) -> bool:
    if len(args) < 3:
        print(f"{C.RED}[!] Usage: rawstate bit <addr> <SET|CLEAR|TOGGLE|TEST> <bit>{C.RESET}")
        return False
    
    target = args[0]
    op = args[1].upper()
    try: bit = int(args[2])
    except:
        print(f"{C.RED}[!] Invalid bit: {args[2]}{C.RESET}"); return False
    
    if bit < 0 or bit > 63:
        print(f"{C.RED}[!] Bit must be 0-63{C.RESET}"); return False
    
    op_norm = BIT_OPS.get(op)
    if not op_norm:
        print(f"{C.RED}[!] Unknown op: {op}{C.RESET}"); return False
    
    size = 1 if bit<8 else 2 if bit<16 else 4 if bit<32 else 8
    
    print(f"\n{C.CYAN}[*] Bit: {target} bit{bit} {op_norm} ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    data, ok = _read_state(dev, addr, size)
    if not ok or not data:
        print(f"{C.RED}[!] Read failed{C.RESET}"); return False
    
    curr = int.from_bytes(data[:size], 'little')
    bit_val = (curr >> bit) & 1
    print(f"    Current: 0x{curr:0{size*2}X}, Bit{bit}={bit_val}")
    
    if op_norm == 'TEST':
        print(f"    Result: {bit_val}")
        return True
    
    if op_norm == 'SET': new = curr | (1 << bit)
    elif op_norm == 'CLEAR': new = curr & ~(1 << bit)
    else: new = curr ^ (1 << bit)
    
    new_data = new.to_bytes(size, 'little')
    
    if _is_critical(addr) and not _confirm(
        f"⚠️  Modifying {_get_reg_name(addr)}", 'BIT', force
    ): return False
    
    if _write_state(dev, addr, new_data):
        print(f"{C.GREEN}[+] Done: Bit{bit}={(new>>bit)&1}{C.RESET}")
        return True
    print(f"{C.RED}[!] Write failed{C.RESET}")
    return False

def rawstate_field(dev, args, force=False, verbose=False) -> bool:
    if len(args) < 2:
        print(f"{C.RED}[!] Usage: rawstate field <addr> <high:low|bit>{C.RESET}")
        return False
    
    target = args[0]
    spec = args[1]
    
    if ':' in spec:
        parts = spec.split(':')
        try:
            hi, lo = int(parts[0]), int(parts[1])
            if hi < lo: hi, lo = lo, hi
        except:
            print(f"{C.RED}[!] Invalid range: {spec}{C.RESET}"); return False
    else:
        try: hi = lo = int(spec)
        except:
            print(f"{C.RED}[!] Invalid bit: {spec}{C.RESET}"); return False
    
    if hi > 63:
        print(f"{C.RED}[!] Bits must be 0-63{C.RESET}"); return False
    
    size = 1 if hi<8 else 2 if hi<16 else 4 if hi<32 else 8
    
    print(f"\n{C.CYAN}[*] Field: {target} [{hi}:{lo}] ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    data, ok = _read_state(dev, addr, size)
    if not ok or not data:
        print(f"{C.RED}[!] Read failed{C.RESET}"); return False
    
    value = int.from_bytes(data[:size], 'little')
    width = hi - lo + 1
    mask = ((1 << width) - 1) << lo
    field_val = (value & mask) >> lo
    
    print(f"    Raw:    0x{value:0{size*2}X}")
    print(f"    Field:  0x{field_val:0{(width+3)//4}X} ({field_val})")
    if width > 1:
        if field_val & (1 << (width-1)):
            print(f"    Signed: {field_val - (1<<width)}")
    print(f"    Width:  {width} bits, Mask: 0x{mask:0{size*2}X}")
    return True

def rawstate_scan(dev, args, force=False, verbose=False) -> bool:
    if len(args) < 3:
        print(f"{C.RED}[!] Usage: rawstate scan <start> <end> <pattern> [size]{C.RESET}")
        return False
    
    t1, t2, pat_str = args[0], args[1], args[2]
    size = 4
    if len(args) > 3:
        try: size = _parse_size(args[3])
        except: pass
    
    a1 = _resolve_address(t1, dev)
    a2 = _resolve_address(t2, dev)
    if a1 is None or a2 is None:
        print(f"{C.RED}[!] Cannot resolve{C.RESET}"); return False
    
    if a1 >= a2:
        print(f"{C.RED}[!] Start >= End{C.RESET}"); return False
    
    scan_range = min(a2 - a1, MAX_SCAN_SIZE)
    
    print(f"\n{C.CYAN}[*] Scan: 0x{a1:08X}-0x{a1+scan_range:08X} for {pat_str}{C.RESET}")
    
    pat_bytes = _parse_value(pat_str, size)
    if pat_bytes is None:
        print(f"{C.RED}[!] Invalid pattern{C.RESET}"); return False
    
    data = _dump_region(dev, a1, scan_range, verbose)
    
    found = []
    for off in range(0, len(data) - size + 1, size):
        if data[off:off+size] == pat_bytes[:size]:
            found.append(a1 + off)
    
    if found:
        print(f"\n{C.GREEN}[+] {len(found)} match(es):{C.RESET}")
        for addr in found[:20]:
            print(f"    0x{addr:08X}")
        if len(found) > 20:
            print(f"    ... and {len(found)-20} more")
    else:
        print(f"{C.YELLOW}[+] No matches{C.RESET}")
    return True

def rawstate_reset(dev, args, force=False, verbose=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Usage: rawstate reset <addr|name> [value] [size]{C.RESET}")
        return False
    
    target = args[0]
    def_val = 0
    if len(args) > 1:
        try: def_val = _parse_address(args[1])
        except: pass
    size = 4
    if len(args) > 2:
        try: size = _parse_size(args[2])
        except: pass
    
    print(f"\n{C.CYAN}[*] Reset: {target} → 0x{def_val:0{size*2}X} ({size}B){C.RESET}")
    
    addr = _resolve_address(target, dev)
    if addr is None:
        print(f"{C.RED}[!] Cannot resolve: {target}{C.RESET}"); return False
    
    if _is_critical(addr) and not _confirm(
        f"⚠️  Resetting {_get_reg_name(addr)}", 'RESET', force
    ): return False
    
    wdata = def_val.to_bytes(size, 'little')
    if _write_state(dev, addr, wdata):
        print(f"{C.GREEN}[+] Reset done{C.RESET}")
        return True
    print(f"{C.RED}[!] Reset failed{C.RESET}")
    return False

def rawstate_bank(dev, args, force=False, verbose=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Usage: rawstate bank <name|address|all>{C.RESET}")
        return False
    
    spec = args[0].upper()
    caps = _get_capabilities(dev, verbose)
    banks = caps.get('register_banks', [])
    
    if spec == 'ALL':
        print(f"\n{C.BOLD}[+] All Banks ({len(banks)}):{C.RESET}")
        for b in banks:
            print(f"\n    {b['name']}: 0x{b['base']:08X} ({b['size']}B) [{b['access']}]")
            if 'registers' in b:
                for rn, ro in sorted(b['registers'].items(), key=lambda x:x[1])[:10]:
                    print(f"      0x{ro:04X} [{b['base']+ro:08X}] {rn}")
        return True
    
    # Find specific bank
    found = None
    for b in banks:
        if b['name'].upper() == spec: found = b; break
    
    if not found:
        try:
            addr = _parse_address(spec)
            for b in banks:
                if b['base'] <= addr < b['base'] + b['size']: found = b; break
        except: pass
    
    if not found:
        print(f"{C.RED}[!] Bank not found: {spec}{C.RESET}")
        names = ', '.join(b['name'] for b in banks)
        print(f"[*] Available: {names}")
        return False
    
    print(f"\n{C.BOLD}[+] Bank: {found['name']}{C.RESET}")
    print(f"    Base: 0x{found['base']:08X}, Size: {found['size']}B, Access: {found['access']}")
    if 'description' in found:
        print(f"    Desc: {found['description']}")
    if 'registers' in found:
        print(f"\n    Registers:")
        for rn, ro in sorted(found['registers'].items(), key=lambda x:x[1]):
            print(f"      0x{ro:04X} [0x{found['base']+ro:08X}] {rn}")
    return True


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
RAWSTATE_HANDLERS = {
    'list':rawstate_list, 'ls':rawstate_list, 'show':rawstate_list,
    'read':rawstate_read, 'get':rawstate_read, 'peek':rawstate_read,
    'write':rawstate_write, 'set':rawstate_write, 'poke':rawstate_write,
    'dump':rawstate_dump, 'snapshot':rawstate_dump, 'capture':rawstate_dump,
    'compare':rawstate_compare, 'diff':rawstate_compare,
    'monitor':rawstate_monitor, 'watch':rawstate_monitor, 'trace':rawstate_monitor,
    'bit':rawstate_bit, 'bits':rawstate_bit, 'bitwise':rawstate_bit,
    'field':rawstate_field, 'fields':rawstate_field,
    'scan':rawstate_scan, 'search':rawstate_scan, 'find':rawstate_scan,
    'reset':rawstate_reset, 'clear':rawstate_reset, 'init':rawstate_reset,
    'bank':rawstate_bank, 'banks':rawstate_bank,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_rawstate_help():
    print(f"""
{C.BOLD}RAWSTATE - Low-Level Hardware State Inspection{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  list, ls                List register banks and locations
  read <addr> [size]      Read hardware state
  write <addr> <val> [sz] Write hardware state
  dump <addr> [size]      Dump memory region
  compare <a1> <a2> [sz]  Compare two addresses
  monitor <addr> [int] [dur] Monitor state changes
  bit <addr> <op> <bit>   Bit ops: SET, CLEAR, TOGGLE, TEST
  field <addr> <hi:lo>    Extract bit field
  scan <start> <end> <pat> Scan for pattern
  reset <addr> [val] [sz] Reset to value
  bank <name|all>         Show register bank info

{C.CYAN}NAMED REGISTERS:{C.RESET}
  CPUID, SYSCFG, RST_CTL, PWR_CTL, CLK_CTL,
  GPIO_DIR, GPIO_DATA, GPIO_SET, GPIO_CLR,
  UART_TX, UART_RX, UART_STAT, UART_BAUD

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl rawstate list
  qslcl rawstate read CPUID
  qslcl rawstate write PWR_CTL 0x1234
  qslcl rawstate monitor CLK_CTL 0.5 30
  qslcl rawstate bit GPIO_SET SET 15
  qslcl rawstate field STATUS 31:24

{C.CYAN}OPTIONS:{C.RESET}
  --verbose, -v   Detailed output
  --force         Skip safety confirmations
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_rawstate(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_rawstate_help(); return 1
    
    if not _use_qslcl: _warn_standalone()
    
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return 1
        if not devs: print(f"{C.RED}[!] No device{C.RESET}"); return 1
        dev = devs[0]
        print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        print(f"{C.RED}[!] No QSLCL{C.RESET}"); return 1
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    sub = (getattr(args, 'rawstate_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    rargs = getattr(args, 'rawstate_args', []) or []
    verbose = getattr(args, 'verbose', False)
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_rawstate_help(); return 0
    
    handler = RAWSTATE_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_rawstate_help(); return 1
    
    try:
        return 0 if handler(dev, rargs, force, verbose) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if verbose: traceback.print_exc()
        return 1


def add_rawstate_arguments(parser):
    parser.add_argument('rawstate_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('rawstate_args', nargs='*', help='Arguments')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--force', '-f', action='store_true')
    return parser


if __name__ == "__main__":
    print("[*] rawstate.py - QSLCL RAWSTATE Module v2.0")
    print_rawstate_help()