#!/usr/bin/env python3
"""
rawstate.py - QSLCL RAWSTATE Command Module v2.1 (CLEANED)
Low-level hardware state inspection and manipulation
"""

import os
import sys
import struct
import time
from typing import Optional, List, Tuple, Dict

# =============================================================================
# IMPORTS - With proper fallbacks
# =============================================================================
try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
        qslcl_dispatch,
        decode_runtime_result,
        encode_qslcl_structure,
        QSLCLCMD_DB,
        _DEBUG
    )
except ImportError:
    try:
        from .qslcl import (
            scan_all,
            auto_loader_if_needed,
            qslcl_dispatch,
            decode_runtime_result,
            encode_qslcl_structure,
            QSLCLCMD_DB,
            _DEBUG
        )
    except ImportError:
        print("[!] CRITICAL: Cannot import qslcl core module")
        sys.exit(1)

# =============================================================================
# CONSTANTS
# =============================================================================
TIMEOUT = 10.0
MAX_READ = 1024
MAX_DUMP = 1024 * 1024
MAX_SCAN = 64 * 1024
CHUNK = 64

# Named registers
REGISTERS = {
    'CPUID': 0x10000000, 'SYSCFG': 0x10000004, 'RST_CTL': 0x10000008,
    'CLK_SRC': 0x1000000C, 'PWR_CTL': 0x20000000, 'PWR_STAT': 0x20000004,
    'VOLT_CTL': 0x20000008, 'PMIC_CFG': 0x2000000C,
    'CLK_CTL': 0x30000000, 'PLL_CTL': 0x30000004, 'DIV_CTL': 0x30000008,
    'GPIO_DIR': 0x40000000, 'GPIO_DATA': 0x40000004, 'GPIO_SET': 0x40000008,
    'GPIO_CLR': 0x4000000C, 'UART_TX': 0x50000000, 'UART_RX': 0x50000004,
    'UART_STAT': 0x50000008, 'UART_BAUD': 0x5000000C,
}

REG_NAMES = {v: k for k, v in REGISTERS.items()}
REG_NAMES.update({
    0x10000000: "CPUID", 0x10000004: "SYSCFG", 0x10000008: "RST_CTL",
    0x20000000: "PWR_CTL", 0x20000004: "PWR_STAT",
    0x30000000: "CLK_CTL", 0x40000000: "GPIO_DIR",
    0x50000000: "UART_TX", 0x50000004: "UART_RX",
})

CRITICAL = {0x10000000, 0x10000004, 0x10000008, 0x20000000, 0x30000000}

BIT_OPS = {'SET':'SET', '1':'SET', 'CLEAR':'CLEAR', '0':'CLEAR',
           'TOGGLE':'TOGGLE', 'FLIP':'TOGGLE', 'TEST':'TEST'}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_addr(s: str) -> int:
    s = str(s).strip()
    if s.lower().startswith('0x'): return int(s[2:], 16)
    if s.lower().startswith('0b'): return int(s[2:], 2)
    try: return int(s, 16)
    except: return int(s, 10)


def parse_val(val: str, size: int) -> Optional[bytes]:
    """Parse value to bytes"""
    val = val.strip()
    try:
        if val.lower().startswith('0x'):
            return int(val[2:], 16).to_bytes(size, 'little')
        elif len(val) % 2 == 0 and all(c in '0123456789ABCDEFabcdef' for c in val):
            return int(val, 16).to_bytes(size, 'little')
        else:
            return int(val).to_bytes(size, 'little')
    except:
        return None


def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ").upper() == req.upper()
    except: return False


def resolve(dev, target: str) -> Optional[int]:
    """Resolve target to address"""
    upper = target.upper().strip()
    
    # Named register
    if upper in REGISTERS:
        return REGISTERS[upper]
    
    # Parse as hex
    try: return parse_addr(target)
    except: pass
    
    # Try partition resolution
    try:
        from qslcl import load_partitions
        parts = load_partitions(dev)
        for p in parts:
            if p['name'].lower() == target.lower():
                return p['offset']
    except: pass
    
    return None


def reg_name(addr: int) -> str:
    return REG_NAMES.get(addr, f"0x{addr:08X}")


def raw_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send rawstate command"""
    for attempt in range(2):
        try:
            if "RAWSTATE" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "RAWSTATE", payload, timeout=TIMEOUT)
            elif "READ" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "READ", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt == 0: time.sleep(0.1)
    return False, "NO_RESPONSE", b""


def read_state(dev, addr: int, size: int) -> Tuple[Optional[bytes], bool]:
    """Read hardware state"""
    if size <= 0 or size > MAX_READ: return None, False
    payload = struct.pack("<II", addr, size)
    ok, _, data = raw_cmd(dev, payload)
    if ok and data:
        return data[:size] if len(data) >= size else data.ljust(size, b'\x00'), True
    return None, False


def write_state(dev, addr: int, data: bytes) -> bool:
    """Write hardware state"""
    payload = struct.pack("<II", addr, len(data)) + data
    ok, _, _ = raw_cmd(dev, payload)
    return ok


def dump_region(dev, addr: int, size: int, verbose: bool) -> bytes:
    """Dump memory region"""
    result = bytearray()
    for off in range(0, size, CHUNK):
        cs = min(CHUNK, size - off)
        data, ok = read_state(dev, addr + off, cs)
        result.extend(data if ok and data else b'\x00' * cs)
        if verbose:
            print(f"\r    {off+cs}/{size} bytes ({100*(off+cs)//size}%)", end="", flush=True)
    if verbose: print()
    return bytes(result)


def display_value(data: bytes, addr: int, size: int, target: str):
    """Display register value"""
    value = int.from_bytes(data[:size], 'little')
    print(f"\n[+] State: {target}")
    print(f"    Address: 0x{addr:08X} ({reg_name(addr)})")
    print(f"    Size:    {size} bytes ({size*8} bits)")
    print(f"    Hex:     0x{value:0{size*2}X}")
    print(f"    Decimal: {value}")
    
    if size <= 8:
        binary = format(value, f'0{size*8}b')
        grouped = ' '.join(binary[i:i+8] for i in range(0, len(binary), 8))
        print(f"    Binary:  {grouped}")
    
    if size == 4:
        for i in range(4):
            print(f"    Byte{i}:  0x{(value>>(i*8))&0xFF:02X}")


def display_dump(data: bytes, addr: int):
    """Display hex dump"""
    if not data: return
    print(f"\n[+] Dump: 0x{addr:08X} ({len(data)} bytes)")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"    0x{addr+i:08x}: {hx:<48} |{asc}|")
    
    zeros = data.count(b'\x00')
    if zeros == len(data): print(f"\n    All zeros")
    elif data.count(b'\xff') == len(data): print(f"\n    All 0xFF")


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force, verbose):
    """List register banks"""
    banks = [
        ('SYSTEM_CTRL', 0x10000000, 0x1000, ['CPUID','SYSCFG','RST_CTL','CLK_SRC']),
        ('POWER_MGMT',  0x20000000, 0x1000, ['PWR_CTL','PWR_STAT','VOLT_CTL','PMIC_CFG']),
        ('CLOCK_CTRL',  0x30000000, 0x1000, ['CLK_CTL','PLL_CTL','DIV_CTL','FREQ_STAT']),
        ('GPIO_BANK0',  0x40000000, 0x1000, ['GPIO_DIR','GPIO_DATA','GPIO_SET','GPIO_CLR']),
        ('UART0',       0x50000000, 0x1000, ['UART_TX','UART_RX','UART_STAT','UART_BAUD']),
    ]
    
    print(f"\n[*] Register Banks:")
    for name, base, size, regs in banks:
        print(f"    {name:<16} 0x{base:08X} ({size}B)")
        for r in regs:
            addr = REGISTERS.get(r, 0)
            print(f"      0x{addr:08X} {r}")
    
    print(f"\n[*] Named Registers: {len(REGISTERS)} available")
    return True


def cmd_read(dev, args, force, verbose):
    """Read state"""
    if not args:
        print("[!] Usage: rawstate read <addr|name> [size]")
        return False
    
    target = args[0]
    size = parse_addr(args[1]) if len(args) > 1 else 4
    size = max(1, min(size, MAX_READ))
    
    addr = resolve(dev, target)
    if addr is None:
        print(f"[!] Cannot resolve: {target}")
        return False
    
    print(f"[*] Reading: {target} ({size} bytes)")
    
    data, ok = read_state(dev, addr, size)
    if ok and data:
        display_value(data, addr, size, target)
        return True
    
    print("[!] Read failed")
    return False


def cmd_write(dev, args, force, verbose):
    """Write state"""
    if len(args) < 2:
        print("[!] Usage: rawstate write <addr|name> <value> [size]")
        return False
    
    target = args[0]
    size = parse_addr(args[2]) if len(args) > 2 else 4
    
    addr = resolve(dev, target)
    if addr is None:
        print(f"[!] Cannot resolve: {target}")
        return False
    
    wdata = parse_val(args[1], size)
    if wdata is None:
        print(f"[!] Invalid value: {args[1]}")
        return False
    
    # Safety
    if addr in CRITICAL and not confirm(
        f"CRITICAL REGISTER: {reg_name(addr)}\nWriting may DAMAGE device!", 'YES', force):
        return False
    
    print(f"[*] Writing: {target} = 0x{int.from_bytes(wdata, 'little'):0{size*2}X}")
    
    # Read original
    orig, _ = read_state(dev, addr, min(size, 8))
    if orig:
        print(f"    Before: 0x{int.from_bytes(orig[:4], 'little'):08X}")
    
    if write_state(dev, addr, wdata):
        print("[+] Write successful")
        
        # Verify
        vdata, vok = read_state(dev, addr, size)
        if vok and vdata[:size] == wdata[:size]:
            print("[+] Verified")
        else:
            print("[!] Verification mismatch")
        return True
    
    print("[!] Write failed")
    return False


def cmd_dump(dev, args, force, verbose):
    """Dump region"""
    if not args:
        print("[!] Usage: rawstate dump <addr|name> [size]")
        return False
    
    target = args[0]
    size = min(parse_addr(args[1]) if len(args) > 1 else 256, MAX_DUMP)
    
    addr = resolve(dev, target)
    if addr is None:
        print(f"[!] Cannot resolve: {target}")
        return False
    
    print(f"[*] Dumping: {target} ({size} bytes)")
    data = dump_region(dev, addr, size, verbose)
    
    if data:
        display_dump(data, addr)
        return True
    return False


def cmd_compare(dev, args, force, verbose):
    """Compare two addresses"""
    if len(args) < 2:
        print("[!] Usage: rawstate compare <addr1> <addr2> [size]")
        return False
    
    size = parse_addr(args[2]) if len(args) > 2 else 4
    
    a1 = resolve(dev, args[0])
    a2 = resolve(dev, args[1])
    if a1 is None or a2 is None:
        print("[!] Cannot resolve")
        return False
    
    d1, ok1 = read_state(dev, a1, size)
    d2, ok2 = read_state(dev, a2, size)
    
    if not ok1 or not ok2:
        print("[!] Read failed")
        return False
    
    if d1[:size] == d2[:size]:
        val = int.from_bytes(d1[:size], 'little')
        print(f"[+] Identical: 0x{val:0{size*2}X}")
    else:
        print("[+] Different:")
        for i in range(min(len(d1), len(d2))):
            if i < size and d1[i] != d2[i]:
                print(f"    Byte{i}: 0x{d1[i]:02X} ≠ 0x{d2[i]:02X}")
    
    return True


def cmd_monitor(dev, args, force, verbose):
    """Monitor state changes"""
    if not args:
        print("[!] Usage: rawstate monitor <addr|name> [interval] [duration]")
        return False
    
    target = args[0]
    interval = max(0.05, float(args[1]) if len(args) > 1 else 1.0)
    duration = float(args[2]) if len(args) > 2 else None
    
    addr = resolve(dev, target)
    if addr is None:
        print(f"[!] Cannot resolve: {target}")
        return False
    
    print(f"[*] Monitoring: {target} every {interval}s")
    prev = None
    changes = 0
    start = time.time()
    print(f"{'-'*50}")
    
    try:
        while True:
            elapsed = time.time() - start
            if duration and elapsed >= duration:
                print(f"\n[*] Duration reached")
                break
            
            data, ok = read_state(dev, addr, 4)
            if ok and data and len(data) >= 4:
                curr = int.from_bytes(data[:4], 'little')
                
                if prev is None:
                    print(f"[{elapsed:7.3f}s] 0x{curr:08X}")
                    prev = curr
                elif curr != prev:
                    changes += 1
                    print(f"[{elapsed:7.3f}s] CHANGE #{changes}: 0x{prev:08X} → 0x{curr:08X}")
                    prev = curr
                elif verbose:
                    print(f"[{elapsed:7.3f}s] 0x{curr:08X}")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print(f"\n[*] Stopped")
    
    print(f"{'-'*50}")
    print(f"[+] {changes} changes in {time.time()-start:.1f}s")
    return True


def cmd_bit(dev, args, force, verbose):
    """Bit operations"""
    if len(args) < 3:
        print("[!] Usage: rawstate bit <addr> <SET|CLEAR|TOGGLE|TEST> <bit>")
        return False
    
    addr = resolve(dev, args[0])
    if addr is None:
        print(f"[!] Cannot resolve: {args[0]}")
        return False
    
    op = BIT_OPS.get(args[1].upper())
    if not op:
        print(f"[!] Unknown op: {args[1]}")
        return False
    
    try: bit = int(args[2])
    except:
        print(f"[!] Invalid bit: {args[2]}")
        return False
    
    if bit < 0 or bit > 63:
        print("[!] Bit must be 0-63")
        return False
    
    size = 1 if bit < 8 else 2 if bit < 16 else 4 if bit < 32 else 8
    
    data, ok = read_state(dev, addr, size)
    if not ok or not data:
        print("[!] Read failed")
        return False
    
    curr = int.from_bytes(data[:size], 'little')
    bit_val = (curr >> bit) & 1
    print(f"[*] {reg_name(addr)}[{bit}] = {bit_val}")
    
    if op == 'TEST':
        return True
    
    if op == 'SET': new = curr | (1 << bit)
    elif op == 'CLEAR': new = curr & ~(1 << bit)
    else: new = curr ^ (1 << bit)
    
    if addr in CRITICAL and not confirm(f"Modifying {reg_name(addr)}", 'BIT', force):
        return False
    
    new_data = new.to_bytes(size, 'little')
    if write_state(dev, addr, new_data):
        print(f"[+] Done: bit{bit} = {(new>>bit)&1}")
        return True
    
    print("[!] Write failed")
    return False


def cmd_field(dev, args, force, verbose):
    """Extract bit field"""
    if len(args) < 2:
        print("[!] Usage: rawstate field <addr> <high:low|bit>")
        return False
    
    addr = resolve(dev, args[0])
    if addr is None:
        print(f"[!] Cannot resolve: {args[0]}")
        return False
    
    spec = args[1]
    if ':' in spec:
        parts = spec.split(':')
        try:
            hi, lo = int(parts[0]), int(parts[1])
            if hi < lo: hi, lo = lo, hi
        except:
            print(f"[!] Invalid range: {spec}")
            return False
    else:
        try: hi = lo = int(spec)
        except:
            print(f"[!] Invalid bit: {spec}")
            return False
    
    if hi > 63:
        print("[!] Bits must be 0-63")
        return False
    
    size = 1 if hi < 8 else 2 if hi < 16 else 4 if hi < 32 else 8
    
    data, ok = read_state(dev, addr, size)
    if not ok or not data:
        print("[!] Read failed")
        return False
    
    value = int.from_bytes(data[:size], 'little')
    width = hi - lo + 1
    mask = ((1 << width) - 1) << lo
    field = (value & mask) >> lo
    
    print(f"[+] Field [{hi}:{lo}]: 0x{field:0{(width+3)//4}X} ({field})")
    if field & (1 << (width-1)):
        print(f"    Signed: {field - (1<<width)}")
    print(f"    Raw:    0x{value:0{size*2}X}")
    return True


def cmd_scan(dev, args, force, verbose):
    """Scan for pattern"""
    if len(args) < 3:
        print("[!] Usage: rawstate scan <start> <end> <pattern> [size]")
        return False
    
    a1 = resolve(dev, args[0])
    a2 = resolve(dev, args[1])
    
    if a1 is None or a2 is None:
        print("[!] Cannot resolve")
        return False
    
    if a1 >= a2:
        print("[!] Start >= End")
        return False
    
    size = parse_addr(args[3]) if len(args) > 3 else 4
    scan_sz = min(a2 - a1, MAX_SCAN)
    
    pat = parse_val(args[2], size)
    if pat is None:
        print(f"[!] Invalid pattern: {args[2]}")
        return False
    
    print(f"[*] Scanning 0x{a1:08X}-0x{a1+scan_sz:08X} for {pat[:size].hex()}")
    
    data = dump_region(dev, a1, scan_sz, verbose)
    
    found = []
    for off in range(0, len(data)-size+1, size):
        if data[off:off+size] == pat[:size]:
            found.append(a1 + off)
    
    if found:
        print(f"\n[+] {len(found)} match(es):")
        for addr in found[:20]:
            print(f"    0x{addr:08X}")
        if len(found) > 20:
            print(f"    ... and {len(found)-20} more")
    else:
        print("[+] No matches")
    
    return True


def cmd_bank(dev, args, force, verbose):
    """Show register bank"""
    if not args:
        print("[!] Usage: rawstate bank <name|address|all>")
        return False
    
    spec = args[0].upper()
    
    banks = [
        ('SYSTEM_CTRL', 0x10000000, 0x1000, {'CPUID':0,'SYSCFG':4,'RST_CTL':8,'CLK_SRC':12}),
        ('POWER_MGMT',  0x20000000, 0x1000, {'PWR_CTL':0,'PWR_STAT':4,'VOLT_CTL':8,'PMIC_CFG':12}),
        ('CLOCK_CTRL',  0x30000000, 0x1000, {'CLK_CTL':0,'PLL_CTL':4,'DIV_CTL':8,'FREQ_STAT':12}),
        ('GPIO_BANK0',  0x40000000, 0x1000, {'GPIO_DIR':0,'GPIO_DATA':4,'GPIO_SET':8,'GPIO_CLR':12}),
        ('UART0',       0x50000000, 0x1000, {'UART_TX':0,'UART_RX':4,'UART_STAT':8,'UART_BAUD':12}),
    ]
    
    if spec == 'ALL':
        for name, base, size, regs in banks:
            print(f"\n[*] {name}: 0x{base:08X} ({size}B)")
            for rn, ro in sorted(regs.items(), key=lambda x: x[1]):
                print(f"    0x{ro:04X} [{base+ro:08X}] {rn}")
        return True
    
    # Find specific bank
    for name, base, size, regs in banks:
        if name.upper() == spec:
            print(f"\n[*] {name}: 0x{base:08X} ({size}B)")
            for rn, ro in sorted(regs.items(), key=lambda x: x[1]):
                print(f"    0x{ro:04X} [0x{base+ro:08X}] {rn}")
            return True
        # Check if address falls in this bank
        try:
            addr = parse_addr(spec)
            if base <= addr < base + size:
                print(f"\n[*] {name}: 0x{base:08X} ({size}B)")
                for rn, ro in sorted(regs.items(), key=lambda x: x[1]):
                    print(f"    0x{ro:04X} [0x{base+ro:08X}] {rn}")
                return True
        except: pass
    
    print(f"[!] Bank not found: {spec}")
    print(f"[*] Available: {', '.join(b[0] for b in banks)}")
    return False


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'list': cmd_list, 'ls': cmd_list,
    'read': cmd_read, 'get': cmd_read, 'peek': cmd_read,
    'write': cmd_write, 'set': cmd_write, 'poke': cmd_write,
    'dump': cmd_dump, 'snapshot': cmd_dump,
    'compare': cmd_compare, 'diff': cmd_compare,
    'monitor': cmd_monitor, 'watch': cmd_monitor,
    'bit': cmd_bit, 'bits': cmd_bit,
    'field': cmd_field, 'fields': cmd_field,
    'scan': cmd_scan, 'search': cmd_scan, 'find': cmd_scan,
    'bank': cmd_bank, 'banks': cmd_bank,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_rawstate(args=None) -> int:
    """
    QSLCL RAWSTATE - Low-level hardware state inspection
    
    Examples:
        rawstate list                    - List register banks
        rawstate read CPUID              - Read named register
        rawstate write PWR_CTL 0x1234    - Write register
        rawstate dump 0x40000000 256     - Dump memory region
        rawstate compare CPUID SYSCFG    - Compare two registers
        rawstate monitor CLK_CTL 0.5 30  - Monitor for changes
        rawstate bit GPIO_SET SET 15     - Set bit 15
        rawstate field STATUS 31:24      - Extract bit field
        rawstate scan 0x40000000 0x40001000 FF 4  - Scan for pattern
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: rawstate <list|read|write|dump|compare|monitor|bit|field|scan|bank>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'rawstate_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    rargs = getattr(args, 'rawstate_args', []) or getattr(args, 'args', []) or []
    verbose = getattr(args, 'verbose', False)
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Rawstate Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip()
                print(f"    {name:<12} {doc}")
        print(f"\n[*] Named Registers: {', '.join(sorted(REGISTERS)[:10])}...")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        print(f"[*] Valid: {', '.join(sorted(set(k for k in HANDLERS if '_' not in k)))}")
        return 1
    
    try:
        return 0 if handler(dev, rargs, force, verbose) else 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if verbose and _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] rawstate.py - QSLCL RAWSTATE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py rawstate <subcommand> [args]")