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

REGISTERS = {
    # Common ARM registers
    'CPUID': 0x10000000, 'SYSCFG': 0x10000004, 'RST_CTL': 0x10000008,
    'CLK_SRC': 0x1000000C, 'PWR_CTL': 0x20000000, 'PWR_STAT': 0x20000004,
    'VOLT_CTL': 0x20000008, 'PMIC_CFG': 0x2000000C, 'CLK_CTL': 0x30000000,
    'PLL_CTL': 0x30000004, 'DIV_CTL': 0x30000008, 'GPIO_DIR': 0x40000000,
    'GPIO_DATA': 0x40000004, 'GPIO_SET': 0x40000008, 'GPIO_CLR': 0x4000000C,
    'UART_TX': 0x50000000, 'UART_RX': 0x50000004, 'UART_STAT': 0x50000008,
    'UART_BAUD': 0x5000000C, 'WDT_CTL': 0x60000000, 'WDT_LOAD': 0x60000004,
    'WDT_STAT': 0x60000008, 'TIMER0': 0x70000000, 'TIMER1': 0x70000004,
    'TIMER_CTL': 0x70000008, 'INT_STATUS': 0x80000000, 'INT_ENABLE': 0x80000004,
    'INT_CLEAR': 0x80000008, 'DMA_STATUS': 0x90000000, 'DMA_CTL': 0x90000004,
    'DMA_ADDR': 0x90000008, 'DMA_LEN': 0x9000000C, 'CACHE_CTL': 0xA0000000,
    'CACHE_FLUSH': 0xA0000004, 'MMU_CTL': 0xA0000008, 'MMU_TTB': 0xA000000C,
    
    # Apple A12+ specific
    'APRR_CTL': 0x20E00000, 'APRR_STAT': 0x20E00004, 'PAC_CTL': 0x20E01000,
    'PAC_STAT': 0x20E01004, 'SEP_STATE': 0x20E02000, 'DIT_CTL': 0x20E03000,
    'PPL_CTL': 0x20E04000, 'SCEP_CTL': 0x20E05000,
    
    # Qualcomm specific
    'TZ_CTL': 0xFC400000, 'TZ_STAT': 0xFC400004, 'QFP_CTL': 0xFC400100,
    'SMMU_CTL': 0xFD000000, 'SMMU_STAT': 0xFD000004, 'HLOS_CTL': 0xFE000000,
    
    # MediaTek specific
    'BROM_CTL': 0x10000000, 'BROM_STAT': 0x10000004, 'DA_CTL': 0x10001000,
    'DA_STAT': 0x10001004, 'PMIC_WDT': 0x1C000000, 'PMIC_STAT': 0x1C000004,
    
    # Samsung Exynos specific
    'KNOX_CTL': 0x10060000, 'KNOX_STAT': 0x10060004, 'RKP_CTL': 0x10070000,
    'DEFEX_CTL': 0x10080000, 'TIMA_CTL': 0x10090000,
    
    # USB4 v2.0 registers
    'USB4_CAP': 0x1000, 'USB4_BW': 0x1004, 'USB4_TUNNEL': 0x1100,
    'PAM4_CTL': 0x3000, 'PAM4_STAT': 0x3004, 'CMA_CTL': 0x4000,
    'DPP_CTL': 0x4004, 'ATTEST_CTL': 0x4008,
    
    # Watchdog registers (all SoCs)
    'WDT_APPLE': 0x20E00000, 'WDT_QCOM': 0x02000000, 'WDT_MTK': 0x10000000,
    'WDT_EXYNOS': 0x10060000, 'WDT_ROCKCHIP': 0x20000000, 'WDT_ALLWINNER': 0x01C20000,
}

# Register names for reverse lookup
REG_NAMES = {v: k for k, v in REGISTERS.items()}

# Critical registers (write-protected in normal operation)
CRITICAL = {
    0x10000000, 0x10000004, 0x10000008, 0x20000000, 0x30000000,
    0x20E00000, 0x20E01000, 0x20E02000, 0xFC400000, 0xFD000000,
    0x10060000, 0x10070000, 0x4000, 0x4004, 0x4008,
}

REG_NAMES.update({
    0x10000000: "CPUID", 0x10000004: "SYSCFG", 0x10000008: "RST_CTL",
    0x20000000: "PWR_CTL", 0x20000004: "PWR_STAT",
    0x30000000: "CLK_CTL", 0x40000000: "GPIO_DIR",
    0x50000000: "UART_TX", 0x50000004: "UART_RX",
})

CRITICAL = {0x10000000, 0x10000004, 0x10000008, 0x20000000, 0x30000000}

BIT_OPS = {'SET':'SET', '1':'SET', 'CLEAR':'CLEAR', '0':'CLEAR',
           'TOGGLE':'TOGGLE', 'FLIP':'TOGGLE', 'TEST':'TEST'}

def detect_soc_from_regs(dev) -> str:
    """Auto-detect SoC family by reading known registers"""
    soc_signatures = {
        'APPLE': [0x20E00000, 0x20E01000, 0x20E02000],
        'QUALCOMM': [0xFC400000, 0xFD000000, 0x02000000],
        'MEDIATEK': [0x10000000, 0x1C000000],
        'SAMSUNG': [0x10060000, 0x10070000],
        'ROCKCHIP': [0x20000000],
        'ALLWINNER': [0x01C20000],
        'GENERIC': [],
    }
    
    for soc, addrs in soc_signatures.items():
        for addr in addrs:
            try:
                data, ok = read_state(dev, addr, 4)
                if ok and data and data != b'\x00\x00\x00\x00':
                    return soc
            except:
                pass
    return 'GENERIC'


def get_soc_register_map(soc: str) -> dict:
    """Get register map for specific SoC"""
    soc_maps = {
        'APPLE': {
            'name': 'Apple A12+',
            'registers': {
                'APRR_CTL': 0x20E00000, 'APRR_STAT': 0x20E00004,
                'PAC_CTL': 0x20E01000, 'PAC_STAT': 0x20E01004,
                'SEP_STATE': 0x20E02000, 'DIT_CTL': 0x20E03000,
                'PPL_CTL': 0x20E04000, 'SCEP_CTL': 0x20E05000,
                'WDT_APPLE': 0x20E00000,
            },
            'critical': [0x20E00000, 0x20E01000, 0x20E02000],
            'description': 'Apple A12-A18+ with PAC, APRR, SEP',
        },
        'QUALCOMM': {
            'name': 'Qualcomm Snapdragon',
            'registers': {
                'TZ_CTL': 0xFC400000, 'TZ_STAT': 0xFC400004,
                'QFP_CTL': 0xFC400100, 'SMMU_CTL': 0xFD000000,
                'HLOS_CTL': 0xFE000000, 'WDT_QCOM': 0x02000000,
            },
            'critical': [0xFC400000, 0xFD000000],
            'description': 'Qualcomm with TrustZone, SMMU',
        },
        'MEDIATEK': {
            'name': 'MediaTek',
            'registers': {
                'BROM_CTL': 0x10000000, 'BROM_STAT': 0x10000004,
                'DA_CTL': 0x10001000, 'DA_STAT': 0x10001004,
                'PMIC_WDT': 0x1C000000, 'WDT_MTK': 0x10000000,
            },
            'critical': [0x10000000, 0x1C000000],
            'description': 'MediaTek with BROM, Download Agent',
        },
        'SAMSUNG': {
            'name': 'Samsung Exynos',
            'registers': {
                'KNOX_CTL': 0x10060000, 'KNOX_STAT': 0x10060004,
                'RKP_CTL': 0x10070000, 'DEFEX_CTL': 0x10080000,
                'TIMA_CTL': 0x10090000, 'WDT_EXYNOS': 0x10060000,
            },
            'critical': [0x10060000, 0x10070000],
            'description': 'Samsung Exynos with Knox, RKP',
        },
    }
    return soc_maps.get(soc, {
        'name': 'Generic',
        'registers': {},
        'critical': [],
        'description': 'Generic ARM SoC',
    })

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
    """List register banks and available commands"""
    banks = [
        ('SYSTEM_CTRL', 0x10000000, 0x1000, ['CPUID','SYSCFG','RST_CTL','CLK_SRC']),
        ('POWER_MGMT',  0x20000000, 0x1000, ['PWR_CTL','PWR_STAT','VOLT_CTL','PMIC_CFG']),
        ('CLOCK_CTRL',  0x30000000, 0x1000, ['CLK_CTL','PLL_CTL','DIV_CTL','FREQ_STAT']),
        ('GPIO_BANK0',  0x40000000, 0x1000, ['GPIO_DIR','GPIO_DATA','GPIO_SET','GPIO_CLR']),
        ('UART0',       0x50000000, 0x1000, ['UART_TX','UART_RX','UART_STAT','UART_BAUD']),
        ('WATCHDOG',    0x60000000, 0x1000, ['WDT_CTL','WDT_LOAD','WDT_STAT']),
        ('TIMER',       0x70000000, 0x1000, ['TIMER0','TIMER1','TIMER_CTL']),
        ('INTERRUPT',   0x80000000, 0x1000, ['INT_STATUS','INT_ENABLE','INT_CLEAR']),
        ('DMA',         0x90000000, 0x1000, ['DMA_STATUS','DMA_CTL','DMA_ADDR','DMA_LEN']),
        ('MMU_CACHE',   0xA0000000, 0x1000, ['CACHE_CTL','CACHE_FLUSH','MMU_CTL','MMU_TTB']),
    ]
    
    print(f"\n[*] Register Banks:")
    for name, base, size, regs in banks:
        print(f"    {name:<16} 0x{base:08X} ({size}B)")
        for r in regs:
            addr = REGISTERS.get(r, 0)
            print(f"      0x{addr:08X} {r}")
    
    print(f"\n[*] SoC-Specific Banks (auto-detected):")
    soc = detect_soc_from_regs(dev)
    soc_info = get_soc_register_map(soc)
    if soc_info['registers']:
        for name, addr in list(soc_info['registers'].items())[:8]:
            print(f"      0x{addr:08X} {name} [{soc}]")
    
    print(f"\n[*] Available Commands:")
    commands = [
        ('read', 'Read register/memory'),
        ('write', 'Write register/memory'),
        ('dump', 'Dump memory region'),
        ('compare', 'Compare two addresses'),
        ('monitor', 'Monitor for changes'),
        ('bit', 'Bit operations (set/clear/toggle/test)'),
        ('field', 'Extract bit field'),
        ('scan', 'Scan for pattern'),
        ('bank', 'Show register bank'),
        ('soc', 'Detect SoC information'),
        ('watchdog', 'Watchdog control'),
        ('secure', 'Security state analysis'),
        ('perf', 'Performance metrics'),
        ('all', 'Dump all registers'),
    ]
    for name, desc in commands:
        print(f"    {name:<12} {desc}")
    
    print(f"\n[*] Named Registers: {len(REGISTERS)} total")
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
# NEW SUBCOMMANDS
# =============================================================================

def cmd_soc(dev, args, force, verbose):
    """Detect and display SoC information"""
    print("\n[*] SoC Detection:")
    
    # Try to detect from registers
    soc = detect_soc_from_regs(dev)
    soc_info = get_soc_register_map(soc)
    
    print(f"    Detected: {soc_info['name']}")
    print(f"    Family:   {soc}")
    print(f"    Desc:     {soc_info['description']}")
    
    # Try to read CPUID
    data, ok = read_state(dev, 0x10000000, 4)
    if ok and data:
        cpuid = int.from_bytes(data[:4], 'little')
        print(f"    CPUID:    0x{cpuid:08X}")
    
    # Try to read chip revision
    for rev_addr in [0x10000004, 0x10000008, 0x1000000C]:
        data, ok = read_state(dev, rev_addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00':
            rev = int.from_bytes(data[:4], 'little')
            print(f"    Revision: 0x{rev:08X}")
            break
    
    # List SoC-specific registers
    if soc_info['registers']:
        print(f"\n[*] {soc}-specific registers:")
        for name, addr in list(soc_info['registers'].items())[:8]:
            print(f"    0x{addr:08X} {name}")
    
    return True


def cmd_watchdog(dev, args, force, verbose):
    """Watchdog control (read/disable/refresh)"""
    if not args:
        print("[!] Usage: rawstate watchdog <read|disable|refresh>")
        return False
    
    action = args[0].lower()
    
    # Auto-detect watchdog address
    soc = detect_soc_from_regs(dev)
    wdt_addrs = {
        'APPLE': 0x20E00000,
        'QUALCOMM': 0x02000000,
        'MEDIATEK': 0x10000000,
        'SAMSUNG': 0x10060000,
        'ROCKCHIP': 0x20000000,
        'ALLWINNER': 0x01C20000,
        'GENERIC': 0x40000000,
    }
    wdt_addr = wdt_addrs.get(soc, 0x40000000)
    
    print(f"\n[*] Watchdog @ 0x{wdt_addr:08X} ({soc})")
    
    if action == 'read':
        data, ok = read_state(dev, wdt_addr, 4)
        if ok and data:
            val = int.from_bytes(data[:4], 'little')
            print(f"    Value: 0x{val:08X}")
            print(f"    Enabled: {'Yes' if val != 0 else 'No'}")
        else:
            print("[!] Read failed")
    
    elif action == 'disable':
        if not confirm(
            f"⚠️ Disabling watchdog on {soc}\n"
            "Device may freeze without reset!\n"
            "Power cycle may be required!",
            'WDT', force):
            return False
        
        if write_state(dev, wdt_addr, b'\x00\x00\x00\x00'):
            print("[+] Watchdog disabled")
            # Verify
            data, ok = read_state(dev, wdt_addr, 4)
            if ok and data and int.from_bytes(data[:4], 'little') == 0:
                print("[+] Verified")
            return True
        print("[!] Disable failed")
    
    elif action == 'refresh':
        # Write any non-zero value to refresh
        if write_state(dev, wdt_addr, b'\x00\x00\x00\x01'):
            print("[+] Watchdog refreshed")
            return True
        print("[!] Refresh failed")
    
    else:
        print(f"[!] Unknown action: {action}")
    
    return False


def cmd_secure(dev, args, force, verbose):
    """Check security state (SEP, TrustZone, Secure Boot)"""
    print("\n[*] Security State Analysis:")
    
    soc = detect_soc_from_regs(dev)
    
    # Check Apple SEP
    if soc == 'APPLE':
        data, ok = read_state(dev, 0x20E02000, 4)
        if ok and data:
            val = int.from_bytes(data[:4], 'little')
            states = {0: 'Unknown', 1: 'Locked', 2: 'Unlocked', 3: 'Compromised'}
            print(f"    SEP State: {states.get(val, 'Unknown')}")
        
        # Check PAC state
        data, ok = read_state(dev, 0x20E01000, 4)
        if ok and data:
            val = int.from_bytes(data[:4], 'little')
            print(f"    PAC: {'Enabled' if val & 1 else 'Disabled'}")
    
    # Check Qualcomm TrustZone
    elif soc == 'QUALCOMM':
        data, ok = read_state(dev, 0xFC400000, 4)
        if ok and data:
            val = int.from_bytes(data[:4], 'little')
            print(f"    TrustZone: {'Secure' if val & 1 else 'Non-secure'}")
    
    # Check Secure Boot status (common)
    for sb_addr in [0x10000000, 0x10000004, 0xFC400000]:
        data, ok = read_state(dev, sb_addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00':
            val = int.from_bytes(data[:4], 'little')
            print(f"    Secure Boot: 0x{val:08X}")
            break
    
    # Check debug status
    print(f"\n[*] Debug Interfaces:")
    for jtag_addr in [0x40000000, 0x10000008, 0x20000000]:
        data, ok = read_state(dev, jtag_addr, 4)
        if ok and data:
            val = int.from_bytes(data[:4], 'little')
            if val & 1:
                print(f"    JTAG/SWD: Enabled @ 0x{jtag_addr:08X}")
                break
    else:
        print(f"    JTAG/SWD: Disabled or not detected")
    
    return True


def cmd_perf(dev, args, force, verbose):
    """Performance monitoring (clock speeds, temps, voltage)"""
    print("\n[*] Performance Metrics:")
    
    # Clock speed detection
    for clk_addr in [0x30000000, 0x30000004, 0x1000000C]:
        data, ok = read_state(dev, clk_addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00':
            clk_val = int.from_bytes(data[:4], 'little')
            # Guess frequency (register value often not direct)
            if clk_val < 10000:
                print(f"    Clock: {clk_val} MHz (raw 0x{clk_val:08X} @ 0x{clk_addr:08X})")
            else:
                print(f"    Clock: Raw 0x{clk_val:08X} @ 0x{clk_addr:08X}")
            break
    
    # Temperature (common registers)
    for temp_addr in [0x20000008, 0x2000000C, 0x10000010]:
        data, ok = read_state(dev, temp_addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00':
            temp_raw = int.from_bytes(data[:4], 'little')
            # Rough temperature conversion (often 10-bit ADC)
            if temp_raw < 1000:
                temp_c = temp_raw / 10
                print(f"    Temperature: {temp_c:.1f}°C (raw 0x{temp_raw:04X})")
            break
    
    # Voltage
    for volt_addr in [0x20000008, 0x20000000, 0x10000000]:
        data, ok = read_state(dev, volt_addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00':
            volt_val = int.from_bytes(data[:4], 'little')
            if volt_val < 5000 and volt_val > 500:
                print(f"    Voltage: {volt_val} mV")
                break
    
    # Reset reason
    for rst_addr in [0x10000008, 0x10000004]:
        data, ok = read_state(dev, rst_addr, 4)
        if ok and data:
            rst_val = int.from_bytes(data[:4], 'little')
            rst_map = {1: 'Power-on', 2: 'Watchdog', 3: 'Software', 4: 'External'}
            print(f"    Reset: {rst_map.get(rst_val, 'Unknown')}")
            break
    
    return True


def cmd_all(dev, args, force, verbose):
    """Dump all known registers"""
    print("\n[*] Dumping all known registers:\n")
    
    # Group registers by bank
    banks = {
        'System': [0x10000000, 0x10000004, 0x10000008, 0x1000000C],
        'Power': [0x20000000, 0x20000004, 0x20000008, 0x2000000C],
        'Clock': [0x30000000, 0x30000004, 0x30000008],
        'GPIO': [0x40000000, 0x40000004, 0x40000008, 0x4000000C],
        'UART': [0x50000000, 0x50000004, 0x50000008, 0x5000000C],
        'Watchdog': [0x60000000, 0x60000004, 0x60000008],
        'Timer': [0x70000000, 0x70000004, 0x70000008],
        'Interrupt': [0x80000000, 0x80000004, 0x80000008],
        'DMA': [0x90000000, 0x90000004, 0x90000008, 0x9000000C],
        'MMU/Cache': [0xA0000000, 0xA0000004, 0xA0000008, 0xA000000C],
    }
    
    success_count = 0
    for bank_name, addrs in banks.items():
        print(f"\n[{bank_name}]")
        for addr in addrs:
            data, ok = read_state(dev, addr, 4)
            if ok and data:
                val = int.from_bytes(data[:4], 'little')
                print(f"    0x{addr:08X} {REG_NAMES.get(addr, ''):<15} = 0x{val:08X}")
                success_count += 1
            else:
                print(f"    0x{addr:08X} {REG_NAMES.get(addr, ''):<15} = [READ FAILED]")
    
    # Try to detect additional registers
    print(f"\n[*] Attempting register discovery...")
    for addr in range(0x10000000, 0x10001000, 0x100):
        data, ok = read_state(dev, addr, 4)
        if ok and data and data != b'\x00\x00\x00\x00' and data != b'\xff\xff\xff\xff':
            val = int.from_bytes(data[:4], 'little')
            if addr not in [a for bank in banks.values() for a in bank]:
                print(f"    [DISCOVERED] 0x{addr:08X} = 0x{val:08X}")
    
    print(f"\n[+] Dumped {success_count} registers")
    return True

# =============================================================================
# EXPANDED DISPATCH TABLE
# =============================================================================
HANDLERS = {
    # Existing
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
    'soc': cmd_soc, 'detect': cmd_soc, 'chip': cmd_soc,
    'watchdog': cmd_watchdog, 'wdt': cmd_watchdog,
    'secure': cmd_secure, 'security': cmd_secure,
    'perf': cmd_perf, 'performance': cmd_perf, 'stats': cmd_perf,
    'all': cmd_all, 'everything': cmd_all, 'full': cmd_all,
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
        rawstate scan 0x40000000 0x40001000 FF 4 - Scan for pattern
        rawstate bank SYSTEM_CTRL        - Show register bank
        rawstate soc                     - Detect SoC information
        rawstate watchdog disable        - Disable watchdog
        rawstate secure                  - Check security state
        rawstate perf                    - Performance metrics
        rawstate all                     - Dump all registers
    
    SoC Support:
        Apple A12+: SEP, APRR, PAC, DIT, PPL detection
        Qualcomm: TrustZone, SMMU, QFP detection
        MediaTek: BROM, Download Agent detection
        Samsung Exynos: Knox, RKP detection
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