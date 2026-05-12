#!/usr/bin/env python3
"""
voltage.py - QSLCL VOLTAGE Command Module v2.1 (CLEANED)
Power management and voltage control with safety checks
"""

import os
import sys
import struct
import time
import signal
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
TIMEOUT = 5.0
MAX_RETRIES = 3
DEFAULT_TOLERANCE_UV = 20000  # 20mV
MAX_VOLTAGE_UV = 5_000_000    # 5V
MIN_VOLTAGE_UV = 0

# Known safe voltage ranges per rail (microvolts)
SAFE_RANGES = {
    'VDD_CORE':     (700000, 1350000),
    'VDD_CPU':      (650000, 1250000),
    'VDD_CPU_BIG':  (650000, 1250000),
    'VDD_CPU_LITTLE': (600000, 1100000),
    'VDD_GPU':      (600000, 1150000),
    'VDD_DDR':      (1050000, 1400000),
    'VDD_MEM':      (850000, 1150000),
    'VDD_IO':       (1500000, 3400000),
    'VDD_AON':      (850000, 1150000),
    'VDD_SRAM':     (700000, 1000000),
    'VDD_PLL':      (800000, 1200000),
    'VDD_MODEM':    (800000, 1200000),
    'VDD_DSP':      (700000, 1100000),
}

CRITICAL_KEYWORDS = ['CORE', 'CPU', 'SOC', 'DDR', 'BOOT']

# Default rail definitions
DEFAULT_RAILS = [
    {'name': 'VDD_CORE', 'desc': 'Core logic', 'min': 800000, 'max': 1300000, 'current': 1100000},
    {'name': 'VDD_CPU',  'desc': 'CPU voltage', 'min': 700000, 'max': 1200000, 'current': 1000000},
    {'name': 'VDD_GPU',  'desc': 'GPU voltage', 'min': 700000, 'max': 1100000, 'current': 900000},
    {'name': 'VDD_DDR',  'desc': 'DRAM voltage', 'min': 1100000, 'max': 1350000, 'current': 1200000},
    {'name': 'VDD_MEM',  'desc': 'Memory controller', 'min': 900000, 'max': 1100000, 'current': 1000000},
    {'name': 'VDD_IO',   'desc': 'I/O voltage', 'min': 1500000, 'max': 3300000, 'current': 1800000},
    {'name': 'VDD_AON',  'desc': 'Always-on domain', 'min': 900000, 'max': 1100000, 'current': 1000000},
]

DEFAULT_DOMAINS = [
    {'name': 'PD_CPU', 'desc': 'CPU domain', 'state': 'ON'},
    {'name': 'PD_GPU', 'desc': 'GPU domain', 'state': 'ON'},
    {'name': 'PD_DSP', 'desc': 'DSP domain', 'state': 'OFF'},
    {'name': 'PD_MODEM', 'desc': 'Modem domain', 'state': 'ON'},
    {'name': 'PD_DISPLAY', 'desc': 'Display domain', 'state': 'ON'},
    {'name': 'PD_AUDIO', 'desc': 'Audio domain', 'state': 'ON'},
    {'name': 'PD_SENSORS', 'desc': 'Sensors domain', 'state': 'OFF'},
    {'name': 'PD_CAMERA', 'desc': 'Camera domain', 'state': 'OFF'},
]

# Opcodes
OP_CAPABILITIES = 0x00
OP_READ = 0x10
OP_SET = 0x20
OP_SET_FV = 0x30
OP_MONITOR = 0x40
OP_CALIBRATE = 0x50
OP_RESET = 0x60
OP_PMIC_READ = 0x70
OP_PMIC_WRITE = 0x71


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_voltage(val: str, unit: str = "V") -> Tuple[bool, int, str]:
    """Parse voltage string to microvolts"""
    try:
        v = float(''.join(c for c in val if c.isdigit() or c in '.-eE'))
        unit = unit.upper()
        if unit in ('V', 'VOLTS'): uv = int(v * 1_000_000)
        elif unit in ('MV', 'MILLIVOLTS'): uv = int(v * 1_000)
        elif unit in ('UV', 'MICROVOLTS'): uv = int(v)
        else: return False, 0, f"Unknown unit: {unit}"
        
        if uv < MIN_VOLTAGE_UV or uv > MAX_VOLTAGE_UV:
            return False, uv, f"Voltage {v}{unit} outside 0-5V range"
        return True, uv, ""
    except (ValueError, OverflowError) as e:
        return False, 0, f"Invalid voltage: {e}"


def parse_freq(val: str) -> Tuple[bool, int, str]:
    """Parse frequency to Hz"""
    s = val.upper().strip()
    for sfx, mul in [('GHZ', 1_000_000_000), ('G', 1_000_000_000),
                      ('MHZ', 1_000_000), ('M', 1_000_000),
                      ('KHZ', 1_000), ('K', 1_000), ('HZ', 1), ('H', 1)]:
        if s.endswith(sfx):
            try: return True, int(float(s[:-len(sfx)]) * mul), ""
            except: pass
    try: return True, int(float(s)), ""
    except: return False, 0, f"Invalid frequency: {val}"


def check_safety(rail: str, uv: int) -> Tuple[bool, str]:
    """Check voltage against safe ranges"""
    for known, (lo, hi) in SAFE_RANGES.items():
        if known in rail.upper() or rail.upper() in known:
            if lo <= uv <= hi:
                return True, f"OK ({lo/1e6:.2f}V-{hi/1e6:.2f}V)"
            return False, f"OUT OF RANGE: {uv/1e6:.3f}V not in {lo/1e6:.2f}V-{hi/1e6:.2f}V"
    
    if uv < 500_000: return False, f"Unusually low ({uv/1e6:.3f}V)"
    if uv > 4_000_000: return False, f"Unusually high ({uv/1e6:.3f}V)"
    return True, "Unknown rail - proceed with caution"


def is_critical(rail: str) -> bool:
    return any(kw in rail.upper() for kw in CRITICAL_KEYWORDS)


def confirm(msg: str, req: str, force: bool) -> bool:
    if force:
        print(f"\n[!] Force mode: skipping confirmation")
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}' to confirm: ") == req
    except (EOFError, KeyboardInterrupt):
        return False


# =============================================================================
# VOLTAGE DISPATCH
# =============================================================================
def volt_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send voltage command to device"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "VOLTAGE" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "VOLTAGE", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.2 * (attempt + 1))
    
    return False, "NO_RESPONSE", b""


def parse_vdata(data: bytes) -> dict:
    """Parse single voltage reading"""
    r = {'uv': -1, 'v': -1.0, 'status': '?', 'ma': 0, 'temp': 0}
    try:
        if len(data) >= 8:
            r['uv'] = struct.unpack("<I", data[0:4])[0]
            r['v'] = r['uv'] / 1_000_000
            r['status'] = data[4:8].decode('ascii', errors='ignore').rstrip('\x00').strip() or '?'
        if len(data) >= 12:
            r['ma'] = struct.unpack("<I", data[8:12])[0]
        if len(data) >= 16:
            r['temp'] = struct.unpack("<i", data[12:16])[0] / 1000
    except:
        pass
    return r


def parse_all_v(data: bytes) -> dict:
    """Parse multiple voltage readings"""
    result = {}
    try:
        pos = 0
        while pos + 16 <= len(data) and len(result) < 50:
            name = data[pos:pos+8].decode('ascii', errors='ignore').rstrip('\x00').strip()
            uv = struct.unpack("<I", data[pos+8:pos+12])[0]
            status = data[pos+12:pos+16].decode('ascii', errors='ignore').rstrip('\x00').strip() or '?'
            if name and len(name) >= 2:
                result[name] = {'v': uv/1e6, 'uv': uv, 'status': status}
            pos += 16
    except:
        pass
    return result


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force, verbose):
    """List voltage rails and domains"""
    print(f"\n[*] Voltage System:")
    
    # Read all rails
    ok, _, data = volt_cmd(dev, OP_READ)
    if ok:
        voltages = parse_all_v(data)
    else:
        voltages = {}
    
    rails = []
    for r in DEFAULT_RAILS:
        name = r['name']
        v = voltages.get(name, {})
        rails.append({
            'name': name,
            'desc': r['desc'],
            'v': v.get('v', r['current']/1e6),
            'min': r['min']/1e6,
            'max': r['max']/1e6,
            'status': v.get('status', '?'),
        })
    
    print(f"\n  {'Name':<18} {'Voltage':<10} {'Range':<16} {'Status':<10} Description")
    print(f"  {'-'*18} {'-'*10} {'-'*16} {'-'*10} {'-'*20}")
    for r in rails:
        v_str = f"{r['v']:.3f}V"
        rng = f"{r['min']:.2f}V-{r['max']:.2f}V"
        print(f"  {r['name']:<18} {v_str:<10} {rng:<16} {r['status']:<10} {r['desc'][:20]}")
    
    print(f"\n[*] Power Domains:")
    for d in DEFAULT_DOMAINS:
        icon = '🟢' if d['state'] == 'ON' else '🔴'
        print(f"    {icon} {d['name']:<18} {d['desc']}")
    
    return 0


def cmd_read(dev, args, force, verbose):
    """Read voltage(s)"""
    rail = args[0].upper() if args else "ALL"
    
    if rail == "ALL":
        print(f"\n[*] All voltages:")
        ok, _, data = volt_cmd(dev, OP_READ)
        if ok:
            voltages = parse_all_v(data)
            if voltages:
                for name in sorted(voltages):
                    v = voltages[name]
                    print(f"    {name:<18} {v['v']:.3f}V [{v['status']}]")
            else:
                # Individual reads
                for r in DEFAULT_RAILS:
                    d = r['name'].encode()[:8].ljust(8, b'\x00')
                    ok, _, data = volt_cmd(dev, OP_READ, d)
                    if ok:
                        v = parse_vdata(data)
                        print(f"    {r['name']:<18} {v['v']:.3f}V [{v['status']}]")
        else:
            print("    Read failed")
        return 0
    
    print(f"\n[*] Reading: {rail}")
    d = rail.encode()[:8].ljust(8, b'\x00')
    ok, _, data = volt_cmd(dev, OP_READ, d)
    
    if ok:
        v = parse_vdata(data)
        print(f"    Voltage:  {v['v']:.3f}V")
        print(f"    Status:   {v['status']}")
        if v['ma']: print(f"    Current:  {v['ma']}mA")
        if v['temp']: print(f"    Temp:     {v['temp']:.1f}°C")
        return 0
    
    print(f"    Read failed")
    return 1


def cmd_set(dev, args, force, verbose):
    """Set voltage"""
    if len(args) < 2:
        print("[!] Usage: voltage set <rail> <value> [V|mV|uV]")
        return 1
    
    rail = args[0].upper()
    unit = args[2].upper() if len(args) > 2 else "V"
    
    ok, uv, err = parse_voltage(args[1], unit)
    if not ok:
        print(f"[!] {err}")
        return 1
    
    v_str = f"{uv/1e6:.3f}V"
    print(f"\n[*] Setting {rail} = {v_str}")
    
    # Safety
    safe, msg = check_safety(rail, uv)
    if not safe:
        print(f"[!] {msg}")
        if not force: return 1
        print(f"[!] Proceeding with force...")
    
    if is_critical(rail):
        if not confirm(f"CRITICAL RAIL: {rail} → {v_str}\nMay cause PERMANENT DAMAGE!", 'VOLTAGE', force):
            return 0
    
    d = rail.encode()[:8].ljust(8, b'\x00') + struct.pack("<I", uv)
    ok, _, data = volt_cmd(dev, OP_SET, d)
    
    if ok:
        print(f"[+] Set: {rail} = {v_str}")
        return 0
    
    print(f"[!] Set failed")
    return 1


def cmd_scale(dev, args, force, verbose):
    """Scale voltage or set frequency-voltage pair"""
    if len(args) < 2:
        print("[!] Usage: voltage scale <rail> <factor> OR <rail> <freq> <volt>")
        return 1
    
    rail = args[0].upper()
    
    if len(args) == 2:
        # Simple scaling
        try:
            factor = float(args[1])
            if factor <= 0:
                print("[!] Factor must be positive")
                return 1
        except ValueError:
            print(f"[!] Invalid factor: {args[1]}")
            return 1
        
        # Read current
        d = rail.encode()[:8].ljust(8, b'\x00')
        ok, _, data = volt_cmd(dev, OP_READ, d)
        if not ok:
            print("[!] Cannot read current voltage")
            return 1
        
        v = parse_vdata(data)
        cur_uv = v['uv']
        if cur_uv <= 0:
            print("[!] Invalid current reading")
            return 1
        
        new_uv = int(cur_uv * factor)
        print(f"[*] {rail}: {cur_uv/1e6:.3f}V → {new_uv/1e6:.3f}V (×{factor})")
        
        safe, msg = check_safety(rail, new_uv)
        if not safe and not force:
            print(f"[!] {msg}")
            return 1
        
        d = rail.encode()[:8].ljust(8, b'\x00') + struct.pack("<I", new_uv)
        ok, _, _ = volt_cmd(dev, OP_SET, d)
        
        if ok:
            print(f"[+] Scaled to {new_uv/1e6:.3f}V")
            return 0
        print("[!] Scale failed")
        return 1
    
    else:
        # Frequency-voltage pair
        ok_f, hz, _ = parse_freq(args[1])
        ok_v, uv, err = parse_voltage(args[2], args[3].upper() if len(args) > 3 else "V")
        
        if not ok_f: print(f"[!] Invalid frequency: {args[1]}"); return 1
        if not ok_v: print(f"[!] {err}"); return 1
        
        print(f"[*] F-V: {rail} @ {hz/1e6:.0f}MHz = {uv/1e6:.3f}V")
        
        safe, msg = check_safety(rail, uv)
        if not safe and not force:
            print(f"[!] {msg}")
            return 1
        
        d = rail.encode()[:8].ljust(8, b'\x00') + struct.pack("<II", hz, uv)
        ok, _, _ = volt_cmd(dev, OP_SET_FV, d)
        
        if ok: print("[+] F-V pair set"); return 0
        print("[!] F-V set failed"); return 1


def cmd_monitor(dev, args, force, verbose):
    """Real-time voltage monitoring"""
    rail = args[0].upper() if args else "ALL"
    duration = max(1, min(3600, float(args[1]) if len(args) > 1 else 30))
    interval = max(0.1, min(60, float(args[2]) if len(args) > 2 else 1.0))
    
    print(f"\n[*] Monitoring {rail} for {duration}s (every {interval}s)")
    print("[*] Ctrl+C to stop\n")
    
    interrupted = False
    def handler(s, f):
        nonlocal interrupted
        interrupted = True
    
    old = signal.signal(signal.SIGINT, handler)
    start = time.time()
    samples = 0
    
    try:
        while time.time() - start < duration and not interrupted:
            elapsed = time.time() - start
            
            if rail == "ALL":
                ok, _, data = volt_cmd(dev, OP_READ)
                if ok:
                    voltages = parse_all_v(data)
                    ts = f"[{elapsed:5.1f}s]"
                    for name in sorted(voltages):
                        v = voltages[name]
                        print(f"  {ts} {name:<16} {v['v']:.3f}V [{v['status']}]")
                        ts = "        "
                else:
                    print(f"[{elapsed:5.1f}s] Read failed")
            else:
                d = rail.encode()[:8].ljust(8, b'\x00')
                ok, _, data = volt_cmd(dev, OP_READ, d)
                if ok:
                    v = parse_vdata(data)
                    print(f"[{elapsed:5.1f}s] {rail}: {v['v']:.3f}V [{v['status']}]")
                else:
                    print(f"[{elapsed:5.1f}s] {rail}: Read failed")
            
            samples += 1
            remaining = start + (samples * interval) - time.time()
            if remaining > 0:
                time.sleep(remaining)
    
    finally:
        signal.signal(signal.SIGINT, old)
    
    print(f"\n[*] Done: {samples} samples in {time.time()-start:.1f}s")
    return 0


def cmd_limits(dev, args, force, verbose):
    """Show safe voltage ranges"""
    filt = args[0].upper() if args else None
    
    print(f"\n[*] Safe Voltage Ranges:\n")
    print(f"  {'Rail':<20} {'Min':<10} {'Max':<10}")
    print(f"  {'-'*20} {'-'*10} {'-'*10}")
    
    for name, (lo, hi) in sorted(SAFE_RANGES.items()):
        if filt and filt not in name: continue
        print(f"  {name:<20} {lo/1e6:.2f}V{'':<5} {hi/1e6:.2f}V")
    
    return 0


def cmd_calibrate(dev, args, force, verbose):
    """Calibrate voltage measurement"""
    cal = args[0].upper() if args else "AUTO"
    print(f"\n[*] Calibrating: {cal}")
    
    d = cal.encode()[:8].ljust(8, b'\x00')
    ok, _, _ = volt_cmd(dev, OP_CALIBRATE, d)
    
    if ok: print("[+] Calibration complete"); return 0
    print("[!] Calibration failed"); return 1


def cmd_reset(dev, args, force, verbose):
    """Reset voltages to defaults"""
    scope = args[0].upper() if args else "ALL"
    print(f"\n[*] Resetting: {scope}")
    
    if scope == "ALL" and not confirm("Reset ALL voltages to defaults?", 'RESET', force):
        return 0
    
    d = scope.encode()[:8].ljust(8, b'\x00')
    ok, _, _ = volt_cmd(dev, OP_RESET, d)
    
    if ok: print("[+] Reset complete"); return 0
    print("[!] Reset failed"); return 1


def cmd_pmic(dev, args, force, verbose):
    """Direct PMIC register access"""
    if len(args) < 2:
        print("[!] Usage: voltage pmic <reg> <read|write> [value]")
        return 1
    
    try:
        reg = int(args[0], 16) if args[0].lower().startswith('0x') else int(args[0])
        if not 0 <= reg <= 0xFF:
            print("[!] Register 0x00-0xFF only")
            return 1
    except ValueError:
        print(f"[!] Invalid register: {args[0]}")
        return 1
    
    op = args[1].lower()
    
    if op == 'read':
        print(f"[*] PMIC reg 0x{reg:02X}")
        d = struct.pack("<B", reg)
        ok, _, data = volt_cmd(dev, OP_PMIC_READ, d)
        if ok and data:
            print(f"[+] 0x{reg:02X} = 0x{data[0]:02X}")
            return 0
        print("[!] Read failed")
        return 1
    
    elif op == 'write':
        if len(args) < 3:
            print("[!] Specify value")
            return 1
        try:
            val = int(args[2], 16) if args[2].lower().startswith('0x') else int(args[2])
            if not 0 <= val <= 0xFF:
                print("[!] Value 0x00-0xFF only")
                return 1
        except ValueError:
            print(f"[!] Invalid value: {args[2]}")
            return 1
        
        if not confirm(f"Write 0x{val:02X} to PMIC reg 0x{reg:02X}?\nIncorrect PMIC writes can DAMAGE hardware!", 'PMIC', force):
            return 0
        
        d = struct.pack("<BB", reg, val)
        ok, _, _ = volt_cmd(dev, OP_PMIC_WRITE, d)
        
        if ok: print(f"[+] Wrote 0x{val:02X} to 0x{reg:02X}"); return 0
        print("[!] Write failed"); return 1
    
    else:
        print(f"[!] Unknown operation: {op}. Use 'read' or 'write'")
        return 1


# =============================================================================
# SUBCOMMAND TABLE
# =============================================================================
SUBCOMMANDS = {
    'list': cmd_list, 'ls': cmd_list, 'rails': cmd_list,
    'read': cmd_read, 'get': cmd_read, 'measure': cmd_read,
    'set': cmd_set, 'write': cmd_set, 'adjust': cmd_set,
    'monitor': cmd_monitor, 'watch': cmd_monitor, 'log': cmd_monitor,
    'scale': cmd_scale, 'vscale': cmd_scale, 'dvs': cmd_scale,
    'limits': cmd_limits, 'range': cmd_limits, 'spec': cmd_limits,
    'calibrate': cmd_calibrate, 'cal': cmd_calibrate,
    'reset': cmd_reset, 'default': cmd_reset, 'normal': cmd_reset,
    'pmic': cmd_pmic, 'register': cmd_pmic, 'reg': cmd_pmic,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_voltage(args=None) -> int:
    """QSLCL VOLTAGE - Power management and voltage control"""
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: voltage <list|read|set|monitor|scale|limits|pmic> [args]")
        return 1
    
    # Device
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Get subcommand
    sub = getattr(args, 'voltage_subcommand', '') or getattr(args, 'subcmd', '') or ''
    sub = sub.lower().strip()
    
    if not sub or sub in ('help', '?'):
        print("[*] Voltage Subcommands:")
        for cmd in sorted(set(SUBCOMMANDS.values()), key=lambda f: f.__name__):
            doc = cmd.__doc__ or ''
            print(f"    {cmd.__name__[4:]:<15} {doc}")
        return 0
    
    handler = SUBCOMMANDS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        print(f"[*] Valid: {', '.join(sorted(SUBCOMMANDS))}")
        return 1
    
    vargs = getattr(args, 'voltage_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    try:
        return handler(dev, vargs, force, verbose)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        return 130
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
    print("[*] voltage.py - QSLCL VOLTAGE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py voltage <subcommand> [args]")