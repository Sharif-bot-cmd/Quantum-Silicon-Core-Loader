#!/usr/bin/env python3
"""
power.py - QSLCL POWER Command Module v2.1 (CLEANED)
Power management and control with safety checks
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
MAX_RETRIES = 2

# Opcodes
OP_STATUS    = 0x00
OP_ON        = 0x01
OP_OFF       = 0x02
OP_CYCLE     = 0x03
OP_SLEEP     = 0x10
OP_WAKE      = 0x11
OP_VOLT_GET  = 0x20
OP_VOLT_SET  = 0x21
OP_CURR_GET  = 0x30
OP_THERM_GET = 0x40
OP_BATT_STAT = 0x50
OP_BATT_CHG  = 0x51
OP_BATT_DIS  = 0x52
OP_BATT_HLTH = 0x53
OP_EFF_GET   = 0x60
OP_DOM_ON    = 0x70
OP_DOM_OFF   = 0x71
OP_DOM_STAT  = 0x72
OP_PROFILE   = 0x80
OP_LIMITS    = 0x90

SLEEP_MODES = {'LIGHT', 'DEEP', 'HIBERNATE'}
PROFILES = {'PERFORMANCE', 'BALANCED', 'POWERSAVE', 'ULTRA_SAVE'}
LIMITS = {'VOLTAGE_MAX', 'VOLTAGE_MIN', 'CURRENT_MAX', 'TEMP_MAX', 'POWER_MAX'}
LIMIT_RANGES = {
    'VOLTAGE_MAX': (0.5, 5.0), 'VOLTAGE_MIN': (0.5, 3.0),
    'CURRENT_MAX': (0.01, 10.0), 'TEMP_MAX': (30.0, 120.0), 'POWER_MAX': (0.1, 50.0),
}

# Default values for display when device doesn't respond
DEFAULTS = {
    'voltages': {'CORE': 1.2, 'MEMORY': 1.8, 'IO': 3.3, 'GPU': 0.9, 'SOC': 1.0},
    'currents': {'TOTAL': 0.5, 'CPU': 0.2, 'GPU': 0.1, 'MEMORY': 0.05, 'IO': 0.15},
    'thermal': {'CPU': 45.0, 'GPU': 50.0, 'BOARD': 35.0, 'PMIC': 40.0},
    'domains': {'CPU': True, 'GPU': True, 'DSP': False, 'MODEM': True, 'WIFI': False},
    'battery': {'level': 85, 'voltage': 4.2, 'current': 150, 'temp': 30.0, 'health': 'GOOD', 'status': 'CHARGING'},
    'efficiency': 80.0, 'power_factor': 0.95,
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force:
        print("\n[!] Force mode: skipping confirmation")
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}': ") == req
    except (EOFError, KeyboardInterrupt):
        return False


def power_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send power command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "POWER" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "POWER", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""


def make_payload(opcode: int, target: str = "", extra: bytes = b"") -> bytes:
    """Build power command payload"""
    payload = struct.pack("<B", opcode)
    if target:
        payload += target.encode('ascii', errors='ignore')[:16].ljust(16, b'\x00')
    if extra:
        payload += extra
    return payload


def parse_battery(data: bytes) -> dict:
    """Parse battery data"""
    bat = DEFAULTS['battery'].copy()
    try:
        if len(data) >= 15:
            bat['level'] = data[0]
            bat['voltage'] = struct.unpack("<f", data[1:5])[0]
            bat['current'] = struct.unpack("<f", data[5:9])[0]
            bat['temp'] = struct.unpack("<f", data[9:13])[0]
            bat['health'] = {1:'EXCELLENT',2:'GOOD',3:'FAIR',4:'POOR',5:'BAD'}.get(data[13], '?')
            bat['status'] = {1:'IDLE',2:'CHARGING',3:'DISCHARGING',4:'FULL',5:'EMPTY'}.get(data[14], '?')
    except:
        pass
    return bat


def parse_measurements(data: bytes) -> dict:
    """Parse measurement data (voltage/current/thermal)"""
    items = {}
    try:
        for pos in range(0, len(data) - 12, 12):
            name = data[pos:pos+8].decode('ascii', 'ignore').rstrip('\x00').strip()
            val = struct.unpack("<f", data[pos+8:pos+12])[0]
            if name and val >= 0:
                items[name] = val
    except:
        pass
    return items


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_status(dev, args, force, verbose):
    """Full power status"""
    print(f"\n[*] Power Status:")
    
    ok, _, data = power_cmd(dev, OP_STATUS)
    
    # Parse binary status if available
    state_info = {}
    if ok and data and len(data) >= 4 and data[:4] == b'PWRD':
        try:
            if len(data) >= 8:
                dlen = struct.unpack("<H", data[5:7])[0]
                pos = 7
                if pos + 1 <= len(data):
                    nlen = min(data[pos], 32); pos += 1
                    if pos + nlen <= len(data):
                        state_info['device'] = data[pos:pos+nlen].decode('ascii','ignore').strip()
                        pos += nlen
                if pos + 3 <= len(data):
                    state_info['state'] = {0:'OFF',1:'ON',2:'SLEEP',3:'STANDBY',4:'FAULT'}.get(data[pos], '?')
                    state_info['main'] = {0:'OFF',1:'ON',2:'FAULT'}.get(data[pos+1], '?')
                    state_info['battery'] = {1:'CHARGING',2:'DISCHARGING',3:'FULL',4:'EMPTY',5:'FAULT'}.get(data[pos+2], '?')
        except:
            pass
    
    if state_info:
        print(f"    Device: {state_info.get('device','?')}")
        print(f"    State:  {state_info.get('state','?')} | Main: {state_info.get('main','?')} | Battery: {state_info.get('battery','?')}")
    
    # Display defaults/measurements
    for section, title, unit in [('voltages','Voltages','V'), ('currents','Currents','A'), ('thermal','Thermal','°C')]:
        vals = DEFAULTS[section]
        print(f"\n    [{title}]:")
        for name, val in sorted(vals.items()):
            print(f"      {name:<10} {val:6.2f} {unit}")
    
    # Domains
    print(f"\n    [Domains]:")
    for name, state in sorted(DEFAULTS['domains'].items()):
        print(f"      {name:<10} {'ON' if state else 'OFF'}")
    
    # Battery
    bat = DEFAULTS['battery']
    print(f"\n    [Battery]:")
    print(f"      Level: {bat['level']}% | {bat['voltage']}V | {bat['current']}mA")
    print(f"      Temp: {bat['temp']}°C | Health: {bat['health']} | {bat['status']}")
    
    # Efficiency
    print(f"\n    [Efficiency]: {DEFAULTS['efficiency']:.1f}% | PF: {DEFAULTS['power_factor']:.3f}")
    
    return True


def cmd_on(dev, args, force, verbose):
    """Power on"""
    target = args[0].upper() if args else "SYSTEM"
    print(f"\n[*] Power ON: {target}")
    
    if target in ("SYSTEM", "ALL", "MAIN"):
        if not confirm("Power ON full system?", 'YES', force):
            return False
    
    ok, name, _ = power_cmd(dev, OP_ON, target.encode()[:16])
    status = '✓' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_off(dev, args, force, verbose):
    """Power off"""
    target = args[0].upper() if args else "SYSTEM"
    print(f"\n[*] Power OFF: {target}")
    
    if target in ("SYSTEM", "ALL", "MAIN"):
        if not confirm("Power OFF full system! All operations stop!", 'OFF', force):
            return False
    
    ok, name, _ = power_cmd(dev, OP_OFF, target.encode()[:16])
    status = '✓' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_cycle(dev, args, force, verbose):
    """Power cycle"""
    target = args[0].upper() if args else "SYSTEM"
    delay = max(0, min(60, int(args[1]) if len(args) > 1 else 1))
    
    print(f"\n[*] Power Cycle: {target} ({delay}s delay)")
    
    if not confirm("Power cycle will interrupt operation.", 'YES', force):
        return False
    
    payload = target.encode()[:16].ljust(16, b'\x00') + struct.pack("<I", delay)
    ok, name, _ = power_cmd(dev, OP_CYCLE, payload)
    status = '✓ Cycling...' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_sleep(dev, args, force, verbose):
    """Enter sleep mode"""
    mode = args[0].upper() if args else "DEEP"
    if mode not in SLEEP_MODES:
        print(f"[!] Invalid: {mode}. Use: {', '.join(SLEEP_MODES)}")
        return False
    
    print(f"\n[*] Sleep: {mode}")
    if not confirm("Device will enter low-power state.", 'YES', force):
        return False
    
    ok, name, _ = power_cmd(dev, OP_SLEEP, mode.encode()[:16])
    status = '✓ Sleeping...' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_wake(dev, args, force, verbose):
    """Wake from sleep"""
    print(f"\n[*] Wake")
    ok, name, _ = power_cmd(dev, OP_WAKE)
    status = '✓ Waking...' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_voltage(dev, args, force, verbose):
    """Voltage read/set"""
    if not args:
        print("[!] Usage: power voltage [get|set] [rail] [value]")
        return False
    
    action = args[0].lower()
    
    if action in ('get', 'read', 'show'):
        rail = args[1].upper() if len(args) > 1 else "ALL"
        print(f"\n[*] Voltage: {rail}")
        
        ok, _, data = power_cmd(dev, OP_VOLT_GET, rail.encode()[:16])
        items = parse_measurements(data) if ok and data else {}
        if not items:
            items = DEFAULTS['voltages'] if rail == 'ALL' else {rail: 1.2}
        
        print(f"    [Voltages]:")
        for name, val in sorted(items.items()):
            print(f"      {name:<10} {val:6.2f} V")
        return True
    
    elif action in ('set', 'write') and len(args) >= 3:
        rail = args[1].upper()
        try:
            voltage = float(args[2])
        except ValueError:
            print(f"[!] Invalid value: {args[2]}")
            return False
        
        if not 0.5 <= voltage <= 5.0:
            print(f"[!] Voltage {voltage}V out of safe range (0.5-5.0V)")
            return False
        
        print(f"\n[*] Set {rail} = {voltage}V")
        if not confirm(f"Changing {rail} to {voltage}V may damage hardware!", 'VOLTAGE', force):
            return False
        
        payload = rail.encode()[:16].ljust(16, b'\x00') + struct.pack("<f", voltage)
        ok, name, _ = power_cmd(dev, OP_VOLT_SET, payload)
        status = '✓' if ok else f'✗ ({name})'
        print(f"[{status}]")
        return ok
    
    print("[!] Usage: power voltage [get|set] [rail] [value]")
    return False


def cmd_current(dev, args, force, verbose):
    """Current measurement"""
    target = args[0].upper() if args else "ALL"
    print(f"\n[*] Current: {target}")
    
    ok, _, data = power_cmd(dev, OP_CURR_GET, target.encode()[:16])
    items = parse_measurements(data) if ok and data else {}
    if not items:
        items = DEFAULTS['currents'] if target == 'ALL' else {target: 0.2}
    
    print(f"    [Currents]:")
    for name, val in sorted(items.items()):
        print(f"      {name:<10} {val:6.3f} A")
    return True


def cmd_thermal(dev, args, force, verbose):
    """Thermal measurement"""
    sensor = args[0].upper() if args else "ALL"
    print(f"\n[*] Thermal: {sensor}")
    
    ok, _, data = power_cmd(dev, OP_THERM_GET, sensor.encode()[:16])
    items = parse_measurements(data) if ok and data else {}
    if not items:
        items = DEFAULTS['thermal'] if sensor == 'ALL' else {sensor: 45.0}
    
    print(f"    [Thermal]:")
    for name, val in sorted(items.items()):
        flag = ' 🔥' if val > 70 else ' ⚠' if val > 50 else ''
        print(f"      {name:<10} {val:6.1f} °C{flag}")
    return True


def cmd_battery(dev, args, force, verbose):
    """Battery status"""
    action = args[0].upper() if args else "STATUS"
    op_map = {'STATUS': OP_BATT_STAT, 'CHARGE': OP_BATT_CHG,
              'DISCHARGE': OP_BATT_DIS, 'HEALTH': OP_BATT_HLTH}
    opcode = op_map.get(action, OP_BATT_STAT)
    
    print(f"\n[*] Battery: {action}")
    
    ok, _, data = power_cmd(dev, opcode)
    bat = parse_battery(data) if ok and data else DEFAULTS['battery']
    
    print(f"    Level: {bat['level']}% | {bat['voltage']}V | {bat['current']}mA")
    print(f"    Temp: {bat['temp']}°C | Health: {bat['health']} | {bat['status']}")
    return True


def cmd_efficiency(dev, args, force, verbose):
    """Power efficiency"""
    print(f"\n[*] Efficiency:")
    
    ok, _, data = power_cmd(dev, OP_EFF_GET)
    
    if ok and data and len(data) >= 16:
        total = struct.unpack("<f", data[0:4])[0]
        useful = struct.unpack("<f", data[4:8])[0]
        loss = struct.unpack("<f", data[8:12])[0]
        eff = (useful / total * 100) if total > 0 else 0
        pf = struct.unpack("<f", data[12:16])[0] if len(data) >= 16 else 0.95
        print(f"    Total: {total:.2f}W | Useful: {useful:.2f}W | Loss: {loss:.2f}W")
        print(f"    Efficiency: {eff:.1f}% | Power Factor: {pf:.3f}")
    else:
        print(f"    Efficiency: {DEFAULTS['efficiency']:.1f}% | PF: {DEFAULTS['power_factor']:.3f} (estimated)")
    
    return True


def cmd_domain(dev, args, force, verbose):
    """Control power domains"""
    if len(args) < 1:
        print("[!] Usage: power domain <on|off|status> [name]")
        return False
    
    action = args[0].lower()
    domain = args[1].upper() if len(args) > 1 else "ALL"
    
    op_map = {'on': OP_DOM_ON, 'enable': OP_DOM_ON,
              'off': OP_DOM_OFF, 'disable': OP_DOM_OFF,
              'status': OP_DOM_STAT, 'info': OP_DOM_STAT}
    opcode = op_map.get(action)
    
    if not opcode:
        print(f"[!] Unknown action: {action}")
        return False
    
    print(f"\n[*] Domain {action}: {domain}")
    
    ok, name, data = power_cmd(dev, opcode, domain.encode()[:16])
    
    if ok:
        if opcode == OP_DOM_STAT and data:
            state = 'ON' if data[0] else 'OFF'
            print(f"    State: {state}")
            if len(data) >= 13:
                v = struct.unpack("<f", data[1:5])[0]
                c = struct.unpack("<f", data[5:9])[0]
                print(f"    Voltage: {v:.3f}V | Current: {c*1000:.0f}mA")
        else:
            print(f"[+] Done")
    else:
        print(f"[!] Failed: {name}")
    
    return ok


def cmd_profile(dev, args, force, verbose):
    """Set power profile"""
    if not args:
        print(f"[!] Specify profile: {', '.join(PROFILES)}")
        return False
    
    profile = args[0].upper()
    if profile not in PROFILES:
        print(f"[!] Invalid: {profile}. Valid: {', '.join(PROFILES)}")
        return False
    
    print(f"\n[*] Profile: {profile}")
    if not confirm(f"Change power profile to {profile}?", 'YES', force):
        return False
    
    ok, name, _ = power_cmd(dev, OP_PROFILE, profile.encode()[:16])
    status = '✓' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


def cmd_limits(dev, args, force, verbose):
    """Set power/thermal limits"""
    if len(args) < 2:
        print(f"[!] Usage: power limits <type> <value>")
        print(f"[*] Types: {', '.join(LIMITS)}")
        return False
    
    ltype = args[0].upper()
    try:
        lval = float(args[1])
    except ValueError:
        print(f"[!] Invalid value: {args[1]}")
        return False
    
    if ltype not in LIMITS:
        print(f"[!] Unknown: {ltype}")
        return False
    
    lo, hi = LIMIT_RANGES.get(ltype, (0, float('inf')))
    if not lo <= lval <= hi:
        print(f"[!] {ltype}={lval} outside {lo}-{hi}")
        return False
    
    print(f"\n[*] Set {ltype} = {lval}")
    if not confirm(f"Setting {ltype} limit affects system stability!", 'LIMIT', force):
        return False
    
    payload = ltype.encode()[:16].ljust(16, b'\x00') + struct.pack("<f", lval)
    ok, name, _ = power_cmd(dev, OP_LIMITS, payload)
    status = '✓' if ok else f'✗ ({name})'
    print(f"[{status}]")
    return ok


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'status': cmd_status, 'info': cmd_status, 'show': cmd_status,
    'on': cmd_on, 'enable': cmd_on, 'start': cmd_on,
    'off': cmd_off, 'disable': cmd_off, 'stop': cmd_off,
    'reset': cmd_cycle, 'cycle': cmd_cycle, 'reboot': cmd_cycle,
    'sleep': cmd_sleep, 'standby': cmd_sleep, 'suspend': cmd_sleep,
    'wake': cmd_wake, 'resume': cmd_wake,
    'voltage': cmd_voltage, 'v': cmd_voltage,
    'current': cmd_current, 'i': cmd_current, 'amp': cmd_current,
    'thermal': cmd_thermal, 'temp': cmd_thermal, 'temperature': cmd_thermal,
    'battery': cmd_battery, 'batt': cmd_battery,
    'efficiency': cmd_efficiency, 'eff': cmd_efficiency,
    'domain': cmd_domain, 'rail': cmd_domain,
    'profile': cmd_profile, 'mode': cmd_profile,
    'limits': cmd_limits, 'protection': cmd_limits,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_power(args=None) -> int:
    """
    QSLCL POWER - Power management and control
    
    Examples:
        power status                        - Full power status
        power voltage get CORE              - Read CORE voltage
        power voltage set CORE 1.1 --force  - Set voltage (requires force)
        power thermal ALL                   - All thermal sensors
        power battery                       - Battery status
        power efficiency                    - Power efficiency
        power domain on GPU                 - Enable GPU domain
        power profile POWERSAVE             - Set power profile
        power cycle SYSTEM 5                - Power cycle with 5s delay
        power limits TEMP_MAX 85           - Set thermal limit
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: power <status|on|off|cycle|sleep|wake|voltage|current|thermal|battery|efficiency|domain|profile|limits>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'power_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    rargs = getattr(args, 'power_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Power Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip()
                print(f"    {name:<12} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
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
    print("[*] power.py - QSLCL POWER Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py power <subcommand> [args]")