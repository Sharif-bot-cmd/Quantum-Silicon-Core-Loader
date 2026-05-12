#!/usr/bin/env python3
"""
glitch.py - QSLCL GLITCH Command Module v2.1 (CLEANED)
Hardware fault injection with parameter control and safety checks
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
TIMEOUT = 30.0
MAX_RETRIES = 2
MIN_LVL, MAX_LVL = 1, 10
MIN_ITER, MAX_ITER = 1, 10000
MIN_WIN, MAX_WIN = 1, 10000
MIN_SWP, MAX_SWP = 0, 1000

# Opcodes
OP_CAPABILITIES = 0x00
OP_VOLTAGE = 0x10
OP_CLOCK = 0x20
OP_EM = 0x30
OP_LASER = 0x40
OP_TIMING = 0x50
OP_RESET = 0x60
OP_SCAN = 0x70
OP_MONITOR = 0x80
OP_CALIBRATE = 0x90

# Glitch type definitions
GLITCH_TYPES = {
    'voltage': {'opcode': OP_VOLTAGE, 'risk': 'HIGH',   'desc': 'Power supply manipulation'},
    'clock':   {'opcode': OP_CLOCK,   'risk': 'MEDIUM', 'desc': 'Clock frequency manipulation'},
    'em':      {'opcode': OP_EM,      'risk': 'MEDIUM', 'desc': 'Electromagnetic pulses'},
    'laser':   {'opcode': OP_LASER,   'risk': 'HIGH',   'desc': 'Optical fault injection'},
    'timing':  {'opcode': OP_TIMING,  'risk': 'LOW',    'desc': 'Synchronization attacks'},
    'reset':   {'opcode': OP_RESET,   'risk': 'LOW',    'desc': 'Reset/brownout glitches'},
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


def glitch_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send glitch command"""
    for attempt in range(MAX_RETRIES):
        try:
            if "GLITCH" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "GLITCH", payload, timeout=TIMEOUT)
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


def ping(dev) -> bool:
    """Quick health check"""
    ok, _, _ = glitch_cmd(dev, b"")
    return ok


def validate_params(level: int, iterations: int, window: int, sweep: int) -> bool:
    """Validate glitch parameters"""
    errors = []
    if not MIN_LVL <= level <= MAX_LVL:
        errors.append(f"Level must be {MIN_LVL}-{MAX_LVL}")
    if not MIN_ITER <= iterations <= MAX_ITER:
        errors.append(f"Iterations must be {MIN_ITER}-{MAX_ITER}")
    if not MIN_WIN <= window <= MAX_WIN:
        errors.append(f"Window must be {MIN_WIN}-{MAX_WIN}µs")
    if not MIN_SWP <= sweep <= MAX_SWP:
        errors.append(f"Sweep must be {MIN_SWP}-{MAX_SWP}")
    
    if errors:
        for e in errors: print(f"[!] {e}")
        return False
    
    if level > 7 and iterations > 5000:
        print(f"[!] High level ({level}) with many iterations ({iterations}) - may damage hardware")
        return False
    
    return True


def make_payload(opcode: int, level: int, iterations: int, window: int, sweep: int, target: str = "") -> bytes:
    """Build glitch payload"""
    payload = struct.pack("<B", opcode)
    payload += struct.pack("<B", level)
    payload += struct.pack("<I", iterations)
    payload += struct.pack("<I", window)
    payload += struct.pack("<I", sweep)
    if target:
        payload += target.encode()[:16].ljust(16, b'\x00')
    return payload


class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=40):
        self.total = max(total, 1); self.prefix = prefix
        self.suffix = suffix; self.length = length; self.current = 0
    
    def __enter__(self):
        self.update(0); return self
    
    def __exit__(self, *a): print()
    
    def update(self, n):
        self.current += n
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '─' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {self.suffix}', end='', flush=True)


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, level, iters, window, sweep, safe_mode):
    """List capabilities"""
    print(f"\n[*] Glitch Capabilities:\n")
    for name, info in GLITCH_TYPES.items():
        icon = {'LOW':'🟢', 'MEDIUM':'🟡', 'HIGH':'🔴'}[info['risk']]
        print(f"    {icon} {name:<10} {info['desc']} ({info['risk']} risk)")
    
    print(f"\n[*] Parameters:")
    print(f"    LEVEL       {MIN_LVL}-{MAX_LVL}")
    print(f"    ITERATIONS  {MIN_ITER}-{MAX_ITER}")
    print(f"    WINDOW      {MIN_WIN}-{MAX_WIN}µs")
    print(f"    SWEEP       0-{MAX_SWP} steps")
    return True


def run_glitch(dev, gtype: str, level: int, iterations: int, window: int, sweep: int,
               target: str, safe_mode: bool) -> bool:
    """Execute glitch attack"""
    info = GLITCH_TYPES[gtype]
    
    print(f"\n[*] {gtype.upper()} Glitch: {info['desc']}")
    print(f"    Level: {level}, Iterations: {iterations}, Window: {window}µs")
    
    # Safety for HIGH risk
    if safe_mode and info['risk'] == 'HIGH':
        if not confirm(f"⚠️  {gtype.upper()} glitching is HIGH RISK!\nMay cause PERMANENT HARDWARE DAMAGE!", 
                       gtype.upper(), False):
            return False
    
    if not validate_params(level, iterations, window, sweep):
        return False
    
    payload = make_payload(info['opcode'], level, iterations, window, sweep, target)
    
    results = {'success': 0, 'failed': 0, 'resets': 0, 'errors': [], 'response_times': []}
    
    print(f"\n[*] Running {iterations} glitches...")
    
    try:
        with ProgressBar(iterations, prefix='Glitching', suffix='Complete') as pb:
            for i in range(iterations):
                t0 = time.time()
                try:
                    ok, name, _ = glitch_cmd(dev, payload)
                    rt = (time.time() - t0) * 1000
                    results['response_times'].append(rt)
                    
                    if ok:
                        results['success'] += 1
                    else:
                        results['failed'] += 1
                        if name == 'NO_RESPONSE':
                            results['resets'] += 1
                        results['errors'].append(name)
                except Exception as e:
                    results['failed'] += 1
                    if safe_mode:
                        print(f"\n[!] Error at {i+1}: {e}")
                
                pb.update(1)
                
                if safe_mode and i % 50 == 0 and i > 0:
                    if not ping(dev):
                        print(f"\n[!] Device unresponsive, stopping")
                        results['interrupted'] = True
                        break
                    time.sleep(0.01 * (MAX_LVL - level))
    
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted")
        results['interrupted'] = True
    
    # Results
    total = results['success'] + results['failed']
    if total > 0:
        rate = results['success'] / total * 100
        print(f"\n[+] Results: {results['success']}/{total} ({rate:.1f}%)")
        print(f"    Failed: {results['failed']}, Resets: {results['resets']}")
        if results.get('interrupted'):
            print(f"    [NOTE] Interrupted")
    
    return True


def cmd_voltage(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'voltage', max(level, 2), iters, window, sweep, 
                      args[0] if args else "", safe_mode)

def cmd_clock(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'clock', level, iters, window, sweep,
                      args[0] if args else "", safe_mode)

def cmd_em(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'em', level, iters, window, sweep,
                      args[0] if args else "", safe_mode)

def cmd_laser(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'laser', level, iters, window, sweep,
                      args[0] if args else "", safe_mode)

def cmd_timing(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'timing', level, iters, window, sweep,
                      args[0] if args else "", safe_mode)

def cmd_reset(dev, args, level, iters, window, sweep, safe_mode):
    return run_glitch(dev, 'reset', level, iters, window, sweep,
                      args[0] if args else "", safe_mode)


def cmd_scan(dev, args, level, iters, window, sweep, safe_mode):
    """Automated parameter scan"""
    print(f"\n[*] Glitch Scan: Testing parameters...")
    
    if safe_mode:
        if not confirm("Automated scan may cause instability!", 'SCAN', False):
            return False
    
    results = {'tested': 0, 'successful': []}
    start = time.time()
    
    for lvl in [1, 2, 3, 5]:
        for win in [100, 300, 500, 1000]:
            results['tested'] += 1
            payload = make_payload(OP_VOLTAGE, lvl, 3, win, 0)
            ok, _, _ = glitch_cmd(dev, payload)
            if ok:
                results['successful'].append({'level': lvl, 'window': win})
            if safe_mode:
                time.sleep(0.2)
    
    elapsed = time.time() - start
    
    if results['successful']:
        optimal = min(results['successful'], key=lambda x: (x['level'], abs(x['window']-300)))
        print(f"\n[+] Scan complete in {elapsed:.1f}s")
        print(f"    Tested: {results['tested']}, Successful: {len(results['successful'])}")
        print(f"    Optimal: level={optimal['level']}, window={optimal['window']}µs")
    else:
        print(f"\n[!] No successful parameters found")
    
    return True


def cmd_monitor(dev, args, level, iters, window, sweep, safe_mode):
    """Monitor glitch effects"""
    duration = int(args[0]) if args else 30
    duration = max(5, min(duration, 300))
    
    print(f"\n[*] Monitoring for {duration}s...")
    print("[*] Ctrl+C to stop")
    
    payload = make_payload(OP_MONITOR, level, iters, 0, 0)
    data = {'events': 0, 'timing': 0, 'voltage': 0, 'clock': 0}
    start = time.time()
    
    try:
        with ProgressBar(duration, prefix='Monitoring', suffix='Complete') as pb:
            last = start
            while time.time() - start < duration:
                ok, _, extra = glitch_cmd(dev, payload)
                if ok:
                    data['events'] += 1
                    if extra and len(extra) >= 12:
                        etype = struct.unpack("<I", extra[:4])[0]
                        if etype == 1: data['timing'] += 1
                        elif etype == 2: data['voltage'] += 1
                        elif etype == 3: data['clock'] += 1
                
                now = time.time()
                pb.update(now - last)
                last = now
                time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped")
    
    elapsed = time.time() - start
    print(f"\n[+] Results: {elapsed:.1f}s, {data['events']} events")
    print(f"    Timing: {data['timing']}, Voltage: {data['voltage']}, Clock: {data['clock']}")
    if elapsed > 0:
        print(f"    Rate: {data['events']/elapsed:.2f} events/s")
    
    return True


def cmd_calibrate(dev, args, level, iters, window, sweep, safe_mode):
    """Calibrate parameters"""
    print(f"\n[*] Calibrating...")
    
    results = {'level': 3, 'window': 500, 'success_rate': 0}
    start = time.time()
    tests = []
    
    for lvl in [1, 2, 3, 4, 5]:
        for win in [100, 300, 500, 700, 900]:
            payload = make_payload(OP_VOLTAGE, lvl, 3, win, 0)
            ok, _, _ = glitch_cmd(dev, payload)
            tests.append({'level': lvl, 'window': win, 'ok': ok})
            if safe_mode:
                time.sleep(0.15)
    
    good = [t for t in tests if t['ok']]
    if good:
        best_lvl = max(set(t['level'] for t in good), key=lambda l: sum(1 for t in good if t['level']==l))
        best_win = max(set(t['window'] for t in good), key=lambda w: sum(1 for t in good if t['window']==w))
        results['level'] = best_lvl
        results['window'] = best_win
        results['success_rate'] = len(good) / len(tests) * 100
    
    elapsed = time.time() - start
    print(f"\n[+] Calibration complete in {elapsed:.1f}s")
    print(f"    Optimal: level={results['level']}, window={results['window']}µs")
    print(f"    Success rate: {results['success_rate']:.1f}%")
    
    return True


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'list': cmd_list, 'types': cmd_list, 'capabilities': cmd_list,
    'voltage': cmd_voltage, 'vcc': cmd_voltage, 'power': cmd_voltage,
    'clock': cmd_clock, 'frequency': cmd_clock,
    'em': cmd_em, 'electromagnetic': cmd_em, 'emf': cmd_em,
    'laser': cmd_laser, 'optical': cmd_laser, 'light': cmd_laser,
    'timing': cmd_timing, 'sync': cmd_timing, 'trigger': cmd_timing,
    'reset': cmd_reset, 'brownout': cmd_reset,
    'scan': cmd_scan, 'explore': cmd_scan, 'auto': cmd_scan,
    'monitor': cmd_monitor, 'analyze': cmd_monitor, 'watch': cmd_monitor,
    'calibrate': cmd_calibrate, 'tune': cmd_calibrate, 'optimize': cmd_calibrate,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_glitch(args=None) -> int:
    """
    QSLCL GLITCH - Hardware fault injection
    
    Examples:
        glitch list                          - List capabilities
        glitch voltage --level 3 --iter 100  - Voltage glitching
        glitch clock --level 2 --iter 50     - Clock glitching
        glitch scan                          - Auto parameter scan
        glitch monitor 30                    - Monitor for 30s
        glitch calibrate                     - Find optimal params
        glitch reset --level 5               - Reset glitching
    
    Parameters:
        --level 1-10      Intensity (default: 1)
        --iter 1-10000    Iterations (default: 100)
        --window 1-10000  Timing window µs (default: 1000)
        --sweep 0-1000    Sweep steps (default: 0)
        --no-safe         Disable safety checks
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: glitch <list|voltage|clock|em|laser|timing|reset|scan|monitor|calibrate>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'glitch_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    gargs = getattr(args, 'glitch_args', []) or getattr(args, 'args', []) or []
    
    level = max(MIN_LVL, min(MAX_LVL, getattr(args, 'level', 1) or 1))
    iters = max(MIN_ITER, min(MAX_ITER, getattr(args, 'iter', 100) or 100))
    window = max(MIN_WIN, min(MAX_WIN, getattr(args, 'window', 1000) or 1000))
    sweep = max(MIN_SWP, min(MAX_SWP, getattr(args, 'sweep', 0) or 0))
    safe_mode = not getattr(args, 'no_safe', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Glitch Commands:")
        for name in sorted(set(k for k in HANDLERS if '_' not in k)):
            handler = HANDLERS.get(name)
            doc = (handler.__doc__ or '').strip()
            print(f"    {name:<12} {doc}")
        print(f"\n[*] Risk levels: 🟢 LOW  🟡 MEDIUM  🔴 HIGH")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    try:
        return 0 if handler(dev, gargs, level, iters, window, sweep, safe_mode) else 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] glitch.py - QSLCL GLITCH Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py glitch <subcommand> [options]")