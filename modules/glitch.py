#!/usr/bin/env python3
"""
glitch.py - QSLCL GLITCH Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, safety checks,
       parameter validation, result analysis, monitoring
"""

import os
import sys
import struct
import time
import random
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
_ProgressBar = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        ProgressBar as _qslcl_ProgressBar,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _auto_loader_if_needed = _qslcl_auto_loader
    _qslcl_dispatch = _qslcl_dispatch_fn
    _decode_runtime_result = _qslcl_decode_runtime
    _QSLCLCMD_DB = _qslcl_cmd_db
    _ProgressBar = _qslcl_ProgressBar
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
            ProgressBar as _qslcl_ProgressBar,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _auto_loader_if_needed = _qslcl_auto_loader
        _qslcl_dispatch = _qslcl_dispatch_fn
        _decode_runtime_result = _qslcl_decode_runtime
        _QSLCLCMD_DB = _qslcl_cmd_db
        _ProgressBar = _qslcl_ProgressBar
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
        print("[!] Running in standalone mode"); _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
GLITCH_TIMEOUT = 30.0
MAX_RETRIES = 2
MIN_LEVEL = 1; MAX_LEVEL = 10
MIN_ITERATIONS = 1; MAX_ITERATIONS = 10000
MIN_WINDOW = 1; MAX_WINDOW = 10000
MIN_SWEEP = 0; MAX_SWEEP = 1000

# Glitch opcodes
class GlitchOp:
    CAPABILITIES = 0x00
    VOLTAGE = 0x10
    CLOCK = 0x20
    EM = 0x30
    LASER = 0x40
    TIMING = 0x50
    RESET = 0x60
    SCAN = 0x70
    MONITOR = 0x80
    CALIBRATE = 0x90

# Glitch type definitions
GLITCH_TYPES = {
    'VOLTAGE': {'opcode': GlitchOp.VOLTAGE, 'risk': 'HIGH', 
                'desc': 'Power supply manipulation', 'confirm': 'VOLTAGE'},
    'CLOCK':   {'opcode': GlitchOp.CLOCK, 'risk': 'MEDIUM',
                'desc': 'Clock frequency manipulation', 'confirm': 'CLOCK'},
    'EM':      {'opcode': GlitchOp.EM, 'risk': 'MEDIUM',
                'desc': 'Electromagnetic pulses', 'confirm': 'EM'},
    'LASER':   {'opcode': GlitchOp.LASER, 'risk': 'HIGH',
                'desc': 'Optical fault injection', 'confirm': 'LASER'},
    'TIMING':  {'opcode': GlitchOp.TIMING, 'risk': 'LOW',
                'desc': 'Synchronization attacks', 'confirm': 'TIMING'},
    'RESET':   {'opcode': GlitchOp.RESET, 'risk': 'LOW',
                'desc': 'Reset/brownout glitches', 'confirm': 'RESET'},
}

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'; CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Local ProgressBar fallback
# =============================================================================
class LocalProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50):
        self.total = max(total, 1); self.prefix = prefix
        self.suffix = suffix; self.length = length; self.current = 0
    def __enter__(self): return self
    def __exit__(self, *a):
        if hasattr(self, '_started'): print()
    def update(self, n):
        self.current += n
        pct = min(100, 100 * self.current / self.total)
        filled = int(self.length * self.current // self.total)
        print(f'\r{self.prefix} |{"█"*filled}{"-"*(self.length-filled)}| {pct:.0f}% {self.suffix}', end='', flush=True)

def _get_progress(total, **kw):
    if _use_qslcl and _ProgressBar: return _ProgressBar(total, **kw)
    return LocalProgressBar(total, **kw)


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.BRIGHT_RED}{msg}{C.RESET}")
    try: return input(f"    Type '{req}': ") == req
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
    for attempt in range(MAX_RETRIES):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or GLITCH_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or GLITCH_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Payload builder
# =============================================================================
def _make_glitch_payload(opcode: int, level: int, iterations: int, 
                         window: int, sweep: int, target: str = "") -> bytes:
    payload = struct.pack("<B", opcode)
    payload += struct.pack("<B", level)
    payload += struct.pack("<I", iterations)
    payload += struct.pack("<I", window)
    payload += struct.pack("<I", sweep)
    if target:
        payload += target.encode('ascii', errors='ignore')[:16].ljust(16, b'\x00')
    return payload


# =============================================================================
# FIXED: Parameter validation
# =============================================================================
def _validate_params(level: int, iterations: int, window: int, sweep: int, 
                     safe_mode: bool) -> bool:
    """Validate glitch parameters."""
    errors = []
    if not MIN_LEVEL <= level <= MAX_LEVEL:
        errors.append(f"Level must be {MIN_LEVEL}-{MAX_LEVEL}")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        errors.append(f"Iterations must be {MIN_ITERATIONS}-{MAX_ITERATIONS}")
    if not MIN_WINDOW <= window <= MAX_WINDOW:
        errors.append(f"Window must be {MIN_WINDOW}-{MAX_WINDOW}µs")
    if not MIN_SWEEP <= sweep <= MAX_SWEEP:
        errors.append(f"Sweep must be {MIN_SWEEP}-{MAX_SWEEP}")
    
    if errors:
        for e in errors: print(f"{C.RED}[!] {e}{C.RESET}")
        return False
    
    if level > 7 and iterations > 5000:
        print(f"{C.YELLOW}[!] High level ({level}) with many iterations ({iterations}) - may damage hardware{C.RESET}")
        if safe_mode:
            response = input("    Continue? (yes/no): ")
            if response.lower() not in ('yes','y'): return False
    
    return True


# =============================================================================
# FIXED: Device health check
# =============================================================================
def _check_device_health(dev) -> bool:
    """Quick device health check."""
    ok, _, _ = _dispatch(dev, "PING", b"", timeout=3)
    return ok


# =============================================================================
# FIXED: Capabilities
# =============================================================================
def _get_capabilities(dev) -> Dict:
    caps = {
        'device_name': 'QSLCL Device',
        'architecture': 'Generic',
        'glitch_support': True,
        'safety_features': 'Basic',
        'glitch_types': [
            {'name':n, 'description':t['desc'], 'risk':t['risk']} 
            for n,t in GLITCH_TYPES.items()
        ],
        'glitch_parameters': [
            {'name':'LEVEL','range':f'{MIN_LEVEL}-{MAX_LEVEL}'},
            {'name':'ITERATIONS','range':f'{MIN_ITERATIONS}-{MAX_ITERATIONS}'},
            {'name':'WINDOW','range':f'{MIN_WINDOW}-{MAX_WINDOW}µs'},
            {'name':'SWEEP','range':f'{MIN_SWEEP}-{MAX_SWEEP} steps'},
        ],
    }
    return caps


# =============================================================================
# FIXED: Result analysis
# =============================================================================
def _analyze_results(results: Dict, glitch_type: str):
    """Display glitch results."""
    print(f"\n{C.BOLD}[+] {glitch_type.upper()} Results:{C.RESET}")
    
    total = results.get('success', 0) + results.get('failed', 0)
    if total > 0:
        rate = results['success'] / total * 100
        color = C.GREEN if rate > 50 else C.YELLOW if rate > 20 else C.RED
        print(f"    Success: {results['success']}/{total} ({color}{rate:.1f}%{C.RESET})")
    
    print(f"    Failed:  {results.get('failed', 0)}")
    print(f"    Resets:  {results.get('resets', 0)}")
    print(f"    Anomalies: {results.get('anomalies', 0)}")
    
    if results.get('errors'):
        unique = set(results['errors'])
        print(f"    Error codes: {len(unique)} unique")
    
    if results.get('response_times'):
        avg = sum(results['response_times']) / len(results['response_times'])
        print(f"    Avg response: {avg:.1f}ms")
    
    if results.get('interrupted'):
        print(f"    {C.YELLOW}[NOTE] Interrupted{C.RESET}")


def _analyze_scan(results: Dict):
    """Display scan results."""
    print(f"\n{C.BOLD}[+] Scan Results:{C.RESET}")
    print(f"    Parameters tested: {results.get('tested', 0)}")
    print(f"    Duration: {results.get('duration', 0):.1f}s")
    print(f"    Successful: {len(results.get('successful', []))}")
    
    if results.get('optimal'):
        opt = results['optimal']
        print(f"    Optimal: level={opt.get('level','?')}, window={opt.get('window','?')}µs")


def _analyze_monitor(data: Dict):
    """Display monitoring results."""
    print(f"\n{C.BOLD}[+] Monitor Results:{C.RESET}")
    print(f"    Duration: {data.get('duration', 0):.1f}s")
    print(f"    Events: {data.get('events', 0)}")
    print(f"    Timing anomalies: {data.get('timing', 0)}")
    print(f"    Voltage dips: {data.get('voltage', 0)}")
    print(f"    Clock skews: {data.get('clock', 0)}")
    
    if data.get('events', 0) > 0 and data.get('duration', 0) > 0:
        rate = data['events'] / data['duration']
        print(f"    Rate: {rate:.2f} events/s")


def _analyze_calibration(results: Dict):
    """Display calibration results."""
    print(f"\n{C.BOLD}[+] Calibration Results:{C.RESET}")
    print(f"    Time: {results.get('time', 0):.1f}s")
    print(f"    Optimal level: {results.get('level', '?')}")
    print(f"    Optimal window: {results.get('window', '?')}µs")
    print(f"    Success rate: {results.get('success_rate', 0):.1f}%")


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def glitch_list(dev, args, level=1, iterations=100, window=1000, sweep=0, safe_mode=True) -> bool:
    caps = _get_capabilities(dev)
    
    print(f"\n{C.BOLD}[+] Glitch Capabilities{C.RESET}")
    print(f"    Device: {caps['device_name']}")
    print(f"    Support: {'Yes' if caps['glitch_support'] else 'No'}")
    
    types = caps.get('glitch_types', [])
    if types:
        print(f"\n{C.BOLD}[+] Types:{C.RESET}")
        for t in types:
            icon = {'LOW':'🟢','MEDIUM':'🟡','HIGH':'🔴'}.get(t.get('risk','?'),'❓')
            print(f"    {icon} {t['name']:<12} {t.get('description','')}")
    
    params = caps.get('glitch_parameters', [])
    if params:
        print(f"\n{C.BOLD}[+] Parameters:{C.RESET}")
        for p in params:
            print(f"    {p['name']:<14} {p.get('range','?')}")
    return True


def _run_glitch(dev, args, glitch_type: str, level: int, iterations: int,
                window: int, sweep: int, safe_mode: bool) -> bool:
    """Generic glitch execution."""
    info = GLITCH_TYPES[glitch_type]
    
    print(f"\n{C.CYAN}[*] {glitch_type} Glitch{C.RESET}")
    print(f"    {info['desc']} (Risk: {info['risk']})")
    print(f"    Level: {level}, Iterations: {iterations}, Window: {window}µs, Sweep: {sweep}")
    
    # Safety
    if safe_mode and info['risk'] in ('HIGH',):
        if not _confirm(
            f"⚠️  {glitch_type} glitching is {info['risk']} RISK!\n"
            f"May cause PERMANENT HARDWARE DAMAGE!",
            info['confirm'], False
        ):
            return False
    
    if not _validate_params(level, iterations, window, sweep, safe_mode):
        return False
    
    target = args[0] if args else ""
    payload = _make_glitch_payload(info['opcode'], level, iterations, window, sweep, target)
    
    results = {'success':0, 'failed':0, 'resets':0, 'anomalies':0, 'errors':[], 'response_times':[]}
    
    print(f"\n[*] Executing {iterations} glitches...")
    
    try:
        with _get_progress(iterations, prefix='Glitching', suffix='Complete') as pb:
            for i in range(iterations):
                t0 = time.time()
                try:
                    ok, name, extra = _dispatch(dev, "GLITCH", payload, timeout=5)
                    rt = (time.time() - t0) * 1000
                    results['response_times'].append(rt)
                    
                    if ok: results['success'] += 1
                    else:
                        results['failed'] += 1
                        if name == 'NO_RESPONSE': results['resets'] += 1
                        results['errors'].append(name)
                except Exception as e:
                    results['failed'] += 1
                    results['anomalies'] += 1
                    if safe_mode: print(f"\n[!] Glitch {i+1} error: {e}")
                
                pb.update(1)
                
                if safe_mode and i < iterations - 1:
                    time.sleep(max(0.005, (MAX_LEVEL - level) * 0.003))
                    
                    if i % 50 == 0 and not _check_device_health(dev):
                        print(f"\n{C.RED}[!] Device health check failed, stopping{C.RESET}")
                        results['interrupted'] = True
                        break
    
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}")
        results['interrupted'] = True
    
    _analyze_results(results, glitch_type)
    return True


# Individual glitch type handlers
def glitch_voltage(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'VOLTAGE', level, iterations, window, sweep, safe_mode)
def glitch_clock(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'CLOCK', level, iterations, window, sweep, safe_mode)
def glitch_em(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'EM', level, iterations, window, sweep, safe_mode)
def glitch_laser(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'LASER', level, iterations, window, sweep, safe_mode)
def glitch_timing(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'TIMING', level, iterations, window, sweep, safe_mode)
def glitch_reset(dev, args, level, iterations, window, sweep, safe_mode):
    return _run_glitch(dev, args, 'RESET', level, iterations, window, sweep, safe_mode)


def glitch_scan(dev, args, level, iterations, window, sweep, safe_mode):
    """Automated parameter scan."""
    print(f"\n{C.CYAN}[*] Glitch Scan{C.RESET}")
    
    if safe_mode:
        if not _confirm("Automated scan may take a long time and cause instability!", 'SCAN', False):
            return False
    
    results = {'tested':0, 'successful':[], 'optimal':{}, 'duration':0}
    start = time.time()
    
    test_levels = [1, 2, 3, 5]
    test_windows = [100, 300, 500, 1000]
    
    for lvl in test_levels:
        for win in test_windows:
            results['tested'] += 1
            payload = _make_glitch_payload(GlitchOp.VOLTAGE, lvl, 5, win, 0)
            ok, _, _ = _dispatch(dev, "GLITCH", payload, timeout=10)
            if ok: results['successful'].append({'level':lvl, 'window':win})
            if safe_mode: time.sleep(0.3)
    
    if results['successful']:
        results['optimal'] = min(results['successful'], key=lambda x: (x['level'], abs(x['window']-300)))
    
    results['duration'] = time.time() - start
    _analyze_scan(results)
    return True


def glitch_monitor(dev, args, level, iterations, window, sweep, safe_mode):
    """Monitor glitch effects."""
    duration = int(args[1]) if len(args) > 1 else 30
    
    print(f"\n{C.CYAN}[*] Glitch Monitor ({duration}s){C.RESET}")
    
    payload = _make_glitch_payload(GlitchOp.MONITOR, level, iterations, 0, 0)
    data = {'duration':0, 'events':0, 'timing':0, 'voltage':0, 'clock':0, 'log':[]}
    start = time.time()
    
    try:
        with _get_progress(duration, prefix='Monitoring', suffix='Complete') as pb:
            while time.time() - start < duration:
                ok, _, extra = _dispatch(dev, "GLITCH", payload, timeout=3)
                if ok:
                    data['events'] += 1
                    if extra and len(extra) >= 12:
                        etype = struct.unpack("<I", extra[:4])[0]
                        if etype == 1: data['timing'] += 1
                        elif etype == 2: data['voltage'] += 1
                        elif etype == 3: data['clock'] += 1
                time.sleep(0.5)
                pb.update(0.5)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}")
    
    data['duration'] = time.time() - start
    _analyze_monitor(data)
    return True


def glitch_calibrate(dev, args, level, iterations, window, sweep, safe_mode):
    """Calibrate glitch parameters."""
    print(f"\n{C.CYAN}[*] Calibration{C.RESET}")
    
    results = {'level':3, 'window':500, 'success_rate':0, 'time':0}
    start = time.time()
    tests = []
    
    for lvl in [1, 2, 3, 4, 5]:
        for win in [100, 300, 500, 700, 900]:
            payload = _make_glitch_payload(GlitchOp.VOLTAGE, lvl, 5, win, 0)
            ok, _, _ = _dispatch(dev, "GLITCH", payload, timeout=5)
            tests.append({'level':lvl, 'window':win, 'ok':ok})
            if safe_mode: time.sleep(0.2)
    
    good = [t for t in tests if t['ok']]
    if good:
        best = max(set(t['level'] for t in good), key=lambda l: sum(1 for t in good if t['level']==l))
        best_win = max(set(t['window'] for t in good), key=lambda w: sum(1 for t in good if t['window']==w))
        results['level'] = best
        results['window'] = best_win
        results['success_rate'] = len(good) / len(tests) * 100
    
    results['time'] = time.time() - start
    _analyze_calibration(results)
    return True


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
GLITCH_HANDLERS = {
    'list': glitch_list, 'types': glitch_list, 'capabilities': glitch_list,
    'voltage': glitch_voltage, 'vcc': glitch_voltage, 'power': glitch_voltage,
    'clock': glitch_clock, 'frequency': glitch_clock, 'timing_glitch': glitch_timing,
    'em': glitch_em, 'electromagnetic': glitch_em, 'emf': glitch_em,
    'laser': glitch_laser, 'optical': glitch_laser, 'light': glitch_laser,
    'timing': glitch_timing, 'sync': glitch_timing, 'trigger': glitch_timing,
    'reset': glitch_reset, 'brownout': glitch_reset,
    'scan': glitch_scan, 'explore': glitch_scan, 'auto': glitch_scan,
    'monitor': glitch_monitor, 'analyze': glitch_monitor, 'watch': glitch_monitor,
    'calibrate': glitch_calibrate, 'tune': glitch_calibrate, 'optimize': glitch_calibrate,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_glitch_help():
    print(f"""
{C.BOLD}GLITCH - Hardware Fault Injection{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  list                    List capabilities
  voltage [target]        Voltage glitching (HIGH RISK)
  clock [target]          Clock frequency glitching
  em [type]               Electromagnetic glitching
  laser [params]          Laser fault injection (HIGH RISK)
  timing [type] [trig]    Timing/synchronization glitches
  reset [type]            Reset/brownout glitches
  scan [type]             Automated parameter exploration
  monitor [type] [dur]    Monitor glitch effects
  calibrate [type]        Calibrate glitch parameters

{C.CYAN}PARAMETERS:{C.RESET}
  --level 1-10           Intensity (default: 1)
  --iter 1-10000         Iterations (default: 100)
  --window 1-10000       Timing window in µs (default: 1000)
  --sweep 0-1000         Sweep steps (default: 0)
  --safe / --no-safe     Safety mode (default: safe)

{C.CYAN}RISK LEVELS:{C.RESET}
  🟢 LOW     Timing, reset glitches
  🟡 MEDIUM  Clock, EM glitches
  🔴 HIGH    Voltage, laser injection

{C.RED}⚠️  WARNING: High-risk glitching can PERMANENTLY DAMAGE hardware!{C.RESET}
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_glitch(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_glitch_help(); return 1
    
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
    
    sub = (getattr(args, 'glitch_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    gargs = getattr(args, 'glitch_args', []) or []
    level = max(MIN_LEVEL, min(MAX_LEVEL, int(getattr(args, 'level', 1) or 1)))
    iterations = max(MIN_ITERATIONS, min(MAX_ITERATIONS, int(getattr(args, 'iter', 100) or 100)))
    window = max(MIN_WINDOW, min(MAX_WINDOW, int(getattr(args, 'window', 1000) or 1000)))
    sweep = max(MIN_SWEEP, min(MAX_SWEEP, int(getattr(args, 'sweep', 0) or 0)))
    safe_mode = not getattr(args, 'no_safe', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_glitch_help(); return 0
    
    handler = GLITCH_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_glitch_help(); return 1
    
    try:
        return 0 if handler(dev, gargs, level, iterations, window, sweep, safe_mode) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def add_glitch_arguments(parser):
    parser.add_argument('glitch_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('glitch_args', nargs='*', help='Arguments')
    parser.add_argument('--level', type=int, default=1, help=f'Level ({MIN_LEVEL}-{MAX_LEVEL})')
    parser.add_argument('--iter', type=int, default=100, help='Iterations')
    parser.add_argument('--window', type=int, default=1000, help='Window (µs)')
    parser.add_argument('--sweep', type=int, default=0, help='Sweep steps')
    parser.add_argument('--no-safe', action='store_true', help='Disable safety')
    return parser


if __name__ == "__main__":
    print("[*] glitch.py - QSLCL GLITCH Module v2.0")
    print_glitch_help()