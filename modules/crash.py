#!/usr/bin/env python3
"""
crash.py - QSLCL CRASH Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, safety checks,
       crash injection, recovery monitoring, test suites
"""

import os
import sys
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
_ProgressBar = None
_QSLCLCMD_DB = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        ProgressBar as _qslcl_ProgressBar,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _auto_loader_if_needed = _qslcl_auto_loader
    _qslcl_dispatch = _qslcl_dispatch_fn
    _decode_runtime_result = _qslcl_decode_runtime
    _ProgressBar = _qslcl_ProgressBar
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
            ProgressBar as _qslcl_ProgressBar,
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _auto_loader_if_needed = _qslcl_auto_loader
        _qslcl_dispatch = _qslcl_dispatch_fn
        _decode_runtime_result = _qslcl_decode_runtime
        _ProgressBar = _qslcl_ProgressBar
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
        print("[!] Running in standalone mode"); _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
CRASH_TIMEOUT = 15.0
MAX_RETRIES = 2
MAX_ITERATIONS = 100
MAX_DELAY = 300

# Crash opcodes
class CrashOp:
    CAPABILITIES = 0x00
    KERNEL_PANIC = 0x01
    NULL_POINTER = 0x02
    STACK_OVERFLOW = 0x03
    HEAP_CORRUPTION = 0x04
    DIVIDE_ZERO = 0x05
    MEMORY_CORRUPTION = 0x06
    WATCHDOG = 0x07
    INTERRUPT_STORM = 0x08
    DMA_OVERFLOW = 0x09
    CUSTOM = 0x0A
    ANALYSIS = 0x20

# Crash type definitions
CRASH_TYPES = {
    'KERNEL_PANIC':      {'severity':'HIGH',   'recovery':'MANUAL', 'confirm':'PANIC'},
    'NULL_POINTER':      {'severity':'MEDIUM', 'recovery':'AUTO',   'confirm':None},
    'STACK_OVERFLOW':    {'severity':'MEDIUM', 'recovery':'AUTO',   'confirm':None},
    'HEAP_CORRUPTION':   {'severity':'HIGH',   'recovery':'MANUAL', 'confirm':None},
    'DIVIDE_ZERO':       {'severity':'LOW',    'recovery':'AUTO',   'confirm':None},
    'MEMORY_CORRUPTION': {'severity':'HIGH',   'recovery':'MANUAL', 'confirm':None},
    'WATCHDOG':          {'severity':'MEDIUM', 'recovery':'AUTO',   'confirm':None},
    'INTERRUPT_STORM':   {'severity':'MEDIUM', 'recovery':'AUTO',   'confirm':None},
    'DMA_OVERFLOW':      {'severity':'HIGH',   'recovery':'MANUAL', 'confirm':None},
}

HEAP_TYPES = ['DOUBLE_FREE', 'USE_AFTER_FREE', 'BUFFER_OVERFLOW', 'RACE_CONDITION']
TEST_TYPES = ['basic', 'comprehensive', 'recovery', 'stress']

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
        self._started = False
    def __enter__(self): return self
    def __exit__(self, *a):
        if self._started: print()
    def update(self, n):
        self._started = True; self.current += n
        pct = min(100, 100 * self.current / self.total)
        filled = int(self.length * self.current // self.total)
        print(f'\r{self.prefix} |{"█"*filled}{"-"*(self.length-filled)}| {pct:.0f}% {self.suffix}', end='', flush=True)

def _get_progress(total, **kw):
    if _use_qslcl and _ProgressBar: return _ProgressBar(total, **kw)
    return LocalProgressBar(total, **kw)


# =============================================================================
# FIXED: Parse helpers
# =============================================================================
def _parse_address(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    try: return int(s, 16)
    except: return int(s, 10)


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
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or CRASH_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or CRASH_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: System health check
# =============================================================================
def _check_health(dev) -> bool:
    """Check if device is responsive."""
    ok, _, _ = _dispatch(dev, "PING", b"", timeout=3)
    return ok


# =============================================================================
# FIXED: Crash execution helper
# =============================================================================
def _execute_crash(dev, opcode: int, data: bytes = b"", crash_name: str = "",
                   force: bool = False, timeout: int = 10) -> bool:
    """Execute a crash command with safety and monitoring."""
    info = CRASH_TYPES.get(crash_name, {})
    
    # Safety confirmation
    if info.get('confirm'):
        if not _confirm(
            f"⚠️  {crash_name} - {info.get('severity','?')} RISK\n"
            f"System will crash and may require {'MANUAL' if info.get('recovery')=='MANUAL' else 'automatic'} recovery!",
            info['confirm'], force
        ):
            return False
    
    if info.get('severity') in ('HIGH',) and not force:
        if not _confirm(
            f"⚠️  HIGH SEVERITY crash: {crash_name}\n"
            f"This may cause data loss or require manual recovery!",
            'CRASH', force
        ):
            return False
    
    payload = struct.pack("<B", opcode) + data + struct.pack("<I", timeout)
    
    print(f"\n{C.CYAN}[*] Triggering: {crash_name}{C.RESET}")
    ok, name, extra = _dispatch(dev, "CRASH", payload, timeout=5)
    
    if ok:
        print(f"{C.GREEN}[+] Crash triggered{C.RESET}")
    else:
        print(f"{C.YELLOW}[*] Device may have crashed (no response){C.RESET}")
    
    # Monitor recovery
    _monitor_recovery(dev, timeout, crash_name)
    return True


def _monitor_recovery(dev, timeout: int, crash_name: str):
    """Monitor device recovery after crash."""
    print(f"\n{C.CYAN}[*] Recovery: {timeout}s timeout{C.RESET}")
    start = time.time()
    
    while time.time() - start < timeout:
        elapsed = time.time() - start
        remaining = timeout - int(elapsed)
        bar = '█' * (int(elapsed) % 20) + '░' * (20 - (int(elapsed) % 20))
        print(f"\r    [{bar}] {remaining}s", end="", flush=True)
        
        try:
            if _check_health(dev):
                print(f"\n{C.GREEN}[+] Recovered after {elapsed:.1f}s{C.RESET}")
                return
        except: pass
        time.sleep(1)
    
    print(f"\n{C.RED}[!] Recovery timeout - manual intervention may be needed{C.RESET}")
    print(f"[*] Steps: 1) Power cycle  2) Recovery mode  3) JTAG/SWD debugger")


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def crash_list(dev, args, force=False, severity='medium', timeout=10) -> bool:
    """List available crash types."""
    print(f"\n{C.BOLD}[+] Crash Types:{C.RESET}\n")
    print(f"  {'Name':<20} {'Severity':<10} {'Recovery':<10}")
    print(f"  {'-'*20} {'-'*10} {'-'*10}")
    
    for name, info in CRASH_TYPES.items():
        icon = {'LOW':'🟢','MEDIUM':'🟡','HIGH':'🔴'}.get(info['severity'],'❓')
        print(f"  {icon} {name:<17} {info['severity']:<10} {info['recovery']:<10}")
    
    print(f"\n{C.CYAN}Heap types: {', '.join(HEAP_TYPES)}{C.RESET}")
    print(f"{C.CYAN}Test types: {', '.join(TEST_TYPES)}{C.RESET}")
    return True


def crash_kernel(dev, args, force=False, severity='medium', timeout=10) -> bool:
    ptype = args[0].upper() if args else "GENERIC"
    data = ptype.encode('ascii','ignore')[:16].ljust(16, b'\x00')
    return _execute_crash(dev, CrashOp.KERNEL_PANIC, data, 'KERNEL_PANIC', force, timeout)

def crash_null_pointer(dev, args, force=False, severity='medium', timeout=10) -> bool:
    addr = _parse_address(args[0]) if args else 0
    data = struct.pack("<I", addr)
    return _execute_crash(dev, CrashOp.NULL_POINTER, data, 'NULL_POINTER', force, timeout)

def crash_stack_overflow(dev, args, force=False, severity='medium', timeout=10) -> bool:
    depth = max(10, min(100000, int(args[0]) if args else 1000))
    data = struct.pack("<I", depth)
    return _execute_crash(dev, CrashOp.STACK_OVERFLOW, data, 'STACK_OVERFLOW', force, timeout)

def crash_heap_corruption(dev, args, force=False, severity='medium', timeout=10) -> bool:
    htype = args[0].upper() if args and args[0].upper() in HEAP_TYPES else "DOUBLE_FREE"
    data = htype.encode('ascii','ignore')[:16].ljust(16, b'\x00')
    return _execute_crash(dev, CrashOp.HEAP_CORRUPTION, data, 'HEAP_CORRUPTION', force, timeout)

def crash_divide_zero(dev, args, force=False, severity='medium', timeout=10) -> bool:
    return _execute_crash(dev, CrashOp.DIVIDE_ZERO, b'', 'DIVIDE_ZERO', force, timeout)

def crash_memory_corruption(dev, args, force=False, severity='medium', timeout=10) -> bool:
    addr = _parse_address(args[0]) if args else 0x10000000
    pattern = _parse_address(args[1]) if len(args) > 1 else 0xDEADBEEF
    if addr < 0x1000 and not force:
        if not _confirm(f"⚠️  Low memory corruption at 0x{addr:08X} may brick device!", 'MEMORY', force):
            return False
    data = struct.pack("<II", addr, pattern)
    return _execute_crash(dev, CrashOp.MEMORY_CORRUPTION, data, 'MEMORY_CORRUPTION', force, timeout)

def crash_watchdog(dev, args, force=False, severity='medium', timeout=10) -> bool:
    ms = max(100, min(60000, int(args[0]) if args else 1000))
    data = struct.pack("<I", ms)
    return _execute_crash(dev, CrashOp.WATCHDOG, data, 'WATCHDOG', force, max(timeout, ms//1000+5))

def crash_interrupt(dev, args, force=False, severity='medium', timeout=10) -> bool:
    irq = max(0, min(255, int(args[0]) if args else 0))
    freq = max(1, min(100000, int(args[1]) if len(args)>1 else 1000))
    data = struct.pack("<II", irq, freq)
    return _execute_crash(dev, CrashOp.INTERRUPT_STORM, data, 'INTERRUPT_STORM', force, timeout)

def crash_dma(dev, args, force=False, severity='medium', timeout=10) -> bool:
    ch = max(0, min(31, int(args[0]) if args else 0))
    data = struct.pack("<I", ch)
    return _execute_crash(dev, CrashOp.DMA_OVERFLOW, data, 'DMA_OVERFLOW', force, timeout)

def crash_custom(dev, args, force=False, severity='medium', timeout=10) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify crash scenario{C.RESET}")
        return False
    scenario = ' '.join(str(a) for a in args)[:60]
    data = scenario.encode('ascii','ignore')[:64].ljust(64, b'\x00')
    return _execute_crash(dev, CrashOp.CUSTOM, data, 'CUSTOM', force, timeout)

def crash_analyze(dev, args, force=False, severity='medium', timeout=10) -> bool:
    print(f"\n{C.CYAN}[*] Crash Analysis{C.RESET}")
    ok, _, data = _dispatch(dev, "CRASH", struct.pack("<B", CrashOp.ANALYSIS))
    
    if ok and data:
        analysis = _parse_analysis(data)
        _display_analysis(analysis)
    else:
        print(f"{C.YELLOW}[*] No crash data available{C.RESET}")
    return True


# =============================================================================
# FIXED: Analysis parsing and display
# =============================================================================
def _parse_analysis(data: bytes) -> Dict:
    a = {'crash_count':0, 'last_crash':'Unknown', 'recovery_rate':0, 'health':'UNKNOWN'}
    try:
        if len(data) >= 4: a['crash_count'] = struct.unpack("<I", data[0:4])[0]
        if len(data) >= 8:
            ts = struct.unpack("<I", data[4:8])[0]
            if ts > 0:
                try: a['last_crash'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                except: a['last_crash'] = f"ts=0x{ts:X}"
        if len(data) >= 12: a['recovery_rate'] = struct.unpack("<I", data[8:12])[0]
        if len(data) >= 13:
            a['health'] = {0:'CRITICAL',1:'POOR',2:'FAIR',3:'GOOD',4:'EXCELLENT'}.get(data[12],'UNKNOWN')
    except: pass
    return a

def _display_analysis(a: Dict):
    print(f"\n{C.BOLD}[+] Crash Report:{C.RESET}")
    print(f"    Crashes:  {a.get('crash_count',0)}")
    print(f"    Last:     {a.get('last_crash','?')}")
    print(f"    Recovery: {a.get('recovery_rate',0)}%")
    print(f"    Health:   {a.get('health','?')}")
    
    count = a.get('crash_count', 0)
    rate = a.get('recovery_rate', 0)
    
    if count > 10:
        print(f"\n{C.RED}[!] High crash count ({count}) - investigate stability{C.RESET}")
    elif count > 0:
        print(f"\n{C.YELLOW}[*] {count} crash(es) recorded{C.RESET}")
        if rate < 80:
            print(f"{C.RED}[!] Low recovery rate ({rate}%) - improve recovery{C.RESET}")
    else:
        print(f"\n{C.GREEN}[+] No crashes - system stable{C.RESET}")


# =============================================================================
# FIXED: Test suites
# =============================================================================
def cmd_crash_test(args=None) -> int:
    """Crash test suite."""
    if not _use_qslcl: _warn_standalone()
    
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return 1
        if not devs: print(f"{C.RED}[!] No device{C.RESET}"); return 1
        dev = devs[0]
    else:
        print(f"{C.RED}[!] No QSLCL{C.RESET}"); return 1
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    cargs = getattr(args, 'crash_args', []) or []
    ttype = cargs[0] if cargs and cargs[0] in TEST_TYPES else 'basic'
    iterations = max(1, min(MAX_ITERATIONS, int(cargs[1]) if len(cargs) > 1 else 1))
    delay = max(1, min(MAX_DELAY, int(cargs[2]) if len(cargs) > 2 else 5))
    
    print(f"\n{C.BOLD}[+] Crash Test: {ttype} ({iterations}x, {delay}s delay){C.RESET}")
    
    if not _confirm("⚠️  Crash testing may cause instability and require manual recovery!", 'TEST', False):
        return 0
    
    if ttype == 'basic':
        return _run_test(dev, iterations, delay, [
            ('NULL_POINTER', lambda: crash_null_pointer(dev, [], True, 'medium', delay)),
            ('DIVIDE_ZERO', lambda: crash_divide_zero(dev, [], True, 'medium', delay)),
            ('STACK_OVERFLOW', lambda: crash_stack_overflow(dev, ['100'], True, 'medium', delay)),
        ])
    elif ttype == 'comprehensive':
        return _run_test(dev, iterations, delay, [
            ('NULL_POINTER', lambda: crash_null_pointer(dev, [], True, 'medium', delay)),
            ('DIVIDE_ZERO', lambda: crash_divide_zero(dev, [], True, 'medium', delay)),
            ('STACK', lambda: crash_stack_overflow(dev, ['500'], True, 'medium', delay)),
            ('HEAP', lambda: crash_heap_corruption(dev, ['DOUBLE_FREE'], True, 'medium', delay)),
            ('MEMORY', lambda: crash_memory_corruption(dev, ['0x20000000','0xBAD'], True, 'medium', delay)),
        ])
    elif ttype == 'recovery':
        return _run_recovery_test(dev, iterations, delay)
    elif ttype == 'stress':
        return _run_stress_test(dev, iterations, delay)
    
    return 0


def _run_test(dev, iterations: int, delay: int, scenarios: List[Tuple[str, callable]]) -> int:
    """Run crash test suite."""
    total = iterations * len(scenarios)
    passed = 0
    
    print(f"\n{C.CYAN}[*] {len(scenarios)} scenarios × {iterations} = {total} tests{C.RESET}")
    
    with _get_progress(total, prefix='Testing', suffix='Complete') as pb:
        for i in range(iterations):
            for name, func in scenarios:
                print(f"\n  [{name}] ", end="", flush=True)
                try:
                    func()
                    time.sleep(delay)
                    if _check_health(dev):
                        print(f"{C.GREEN}PASS{C.RESET}")
                        passed += 1
                    else:
                        print(f"{C.RED}NO RECOVERY{C.RESET}")
                        # Try re-scan
                        time.sleep(3)
                        d2 = _scan_all()
                        if d2: dev = d2[0]
                except KeyboardInterrupt:
                    print(f"{C.YELLOW}SKIP{C.RESET}")
                    return 0 if passed >= total * 0.8 else 1
                except Exception as e:
                    print(f"{C.RED}ERROR: {e}{C.RESET}")
                
                pb.update(1)
            
            if i < iterations - 1:
                time.sleep(2)
    
    rate = passed / total * 100 if total > 0 else 0
    print(f"\n{C.BOLD}[+] Result: {passed}/{total} ({rate:.0f}%){C.RESET}")
    return 0 if rate >= 80 else 1


def _run_recovery_test(dev, iterations: int, delay: int) -> int:
    """Test recovery mechanisms."""
    passed = 0
    
    with _get_progress(iterations, prefix='Recovery', suffix='Complete') as pb:
        for i in range(iterations):
            print(f"\n  [{i+1}/{iterations}] ", end="", flush=True)
            try:
                crash_null_pointer(dev, [], True, 'medium', delay)
                time.sleep(delay)
                
                # Test recovery mechanisms
                recovered = _check_health(dev)
                if recovered:
                    print(f"{C.GREEN}RECOVERED{C.RESET}")
                    passed += 1
                else:
                    print(f"{C.RED}FAILED{C.RESET}")
                    time.sleep(3)
                    d2 = _scan_all()
                    if d2: dev = d2[0]
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{C.RED}ERROR: {e}{C.RESET}")
            
            pb.update(1)
    
    return 0 if passed >= iterations * 0.8 else 1


def _run_stress_test(dev, iterations: int, delay: int) -> int:
    """Run stress testing."""
    crashes = 0
    target = iterations * 3
    
    with _get_progress(target, prefix='Crashes', suffix='Complete') as pb:
        for i in range(iterations):
            for name in ['NULL_POINTER','DIVIDE_ZERO','STACK']:
                try:
                    handler = {'NULL_POINTER': lambda: crash_null_pointer(dev, [], True, 'medium', 5),
                              'DIVIDE_ZERO': lambda: crash_divide_zero(dev, [], True, 'medium', 5),
                              'STACK': lambda: crash_stack_overflow(dev, ['50'], True, 'medium', 5)}[name]
                    handler()
                    crashes += 1
                    time.sleep(1)
                except KeyboardInterrupt: break
                except: pass
                pb.update(1)
    
    rate = crashes / target * 100 if target > 0 else 0
    print(f"\n{C.BOLD}[+] Stress: {crashes}/{target} ({rate:.0f}%){C.RESET}")
    return 0 if rate >= 80 else 1


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
CRASH_HANDLERS = {
    'list': crash_list, 'ls': crash_list, 'types': crash_list,
    'kernel': crash_kernel, 'panic': crash_kernel,
    'null': crash_null_pointer, 'nullptr': crash_null_pointer, 'null-pointer': crash_null_pointer,
    'stack': crash_stack_overflow, 'overflow': crash_stack_overflow, 'stack-overflow': crash_stack_overflow,
    'heap': crash_heap_corruption, 'corruption': crash_heap_corruption, 'heap-corruption': crash_heap_corruption,
    'divide': crash_divide_zero, 'divide-zero': crash_divide_zero, 'div0': crash_divide_zero,
    'memory': crash_memory_corruption, 'mem': crash_memory_corruption, 'memory-corruption': crash_memory_corruption,
    'watchdog': crash_watchdog, 'wdt': crash_watchdog,
    'interrupt': crash_interrupt, 'irq': crash_interrupt, 'isr': crash_interrupt,
    'dma': crash_dma, 'dma-overflow': crash_dma,
    'custom': crash_custom, 'user': crash_custom,
    'analyze': crash_analyze, 'analysis': crash_analyze,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_crash_help():
    print(f"""
{C.BOLD}CRASH - Controlled Crash Injection{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  list                    List crash types
  kernel [type]           Kernel panic
  null [addr]             Null pointer dereference
  stack [depth]           Stack overflow (default: 1000)
  heap [type]             Heap corruption ({', '.join(HEAP_TYPES)})
  divide-zero             Division by zero
  memory [addr] [pat]     Memory corruption
  watchdog [ms]           Watchdog timeout (default: 1000ms)
  interrupt [irq] [freq]  Interrupt storm
  dma [channel]           DMA overflow
  custom <scenario>       Custom crash
  analyze                 Crash analysis
  crash-test [type] [n] [d]  Run test suite

{C.CYAN}SEVERITY:{C.RESET}
  🟢 LOW      Auto-recovery expected
  🟡 MEDIUM   May need intervention
  🔴 HIGH     Manual recovery likely

{C.CYAN}OPTIONS:{C.RESET}
  --force        Skip confirmations
  --severity     low/medium/high
  --timeout N    Recovery timeout

{C.RED}⚠️  WARNING: Crashes may cause data loss or require manual recovery!{C.RESET}
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_crash(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_crash_help(); return 1
    
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
    
    sub = (getattr(args, 'crash_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    cargs = getattr(args, 'crash_args', []) or []
    force = getattr(args, 'force', False)
    severity = getattr(args, 'severity', 'medium') or 'medium'
    timeout = max(5, int(getattr(args, 'timeout', 10) or 10))
    
    if not sub or sub in ('help','?','-h','--help'):
        print_crash_help(); return 0
    
    handler = CRASH_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_crash_help(); return 1
    
    try:
        return 0 if handler(dev, cargs, force, severity, timeout) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def add_crash_arguments(parser):
    parser.add_argument('crash_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('crash_args', nargs='*', help='Arguments')
    parser.add_argument('--severity', choices=['low','medium','high'], default='medium')
    parser.add_argument('--timeout', type=int, default=10, help='Recovery timeout')
    parser.add_argument('--force', action='store_true', help='Skip confirmations')
    return parser


if __name__ == "__main__":
    print("[*] crash.py - QSLCL CRASH Module v2.0")
    print_crash_help()