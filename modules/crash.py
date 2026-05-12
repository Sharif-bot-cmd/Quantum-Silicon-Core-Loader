#!/usr/bin/env python3
"""
crash.py - QSLCL CRASH Command Module v2.1 (CLEANED)
Controlled crash injection and system stability testing
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
TIMEOUT = 15.0
MAX_ITER = 100
MAX_DELAY = 300

# Opcodes
OP_CAPABILITIES = 0x00
OP_KERNEL_PANIC = 0x01
OP_NULL_POINTER = 0x02
OP_STACK_OVERFLOW = 0x03
OP_HEAP_CORRUPT = 0x04
OP_DIVIDE_ZERO = 0x05
OP_MEM_CORRUPT = 0x06
OP_WATCHDOG = 0x07
OP_IRQ_STORM = 0x08
OP_DMA_OVERFLOW = 0x09
OP_CUSTOM = 0x0A
OP_ANALYSIS = 0x20

# Crash type definitions
CRASH_TYPES = {
    'KERNEL_PANIC':      {'opcode': OP_KERNEL_PANIC,   'risk': 'HIGH',   'recovery': 'MANUAL'},
    'NULL_POINTER':      {'opcode': OP_NULL_POINTER,    'risk': 'MEDIUM', 'recovery': 'AUTO'},
    'STACK_OVERFLOW':    {'opcode': OP_STACK_OVERFLOW,  'risk': 'MEDIUM', 'recovery': 'AUTO'},
    'HEAP_CORRUPTION':   {'opcode': OP_HEAP_CORRUPT,    'risk': 'HIGH',   'recovery': 'MANUAL'},
    'DIVIDE_ZERO':       {'opcode': OP_DIVIDE_ZERO,     'risk': 'LOW',    'recovery': 'AUTO'},
    'MEMORY_CORRUPTION': {'opcode': OP_MEM_CORRUPT,     'risk': 'HIGH',   'recovery': 'MANUAL'},
    'WATCHDOG':          {'opcode': OP_WATCHDOG,        'risk': 'MEDIUM', 'recovery': 'AUTO'},
    'IRQ_STORM':         {'opcode': OP_IRQ_STORM,       'risk': 'MEDIUM', 'recovery': 'AUTO'},
    'DMA_OVERFLOW':      {'opcode': OP_DMA_OVERFLOW,    'risk': 'HIGH',   'recovery': 'MANUAL'},
}

HEAP_TYPES = ['DOUBLE_FREE', 'USE_AFTER_FREE', 'BUFFER_OVERFLOW', 'RACE_CONDITION']


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def parse_addr(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    try: return int(s, 16)
    except: return int(s, 10)


def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


def crash_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send crash command"""
    for attempt in range(2):
        try:
            if "CRASH" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "CRASH", payload, timeout=TIMEOUT)
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


def ping(dev) -> bool:
    """Quick health check"""
    ok, _, _ = crash_cmd(dev, b"")
    return ok


def monitor_recovery(dev, timeout: int = 30):
    """Monitor device recovery after crash"""
    print(f"\n[*] Monitoring recovery ({timeout}s)...")
    start = time.time()
    
    while time.time() - start < timeout:
        elapsed = time.time() - start
        remaining = timeout - int(elapsed)
        bar = '█' * (int(elapsed) % 20) + '░' * (20 - (int(elapsed) % 20))
        print(f"\r    [{bar}] {remaining}s", end="", flush=True)
        
        if ping(dev):
            print(f"\n[+] Recovered after {elapsed:.1f}s")
            return True
        
        time.sleep(1)
    
    print(f"\n[!] Recovery timeout - manual intervention may be needed")
    print("[*] Try: power cycle, recovery mode, or hardware reset")
    return False


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
# CRASH EXECUTION
# =============================================================================
def execute_crash(dev, crash_name: str, opcode: int, data: bytes = b"",
                  force: bool = False, timeout: int = 10) -> bool:
    """Execute a crash with safety and recovery monitoring"""
    info = CRASH_TYPES.get(crash_name, {'risk': 'MEDIUM', 'recovery': 'AUTO'})
    
    # Safety for HIGH risk
    if info['risk'] == 'HIGH' and not force:
        if not confirm(f"⚠️  {crash_name} - HIGH RISK!\nMay require manual recovery!", 'CRASH', force):
            return False
    
    # Kernel panic warning
    if crash_name == 'KERNEL_PANIC' and not force:
        if not confirm(f"⚠️  KERNEL PANIC - System will crash completely!", 'PANIC', force):
            return False
    
    payload = struct.pack("<B", opcode) + data + struct.pack("<I", timeout)
    
    print(f"\n[*] Triggering: {crash_name}")
    ok, name, _ = crash_cmd(dev, payload)
    
    if ok:
        print("[+] Crash triggered")
    else:
        print("[*] Device may have crashed (no response)")
    
    monitor_recovery(dev, timeout)
    return True


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force, timeout):
    """List crash types"""
    print(f"\n[*] Crash Types:\n")
    print(f"  {'Name':<20} {'Risk':<10} {'Recovery':<10}")
    print(f"  {'-'*20} {'-'*10} {'-'*10}")
    
    for name, info in CRASH_TYPES.items():
        icon = {'LOW':'🟢', 'MEDIUM':'🟡', 'HIGH':'🔴'}[info['risk']]
        print(f"  {icon} {name:<17} {info['risk']:<10} {info['recovery']:<10}")
    
    print(f"\n[*] Heap types: {', '.join(HEAP_TYPES)}")
    return True


def cmd_kernel(dev, args, force, timeout):
    ptype = args[0].upper() if args else "GENERIC"
    data = ptype.encode()[:16].ljust(16, b'\x00')
    return execute_crash(dev, 'KERNEL_PANIC', OP_KERNEL_PANIC, data, force, timeout)

def cmd_nullptr(dev, args, force, timeout):
    addr = parse_addr(args[0]) if args else 0
    data = struct.pack("<I", addr)
    return execute_crash(dev, 'NULL_POINTER', OP_NULL_POINTER, data, force, timeout)

def cmd_stack(dev, args, force, timeout):
    depth = max(10, min(100000, int(args[0]) if args else 1000))
    data = struct.pack("<I", depth)
    return execute_crash(dev, 'STACK_OVERFLOW', OP_STACK_OVERFLOW, data, force, timeout)

def cmd_heap(dev, args, force, timeout):
    htype = args[0].upper() if args and args[0].upper() in HEAP_TYPES else "DOUBLE_FREE"
    data = htype.encode()[:16].ljust(16, b'\x00')
    return execute_crash(dev, 'HEAP_CORRUPTION', OP_HEAP_CORRUPT, data, force, timeout)

def cmd_divzero(dev, args, force, timeout):
    return execute_crash(dev, 'DIVIDE_ZERO', OP_DIVIDE_ZERO, b'', force, timeout)

def cmd_memory(dev, args, force, timeout):
    addr = parse_addr(args[0]) if args else 0x10000000
    pattern = parse_addr(args[1]) if len(args) > 1 else 0xDEADBEEF
    
    if addr < 0x1000 and not force:
        if not confirm(f"⚠️  Low memory corruption at 0x{addr:08X} may brick device!", 'MEMORY', force):
            return False
    
    data = struct.pack("<II", addr, pattern)
    return execute_crash(dev, 'MEMORY_CORRUPTION', OP_MEM_CORRUPT, data, force, timeout)

def cmd_watchdog(dev, args, force, timeout):
    ms = max(100, min(60000, int(args[0]) if args else 1000))
    data = struct.pack("<I", ms)
    return execute_crash(dev, 'WATCHDOG', OP_WATCHDOG, data, force, max(timeout, ms//1000+5))

def cmd_irq(dev, args, force, timeout):
    irq = max(0, min(255, int(args[0]) if args else 0))
    freq = max(1, min(100000, int(args[1]) if len(args) > 1 else 1000))
    data = struct.pack("<II", irq, freq)
    return execute_crash(dev, 'IRQ_STORM', OP_IRQ_STORM, data, force, timeout)

def cmd_dma(dev, args, force, timeout):
    ch = max(0, min(31, int(args[0]) if args else 0))
    data = struct.pack("<I", ch)
    return execute_crash(dev, 'DMA_OVERFLOW', OP_DMA_OVERFLOW, data, force, timeout)

def cmd_custom(dev, args, force, timeout):
    if not args:
        print("[!] Specify crash scenario")
        return False
    scenario = ' '.join(str(a) for a in args)[:60]
    data = scenario.encode()[:64].ljust(64, b'\x00')
    return execute_crash(dev, 'CUSTOM', OP_CUSTOM, data, force, timeout)

def cmd_analyze(dev, args, force, timeout):
    """Crash analysis"""
    print(f"\n[*] Crash Analysis:")
    
    ok, _, data = crash_cmd(dev, struct.pack("<B", OP_ANALYSIS))
    
    if ok and data and len(data) >= 13:
        count = struct.unpack("<I", data[0:4])[0]
        ts = struct.unpack("<I", data[4:8])[0]
        rate = struct.unpack("<I", data[8:12])[0]
        health = {0:'CRITICAL', 1:'POOR', 2:'FAIR', 3:'GOOD', 4:'EXCELLENT'}.get(data[12], '?')
        
        ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if 946684800 < ts < 2000000000 else f"0x{ts:X}"
        
        print(f"    Crashes:  {count}")
        print(f"    Last:     {ts_str}")
        print(f"    Recovery: {rate}%")
        print(f"    Health:   {health}")
        
        if count > 10:
            print(f"\n[!] High crash count ({count}) - investigate stability")
        elif count > 0 and rate < 80:
            print(f"\n[!] Low recovery rate ({rate}%) - improve recovery")
        elif count == 0:
            print(f"\n[+] No crashes - system stable")
    else:
        print("    No crash data available")
    
    return True


# =============================================================================
# TEST SUITES
# =============================================================================
def cmd_crash_test(args=None) -> int:
    """Crash test suite"""
    if args is None:
        print("[!] No arguments")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    cargs = getattr(args, 'crash_args', []) or []
    ttype = cargs[0] if cargs and cargs[0] in ('basic', 'comprehensive', 'recovery', 'stress') else 'basic'
    iters = max(1, min(MAX_ITER, int(cargs[1]) if len(cargs) > 1 else 1))
    delay = max(1, min(MAX_DELAY, int(cargs[2]) if len(cargs) > 2 else 5))
    
    print(f"\n[*] Crash Test: {ttype} ({iters}x, {delay}s delay)")
    
    if not confirm("⚠️  Crash testing may cause instability and require manual recovery!", 'TEST', False):
        return 0
    
    if ttype == 'basic':
        scenarios = [('NULL', cmd_nullptr), ('DIV0', cmd_divzero), ('STACK', lambda d,a,f,t: cmd_stack(d, ['100'], f, t))]
    elif ttype == 'comprehensive':
        scenarios = [('NULL', cmd_nullptr), ('DIV0', cmd_divzero), ('STACK', lambda d,a,f,t: cmd_stack(d, ['500'], f, t)),
                    ('HEAP', lambda d,a,f,t: cmd_heap(d, ['DOUBLE_FREE'], f, t)),
                    ('MEM', lambda d,a,f,t: cmd_memory(d, ['0x20000000', '0xBAD'], f, t))]
    elif ttype == 'recovery':
        scenarios = [('NULL', cmd_nullptr)]
    else:  # stress
        scenarios = [('NULL', cmd_nullptr), ('DIV0', cmd_divzero), ('STACK', lambda d,a,f,t: cmd_stack(d, ['50'], f, t))]
    
    total = iters * len(scenarios)
    passed = 0
    
    print(f"\n[*] {len(scenarios)} scenarios × {iters} = {total} tests")
    
    try:
        with ProgressBar(total, prefix='Testing', suffix='Complete') as pb:
            for i in range(iters):
                for name, func in scenarios:
                    print(f"\n  [{name}] ", end="", flush=True)
                    try:
                        func(dev, [], True, delay)
                        time.sleep(delay)
                        if ping(dev):
                            print("PASS")
                            passed += 1
                        else:
                            print("NO RECOVERY")
                            time.sleep(3)
                            new_devs = scan_all()
                            if new_devs: dev = new_devs[0]
                    except KeyboardInterrupt:
                        print("SKIP")
                        return 0 if passed >= total * 0.8 else 1
                    except Exception as e:
                        print(f"ERROR: {e}")
                    
                    pb.update(1)
                
                if i < iters - 1:
                    time.sleep(2)
    except KeyboardInterrupt:
        pass
    
    rate = passed / total * 100 if total > 0 else 0
    print(f"\n[+] Result: {passed}/{total} ({rate:.0f}%)")
    return 0 if rate >= 80 else 1


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'list': cmd_list, 'ls': cmd_list, 'types': cmd_list,
    'kernel': cmd_kernel, 'panic': cmd_kernel,
    'null': cmd_nullptr, 'nullptr': cmd_nullptr, 'null-pointer': cmd_nullptr,
    'stack': cmd_stack, 'overflow': cmd_stack, 'stack-overflow': cmd_stack,
    'heap': cmd_heap, 'corruption': cmd_heap, 'heap-corruption': cmd_heap,
    'divide': cmd_divzero, 'divide-zero': cmd_divzero, 'div0': cmd_divzero,
    'memory': cmd_memory, 'mem': cmd_memory, 'memory-corruption': cmd_memory,
    'watchdog': cmd_watchdog, 'wdt': cmd_watchdog,
    'interrupt': cmd_irq, 'irq': cmd_irq, 'isr': cmd_irq,
    'dma': cmd_dma, 'dma-overflow': cmd_dma,
    'custom': cmd_custom, 'user': cmd_custom,
    'analyze': cmd_analyze, 'analysis': cmd_analyze,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_crash(args=None) -> int:
    """
    QSLCL CRASH - Controlled crash injection and stability testing
    
    Examples:
        crash list                          - List crash types
        crash kernel                        - Kernel panic
        crash null                          - Null pointer dereference
        crash stack 5000                    - Stack overflow (depth 5000)
        crash heap DOUBLE_FREE              - Heap corruption
        crash divide-zero                   - Division by zero
        crash memory 0x20000000 0xBAD       - Memory corruption
        crash watchdog 5000                 - Watchdog timeout (5s)
        crash interrupt 10 1000             - IRQ storm on IRQ10
        crash dma 3                         - DMA overflow on ch3
        crash custom "race condition"       - Custom crash
        crash analyze                       - Crash analysis
        crash-test basic 3 5                - Basic test: 3x, 5s delay
    
    Risk Levels: 🟢 LOW  🟡 MEDIUM  🔴 HIGH
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: crash <list|kernel|null|stack|heap|divide|memory|watchdog|interrupt|dma|custom|analyze>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'crash_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    cargs = getattr(args, 'crash_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    timeout = max(5, getattr(args, 'timeout', 10) or 10)
    
    if not sub or sub in ('help', '?'):
        print("[*] Crash Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<15} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    try:
        return 0 if handler(dev, cargs, force, timeout) else 1
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
    print("[*] crash.py - QSLCL CRASH Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py crash <subcommand> [args]")