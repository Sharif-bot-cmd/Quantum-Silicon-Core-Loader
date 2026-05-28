#!/usr/bin/env python3
"""
bruteforce.py - QSLCL BRUTEFORCE Command Module v3.0 (CLEANED)
Core commands only: BRUTEFORCE, TEST, FUZZ, RAWMODE
"""

import os
import sys
import struct
import time
import json
import random
from typing import Optional, List, Tuple, Dict

# =============================================================================
# IMPORTS
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
MAX_SCAN = 0x10000
MAX_SEQ = 1000
MAX_FUZZ = 10000
DEFAULT_THREADS = 4

# =============================================================================
# CORE OPCODES
# =============================================================================
BF_OP_TEST = 0x00
BF_OP_SCAN = 0x01
BF_OP_PATTERN = 0x02
BF_OP_FUZZ = 0x03
BF_OP_DICT = 0x04
BF_OP_REPLAY = 0x05
BF_OP_ANALYZE = 0x06

# =============================================================================
# STRATEGIES
# =============================================================================
STRATEGIES = {
    'basic':      'Sequential linear search',
    'smart':      'Heuristic optimization',
    'aggressive': 'Parallel multi-threaded',
}

BUILTIN_DICTS = {
    'common':    ['admin', 'password', '1234', 'test', 'default', 'root', 'user', 'guest'],
    'hex':       [f"0x{i:04X}" for i in range(0, 0x100, 0x10)],
    'commands':  ['READ', 'WRITE', 'ERASE', 'HELLO', 'PING', 'GETINFO', 'CONFIG'],
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def bf_cmd(dev, cmd: str, payload: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send bruteforce command"""
    for attempt in range(2):
        try:
            if cmd in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, cmd, payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt == 0:
                time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""

def parse_addr(s: str) -> int:
    """Parse address from hex or decimal string"""
    s = str(s).strip().lower()
    if s.startswith('0x'):
        return int(s[2:], 16)
    try:
        return int(s, 16)
    except:
        return int(s, 10)

def parse_range(pattern: str) -> List[Tuple[int, int, str]]:
    """Parse pattern into scan ranges"""
    if not pattern:
        return []
    
    try:
        if '-' in pattern and pattern.count('-') == 1:
            if pattern.startswith('0x'):
                parts = pattern.split('-')
                s, e = int(parts[0], 16), int(parts[1], 16)
                return [(s, e, f"Hex range 0x{s:X}-0x{e:X}")]
            elif pattern.replace('-', '').isdigit():
                parts = pattern.split('-')
                return [(int(parts[0]), int(parts[1]), "Numeric range")]
        
        addr = parse_addr(pattern)
        return [(addr, addr + 0x1000, f"Address 0x{addr:X}")]
    except:
        pass
    
    return [(0x10000000, 0x10001000, "Default")]

def gen_sequences(pattern: str) -> List[str]:
    """Generate test sequences from pattern"""
    seqs = []
    try:
        if pattern.startswith('0x') and '-' in pattern:
            parts = pattern.split('-')
            s, e = int(parts[0], 16), int(parts[1], 16)
            step = max(1, (e - s) // MAX_SEQ)
            for v in range(s, min(e + 1, s + MAX_SEQ * step), step):
                seqs.append(f"0x{v:0{(e.bit_length() + 3) // 4}X}")
        elif pattern.replace('-', '').isdigit() and '-' in pattern:
            parts = pattern.split('-')
            s, e = int(parts[0]), int(parts[1])
            step = max(1, (e - s) // MAX_SEQ)
            for v in range(s, min(e + 1, s + MAX_SEQ * step), step):
                seqs.append(str(v))
        else:
            seqs.append(pattern)
    except:
        seqs = [pattern] if pattern else []
    return seqs[:MAX_SEQ]

def gen_fuzz(max_size: int = 256) -> bytes:
    """Generate fuzz data"""
    size = random.randint(1, min(max_size, 1024))
    choices = [
        b'\x00' * size,
        b'\xFF' * size,
        bytes([random.getrandbits(8)]) * size,
        os.urandom(size)
    ]
    return random.choice(choices)

def load_dict(source: str) -> List[str]:
    """Load dictionary"""
    if source in BUILTIN_DICTS:
        return BUILTIN_DICTS[source]
    try:
        if os.path.exists(source):
            with open(source, 'r', errors='ignore') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except:
        pass
    return []

def save_results(path: str, results: dict, atype: str):
    """Save results to file"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        with open(path, 'a' if os.path.exists(path) else 'w') as f:
            f.write(f"\n{'=' * 50}\n{atype.upper()} RESULTS\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tested: {results.get('tested', results.get('scanned', 0))}\n")
            f.write(f"Success: {len(results.get('successful', []))}\n")
            
            for s in results.get('successful', [])[:50]:
                f.write(f"  {s}\n")
        
        if not _DEBUG:
            print(f"\n[+] Saved: {path}")
    except Exception as e:
        print(f"[!] Save error: {e}")

def test_sequence(dev, seq, rawmode: bool = False) -> bool:
    """Test a sequence against device"""
    try:
        if isinstance(seq, str):
            if seq.startswith('0x'):
                val = int(seq, 16)
                data = val.to_bytes(max(1, (val.bit_length() + 7) // 8), 'little')
            else:
                data = seq.encode('utf-8')
        else:
            data = seq if isinstance(seq, bytes) else str(seq).encode()
        
        ok, _, _ = bf_cmd(dev, "TEST", data)
        if not ok and isinstance(seq, str) and len(seq) <= 16:
            ok, _, _ = bf_cmd(dev, seq.upper())
        return ok
    except:
        return False

def test_fuzz(dev, data: bytes) -> Tuple[bool, bool]:
    """Test fuzz data. Returns (crash, interesting)"""
    try:
        ok, name, extra = bf_cmd(dev, "FUZZ", data)
        crash_indicators = ['CRASH', 'FATAL', 'PANIC', 'EXCEPTION', 'RESET']
        crash = any(i in name.upper() for i in crash_indicators) if name else True
        return crash, len(extra) > 0
    except:
        return True, False

class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=40):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
    
    def __enter__(self):
        self.update(0)
        return self
    
    def __exit__(self, *a):
        print()
    
    def update(self, n):
        self.current += n
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '─' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {self.suffix}', end='', flush=True)

# =============================================================================
# CORE SUBCOMMANDS (BRUTEFORCE, TEST, FUZZ, RAWMODE)
# =============================================================================

def cmd_list(dev, args, threads, rawmode, output, strategy):
    """List available strategies and dictionaries"""
    print(f"\n[*] Bruteforce Strategies:")
    for name, desc in STRATEGIES.items():
        print(f"    {name:<12} {desc}")
    
    print(f"\n[*] Built-in Dictionaries:")
    for k, v in BUILTIN_DICTS.items():
        print(f"    {k:<12} {len(v)} words")
    
    print(f"\n[*] Pattern formats:")
    print(f"    hex:       0x1000-0x2000  (address range)")
    print(f"    numeric:   0000-9999      (numeric range)")
    print(f"    string:    admin          (exact string)")
    
    return True

def cmd_scan(dev, args, threads, rawmode, output, strategy):
    """Systematic address scan (BRUTEFORCE)"""
    pattern = args[0] if args else ""
    ranges = parse_range(pattern) if pattern else [
        (0x10000000, 0x10001000, "Peripheral"),
        (0x80000000, 0x80001000, "DRAM"),
    ]
    
    if rawmode:
        bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
    results = {'scanned': 0, 'interesting': []}
    start_time = time.time()
    
    for start, end, desc in ranges:
        scan_sz = min(end - start, MAX_SCAN)
        total = scan_sz // 4
        
        print(f"\n[*] {desc}: 0x{start:08X}-0x{start + scan_sz:08X}")
        
        with ProgressBar(total, prefix='Scanning', suffix='Complete') as pb:
            for off in range(0, scan_sz, 4):
                addr = start + off
                ok, _, data = bf_cmd(dev, "READ", struct.pack("<II", addr, 4))
                if ok and data and data != b'\x00\x00\x00\x00':
                    results['interesting'].append({
                        'address': f"0x{addr:08X}",
                        'data': data[:4].hex()
                    })
                results['scanned'] += 1
                pb.update(1)
    
    elapsed = time.time() - start_time
    rate = results['scanned'] / max(elapsed, 0.001)
    
    print(f"\n[+] Scan: {results['scanned']} addresses in {elapsed:.1f}s ({rate:.0f}/s)")
    print(f"    Interesting: {len(results['interesting'])}")
    
    if output:
        save_results(output, results, 'scan')
    return True

def cmd_pattern(dev, args, threads, rawmode, output, strategy):
    """Pattern-based brute-force (BRUTEFORCE)"""
    if not args:
        print("[!] Specify pattern (e.g., 0x0000-0xFFFF)")
        return False
    
    pattern = args[0]
    seqs = gen_sequences(pattern)
    
    if rawmode:
        bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
    print(f"\n[*] Pattern: {pattern} ({len(seqs)} sequences)")
    
    results = {'successful': [], 'tested': 0}
    start_time = time.time()
    
    with ProgressBar(len(seqs), prefix='Pattern', suffix='Complete') as pb:
        for i, seq in enumerate(seqs):
            if test_sequence(dev, seq, rawmode):
                results['successful'].append(seq)
                print(f"\n[+] Match: {seq}")
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output:
                save_results(output, results, 'pattern')
    
    elapsed = time.time() - start_time
    rate = len(results['successful']) / max(results['tested'], 1) * 100
    
    print(f"\n[+] {results['tested']} tested, {len(results['successful'])} found ({rate:.1f}%) in {elapsed:.1f}s")
    
    if output:
        save_results(output, results, 'pattern')
    return True

def cmd_fuzz(dev, args, threads, rawmode, output, strategy):
    """Fuzzing attack (FUZZ)"""
    iters = min(MAX_FUZZ, 1000)
    max_sz = 256
    
    for a in args:
        if a.startswith('iterations:'):
            iters = min(MAX_FUZZ, int(a.split(':')[1]))
        elif a.startswith('size:'):
            max_sz = int(a.split(':')[1])
    
    if rawmode:
        bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
    print(f"\n[*] Fuzzing: {iters} iterations ({max_sz}B max)")
    
    results = {'crashes': [], 'interesting': [], 'tested': 0}
    start_time = time.time()
    
    with ProgressBar(iters, prefix='Fuzzing', suffix='Complete') as pb:
        for i in range(iters):
            data = gen_fuzz(max_sz)
            crash, interesting = test_fuzz(dev, data)
            
            if crash:
                results['crashes'].append({'iteration': i, 'data': data[:32].hex()})
                print(f"\n[!] Crash at {i}")
            if interesting:
                results['interesting'].append({'iteration': i, 'data': data[:32].hex()})
            
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output:
                save_results(output, results, 'fuzz')
    
    elapsed = time.time() - start_time
    
    print(f"\n[+] {results['tested']} tests, {len(results['crashes'])} crashes, "
          f"{len(results['interesting'])} interesting in {elapsed:.1f}s")
    
    if output:
        save_results(output, results, 'fuzz')
    return True

def cmd_dictionary(dev, args, threads, rawmode, output, strategy):
    """Dictionary attack (BRUTEFORCE)"""
    if not args:
        print("[!] Specify dictionary source")
        return False
    
    words = load_dict(args[0])
    if not words:
        print("[!] No words loaded")
        return False
    
    if rawmode:
        bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
    print(f"\n[*] Dictionary: {len(words)} words")
    
    results = {'successful': [], 'tested': 0}
    start_time = time.time()
    
    with ProgressBar(len(words), prefix='Dictionary', suffix='Complete') as pb:
        for i, word in enumerate(words):
            if test_sequence(dev, word, rawmode):
                results['successful'].append(word)
                print(f"\n[+] Match: {word}")
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output:
                save_results(output, results, 'dictionary')
    
    elapsed = time.time() - start_time
    
    print(f"\n[+] {results['tested']} tested, {len(results['successful'])} found in {elapsed:.1f}s")
    
    if output:
        save_results(output, results, 'dictionary')
    return True

def cmd_analyze(dev, args, threads, rawmode, output, strategy):
    """Analyze results file"""
    if not args:
        print("[!] Specify results file")
        return False
    
    if not os.path.exists(args[0]):
        print(f"[!] Not found: {args[0]}")
        return False
    
    try:
        with open(args[0], 'r', errors='ignore') as f:
            content = f.read()
        
        lines = [l for l in content.split('\n') if l.strip()]
        success_lines = [l for l in lines if any(k in l.upper() for k in ['SUCCESS', 'MATCHED', 'FOUND'])]
        
        print(f"\n[+] Analysis of {args[0]}:")
        print(f"    Lines:     {len(lines)}")
        print(f"    Successful: {len(success_lines)} ({len(success_lines) / max(len(lines), 1) * 100:.1f}%)")
        
        if success_lines:
            print(f"\n    Examples:")
            for s in success_lines[:5]:
                print(f"    - {s[:80]}")
    except Exception as e:
        print(f"[!] Analyze error: {e}")
    
    return True

def cmd_rawmode_helper(dev, args, threads, rawmode, output, strategy):
    """Enable/disable RAWMODE for bruteforce"""
    subcmd = args[0].lower() if args else 'status'
    
    if subcmd == 'enable':
        ok, name, _ = bf_cmd(dev, "RAWMODE", b"ENABLE")
        if ok:
            print("[+] RAWMODE enabled")
        else:
            print(f"[!] RAWMODE failed: {name}")
        return ok
    elif subcmd == 'disable':
        ok, name, _ = bf_cmd(dev, "RAWMODE", b"DISABLE")
        if ok:
            print("[+] RAWMODE disabled")
        else:
            print(f"[!] RAWMODE disable failed: {name}")
        return ok
    else:
        print("[*] RAWMODE status helper")
        print("    Usage: bruteforce rawmode enable|disable")
        return True

# =============================================================================
# COMMAND HANDLERS
# =============================================================================
HANDLERS = {
    # Core bruteforce commands
    'list': cmd_list,
    'ls': cmd_list,
    'scan': cmd_scan,
    'search': cmd_scan,
    'pattern': cmd_pattern,
    'seq': cmd_pattern,
    'fuzz': cmd_fuzz,
    'fuzzer': cmd_fuzz,
    'dictionary': cmd_dictionary,
    'dict': cmd_dictionary,
    'analyze': cmd_analyze,
    'analysis': cmd_analyze,
    # RAWMODE helper
    'rawmode': cmd_rawmode_helper,
}

# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_bruteforce(args=None) -> int:
    """
    QSLCL BRUTEFORCE - Automated testing and scanning
    
    Core commands (BRUTEFORCE, TEST, FUZZ, RAWMODE):
    
        bruteforce list                        - List strategies
        bruteforce scan 0x10000000-0x10001000  - Address scan
        bruteforce pattern 0x0000-0x00FF       - Pattern brute-force
        bruteforce fuzz iterations:500         - Fuzzing (FUZZ)
        bruteforce dictionary common           - Dictionary attack
        bruteforce analyze results.txt         - Analyze results
        bruteforce rawmode enable              - Enable RAWMODE
    
    Note: TEST command is used internally by bruteforce operations
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: bruteforce <list|scan|pattern|fuzz|dictionary|analyze|rawmode>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'bruteforce_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    bargs = getattr(args, 'bruteforce_args', []) or getattr(args, 'args', []) or []
    
    # Legacy pattern argument
    pattern = getattr(args, 'pattern', '')
    if pattern and not bargs:
        bargs = [pattern]
    
    threads = max(1, min(32, getattr(args, 'threads', DEFAULT_THREADS) or DEFAULT_THREADS))
    rawmode = getattr(args, 'rawmode', False)
    output = getattr(args, 'output', '') or getattr(args, 'output_file', '')
    strategy = getattr(args, 'strategy', 'basic') or 'basic'
    
    if not sub or sub in ('help', '?'):
        print("[*] Bruteforce Commands:")
        for name in sorted(HANDLERS.keys()):
            if '_' not in name and len(name) < 15:
                doc = (HANDLERS[name].__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<12} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        print(f"[*] Available: {', '.join(sorted(set(HANDLERS.keys())))}")
        return 1
    
    try:
        return 0 if handler(dev, bargs, threads, rawmode, output, strategy) else 1
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
    print("[*] bruteforce.py - QSLCL BRUTEFORCE Command Module v3.0")
    print("[*] Core commands: BRUTEFORCE, TEST, FUZZ, RAWMODE")
    print("[*] Usage: python qslcl.py bruteforce <subcommand> [args]")