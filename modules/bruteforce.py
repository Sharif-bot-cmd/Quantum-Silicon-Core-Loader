#!/usr/bin/env python3
"""
bruteforce.py - QSLCL BRUTEFORCE Command Module v2.1 (CLEANED)
Automated testing, scanning, fuzzing, and dictionary attacks
"""

import os
import sys
import struct
import time
import json
import random
import threading
from queue import Queue
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
MAX_SCAN = 0x10000
MAX_SEQ = 1000
MAX_FUZZ = 10000
DEFAULT_THREADS = 4

# =============================================================================
# BRUTEFORCE OPCODES (Missing from original)
# =============================================================================

BF_OP_TEST = 0x00
BF_OP_SCAN = 0x01
BF_OP_PATTERN = 0x02
BF_OP_FUZZ = 0x03
BF_OP_DICT = 0x04
BF_OP_REPLAY = 0x05
BF_OP_ANALYZE = 0x06
BF_OP_CONTINUE = 0x07

# Advanced opcodes (missing)
BF_OP_TIMING = 0x10          # Timing attack
BF_OP_GLITCH = 0x11          # Glitch injection
BF_OP_VOLTAGE = 0x12         # Voltage fault injection
BF_OP_CLOCK = 0x13           # Clock glitching
BF_OP_EMFI = 0x14            # Electromagnetic fault injection
BF_OP_LASER = 0x15           # Laser fault injection (theoretical)
BF_OP_BF_MEM = 0x20          # Memory brute-force
BF_OP_BF_REG = 0x21          # Register brute-force
BF_OP_BF_IO = 0x22           # I/O brute-force
BF_OP_BF_USB = 0x23          # USB endpoint brute-force
BF_OP_BF_DFU = 0x24          # DFU command brute-force
BF_OP_BF_EDL = 0x25          # EDL command brute-force
BF_OP_BF_BROM = 0x26         # BROM command brute-force
BF_OP_BF_POWER = 0x30        # Power analysis brute-force
BF_OP_BF_TEMP = 0x31         # Temperature analysis
BF_OP_BF_EM = 0x32           # Electromagnetic analysis
BF_OP_BF_AI = 0x40           # AI-assisted brute-force
BF_OP_BF_ML = 0x41           # Machine learning pattern detection
BF_OP_BF_QUANTUM = 0x50      # Quantum brute-force (future)

# =============================================================================
# EXPANDED STRATEGIES (More comprehensive)
# =============================================================================

STRATEGIES = {
    # Basic strategies
    'basic':      'Sequential linear search (slow, thorough)',
    'smart':      'Heuristic optimization (balanced)',
    'aggressive': 'Parallel multi-threaded (fast, less coverage)',
    
    # Advanced strategies (MISSING from original)
    'timing':     'Timing-based side-channel attack',
    'adaptive':   'Adaptive learning from previous results',
    'differential': 'Differential fault analysis',
    'statistical':  'Statistical pattern analysis',
    'entropy':      'Entropy-based prioritization',
    'dictionary':   'Smart dictionary with mutations',
    'hybrid':       'Combination of multiple strategies',
    'cloud':        'Distributed across multiple devices',
    'ai':           'AI/ML assisted pattern recognition',
    'quantum':      'Quantum-resistant brute-force (future)',
}

# Fault injection types (MISSING)
FAULT_TYPES = {
    'voltage':   'Voltage glitching (VDD/VSS)',
    'clock':     'Clock glitching (Fault injection)',
    'em':        'Electromagnetic fault injection',
    'laser':     'Laser fault injection (physical)',
    'temp':      'Temperature extreme injection',
    'power':     'Power analysis fault',
    'usb':       'USB protocol fault injection',
    'timing':    'Timing violation injection',
}

# Scan types (MISSING)
SCAN_TYPES = {
    'memory':    'Memory address space scan',
    'register':  'Register space scan',
    'mmio':      'MMIO region scan',
    'pcie':      'PCIe configuration space',
    'usb':       'USB endpoint scan',
    'dfu':       'DFU command scan',
    'edl':       'EDL command scan',
    'brom':      'BROM command scan',
}

BUILTIN_DICTS = {
    'common':    ['admin','password','1234','test','default','root','user','guest','abc123','letmein'],
    'passwords': ['password','123456','admin','letmein','qwerty','monkey','abc123','dragon','master','hello'],
    'hex':       [f"0x{i:04X}" for i in range(0, 0x100, 0x10)],
    'commands':  ['READ','WRITE','ERASE','HELLO','PING','GETINFO','AUTH','UNLOCK','CONFIG','BRUTEFORCE'],
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
            if attempt == 0: time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""

def timing_attack(dev, cmd: str, payload: bytes = b"", samples: int = 100) -> dict:
    """Perform timing-based side-channel attack"""
    times = []
    
    for i in range(samples):
        start = time.perf_counter()
        ok, _, _ = bf_cmd(dev, cmd, payload)
        elapsed = (time.perf_counter() - start) * 1000000  # microseconds
        
        if ok:
            times.append(elapsed)
        
        # Small delay between samples
        time.sleep(0.001)
    
    if not times:
        return {'success': False, 'avg_time': 0, 'min_time': 0, 'max_time': 0, 'stddev': 0}
    
    avg = sum(times) / len(times)
    min_t = min(times)
    max_t = max(times)
    variance = sum((t - avg) ** 2 for t in times) / len(times)
    stddev = variance ** 0.5
    
    return {
        'success': True,
        'samples': len(times),
        'avg_time': avg,
        'min_time': min_t,
        'max_time': max_t,
        'stddev': stddev,
        'timing_leak': stddev > (avg * 0.1)  # >10% variance indicates leak
    }

def entropy_analysis(data: bytes) -> dict:
    """Calculate entropy of data for prioritization"""
    if not data:
        return {'entropy': 0, 'unique_bytes': 0, 'distribution': {}}
    
    byte_counts = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    
    entropy = 0
    total = len(data)
    for count in byte_counts.values():
        p = count / total
        entropy -= p * (p.bit_length() - 1) if p > 0 else 0
    
    return {
        'entropy': entropy,
        'unique_bytes': len(byte_counts),
        'distribution': byte_counts,
        'random_likely': entropy > 6.5  # High entropy suggests random/encrypted
    }

def adaptive_next(previous_results: list, strategy: str) -> list:
    """Generate next test values based on previous results"""
    if not previous_results:
        return []
    
    next_values = []
    
    if strategy == 'adaptive':
        # Find patterns in successful values
        successes = [r for r in previous_results if r.get('success')]
        
        if successes:
            # Extract numeric values
            numeric_vals = []
            for s in successes:
                val = s.get('value', '')
                if val.startswith('0x'):
                    try:
                        numeric_vals.append(int(val, 16))
                    except:
                        pass
            
            if numeric_vals:
                # Generate values around successes
                for val in numeric_vals:
                    next_values.extend([
                        f"0x{val - 0x10:08X}",
                        f"0x{val - 0x01:08X}",
                        f"0x{val + 0x01:08X}",
                        f"0x{val + 0x10:08X}",
                    ])
    
    elif strategy == 'differential':
        # Differential analysis - try bit flips
        successes = [r for r in previous_results if r.get('success')]
        for s in successes[:5]:  # Limit to 5
            val_str = s.get('value', '')
            if val_str.startswith('0x'):
                try:
                    val = int(val_str, 16)
                    # Try flipping each bit
                    for bit in range(32):
                        flipped = val ^ (1 << bit)
                        next_values.append(f"0x{flipped:08X}")
                except:
                    pass
    
    # Remove duplicates and limit
    next_values = list(dict.fromkeys(next_values))[:100]
    
    return next_values

def multi_device_scan(devices: list, pattern: str, threads: int = 4) -> dict:
    """Distribute bruteforce across multiple devices"""
    if len(devices) <= 1:
        return {'error': 'Need multiple devices'}
    
    results = {'total': 0, 'successful': [], 'device_results': {}}
    
    def scan_device(dev, seqs, device_id):
        local_results = []
        for seq in seqs:
            if test_sequence(dev, seq, False):
                local_results.append(seq)
        results['device_results'][device_id] = local_results
    
    # Split sequences across devices
    seqs = gen_sequences(pattern)
    chunk_size = max(1, len(seqs) // len(devices))
    
    threads_list = []
    for i, dev in enumerate(devices):
        start = i * chunk_size
        end = start + chunk_size if i < len(devices) - 1 else len(seqs)
        dev_seqs = seqs[start:end]
        
        t = threading.Thread(target=scan_device, args=(dev, dev_seqs, i))
        threads_list.append(t)
        t.start()
    
    for t in threads_list:
        t.join()
    
    # Aggregate results
    for device_results in results['device_results'].values():
        results['successful'].extend(device_results)
    
    results['total'] = len(seqs)
    results['unique_success'] = len(set(results['successful']))
    
    return results

def test_sequence(dev, seq, rawmode: bool = False) -> bool:
    """Test a sequence against device"""
    try:
        if isinstance(seq, str):
            if seq.startswith('0x'):
                val = int(seq, 16)
                data = val.to_bytes(max(1, (val.bit_length()+7)//8), 'little')
            else:
                data = seq.encode('utf-8')
        else:
            data = seq if isinstance(seq, bytes) else str(seq).encode()
        
        ok, _, _ = bf_cmd(dev, "TEST", data)
        if not ok and isinstance(seq, str) and len(seq) <= 16:
            ok, _, _ = bf_cmd(dev, seq.upper())
        return ok
    except: return False


def test_fuzz(dev, data: bytes) -> Tuple[bool, bool]:
    """Test fuzz data. Returns (crash, interesting)"""
    try:
        ok, name, extra = bf_cmd(dev, "FUZZ", data)
        crash_indicators = ['CRASH','FATAL','PANIC','EXCEPTION','RESET']
        crash = any(i in name.upper() for i in crash_indicators) if name else True
        return crash, len(extra) > 0
    except: return True, False


def parse_addr(s: str) -> int:
    s = str(s).strip().lower()
    if s.startswith('0x'): return int(s[2:], 16)
    try: return int(s, 16)
    except: return int(s, 10)


def parse_range(pattern: str) -> List[Tuple[int, int, str]]:
    """Parse pattern into scan ranges"""
    if not pattern: return []
    
    try:
        if '-' in pattern and pattern.count('-') == 1:
            if pattern.startswith('0x'):
                parts = pattern.split('-')
                s, e = int(parts[0], 16), int(parts[1], 16)
                return [(s, e, f"Hex range 0x{s:X}-0x{e:X}")]
            elif pattern.replace('-','').isdigit():
                parts = pattern.split('-')
                return [(int(parts[0]), int(parts[1]), f"Numeric range")]
        
        addr = parse_addr(pattern)
        return [(addr, addr + 0x1000, f"Address 0x{addr:X}")]
    except: pass
    
    return [(0x10000000, 0x10001000, "Default")]


def gen_sequences(pattern: str) -> List[str]:
    """Generate test sequences from pattern"""
    seqs = []
    try:
        if pattern.startswith('0x') and '-' in pattern:
            parts = pattern.split('-')
            s, e = int(parts[0], 16), int(parts[1], 16)
            step = max(1, (e - s) // MAX_SEQ)
            for v in range(s, min(e+1, s+MAX_SEQ*step), step):
                seqs.append(f"0x{v:0{(e.bit_length()+3)//4}X}")
        elif pattern.replace('-','').isdigit() and '-' in pattern:
            parts = pattern.split('-')
            s, e = int(parts[0]), int(parts[1])
            step = max(1, (e - s) // MAX_SEQ)
            for v in range(s, min(e+1, s+MAX_SEQ*step), step):
                seqs.append(str(v))
        else:
            seqs.append(pattern)
    except: seqs = [pattern] if pattern else []
    return seqs[:MAX_SEQ]


def gen_fuzz(ms: int = 256) -> bytes:
    """Generate fuzz data"""
    size = random.randint(1, min(ms, 1024))
    choices = [b'\x00'*size, b'\xFF'*size, 
               bytes([random.getrandbits(8)])*size, os.urandom(size)]
    return random.choice(choices)


def load_dict(source: str) -> List[str]:
    """Load dictionary"""
    if source in BUILTIN_DICTS:
        return BUILTIN_DICTS[source]
    try:
        if os.path.exists(source):
            with open(source, 'r', errors='ignore') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except: pass
    return []


def save_results(path: str, results: dict, atype: str):
    """Save results to file"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        with open(path, 'a' if os.path.exists(path) else 'w') as f:
            f.write(f"\n{'='*50}\n{atype.upper()} RESULTS\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tested: {results.get('tested',results.get('scanned',0))}\n")
            f.write(f"Success: {len(results.get('successful',[]))}\n")
            
            for s in results.get('successful', [])[:50]:
                f.write(f"  {s}\n")
            for i in results.get('interesting', [])[:50]:
                f.write(f"  {i}\n")
        
        if not _DEBUG: print(f"\n[+] Saved: {path}")
    except Exception as e:
        print(f"[!] Save error: {e}")


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
def cmd_list(dev, args, threads, rawmode, output, strategy):
    """List strategies, fault types, and scan methods"""
    print(f"\n[*] Strategies:")
    for name, desc in STRATEGIES.items():
        print(f"    {name:<14} {desc}")
    
    print(f"\n[*] Fault Injection Types:")
    for name, desc in FAULT_TYPES.items():
        print(f"    {name:<14} {desc}")
    
    print(f"\n[*] Scan Types:")
    for name, desc in SCAN_TYPES.items():
        print(f"    {name:<14} {desc}")
    
    print(f"\n[*] Built-in Dictionaries:")
    for k, v in BUILTIN_DICTS.items():
        print(f"    {k:<14} {len(v)} words")
    
    print(f"\n[*] Pattern formats:")
    print(f"    hex:           0x1000-0x2000  (address range)")
    print(f"    numeric:       0000-9999      (numeric range)")
    print(f"    string:        admin          (exact string)")
    print(f"    wildcard:      pass*          (prefix match)")
    print(f"    regex:         [A-Z0-9]{8}    (regex pattern)")
    
    return True

def cmd_scan(dev, args, threads, rawmode, output, strategy):
    """Systematic address scan"""
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
        
        print(f"\n[*] {desc}: 0x{start:08X}-0x{start+scan_sz:08X}")
        
        with ProgressBar(total, prefix='Scanning', suffix='Complete') as pb:
            for off in range(0, scan_sz, 4):
                addr = start + off
                ok, _, data = bf_cmd(dev, "READ", struct.pack("<II", addr, 4))
                if ok and data and data != b'\x00\x00\x00\x00':
                    results['interesting'].append({'address': f"0x{addr:08X}", 'data': data[:4].hex()})
                results['scanned'] += 1
                pb.update(1)
    
    elapsed = time.time() - start_time
    rate = results['scanned'] / max(elapsed, 0.001)
    
    print(f"\n[+] Scan: {results['scanned']} addresses in {elapsed:.1f}s ({rate:.0f}/s)")
    print(f"    Interesting: {len(results['interesting'])}")
    
    if output: save_results(output, results, 'scan')
    return True


def cmd_pattern(dev, args, threads, rawmode, output, strategy):
    """Pattern-based brute-force"""
    if not args:
        print("[!] Specify pattern (e.g., 0x0000-0xFFFF)"); return False
    
    pattern = args[0]
    seqs = gen_sequences(pattern)
    
    if rawmode: bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
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
    
    if output: save_results(output, results, 'pattern')
    return True


def cmd_fuzz(dev, args, threads, rawmode, output, strategy):
    """Fuzzing attack"""
    iters = min(MAX_FUZZ, 1000)
    max_sz = 256
    
    for a in args:
        if a.startswith('iterations:'):
            iters = min(MAX_FUZZ, int(a.split(':')[1]))
        elif a.startswith('size:'):
            max_sz = int(a.split(':')[1])
    
    if rawmode: bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
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
    
    if output: save_results(output, results, 'fuzz')
    return True


def cmd_dictionary(dev, args, threads, rawmode, output, strategy):
    """Dictionary attack"""
    if not args:
        print("[!] Specify dictionary source"); return False
    
    words = load_dict(args[0])
    if not words:
        print("[!] No words loaded"); return False
    
    if rawmode: bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
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
    
    if output: save_results(output, results, 'dictionary')
    return True


def cmd_replay(dev, args, threads, rawmode, output, strategy):
    """Replay captured data"""
    if not args:
        print("[!] Specify replay file"); return False
    
    items = load_dict(args[0])
    if not items:
        print("[!] No replay data"); return False
    
    if rawmode: bf_cmd(dev, "RAWMODE", b"UNLOCK")
    
    print(f"\n[*] Replay: {len(items)} items")
    
    results = {'successful': [], 'tested': 0}
    start_time = time.time()
    
    with ProgressBar(len(items), prefix='Replay', suffix='Complete') as pb:
        for i, item in enumerate(items):
            if test_sequence(dev, item, rawmode):
                results['successful'].append(item)
                print(f"\n[+] Success: {item}")
            results['tested'] += 1
            pb.update(1)
    
    elapsed = time.time() - start_time
    
    print(f"\n[+] {results['tested']} replayed, {len(results['successful'])} success in {elapsed:.1f}s")
    
    if output: save_results(output, results, 'replay')
    return True


def cmd_analyze(dev, args, threads, rawmode, output, strategy):
    """Analyze results file"""
    if not args:
        print("[!] Specify results file"); return False
    
    if not os.path.exists(args[0]):
        print(f"[!] Not found: {args[0]}"); return False
    
    try:
        with open(args[0], 'r', errors='ignore') as f:
            content = f.read()
        
        lines = [l for l in content.split('\n') if l.strip()]
        success_lines = [l for l in lines if any(k in l.upper() for k in ['SUCCESS','MATCHED','FOUND','CRASH'])]
        
        print(f"\n[+] Analysis of {args[0]}:")
        print(f"    Lines:     {len(lines)}")
        print(f"    Successful: {len(success_lines)} ({len(success_lines)/max(len(lines),1)*100:.1f}%)")
        
        if success_lines:
            print(f"\n    Examples:")
            for s in success_lines[:5]:
                print(f"    - {s[:80]}")
    except Exception as e:
        print(f"[!] Analyze error: {e}")
    
    return True

def cmd_timing(dev, args, threads, rawmode, output, strategy):
    """Timing side-channel attack"""
    print(f"\n[*] Timing attack (strategy: {strategy})")
    
    cmd = args[0] if args else "PING"
    samples = int(args[1]) if len(args) > 1 else 100
    
    print(f"    Target command: {cmd}")
    print(f"    Samples: {samples}")
    
    results = timing_attack(dev, cmd, b"", samples)
    
    print(f"\n[+] Timing analysis:")
    print(f"    Samples: {results.get('samples', 0)}")
    print(f"    Avg: {results.get('avg_time', 0):.2f} μs")
    print(f"    Min: {results.get('min_time', 0):.2f} μs")
    print(f"    Max: {results.get('max_time', 0):.2f} μs")
    print(f"    StdDev: {results.get('stddev', 0):.2f} μs")
    print(f"    Timing leak: {'YES (vulnerable)' if results.get('timing_leak') else 'NO'}")
    
    if output:
        save_results(output, results, 'timing')
    
    return True

def cmd_glitch(dev, args, threads, rawmode, output, strategy):
    """Fault injection glitching"""
    glitch_type = args[0] if args else 'voltage'
    
    if glitch_type not in FAULT_TYPES:
        print(f"[!] Unknown glitch type: {glitch_type}")
        print(f"    Available: {', '.join(FAULT_TYPES.keys())}")
        return False
    
    print(f"\n[*] Fault injection: {FAULT_TYPES[glitch_type]}")
    print("    This may cause device instability!")
    
    if not rawmode:
        print("[!] RAWMODE required for glitching")
        bf_cmd(dev, "RAWMODE", b"ENABLE")
    
    iterations = 100
    results = {'crashes': [], 'successes': [], 'tested': 0}
    
    print(f"    Iterations: {iterations}")
    
    with ProgressBar(iterations, prefix='Glitching', suffix='Complete') as pb:
        for i in range(iterations):
            # Send glitch command
            payload = struct.pack("<BI", BF_OP_GLITCH, i)
            ok, name, extra = bf_cmd(dev, "GLITCH", payload)
            
            if not ok or 'CRASH' in name.upper():
                results['crashes'].append({'iteration': i, 'result': name})
                print(f"\n[!] Crash at iteration {i}: {name}")
            elif ok:
                results['successes'].append({'iteration': i, 'result': name})
            
            results['tested'] += 1
            pb.update(1)
    
    print(f"\n[+] Glitch results:")
    print(f"    Iterations: {results['tested']}")
    print(f"    Crashes: {len(results['crashes'])} ({len(results['crashes'])/results['tested']*100:.1f}%)")
    print(f"    Successes: {len(results['successes'])}")
    
    if output:
        save_results(output, results, 'glitch')
    
    return True

def cmd_voltage_fault(dev, args, threads, rawmode, output, strategy):
    """Voltage fault injection"""
    if not args:
        print("[!] Specify voltage range (e.g., 0.8-1.2)")
        return False
    
    try:
        if '-' in args[0]:
            v_min, v_max = [float(x) for x in args[0].split('-')]
        else:
            v_min = v_max = float(args[0])
    except:
        print("[!] Invalid voltage format")
        return False
    
    steps = int(args[1]) if len(args) > 1 else 10
    step_size = (v_max - v_min) / steps
    
    print(f"\n[*] Voltage fault injection: {v_min}V - {v_max}V ({steps} steps)")
    
    if not rawmode:
        bf_cmd(dev, "RAWMODE", b"ENABLE")
    
    results = {'voltage_levels': [], 'crashes': [], 'successes': []}
    
    with ProgressBar(steps, prefix='Voltage', suffix='Complete') as pb:
        for i in range(steps + 1):
            voltage = v_min + (i * step_size)
            
            payload = struct.pack("<Bf", BF_OP_VOLTAGE, voltage)
            ok, name, extra = bf_cmd(dev, "VOLTAGE", payload)
            
            results['voltage_levels'].append(voltage)
            
            if not ok or 'CRASH' in name.upper():
                results['crashes'].append({'voltage': voltage, 'result': name})
                print(f"\n[!] Crash at {voltage:.2f}V: {name}")
            elif ok:
                results['successes'].append({'voltage': voltage, 'result': name})
            
            pb.update(1)
    
    print(f"\n[+] Voltage analysis:")
    print(f"    Safe voltages: {len([v for v in results['successes'] if 'CRASH' not in str(v)])}")
    print(f"    Crash voltages: {len(results['crashes'])}")
    
    if output:
        save_results(output, results, 'voltage')
    
    return True

def cmd_ai_assisted(dev, args, threads, rawmode, output, strategy):
    """AI/ML assisted pattern detection"""
    print(f"\n[*] AI-assisted brute-force (experimental)")
    
    # This is a placeholder for AI/ML integration
    # In production, you'd integrate with TensorFlow Lite, PyTorch, etc.
    
    print("    Analyzing previous results for patterns...")
    
    # Load previous results if available
    previous_results = []
    if args and os.path.exists(args[0]):
        try:
            with open(args[0], 'r') as f:
                content = f.read()
                # Simple pattern extraction
                import re
                hex_matches = re.findall(r'0x[0-9A-Fa-f]+', content)
                for match in hex_matches[:100]:
                    previous_results.append({'value': match, 'success': True})
        except:
            pass
    
    # Generate predictions based on patterns
    predictions = adaptive_next(previous_results, 'adaptive')
    
    print(f"    Generated {len(predictions)} predictions from patterns")
    
    # Test predictions
    results = {'tested': 0, 'successful': [], 'ai_predictions': len(predictions)}
    
    with ProgressBar(len(predictions), prefix='AI Testing', suffix='Complete') as pb:
        for pred in predictions:
            if test_sequence(dev, pred, rawmode):
                results['successful'].append(pred)
                print(f"\n[+] AI found: {pred}")
            results['tested'] += 1
            pb.update(1)
    
    print(f"\n[+] AI-assisted results:")
    print(f"    Predictions tested: {results['tested']}")
    print(f"    Successful: {len(results['successful'])} ({len(results['successful'])/results['tested']*100:.1f}%)")
    
    if output:
        save_results(output, results, 'ai_assisted')
    
    return True

def cmd_quantum_bf(dev, args, threads, rawmode, output, strategy):
    """Quantum brute-force (future/placeholder)"""
    print(f"\n[*] Quantum brute-force (theoretical)")
    print("    This is a placeholder for future quantum computing integration")
    print("    When quantum hardware becomes available, this will:")
    print("    - Use Grover's algorithm for 2x speedup")
    print("    - Implement Shor's algorithm for factorization")
    print("    - Leverage quantum annealing for optimization")
    
    print("\n[!] Quantum hardware not detected - simulation mode")
    
    # Simulate quantum speedup (just for demonstration)
    print("\n[*] Simulated quantum speedup:")
    traditional_time = 1000  # seconds
    quantum_speedup = 100  # 100x for Grover's algorithm
    quantum_time = traditional_time / quantum_speedup
    
    print(f"    Traditional time: {traditional_time}s")
    print(f"    Quantum time: {quantum_time:.1f}s ({quantum_speedup}x faster)")
    
    return True

def cmd_scan_memory(dev, args, threads, rawmode, output, strategy):
    """Memory-specific scan"""
    start_addr = parse_addr(args[0]) if args else 0x80000000
    end_addr = parse_addr(args[1]) if len(args) > 1 else start_addr + 0x10000
    pattern = args[2] if len(args) > 2 else None
    
    print(f"\n[*] Memory scan: 0x{start_addr:08X} - 0x{end_addr:08X}")
    
    if pattern:
        print(f"    Pattern filter: {pattern}")
    
    results = {'scanned': 0, 'interesting': [], 'matches': []}
    
    with ProgressBar((end_addr - start_addr) // 4, prefix='Memory', suffix='Complete') as pb:
        for addr in range(start_addr, end_addr, 4):
            ok, _, data = bf_cmd(dev, "READ", struct.pack("<II", addr, 4))
            
            if ok and data and data != b'\x00\x00\x00\x00':
                if pattern:
                    hex_data = data[:4].hex()
                    if pattern.lower() in hex_data.lower():
                        results['matches'].append({'address': f"0x{addr:08X}", 'data': hex_data})
                else:
                    results['interesting'].append({'address': f"0x{addr:08X}", 'data': data[:4].hex()})
            
            results['scanned'] += 1
            pb.update(1)
            if results['scanned'] % 10000 == 0:
                # Yield to prevent blocking
                time.sleep(0.001)
    
    print(f"\n[+] Memory scan complete:")
    print(f"    Addresses: {results['scanned']}")
    print(f"    Interesting: {len(results['interesting'])}")
    print(f"    Pattern matches: {len(results['matches'])}")
    
    if output:
        save_results(output, results, 'memory_scan')
    
    return True

def cmd_scan_usb(dev, args, threads, rawmode, output, strategy):
    """USB endpoint scan"""
    print(f"\n[*] USB endpoint scan")
    
    results = {'endpoints': [], 'control_requests': [], 'tested': 0}
    
    # Scan endpoint addresses
    for ep_addr in range(0x00, 0x90, 0x01):
        ok, name, extra = bf_cmd(dev, "USB_TEST", struct.pack("<B", ep_addr))
        results['tested'] += 1
        
        if ok:
            results['endpoints'].append({
                'address': f"0x{ep_addr:02X}",
                'direction': 'IN' if ep_addr & 0x80 else 'OUT',
                'response': name
            })
            print(f"    [+] Endpoint 0x{ep_addr:02X}: {name}")
    
    # Scan control requests (for DFU/EDL mode)
    for req in range(0x00, 0x20):
        ok, name, extra = bf_cmd(dev, "CTRL_TEST", struct.pack("<B", req))
        results['tested'] += 1
        
        if ok:
            results['control_requests'].append({
                'request': f"0x{req:02X}",
                'response': name
            })
            print(f"    [+] Control request 0x{req:02X}: {name}")
    
    print(f"\n[+] USB scan complete:")
    print(f"    Endpoints found: {len(results['endpoints'])}")
    print(f"    Control requests: {len(results['control_requests'])}")
    
    if output:
        save_results(output, results, 'usb_scan')
    
    return True

def cmd_continue(dev, args, threads, rawmode, output, strategy):
    """Continue interrupted session"""
    if not args:
        print("[!] Specify session file"); return False
    
    try:
        with open(args[0], 'r') as f:
            session = json.load(f)
    except:
        print("[!] Cannot load session"); return False
    
    stype = session.get('type', 'scan')
    print(f"\n[*] Resuming: {stype}")
    
    # Route based on saved type
    if stype == 'scan': return cmd_scan(dev, args, threads, rawmode, output, strategy)
    elif stype == 'pattern': return cmd_pattern(dev, args, threads, rawmode, output, strategy)
    elif stype == 'fuzz': return cmd_fuzz(dev, args, threads, rawmode, output, strategy)
    elif stype == 'dictionary': return cmd_dictionary(dev, args, threads, rawmode, output, strategy)
    
    print(f"[!] Unknown session type: {stype}")
    return False

HANDLERS = {
    # Existing
    'list': cmd_list, 'ls': cmd_list, 'strategies': cmd_list,
    'scan': cmd_scan, 'search': cmd_scan, 'explore': cmd_scan,
    'pattern': cmd_pattern, 'seq': cmd_pattern, 'sequence': cmd_pattern,
    'fuzz': cmd_fuzz, 'fuzzer': cmd_fuzz, 'random': cmd_fuzz,
    'dictionary': cmd_dictionary, 'dict': cmd_dictionary, 'wordlist': cmd_dictionary,
    'replay': cmd_replay, 'repeat': cmd_replay, 'retry': cmd_replay,
    'analyze': cmd_analyze, 'analysis': cmd_analyze, 'stats': cmd_analyze,
    'continue': cmd_continue, 'resume': cmd_continue, 'restart': cmd_continue,
    
    # NEW - Timing & Side-channel
    'timing': cmd_timing, 'sidechannel': cmd_timing,
    
    # NEW - Fault injection
    'glitch': cmd_glitch, 'fault': cmd_glitch,
    'voltage': cmd_voltage_fault, 'vfault': cmd_voltage_fault,
    
    # NEW - AI/ML
    'ai': cmd_ai_assisted, 'ml': cmd_ai_assisted, 'neural': cmd_ai_assisted,
    
    # NEW - Quantum (future)
    'quantum': cmd_quantum_bf, 'qbf': cmd_quantum_bf,
    
    # NEW - Specialized scans
    'scanmem': cmd_scan_memory, 'memscan': cmd_scan_memory, 'memoryscan': cmd_scan_memory,
    'scanusb': cmd_scan_usb, 'usbscan': cmd_scan_usb, 'endpointscan': cmd_scan_usb,
}

# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_bruteforce(args=None) -> int:
    """
    QSLCL BRUTEFORCE - Automated testing and scanning
    
    Examples:
        bruteforce list                        - List strategies
        bruteforce scan 0x10000000-0x10001000  - Address scan
        bruteforce pattern 0x0000-0x00FF       - Pattern brute-force
        bruteforce fuzz iterations:500         - Fuzzing
        bruteforce dictionary common           - Dictionary attack
        bruteforce replay captured.txt         - Replay data
        bruteforce analyze results.txt         - Analyze results
        bruteforce continue session.json       - Resume session
    
    Strategies: basic, smart, aggressive
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: bruteforce <list|scan|pattern|fuzz|dictionary|replay|analyze|continue>")
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
    
    # Also check for legacy pattern argument
    pattern = getattr(args, 'pattern', '')
    if pattern and not bargs:
        bargs = [pattern]
    
    threads = max(1, min(32, getattr(args, 'threads', DEFAULT_THREADS) or DEFAULT_THREADS))
    rawmode = getattr(args, 'rawmode', False)
    output = getattr(args, 'output', '') or getattr(args, 'output_file', '')
    strategy = getattr(args, 'strategy', 'basic') or 'basic'
    
    if not sub or sub in ('help', '?'):
        print("[*] Bruteforce Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<12} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
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
    print("[*] bruteforce.py - QSLCL BRUTEFORCE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py bruteforce <subcommand> [args]")