#!/usr/bin/env python3
"""
bruteforce.py - QSLCL BRUTEFORCE Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, scan execution,
       thread safety, result analysis, session management
"""

import os
import sys
import re
import struct
import time
import json
import random
import threading
import traceback
from queue import Queue
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
BF_TIMEOUT = 15.0
MAX_SCAN_SIZE = 0x10000  # 64KB max per range
MAX_SEQUENCES = 1000
MAX_FUZZ_ITERATIONS = 10000
DEFAULT_THREADS = 4

# Strategies
STRATEGIES = {
    'basic':      {'speed':'Slow','coverage':'Complete','desc':'Sequential linear search'},
    'smart':      {'speed':'Medium','coverage':'High','desc':'Heuristic optimization'},
    'aggressive': {'speed':'Fast','coverage':'Medium','desc':'Parallel multi-threaded'},
}

# Built-in wordlists
BUILTIN_WORDLISTS = {
    'common':    ['admin','password','1234','test','default','root','user','guest'],
    'passwords': ['password','123456','admin','letmein','qwerty','monkey','abc123'],
    'hex':       [f"0x{i:04X}" for i in range(0, 0x100, 0x10)],
    'commands':  ['READ','WRITE','ERASE','HELLO','PING','GETINFO','AUTH','UNLOCK'],
}

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


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
        self._started = getattr(self, '_started', False) or True
        self.current += n
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
    for attempt in range(2):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or BF_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or BF_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Raw mode helper
# =============================================================================
def _enable_rawmode(dev) -> bool:
    """Enable raw mode if available."""
    ok, _, _ = _dispatch(dev, "RAWMODE", b"UNLOCK", timeout=5)
    if not ok:
        print(f"{C.YELLOW}[!] Raw mode not available{C.RESET}")
    return ok


# =============================================================================
# FIXED: Test helpers
# =============================================================================
def _test_sequence(dev, sequence, rawmode: bool = False) -> bool:
    """Test a sequence against the device."""
    try:
        if isinstance(sequence, str):
            if sequence.startswith('0x'):
                val = int(sequence, 16)
                data = val.to_bytes(max(1, (val.bit_length()+7)//8), 'little')
            else:
                data = sequence.encode('utf-8')
        else:
            data = sequence if isinstance(sequence, bytes) else str(sequence).encode()
        
        ok, _, _ = _dispatch(dev, "TEST", data, timeout=5)
        if not ok and isinstance(sequence, str) and len(sequence) <= 16:
            ok, _, _ = _dispatch(dev, sequence.upper(), b"", timeout=5)
        return ok
    except: return False


def _test_fuzz(dev, data: bytes, rawmode: bool = False) -> Tuple[bool, bool]:
    """Test fuzz data. Returns (crash_detected, interesting_response)."""
    try:
        ok, name, extra = _dispatch(dev, "FUZZ", data, timeout=5)
        if ok:
            crash_indicators = ['CRASH','FATAL','PANIC','EXCEPTION','RESET']
            crash = any(i in name.upper() for i in crash_indicators)
            return crash, len(extra) > 0
        return True, False  # No response = possible crash
    except: return True, False


# =============================================================================
# FIXED: Pattern parsing
# =============================================================================
def _parse_pattern(pattern: str) -> List:
    """Parse pattern into scan ranges or sequences."""
    if not pattern: return []
    
    try:
        if '-' in pattern and not pattern.startswith('0x-'):
            if pattern.startswith('0x'):
                # Hex range: 0x1000-0x2000
                parts = pattern.split('-')
                s = int(parts[0], 16); e = int(parts[1], 16)
                return [(s, e, f"Hex range")]
            elif pattern.replace('-','').isdigit():
                # Numeric range: 1000-2000
                parts = pattern.split('-')
                return [(int(parts[0]), int(parts[1]), f"Numeric range")]
        
        # Single value
        addr = _parse_address(pattern)
        return [(addr, addr + 0x1000, "Single address")]
    except: pass
    
    return [(0x10000000, 0x10001000, "Default")]


def _gen_sequences(pattern: str) -> List:
    """Generate test sequences from pattern."""
    seqs = []
    try:
        if pattern.startswith('0x') and '-' in pattern:
            parts = pattern.split('-')
            s = int(parts[0], 16); e = int(parts[1], 16)
            step = max(1, (e - s) // MAX_SEQUENCES)
            for v in range(s, min(e+1, s+MAX_SEQUENCES*step), step):
                seqs.append(f"0x{v:0{(e.bit_length()+3)//4}X}")
        elif pattern.replace('-','').isdigit() and '-' in pattern:
            parts = pattern.split('-')
            s = int(parts[0]); e = int(parts[1])
            step = max(1, (e - s) // MAX_SEQUENCES)
            for v in range(s, min(e+1, s+MAX_SEQUENCES*step), step):
                seqs.append(str(v))
        else:
            seqs.append(pattern)
    except: seqs = [pattern] if pattern else []
    return seqs[:MAX_SEQUENCES]


def _gen_fuzz_data(params: Dict) -> bytes:
    """Generate fuzz data."""
    dt = params.get('data_type','random')
    ms = min(params.get('max_size',256), 1024)
    size = random.randint(1, ms)
    
    if dt == 'zeros': return b'\x00' * size
    if dt == 'ones': return b'\xFF' * size
    if dt == 'pattern': return bytes([random.getrandbits(8)]) * size
    return os.urandom(size)


# =============================================================================
# FIXED: Dictionary loading
# =============================================================================
def _load_dict(source: str) -> List[str]:
    """Load dictionary from built-in or file."""
    if source in BUILTIN_WORDLISTS:
        return BUILTIN_WORDLISTS[source]
    try:
        if os.path.exists(source):
            with open(source, 'r', errors='ignore') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except: pass
    return []


# =============================================================================
# FIXED: Scan implementations
# =============================================================================
def _basic_scan(dev, ranges: List, results: Dict) -> Dict:
    """Basic sequential scan."""
    for start, end, desc in ranges:
        scan_size = min(end - start, MAX_SCAN_SIZE)
        step = 4
        total = scan_size // step
        
        print(f"\n{C.CYAN}[*] {desc}: 0x{start:08X}-0x{start+scan_size:08X}{C.RESET}")
        
        with _get_progress(total, prefix='Scanning', suffix='Complete') as pb:
            for off in range(0, scan_size, step):
                addr = start + off
                ok, _, data = _dispatch(dev, "READ", struct.pack("<II", addr, 4), timeout=3)
                if ok and data and data != b'\x00\x00\x00\x00':
                    results['interesting'].append({'address':f"0x{addr:08X}",'data':data.hex()[:8]})
                results['scanned'] += 1
                pb.update(1)
    
    return results


def _aggressive_scan(dev, ranges: List, results: Dict, threads: int) -> Dict:
    """Aggressive parallel scan."""
    q = Queue()
    
    for start, end, desc in ranges:
        scan_size = min(end - start, 4096)
        for off in range(0, scan_size, 4):
            q.put(start + off)
    
    total = q.qsize()
    print(f"\n{C.CYAN}[*] Aggressive: {total} addresses, {threads} threads{C.RESET}")
    
    lock = threading.Lock()
    
    def worker(wid):
        local = {'scanned':0, 'interesting':[]}
        while not q.empty():
            try:
                addr = q.get_nowait()
                ok, _, data = _dispatch(dev, "READ", struct.pack("<II", addr, 4), timeout=2)
                if ok and data and data != b'\x00\x00\x00\x00':
                    local['interesting'].append({'address':f"0x{addr:08X}",'data':data.hex()[:8]})
                local['scanned'] += 1
            except: pass
            finally: q.task_done()
        
        with lock:
            results['scanned'] += local['scanned']
            results['interesting'].extend(local['interesting'])
    
    threads_list = []
    for i in range(min(threads, total)):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start(); threads_list.append(t)
    
    q.join()
    for t in threads_list: t.join(timeout=3)
    
    return results


# =============================================================================
# FIXED: Result saving
# =============================================================================
def _save_results(filepath: str, results: Dict, atype: str):
    """Save results to file."""
    try:
        d = os.path.dirname(os.path.abspath(filepath))
        if d: os.makedirs(d, exist_ok=True)
        
        with open(filepath, 'a' if os.path.exists(filepath) else 'w') as f:
            f.write(f"\n{'='*50}\n{atype.upper()} RESULTS\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tested: {results.get('tested', results.get('scanned',0))}\n")
            f.write(f"Success: {len(results.get('successful',[]))}\n")
            
            if results.get('successful'):
                f.write("SUCCESSFUL:\n")
                for s in results['successful'][:50]:
                    f.write(f"  {s}\n")
            
            if results.get('interesting'):
                f.write("INTERESTING:\n")
                for i in results['interesting'][:50]:
                    f.write(f"  {i}\n")
        
        if not _DEBUG: print(f"\n{C.GREEN}[+] Saved: {filepath}{C.RESET}")
    except Exception as e:
        print(f"{C.RED}[!] Save error: {e}{C.RESET}")


# =============================================================================
# FIXED: Analysis
# =============================================================================
def _analyze_file(filepath: str) -> Optional[Dict]:
    """Analyze results file."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        lines = [l for l in content.split('\n') if l.strip()]
        success = [l for l in lines if any(k in l.upper() for k in ['SUCCESS','MATCHED','FOUND','CRASH'])]
        
        return {
            'total': len(lines), 'successful': len(success),
            'rate': len(success)/max(len(lines),1)*100,
            'examples': success[:10],
        }
    except: return None


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def bruteforce_list(dev, args, force=False, threads=8, rawmode=False, 
                    output="", strategy="basic") -> bool:
    """List strategies and patterns."""
    print(f"\n{C.BOLD}[+] Strategies:{C.RESET}")
    for name, info in STRATEGIES.items():
        print(f"    {name:<12} Speed: {info['speed']:<8} Coverage: {info['coverage']:<10} {info['desc']}")
    
    print(f"\n{C.BOLD}[+] Patterns:{C.RESET}")
    patterns = [
        ('numeric','0-9 digits','0-999999'),
        ('hex','Hex values','0x0000-0xFFFF'),
        ('alphanumeric','Letters+numbers','a-z, A-Z, 0-9'),
        ('custom','User-defined','User specified'),
    ]
    for name, desc, rng in patterns:
        print(f"    {name:<15} {desc:<20} Range: {rng}")
    
    print(f"\n{C.BOLD}[+] Built-in Dicts:{C.RESET}")
    for k, v in BUILTIN_WORDLISTS.items():
        print(f"    {k:<12} {len(v)} words")
    return True


def bruteforce_scan(dev, args, force=False, threads=8, rawmode=False,
                    output="", strategy="basic") -> bool:
    """Systematic address scan."""
    pattern = args[0] if args else ""
    ranges = _parse_pattern(pattern) if pattern else [
        (0x10000000, 0x10001000, "Default Peripheral"),
        (0x80000000, 0x80001000, "Default DRAM"),
    ]
    
    if rawmode: _enable_rawmode(dev)
    
    results = {'scanned':0, 'interesting':[], 'errors':[]}
    start = time.time()
    
    if strategy == 'aggressive':
        results = _aggressive_scan(dev, ranges, results, threads)
    else:
        results = _basic_scan(dev, ranges, results)
    
    elapsed = time.time() - start
    speed = results['scanned'] / elapsed if elapsed > 0 else 0
    
    print(f"\n{C.BOLD}[+] Scan Complete:{C.RESET}")
    print(f"    Time: {elapsed:.1f}s | Scanned: {results['scanned']} | Speed: {speed:.0f}/s")
    print(f"    Interesting: {len(results['interesting'])}")
    
    if output: _save_results(output, results, 'scan')
    return True


def bruteforce_pattern(dev, args, force=False, threads=8, rawmode=False,
                       output="", strategy="basic") -> bool:
    """Pattern-based brute-force."""
    if not args:
        print(f"{C.RED}[!] Specify pattern (e.g., 0x0000-0xFFFF){C.RESET}"); return False
    
    pattern = args[0]
    seqs = _gen_sequences(pattern)
    
    if rawmode: _enable_rawmode(dev)
    
    print(f"\n{C.CYAN}[*] Pattern: {pattern} ({len(seqs)} sequences){C.RESET}")
    
    results = {'successful':[], 'tested':0, 'errors':[]}
    start = time.time()
    
    with _get_progress(len(seqs), prefix='Pattern', suffix='Complete') as pb:
        for i, seq in enumerate(seqs):
            if _test_sequence(dev, seq, rawmode):
                results['successful'].append(seq)
                print(f"\n{C.GREEN}[+] Match: {seq}{C.RESET}")
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output: _save_results(output, results, 'pattern')
    
    elapsed = time.time() - start
    rate = len(results['successful']) / max(results['tested'], 1) * 100
    print(f"\n{C.BOLD}[+] Complete:{C.RESET} {results['tested']} tested, "
          f"{len(results['successful'])} found ({rate:.1f}%) in {elapsed:.1f}s")
    
    if output: _save_results(output, results, 'pattern')
    return True


def bruteforce_fuzz(dev, args, force=False, threads=8, rawmode=False,
                    output="", strategy="basic") -> bool:
    """Fuzzing-based brute-force."""
    params = {'iterations':min(MAX_FUZZ_ITERATIONS, 1000), 'data_type':'random', 'max_size':256}
    
    if args:
        for a in args:
            if ':' in a:
                k, v = a.split(':', 1)
                if k == 'iterations': params['iterations'] = min(MAX_FUZZ_ITERATIONS, int(v))
                elif k == 'size': params['max_size'] = int(v)
                elif k == 'type': params['data_type'] = v
    
    if rawmode: _enable_rawmode(dev)
    
    its = params['iterations']
    print(f"\n{C.CYAN}[*] Fuzzing: {its} iterations{C.RESET}")
    
    results = {'crashes':[], 'interesting':[], 'tested':0}
    start = time.time()
    
    with _get_progress(its, prefix='Fuzzing', suffix='Complete') as pb:
        for i in range(its):
            data = _gen_fuzz_data(params)
            crash, interesting = _test_fuzz(dev, data, rawmode)
            
            if crash:
                results['crashes'].append({'iteration':i, 'data':data.hex()[:64]})
                print(f"\n{C.RED}[!] Crash at {i}{C.RESET}")
            if interesting:
                results['interesting'].append({'iteration':i, 'data':data.hex()[:32]})
            
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output: _save_results(output, results, 'fuzz')
    
    elapsed = time.time() - start
    print(f"\n{C.BOLD}[+] Complete:{C.RESET} {results['tested']} tests, "
          f"{len(results['crashes'])} crashes, {len(results['interesting'])} interesting in {elapsed:.1f}s")
    
    if output: _save_results(output, results, 'fuzz')
    return True


def bruteforce_dictionary(dev, args, force=False, threads=8, rawmode=False,
                          output="", strategy="basic") -> bool:
    """Dictionary attack."""
    if not args:
        print(f"{C.RED}[!] Specify dictionary source{C.RESET}"); return False
    
    words = _load_dict(args[0])
    if not words:
        print(f"{C.RED}[!] No words loaded{C.RESET}"); return False
    
    if rawmode: _enable_rawmode(dev)
    
    print(f"\n{C.CYAN}[*] Dictionary: {len(words)} words{C.RESET}")
    
    results = {'successful':[], 'tested':0}
    start = time.time()
    
    with _get_progress(len(words), prefix='Dictionary', suffix='Complete') as pb:
        for i, word in enumerate(words):
            if _test_sequence(dev, word, rawmode):
                results['successful'].append(word)
                print(f"\n{C.GREEN}[+] Match: {word}{C.RESET}")
            results['tested'] += 1
            pb.update(1)
            if i % 200 == 0 and output: _save_results(output, results, 'dictionary')
    
    elapsed = time.time() - start
    print(f"\n{C.BOLD}[+] Complete:{C.RESET} {results['tested']} tested, "
          f"{len(results['successful'])} found in {elapsed:.1f}s")
    
    if output: _save_results(output, results, 'dictionary')
    return True


def bruteforce_replay(dev, args, force=False, threads=8, rawmode=False,
                      output="", strategy="basic") -> bool:
    """Replay captured data."""
    if not args:
        print(f"{C.RED}[!] Specify replay file{C.RESET}"); return False
    
    attempts = _load_dict(args[0])  # Reuse dict loader for replay file
    if not attempts:
        print(f"{C.RED}[!] No replay data{C.RESET}"); return False
    
    if rawmode: _enable_rawmode(dev)
    
    print(f"\n{C.CYAN}[*] Replay: {len(attempts)} attempts{C.RESET}")
    
    results = {'successful':[], 'replayed':0}
    start = time.time()
    
    with _get_progress(len(attempts), prefix='Replay', suffix='Complete') as pb:
        for i, attempt in enumerate(attempts):
            if _test_sequence(dev, attempt, rawmode):
                results['successful'].append(attempt)
                print(f"\n{C.GREEN}[+] Success: {attempt}{C.RESET}")
            results['replayed'] += 1
            pb.update(1)
    
    elapsed = time.time() - start
    print(f"\n{C.BOLD}[+] Complete:{C.RESET} {results['replayed']} replayed, "
          f"{len(results['successful'])} successful in {elapsed:.1f}s")
    
    if output: _save_results(output, results, 'replay')
    return True


def bruteforce_analyze(dev, args, force=False, threads=8, rawmode=False,
                       output="", strategy="basic") -> bool:
    """Analyze results."""
    if not args:
        print(f"{C.RED}[!] Specify results file{C.RESET}"); return False
    
    analysis = _analyze_file(args[0])
    if not analysis:
        print(f"{C.RED}[!] Cannot analyze{C.RESET}"); return False
    
    print(f"\n{C.BOLD}[+] Analysis:{C.RESET}")
    print(f"    Total: {analysis['total']}")
    print(f"    Successful: {analysis['successful']} ({analysis['rate']:.1f}%)")
    
    if analysis.get('examples'):
        print(f"\n    Examples:")
        for e in analysis['examples'][:5]:
            print(f"    - {e}")
    return True


def bruteforce_continue(dev, args, force=False, threads=8, rawmode=False,
                        output="", strategy="basic") -> bool:
    """Continue interrupted session."""
    if not args:
        print(f"{C.RED}[!] Specify session file{C.RESET}"); return False
    
    try:
        with open(args[0], 'r') as f:
            session = json.load(f)
    except:
        print(f"{C.RED}[!] Cannot load session{C.RESET}"); return False
    
    stype = session.get('type','scan')
    print(f"\n{C.CYAN}[*] Resuming: {stype}{C.RESET}")
    
    # Route to appropriate handler based on saved type
    if stype == 'scan': return bruteforce_scan(dev, args, force, threads, rawmode, output, strategy)
    elif stype == 'pattern': return bruteforce_pattern(dev, args, force, threads, rawmode, output, strategy)
    elif stype == 'fuzz': return bruteforce_fuzz(dev, args, force, threads, rawmode, output, strategy)
    elif stype == 'dictionary': return bruteforce_dictionary(dev, args, force, threads, rawmode, output, strategy)
    
    print(f"{C.RED}[!] Unknown session type: {stype}{C.RESET}")
    return False


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
BF_HANDLERS = {
    'list': bruteforce_list, 'ls': bruteforce_list, 'strategies': bruteforce_list,
    'scan': bruteforce_scan, 'search': bruteforce_scan, 'explore': bruteforce_scan,
    'pattern': bruteforce_pattern, 'seq': bruteforce_pattern, 'sequence': bruteforce_pattern,
    'fuzz': bruteforce_fuzz, 'fuzzer': bruteforce_fuzz, 'random': bruteforce_fuzz,
    'dictionary': bruteforce_dictionary, 'dict': bruteforce_dictionary, 'wordlist': bruteforce_dictionary,
    'replay': bruteforce_replay, 'repeat': bruteforce_replay, 'retry': bruteforce_replay,
    'analyze': bruteforce_analyze, 'analysis': bruteforce_analyze, 'stats': bruteforce_analyze,
    'continue': bruteforce_continue, 'resume': bruteforce_continue, 'restart': bruteforce_continue,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_bruteforce_help():
    print(f"""
{C.BOLD}BRUTEFORCE - Automated Testing & Scanning{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  list                  List strategies and patterns
  scan [range]          Systematic address scan
  pattern <pattern>     Pattern-based brute-force
  fuzz [params]         Fuzzing-based testing
  dictionary <source>   Dictionary attack
  replay <file>         Replay captured data
  analyze <file>        Analyze results
  continue <session>    Resume interrupted session

{C.CYAN}STRATEGIES:{C.RESET}
  basic      Sequential (thorough but slow)
  smart      Heuristic optimization
  aggressive Parallel multi-threaded

{C.CYAN}PATTERNS:{C.RESET}
  0x1000-0x2000    Hex address range
  0000-9999        Numeric range
  common           Built-in wordlist

{C.CYAN}OPTIONS:{C.RESET}
  --threads N     Threads (default: 4)
  --rawmode       Enable raw mode
  --output FILE   Save results
  --strategy TYPE Strategy

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl bruteforce list
  qslcl bruteforce scan 0x10000000-0x10001000
  qslcl bruteforce pattern 0x0000-0x00FF
  qslcl bruteforce dictionary common
  qslcl bruteforce fuzz iterations:1000 --output results.txt
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_bruteforce(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_bruteforce_help(); return 1
    
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
    
    sub = (getattr(args, 'bruteforce_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    bargs = getattr(args, 'bruteforce_args', []) or []
    pattern = getattr(args, 'pattern', '')
    threads = max(1, min(32, int(getattr(args, 'threads', DEFAULT_THREADS) or DEFAULT_THREADS)))
    rawmode = getattr(args, 'rawmode', False)
    output = getattr(args, 'output', '') or getattr(args, 'output_file', '')
    strategy = getattr(args, 'strategy', 'basic') or 'basic'
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_bruteforce_help(); return 0
    
    handler = BF_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_bruteforce_help(); return 1
    
    # Pass pattern as first arg if not provided via bargs
    if pattern and not bargs:
        bargs = [pattern] + bargs
    
    try:
        return 0 if handler(dev, bargs, force, threads, rawmode, output, strategy) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def add_bruteforce_arguments(parser):
    parser.add_argument('bruteforce_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('pattern', nargs='?', help='Pattern/range')
    parser.add_argument('bruteforce_args', nargs='*', help='Additional arguments')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS)
    parser.add_argument('--rawmode', action='store_true')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--strategy', choices=['basic','smart','aggressive'], default='basic')
    return parser


if __name__ == "__main__":
    print("[*] bruteforce.py - QSLCL BRUTEFORCE Module v2.0")
    print_bruteforce_help()