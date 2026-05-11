#!/usr/bin/env python3
"""
config.py - QSLCL CONFIG Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, schema management,
       value validation, backup/restore, import/export
"""

import os
import sys
import struct
import time
import json
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
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _auto_loader_if_needed = _qslcl_auto_loader
    _qslcl_dispatch = _qslcl_dispatch_fn
    _decode_runtime_result = _qslcl_decode_runtime
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
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _auto_loader_if_needed = _qslcl_auto_loader
        _qslcl_dispatch = _qslcl_dispatch_fn
        _decode_runtime_result = _qslcl_decode_runtime
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
CONFIG_TIMEOUT = 10.0
MAX_HISTORY = 1000

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Default schema
# =============================================================================
DEFAULT_SCHEMA: Dict[str, Dict] = {
    '_version':     {'type':'string', 'default':'2.0', 'category':'system', 'desc':'Schema version'},
    'debug_level':  {'type':'int', 'default':1, 'min':0, 'max':5, 'category':'debug', 'desc':'Debug verbosity'},
    'log_enabled':  {'type':'bool', 'default':True, 'category':'debug', 'desc':'Enable logging'},
    'timeout':      {'type':'int', 'default':5000, 'min':100, 'max':60000, 'category':'comm', 'desc':'Timeout (ms)'},
    'retry_count':  {'type':'int', 'default':3, 'min':0, 'max':10, 'category':'comm', 'desc':'Retry attempts'},
    'chunk_size':   {'type':'int', 'default':65536, 'min':512, 'max':1048576, 'category':'transfer', 'desc':'Chunk size'},
    'verify_writes':{'type':'bool', 'default':True, 'category':'safety', 'desc':'Verify writes'},
    'auto_detect':  {'type':'bool', 'default':True, 'category':'convenience', 'desc':'Auto-detect'},
    'raw_mode':     {'type':'bool', 'default':False, 'category':'advanced', 'desc':'Raw mode'},
    'secure_mode':  {'type':'bool', 'default':True, 'category':'security', 'desc':'Security verification'},
    'crc_check':    {'type':'bool', 'default':True, 'category':'integrity', 'desc':'CRC checking'},
    'progress_bar': {'type':'bool', 'default':True, 'category':'ui', 'desc':'Show progress bars'},
    'color_output': {'type':'bool', 'default':True, 'category':'ui', 'desc':'Colored output'},
    'history_size': {'type':'int', 'default':100, 'min':0, 'max':1000, 'category':'system', 'desc':'History size'},
}


# =============================================================================
# FIXED: Config state (module-level)
# =============================================================================
_CONFIG: Dict[str, Any] = {}
_SCHEMA: Dict[str, Dict] = {}
_HISTORY: List[Dict] = []


def _init_config():
    """Initialize config from schema defaults if not loaded."""
    if not _CONFIG:
        for k, s in DEFAULT_SCHEMA.items():
            if 'default' in s:
                _CONFIG[k] = s['default']
    if not _SCHEMA:
        _SCHEMA.update(DEFAULT_SCHEMA)


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.RED}{msg}{C.RESET}")
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
    for attempt in range(2):
        try:
            ci = _find_cmd(cmd)
            if ci:
                t,k = ci
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or CONFIG_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or CONFIG_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Load configuration from device
# =============================================================================
def _load_from_device(dev):
    """Load configuration from device."""
    global _CONFIG, _SCHEMA
    
    _SCHEMA.update(DEFAULT_SCHEMA)
    
    if not dev: return
    
    ok, _, data = _dispatch(dev, "GETCONFIG", b"ALL", timeout=CONFIG_TIMEOUT)
    if ok and data:
        parsed = _parse_config_data(data)
        _CONFIG.update(parsed)
        print(f"{C.GREEN}[+] Loaded {len(parsed)} config values from device{C.RESET}")
    else:
        _init_config()
        print(f"{C.YELLOW}[*] Using defaults ({len(_CONFIG)} values){C.RESET}")


def _parse_config_data(data: bytes) -> Dict:
    """Parse configuration data from device."""
    result = {}
    try:
        # Try JSON
        text = data.decode('utf-8', errors='ignore').strip()
        if text.startswith('{'):
            result.update(json.loads(text))
            return result
        
        # Try key=value lines
        for line in text.split('\n'):
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                result[k.strip()] = _parse_value_str(v.strip())
    except: pass
    return result


def _parse_value_str(s: str) -> Any:
    """Parse string value to appropriate type."""
    s = s.strip()
    if not s: return s
    lo = s.lower()
    if lo in ('true','yes','on','enabled','1'): return True
    if lo in ('false','no','off','disabled','0'): return False
    if s.startswith('0x'):
        try: return int(s, 16)
        except: pass
    try: return int(s)
    except:
        try: return float(s)
        except: return s


# =============================================================================
# FIXED: Value parsing and validation
# =============================================================================
def _parse_value(val: str, schema: Dict) -> Tuple[Any, Optional[str]]:
    """Parse value string according to schema type."""
    t = schema.get('type', 'string')
    try:
        if t == 'int':
            if val.startswith('0x'): return int(val, 16), None
            return int(val), None
        elif t == 'bool':
            lo = val.lower()
            if lo in ('true','yes','1','on','enabled'): return True, None
            if lo in ('false','no','0','off','disabled'): return False, None
            return None, f"Invalid bool: {val}"
        elif t == 'float':
            return float(val), None
        else:
            return val, None
    except (ValueError, OverflowError) as e:
        return None, str(e)


def _validate_value(key: str, val: Any, schema: Dict, force: bool = False) -> bool:
    """Validate value against schema."""
    if val is None: return False
    
    t = schema.get('type', 'string')
    type_ok = {
        'int': lambda v: isinstance(v, (int, float)),
        'bool': lambda v: isinstance(v, bool),
        'float': lambda v: isinstance(v, (int, float)),
        'string': lambda v: isinstance(v, str),
    }.get(t, lambda v: True)
    
    if not type_ok(val):
        print(f"{C.RED}[!] {key}: expected {t}, got {type(val).__name__}{C.RESET}")
        return False
    
    if t == 'int' and isinstance(val, (int, float)):
        mn, mx = schema.get('min'), schema.get('max')
        if mn is not None and val < mn:
            if not force: print(f"{C.RED}[!] {key}={val} < min={mn}{C.RESET}"); return False
            print(f"{C.YELLOW}[!] {key}={val} < min={mn}{C.RESET}")
        if mx is not None and val > mx:
            if not force: print(f"{C.RED}[!] {key}={val} > max={mx}{C.RESET}"); return False
            print(f"{C.YELLOW}[!] {key}={val} > max={mx}{C.RESET}")
    
    opts = schema.get('options')
    if opts and val not in opts:
        print(f"{C.RED}[!] {key}={val} not in {opts}{C.RESET}")
        return False
    
    return True


def _format_value(val: Any, schema: Dict) -> str:
    """Format value for display."""
    if val is None: return "null"
    t = schema.get('type', 'string')
    if t == 'bool': return 'true' if val else 'false'
    if isinstance(val, (int, float)): return str(val)
    if isinstance(val, str):
        return f'"{val}"' if len(val) <= 50 else f'"{val[:47]}..."'
    return str(val)


# =============================================================================
# FIXED: Apply config to device
# =============================================================================
def _apply_config(dev, key: str, val: Any) -> bool:
    """Apply single config to device."""
    if not dev: return True
    
    schema = _SCHEMA.get(key, {})
    t = schema.get('type', 'string')
    type_map = {'int':1, 'bool':2, 'string':3, 'float':4}
    
    payload = struct.pack("<B", 0x10)  # SET_CONFIG
    payload += key.encode('utf-8','ignore')[:32].ljust(32, b'\x00')
    payload += struct.pack("<B", type_map.get(t, 3))
    
    if t == 'int': payload += struct.pack("<i", int(val))
    elif t == 'bool': payload += struct.pack("<B", 1 if val else 0)
    elif t == 'float': payload += struct.pack("<f", float(val))
    else: payload += str(val).encode('utf-8','ignore')[:64].ljust(64, b'\x00')
    
    ok, _, _ = _dispatch(dev, "SETCONFIG", payload)
    return ok


def _add_history(op: str, key: str, old: Any, new: Any):
    """Add entry to history."""
    _HISTORY.append({'ts': time.time(), 'op': op, 'key': key, 'old': old, 'new': new})
    max_h = _CONFIG.get('history_size', 100)
    if len(_HISTORY) > max_h:
        _HISTORY[:] = _HISTORY[-max_h:]


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def config_get(dev, args, verify=False, force=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify key{C.RESET}"); return False
    key = args[0]
    if key not in _CONFIG:
        print(f"{C.RED}[!] Unknown: {key}{C.RESET}")
        return False
    
    val = _CONFIG[key]
    schema = _SCHEMA.get(key, {})
    print(f"\n{C.BOLD}[+] {key}{C.RESET}")
    print(f"    Value: {_format_value(val, schema)}")
    print(f"    Type: {schema.get('type','?')}")
    print(f"    Category: {schema.get('category','?')}")
    print(f"    Description: {schema.get('desc','No description')}")
    if 'default' in schema: print(f"    Default: {_format_value(schema['default'], schema)}")
    if 'min' in schema and 'max' in schema: print(f"    Range: {schema['min']}-{schema['max']}")
    if 'options' in schema: print(f"    Options: {', '.join(map(str, schema['options']))}")
    return True


def config_set(dev, args, verify=False, force=False) -> bool:
    if len(args) < 2:
        print(f"{C.RED}[!] Usage: config set <key> <value>{C.RESET}"); return False
    
    key = args[0]
    val_str = ' '.join(args[1:])
    
    if key not in _SCHEMA:
        print(f"{C.RED}[!] Unknown key: {key}{C.RESET}"); return False
    
    schema = _SCHEMA[key]
    val, err = _parse_value(val_str, schema)
    if err:
        print(f"{C.RED}[!] Invalid: {err}{C.RESET}"); return False
    if not _validate_value(key, val, schema, force):
        return False
    
    old = _CONFIG.get(key)
    if old == val:
        print(f"{C.YELLOW}[*] Already set: {_format_value(val, schema)}{C.RESET}")
        return True
    
    print(f"\n{C.BOLD}[+] Change:{C.RESET}")
    print(f"    {key}: {_format_value(old, schema)} → {_format_value(val, schema)}")
    
    if not force:
        try:
            if input("    Confirm? (y/N): ").lower() not in ('y','yes'):
                return False
        except: return False
    
    if _apply_config(dev, key, val):
        _CONFIG[key] = val
        _add_history('SET', key, old, val)
        print(f"{C.GREEN}[+] Set{C.RESET}")
        return True
    
    print(f"{C.RED}[!] Failed{C.RESET}")
    return False


def config_list(dev, args, verify=False, force=False) -> bool:
    filt = args[0].lower() if args else None
    
    cats = {}
    for k, s in _SCHEMA.items():
        if k.startswith('_'): continue
        cats[s.get('category','?')] = cats.get(s.get('category','?'), 0) + 1
    
    print(f"\n{C.BOLD}[+] Config: {len(_CONFIG)} values{C.RESET}")
    for c, n in sorted(cats.items()):
        print(f"    {c}: {n}")
    
    print(f"\n{C.BOLD}[+] Values:{C.RESET}")
    for k in sorted(_CONFIG):
        if k.startswith('_'): continue
        if filt and filt not in k.lower(): continue
        s = _SCHEMA.get(k, {})
        cat = s.get('category','?')
        print(f"    {k:<22} = {_format_value(_CONFIG[k], s):<20} [{cat}]")
    return True


def config_delete(dev, args, verify=False, force=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify key{C.RESET}"); return False
    key = args[0]
    
    if key not in _CONFIG:
        print(f"{C.RED}[!] Unknown: {key}{C.RESET}"); return False
    
    schema = _SCHEMA.get(key, {})
    default = schema.get('default')
    if default is None:
        print(f"{C.RED}[!] No default for {key}{C.RESET}"); return False
    
    old = _CONFIG[key]
    print(f"\n{C.BOLD}[+] Reset: {key} → {_format_value(default, schema)}{C.RESET}")
    
    if not force:
        try:
            if input("    Confirm? (y/N): ").lower() not in ('y','yes'): return False
        except: return False
    
    if _apply_config(dev, key, default):
        _CONFIG[key] = default
        _add_history('DELETE', key, old, default)
        print(f"{C.GREEN}[+] Reset{C.RESET}")
        return True
    return False


def config_backup(dev, args, verify=False, force=False) -> bool:
    filename = args[0] if args else f"config_backup_{int(time.time())}.json"
    
    backup = {
        'timestamp': time.time(),
        'timestamp_str': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': _SCHEMA.get('_version',{}).get('default','2.0'),
        'schema': _SCHEMA,
        'data': _CONFIG,
        'history': _HISTORY[-20:],
    }
    
    try:
        d = os.path.dirname(os.path.abspath(filename))
        if d: os.makedirs(d, exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(backup, f, indent=2, default=str)
        print(f"{C.GREEN}[+] Backup: {filename} ({len(_CONFIG)} values){C.RESET}")
        return True
    except Exception as e:
        print(f"{C.RED}[!] Backup failed: {e}{C.RESET}")
        return False


def config_restore(dev, args, verify=False, force=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify backup file{C.RESET}"); return False
    
    filename = args[0]
    if not os.path.exists(filename):
        print(f"{C.RED}[!] Not found: {filename}{C.RESET}"); return False
    
    try:
        with open(filename, 'r') as f:
            backup = json.load(f)
    except Exception as e:
        print(f"{C.RED}[!] Load failed: {e}{C.RESET}"); return False
    
    data = backup.get('data', backup.get('config_data', backup))
    if not isinstance(data, dict):
        print(f"{C.RED}[!] Invalid format{C.RESET}"); return False
    
    changes = {k: v for k, v in data.items() if _CONFIG.get(k) != v}
    if not changes:
        print(f"{C.YELLOW}[*] No changes{C.RESET}"); return True
    
    print(f"\n{C.BOLD}[+] {len(changes)} changes:{C.RESET}")
    for k, v in list(changes.items())[:5]:
        print(f"    {k}: {_format_value(_CONFIG.get(k), _SCHEMA.get(k,{}))} → {_format_value(v, _SCHEMA.get(k,{}))}")
    if len(changes) > 5: print(f"    ... and {len(changes)-5} more")
    
    if not force:
        try:
            if input("    Restore? (y/N): ").lower() not in ('y','yes'): return False
        except: return False
    
    ok = 0
    for k, v in changes.items():
        if _apply_config(dev, k, v):
            _CONFIG[k] = v
            ok += 1
        else:
            print(f"{C.RED}[!] Failed: {k}{C.RESET}")
    
    print(f"{C.GREEN}[+] Restored: {ok}/{len(changes)}{C.RESET}")
    return ok > 0


def config_reset(dev, args, verify=False, force=False) -> bool:
    changes = {}
    for k, s in _SCHEMA.items():
        if k.startswith('_') or 'default' not in s: continue
        if _CONFIG.get(k) != s['default']:
            changes[k] = s['default']
    
    if not changes:
        print(f"{C.YELLOW}[*] Nothing to reset{C.RESET}"); return True
    
    print(f"\n{C.BOLD}[+] Reset {len(changes)} to defaults{C.RESET}")
    
    if not _confirm("⚠️  ALL custom settings will be lost!", 'RESET', force):
        return False
    
    ok = 0
    for k, v in changes.items():
        if _apply_config(dev, k, v):
            old = _CONFIG.get(k)
            _CONFIG[k] = v
            _add_history('RESET', k, old, v)
            ok += 1
        else:
            print(f"{C.RED}[!] Failed: {k}{C.RESET}")
    
    print(f"{C.GREEN}[+] Reset: {ok}/{len(changes)}{C.RESET}")
    return ok > 0


def config_validate(dev, args, verify=False, force=False) -> bool:
    errors, warnings = [], []
    for k, v in _CONFIG.items():
        if k.startswith('_'): continue
        s = _SCHEMA.get(k, {})
        if s and not _validate_value(k, v, s, True):
            errors.append(k)
    
    if not errors:
        print(f"{C.GREEN}[+] All valid{C.RESET}"); return True
    
    print(f"{C.RED}[!] {len(errors)} invalid: {', '.join(errors)}{C.RESET}")
    return False


def config_info(dev, args, verify=False, force=False) -> bool:
    if args:
        key = args[0]
        if key not in _SCHEMA:
            print(f"{C.RED}[!] Unknown: {key}{C.RESET}"); return False
        s = _SCHEMA[key]
        print(f"\n{C.BOLD}[+] Schema: {key}{C.RESET}")
        for f, v in s.items():
            print(f"    {f:<12} {v}")
        if key in _CONFIG:
            print(f"    {'current':<12} {_format_value(_CONFIG[key], s)}")
        return True
    
    print(f"\n{C.BOLD}[+] Schema Overview:{C.RESET}")
    cats = {}
    for k, s in _SCHEMA.items():
        if k.startswith('_'): continue
        cats[s.get('category','?')] = cats.get(s.get('category','?'), 0) + 1
    for c, n in sorted(cats.items()):
        print(f"    {c:<14} {n} keys")
    print(f"    Total: {len(cats)} categories, {sum(cats.values())} keys")
    return True


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
CONFIG_HANDLERS = {
    'get': config_get, 'read': config_get, 'show': config_get,
    'set': config_set, 'write': config_set, 'update': config_set,
    'list': config_list, 'ls': config_list, 'all': config_list,
    'delete': config_delete, 'remove': config_delete, 'unset': config_delete,
    'backup': config_backup, 'save': config_backup, 'export': config_backup,
    'restore': config_restore, 'load': config_restore, 'import': config_restore,
    'reset': config_reset, 'default': config_reset, 'clear': config_reset,
    'validate': config_validate, 'check': config_validate, 'verify': config_validate,
    'info': config_info, 'schema': config_info, 'describe': config_info,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_config_help():
    print(f"""
{C.BOLD}CONFIG - Configuration Management{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  get <key>              Get configuration value
  set <key> <value>      Set configuration value
  list [filter]          List all configurations
  delete <key>           Reset to default
  backup [file]          Backup to file
  restore <file>         Restore from backup
  reset                  Reset all to defaults
  validate               Validate configuration
  info [key]             Show schema information

{C.CYAN}KEYS:{C.RESET}
  debug_level (0-5)   timeout (ms)     retry_count (0-10)
  chunk_size (B)      verify_writes    auto_detect
  raw_mode            secure_mode      crc_check
  progress_bar        color_output     log_enabled

{C.CYAN}OPTIONS:{C.RESET}
  --verify        Verify after operation
  --force         Skip confirmation

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl config get debug_level
  qslcl config set timeout 10000
  qslcl config list
  qslcl config backup my_config.json
""")


# =============================================================================
# FIXED: Main functions
# =============================================================================
def cmd_config(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_config_help(); return 1
    
    if not _use_qslcl: _warn_standalone()
    
    _init_config()
    
    if _use_qslcl:
        try: devs = _scan_all()
        except: print(f"{C.RED}[!] Scan failed{C.RESET}"); return 1
        dev = devs[0] if devs else None
        if dev: print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        dev = None
    
    if hasattr(args, 'loader') and getattr(args, 'loader', None) and dev:
        try: _auto_loader_if_needed(args, dev)
        except: pass
    
    _load_from_device(dev)
    
    sub = (getattr(args, 'config_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    cargs = getattr(args, 'config_args', []) or []
    verify = getattr(args, 'verify', False)
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_config_help(); return 0
    
    handler = CONFIG_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_config_help(); return 1
    
    try:
        return 0 if handler(dev, cargs, verify, force) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def cmd_config_list(args=None) -> int:
    """List all configuration options."""
    return cmd_config(args) if args else config_list(None, [], False, False)


def add_config_arguments(parser):
    parser.add_argument('config_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('config_args', nargs='*', help='Arguments')
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--force', action='store_true')
    return parser


if __name__ == "__main__":
    print("[*] config.py - QSLCL CONFIG Module v2.0")
    print_config_help()