#!/usr/bin/env python3
"""
config.py - QSLCL CONFIG Command Module v2.1 (CLEANED)
Configuration management with schema validation and backup/restore
"""

import os
import sys
import struct
import time
import json
from typing import Optional, List, Tuple, Dict, Any

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
# SCHEMA DEFINITION
# =============================================================================
SCHEMA = {
    '_version':     {'type': 'string', 'default': '2.1', 'category': 'system', 'desc': 'Schema version'},
    'debug_level':  {'type': 'int', 'default': 1, 'min': 0, 'max': 5, 'category': 'debug', 'desc': 'Debug verbosity (0-5)'},
    'log_enabled':  {'type': 'bool', 'default': True, 'category': 'debug', 'desc': 'Enable logging'},
    'timeout':      {'type': 'int', 'default': 5000, 'min': 100, 'max': 60000, 'category': 'comm', 'desc': 'Timeout (ms)'},
    'retry_count':  {'type': 'int', 'default': 3, 'min': 0, 'max': 10, 'category': 'comm', 'desc': 'Retry attempts'},
    'chunk_size':   {'type': 'int', 'default': 65536, 'min': 512, 'max': 1048576, 'category': 'transfer', 'desc': 'Chunk size (bytes)'},
    'verify_writes':{'type': 'bool', 'default': True, 'category': 'safety', 'desc': 'Verify write operations'},
    'auto_detect':  {'type': 'bool', 'default': True, 'category': 'convenience', 'desc': 'Auto-detect settings'},
    'raw_mode':     {'type': 'bool', 'default': False, 'category': 'advanced', 'desc': 'Raw mode access'},
    'secure_mode':  {'type': 'bool', 'default': True, 'category': 'security', 'desc': 'Security verification'},
    'crc_check':    {'type': 'bool', 'default': True, 'category': 'integrity', 'desc': 'CRC validation'},
    'progress_bar': {'type': 'bool', 'default': True, 'category': 'ui', 'desc': 'Show progress bars'},
    'color_output': {'type': 'bool', 'default': True, 'category': 'ui', 'desc': 'Colored output'},
    'history_size': {'type': 'int', 'default': 100, 'min': 0, 'max': 1000, 'category': 'system', 'desc': 'History size'},
}

# Module state
CONFIG: Dict[str, Any] = {}
HISTORY: List[Dict] = []


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False


def config_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send config command"""
    for attempt in range(2):
        try:
            if "CONFIG" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "CONFIG", payload, timeout=10)
            elif "SETCONFIG" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "SETCONFIG", payload, timeout=10)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=10)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt == 0: time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""


def parse_value(val: str, schema: dict) -> Tuple[Any, Optional[str]]:
    """Parse string to typed value"""
    t = schema.get('type', 'string')
    try:
        if t == 'int':
            return int(val, 16) if val.startswith('0x') else int(val), None
        elif t == 'bool':
            lo = val.lower()
            if lo in ('true', 'yes', '1', 'on', 'enabled'): return True, None
            if lo in ('false', 'no', '0', 'off', 'disabled'): return False, None
            return None, f"Invalid bool: {val}"
        elif t == 'float':
            return float(val), None
        return val, None
    except (ValueError, OverflowError) as e:
        return None, str(e)


def validate_value(key: str, val: Any, schema: dict) -> bool:
    """Validate value against schema"""
    if val is None: return False
    
    t = schema.get('type', 'string')
    type_map = {'int': (int, float), 'bool': bool, 'float': (int, float), 'string': str}
    expected = type_map.get(t, object)
    if not isinstance(val, expected):
        print(f"[!] {key}: expected {t}, got {type(val).__name__}")
        return False
    
    if t == 'int' and isinstance(val, (int, float)):
        if 'min' in schema and val < schema['min']:
            print(f"[!] {key}={val} < min={schema['min']}")
            return False
        if 'max' in schema and val > schema['max']:
            print(f"[!] {key}={val} > max={schema['max']}")
            return False
    
    if 'options' in schema and val not in schema['options']:
        print(f"[!] {key}={val} not in {schema['options']}")
        return False
    
    return True


def format_val(val: Any, schema: dict) -> str:
    """Format value for display"""
    if val is None: return "null"
    if schema.get('type') == 'bool': return 'true' if val else 'false'
    if isinstance(val, str) and len(val) > 50: return f'"{val[:47]}..."'
    return str(val)


def apply_to_device(dev, key: str, val: Any) -> bool:
    """Apply single config to device"""
    if not dev: return True
    
    schema = SCHEMA.get(key, {})
    t = schema.get('type', 'string')
    type_id = {'int': 1, 'bool': 2, 'string': 3, 'float': 4}.get(t, 3)
    
    payload = struct.pack("<B", 0x10)  # SET_CONFIG
    payload += key.encode()[:32].ljust(32, b'\x00')
    payload += struct.pack("<B", type_id)
    
    if t == 'int': payload += struct.pack("<i", int(val))
    elif t == 'bool': payload += struct.pack("<B", 1 if val else 0)
    elif t == 'float': payload += struct.pack("<f", float(val))
    else: payload += str(val).encode()[:64].ljust(64, b'\x00')
    
    ok, _, _ = config_cmd(dev, payload)
    return ok


def add_history(op: str, key: str, old: Any, new: Any):
    """Add history entry"""
    HISTORY.append({'ts': time.time(), 'op': op, 'key': key, 'old': old, 'new': new})
    limit = CONFIG.get('history_size', 100)
    if len(HISTORY) > limit:
        HISTORY[:] = HISTORY[-limit:]


def init_config():
    """Initialize from schema defaults"""
    if not CONFIG:
        for k, s in SCHEMA.items():
            if 'default' in s:
                CONFIG[k] = s['default']


def load_from_device(dev):
    """Load config from device"""
    if not dev:
        init_config()
        return
    
    ok, _, data = config_cmd(dev, b"ALL")
    if ok and data:
        try:
            text = data.decode('utf-8', 'ignore').strip()
            if text.startswith('{'):
                CONFIG.update(json.loads(text))
            else:
                for line in text.split('\n'):
                    line = line.strip()
                    if line and '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        CONFIG[k.strip()] = parse_value(v.strip(), SCHEMA.get(k.strip(), {}))[0]
            print(f"[+] Loaded {len(CONFIG)} config values from device")
        except:
            init_config()
            print(f"    Using defaults ({len(CONFIG)} values)")
    else:
        init_config()
        print(f"    Using defaults ({len(CONFIG)} values)")


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_get(dev, args, force):
    """Get config value"""
    if not args:
        print("[!] Specify key"); return False
    
    key = args[0]
    if key not in CONFIG:
        print(f"[!] Unknown: {key}")
        return False
    
    val = CONFIG[key]
    schema = SCHEMA.get(key, {})
    
    print(f"\n[+] {key}")
    print(f"    Value:      {format_val(val, schema)}")
    print(f"    Type:       {schema.get('type', '?')}")
    print(f"    Category:   {schema.get('category', '?')}")
    print(f"    Desc:       {schema.get('desc', 'No description')}")
    if 'default' in schema: print(f"    Default:    {format_val(schema['default'], schema)}")
    if 'min' in schema and 'max' in schema: print(f"    Range:      {schema['min']}-{schema['max']}")
    return True


def cmd_set(dev, args, force):
    """Set config value"""
    if len(args) < 2:
        print("[!] Usage: config set <key> <value>"); return False
    
    key = args[0]
    val_str = ' '.join(args[1:])
    
    if key not in SCHEMA:
        print(f"[!] Unknown: {key}"); return False
    
    schema = SCHEMA[key]
    val, err = parse_value(val_str, schema)
    if err:
        print(f"[!] Invalid: {err}"); return False
    if not validate_value(key, val, schema):
        return False
    
    old = CONFIG.get(key)
    if old == val:
        print(f"[*] Already: {format_val(val, schema)}"); return True
    
    print(f"\n[+] Change: {key}")
    print(f"    {format_val(old, schema)} → {format_val(val, schema)}")
    
    if not force:
        try:
            if input("    Confirm? (y/N): ").lower() != 'y': return False
        except: return False
    
    if apply_to_device(dev, key, val):
        CONFIG[key] = val
        add_history('SET', key, old, val)
        print("[+] Set")
        return True
    
    print("[!] Failed")
    return False


def cmd_list(dev, args, force):
    """List all config"""
    filt = args[0].lower() if args else None
    
    # Category summary
    cats = {}
    for k, s in SCHEMA.items():
        if k.startswith('_'): continue
        cats[s.get('category', '?')] = cats.get(s.get('category', '?'), 0) + 1
    
    print(f"\n[+] Configuration: {len(CONFIG)} values")
    for c, n in sorted(cats.items()):
        print(f"    {c:<14} {n} keys")
    
    print(f"\n[+] Values:")
    print(f"    {'Key':<22} {'Value':<20} {'Category'}")
    print(f"    {'─'*22} {'─'*20} {'─'*14}")
    
    for k in sorted(CONFIG):
        if k.startswith('_'): continue
        if filt and filt not in k.lower(): continue
        s = SCHEMA.get(k, {})
        print(f"    {k:<22} {format_val(CONFIG[k], s):<20} {s.get('category','?')}")
    
    return True


def cmd_delete(dev, args, force):
    """Reset to default"""
    if not args:
        print("[!] Specify key"); return False
    
    key = args[0]
    if key not in CONFIG:
        print(f"[!] Unknown: {key}"); return False
    
    schema = SCHEMA.get(key, {})
    default = schema.get('default')
    if default is None:
        print(f"[!] No default for {key}"); return False
    
    old = CONFIG[key]
    print(f"\n[+] Reset: {key} → {format_val(default, schema)}")
    
    if not force:
        try:
            if input("    Confirm? (y/N): ").lower() != 'y': return False
        except: return False
    
    if apply_to_device(dev, key, default):
        CONFIG[key] = default
        add_history('DELETE', key, old, default)
        print("[+] Reset")
        return True
    return False


def cmd_backup(dev, args, force):
    """Backup to file"""
    filename = args[0] if args else f"config_backup_{int(time.time())}.json"
    
    backup = {
        'timestamp': time.time(),
        'timestamp_str': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': SCHEMA.get('_version', {}).get('default', '2.1'),
        'data': CONFIG,
        'history': HISTORY[-20:],
    }
    
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filename)) or '.', exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(backup, f, indent=2, default=str)
        print(f"[+] Backup: {filename} ({len(CONFIG)} values)")
        return True
    except Exception as e:
        print(f"[!] Failed: {e}")
        return False


def cmd_restore(dev, args, force):
    """Restore from backup"""
    if not args:
        print("[!] Specify backup file"); return False
    
    if not os.path.exists(args[0]):
        print(f"[!] Not found: {args[0]}"); return False
    
    try:
        with open(args[0], 'r') as f:
            backup = json.load(f)
    except Exception as e:
        print(f"[!] Load failed: {e}"); return False
    
    data = backup.get('data', backup)
    if not isinstance(data, dict):
        print("[!] Invalid format"); return False
    
    changes = {k: v for k, v in data.items() if CONFIG.get(k) != v}
    if not changes:
        print("[*] No changes needed"); return True
    
    print(f"\n[+] {len(changes)} changes:")
    for k, v in list(changes.items())[:8]:
        print(f"    {k}: {format_val(CONFIG.get(k), SCHEMA.get(k,{}))} → {format_val(v, SCHEMA.get(k,{}))}")
    if len(changes) > 8: print(f"    ... and {len(changes)-8} more")
    
    if not force:
        try:
            if input("    Restore? (y/N): ").lower() != 'y': return False
        except: return False
    
    ok = 0
    for k, v in changes.items():
        if apply_to_device(dev, k, v):
            CONFIG[k] = v; ok += 1
        else:
            print(f"[!] Failed: {k}")
    
    print(f"[+] Restored: {ok}/{len(changes)}")
    return ok > 0


def cmd_reset(dev, args, force):
    """Reset all to defaults"""
    changes = {k: s['default'] for k, s in SCHEMA.items()
               if not k.startswith('_') and 'default' in s and CONFIG.get(k) != s['default']}
    
    if not changes:
        print("[*] Nothing to reset"); return True
    
    print(f"\n[+] Reset {len(changes)} to defaults")
    
    if not confirm("⚠️  ALL custom settings will be lost!", 'RESET', force):
        return False
    
    ok = 0
    for k, v in changes.items():
        if apply_to_device(dev, k, v):
            CONFIG[k] = v; ok += 1
        else:
            print(f"[!] Failed: {k}")
    
    print(f"[+] Reset: {ok}/{len(changes)}")
    return ok > 0


def cmd_validate(dev, args, force):
    """Validate configuration"""
    errors = []
    for k, v in CONFIG.items():
        if k.startswith('_'): continue
        s = SCHEMA.get(k, {})
        if s and not validate_value(k, v, s):
            errors.append(k)
    
    if not errors:
        print("[+] All valid")
        return True
    
    print(f"[!] {len(errors)} invalid: {', '.join(errors)}")
    return False


def cmd_info(dev, args, force):
    """Schema info"""
    if args:
        key = args[0]
        if key not in SCHEMA:
            print(f"[!] Unknown: {key}"); return False
        
        s = SCHEMA[key]
        print(f"\n[+] Schema: {key}")
        for f, v in s.items():
            print(f"    {f:<12} {v}")
        if key in CONFIG:
            print(f"    {'current':<12} {format_val(CONFIG[key], s)}")
        return True
    
    cats = {}
    for k, s in SCHEMA.items():
        if k.startswith('_'): continue
        cats[s.get('category', '?')] = cats.get(s.get('category', '?'), 0) + 1
    
    print(f"\n[+] Schema: {len(cats)} categories, {sum(cats.values())} keys")
    for c, n in sorted(cats.items()):
        print(f"    {c:<14} {n} keys")
    return True


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'get': cmd_get, 'read': cmd_get, 'show': cmd_get,
    'set': cmd_set, 'write': cmd_set, 'update': cmd_set,
    'list': cmd_list, 'ls': cmd_list, 'all': cmd_list,
    'delete': cmd_delete, 'remove': cmd_delete, 'unset': cmd_delete,
    'backup': cmd_backup, 'save': cmd_backup, 'export': cmd_backup,
    'restore': cmd_restore, 'load': cmd_restore, 'import': cmd_restore,
    'reset': cmd_reset, 'default': cmd_reset, 'clear': cmd_reset,
    'validate': cmd_validate, 'check': cmd_validate,
    'info': cmd_info, 'schema': cmd_info, 'describe': cmd_info,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_config(args=None) -> int:
    """
    QSLCL CONFIG - Configuration management
    
    Examples:
        config get debug_level          - Get a config value
        config set timeout 10000        - Set timeout to 10000ms
        config list                     - List all config
        config delete timeout           - Reset timeout to default
        config backup my_config.json    - Backup to file
        config restore my_config.json   - Restore from backup
        config reset                    - Reset all to defaults
        config validate                 - Validate configuration
        config info                     - Show schema overview
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: config <get|set|list|delete|backup|restore|reset|validate|info>")
        return 1
    
    init_config()
    
    devs = scan_all()
    dev = devs[0] if devs else None
    
    if dev:
        print(f"[*] Device: {dev.product}")
        if getattr(args, 'loader', None):
            auto_loader_if_needed(args, dev)
    
    load_from_device(dev)
    
    sub = (getattr(args, 'config_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    cargs = getattr(args, 'config_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Config Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<10} {doc}")
        print(f"\n[*] Available keys: {', '.join(k for k in sorted(SCHEMA) if not k.startswith('_'))}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    try:
        return 0 if handler(dev, cargs, force) else 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


def cmd_config_list(args=None):
    """List all config (shortcut)"""
    if args is None:
        args = type('Args', (), {})()
        args.config_subcommand = 'list'
        args.config_args = []
        args.loader = None
        args.force = False
    return cmd_config(args)


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] config.py - QSLCL CONFIG Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py config <get|set|list|delete|backup|restore|reset|validate|info>")