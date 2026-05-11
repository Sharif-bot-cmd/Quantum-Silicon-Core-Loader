#!/usr/bin/env python3
"""
mode.py - QSLCL MODE Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, mode validation,
       safety checks, data parsing, status display
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
MODE_TIMEOUT = 10.0
MAX_RETRIES = 2

# Mode opcodes
class ModeOp:
    CAPABILITIES = 0x00
    SET = 0x01
    UNSET = 0x02
    CONFIGURE = 0x03
    SAVE = 0x04
    LOAD = 0x05
    RESET = 0x06
    STATUS = 0x10

# Valid modes with metadata
VALID_MODES: Dict[str, Dict] = {
    'NORMAL':      {'safety':'SAFE',     'desc':'Standard operation mode', 'features':[]},
    'DEBUG':       {'safety':'WARNING',  'desc':'Debugging and diagnostics', 'features':['EXTENDED_LOGGING','MEMORY_DEBUG']},
    'DIAGNOSTIC':  {'safety':'SAFE',     'desc':'Hardware diagnostics', 'features':['HW_TEST','COMPONENT_VERIFY']},
    'RECOVERY':    {'safety':'SAFE',     'desc':'System recovery', 'features':['RESTORE','BACKUP']},
    'SECURE':      {'safety':'SAFE',     'desc':'Enhanced security', 'features':['SECURE_BOOT','ENCRYPTION']},
    'PERFORMANCE': {'safety':'WARNING',  'desc':'Maximum performance', 'features':['CPU_BOOST','GPU_BOOST']},
    'DEVELOPMENT': {'safety':'DANGEROUS','desc':'Full development mode', 'features':['ALL_DEBUG','UNRESTRICTED']},
    'TESTING':     {'safety':'WARNING',  'desc':'Testing and validation', 'features':['TEST_FRAMEWORK']},
    'MAINTENANCE': {'safety':'DANGEROUS','desc':'System maintenance', 'features':['FW_UPDATE','DATA_RECOVERY']},
    'BOOTSTRAP':   {'safety':'DANGEROUS','desc':'Low-level bootstrap', 'features':['HW_INIT','BOOTLOADER']},
}

PERFORMANCE_LEVELS = ['LOW','NORMAL','HIGH','MAX']
SECURITY_LEVELS = ['MINIMAL','NORMAL','ENHANCED','MAXIMUM']
MODE_STATES = ['INACTIVE','ACTIVE','TRANSITION','ERROR']

# =============================================================================
# FIXED: Colors
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Confirmation helper
# =============================================================================
def _confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n{C.RED}{msg}{C.RESET}")
    try: return input(f"    Type '{req}': ").upper() == req.upper()
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
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or MODE_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or MODE_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.1)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Make payload helper
# =============================================================================
def _make_payload(opcode: int, *args) -> bytes:
    payload = struct.pack("<B", opcode)
    for arg in args:
        if isinstance(arg, str):
            payload += arg.encode('ascii', errors='ignore')[:32].ljust(32, b'\x00')
        elif isinstance(arg, int):
            payload += struct.pack("<I", arg)
        elif isinstance(arg, bytes):
            payload += arg[:32].ljust(32, b'\x00')
    return payload


# =============================================================================
# FIXED: Data parsing
# =============================================================================
def _parse_status(data: bytes) -> Dict[str, Any]:
    status = {
        'current_mode':'UNKNOWN','mode_state':'UNKNOWN',
        'features_active':0,'performance_level':'UNKNOWN',
        'security_level':'UNKNOWN','resources_used':0,'uptime':0,
    }
    try:
        if not data or len(data) < 16: return status
        status['current_mode'] = data[0:16].decode('ascii','ignore').rstrip('\x00').strip() or 'UNKNOWN'
        if len(data) >= 20:
            status['features_active'] = struct.unpack("<I", data[16:20])[0]
        if len(data) >= 24:
            status['resources_used'] = struct.unpack("<I", data[20:24])[0]
        if len(data) >= 28:
            status['uptime'] = struct.unpack("<I", data[24:28])[0]
        if len(data) >= 32:
            flags = struct.unpack("<I", data[28:32])[0]
            status['performance_level'] = PERFORMANCE_LEVELS[(flags>>0)&3]
            status['security_level'] = SECURITY_LEVELS[(flags>>2)&3]
            status['mode_state'] = MODE_STATES[(flags>>4)&3]
    except: pass
    return status

def _parse_simple(data: bytes, count: int = 2) -> Dict:
    """Parse simple result with N uint32 values."""
    result = {}
    try:
        if data and len(data) >= count*4:
            for i in range(count):
                result[f'value_{i}'] = struct.unpack("<I", data[i*4:(i+1)*4])[0]
    except: pass
    return result

def _format_time(seconds: int) -> str:
    if seconds < 60: return f"{seconds}s"
    elif seconds < 3600: return f"{seconds//60}m {seconds%60}s"
    elif seconds < 86400: return f"{seconds//3600}h {(seconds%3600)//60}m"
    else: return f"{seconds//86400}d {(seconds%86400)//3600}h"


# =============================================================================
# FIXED: Capabilities
# =============================================================================
def _get_capabilities(dev) -> Dict:
    caps = {
        'device_name':'QSLCL Device','mode_support':'Advanced',
        'active_mode':'NORMAL',
        'modes': [{'name':n,'description':m['desc'],'safety':m['safety'],'active':n=='NORMAL'}
                  for n,m in VALID_MODES.items()],
        'features': [
            {'name':'EXTENDED_LOGGING','description':'Detailed system logging','enabled':False},
            {'name':'HARDWARE_ACCESS','description':'Direct hardware access','enabled':False},
            {'name':'MEMORY_DEBUG','description':'Memory debugging','enabled':False},
            {'name':'PERFORMANCE_MONITOR','description':'Performance monitoring','enabled':False},
            {'name':'SECURE_BOOT','description':'Secure boot verification','enabled':True},
        ],
    }
    
    # Try to get current status
    ok, _, data = _dispatch(dev, "MODE", _make_payload(ModeOp.STATUS))
    if ok:
        st = _parse_status(data)
        caps['active_mode'] = st['current_mode']
        for m in caps['modes']:
            m['active'] = (m['name'] == st['current_mode'])
    
    return caps


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def mode_list(dev, args, force=False, persistent=False) -> bool:
    caps = _get_capabilities(dev)
    
    print(f"\n{C.BOLD}[+] Mode Capabilities{C.RESET}")
    print(f"    Device: {caps['device_name']}")
    print(f"    Support: {caps['mode_support']}")
    print(f"    Active: {C.GREEN}{caps['active_mode']}{C.RESET}")
    
    modes = caps.get('modes', [])
    if modes:
        print(f"\n{C.BOLD}[+] Available Modes:{C.RESET}")
        for m in modes:
            icon = {'SAFE':'🟢','WARNING':'🟡','DANGEROUS':'🔴'}.get(m.get('safety','?'),'❓')
            active = f" {C.GREEN}← ACTIVE{C.RESET}" if m.get('active') else ""
            print(f"    {icon} {m['name']:<16} {m.get('description','')}{active}")
    
    features = caps.get('features', [])
    if features:
        print(f"\n{C.BOLD}[+] Features:{C.RESET}")
        for f in features:
            state = f"{C.GREEN}✓{C.RESET}" if f.get('enabled') else f"{C.RED}✗{C.RESET}"
            print(f"    [{state}] {f['name']:<22} {f.get('description','')}")
    return True


def mode_set(dev, args, force=False, persistent=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify mode: {', '.join(VALID_MODES.keys())}{C.RESET}")
        return False
    
    mode = args[0].upper()
    if mode not in VALID_MODES:
        print(f"{C.RED}[!] Invalid: {mode}. Valid: {', '.join(VALID_MODES.keys())}{C.RESET}")
        return False
    
    info = VALID_MODES[mode]
    print(f"\n{C.CYAN}[*] Set mode: {mode}{C.RESET}")
    print(f"    {info['desc']} (Safety: {info['safety']})")
    
    # Safety
    if info['safety'] == 'DANGEROUS':
        if not _confirm(f"⚠️  {mode} is DANGEROUS! May cause instability or damage!", 'ENABLE', force):
            return False
    elif info['safety'] == 'WARNING':
        if not _confirm(f"⚠️  {mode} has potential side effects.", 'YES', force):
            return False
    
    payload = _make_payload(ModeOp.SET, mode, 1 if persistent else 0)
    ok, name, data = _dispatch(dev, "MODE", payload)
    
    if ok:
        print(f"{C.GREEN}[+] Mode set: {mode}{C.RESET}")
        features = info.get('features', [])
        if features:
            print(f"    Features: {', '.join(features)}")
        if persistent:
            print(f"    Persistent: YES")
    else:
        print(f"{C.RED}[!] Failed: {name}{C.RESET}")
    return ok


def mode_unset(dev, args, force=False, persistent=False) -> bool:
    print(f"\n{C.CYAN}[*] Return to NORMAL mode{C.RESET}")
    
    ok, _, data = _dispatch(dev, "MODE", _make_payload(ModeOp.UNSET))
    
    if ok:
        print(f"{C.GREEN}[+] Returned to NORMAL mode{C.RESET}")
    else:
        # Check if already normal
        ok2, _, d2 = _dispatch(dev, "MODE", _make_payload(ModeOp.STATUS))
        if ok2:
            st = _parse_status(d2)
            if st['current_mode'] == 'NORMAL':
                print(f"{C.GREEN}[+] Already in NORMAL mode{C.RESET}")
                return True
        print(f"{C.RED}[!] Failed to unset mode{C.RESET}")
    return ok


def mode_configure(dev, args, force=False, persistent=False) -> bool:
    if len(args) < 2:
        print(f"{C.RED}[!] Usage: mode configure <param> <value>{C.RESET}")
        return False
    
    param = args[0].upper()
    value = args[1]
    
    print(f"\n{C.CYAN}[*] Configure: {param} = {value}{C.RESET}")
    
    payload = _make_payload(ModeOp.CONFIGURE, param, value)
    ok, name, _ = _dispatch(dev, "MODE", payload)
    
    print(f"[{'✓' if ok else '✗'}] {'Done' if ok else f'Failed: {name}'}")
    return ok


def mode_save(dev, args, force=False, persistent=False) -> bool:
    profile = args[0] if args else "default"
    print(f"\n{C.CYAN}[*] Save profile: {profile}{C.RESET}")
    
    payload = _make_payload(ModeOp.SAVE, profile)
    ok, name, _ = _dispatch(dev, "MODE", payload)
    
    print(f"[{'✓' if ok else '✗'}] {'Saved' if ok else f'Failed: {name}'}")
    return ok


def mode_load(dev, args, force=False, persistent=False) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify profile name{C.RESET}")
        return False
    
    profile = args[0]
    print(f"\n{C.CYAN}[*] Load profile: {profile}{C.RESET}")
    
    payload = _make_payload(ModeOp.LOAD, profile)
    ok, name, _ = _dispatch(dev, "MODE", payload)
    
    print(f"[{'✓' if ok else '✗'}] {'Loaded' if ok else f'Failed: {name}'}")
    return ok


def mode_reset(dev, args, force=False, persistent=False) -> bool:
    print(f"\n{C.CYAN}[*] Reset all mode configs{C.RESET}")
    
    if not _confirm("⚠️  Clear all custom mode settings?", 'RESET', force):
        return False
    
    payload = _make_payload(ModeOp.RESET)
    ok, name, _ = _dispatch(dev, "MODE", payload)
    
    print(f"[{'✓' if ok else '✗'}] {'Reset' if ok else f'Failed: {name}'}")
    return ok


# =============================================================================
# FIXED: Status display
# =============================================================================
def cmd_mode_status(args=None) -> int:
    """Display current mode status."""
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
    
    print(f"\n{C.CYAN}[*] Mode Status{C.RESET}")
    
    ok, name, data = _dispatch(dev, "MODE", _make_payload(ModeOp.STATUS))
    
    if not ok:
        print(f"{C.RED}[!] Query failed: {name}{C.RESET}")
        return 1
    
    st = _parse_status(data)
    _display_status(st)
    return 0


def _display_status(st: Dict):
    mode = st.get('current_mode','?')
    info = VALID_MODES.get(mode, {})
    icon = {'SAFE':'🟢','WARNING':'🟡','DANGEROUS':'🔴'}.get(info.get('safety','?'),'❓')
    
    print(f"\n{C.BOLD}[+] Current Mode:{C.RESET}")
    print(f"    {icon} {mode} - {info.get('desc','Standard operation')}")
    print(f"\n    State:       {st.get('mode_state','?')}")
    print(f"    Performance: {st.get('performance_level','?')}")
    print(f"    Security:    {st.get('security_level','?')}")
    print(f"    Features:    {st.get('features_active',0)} active")
    print(f"    Resources:   {st.get('resources_used',0)} units")
    
    if st.get('uptime', 0) > 0:
        print(f"    Uptime:      {_format_time(st['uptime'])}")
    
    # Resource bar
    if st.get('resources_used', 0) > 0:
        pct = min(100, st['resources_used'])
        bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
        print(f"\n    Resources:   [{bar}] {pct}%")
    
    # Mode-specific details
    details = {
        'DEBUG':       "Extended logging and debug features active",
        'DIAGNOSTIC':  "Hardware testing capabilities available",
        'RECOVERY':    "System recovery tools accessible",
        'SECURE':      "Enhanced security protections enabled",
        'PERFORMANCE': "Maximum performance profile active",
        'DEVELOPMENT': "⚠️  Full development access - security disabled",
        'BOOTSTRAP':   "⚠️  Low-level bootstrap - EXTREME CAUTION REQUIRED",
    }
    
    if mode in details:
        print(f"\n{C.YELLOW}[*] {details[mode]}{C.RESET}")
    
    # Recommendations
    recs = []
    if mode in ('DEBUG','DEVELOPMENT') and st.get('security_level','') in ('MINIMAL',):
        recs.append("Security is minimal - consider switching to NORMAL for production")
    if st.get('performance_level') == 'MAX' and st.get('resources_used',0) > 80:
        recs.append("High resource usage - consider reducing performance level")
    if mode in ('DEVELOPMENT','BOOTSTRAP','MAINTENANCE'):
        recs.append("Dangerous mode active - ensure proper safeguards")
    
    if recs:
        print(f"\n{C.YELLOW}[+] Recommendations:{C.RESET}")
        for r in recs:
            print(f"    • {r}")


# =============================================================================
# FIXED: Dispatch table
# =============================================================================
MODE_HANDLERS = {
    'list': mode_list, 'ls': mode_list, 'show': mode_list,
    'set': mode_set, 'enable': mode_set, 'activate': mode_set,
    'unset': mode_unset, 'disable': mode_unset, 'deactivate': mode_unset,
    'configure': mode_configure, 'config': mode_configure, 'cfg': mode_configure,
    'save': mode_save, 'store': mode_save, 'persist': mode_save,
    'load': mode_load, 'restore': mode_load,
    'reset': mode_reset, 'default': mode_reset, 'clear': mode_reset,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_mode_help():
    print(f"""
{C.BOLD}MODE - QSLCL Mode Management{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}
  list, ls                List available modes
  set <mode>              Activate a mode
  unset                   Return to NORMAL mode
  configure <p> <v>       Configure mode parameter
  save [profile]          Save current configuration
  load <profile>          Load saved configuration
  reset                   Reset all configurations
  status                  Show current mode status

{C.CYAN}MODES:{C.RESET}
  🟢 NORMAL        Standard operation
  🟡 DEBUG         Debugging and development
  🟢 DIAGNOSTIC    Hardware diagnostics
  🟢 RECOVERY      System recovery
  🟢 SECURE        Enhanced security
  🟡 PERFORMANCE   Maximum performance
  🔴 DEVELOPMENT   Full development (dangerous)
  🟡 TESTING       Testing and validation
  🔴 MAINTENANCE   System maintenance
  🔴 BOOTSTRAP     Low-level bootstrap

{C.CYAN}PARAMETERS:{C.RESET}
  LOG_LEVEL      0=off, 1=error, 2=warning, 3=debug
  SECURITY       MINIMAL, NORMAL, ENHANCED, MAXIMUM
  PERFORMANCE    LOW, NORMAL, HIGH, MAX

{C.CYAN}OPTIONS:{C.RESET}
  --persistent   Make changes survive reboot
  --force        Skip safety confirmations

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl mode list
  qslcl mode set DEBUG
  qslcl mode set PERFORMANCE --persistent
  qslcl mode configure LOG_LEVEL 3
  qslcl mode status
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_mode(args=None) -> int:
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_mode_help(); return 1
    
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
    
    sub = (getattr(args, 'mode_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    mar = getattr(args, 'mode_args', []) or []
    force = getattr(args, 'force', False)
    persistent = getattr(args, 'persistent', False)
    
    if not sub or sub in ('help','?','-h','--help'):
        print_mode_help(); return 0
    
    # Handle status as special case
    if sub == 'status':
        return cmd_mode_status(args)
    
    handler = MODE_HANDLERS.get(sub)
    if not handler:
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_mode_help(); return 1
    
    try:
        return 0 if handler(dev, mar, force, persistent) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


def add_mode_arguments(parser):
    parser.add_argument('mode_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('mode_args', nargs='*', help='Arguments')
    parser.add_argument('--persistent', action='store_true', help='Make persistent')
    parser.add_argument('--force', action='store_true', help='Skip confirmations')
    return parser


if __name__ == "__main__":
    print("[*] mode.py - QSLCL MODE Module v2.0")
    print_mode_help()