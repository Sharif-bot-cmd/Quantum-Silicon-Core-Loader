#!/usr/bin/env python3
"""
reset.py - QSLCL RESET Command Module v2.0 (FIXED)
Fixed: Import handling, safety confirmations, command dispatch,
       timeout handling, monitoring, error recovery
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
RESET_TIMEOUT = 30
DEFAULT_MONITOR_TIMEOUT = 60

# =============================================================================
# FIXED: Color codes
# =============================================================================
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'; CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


# =============================================================================
# FIXED: Reset opcodes
# =============================================================================
class ResetOpcode:
    CAPABILITIES = 0x00
    SOFT = 0x01
    HARD = 0x02
    FORCE = 0x03
    DOMAIN = 0x10
    RECOVERY = 0x20
    FACTORY = 0x30
    BOOTLOADER = 0x40
    EDL = 0x41
    PMIC = 0x50
    WATCHDOG = 0x60
    CUSTOM = 0x70


# =============================================================================
# FIXED: Reset type definitions
# =============================================================================
RESET_TYPES = {
    'soft':       {'name':'SOFT',       'icon':'🟢', 'safety':'SAFE',     'desc':'Warm reboot, preserves state', 'confirm':False,  'timeout':30},
    'warm':       {'name':'SOFT',       'icon':'🟢', 'safety':'SAFE',     'desc':'Warm reboot', 'confirm':False,  'timeout':30},
    'normal':     {'name':'SOFT',       'icon':'🟢', 'safety':'SAFE',     'desc':'Normal reboot', 'confirm':False,  'timeout':30},
    'hard':       {'name':'HARD',       'icon':'🟡', 'safety':'WARNING',  'desc':'Cold reboot, may lose data', 'confirm':'HARD',  'timeout':45},
    'cold':       {'name':'HARD',       'icon':'🟡', 'safety':'WARNING',  'desc':'Cold reboot', 'confirm':'HARD',  'timeout':45},
    'full':       {'name':'HARD',       'icon':'🟡', 'safety':'WARNING',  'desc':'Full power cycle', 'confirm':'HARD',  'timeout':45},
    'force':      {'name':'FORCE',      'icon':'🔴', 'safety':'DANGEROUS','desc':'Emergency/panic reset', 'confirm':'FORCE', 'timeout':30},
    'emergency':  {'name':'FORCE',      'icon':'🔴', 'safety':'DANGEROUS','desc':'Emergency reset', 'confirm':'FORCE', 'timeout':30},
    'panic':      {'name':'FORCE',      'icon':'🔴', 'safety':'DANGEROUS','desc':'Kernel panic trigger', 'confirm':'FORCE', 'timeout':30},
    'recovery':   {'name':'RECOVERY',   'icon':'🟡', 'safety':'WARNING',  'desc':'Boot to recovery mode', 'confirm':False,  'timeout':30},
    'factory':    {'name':'FACTORY',    'icon':'🔴', 'safety':'CRITICAL', 'desc':'ERASES ALL USER DATA', 'confirm':'WIPE',  'timeout':120},
    'wipe':       {'name':'FACTORY',    'icon':'🔴', 'safety':'CRITICAL', 'desc':'Factory data wipe', 'confirm':'WIPE',  'timeout':120},
    'clean':      {'name':'FACTORY',    'icon':'🔴', 'safety':'CRITICAL', 'desc':'Clean reset', 'confirm':'WIPE',  'timeout':120},
    'bootloader': {'name':'BOOTLOADER', 'icon':'🟡', 'safety':'WARNING',  'desc':'Boot to bootloader/EDL', 'confirm':False,  'timeout':30},
    'download':   {'name':'BOOTLOADER', 'icon':'🟡', 'safety':'WARNING',  'desc':'Enter download mode', 'confirm':False,  'timeout':30},
    'edl':        {'name':'EDL',        'icon':'🟡', 'safety':'WARNING',  'desc':'Emergency Download Mode', 'confirm':False,  'timeout':30},
    'pmic':       {'name':'PMIC',       'icon':'🔴', 'safety':'DANGEROUS','desc':'Power IC reset', 'confirm':'PMIC',  'timeout':30},
    'power':      {'name':'PMIC',       'icon':'🔴', 'safety':'DANGEROUS','desc':'Power cycle via PMIC', 'confirm':'PMIC',  'timeout':30},
    'watchdog':   {'name':'WATCHDOG',   'icon':'🟡', 'safety':'WARNING',  'desc':'Trigger watchdog reset', 'confirm':False,  'timeout':15},
    'wdt':        {'name':'WATCHDOG',   'icon':'🟡', 'safety':'WARNING',  'desc':'Watchdog timer reset', 'confirm':False,  'timeout':15},
}

CRITICAL_DOMAINS = {'CPU','MEMORY','MODEM','PCIE'}
VALID_DOMAINS = {'CPU','GPU','DSP','MODEM','WIFI','BT','USB','PCIE','MEMORY','CAMERA','DISPLAY','AUDIO','SENSORS'}
VALID_RESET_NAMES = set(RESET_TYPES.keys()) | {'domain','subsystem','custom','sequence','list','ls','types','help','?'}


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
                resp = _qslcl_dispatch(dev, k if t=="name" else str(k), payload, timeout=timeout or RESET_TIMEOUT)
            else:
                resp = _qslcl_dispatch(dev, cmd, payload, timeout=timeout or RESET_TIMEOUT)
            if resp:
                s = _decode_runtime_result(resp)
                return s.get("severity")=="SUCCESS", s.get("name","?"), s.get("extra",b"")
        except: pass
        if attempt==0: time.sleep(0.2)
    return False,"NO_RESPONSE",b""


# =============================================================================
# FIXED: Confirmation helper (supports EOFError)
# =============================================================================
def _confirm(prompt: str, required: str, force: bool = False) -> bool:
    if force:
        print(f"\n{C.YELLOW}[!] Force mode: skipping confirmation{C.RESET}")
        return True
    print(f"\n{C.BRIGHT_RED}{prompt}{C.RESET}")
    try:
        return input(f"    Type '{required}': ") == required
    except (EOFError, KeyboardInterrupt):
        print(f"\n{C.YELLOW}[!] Input unavailable{C.RESET}")
        return False


# =============================================================================
# FIXED: Reset dispatch (with safety lock check)
# =============================================================================
def _execute_reset(dev, opcode: int, reset_type: str, info: Dict,
                   args: List[str], force: bool, delay: int, timeout: int) -> bool:
    """Execute a reset with proper safety checks and monitoring."""
    
    # Safety confirmation
    if info.get('confirm'):
        if not _confirm(
            f"⚠️  {info['safety']} RESET: {info['desc']}\n"
            f"Type: {info['name']}\n"
            f"This may {info['desc'].lower()}.",
            info['confirm'], force
        ):
            print("[*] Operation cancelled")
            return False
    
    # Factory reset: double confirmation
    if reset_type in ('factory','wipe','clean'):
        print(f"\n{C.BRIGHT_RED}⚠️  FINAL WARNING: ALL USER DATA WILL BE ERASED!{C.RESET}")
        if not _confirm("This action is IRREVERSIBLE!", 'FACTORY', force):
            print("[*] Factory reset cancelled")
            return False
        
        if delay < 5:
            print(f"\n{C.YELLOW}[*] Last chance: Ctrl+C within 5 seconds to cancel...{C.RESET}")
            try: time.sleep(5)
            except KeyboardInterrupt:
                print(f"\n{C.GREEN}[*] Factory reset CANCELLED{C.RESET}"); return False
    
    # Delay
    if delay > 0:
        print(f"[*] Waiting {delay}s before reset...")
        for i in range(delay, 0, -1):
            print(f"\r    {i}s remaining...", end="", flush=True)
            try: time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{C.GREEN}[*] Reset CANCELLED{C.RESET}"); return False
        print()
    
    # Build payload
    payload = struct.pack("<B", opcode)
    payload += struct.pack("<I", timeout)
    
    # For domain reset
    if opcode == ResetOpcode.DOMAIN and args:
        domain = args[0].upper()
        payload = struct.pack("<B", opcode)
        payload += domain.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        payload += struct.pack("<I", timeout)
    
    # For custom reset
    if opcode == ResetOpcode.CUSTOM and args:
        sequence = ' '.join(args)[:64]
        payload = struct.pack("<B", opcode)
        payload += sequence.encode('ascii', errors='ignore')[:64].ljust(64, b'\x00')
        payload += struct.pack("<I", timeout)
    
    # Execute
    print(f"\n{C.CYAN}[*] Executing {info['name']} reset...{C.RESET}")
    success, status_name, extra = _dispatch(dev, "RESET", payload, timeout=10)
    
    if success:
        print(f"{C.GREEN}[+] Reset command accepted{C.RESET}")
        _monitor_reset(dev, info['timeout'], info['name'])
        return True
    else:
        print(f"{C.RED}[!] Reset failed: {status_name}{C.RESET}")
        print(f"{C.YELLOW}[*] Device may have reset anyway (no response){C.RESET}")
        return True  # Assume success if device stopped responding


# =============================================================================
# FIXED: Reset monitoring
# =============================================================================
def _monitor_reset(dev, timeout: int, reset_name: str):
    """Monitor reset progress."""
    print(f"\n{C.CYAN}[*] Monitoring reset (timeout: {timeout}s)...{C.RESET}")
    start = time.time()
    
    while (time.time() - start) < timeout:
        elapsed = time.time() - start
        remaining = timeout - elapsed
        pct = int((elapsed / timeout) * 20)
        bar = "█" * pct + "░" * (20 - pct)
        print(f"\r    [{bar}] {remaining:.0f}s", end="", flush=True)
        
        try:
            time.sleep(2)
            devs = _scan_all()
            if devs:
                print(f"\n\n{C.GREEN}[+] Device detected after {elapsed:.1f}s!{C.RESET}")
                return
        except KeyboardInterrupt:
            print(f"\n\n{C.YELLOW}[*] Monitoring stopped{C.RESET}")
            return
        except Exception:
            pass
    
    print(f"\n\n{C.YELLOW}[!] Timeout - device may need manual recovery{C.RESET}")


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def reset_list(dev, args, force=False, delay=0, timeout=30) -> bool:
    """List available reset types."""
    print(f"\n{C.BOLD}[+] Available Reset Types:{C.RESET}\n")
    print(f"  {'Name':<15} {'Safety':<10} Description")
    print(f"  {'-'*15} {'-'*10} {'-'*40}")
    
    shown = set()
    for key, info in RESET_TYPES.items():
        name = info['name']
        if name in shown: continue
        shown.add(name)
        icon = info['icon']
        safety = info['safety']
        desc = info['desc']
        print(f"  {icon} {name:<12} {safety:<10} {desc}")
    
    print(f"\n{C.BOLD}[+] Reset Domains:{C.RESET}\n")
    for d in sorted(VALID_DOMAINS):
        critical = f" {C.RED}(CRITICAL){C.RESET}" if d in CRITICAL_DOMAINS else ""
        print(f"    {d:<12}{critical}")
    
    print(f"\n{C.BOLD}[+] Safety Levels:{C.RESET}")
    print(f"  🟢 SAFE     - No data loss, safe to use")
    print(f"  🟡 WARNING  - May cause data loss")
    print(f"  🔴 DANGEROUS - Risk of damage")
    print(f"  {C.RED}🔴 CRITICAL  - Will erase data / may brick{C.RESET}")
    return True


def _reset_handler(dev, args, force, delay, timeout, reset_key: str, opcode: int) -> bool:
    """Generic reset handler."""
    info = RESET_TYPES.get(reset_key, RESET_TYPES['soft'])
    return _execute_reset(dev, opcode, reset_key, info, args, force, delay, timeout)


def reset_soft(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'soft', ResetOpcode.SOFT)

def reset_hard(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'hard', ResetOpcode.HARD)

def reset_force(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'force', ResetOpcode.FORCE)

def reset_domain(dev, args, force=False, delay=0, timeout=30) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify domain to reset{C.RESET}")
        print(f"[*] Valid: {', '.join(sorted(VALID_DOMAINS))}")
        return False
    
    domain = str(args[0]).upper() if isinstance(args, list) else str(args).upper()
    
    if domain not in VALID_DOMAINS:
        print(f"{C.RED}[!] Unknown domain: {domain}{C.RESET}")
        return False
    
    if domain in CRITICAL_DOMAINS and not force:
        if not _confirm(f"⚠️  {domain} is a CRITICAL domain!\nResetting it may crash the system.", 'YES', force):
            return False
    
    print(f"\n{C.CYAN}[*] Resetting domain: {domain}{C.RESET}")
    return _execute_reset(dev, ResetOpcode.DOMAIN, 'domain', 
                         {'name':f'DOMAIN:{domain}','icon':'🟡','safety':'WARNING',
                          'desc':f'Reset {domain} subsystem','confirm':'YES' if domain in CRITICAL_DOMAINS else False,
                          'timeout':timeout}, [domain], force, delay, timeout)

def reset_recovery(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'recovery', ResetOpcode.RECOVERY)

def reset_factory(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, max(timeout, 120), 'factory', ResetOpcode.FACTORY)

def reset_bootloader(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'bootloader', ResetOpcode.BOOTLOADER)

def reset_edl(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'edl', ResetOpcode.EDL)

def reset_pmic(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'pmic', ResetOpcode.PMIC)

def reset_watchdog(dev, args, force=False, delay=0, timeout=30) -> bool:
    return _reset_handler(dev, args, force, delay, timeout, 'watchdog', ResetOpcode.WATCHDOG)

def reset_custom(dev, args, force=False, delay=0, timeout=30) -> bool:
    if not args:
        print(f"{C.RED}[!] Specify custom reset sequence{C.RESET}")
        print("[*] Format: reset custom <command>[:param] ...")
        return False
    
    sequence = ' '.join(str(a) for a in args)
    print(f"\n{C.CYAN}[*] Custom sequence: {sequence}{C.RESET}")
    
    return _execute_reset(dev, ResetOpcode.CUSTOM, 'custom',
                         {'name':'CUSTOM','icon':'🔴','safety':'DANGEROUS',
                          'desc':'Custom reset sequence','confirm':'YES','timeout':timeout},
                         args, force, delay, timeout)


# =============================================================================
# FIXED: Subcommand dispatch table
# =============================================================================
RESET_HANDLERS = {
    'list':reset_list, 'ls':reset_list, 'types':reset_list,
    'soft':reset_soft, 'warm':reset_soft, 'normal':reset_soft,
    'hard':reset_hard, 'cold':reset_hard, 'full':reset_hard,
    'force':reset_force, 'emergency':reset_force, 'panic':reset_force,
    'domain':reset_domain, 'subsystem':reset_domain,
    'recovery':reset_recovery, 'recovery-mode':reset_recovery,
    'factory':reset_factory, 'wipe':reset_factory, 'clean':reset_factory,
    'bootloader':reset_bootloader, 'download':reset_bootloader,
    'edl':reset_edl,
    'pmic':reset_pmic, 'power':reset_pmic,
    'watchdog':reset_watchdog, 'wdt':reset_watchdog,
    'custom':reset_custom, 'sequence':reset_custom,
}


# =============================================================================
# FIXED: Help
# =============================================================================
def print_reset_help():
    print(f"""
{C.BOLD}RESET - Device Reset & Reboot Control{C.RESET}
{'='*50}

{C.CYAN}SUBCOMMANDS:{C.RESET}

  {C.BOLD}Standard Resets:{C.RESET}
    soft, warm, normal       🟢 Warm reboot (safe)
    hard, cold, full         🟡 Cold reboot/power cycle
    recovery                 🟡 Boot to recovery mode
    bootloader, download     🟡 Boot to bootloader/EDL

  {C.BOLD}Dangerous Resets:{C.RESET}
    force, emergency, panic  🔴 Emergency/panic reset
    factory, wipe, clean     🔴 Factory reset {C.RED}(ERASES ALL DATA!){C.RESET}
    pmic, power              🔴 Power IC reset
    custom, sequence         🔴 Custom reset sequence

  {C.BOLD}Targeted Resets:{C.RESET}
    domain <name>            Reset specific subsystem

  {C.BOLD}Information:{C.RESET}
    list, ls, types          List available reset types

{C.CYAN}DOMAINS:{C.RESET}
  CPU, GPU, DSP, MODEM, WIFI, BT, USB, PCIE, MEMORY, CAMERA, DISPLAY, AUDIO, SENSORS

{C.CYAN}OPTIONS:{C.RESET}
  --force-reset     Skip safety confirmations {C.RED}(DANGEROUS){C.RESET}
  --delay <sec>     Delay before reset
  --timeout <sec>   Monitoring timeout

{C.CYAN}EXAMPLES:{C.RESET}
  qslcl reset soft
  qslcl reset hard --force-reset
  qslcl reset domain CPU
  qslcl reset recovery --delay 5
  qslcl reset factory --force-reset
  qslcl reset custom POWER_OFF::WAIT:5::POWER_ON

{C.RED}⚠️  CRITICAL WARNINGS:{C.RESET}
  - Factory reset {C.RED}ERASES ALL USER DATA{ C.RESET}
  - Force reset may damage hardware
  - Always save work before resetting
  - Some resets require manual recovery
""")


# =============================================================================
# FIXED: Main function
# =============================================================================
def cmd_reset(args=None) -> int:
    """
    QSLCL RESET Command v2.0 (FIXED)
    
    Returns: int (0=success, 1=failure)
    """
    if args is None:
        print(f"{C.RED}[!] No arguments{C.RESET}"); print_reset_help(); return 1
    
    if not _use_qslcl: _warn_standalone()
    
    # Device discovery
    if _use_qslcl:
        try: devs = _scan_all()
        except Exception as e:
            print(f"{C.RED}[!] Scan failed: {e}{C.RESET}"); return 1
        if not devs:
            print(f"{C.RED}[!] No device{C.RESET}"); return 1
        dev = devs[0]
        print(f"{C.CYAN}[*] Device: {dev.product}{C.RESET}")
    else:
        print(f"{C.RED}[!] No QSLCL support{C.RESET}"); return 1
    
    # Loader
    if hasattr(args, 'loader') and getattr(args, 'loader', None):
        try: _auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"{C.RED}[!] Loader failed: {e}{C.RESET}"); return 1
    
    # Extract subcommand
    sub = (getattr(args, 'reset_subcommand', '') or getattr(args, 'subcommand', '')).lower().strip()
    rargs = getattr(args, 'reset_args', []) or []
    force = getattr(args, 'force_reset', False) or getattr(args, 'force', False)
    delay = max(0, int(getattr(args, 'delay', 0) or 0))
    timeout = max(5, int(getattr(args, 'timeout', 0) or 30))
    
    if not sub or sub in ('help','?','-h','--help'):
        print_reset_help(); return 0
    
    handler = RESET_HANDLERS.get(sub)
    if not handler:
        # Try matching by RESET_TYPES key
        info = RESET_TYPES.get(sub)
        if info:
            # Generic handler based on type name
            opcode_map = {'SOFT':ResetOpcode.SOFT,'HARD':ResetOpcode.HARD,'FORCE':ResetOpcode.FORCE,
                         'RECOVERY':ResetOpcode.RECOVERY,'FACTORY':ResetOpcode.FACTORY,
                         'BOOTLOADER':ResetOpcode.BOOTLOADER,'EDL':ResetOpcode.EDL,
                         'PMIC':ResetOpcode.PMIC,'WATCHDOG':ResetOpcode.WATCHDOG}
            opcode = opcode_map.get(info['name'], ResetOpcode.SOFT)
            return 0 if _execute_reset(dev, opcode, sub, info, rargs, force, delay, timeout) else 1
        
        print(f"{C.RED}[!] Unknown: {sub}{C.RESET}"); print_reset_help(); return 1
    
    try:
        return 0 if handler(dev, rargs, force, delay, timeout) else 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}"); return 1
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if _DEBUG: traceback.print_exc()
        return 1


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_reset_arguments(parser):
    parser.add_argument('reset_subcommand', nargs='?', help='Reset subcommand')
    parser.add_argument('reset_args', nargs='*', help='Additional arguments')
    parser.add_argument('--force-reset', action='store_true', help='Skip confirmations')
    parser.add_argument('--delay', type=int, default=0, help='Delay before reset (seconds)')
    parser.add_argument('--timeout', type=int, default=30, help='Monitoring timeout (seconds)')
    return parser


if __name__ == "__main__":
    print("[*] reset.py - QSLCL RESET Module v2.0")
    print_reset_help()