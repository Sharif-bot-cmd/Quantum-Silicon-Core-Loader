#!/usr/bin/env python3
"""
reset.py - QSLCL RESET Command Module v2.1 (CLEANED)
Device reset and reboot control with safety checks
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
TIMEOUT = 30
MONITOR_TIMEOUT = 60

# Opcodes
OP_CAPABILITIES = 0x00
OP_SOFT = 0x01
OP_HARD = 0x02
OP_FORCE = 0x03
OP_DOMAIN = 0x10
OP_RECOVERY = 0x20
OP_FACTORY = 0x30
OP_BOOTLOADER = 0x40
OP_EDL = 0x41
OP_PMIC = 0x50
OP_WATCHDOG = 0x60
OP_CUSTOM = 0x70

# Reset type definitions
RESET_TYPES = {
    'soft':       {'name':'SOFT',       'opcode':OP_SOFT,       'safety':'SAFE',     'desc':'Warm reboot', 'confirm':None},
    'warm':       {'name':'SOFT',       'opcode':OP_SOFT,       'safety':'SAFE',     'desc':'Warm reboot', 'confirm':None},
    'normal':     {'name':'SOFT',       'opcode':OP_SOFT,       'safety':'SAFE',     'desc':'Normal reboot', 'confirm':None},
    'hard':       {'name':'HARD',       'opcode':OP_HARD,       'safety':'WARNING',  'desc':'Cold reboot, may lose data', 'confirm':'HARD'},
    'cold':       {'name':'HARD',       'opcode':OP_HARD,       'safety':'WARNING',  'desc':'Cold reboot', 'confirm':'HARD'},
    'full':       {'name':'HARD',       'opcode':OP_HARD,       'safety':'WARNING',  'desc':'Full power cycle', 'confirm':'HARD'},
    'force':      {'name':'FORCE',      'opcode':OP_FORCE,      'safety':'DANGEROUS','desc':'Emergency/panic reset', 'confirm':'FORCE'},
    'emergency':  {'name':'FORCE',      'opcode':OP_FORCE,      'safety':'DANGEROUS','desc':'Emergency reset', 'confirm':'FORCE'},
    'panic':      {'name':'FORCE',      'opcode':OP_FORCE,      'safety':'DANGEROUS','desc':'Kernel panic', 'confirm':'FORCE'},
    'recovery':   {'name':'RECOVERY',   'opcode':OP_RECOVERY,   'safety':'WARNING',  'desc':'Boot to recovery', 'confirm':None},
    'factory':    {'name':'FACTORY',    'opcode':OP_FACTORY,    'safety':'CRITICAL', 'desc':'ERASES ALL USER DATA', 'confirm':'WIPE'},
    'wipe':       {'name':'FACTORY',    'opcode':OP_FACTORY,    'safety':'CRITICAL', 'desc':'Factory data wipe', 'confirm':'WIPE'},
    'bootloader': {'name':'BOOTLOADER', 'opcode':OP_BOOTLOADER, 'safety':'WARNING',  'desc':'Boot to bootloader', 'confirm':None},
    'download':   {'name':'BOOTLOADER', 'opcode':OP_BOOTLOADER, 'safety':'WARNING',  'desc':'Download mode', 'confirm':None},
    'edl':        {'name':'EDL',        'opcode':OP_EDL,        'safety':'WARNING',  'desc':'Emergency Download Mode', 'confirm':None},
    'pmic':       {'name':'PMIC',       'opcode':OP_PMIC,       'safety':'DANGEROUS','desc':'Power IC reset', 'confirm':'PMIC'},
    'power':      {'name':'PMIC',       'opcode':OP_PMIC,       'safety':'DANGEROUS','desc':'Power cycle via PMIC', 'confirm':'PMIC'},
    'watchdog':   {'name':'WATCHDOG',   'opcode':OP_WATCHDOG,   'safety':'WARNING',  'desc':'Watchdog reset', 'confirm':None},
    'wdt':        {'name':'WATCHDOG',   'opcode':OP_WATCHDOG,   'safety':'WARNING',  'desc':'Watchdog reset', 'confirm':None},
}

VALID_DOMAINS = {'CPU','GPU','DSP','MODEM','WIFI','BT','USB','PCIE','MEMORY','CAMERA','DISPLAY','AUDIO','SENSORS'}
CRITICAL_DOMAINS = {'CPU','MEMORY','MODEM','PCIE'}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    """Safety confirmation"""
    if force:
        print(f"\n[!] Force mode: skipping confirmation")
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}': ") == req
    except (EOFError, KeyboardInterrupt):
        return False


def reset_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send reset command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(2):
        try:
            if "RESET" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "RESET", payload, timeout=10)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=10)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            pass
        if attempt == 0:
            time.sleep(0.2)
    
    return False, "NO_RESPONSE", b""


def monitor_reset(dev, timeout: int):
    """Monitor for device after reset"""
    print(f"\n[*] Monitoring for device ({timeout}s)...")
    start = time.time()
    
    while time.time() - start < timeout:
        elapsed = time.time() - start
        remaining = timeout - elapsed
        pct = int((elapsed / timeout) * 20)
        bar = "█" * pct + "░" * (20 - pct)
        print(f"\r    [{bar}] {remaining:.0f}s", end="", flush=True)
        
        try:
            time.sleep(2)
            devs = scan_all()
            if devs:
                print(f"\n\n[+] Device detected after {elapsed:.1f}s!")
                return True
        except KeyboardInterrupt:
            print(f"\n\n[*] Monitoring stopped")
            return False
        except:
            pass
    
    print(f"\n\n[!] Timeout - device may need manual recovery")
    return False


def execute_reset(dev, reset_type: str, info: dict, args: List[str],
                  force: bool, delay: int) -> bool:
    """Execute a reset with safety checks"""
    
    # Confirmation
    if info.get('confirm'):
        if not confirm(f"{info['safety']} RESET: {info['desc']}", info['confirm'], force):
            print("[*] Cancelled")
            return False
    
    # Factory reset double confirmation
    if reset_type in ('factory', 'wipe', 'clean'):
        print(f"\n[!] FINAL WARNING: ALL USER DATA WILL BE ERASED!")
        if not confirm("This action is IRREVERSIBLE!", 'FACTORY', force):
            print("[*] Cancelled")
            return False
        
        if delay < 5:
            print(f"[*] 5 second grace period...")
            try: time.sleep(5)
            except KeyboardInterrupt:
                print(f"[*] Factory reset CANCELLED")
                return False
    
    # Delay
    if delay > 0:
        print(f"[*] Waiting {delay}s...")
        for i in range(delay, 0, -1):
            print(f"\r    {i}s remaining...", end="", flush=True)
            try: time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n[*] Reset CANCELLED")
                return False
        print()
    
    # Build payload
    opcode = info['opcode']
    payload = struct.pack("<I", 30)  # timeout
    
    if opcode == OP_DOMAIN and args:
        domain = args[0].upper()[:8]
        payload = domain.encode().ljust(8, b'\x00') + payload
    
    if opcode == OP_CUSTOM and args:
        seq = ' '.join(args)[:64]
        payload = seq.encode().ljust(64, b'\x00') + payload
    
    # Execute
    print(f"\n[*] Executing {info['name']} reset...")
    success, status_name, _ = reset_cmd(dev, opcode, payload)
    
    if success:
        print(f"[+] Reset command accepted")
        monitor_reset(dev, 30)
        return True
    else:
        print(f"[!] Reset failed: {status_name}")
        print(f"[*] Device may have reset anyway (no response)")
        return True  # Assume success if device stopped responding


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force, delay) -> bool:
    """List reset types"""
    print(f"\n[*] Reset Types:\n")
    shown = set()
    for key, info in RESET_TYPES.items():
        name = info['name']
        if name in shown: continue
        shown.add(name)
        icons = {'SAFE':'🟢', 'WARNING':'🟡', 'DANGEROUS':'🔴', 'CRITICAL':'💀'}
        print(f"  {icons.get(info['safety'],'?')} {name:<12} {info['safety']:<10} {info['desc']}")
    
    print(f"\n[*] Reset Domains: {', '.join(sorted(VALID_DOMAINS))}")
    print(f"[*] Critical: {', '.join(sorted(CRITICAL_DOMAINS))}")
    return True


def cmd_domain(dev, args, force, delay) -> bool:
    """Reset specific domain"""
    if not args:
        print("[!] Specify domain to reset")
        print(f"[*] Valid: {', '.join(sorted(VALID_DOMAINS))}")
        return False
    
    domain = args[0].upper()
    if domain not in VALID_DOMAINS:
        print(f"[!] Unknown domain: {domain}")
        return False
    
    if domain in CRITICAL_DOMAINS and not force:
        if not confirm(f"CRITICAL domain: {domain}\nResetting may crash system!", 'YES', force):
            return False
    
    print(f"\n[*] Resetting domain: {domain}")
    info = {'name': f'DOMAIN:{domain}', 'opcode': OP_DOMAIN, 'safety': 'WARNING',
            'desc': f'Reset {domain} subsystem',
            'confirm': 'YES' if domain in CRITICAL_DOMAINS else None}
    return execute_reset(dev, 'domain', info, args, force, delay)


def cmd_custom(dev, args, force, delay) -> bool:
    """Custom reset sequence"""
    if not args:
        print("[!] Specify custom reset sequence")
        return False
    
    seq = ' '.join(args)
    print(f"\n[*] Custom sequence: {seq}")
    
    info = {'name': 'CUSTOM', 'opcode': OP_CUSTOM, 'safety': 'DANGEROUS',
            'desc': 'Custom reset sequence', 'confirm': 'YES'}
    return execute_reset(dev, 'custom', info, args, force, delay)


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_reset(args=None) -> int:
    """
    QSLCL RESET - Device reset and reboot control
    
    Examples:
        reset soft              - Warm reboot
        reset hard              - Cold reboot
        reset recovery          - Boot to recovery
        reset bootloader        - Boot to bootloader
        reset domain CPU        - Reset CPU domain
        reset factory           - Factory reset (ERASES DATA!)
        reset --force-reset     - Skip confirmations
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: reset <soft|hard|recovery|bootloader|factory|domain|custom>")
        return 1
    
    # Device
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Get subcommand
    sub = (getattr(args, 'reset_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    rargs = getattr(args, 'reset_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force_reset', False) or getattr(args, 'force', False)
    delay = max(0, getattr(args, 'delay', 0) or 0)
    
    if not sub or sub in ('help', '?'):
        print("[*] Reset Commands:")
        shown = set()
        for key, info in RESET_TYPES.items():
            if info['name'] not in shown:
                shown.add(info['name'])
                icons = {'SAFE':'🟢', 'WARNING':'🟡', 'DANGEROUS':'🔴', 'CRITICAL':'💀'}
                print(f"    {icons[info['safety']]} {info['name']:<12} - {info['desc']}")
        print(f"    📍 domain <name>  - Reset subsystem")
        print(f"    🔧 custom <seq>   - Custom sequence")
        return 0
    
    # Handle list
    if sub in ('list', 'ls', 'types'):
        return 0 if cmd_list(dev, rargs, force, delay) else 1
    
    # Handle domain
    if sub in ('domain', 'subsystem'):
        return 0 if cmd_domain(dev, rargs, force, delay) else 1
    
    # Handle custom
    if sub in ('custom', 'sequence'):
        return 0 if cmd_custom(dev, rargs, force, delay) else 1
    
    # Handle standard reset types
    info = RESET_TYPES.get(sub)
    if info:
        try:
            return 0 if execute_reset(dev, sub, info, rargs, force, delay) else 1
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            return 1
        except Exception as e:
            print(f"[!] Error: {e}")
            if _DEBUG:
                import traceback
                traceback.print_exc()
            return 1
    
    print(f"[!] Unknown reset type: {sub}")
    print(f"[*] Use 'reset list' to see available types")
    return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] reset.py - QSLCL RESET Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py reset <type> [options]")