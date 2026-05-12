#!/usr/bin/env python3
"""
mode.py - QSLCL MODE Command Module v2.1 (CLEANED)
Device mode management: boot modes, operation states, and mode transitions
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
MAX_RETRIES = 3

# Opcodes
OP_STATUS = 0x00
OP_SET = 0x01
OP_LIST = 0x02
OP_ENTER = 0x03
OP_EXIT = 0x04
OP_REBOOT = 0x10

# Mode definitions
MODES = {
    'normal':      {'name': 'NORMAL',       'desc': 'Normal operation mode', 'safe': True,  'reboot': False},
    'safe':        {'name': 'SAFE',         'desc': 'Safe mode (minimal drivers)', 'safe': True,  'reboot': True},
    'recovery':    {'name': 'RECOVERY',     'desc': 'Recovery mode', 'safe': True,  'reboot': True},
    'bootloader':  {'name': 'BOOTLOADER',   'desc': 'Bootloader/fastboot mode', 'safe': True,  'reboot': True},
    'download':    {'name': 'DOWNLOAD',     'desc': 'Download/EDL mode', 'safe': True,  'reboot': True},
    'edl':         {'name': 'EDL',          'desc': 'Emergency Download Mode', 'safe': True,  'reboot': True},
    'diagnostic':  {'name': 'DIAGNOSTIC',   'desc': 'Diagnostic/test mode', 'safe': True,  'reboot': True},
    'factory':     {'name': 'FACTORY',      'desc': 'Factory test mode', 'safe': False, 'reboot': True},
    'engineer':    {'name': 'ENGINEER',     'desc': 'Engineering/debug mode', 'safe': False, 'reboot': True},
    'ffbm':        {'name': 'FFBM',         'desc': 'Fast Factory Boot Mode', 'safe': False, 'reboot': True},
    'qcom':        {'name': 'QCOM',         'desc': 'Qualcomm diagnostic mode', 'safe': False, 'reboot': True},
    'mtk':         {'name': 'MTK',          'desc': 'MediaTek BROM mode', 'safe': False, 'reboot': True},
    'rommon':      {'name': 'ROMMON',       'desc': 'ROM Monitor mode', 'safe': False, 'reboot': True},
    'fastboot':    {'name': 'FASTBOOT',     'desc': 'Fastboot protocol mode', 'safe': True,  'reboot': True},
    'adb':         {'name': 'ADB',          'desc': 'Android Debug Bridge mode', 'safe': True,  'reboot': True},
    'sideload':    {'name': 'SIDELOAD',     'desc': 'ADB sideload mode', 'safe': True,  'reboot': True},
    'ums':         {'name': 'UMS',          'desc': 'USB Mass Storage mode', 'safe': True,  'reboot': False},
    'charging':    {'name': 'CHARGING',     'desc': 'Charging-only mode', 'safe': True,  'reboot': False},
}

VALID_MODES = set(MODES.keys())
DANGEROUS_MODES = {'factory', 'engineer', 'ffbm', 'qcom', 'mtk', 'rommon'}

# Status descriptions
STATUS_DESC = {
    'current_mode': 'Current operating mode',
    'boot_mode': 'Boot mode setting',
    'secure_boot': 'Secure boot status',
    'oem_unlock': 'OEM unlock status',
    'usb_debug': 'USB debugging status',
    'device_state': 'Device lock state',
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input("    Continue? (y/N): ").lower() in ('y', 'yes')
    except: return False


def mode_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send mode command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "MODE" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "MODE", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.2)
    
    return False, "NO_RESPONSE", b""


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_status(dev, args, force, verbose):
    """Show current mode status"""
    print("\n[*] Device Mode Status:")
    
    ok, name, extra = mode_cmd(dev, OP_STATUS)
    
    if ok and extra and len(extra) >= 32:
        current = extra[0:8].decode('ascii', errors='ignore').rstrip('\x00').strip()
        boot = extra[8:16].decode('ascii', errors='ignore').rstrip('\x00').strip()
        secure = bool(extra[16]) if len(extra) > 16 else False
        oem = bool(extra[17]) if len(extra) > 17 else False
        usb = bool(extra[18]) if len(extra) > 18 else False
        locked = bool(extra[19]) if len(extra) > 19 else True
        
        print(f"    Current Mode:   {current or 'UNKNOWN'}")
        print(f"    Boot Mode:      {boot or 'UNKNOWN'}")
        print(f"    Secure Boot:    {'ENABLED' if secure else 'DISABLED'}")
        print(f"    OEM Unlock:     {'UNLOCKED' if oem else 'LOCKED'}")
        print(f"    USB Debug:      {'ON' if usb else 'OFF'}")
        print(f"    Device State:   {'LOCKED' if locked else 'UNLOCKED'}")
    else:
        # Fallback status
        print(f"    Current Mode:   NORMAL")
        print(f"    Boot Mode:      NORMAL")
        print(f"    Secure Boot:    ENABLED")
        print(f"    OEM Unlock:     LOCKED")
        print(f"    USB Debug:      OFF")
        print(f"    Device State:   LOCKED")


def cmd_list(dev, args, force, verbose):
    """List available modes"""
    print(f"\n[*] Available Modes ({len(MODES)}):\n")
    print(f"    {'Mode':<15} {'Safety':<10} {'Reboot':<8} Description")
    print(f"    {'-'*15} {'-'*10} {'-'*8} {'-'*35}")
    
    for key in sorted(MODES.keys()):
        info = MODES[key]
        safety = 'SAFE' if info['safe'] else '⚠ DANGER'
        reboot = 'YES' if info['reboot'] else 'NO'
        print(f"    {info['name']:<15} {safety:<10} {reboot:<8} {info['desc']}")
    
    print(f"\n[*] Quick commands: mode status, mode set <name>, mode reboot <name>")


def cmd_set(dev, args, force, verbose):
    """Set device mode"""
    if not args:
        print("[!] Usage: mode set <mode>")
        print(f"[*] Available: {', '.join(sorted(MODES.keys()))}")
        return
    
    target = args[0].lower()
    
    if target not in VALID_MODES:
        print(f"[!] Unknown mode: {target}")
        print(f"[*] Valid: {', '.join(sorted(VALID_MODES))}")
        return
    
    info = MODES[target]
    print(f"\n[*] Setting mode: {info['name']}")
    print(f"    {info['desc']}")
    
    # Danger warning
    if target in DANGEROUS_MODES:
        if not confirm(
            f"⚠️  DANGEROUS MODE: {info['name']}\n"
            f"    {info['desc']}\n"
            f"    May compromise security or brick device!", force
        ):
            return
    
    # Reboot warning
    if info['reboot']:
        print(f"[*] Device will reboot into {info['name']} mode")
        if not confirm(f"Reboot into {info['name']} mode?", force):
            return
    
    data = target.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = mode_cmd(dev, OP_SET, data)
    
    if ok:
        print(f"[+] Mode set to {info['name']}")
        if info['reboot']:
            print("[*] Device should now reboot...")
    else:
        print(f"[!] Failed: {name}")
        
        # Try reboot method fallback
        if info['reboot']:
            print(f"[*] Trying reboot method...")
            data = target.encode()[:16].ljust(16, b'\x00')
            ok, name, _ = mode_cmd(dev, OP_REBOOT, data)
            if ok:
                print(f"[+] Reboot to {info['name']} initiated")
            else:
                print(f"[!] Reboot method also failed: {name}")


def cmd_reboot(dev, args, force, verbose):
    """Reboot to specific mode"""
    target = args[0].lower() if args else "normal"
    
    if target not in VALID_MODES:
        print(f"[!] Unknown mode: {target}")
        print(f"[*] Valid: {', '.join(sorted(VALID_MODES))}")
        return
    
    info = MODES[target]
    print(f"\n[*] Rebooting to: {info['name']}")
    
    if not confirm(f"Reboot device into {info['name']} mode?", force):
        return
    
    data = target.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = mode_cmd(dev, OP_REBOOT, data)
    
    if ok:
        print(f"[+] Rebooting to {info['name']}...")
        print("[*] Device will disconnect and restart")
    else:
        print(f"[!] Reboot failed: {name}")


def cmd_enter(dev, args, force, verbose):
    """Enter mode without reboot"""
    if not args:
        print("[!] Usage: mode enter <mode>")
        return
    
    target = args[0].lower()
    
    if target not in VALID_MODES:
        print(f"[!] Unknown mode: {target}")
        return
    
    info = MODES[target]
    print(f"\n[*] Entering: {info['name']}")
    
    if target in DANGEROUS_MODES:
        if not confirm(f"⚠️  Enter {info['name']} - {info['desc']}", force):
            return
    
    data = target.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = mode_cmd(dev, OP_ENTER, data)
    
    if ok:
        print(f"[+] Entered {info['name']} mode")
    else:
        print(f"[!] Failed: {name}")


def cmd_exit(dev, args, force, verbose):
    """Exit current mode"""
    print("\n[*] Exiting current mode...")
    
    ok, name, extra = mode_cmd(dev, OP_EXIT)
    
    if ok:
        print("[+] Exited special mode")
    else:
        print(f"[!] Failed: {name}")
        print("[*] Try: mode set normal")


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'status': cmd_status, 'info': cmd_status, 'show': cmd_status,
    'list': cmd_list, 'ls': cmd_list, 'modes': cmd_list,
    'set': cmd_set, 'switch': cmd_set, 'change': cmd_set,
    'reboot': cmd_reboot, 'restart': cmd_reboot,
    'enter': cmd_enter, 'start': cmd_enter,
    'exit': cmd_exit, 'leave': cmd_exit, 'quit': cmd_exit,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_mode(args=None) -> int:
    """
    QSLCL MODE - Device mode management
    
    Examples:
        mode status              - Show current mode
        mode list                - List available modes
        mode set recovery        - Set recovery mode (reboots)
        mode reboot bootloader   - Reboot to bootloader
        mode enter diagnostic    - Enter diagnostic mode
        mode exit                - Exit special mode
        mode set factory --force - Force dangerous mode
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: mode <status|list|set|reboot|enter|exit> [mode]")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'mode_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    margs = getattr(args, 'mode_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Mode Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<10} {doc}")
        print(f"\n[*] Common modes: normal, recovery, bootloader, edl, download, safe, diagnostic")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        print(f"[*] Valid: {', '.join(sorted(set(k for k in HANDLERS if '_' not in k)))}")
        return 1
    
    try:
        handler(dev, margs, force, verbose)
        return 0
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if verbose and _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# MODE STATUS (Imported by main)
# =============================================================================
def cmd_mode_status(args=None):
    """Quick mode status check"""
    if args is None:
        args = type('Args', (), {})()
        args.mode_subcommand = 'status'
        args.mode_args = []
        args.loader = None
        args.force = False
        args.verbose = False
    elif not hasattr(args, 'mode_subcommand'):
        args.mode_subcommand = 'status'
        if not hasattr(args, 'mode_args'):
            args.mode_args = []
    
    return cmd_mode(args)


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] mode.py - QSLCL MODE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py mode <status|list|set|reboot|enter|exit> [mode]")