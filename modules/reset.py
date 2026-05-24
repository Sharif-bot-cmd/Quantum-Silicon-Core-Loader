#!/usr/bin/env python3
"""
reset.py - QSLCL RESET Command Module v2.2 (CLEANED FOR LOW-LEVEL MODES)
Simple device reset/reboot for DFU, EDL, BROM, and low-level modes.

IN LOW-LEVEL MODES (DFU/EDL/BROM):
- Only "exit" or "reboot" actually works
- Recovery/bootloader/etc don't exist at this level
- You're in the bare minimum firmware - just enough to accept commands
"""

import sys
import struct
import time
from typing import Tuple

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
# CONSTANTS - Only what works in low-level modes
# =============================================================================

# Opcodes for reset in low-level firmware
OP_EXIT = 0x01      # Exit current mode, reboot to normal
OP_REBOOT = 0x02    # Reboot device
OP_RESET = 0x03     # Hard reset

# Valid reset types for low-level modes
RESET_TYPES = {
    'exit': {
        'name': 'EXIT',
        'opcode': OP_EXIT,
        'desc': 'Exit low-level mode, reboot to normal OS',
        'confirm': None
    },
    'reboot': {
        'name': 'REBOOT',
        'opcode': OP_REBOOT,
        'desc': 'Reboot device',
        'confirm': None
    },
    'reset': {
        'name': 'RESET',
        'opcode': OP_RESET,
        'desc': 'Hard reset device',
        'confirm': 'RESET'
    },
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def confirm(msg: str, req: str, force: bool) -> bool:
    """Simple confirmation for dangerous operations"""
    if force:
        return True
    
    print(f"\n[!] {msg}")
    try:
        user_input = input(f"    Type '{req}' to confirm: ")
        return user_input == req
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Cancelled")
        return False


def send_reset_command(dev, opcode: int) -> Tuple[bool, str]:
    """
    Send reset command to device in low-level mode.
    Returns (success, message)
    """
    payload = struct.pack("<B", opcode)
    
    try:
        if "RESET" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "RESET", payload, timeout=5.0)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=5.0)
        
        if resp:
            status = decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return True, "Command accepted"
            else:
                return False, status.get("name", "Unknown error")
                
    except Exception as e:
        # In low-level modes, device often resets before responding
        # This is NORMAL behavior, not an error
        if "pipe" in str(e) or "disconnected" in str(e) or "timeout" in str(e):
            return True, "Device reset (expected)"
        return False, str(e)
    
    return False, "No response"


def wait_for_device_reconnect(timeout: int = 30) -> bool:
    """
    Wait for device to reappear after reset.
    Returns True if device detected again.
    """
    print(f"\n[*] Waiting for device to reappear ({timeout}s)...")
    start = time.time()
    
    while time.time() - start < timeout:
        elapsed = int(time.time() - start)
        remaining = timeout - elapsed
        
        # Simple progress indicator
        print(f"\r    [{remaining:2d}s remaining]", end="", flush=True)
        
        try:
            # Quick scan for any device
            devs = scan_all()
            if devs:
                print(f"\n[+] Device detected after {elapsed}s!")
                return True
        except:
            pass
        
        time.sleep(1)
    
    print(f"\n[!] Timeout: Device not detected")
    print(f"[*] You may need to reconnect manually")
    return False


# =============================================================================
# MAIN RESET COMMAND
# =============================================================================

def cmd_reset(args=None) -> int:
    """
    QSLCL RESET - Reset/exit low-level mode (DFU/EDL/BROM)
    
    In low-level modes (DFU, EDL, BROM), you're in bare minimum firmware.
    These modes only accept basic commands - there's no "recovery" or 
    "bootloader" to boot into because you're ALREADY at the lowest level.
    
    What actually works:
        reset exit    - Exit DFU/EDL/BROM, boot to normal OS
        reset reboot  - Reboot device (may return to same mode)
        reset reset   - Hard reset (confirmation required)
    
    Examples:
        python qslcl.py reset exit
        python qslcl.py reset reboot
        python qslcl.py reset reset --force
    """
    
    # Parse arguments
    if args is None:
        print("[!] No reset type specified")
        print("[*] Usage: reset <exit|reboot|reset> [options]")
        print("\nOptions:")
        print("    --force           Skip confirmation")
        print("    --loader <file>   Load qslcl.bin first")
        return 1
    
    # Get subcommand
    sub = (getattr(args, 'reset_subcommand', '') or 
           getattr(args, 'subcmd', '')).lower().strip()
    
    # Extract args list (for backward compatibility with different arg formats)
    rargs = getattr(args, 'reset_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force_reset', False) or getattr(args, 'force', False)
    
    # Show help if no subcommand
    if not sub or sub in ('help', '-h', '--help'):
        print("\n[*] QSLCL RESET - Exit low-level modes")
        print("\n    reset exit      - Exit DFU/EDL/BROM, boot to normal OS")
        print("    reset reboot    - Reboot device")
        print("    reset reset     - Hard reset (use --force to skip confirm)")
        print("\n    --force         - Skip confirmation for reset")
        print("    --loader <file> - Load qslcl.bin before reset")
        return 0
    
    # Connect to device
    devs = scan_all()
    if not devs:
        print("[!] No device detected")
        print("[*] Make sure device is in DFU/EDL/BROM mode")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    print(f"[*] Mode: {'DFU' if dev.vid == 0x05AC else 'Low-level'}")
    
    # Loader if specified
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Handle each reset type
    if sub == 'exit':
        print("\n[*] Exiting low-level mode...")
        print("[*] Device will reboot to normal OS")
        
        success, msg = send_reset_command(dev, OP_EXIT)
        
        if success:
            print(f"[+] {msg}")
            wait_for_device_reconnect(30)
            print("[+] Done. Device should now be in normal mode.")
        else:
            print(f"[!] Failed: {msg}")
            return 1
    
    elif sub == 'reboot':
        print("\n[*] Rebooting device...")
        
        success, msg = send_reset_command(dev, OP_REBOOT)
        
        if success:
            print(f"[+] {msg}")
            wait_for_device_reconnect(30)
        else:
            print(f"[!] Failed: {msg}")
            return 1
    
    elif sub == 'reset':
        # Hard reset requires confirmation
        if not force:
            print("\n[!] HARD RESET will force reboot the device")
            if not confirm("This may interrupt any ongoing operations", 'RESET', force):
                return 0
        
        print("\n[*] Hard resetting device...")
        
        success, msg = send_reset_command(dev, OP_RESET)
        
        if success:
            print(f"[+] {msg}")
            wait_for_device_reconnect(30)
        else:
            # Even if command fails, device may still reset
            print(f"[*] Device may still reset (normal)")
            return 0
    
    else:
        print(f"[!] Unknown reset type: {sub}")
        print("[*] Valid: exit, reboot, reset")
        return 1
    
    return 0


# =============================================================================
# MODULE INFO
# =============================================================================

if __name__ == "__main__":
    print("[*] reset.py - QSLCL RESET Command Module v2.2")
    print("[*] For low-level modes (DFU/EDL/BROM)")
    print("[*] Imported by qslcl.py")