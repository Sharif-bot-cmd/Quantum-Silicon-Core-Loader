#!/usr/bin/env python3
"""
oem.py - QSLCL OEM Command Module v2.1 (CLEANED)
OEM operations: bootloader unlock/lock, warranty, secure boot, provisioning
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
        load_partitions,
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
            load_partitions,
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
READ_TIMEOUT = 5.0
MAX_RETRIES = 3

# Opcodes
OP_UNLOCK = 0x10
OP_LOCK = 0x11
OP_WARRANTY = 0x20
OP_SECUREBOOT = 0x30
OP_PROVISION = 0x40
OP_CUSTOMIZE = 0x50
OP_INFO = 0x60
OP_CONFIG = 0x70
OP_KEYS = 0x80
OP_DEBUG = 0x90
OP_PANIC = 0x95   

QUERY_FLAG = 0xFF

# Known bootloader lock regions
LOCK_REGIONS = [
    (0x00021000, "Qualcomm PBL Lock"),
    (0x0006F000, "Samsung Bootloader Lock"),
    (0x00070000, "Generic Bootloader Lock"),
    (0x00080000, "MediaTek Preloader Lock"),
    (0x00100000, "Common Bootloader Area"),
    (0x0F000000, "eMMC Boot Partition Lock"),
]

LOCK_PATTERNS = {
    b'\x00\x00\x00\x00': 'unlocked',
    b'\x01\x00\x00\x00': 'locked',
    b'\xEE\xEE\xEE\xEE': 'erased',
    b'\xFF\xFF\xFF\xFF': 'default',
    b'LOCK': 'text_locked',
    b'UNLK': 'text_unlocked',
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force:
        print("\n[!] Force mode: skipping confirmation")
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}': ").upper() == req.upper()
    except (EOFError, KeyboardInterrupt):
        return False


def oem_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send OEM command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "OEM" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "OEM", payload, timeout=TIMEOUT)
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


def read_mem(dev, addr: int, size: int) -> Optional[bytes]:
    """Read memory from device"""
    payload = struct.pack("<II", addr, size)
    
    if "READ" in QSLCLCMD_DB:
        resp = qslcl_dispatch(dev, "READ", payload, timeout=READ_TIMEOUT)
    else:
        pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
        dev.write(pkt)
        _, resp = dev.read(timeout=READ_TIMEOUT)
    
    if resp:
        status = decode_runtime_result(resp)
        if status.get("severity") == "SUCCESS":
            return status.get("extra", b"")
    return None


# =============================================================================
# LOCK REGION SCANNING
# =============================================================================
def scan_lock_regions(dev, verbose: bool = False) -> List[Dict]:
    """Scan known memory regions for bootloader lock data"""
    regions = []
    
    if verbose:
        print("\n[*] Scanning bootloader lock regions...")
    
    for addr, desc in LOCK_REGIONS:
        data = read_mem(dev, addr, 16)
        if not data or len(data) < 4:
            continue
        
        found_type = None
        for pattern, ptype in sorted(LOCK_PATTERNS.items(), key=lambda x: -len(x[0])):
            if data[:len(pattern)] == pattern:
                found_type = ptype
                break
        
        if found_type:
            value = struct.unpack("<I", data[:4])[0]
            is_locked = found_type in ('locked', 'text_locked')
            
            regions.append({
                'address': addr,
                'description': desc,
                'type': found_type,
                'value': value,
                'is_locked': is_locked,
                'unlocked_val': 0x00000000,
                'locked_val': 0x00000001,
            })
            
            if verbose:
                status = "LOCKED" if is_locked else "UNLOCKED"
                print(f"    0x{addr:08X}: {desc} [{status}]")
    
    return regions


def get_lock_status(dev, regions: List[Dict]) -> Dict:
    """Determine overall lock status"""
    if not regions:
        return {'status': 'UNKNOWN', 'locked': 0, 'unlocked': 0, 'total': 0}
    
    locked = unlocked = 0
    
    for r in regions:
        data = read_mem(dev, r['address'], 4)
        if data and len(data) >= 4:
            val = struct.unpack("<I", data[:4])[0]
            if val == r['locked_val']:
                locked += 1
                r['is_locked'] = True
            elif val == r['unlocked_val']:
                unlocked += 1
                r['is_locked'] = False
    
    if locked > unlocked:
        status = 'LOCKED'
    elif unlocked > locked:
        status = 'UNLOCKED'
    else:
        status = 'UNKNOWN'
    
    return {'status': status, 'locked': locked, 'unlocked': unlocked, 'total': len(regions)}


def verify_lock_state(dev, regions: List[Dict], expect_unlocked: bool, verbose: bool) -> bool:
    """Verify lock state after operation"""
    if not regions:
        print("[*] No regions to verify - assuming success")
        return True
    
    verified = failed = 0
    
    for r in regions:
        data = read_mem(dev, r['address'], 4)
        if data and len(data) >= 4:
            val = struct.unpack("<I", data[:4])[0]
            expected = r['unlocked_val'] if expect_unlocked else r['locked_val']
            
            if val == expected:
                verified += 1
                if verbose:
                    print(f"    ✓ 0x{r['address']:08X}: {'Unlocked' if expect_unlocked else 'Locked'}")
            else:
                failed += 1
                if verbose:
                    print(f"    ✗ 0x{r['address']:08X}: 0x{val:08X}")
        else:
            failed += 1
    
    total = verified + failed
    return verified / total >= 0.5 if total > 0 else True


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_unlock(dev, args, force, verbose):
    """Unlock bootloader (ERASES ALL DATA)"""
    print(f"\n{'='*50}")
    print(f"  BOOTLOADER UNLOCK - ERASES ALL USER DATA")
    print(f"{'='*50}")
    
    regions = scan_lock_regions(dev, verbose)
    status = get_lock_status(dev, regions)
    
    if regions:
        print(f"\n[+] Found {len(regions)} lock region(s)")
        for r in regions:
            print(f"    0x{r['address']:08X}: {r['description']} [{'LOCKED' if r['is_locked'] else 'UNLOCKED'}]")
    else:
        print("\n[*] No known lock regions found, attempting standard unlock")
    
    print(f"\n[+] Current status: {status['status']}")
    
    if status['status'] == 'UNLOCKED':
        print("[*] Already unlocked!")
        return
    
    # Warnings
    msg = (
        "⚠️  BOOTLOADER UNLOCK:\n\n"
        "  🔴 ALL USER DATA WILL BE ERASED!\n"
        "  🔴 Device warranty WILL BE VOIDED!\n"
        "  🔴 Security protections REDUCED!\n"
        "  🔴 This is typically IRREVERSIBLE!\n\n"
        "  ✅ Ensure FULL BACKUP of all data"
    )
    if not confirm(msg, 'UNLOCK', force):
        print("[*] Cancelled")
        return
    
    if not confirm("FINAL: All data will be PERMANENTLY ERASED!", 'ERASE', force):
        print("[*] Cancelled")
        return
    
    print("\n[*] Executing unlock...")
    
    payload = struct.pack("<I", 1)  # unlock flag
    
    if regions:
        payload += struct.pack("<B", min(len(regions), 255))
        for r in regions[:255]:
            payload += struct.pack("<II", r['address'], r['unlocked_val'])
    else:
        payload += struct.pack("<B", 0)
    
    ok, name, extra = oem_cmd(dev, OP_UNLOCK, payload)
    
    if ok:
        print("[+] Unlock command accepted")
        time.sleep(1.0)
        
        print("\n[*] Verifying...")
        if verify_lock_state(dev, regions, True, verbose):
            print("\n[+] ✓ Bootloader unlocked!")
            print("[+] Device will erase data and reboot...")
        else:
            print("\n[!] Verification incomplete - device may need manual reboot")
    else:
        print(f"[!] Unlock failed: {name}")


def cmd_lock(dev, args, force, verbose):
    """Lock bootloader"""
    print(f"\n{'='*50}")
    print(f"  BOOTLOADER LOCK")
    print(f"{'='*50}")
    
    regions = scan_lock_regions(dev, verbose)
    status = get_lock_status(dev, regions)
    
    print(f"\n[+] Current status: {status['status']}")
    
    if status['status'] == 'LOCKED':
        print("[*] Already locked!")
        return
    
    msg = (
        "⚠️  BOOTLOADER LOCK:\n\n"
        "  🔴 Only signed firmware will boot\n"
        "  🔴 Custom ROMs may be BLOCKED\n"
        "  🔴 Root access may be LOST\n"
        "  🔴 May require factory reset"
    )
    if not confirm(msg, 'LOCK', force):
        print("[*] Cancelled")
        return
    
    print("\n[*] Executing lock...")
    
    payload = struct.pack("<I", 0)  # lock flag
    
    if regions:
        payload += struct.pack("<B", min(len(regions), 255))
        for r in regions[:255]:
            payload += struct.pack("<II", r['address'], r['locked_val'])
    else:
        payload += struct.pack("<B", 0)
    
    ok, name, extra = oem_cmd(dev, OP_LOCK, payload)
    
    if ok:
        print("[+] Lock command accepted")
        time.sleep(0.5)
        
        print("\n[*] Verifying...")
        if verify_lock_state(dev, regions, False, verbose):
            print("\n[+] ✓ Bootloader locked!")
        else:
            print("\n[!] Verification incomplete")
    else:
        print(f"[!] Lock failed: {name}")


def cmd_warranty(dev, args, force, verbose):
    """Manage warranty bit"""
    if args and args[0].lower() in ('set', 'clear'):
        op = args[0].lower()
        print(f"\n[*] Warranty bit: {op}")
        
        if not confirm("Modifying warranty bit may VOID warranty! This is IRREVERSIBLE on most devices.", 'WARRANTY', force):
            return
        
        payload = struct.pack("<I", 1 if op == 'set' else 0)
        ok, name, _ = oem_cmd(dev, OP_WARRANTY, payload)
        
        if ok:
            print(f"[+] Warranty bit {op} successfully")
        else:
            print(f"[!] Failed: {name}")
    else:
        print("\n[*] Querying warranty status...")
        payload = struct.pack("<I", QUERY_FLAG)
        ok, name, extra = oem_cmd(dev, OP_WARRANTY, payload)
        
        if ok and len(extra) >= 4:
            val = struct.unpack("<I", extra[:4])[0]
            status = "SET (Warranty Void)" if val else "CLEAR (Warranty Valid)"
            print(f"[+] Warranty: {status}")
        else:
            print(f"[!] Query failed: {name}")


def cmd_secureboot(dev, args, force, verbose):
    """Manage secure boot"""
    if args and args[0].lower() in ('enable', 'disable'):
        op = args[0].lower()
        print(f"\n[*] Secure boot: {op}")
        
        msg = "Disabling secure boot reduces security. Enabling may block custom firmware."
        if not confirm(msg, 'SECURE', force):
            return
        
        payload = struct.pack("<I", 1 if op == 'enable' else 0)
        ok, name, _ = oem_cmd(dev, OP_SECUREBOOT, payload)
        
        if ok:
            print(f"[+] Secure boot {op}d")
        else:
            print(f"[!] Failed: {name}")
    else:
        print("\n[*] Querying secure boot status...")
        payload = struct.pack("<I", QUERY_FLAG)
        ok, name, extra = oem_cmd(dev, OP_SECUREBOOT, payload)
        
        if ok and len(extra) >= 4:
            val = struct.unpack("<I", extra[:4])[0]
            print(f"[+] Secure boot: {'ENABLED' if val else 'DISABLED'}")
        else:
            print(f"[!] Query failed: {name}")


def cmd_provision(dev, args, force, verbose):
    """Device provisioning"""
    ptype = args[0].upper() if args else "DEFAULT"
    print(f"\n[*] Provisioning: {ptype}")
    
    if ptype in ("FACTORY", "CLEAN"):
        if not confirm("FACTORY PROVISIONING will RESET device to factory state. ALL data will be LOST!", 'PROVISION', force):
            return
    
    payload = ptype.encode()[:16].ljust(16, b'\x00')
    ok, name, _ = oem_cmd(dev, OP_PROVISION, payload)
    
    if ok:
        print("[+] Provisioning complete")
    else:
        print(f"[!] Failed: {name}")


def cmd_customize(dev, args, force, verbose):
    """Device customization"""
    if not args:
        print("[!] Specify customization parameters")
        return
    
    print(f"\n[*] Customization: {', '.join(args)}")
    
    payload = b""
    for arg in args[:8]:
        payload += arg.encode()[:32].ljust(32, b'\x00')
    
    ok, name, _ = oem_cmd(dev, OP_CUSTOMIZE, payload)
    
    if ok:
        print("[+] Customization complete")
    else:
        print(f"[!] Failed: {name}")


def cmd_info(dev, args, force, verbose):
    """Device information"""
    print("\n[*] Querying OEM information...")
    
    ok, name, extra = oem_cmd(dev, OP_INFO)
    
    if ok and extra and len(extra) >= 144:
        model = extra[0:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
        hw = extra[32:48].decode('ascii', errors='ignore').rstrip('\x00').strip()
        bl = extra[48:80].decode('ascii', errors='ignore').rstrip('\x00').strip()
        bb = extra[80:112].decode('ascii', errors='ignore').rstrip('\x00').strip()
        sn = extra[112:144].decode('ascii', errors='ignore').rstrip('\x00').strip()
        
        print(f"    Model:              {model or '?'}")
        print(f"    Hardware Revision:  {hw or '?'}")
        print(f"    Bootloader Version: {bl or '?'}")
        print(f"    Baseband Version:   {bb or '?'}")
        print(f"    Serial Number:      {sn or '?'}")
        
        if len(extra) >= 148:
            features = struct.unpack("<I", extra[144:148])[0]
            feat_map = {0x01:'BOOTLOADER_UNLOCK', 0x02:'SECURE_BOOT', 0x04:'CUSTOMIZATION',
                       0x08:'DEBUG_ACCESS', 0x10:'FACTORY_PROVISIONED', 0x20:'WARRANTY_BIT'}
            active = [v for k, v in feat_map.items() if features & k]
            print(f"    Features:           {', '.join(active) if active else 'None'}")
    else:
        print(f"[!] Info query failed: {name}")
        print(f"    Model: Unknown | HW: Unknown | BL: Unknown")


def cmd_config(dev, args, force, verbose):
    """Configuration management"""
    if not args:
        print("[!] Usage: oem config <get|set|list> [key] [value]")
        return
    
    op = args[0].lower()
    
    if op == 'get' and len(args) > 1:
        key = args[1]
        print(f"\n[*] Getting: {key}")
        
        payload = struct.pack("<B", 0x01) + key.encode()[:32].ljust(32, b'\x00')
        ok, name, extra = oem_cmd(dev, OP_CONFIG, payload)
        
        if ok and extra:
            value = extra.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"[+] {key} = {value}")
        else:
            print(f"[!] Failed: {name}")
    
    elif op == 'set' and len(args) > 2:
        key, value = args[1], args[2]
        print(f"\n[*] Setting: {key} = {value}")
        
        if not force:
            try:
                if input("    Confirm? (y/N): ").lower() != 'y':
                    print("[*] Cancelled"); return
            except: pass
        
        payload = struct.pack("<B", 0x02)
        payload += key.encode()[:32].ljust(32, b'\x00')
        payload += value.encode()[:32].ljust(32, b'\x00')
        
        ok, name, _ = oem_cmd(dev, OP_CONFIG, payload)
        print(f"[{'✓' if ok else '✗'}] {'Set' if ok else f'Failed: {name}'}")
    
    elif op == 'list':
        print("\n[*] Configuration:")
        ok, name, extra = oem_cmd(dev, OP_CONFIG, struct.pack("<B", 0x03))
        
        if ok and extra:
            for i in range(0, min(len(extra), 256), 32):
                chunk = extra[i:i+32]
                asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"    {i:04x}: {chunk.hex():<64} |{asc}|")
        else:
            print(f"[!] Failed: {name}")
    
    else:
        print(f"[!] Unknown: {op}")


def cmd_keys(dev, args, force, verbose):
    """Key management"""
    op = args[0].upper() if args else "LIST"
    print(f"\n[*] Keys: {op}")
    
    payload = op.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = oem_cmd(dev, OP_KEYS, payload)
    
    if ok:
        print("[+] Key operation complete")
        if verbose and extra:
            print(f"    Data: {extra[:256].hex()}")
    else:
        print(f"[!] Failed: {name}")


def cmd_debug(dev, args, force, verbose):
    """Debug operations"""
    op = args[0].upper() if args else "STATUS"
    print(f"\n[*] Debug: {op}")
    
    payload = op.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = oem_cmd(dev, OP_DEBUG, payload)
    
    if ok:
        print("[+] Debug operation complete")
        if verbose and extra:
            print(f"    Output: {extra.decode('ascii', errors='replace')[:500]}")
    else:
        print(f"[!] Failed: {name}")

def cmd_panic(dev, args, force, verbose):
    """
    Force system panic/crash (low-level hardware reset)
    
    This triggers a hardware-level panic/crash, similar to:
    - Fastboot: fastboot oem panic
    - Linux: echo c > /proc/sysrq-trigger
    - Hardware: watchdog timeout
    
    Panic modes:
        normal   - Standard kernel panic (if available)
        watchdog - Force watchdog timeout
        hard     - Hardware reset (write to reset register)
        soft     - Software crash (division by zero)
        hang     - Infinite loop (requires power cycle)
    """
    
    # Parse panic mode
    mode = args[0].lower() if args else "normal"
    
    # Validate mode
    valid_modes = ['normal', 'watchdog', 'hard', 'soft', 'hang', 'debug']
    if mode not in valid_modes:
        print(f"[!] Invalid mode: {mode}")
        print(f"[*] Valid modes: {', '.join(valid_modes)}")
        return
    
    print(f"\n{'='*50}")
    print(f"  PANIC: {mode.upper()} MODE")
    print(f"{'='*50}")
    
    # Warning for data loss
    msg = (
        f"⚠️  PANIC ({mode.upper()}):\n\n"
        f"  🔴 Device will CRASH/RESET immediately!\n"
        f"  🔴 UNSAVED DATA WILL BE LOST!\n"
        f"  🔴 May require power cycle to recover\n"
        f"  🔴 Debug registers may be cleared\n\n"
        f"  ✅ Only use for crash testing/debugging"
    )
    
    if not confirm(msg, 'PANIC', force):
        print("[*] Cancelled")
        return
    
    print(f"\n[*] Triggering {mode} panic...")
    
    # Build payload: mode (1 byte) + flags (1 byte)
    mode_codes = {
        'normal': 0x00,
        'watchdog': 0x01,
        'hard': 0x02,
        'soft': 0x03,
        'hang': 0x04,
        'debug': 0xFF
    }
    
    flags = 0x00
    if force:
        flags |= 0x01  # Force flag
    
    payload = struct.pack("<BB", mode_codes.get(mode, 0x00), flags)
    
    # Optional: Add custom panic message
    if len(args) > 1 and mode != 'debug':
        msg_bytes = ' '.join(args[1:]).encode()[:64]
        payload += msg_bytes
    
    # Send panic command
    ok, name, extra = oem_cmd(dev, OP_PANIC, payload)  # We'll define OP_PANIC
    
    # Note: If panic works, we won't get here
    if ok:
        print("[+] Panic command sent - device should crash...")
        print("[*] If you see this, panic may have failed")
    else:
        print(f"[!] Panic failed: {name}")
        
        # Fallback attempts for when OEM command isn't supported
        if verbose:
            print("[*] Attempting fallback panic methods...")
            
            # Fallback 1: Write to known reset registers
            reset_regs = [0x20E00000, 0x10000000, 0x60005000, 0x40000000]
            for reg in reset_regs:
                try:
                    # Try to write to reset register
                    from qslcl import qslcl_dispatch
                    payload = struct.pack("<III", reg, 4, 0xDEADBEEF)
                    qslcl_dispatch(dev, "WRITE", payload, timeout=0.5)
                    print(f"[*] Attempted reset via 0x{reg:08X}")
                except:
                    pass
            
            # Fallback 2: Division by zero (if code execution possible)
            # This would need device-side support
            print("[*] No fallback panic method succeeded")

# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'unlock': cmd_unlock, 'unlock-bootloader': cmd_unlock,
    'lock': cmd_lock, 'lock-bootloader': cmd_lock,
    'warranty': cmd_warranty, 'warranty-bit': cmd_warranty,
    'secureboot': cmd_secureboot, 'secure-boot': cmd_secureboot,
    'provision': cmd_provision, 'provisioning': cmd_provision,
    'customize': cmd_customize, 'customization': cmd_customize,
    'info': cmd_info, 'device-info': cmd_info,
    'config': cmd_config, 'configuration': cmd_config,
    'keys': cmd_keys, 'key': cmd_keys, 'signing-keys': cmd_keys,
    'debug': cmd_debug, 'debugging': cmd_debug,
    'panic': cmd_panic, 'crash': cmd_panic,  
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_oem(args=None) -> int:
    """
    QSLCL OEM - Bootloader unlock/lock and device management
    
    Examples:
        oem unlock                    - Unlock bootloader (ERASES DATA!)
        oem lock                      - Lock bootloader
        oem warranty                  - Query warranty status
        oem secureboot enable         - Enable secure boot
        oem info                      - Device information
        oem config get bootloader     - Get config value
        oem provision FACTORY         - Factory provision
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: oem <unlock|lock|warranty|secureboot|info|config|provision|customize|keys|debug>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'oem_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    oargs = getattr(args, 'oem_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] OEM Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<15} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    try:
        handler(dev, oargs, force, verbose)
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
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] oem.py - QSLCL OEM Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py oem <subcommand> [args]")