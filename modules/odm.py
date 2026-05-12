#!/usr/bin/env python3
"""
odm.py - QSLCL ODM Command Module v2.1 (CLEANED)
ODM operations: provisioning, testing, calibration, customization
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
OP_INFO = 0x01
OP_PROVISION = 0x10
OP_CUSTOMIZE = 0x20
OP_TEST = 0x30
OP_CALIBRATE = 0x40
OP_FEATURE = 0x50
OP_REGION = 0x60
OP_SECURITY = 0x70
OP_FIRMWARE_INFO = 0x75
OP_FIRMWARE_UPDATE = 0x76
OP_FIRMWARE_DATA = 0x77
OP_MANUFACTURING = 0x80
OP_SUPPLYCHAIN = 0x85
OP_UNLOCK = 0x90
OP_LOCK = 0xA0
OP_RESET = 0xB0

VALID_CUSTOMIZATIONS = ['branding', 'bootlogo', 'bootanimation', 'sounds', 'themes']
VALID_TESTS = ['QUICK', 'FULL', 'EXTENDED']
VALID_HARDWARE = ['display', 'touch', 'audio', 'sensors', 'camera', 'battery']
VALID_SECURITY = ['enable', 'disable', 'lockdown', 'unlock', 'status']
VALID_REGIONS = ['NA', 'EU', 'ASIA', 'CN', 'JP', 'KR', 'IN', 'LATAM', 'MEA', 'GLOBAL']


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input("    Continue? (y/N): ").lower() in ('y', 'yes')
    except: return False


def odm_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send ODM command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "ODM" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "ODM", payload, timeout=TIMEOUT)
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


def result(ok: bool, name: str, op: str, extra: bytes = b"", verbose: bool = False):
    """Print standardized result"""
    if ok:
        print(f"[+] {op} complete")
        if verbose and extra:
            print(f"    Data: {extra[:64].hex()}{'...' if len(extra)>64 else ''}")
    else:
        print(f"[!] {op} failed: {name}")


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_info(dev, args, force, verbose):
    """Device information"""
    print("\n[*] ODM Device Info:")
    
    ok, name, extra = odm_cmd(dev, OP_INFO)
    
    if ok and extra and len(extra) >= 128:
        fields = {
            'Manufacturer': extra[0:32],
            'Model': extra[32:64],
            'SKU': extra[64:80],
            'Serial': extra[80:96],
            'HW Revision': extra[96:112],
            'Production Date': extra[112:128],
        }
        for key, val in fields.items():
            decoded = val.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"    {key:<18} {decoded or '?'}")
    else:
        print(f"    Manufacturer: Unknown | Model: Unknown | SKU: Unknown")
        print(f"    Serial: Unknown | HW: Unknown | Date: Unknown")


def cmd_provision(dev, args, force, verbose):
    """Device provisioning"""
    print(f"\n{'='*45}")
    print(f"  ODM DEVICE PROVISIONING")
    print(f"{'='*45}")
    
    if not confirm("Provisioning configures device for manufacturing.\nSets manufacturing flags and base parameters.", force):
        return
    
    steps = [
        "Init provisioning", "Set manufacturing flags", "Configure base params",
        "Install ODM certificates", "Setup secure elements", "Finalize provisioning"
    ]
    
    all_ok = True
    for i, step in enumerate(steps):
        print(f"    Step {i+1}/{len(steps)}: {step}...", end=" ", flush=True)
        data = step.encode()[:32].ljust(32, b'\x00')
        ok, name, _ = odm_cmd(dev, OP_PROVISION, data)
        print("OK" if ok else f"FAIL ({name})")
        if not ok:
            all_ok = False
            if not force:
                print(f"[!] Aborted at step {i+1}")
                return
        time.sleep(0.2)
    
    print(f"\n[{' ✓' if all_ok else ' !'}] Provisioning {'complete' if all_ok else 'completed with errors'}")


def cmd_customize(dev, args, force, verbose):
    """Apply customization"""
    if not args:
        print(f"[!] Usage: odm customize <type> <value|file>")
        print(f"[*] Types: {', '.join(VALID_CUSTOMIZATIONS)}")
        return
    
    ctype = args[0].lower()
    if ctype not in VALID_CUSTOMIZATIONS:
        print(f"[!] Invalid type: {ctype}")
        return
    
    value = args[1] if len(args) > 1 else ""
    print(f"\n[*] Customize: {ctype} = {value[:50]}{'...' if len(value)>50 else ''}")
    
    if not confirm(f"Modify device {ctype}. May affect boot behavior.", force):
        return
    
    data = ctype.encode()[:16].ljust(16, b'\x00')
    
    if value and os.path.isfile(value):
        try:
            sz = os.path.getsize(value)
            if sz > 10*1024*1024:
                print(f"[!] File too large: {sz} bytes (max 10MB)")
                return
            with open(value, 'rb') as f:
                data += struct.pack("<I", len(f.read())) + f.read()
        except Exception as e:
            print(f"[!] File error: {e}")
            return
    else:
        data += value.encode()[:64].ljust(64, b'\x00')
    
    ok, name, extra = odm_cmd(dev, OP_CUSTOMIZE, data)
    result(ok, name, f"Customize {ctype}", extra, verbose)


def cmd_test(dev, args, force, verbose):
    """Run manufacturing tests"""
    ttype = args[0].upper() if args else "QUICK"
    if ttype not in VALID_TESTS:
        print(f"[!] Invalid: {ttype}. Use: {', '.join(VALID_TESTS)}")
        return
    
    suites = {
        "QUICK": [("Connectivity", 0.3), ("Memory", 0.5), ("CPU", 0.3), ("Storage", 0.5)],
        "FULL": [("Hardware diag", 1.0), ("Sensors", 1.0), ("Radio", 1.5), ("Display", 0.5),
                 ("Audio", 1.0), ("Battery", 1.0), ("Camera", 0.5)],
        "EXTENDED": [("Burn-in", 3.0), ("Memory stress", 2.0), ("Thermal", 2.0),
                     ("Reliability", 3.0), ("Environmental", 2.0)],
    }
    
    tests = suites.get(ttype, suites["QUICK"])
    duration = sum(d for _, d in tests)
    
    print(f"\n{'='*45}")
    print(f"  ODM {ttype} TEST SUITE ({len(tests)} tests, ~{duration:.0f}s)")
    print(f"{'='*45}")
    
    if not confirm(f"Run {ttype} tests. Device may be unresponsive.", force):
        return
    
    passed = failed = skipped = 0
    for test_name, delay in tests:
        print(f"    [{test_name:<30}] ", end="", flush=True)
        
        data = ttype.encode()[:8].ljust(8, b'\x00') + test_name.encode()[:32].ljust(32, b'\x00')
        ok, name, extra = odm_cmd(dev, OP_TEST, data)
        time.sleep(max(0.1, delay - 0.3))
        
        if ok:
            print("PASS"); passed += 1
        elif name in ("SKIP", "NOT_SUPPORTED"):
            print("SKIP"); skipped += 1
        else:
            print(f"FAIL ({name})"); failed += 1
            if verbose and extra:
                print(f"        {extra[:64].hex()}")
    
    total = passed + failed + skipped
    print(f"\n[+] Results: {passed}/{total} passed, {failed} failed", end='')
    if skipped: print(f", {skipped} skipped", end='')
    print()


def cmd_calibrate(dev, args, force, verbose):
    """Calibrate hardware"""
    if not args:
        print(f"[!] Usage: odm calibrate <hardware>")
        print(f"[*] Available: {', '.join(VALID_HARDWARE)}")
        return
    
    hw = args[0].lower()
    if hw not in VALID_HARDWARE:
        print(f"[!] Invalid: {hw}")
        return
    
    print(f"\n[*] Calibrating: {hw}")
    
    if not confirm(f"{hw.capitalize()} calibration requires proper equipment.\nIncorrect calibration may cause malfunction.", force):
        return
    
    data = hw.encode()[:16].ljust(16, b'\x00')
    for param in args[1:4]:
        try:
            if '.' in param: data += struct.pack("<f", float(param))
            else: data += struct.pack("<I", int(param, 0))
        except ValueError:
            data += param.encode()[:16].ljust(16, b'\x00')
    
    ok, name, extra = odm_cmd(dev, OP_CALIBRATE, data)
    result(ok, name, f"Calibrate {hw}", extra, verbose)


def cmd_feature(dev, args, force, verbose):
    """Toggle features"""
    if not args:
        print("[!] Usage: odm feature <name> [ENABLE|DISABLE|TOGGLE]")
        return
    
    feature = args[0].upper()
    action = args[1].upper() if len(args) > 1 else "TOGGLE"
    
    if action not in ('ENABLE', 'DISABLE', 'TOGGLE'):
        print(f"[!] Invalid action: {action}")
        return
    
    print(f"\n[*] Feature: {feature} -> {action}")
    
    if not confirm(f"{action} feature '{feature}'.", force):
        return
    
    data = feature.encode()[:16].ljust(16, b'\x00') + action.encode()[:8].ljust(8, b'\x00')
    ok, name, extra = odm_cmd(dev, OP_FEATURE, data)
    result(ok, name, f"Feature {feature}", extra, verbose)


def cmd_region(dev, args, force, verbose):
    """Region configuration"""
    if not args:
        print("[!] Usage: odm region <list|info|set> [region]")
        return
    
    op = args[0].lower()
    
    if op == "list":
        print(f"\n[*] Available Regions:")
        for i in range(0, len(VALID_REGIONS), 5):
            print(f"    {', '.join(VALID_REGIONS[i:i+5])}")
        return
    
    elif op == "info":
        print("\n[*] Current region:")
        data = b"GET".ljust(16, b'\x00')
        ok, name, extra = odm_cmd(dev, OP_REGION, data)
        if ok and extra:
            region = extra.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"[+] {region}")
        else:
            result(ok, name, "Region query", extra, verbose)
    
    elif op == "set" and len(args) > 1:
        region = args[1].upper()
        if region not in VALID_REGIONS:
            print(f"[!] Invalid region: {region}")
            return
        
        print(f"\n[*] Setting region: {region}")
        if not confirm("Region change affects radio compliance and features.", force):
            return
        
        data = b"SET".ljust(16, b'\x00') + region.encode()[:8].ljust(8, b'\x00')
        ok, name, extra = odm_cmd(dev, OP_REGION, data)
        result(ok, name, f"Region → {region}", extra, verbose)
    else:
        print("[!] Usage: odm region <list|info|set> [region]")


def cmd_security(dev, args, force, verbose):
    """Security management"""
    if not args or args[0].lower() not in VALID_SECURITY:
        print(f"[!] Usage: odm security <{'|'.join(VALID_SECURITY)}>")
        return
    
    op = args[0].lower()
    print(f"\n[*] Security: {op}")
    
    if op in ("lockdown", "enable"):
        if not confirm(f"Security {op} restricts access and may prevent future modifications.", force):
            return
    
    data = op.encode()[:16].ljust(16, b'\x00')
    ok, name, extra = odm_cmd(dev, OP_SECURITY, data)
    result(ok, name, f"Security {op}", extra, verbose)


def cmd_firmware(dev, args, force, verbose):
    """Firmware management"""
    if not args:
        print("[!] Usage: odm firmware <info|update> [file]")
        return
    
    op = args[0].lower()
    
    if op == "info":
        print("\n[*] ODM Firmware:")
        ok, name, extra = odm_cmd(dev, OP_FIRMWARE_INFO)
        if ok and len(extra) >= 64:
            ver = extra[0:16].decode('ascii', errors='ignore').rstrip('\x00').strip()
            build = extra[16:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
            date = extra[32:48].decode('ascii', errors='ignore').rstrip('\x00').strip()
            custom = extra[48:64].decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"    Version: {ver or '?'}  Build: {build or '?'}")
            print(f"    Date:    {date or '?'}  Customizations: {custom or 'None'}")
        else:
            result(ok, name, "Firmware info", extra, verbose)
    
    elif op == "update" and len(args) > 1:
        fw_file = args[1]
        if not os.path.isfile(fw_file):
            print(f"[!] File not found: {fw_file}")
            return
        
        sz = os.path.getsize(fw_file)
        print(f"\n[*] Firmware update: {fw_file} ({sz:,} bytes)")
        
        if not confirm(
            "⚠️  FIRMWARE UPDATE WARNING:\n"
            "  - Interruption may BRICK device\n"
            "  - Ensure stable power connection\n"
            "  - Have recovery firmware available\n"
            "  - Device may reboot after update", force
        ):
            return
        
        try:
            with open(fw_file, 'rb') as f:
                fw_data = f.read()
            
            print("[*] Initializing...")
            ok, name, _ = odm_cmd(dev, OP_FIRMWARE_UPDATE, struct.pack("<I", len(fw_data)))
            if not ok:
                print(f"[!] Init failed: {name}")
                return
            
            print("[*] Sending firmware...")
            ok, name, _ = odm_cmd(dev, OP_FIRMWARE_DATA, fw_data)
            
            if ok:
                print("[+] Update complete! Device may restart.")
            else:
                print(f"[!] Transfer failed: {name}")
        except Exception as e:
            print(f"[!] Error: {e}")


def cmd_manufacturing(dev, args, force, verbose):
    """Manufacturing mode"""
    print(f"\n{'='*45}")
    print(f"  MANUFACTURING MODE")
    print(f"{'='*45}")
    
    if not confirm(
        "⚠️  MANUFACTURING MODE:\n"
        "  - LOW-LEVEL device access\n"
        "  - Bypasses security\n"
        "  - May void warranty\n"
        "  - For authorized personnel only", force
    ):
        return
    
    ok, name, _ = odm_cmd(dev, OP_MANUFACTURING, b"ENTER".ljust(16, b'\x00'))
    
    if ok:
        print("\n[+] Manufacturing mode active")
        print("[*] Available: RAW_FLASH, HW_TEST, CALIB_RW, SEC_ELEMENT, PROD_KEYS, BOUNDARY_SCAN, JTAG")
    else:
        print(f"[!] Failed: {name}")


def cmd_supplychain(dev, args, force, verbose):
    """Supply chain info"""
    print("\n[*] Supply Chain:")
    
    ok, name, extra = odm_cmd(dev, OP_SUPPLYCHAIN)
    
    if ok and extra and len(extra) >= 128:
        fields = {
            'Factory': extra[0:32], 'Prod Line': extra[32:48], 'Work Order': extra[48:64],
            'Batch': extra[64:80], 'QC Status': extra[80:96], 'Ship Date': extra[96:112],
            'Destination': extra[112:128],
        }
        for key, val in fields.items():
            decoded = val.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"    {key:<14} {decoded or 'N/A'}")
    else:
        result(ok, name, "Supply chain query", extra, verbose)


def cmd_unlock(dev, args, force, verbose):
    """Unlock development features"""
    print(f"\n{'='*45}")
    print(f"  UNLOCK ODM DEVELOPMENT")
    print(f"{'='*45}")
    
    if not confirm(
        "⚠️  DEVELOPMENT UNLOCK:\n"
        "  - Advanced ODM tools\n"
        "  - Bypasses security\n"
        "  - May void warranty\n"
        "  - Development/test devices only", force
    ):
        return
    
    data = b"ODM_DEV".ljust(16, b'\x00')
    if args:
        data += args[0].encode()[:16].ljust(16, b'\x00')
    
    ok, name, _ = odm_cmd(dev, OP_UNLOCK, data)
    
    if ok:
        print("\n[+] Unlocked. Features: DEBUG, RAW_MEM, SEC_BOOT_BYPASS, TEST_POINT, CALIB_OVERRIDE, ENHANCED_LOG")
    else:
        print(f"[!] Failed: {name}")


def cmd_lock(dev, args, force, verbose):
    """Lock to production"""
    print("\n[*] Locking ODM features...")
    ok, name, extra = odm_cmd(dev, OP_LOCK, b"PRODUCTION".ljust(16, b'\x00'))
    result(ok, name, "ODM lock", extra, verbose)


def cmd_reset(dev, args, force, verbose):
    """Reset to factory"""
    print(f"\n{'='*45}")
    print(f"  RESET ODM CUSTOMIZATIONS")
    print(f"{'='*45}")
    
    if not confirm(
        "⚠️  RESET WARNING:\n"
        "  - Removes ALL ODM customizations\n"
        "  - Returns to generic factory state\n"
        "  - Cannot be undone without re-provisioning", force
    ):
        return
    
    ok, name, _ = odm_cmd(dev, OP_RESET, b"FACTORY".ljust(16, b'\x00'))
    
    if ok:
        print("\n[+] Reset complete. Removed: branding, logos, bootanim, sounds, themes, regions, mfg flags, calibration")
    else:
        print(f"[!] Failed: {name}")


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'info': cmd_info, 'status': cmd_info, 'identity': cmd_info,
    'provision': cmd_provision, 'setup': cmd_provision, 'init': cmd_provision,
    'customize': cmd_customize, 'brand': cmd_customize, 'personalize': cmd_customize,
    'test': cmd_test, 'diagnostic': cmd_test, 'selftest': cmd_test,
    'calibrate': cmd_calibrate, 'tune': cmd_calibrate, 'adjust': cmd_calibrate,
    'feature': cmd_feature, 'capability': cmd_feature, 'toggle': cmd_feature,
    'region': cmd_region, 'locale': cmd_region, 'market': cmd_region,
    'security': cmd_security, 'lockdown': cmd_security, 'secure': cmd_security,
    'firmware': cmd_firmware, 'update': cmd_firmware, 'flash': cmd_firmware,
    'manufacturing': cmd_manufacturing, 'factory': cmd_manufacturing, 'production': cmd_manufacturing,
    'supplychain': cmd_supplychain, 'logistics': cmd_supplychain, 'tracking': cmd_supplychain,
    'unlock': cmd_unlock, 'enable': cmd_unlock, 'activate': cmd_unlock,
    'lock': cmd_lock, 'disable': cmd_lock, 'deactivate': cmd_lock,
    'reset': cmd_reset, 'restore': cmd_reset, 'defaults': cmd_reset,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_odm(args=None) -> int:
    """
    QSLCL ODM - ODM operations and device management
    
    Examples:
        odm info                      - Device information
        odm test FULL --verbose       - Full manufacturing test
        odm customize branding "Name" - Apply branding
        odm calibrate display         - Calibrate display
        odm region set EU             - Set region to EU
        odm firmware update fw.bin    - Update firmware
        odm manufacturing --force     - Enter manufacturing mode
        odm reset                     - Reset customizations
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: odm <info|provision|test|calibrate|customize|feature|region|security|firmware|manufacturing|reset>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'odm_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    oargs = getattr(args, 'odm_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] ODM Commands:")
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
    print("[*] odm.py - QSLCL ODM Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py odm <subcommand> [args]")