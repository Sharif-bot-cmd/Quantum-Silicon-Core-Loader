#!/usr/bin/env python3
"""
odm.py - QSLCL ODM Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, subcommand dispatch table,
       error recovery, data parsing, consistency across all handlers
"""

import os
import sys
import re
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
# FIXED: Standalone mode handling
# =============================================================================
_STANDALONE_WARNED = False

def _warn_standalone():
    """Warn about standalone mode once"""
    global _STANDALONE_WARNED
    if not _STANDALONE_WARNED:
        print("[!] Running in standalone mode (limited functionality)")
        print("[*] For full features, ensure qslcl.py is in the Python path")
        _STANDALONE_WARNED = True


# =============================================================================
# FIXED: Constants
# =============================================================================
ODM_TIMEOUT = 15.0              # ODM operation timeout
MAX_RETRIES = 3                 # Max retries

# =============================================================================
# FIXED: ODM Command opcodes
# =============================================================================
class ODMOpcode:
    """ODM command opcodes for structured dispatch."""
    INFO = 0x01
    PROVISION = 0x10
    CUSTOMIZE = 0x20
    TEST = 0x30
    CALIBRATE = 0x40
    FEATURE = 0x50
    REGION = 0x60
    SECURITY = 0x70
    FIRMWARE_INFO = 0x75
    FIRMWARE_UPDATE = 0x76
    FIRMWARE_DATA = 0x77
    MANUFACTURING = 0x80
    SUPPLYCHAIN = 0x85
    UNLOCK = 0x90
    LOCK = 0xA0
    RESET = 0xB0

# Valid values for various operations
VALID_CUSTOMIZATIONS = ['branding', 'bootlogo', 'bootanimation', 'sounds', 'themes']
VALID_TEST_TYPES = ['QUICK', 'FULL', 'EXTENDED']
VALID_HARDWARE = ['display', 'touch', 'audio', 'sensors', 'camera', 'battery']
VALID_SECURITY_OPS = ['enable', 'disable', 'lockdown', 'unlock', 'status']
VALID_REGIONS = ['NA', 'EU', 'ASIA', 'CN', 'JP', 'KR', 'IN', 'LATAM', 'MEA', 'GLOBAL']
VALID_ACTIONS = ['ENABLE', 'DISABLE', 'TOGGLE']


# =============================================================================
# FIXED: Interactive confirmation helper
# =============================================================================
def confirm_action(prompt: str, force: bool = False) -> bool:
    """Request user confirmation for operations."""
    if force:
        return True
    
    print(f"\n{prompt}")
    try:
        response = input("    Continue? (y/N): ")
        return response.lower() in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Interactive input not available")
        return False


# =============================================================================
# FIXED: Find command in QSLCLCMD database
# =============================================================================
def find_command(cmd_name: str) -> Optional[Tuple[str, Any]]:
    """Find a command in QSLCLCMD_DB."""
    if not _use_qslcl or not _QSLCLCMD_DB:
        return None
    
    cmd_upper = cmd_name.upper()
    for key, value in _QSLCLCMD_DB.items():
        if isinstance(key, str) and key.upper() == cmd_upper:
            return ("name", key)
        if isinstance(value, dict) and value.get("name", "").upper() == cmd_upper:
            return ("opcode", key)
    return None


# =============================================================================
# FIXED: Command dispatch helper
# =============================================================================
def dispatch_odm_command(dev, opcode: int, data: bytes = b"", 
                         timeout: float = None) -> Tuple[bool, str, bytes]:
    """
    Dispatch an ODM command with consistent error handling.
    
    Returns:
        Tuple[bool, str, bytes]: (success, status_name, extra_data)
    """
    if not _use_qslcl:
        return False, "NO_QSLCL_SUPPORT", b""
    
    if timeout is None:
        timeout = ODM_TIMEOUT
    
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            # Try ODM command first
            if find_command("ODM"):
                resp = _qslcl_dispatch(dev, "ODM", payload, timeout=timeout)
            else:
                resp = _qslcl_dispatch(dev, str(opcode), payload, timeout=timeout)
            
            if resp:
                status = _decode_runtime_result(resp)
                severity = status.get("severity", "ERROR")
                name = status.get("name", "UNKNOWN")
                extra = status.get("extra", b"")
                return severity == "SUCCESS", name, extra
            
        except Exception as e:
            if _DEBUG:
                print(f"[!] ODM dispatch attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.2 * (attempt + 1))
    
    return False, "NO_RESPONSE", b""


# =============================================================================
# FIXED: Helper to display success/failure
# =============================================================================
def print_result(success: bool, status_name: str, operation: str, extra: bytes = b"",
                 verbose: bool = False):
    """Print standardized operation result."""
    if success:
        print(f"[+] {operation} completed successfully")
        if verbose and extra:
            print(f"    Response data: {extra[:128].hex()}{'...' if len(extra) > 128 else ''}")
    else:
        print(f"[!] {operation} failed: {status_name}")
        if extra and verbose:
            print(f"    Extra data: {extra[:64].hex()}")


# =============================================================================
# FIXED: Display helper functions
# =============================================================================
def print_table(headers: List[str], rows: List[List[str]], indent: str = "    "):
    """Print a formatted table."""
    if not rows:
        print(f"{indent}(empty)")
        return
    
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Print header
    header_line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
    print(f"{indent}{header_line}")
    print(f"{indent}{'-' * len(header_line)}")
    
    # Print rows
    for row in rows:
        row_line = "  ".join(f"{str(c):<{w}}" for c, w in zip(row, col_widths))
        print(f"{indent}{row_line}")


# =============================================================================
# FIXED: ODM Info command
# =============================================================================
def odm_info(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Display ODM-specific device information."""
    print("\n[*] Querying ODM device information...")
    
    # Try to get info from device
    info = _query_odm_info_from_device(dev, verbose)
    
    # Display results
    print(f"\n[+] ODM Device Information:")
    print_table(
        ["Field", "Value"],
        [
            ["Manufacturer", info.get('manufacturer', 'Unknown')],
            ["Model", info.get('model', 'Unknown')],
            ["SKU", info.get('sku', 'Unknown')],
            ["Serial", info.get('serial', 'Unknown')],
            ["HW Revision", info.get('hw_revision', 'Unknown')],
            ["Production Date", info.get('production_date', 'Unknown')],
            ["Region", info.get('region', 'Unknown')],
            ["Carrier", info.get('carrier', 'Unknown')],
        ]
    )
    
    # Features
    features = info.get('features', [])
    if features:
        print(f"\n[+] ODM Features:")
        feature_rows = []
        for f in features:
            status = "[ON]" if f.get('enabled', False) else "[OFF]"
            feature_rows.append([f"  {status}", f.get('name', '?'), f.get('description', '')])
        print_table(["Status", "Feature", "Description"], feature_rows)
    
    # Customizations
    customizations = info.get('customizations', [])
    if customizations:
        print(f"\n[+] Device Customizations:")
        custom_rows = [[c.get('type', '?'), str(c.get('value', ''))] for c in customizations]
        print_table(["Type", "Value"], custom_rows)


def _query_odm_info_from_device(dev, verbose: bool = False) -> Dict[str, Any]:
    """Try to query actual ODM info from device, with fallback."""
    # Default info
    default_info = {
        'manufacturer': 'Unknown ODM',
        'model': 'Unknown Model',
        'sku': 'Unknown SKU',
        'serial': 'Unknown',
        'hw_revision': 'Unknown',
        'production_date': 'Unknown',
        'region': 'GLOBAL',
        'carrier': 'Multi-carrier',
        'features': [],
        'customizations': [],
    }
    
    try:
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.INFO)
        
        if success and extra and len(extra) >= 128:
            info = {}
            info['manufacturer'] = extra[0:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['model'] = extra[32:64].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['sku'] = extra[64:80].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['serial'] = extra[80:96].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['hw_revision'] = extra[96:112].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['production_date'] = extra[112:128].decode('ascii', errors='ignore').rstrip('\x00').strip()
            
            # Merge with defaults for missing fields
            for key, value in default_info.items():
                if key not in info or not info[key]:
                    info[key] = value
            
            return info
    except Exception as e:
        if verbose and _DEBUG:
            print(f"[!] Device ODM info query error: {e}")
    
    return default_info


# =============================================================================
# FIXED: ODM Provision command
# =============================================================================
def odm_provision(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Provision device for ODM manufacturing."""
    print("\n[*] ========================================")
    print("[*] ODM DEVICE PROVISIONING")
    print("[*] ========================================")
    
    if not confirm_action(
        "Provisioning will configure device for manufacturing.\n"
        "This sets manufacturing flags and base parameters.",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    steps = [
        "Initializing provisioning mode",
        "Setting manufacturing flags",
        "Configuring base parameters",
        "Installing ODM certificates",
        "Setting up secure elements",
        "Finalizing provisioning"
    ]
    
    print()
    all_success = True
    
    for i, step in enumerate(steps):
        print(f"[*] Step {i+1}/{len(steps)}: {step}...", end=" ", flush=True)
        
        step_data = step.encode('ascii')[:32].ljust(32, b'\x00')
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.PROVISION, step_data)
        
        if success:
            print("OK")
        else:
            print(f"FAILED ({status_name})")
            all_success = False
            if not force:
                print(f"[!] Provisioning aborted at step {i+1}")
                return
        time.sleep(0.3)
    
    if all_success:
        print(f"\n[+] ODM provisioning completed successfully")
    else:
        print(f"\n[!] ODM provisioning completed with errors (some steps failed)")


# =============================================================================
# FIXED: ODM Customize command
# =============================================================================
def odm_customize(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Apply ODM customizations and branding."""
    if not args:
        print("[!] Specify customization type and value")
        print(f"[*] Available types: {', '.join(VALID_CUSTOMIZATIONS)}")
        print("[*] Usage: odm customize <type> <value|file>")
        return
    
    custom_type = args[0].lower()
    custom_value = args[1] if len(args) > 1 else ""
    
    if custom_type not in VALID_CUSTOMIZATIONS:
        print(f"[!] Invalid customization type: '{custom_type}'")
        print(f"[*] Valid types: {', '.join(VALID_CUSTOMIZATIONS)}")
        return
    
    print(f"\n[*] Customization: {custom_type}")
    
    if not confirm_action(
        f"This will modify device {custom_type}.\n"
        "Custom boot components may affect boot behavior.",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    # Build customization data
    type_bytes = custom_type.encode('ascii')[:16].ljust(16, b'\x00')
    
    # Check if value is a file path
    if custom_value and os.path.exists(custom_value) and os.path.isfile(custom_value):
        try:
            file_size = os.path.getsize(custom_value)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                print(f"[!] File too large: {file_size} bytes (max 10MB)")
                return
            
            print(f"[*] Loading from file: {custom_value} ({file_size} bytes)")
            with open(custom_value, 'rb') as f:
                file_data = f.read()
            
            data = type_bytes + struct.pack("<I", len(file_data)) + file_data
        except Exception as e:
            print(f"[!] File read error: {e}")
            return
    else:
        # String value
        value_bytes = custom_value.encode('ascii')[:64].ljust(64, b'\x00')
        data = type_bytes + value_bytes
    
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.CUSTOMIZE, data)
    print_result(success, status_name, f"{custom_type} customization", extra, verbose)


# =============================================================================
# FIXED: ODM Test command
# =============================================================================
def odm_test(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Run ODM manufacturing tests."""
    test_type = args[0].upper() if args else "QUICK"
    
    if test_type not in VALID_TEST_TYPES:
        print(f"[!] Invalid test type: '{test_type}'")
        print(f"[*] Valid types: {', '.join(VALID_TEST_TYPES)}")
        test_type = "QUICK"
    
    # Test definitions with realistic durations
    test_suites = {
        "QUICK": [
            ("Basic connectivity", 0.3),
            ("Memory test", 0.5),
            ("CPU validation", 0.3),
            ("Storage check", 0.5),
        ],
        "FULL": [
            ("Hardware diagnostics", 1.0),
            ("Sensor calibration check", 1.0),
            ("Radio module test", 1.5),
            ("Display verification", 0.5),
            ("Audio subsystem test", 1.0),
            ("Battery status check", 1.0),
            ("Camera module test", 0.5),
        ],
        "EXTENDED": [
            ("Burn-in stress test", 3.0),
            ("Memory stress testing", 2.0),
            ("Thermal validation", 2.0),
            ("Long-term reliability simulation", 3.0),
            ("Environmental tolerance check", 2.0),
        ]
    }
    
    tests = test_suites.get(test_type, test_suites["QUICK"])
    total_duration = sum(d for _, d in tests)
    
    print(f"\n[*] ========================================")
    print(f"[*] ODM {test_type} TEST SUITE")
    print(f"[*] ========================================")
    print(f"[*] Tests: {len(tests)}")
    print(f"[*] Estimated duration: {total_duration:.1f}s")
    
    if not confirm_action(
        f"Running {test_type} manufacturing tests.\n"
        "Device may be unresponsive during testing.",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    print()
    results = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    
    for test_name, test_duration in tests:
        print(f"    [{test_name:<35}] ", end="", flush=True)
        
        test_data = test_type.encode('ascii')[:8].ljust(8, b'\x00')
        test_data += test_name.encode('ascii')[:32].ljust(32, b'\x00')
        
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.TEST, test_data)
        
        # Simulate remaining test time
        time.sleep(max(0.1, test_duration - 0.3))
        
        if success:
            print("PASS")
            results["PASS"] += 1
        elif status_name == "SKIP" or status_name == "NOT_SUPPORTED":
            print("SKIP")
            results["SKIP"] += 1
        else:
            print(f"FAIL ({status_name})")
            results["FAIL"] += 1
            if verbose and extra:
                print(f"        Details: {extra[:64].hex()}")
    
    # Summary
    total = sum(results.values())
    print(f"\n[+] Test Suite Complete:")
    print(f"    Passed:  {results['PASS']}/{total}")
    print(f"    Failed:  {results['FAIL']}/{total}")
    if results['SKIP'] > 0:
        print(f"    Skipped: {results['SKIP']}/{total}")
    
    if results['FAIL'] == 0:
        print(f"\n[✓] All tests passed!")
    else:
        print(f"\n[!] {results['FAIL']} test(s) failed - review device logs")


# =============================================================================
# FIXED: ODM Calibrate command
# =============================================================================
def odm_calibrate(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Calibrate ODM-specific hardware."""
    if not args:
        print("[!] Specify hardware to calibrate")
        print(f"[*] Available: {', '.join(VALID_HARDWARE)}")
        return
    
    hardware = args[0].lower()
    
    if hardware not in VALID_HARDWARE:
        print(f"[!] Invalid hardware: '{hardware}'")
        print(f"[*] Valid: {', '.join(VALID_HARDWARE)}")
        return
    
    print(f"\n[*] Calibrating: {hardware}")
    
    if not confirm_action(
        f"{hardware.capitalize()} calibration requires proper test equipment.\n"
        "Incorrect calibration may cause hardware malfunction.",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    # Build calibration data
    data = hardware.encode('ascii')[:16].ljust(16, b'\x00')
    
    # Add calibration parameters
    if len(args) > 1:
        for param in args[1:4]:  # Max 3 additional params
            try:
                if '.' in param:
                    data += struct.pack("<f", float(param))
                else:
                    data += struct.pack("<I", int(param, 0))
            except ValueError:
                data += param.encode('ascii')[:16].ljust(16, b'\x00')
    
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.CALIBRATE, data)
    print_result(success, status_name, f"{hardware} calibration", extra, verbose)


# =============================================================================
# FIXED: ODM Feature command
# =============================================================================
def odm_feature(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Enable/disable ODM-specific features."""
    if not args:
        print("[!] Specify feature name and action")
        print("[*] Usage: odm feature <name> [ENABLE|DISABLE|TOGGLE]")
        print("[*] Common features: CUSTOM_BOOTANIMATION, BRANDED_SOUNDS, "
              "CUSTOM_THEME, EXTENDED_DIAGNOSTICS")
        return
    
    feature = args[0].upper()
    action = args[1].upper() if len(args) > 1 else "TOGGLE"
    
    if action not in VALID_ACTIONS:
        print(f"[!] Invalid action: '{action}'")
        print(f"[*] Valid: {', '.join(VALID_ACTIONS)}")
        return
    
    print(f"\n[*] Feature: {feature} -> {action}")
    
    if not confirm_action(
        f"This will {action.lower()} the '{feature}' feature.",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    data = feature.encode('ascii')[:16].ljust(16, b'\x00')
    data += action.encode('ascii')[:8].ljust(8, b'\x00')
    
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.FEATURE, data)
    print_result(success, status_name, f"Feature {feature} {action.lower()}", extra, verbose)


# =============================================================================
# FIXED: ODM Region command
# =============================================================================
def odm_region(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Configure regional settings."""
    if not args:
        print("[!] Specify operation: list, info, set <region>")
        return
    
    operation = args[0].lower()
    
    if operation == "list":
        print(f"\n[+] Available Regions ({len(VALID_REGIONS)}):")
        # Print in columns
        for i in range(0, len(VALID_REGIONS), 4):
            print(f"    {'  '.join(VALID_REGIONS[i:i+4])}")
        return
    
    elif operation == "info":
        print("\n[*] Querying current region...")
        data = b"GET".ljust(16, b'\x00')
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.REGION, data)
        
        if success and extra:
            region = extra.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"[+] Current region: {region}")
        else:
            print_result(success, status_name, "Region query", extra, verbose)
    
    elif operation == "set" and len(args) > 1:
        region = args[1].upper()
        
        if region not in VALID_REGIONS:
            print(f"[!] Invalid region: '{region}'")
            print(f"[*] Valid: {', '.join(VALID_REGIONS)}")
            return
        
        print(f"\n[*] Setting region: {region}")
        
        if not confirm_action(
            "Region change may affect radio compliance, available features,\n"
            "and regulatory certifications.",
            force
        ):
            print("[*] Operation cancelled")
            return
        
        data = b"SET".ljust(16, b'\x00')
        data += region.encode('ascii')[:8].ljust(8, b'\x00')
        
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.REGION, data)
        print_result(success, status_name, f"Region set to {region}", extra, verbose)
    
    else:
        print("[!] Invalid region operation. Use: list, info, set <region>")


# =============================================================================
# FIXED: ODM Security command
# =============================================================================
def odm_security(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Manage ODM security settings."""
    if not args:
        print("[!] Specify security operation")
        print(f"[*] Available: {', '.join(VALID_SECURITY_OPS)}")
        return
    
    operation = args[0].lower()
    
    if operation not in VALID_SECURITY_OPS:
        print(f"[!] Invalid operation: '{operation}'")
        print(f"[*] Valid: {', '.join(VALID_SECURITY_OPS)}")
        return
    
    print(f"\n[*] Security operation: {operation}")
    
    if operation in ("lockdown", "enable"):
        if not confirm_action(
            "Security lockdown restricts device access and may prevent\n"
            "future modifications without proper authorization.",
            force
        ):
            print("[*] Operation cancelled")
            return
    
    data = operation.encode('ascii')[:16].ljust(16, b'\x00')
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.SECURITY, data)
    print_result(success, status_name, f"Security {operation}", extra, verbose)


# =============================================================================
# FIXED: ODM Firmware command
# =============================================================================
def odm_firmware(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Manage ODM-specific firmware."""
    if not args:
        print("[!] Specify operation: info, update <file>")
        return
    
    operation = args[0].lower()
    
    if operation == "info":
        print("\n[*] Querying ODM firmware information...")
        success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.FIRMWARE_INFO)
        
        if success and len(extra) >= 64:
            version = extra[0:16].decode('ascii', errors='ignore').rstrip('\x00').strip()
            build = extra[16:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
            date = extra[32:48].decode('ascii', errors='ignore').rstrip('\x00').strip()
            custom = extra[48:64].decode('ascii', errors='ignore').rstrip('\x00').strip()
            
            print(f"\n[+] ODM Firmware:")
            print_table(
                ["Field", "Value"],
                [
                    ["Version", version or "Unknown"],
                    ["Build", build or "Unknown"],
                    ["Date", date or "Unknown"],
                    ["Customizations", custom or "None"],
                ]
            )
        else:
            print_result(success, status_name, "Firmware info query", extra, verbose)
    
    elif operation == "update" and len(args) > 1:
        firmware_file = args[1]
        
        if not os.path.exists(firmware_file):
            print(f"[!] Firmware file not found: {firmware_file}")
            return
        
        if not os.path.isfile(firmware_file):
            print(f"[!] Not a file: {firmware_file}")
            return
        
        try:
            file_size = os.path.getsize(firmware_file)
        except OSError as e:
            print(f"[!] Cannot access file: {e}")
            return
        
        print(f"\n[*] Firmware update:")
        print(f"    File: {firmware_file}")
        print(f"    Size: {file_size:,} bytes")
        
        if not confirm_action(
            "⚠️  FIRMWARE UPDATE WARNING:\n"
            "  - Interruption may BRICK the device\n"
            "  - Ensure stable power connection\n"
            "  - Have recovery firmware available\n"
            "  - Device may reboot after update",
            force
        ):
            print("[*] Operation cancelled")
            return
        
        try:
            with open(firmware_file, 'rb') as f:
                firmware_data = f.read()
            
            # Initialize update
            print("[*] Initializing firmware update...")
            init_data = struct.pack("<I", len(firmware_data))
            success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.FIRMWARE_UPDATE, init_data)
            
            if not success:
                print(f"[!] Update initialization failed: {status_name}")
                return
            
            print("[*] Sending firmware data...")
            data_success, data_status, data_extra = dispatch_odm_command(
                dev, ODMOpcode.FIRMWARE_DATA, firmware_data, timeout=60.0
            )
            
            if data_success:
                print("[+] Firmware update completed!")
                print("[*] Device may restart automatically")
            else:
                print(f"[!] Firmware data transfer failed: {data_status}")
        
        except Exception as e:
            print(f"[!] Firmware update error: {type(e).__name__}: {e}")
            if _DEBUG:
                traceback.print_exc()
    
    else:
        print("[!] Invalid firmware operation. Use: info, update <file>")


# =============================================================================
# FIXED: ODM Manufacturing command
# =============================================================================
def odm_manufacturing(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Access manufacturing modes."""
    print("\n[*] ========================================")
    print("[*] MANUFACTURING MODE")
    print("[*] ========================================")
    
    if not confirm_action(
        "⚠️  MANUFACTURING MODE WARNING:\n"
        "  - Provides LOW-LEVEL device access\n"
        "  - May VOID warranties\n"
        "  - Bypasses security features\n"
        "  - For authorized personnel only",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    data = b"ENTER".ljust(16, b'\x00')
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.MANUFACTURING, data)
    
    if success:
        print("\n[+] Manufacturing mode activated")
        print("\n[*] Available manufacturing commands:")
        mfg_commands = [
            "RAW_FLASH_ACCESS",
            "HARDWARE_TEST_MODE",
            "CALIBRATION_DATA_RW",
            "SECURE_ELEMENT_ACCESS",
            "PRODUCTION_KEY_MGMT",
            "BOUNDARY_SCAN",
            "JTAG_ENABLE",
        ]
        for cmd in mfg_commands:
            print(f"    • {cmd}")
    else:
        print_result(success, status_name, "Manufacturing mode", extra, verbose)


# =============================================================================
# FIXED: ODM Supply Chain command
# =============================================================================
def odm_supplychain(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Query supply chain information."""
    print("\n[*] Querying supply chain information...")
    
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.SUPPLYCHAIN)
    
    if success and len(extra) >= 128:
        fields = {
            'Factory': extra[0:32],
            'Production Line': extra[32:48],
            'Work Order': extra[48:64],
            'Batch': extra[64:80],
            'QC Status': extra[80:96],
            'Ship Date': extra[96:112],
            'Destination': extra[112:128],
        }
        
        print(f"\n[+] Supply Chain Information:")
        rows = []
        for key, value in fields.items():
            decoded = value.decode('ascii', errors='ignore').rstrip('\x00').strip()
            rows.append([key, decoded or 'N/A'])
        print_table(["Field", "Value"], rows)
    else:
        print_result(success, status_name, "Supply chain query", extra, verbose)


# =============================================================================
# FIXED: ODM Unlock command
# =============================================================================
def odm_unlock(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Unlock ODM development features."""
    print("\n[*] ========================================")
    print("[*] UNLOCK ODM DEVELOPMENT FEATURES")
    print("[*] ========================================")
    
    if not confirm_action(
        "⚠️  DEVELOPMENT UNLOCK WARNING:\n"
        "  - Enables advanced ODM development tools\n"
        "  - Bypasses normal security restrictions\n"
        "  - May void warranty\n"
        "  - Only use on development/test devices",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    data = b"ODM_DEV".ljust(16, b'\x00')
    
    if args:
        unlock_code = args[0]
        data += unlock_code.encode('ascii')[:16].ljust(16, b'\x00')
    
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.UNLOCK, data)
    
    if success:
        print("\n[+] ODM development features unlocked")
        print("\n[*] Available development features:")
        features = [
            "DEBUG_ACCESS",
            "RAW_MEMORY_ACCESS",
            "SECURE_BOOT_BYPASS",
            "TEST_POINT_ACCESS",
            "CALIBRATION_OVERRIDE",
            "LOGGING_ENHANCED",
        ]
        for f in features:
            print(f"    • {f}")
    else:
        print_result(success, status_name, "ODM unlock", extra, verbose)


# =============================================================================
# FIXED: ODM Lock command
# =============================================================================
def odm_lock(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Lock ODM features."""
    print("\n[*] Locking ODM development features...")
    
    data = b"PRODUCTION".ljust(16, b'\x00')
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.LOCK, data)
    print_result(success, status_name, "ODM lock", extra, verbose)


# =============================================================================
# FIXED: ODM Reset command
# =============================================================================
def odm_reset(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Reset ODM customizations to factory defaults."""
    print("\n[*] ========================================")
    print("[*] RESET ODM CUSTOMIZATIONS")
    print("[*] ========================================")
    
    if not confirm_action(
        "⚠️  RESET WARNING:\n"
        "  - Removes ALL ODM customizations and branding\n"
        "  - Device returns to generic factory state\n"
        "  - This cannot be undone without re-provisioning",
        force
    ):
        print("[*] Operation cancelled")
        return
    
    data = b"FACTORY".ljust(16, b'\x00')
    success, status_name, extra = dispatch_odm_command(dev, ODMOpcode.RESET, data)
    
    if success:
        print("\n[+] ODM customizations reset to factory defaults")
        print("\n[*] Reset items:")
        items = [
            "Branding and logos",
            "Custom boot animations",
            "System sounds",
            "UI themes",
            "Regional settings",
            "Manufacturing flags",
            "Calibration overrides",
        ]
        for item in items:
            print(f"    • {item}")
    else:
        print_result(success, status_name, "ODM reset", extra, verbose)


# =============================================================================
# FIXED: Subcommand dispatch table
# =============================================================================
ODM_SUBCOMMANDS = {
    # Info
    'info': odm_info,
    'status': odm_info,
    'identity': odm_info,
    
    # Provisioning
    'provision': odm_provision,
    'setup': odm_provision,
    'init': odm_provision,
    
    # Customization
    'customize': odm_customize,
    'brand': odm_customize,
    'personalize': odm_customize,
    
    # Testing
    'test': odm_test,
    'diagnostic': odm_test,
    'selftest': odm_test,
    
    # Calibration
    'calibrate': odm_calibrate,
    'tune': odm_calibrate,
    'adjust': odm_calibrate,
    
    # Features
    'feature': odm_feature,
    'capability': odm_feature,
    'toggle': odm_feature,
    
    # Region
    'region': odm_region,
    'locale': odm_region,
    'market': odm_region,
    
    # Security
    'security': odm_security,
    'lockdown': odm_security,
    'secure': odm_security,
    
    # Firmware
    'firmware': odm_firmware,
    'update': odm_firmware,
    'flash': odm_firmware,
    
    # Manufacturing
    'manufacturing': odm_manufacturing,
    'factory': odm_manufacturing,
    'production': odm_manufacturing,
    
    # Supply chain
    'supplychain': odm_supplychain,
    'logistics': odm_supplychain,
    'tracking': odm_supplychain,
    
    # Unlock
    'unlock': odm_unlock,
    'enable': odm_unlock,
    'activate': odm_unlock,
    
    # Lock
    'lock': odm_lock,
    'disable': odm_lock,
    'deactivate': odm_lock,
    
    # Reset
    'reset': odm_reset,
    'restore': odm_reset,
    'defaults': odm_reset,
    
    # Help
    'help': lambda dev, args, force, verbose: print_odm_help(),
    '?': lambda dev, args, force, verbose: print_odm_help(),
}


# =============================================================================
# FIXED: Help display
# =============================================================================
def print_odm_help():
    """Display ODM command help."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    ODM COMMAND HELP                          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Device Information:                                         ║
║    info                 Show ODM device information          ║
║    supplychain          Show supply chain information        ║
║                                                              ║
║  Manufacturing:                                              ║
║    provision            Provision device for manufacturing   ║
║    test [QUICK|FULL|EXTENDED]  Run manufacturing tests       ║
║    calibrate <hw>       Calibrate hardware component         ║
║    manufacturing        Enter manufacturing mode             ║
║                                                              ║
║  Customization:                                              ║
║    customize <type> <v> Apply ODM customizations             ║
║    feature <name> [act] Manage ODM features                  ║
║    region [list|info|set <r>]  Configure regional settings   ║
║                                                              ║
║  Security:                                                   ║
║    security <op>        Manage security settings             ║
║    unlock [code]        Unlock ODM development features      ║
║    lock                 Lock ODM features (production)       ║
║                                                              ║
║  Firmware:                                                   ║
║    firmware info        Show ODM firmware information        ║
║    firmware update <f>  Update ODM firmware from file        ║
║                                                              ║
║  Maintenance:                                                ║
║    reset                Reset ODM customizations to default  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  CUSTOMIZATION TYPES:   branding, bootlogo, bootanimation,   ║
║                         sounds, themes                       ║
║  TEST TYPES:            QUICK, FULL, EXTENDED                ║
║  HARDWARE:              display, touch, audio, sensors,      ║
║                         camera, battery                      ║
║  SECURITY OPS:          enable, disable, lockdown, unlock,   ║
║                         status                               ║
║  REGIONS:               NA, EU, ASIA, CN, JP, KR, IN,       ║
║                         LATAM, MEA, GLOBAL                   ║
╠══════════════════════════════════════════════════════════════╣
║  FLAGS:  --force (-f)   Skip confirmation prompts            ║
║          --verbose (-v) Show detailed output                 ║
╠══════════════════════════════════════════════════════════════╣
║  EXAMPLES:                                                   ║
║    qslcl odm info                                            ║
║    qslcl odm test FULL --verbose                             ║
║    qslcl odm customize branding "MyBrand"                    ║
║    qslcl odm calibrate display                               ║
║    qslcl odm region set EU                                   ║
║    qslcl odm firmware update odm_fw.bin --force              ║
║    qslcl odm manufacturing --force                           ║
╚══════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# FIXED: Main ODM command function
# =============================================================================
def cmd_odm(args=None) -> int:
    """
    QSLCL ODM Command v2.0 (FIXED)
    
    Manages ODM operations including:
    - Device provisioning and customization
    - Manufacturing tests and calibration
    - Feature and region management
    - Security and firmware operations
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] ODM: No arguments provided")
        print_odm_help()
        return 1
    
    if not _use_qslcl:
        _warn_standalone()
    
    # =========================================================================
    # Device discovery
    # =========================================================================
    if _use_qslcl:
        try:
            devs = _scan_all()
        except Exception as e:
            print(f"[!] Device scan failed: {e}")
            return 1
        
        if not devs:
            print("[!] No QSLCL-compatible device detected")
            return 1
        
        dev = devs[0]
        print(f"[*] Device: {dev.product} ({dev.vendor})")
    else:
        print("[!] Cannot access device in standalone mode")
        return 1
    
    # =========================================================================
    # Loader injection
    # =========================================================================
    if hasattr(args, 'loader') and args.loader:
        try:
            _auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"[!] Loader injection failed: {e}")
            return 1
    
    # =========================================================================
    # Extract subcommand
    # =========================================================================
    subcommand = None
    for attr in ['odm_subcommand', 'subcommand']:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                subcommand = val.lower().strip()
                break
    
    if not subcommand:
        print("[!] No subcommand specified")
        print_odm_help()
        return 1
    
    # Extract other args
    odm_args = getattr(args, 'odm_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    # =========================================================================
    # Dispatch subcommand
    # =========================================================================
    handler = ODM_SUBCOMMANDS.get(subcommand)
    
    if handler:
        try:
            handler(dev, odm_args, force, verbose)
            return 0
        except TypeError as e:
            # Handle lambda mismatch
            if _DEBUG:
                print(f"[!] Handler signature error for '{subcommand}': {e}")
            handler(dev, odm_args, force, verbose)
            return 0
        except Exception as e:
            print(f"[!] ODM operation failed: {type(e).__name__}: {e}")
            if verbose and _DEBUG:
                traceback.print_exc()
            return 1
    else:
        print(f"[!] Unknown ODM subcommand: '{subcommand}'")
        print_odm_help()
        return 1


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_odm_arguments(parser) -> None:
    """Add ODM-specific arguments to an argument parser."""
    parser.add_argument(
        'odm_subcommand',
        nargs='?',
        help='ODM subcommand (info, test, calibrate, customize, etc.)'
    )
    parser.add_argument(
        'odm_args',
        nargs='*',
        help='Additional arguments for the ODM subcommand'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with detailed information'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force operation without confirmation prompts'
    )
    return parser


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] odm.py - QSLCL ODM Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py odm <subcommand> [options]")
    print()
    print_odm_help()