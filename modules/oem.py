#!/usr/bin/env python3
"""
oem.py - QSLCL OEM Command Module v2.0 (FIXED)
Fixed: Import handling, command dispatch, safety checks, memory scanning,
       bootloader lock/unlock verification, error recovery
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
_load_partitions = None
_auto_loader_if_needed = None
_qslcl_dispatch = None
_decode_runtime_result = None
_QSLCLCMD_DB = None
_DEBUG = False

try:
    from qslcl import (
        scan_all as _qslcl_scan_all,
        load_partitions as _qslcl_load_partitions,
        auto_loader_if_needed as _qslcl_auto_loader,
        qslcl_dispatch as _qslcl_dispatch_fn,
        decode_runtime_result as _qslcl_decode_runtime,
        QSLCLCMD_DB as _qslcl_cmd_db,
        _DEBUG as _qslcl_debug,
        set_debug
    )
    _scan_all = _qslcl_scan_all
    _load_partitions = _qslcl_load_partitions
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
            load_partitions as _qslcl_load_partitions,
            auto_loader_if_needed as _qslcl_auto_loader,
            qslcl_dispatch as _qslcl_dispatch_fn,
            decode_runtime_result as _qslcl_decode_runtime,
            QSLCLCMD_DB as _qslcl_cmd_db,
            _DEBUG as _qslcl_debug,
            set_debug
        )
        _scan_all = _qslcl_scan_all
        _load_partitions = _qslcl_load_partitions
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
OEM_TIMEOUT = 15.0              # OEM operation timeout
READ_TIMEOUT = 5.0              # Memory read timeout
MAX_RETRIES = 3                 # Max retries for operations
SCAN_READ_SIZE = 16             # Bytes to read per lock region scan

# =============================================================================
# FIXED: OEM Command opcodes
# =============================================================================
class OEMOpcode:
    """OEM command opcodes for structured dispatch."""
    UNLOCK = 0x10
    LOCK = 0x11
    WARRANTY = 0x20
    SECUREBOOT = 0x30
    PROVISION = 0x40
    CUSTOMIZE = 0x50
    INFO = 0x60
    CONFIG = 0x70
    KEYS = 0x80
    DEBUG = 0x90

# Config operation types
class ConfigOp:
    GET = 0x01
    SET = 0x02
    LIST = 0x03
    DELETE = 0x04

# Query flag
QUERY_FLAG = 0xFF

# =============================================================================
# FIXED: Common bootloader lock region addresses
# =============================================================================
COMMON_LOCK_ADDRESSES = [
    (0x00021000, "Qualcomm PBL Lock Region"),
    (0x0006F000, "Samsung Bootloader Lock"),
    (0x00070000, "Generic Bootloader Lock"),
    (0x00080000, "MediaTek Preloader Lock"),
    (0x00100000, "Common Bootloader Area"),
    (0x0F000000, "eMMC Boot Partition Lock"),
    (0x10000000, "UFS Boot Partition Lock"),
    (0x41E00000, "Huawei Bootloader Lock"),
    (0x87E00000, "Xiaomi Bootloader Lock"),
]

# Known lock region patterns
LOCK_PATTERNS = {
    'unlocked': b'\x00\x00\x00\x00',
    'locked': b'\x01\x00\x00\x00',
    'erased': b'\xEE\xEE\xEE\xEE',
    'default': b'\xFF\xFF\xFF\xFF',
}

# Text lock patterns
TEXT_PATTERNS = {
    b'LOCK': "Lock Flag (Text)",
    b'UNLK': "Unlock Flag (Text)",
}


# =============================================================================
# FIXED: Interactive confirmation helper
# =============================================================================
def confirm_action(prompt: str, required_text: str, force: bool = False) -> bool:
    """
    Request user confirmation for dangerous actions.
    
    Args:
        prompt: Warning message to display
        required_text: Text user must type to confirm
        force: If True, skip confirmation
    
    Returns:
        bool: True if confirmed, False otherwise
    """
    if force:
        print(f"[!] Force mode: Skipping confirmation")
        return True
    
    print(f"\n{prompt}")
    
    try:
        response = input(f"    Type '{required_text}' to confirm: ")
        return response == required_text
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
def dispatch_command(dev, cmd_name: str, payload: bytes, 
                     fallback_cmd: str = None, timeout: float = None) -> Optional[bytes]:
    """
    Dispatch a command with fallback support.
    
    Returns:
        Optional[bytes]: Response data or None
    """
    if not _use_qslcl:
        return None
    
    if timeout is None:
        timeout = OEM_TIMEOUT
    
    # Try primary command
    cmd_info = find_command(cmd_name)
    if cmd_info:
        cmd_type, cmd_key = cmd_info
        try:
            if cmd_type == "name":
                resp = _qslcl_dispatch(dev, cmd_key, payload, timeout=timeout)
            else:
                resp = _qslcl_dispatch(dev, str(cmd_key), payload, timeout=timeout)
            if resp:
                return resp
        except Exception:
            pass
    
    # Try fallback
    if fallback_cmd:
        try:
            resp = _qslcl_dispatch(dev, fallback_cmd, payload, timeout=timeout)
            if resp:
                return resp
        except Exception:
            pass
    
    # Generic dispatch
    try:
        return _qslcl_dispatch(dev, cmd_name, payload, timeout=timeout)
    except Exception:
        return None


# =============================================================================
# FIXED: Read memory helper
# =============================================================================
def read_memory(dev, address: int, size: int) -> Optional[bytes]:
    """Read memory from device."""
    if not _use_qslcl:
        return None
    
    try:
        read_payload = struct.pack("<II", address, size)
        resp = dispatch_command(dev, "READ", read_payload, 
                                fallback_cmd="PEEK", timeout=READ_TIMEOUT)
        
        if resp:
            status = _decode_runtime_result(resp)
            if status.get("severity") == "SUCCESS":
                return status.get("extra", b"")
    except Exception:
        pass
    
    return None


# =============================================================================
# FIXED: Check response success
# =============================================================================
def is_success(resp) -> Tuple[bool, str, bytes]:
    """
    Check if response indicates success.
    
    Returns:
        Tuple[bool, str, bytes]: (success, status_name, extra_data)
    """
    if not resp:
        return False, "NO_RESPONSE", b""
    
    if _use_qslcl and _decode_runtime_result:
        try:
            status = _decode_runtime_result(resp)
            severity = status.get("severity", "ERROR")
            name = status.get("name", "UNKNOWN")
            extra = status.get("extra", b"")
            return severity == "SUCCESS", name, extra
        except Exception:
            pass
    
    return bool(resp), "RAW_RESPONSE", resp if isinstance(resp, bytes) else b""


# =============================================================================
# FIXED: Memory region scanning for bootloader locks
# =============================================================================
def scan_lock_regions(dev, verbose: bool = False) -> List[Dict]:
    """
    Scan known memory regions for bootloader lock data.
    
    Returns:
        List[Dict]: List of found lock regions with details
    """
    lock_regions = []
    
    if verbose:
        print("\n[*] Scanning bootloader lock regions...")
    
    for address, description in COMMON_LOCK_ADDRESSES:
        try:
            data = read_memory(dev, address, SCAN_READ_SIZE)
            
            if not data or len(data) < 4:
                continue
            
            # Check for known patterns
            region_type = identify_lock_data(data, address)
            
            if region_type:
                current_value = struct.unpack("<I", data[:4])[0]
                
                region_info = {
                    'address': address,
                    'description': description,
                    'region_type': region_type,
                    'current_value': current_value,
                    'current_hex': data[:16].hex(),
                    'is_locked': region_type in ('locked', 'text_locked'),
                    'unlocked_value': 0x00000000,
                    'locked_value': 0x00000001,
                }
                lock_regions.append(region_info)
                
                if verbose:
                    status = "LOCKED" if region_info['is_locked'] else "UNLOCKED"
                    print(f"    0x{address:08X}: {description} [{status}] - {region_type}")
        
        except Exception as e:
            if verbose and _DEBUG:
                print(f"    [!] Scan error at 0x{address:08X}: {e}")
    
    return lock_regions


def identify_lock_data(data: bytes, address: int) -> Optional[str]:
    """Identify the type of lock data at a memory location."""
    if len(data) < 4:
        return None
    
    # Check known binary patterns
    first_four = data[:4]
    
    if first_four == LOCK_PATTERNS['unlocked']:
        return 'unlocked'
    elif first_four == LOCK_PATTERNS['locked']:
        return 'locked'
    elif first_four == LOCK_PATTERNS['erased']:
        return 'erased'
    elif first_four == LOCK_PATTERNS['default']:
        # Default flash state - check if intentionally set
        if all(b == 0xFF for b in data[:8]):
            return 'default_erased'
        return 'default'
    
    # Check text patterns
    for pattern, desc in TEXT_PATTERNS.items():
        if data[:len(pattern)] == pattern:
            return 'text_locked' if pattern == b'LOCK' else 'text_unlocked'
    
    # Check for non-trivial data (could be lock information)
    non_zero = sum(1 for b in first_four if b != 0)
    non_ff = sum(1 for b in first_four if b != 0xFF)
    
    if 0 < non_zero < 4 and 0 < non_ff < 4:
        return 'unknown_data'
    
    return None


def get_lock_status(dev, lock_regions: List[Dict]) -> Dict[str, Any]:
    """
    Determine overall bootloader lock status.
    
    Returns:
        Dict with status details
    """
    if not lock_regions:
        return {
            'status': 'UNKNOWN',
            'locked_count': 0,
            'unlocked_count': 0,
            'details': 'No lock regions found'
        }
    
    locked = 0
    unlocked = 0
    unknown = 0
    
    for region in lock_regions:
        # Re-read to get current state
        data = read_memory(dev, region['address'], 4)
        if data and len(data) >= 4:
            value = struct.unpack("<I", data[:4])[0]
            
            if value == region['locked_value']:
                locked += 1
                region['current_value'] = value
                region['is_locked'] = True
            elif value == region['unlocked_value']:
                unlocked += 1
                region['current_value'] = value
                region['is_locked'] = False
            else:
                unknown += 1
    
    if locked > unlocked and locked > unknown:
        status = 'LOCKED'
    elif unlocked > locked and unlocked > unknown:
        status = 'UNLOCKED'
    elif unknown > locked and unknown > unlocked:
        status = 'UNKNOWN'
    else:
        status = 'MIXED'
    
    return {
        'status': status,
        'locked_count': locked,
        'unlocked_count': unlocked,
        'unknown_count': unknown,
        'total_regions': len(lock_regions)
    }


# =============================================================================
# FIXED: Bootloader unlock implementation
# =============================================================================
def oem_unlock(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Unlock bootloader with comprehensive safety checks."""
    print("\n[*] ========================================")
    print("[*] BOOTLOADER UNLOCK PROCEDURE")
    print("[*] ========================================")
    
    # Scan for lock regions
    lock_regions = scan_lock_regions(dev, verbose)
    
    if lock_regions:
        print(f"\n[+] Found {len(lock_regions)} lock region(s):")
        for region in lock_regions:
            status = "LOCKED" if region['is_locked'] else "UNLOCKED"
            print(f"    0x{region['address']:08X}: {region['description']} [{status}]")
    else:
        print("\n[*] No known lock regions found")
        print("[*] Will attempt standard unlock procedure")
    
    # Check current status
    current_status = get_lock_status(dev, lock_regions)
    print(f"\n[+] Current status: {current_status['status']}")
    
    if current_status['status'] == 'UNLOCKED':
        print("[*] Bootloader is already unlocked!")
        return
    
    # =========================================================================
    # SAFETY WARNINGS
    # =========================================================================
    warnings = [
        "⚠️  BOOTLOADER UNLOCK WARNINGS:",
        "",
        "  🔴 ALL USER DATA WILL BE ERASED!",
        "  🔴 Device warranty WILL BE VOIDED!",
        "  🔴 Security protections will be REDUCED!",
        "  🔴 May make device ineligible for OTA updates!",
        "  🔴 This operation is IRREVERSIBLE on most devices!",
        "  🔴 Custom firmware may BRICK device if incompatible!",
        "",
        "  ✅ Ensure you have a FULL BACKUP of all data",
        "  ✅ Ensure you have the correct firmware for recovery",
        "  ✅ Ensure device battery is sufficiently charged (>50%)",
    ]
    
    if not confirm_action('\n'.join(warnings), 'UNLOCK', force):
        print("[*] Unlock cancelled")
        return
    
    # Final data loss confirmation
    if not confirm_action(
        "FINAL CONFIRMATION: All user data will be PERMANENTLY ERASED!\n"
        "This CANNOT be undone!",
        'ERASE',
        force
    ):
        print("[*] Unlock cancelled")
        return
    
    # =========================================================================
    # Execute unlock
    # =========================================================================
    print("\n[*] Executing bootloader unlock...")
    
    try:
        # Build unlock payload
        unlock_payload = bytearray()
        unlock_payload.append(OEMOpcode.UNLOCK)
        unlock_payload.extend(struct.pack("<I", 0x01))  # Unlock flag
        
        # Add lock region information
        if lock_regions:
            unlock_payload.append(min(len(lock_regions), 255))
            for region in lock_regions[:255]:
                unlock_payload.extend(struct.pack("<I", region['address']))
                unlock_payload.extend(struct.pack("<I", region['unlocked_value']))
        else:
            unlock_payload.append(0)
        
        # Dispatch command
        resp = dispatch_command(dev, "OEM", bytes(unlock_payload), 
                                fallback_cmd="UNLOCK", timeout=OEM_TIMEOUT * 2)
        
        success, status_name, extra = is_success(resp)
        
        if success:
            print("[+] Unlock command accepted by device")
            
            # Brief delay for device to process
            print("[*] Waiting for device to process unlock...")
            time.sleep(1.0)
            
            # Verify unlock
            print("\n[*] Verifying unlock status...")
            verified = verify_unlock(dev, lock_regions, verbose)
            
            if verified:
                print("\n[+] ✅ Bootloader successfully unlocked!")
                print("[+] Device will now reboot and erase user data...")
            else:
                print("\n[!] ⚠️  Unlock verification incomplete")
                print("[*] Device may need manual reboot")
        else:
            print(f"\n[!] Unlock failed: {status_name}")
            if extra:
                print(f"[!] Response data: {extra[:64].hex()}")
    
    except Exception as e:
        print(f"\n[!] Unlock procedure error: {type(e).__name__}: {e}")
        if verbose and _DEBUG:
            traceback.print_exc()


# =============================================================================
# FIXED: Bootloader lock implementation
# =============================================================================
def oem_lock(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Lock bootloader with verification."""
    print("\n[*] ========================================")
    print("[*] BOOTLOADER LOCK PROCEDURE")
    print("[*] ========================================")
    
    # Scan current state
    lock_regions = scan_lock_regions(dev, verbose)
    current_status = get_lock_status(dev, lock_regions)
    
    print(f"\n[+] Current status: {current_status['status']}")
    
    if current_status['status'] == 'LOCKED':
        print("[*] Bootloader is already locked!")
        return
    
    # Safety warnings
    warnings = [
        "⚠️  BOOTLOADER LOCK WARNINGS:",
        "",
        "  🔴 Device will verify system integrity on boot",
        "  🔴 Only signed/OEM firmware will be allowed",
        "  🔴 Custom recoveries may be BLOCKED",
        "  🔴 Root access may be LOST",
        "  🔴 May require factory reset on some devices",
        "",
        "  ✅ Ensure you have stock firmware available for recovery",
        "  ✅ USB debugging should be enabled for recovery options",
    ]
    
    if not confirm_action('\n'.join(warnings), 'LOCK', force):
        print("[*] Lock cancelled")
        return
    
    # Execute lock
    print("\n[*] Executing bootloader lock...")
    
    try:
        lock_payload = bytearray()
        lock_payload.append(OEMOpcode.LOCK)
        lock_payload.extend(struct.pack("<I", 0x00))  # Lock flag
        
        if lock_regions:
            lock_payload.append(min(len(lock_regions), 255))
            for region in lock_regions[:255]:
                lock_payload.extend(struct.pack("<I", region['address']))
                lock_payload.extend(struct.pack("<I", region['locked_value']))
        else:
            lock_payload.append(0)
        
        resp = dispatch_command(dev, "OEM", bytes(lock_payload),
                                fallback_cmd="LOCK", timeout=OEM_TIMEOUT * 2)
        
        success, status_name, extra = is_success(resp)
        
        if success:
            print("[+] Lock command accepted")
            time.sleep(0.5)
            
            # Verify
            print("\n[*] Verifying lock status...")
            verified = verify_lock(dev, lock_regions, verbose)
            
            if verified:
                print("\n[+] ✅ Bootloader successfully locked!")
                print("[+] Security protections are now active")
            else:
                print("\n[!] ⚠️  Lock verification incomplete")
        else:
            print(f"\n[!] Lock failed: {status_name}")
    
    except Exception as e:
        print(f"\n[!] Lock procedure error: {type(e).__name__}: {e}")
        if verbose and _DEBUG:
            traceback.print_exc()


# =============================================================================
# FIXED: Unlock/Lock verification
# =============================================================================
def verify_unlock(dev, lock_regions: List[Dict], verbose: bool = False) -> bool:
    """Verify bootloader is unlocked by re-scanning lock regions."""
    if not lock_regions:
        print("[*] No lock regions to verify - assuming success")
        return True
    
    if verbose:
        print("[*] Re-scanning lock regions for verification...")
    
    verified = 0
    failed = 0
    
    for region in lock_regions:
        data = read_memory(dev, region['address'], 4)
        
        if data and len(data) >= 4:
            value = struct.unpack("<I", data[:4])[0]
            
            if value == region['unlocked_value']:
                verified += 1
                if verbose:
                    print(f"    ✅ 0x{region['address']:08X}: Unlocked")
            else:
                failed += 1
                if verbose:
                    print(f"    ❌ 0x{region['address']:08X}: Still locked (0x{value:08X})")
        else:
            failed += 1
            if verbose:
                print(f"    ⚠️  0x{region['address']:08X}: Cannot read")
    
    total = verified + failed
    ratio = verified / total if total > 0 else 0
    
    if verbose and total > 0:
        print(f"\n    Verified: {verified}/{total} ({ratio*100:.0f}%)")
    
    return ratio >= 0.5


def verify_lock(dev, lock_regions: List[Dict], verbose: bool = False) -> bool:
    """Verify bootloader is locked by re-scanning lock regions."""
    if not lock_regions:
        print("[*] No lock regions to verify - assuming success")
        return True
    
    if verbose:
        print("[*] Re-scanning lock regions for verification...")
    
    verified = 0
    failed = 0
    
    for region in lock_regions:
        data = read_memory(dev, region['address'], 4)
        
        if data and len(data) >= 4:
            value = struct.unpack("<I", data[:4])[0]
            
            if value == region['locked_value']:
                verified += 1
                if verbose:
                    print(f"    ✅ 0x{region['address']:08X}: Locked")
            else:
                failed += 1
                if verbose:
                    print(f"    ❌ 0x{region['address']:08X}: Still unlocked (0x{value:08X})")
        else:
            failed += 1
            if verbose:
                print(f"    ⚠️  0x{region['address']:08X}: Cannot read")
    
    total = verified + failed
    ratio = verified / total if total > 0 else 0
    
    if verbose and total > 0:
        print(f"\n    Verified: {verified}/{total} ({ratio*100:.0f}%)")
    
    return ratio >= 0.5


# =============================================================================
# FIXED: Warranty bit management
# =============================================================================
def oem_warranty(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Manage warranty bit status."""
    if args and args[0].lower() in ('set', 'clear'):
        operation = args[0].lower()
        print(f"\n[*] Warranty bit: {operation}")
        
        warnings = [
            "⚠️  WARRANTY BIT WARNING:",
            "  Modifying warranty bit may VOID device warranty",
            "  This operation is typically IRREVERSIBLE",
        ]
        
        if not confirm_action('\n'.join(warnings), 'WARRANTY', force):
            print("[*] Operation cancelled")
            return
        
        payload = struct.pack("<BI", OEMOpcode.WARRANTY, 
                             1 if operation == 'set' else 0)
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="WARRANTY")
        success, status_name, extra = is_success(resp)
        
        if success:
            print(f"[+] Warranty bit {operation} successful")
        else:
            print(f"[!] Operation failed: {status_name}")
    else:
        # Query status
        print("\n[*] Querying warranty status...")
        payload = struct.pack("<BI", OEMOpcode.WARRANTY, QUERY_FLAG)
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="WARRANTY")
        success, status_name, extra = is_success(resp)
        
        if success and len(extra) >= 4:
            bit_value = struct.unpack("<I", extra[:4])[0]
            status_str = "SET (Warranty Void)" if bit_value else "CLEAR (Warranty Valid)"
            print(f"[+] Warranty bit: {status_str} (0x{bit_value:08X})")
        else:
            print(f"[!] Query failed: {status_name}")


# =============================================================================
# FIXED: Secure boot management
# =============================================================================
def oem_secureboot(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Manage secure boot configuration."""
    if args and args[0].lower() in ('enable', 'disable'):
        operation = args[0].lower()
        print(f"\n[*] Secure boot: {operation}")
        
        warnings = [
            "⚠️  SECURE BOOT WARNING:",
            "  Secure boot verifies firmware signatures on boot",
            "  Disabling may REDUCE security",
            "  Enabling may BLOCK custom firmware",
        ]
        
        if not confirm_action('\n'.join(warnings), 'SECURE', force):
            print("[*] Operation cancelled")
            return
        
        payload = struct.pack("<BI", OEMOpcode.SECUREBOOT,
                             1 if operation == 'enable' else 0)
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="SECUREBOOT")
        success, status_name, extra = is_success(resp)
        
        if success:
            print(f"[+] Secure boot {operation}d successfully")
        else:
            print(f"[!] Operation failed: {status_name}")
    else:
        # Query status
        print("\n[*] Querying secure boot status...")
        payload = struct.pack("<BI", OEMOpcode.SECUREBOOT, QUERY_FLAG)
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="SECUREBOOT")
        success, status_name, extra = is_success(resp)
        
        if success and len(extra) >= 4:
            sb_status = struct.unpack("<I", extra[:4])[0]
            status_str = "ENABLED" if sb_status else "DISABLED"
            print(f"[+] Secure boot: {status_str}")
        else:
            print(f"[!] Query failed: {status_name}")


# =============================================================================
# FIXED: Device provisioning
# =============================================================================
def oem_provision(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Device provisioning operations."""
    provision_type = args[0].upper() if args else "DEFAULT"
    print(f"\n[*] Provisioning: {provision_type}")
    
    if provision_type in ("FACTORY", "CLEAN"):
        warnings = [
            "⚠️  FACTORY PROVISIONING WARNING:",
            "  This will RESET device to factory state",
            "  ALL data and settings will be LOST",
            "  Device will reboot after provisioning",
        ]
        
        if not confirm_action('\n'.join(warnings), 'PROVISION', force):
            print("[*] Provisioning cancelled")
            return
    
    payload = bytearray([OEMOpcode.PROVISION])
    payload.extend(provision_type.encode('ascii')[:16].ljust(16, b'\x00'))
    
    resp = dispatch_command(dev, "OEM", bytes(payload), fallback_cmd="PROVISION")
    success, status_name, extra = is_success(resp)
    
    if success:
        print("[+] Provisioning completed successfully")
    else:
        print(f"[!] Provisioning failed: {status_name}")


# =============================================================================
# FIXED: Device customization
# =============================================================================
def oem_customize(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Device customization operations."""
    if not args:
        print("[!] Specify customization parameters")
        print("[*] Usage: oem customize <param1> [param2] ...")
        return
    
    print(f"\n[*] Customization: {', '.join(args)}")
    
    payload = bytearray([OEMOpcode.CUSTOMIZE])
    for arg in args[:8]:  # Limit to 8 parameters
        payload.extend(arg.encode('ascii')[:32].ljust(32, b'\x00'))
    
    resp = dispatch_command(dev, "OEM", bytes(payload), fallback_cmd="CUSTOMIZE")
    success, status_name, extra = is_success(resp)
    
    if success:
        print("[+] Customization completed")
    else:
        print(f"[!] Customization failed: {status_name}")


# =============================================================================
# FIXED: OEM info query
# =============================================================================
def oem_info(dev, args: List[str], verbose: bool = False):
    """Query OEM device information."""
    print("\n[*] Querying OEM device information...")
    
    payload = struct.pack("<B", OEMOpcode.INFO)
    resp = dispatch_command(dev, "OEM", payload, fallback_cmd="OEM_INFO")
    success, status_name, extra = is_success(resp)
    
    if success and extra:
        info = parse_oem_info(extra)
        display_oem_info(info)
    else:
        print(f"[!] Info query failed: {status_name}")


def parse_oem_info(data: bytes) -> Dict[str, Any]:
    """Parse OEM information from response data."""
    info = {
        'device_model': 'Unknown',
        'hardware_revision': 'Unknown',
        'bootloader_version': 'Unknown',
        'baseband_version': 'Unknown',
        'serial_number': 'Unknown',
        'oem_features': []
    }
    
    try:
        if len(data) >= 144:
            info['device_model'] = data[0:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['hardware_revision'] = data[32:48].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['bootloader_version'] = data[48:80].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['baseband_version'] = data[80:112].decode('ascii', errors='ignore').rstrip('\x00').strip()
            info['serial_number'] = data[112:144].decode('ascii', errors='ignore').rstrip('\x00').strip()
            
            if len(data) >= 148:
                features = struct.unpack("<I", data[144:148])[0]
                feature_map = {
                    0x01: 'BOOTLOADER_UNLOCK',
                    0x02: 'SECURE_BOOT',
                    0x04: 'OEM_CUSTOMIZATION',
                    0x08: 'DEBUG_ACCESS',
                    0x10: 'FACTORY_PROVISIONED',
                    0x20: 'WARRANTY_BIT',
                }
                for bit, name in feature_map.items():
                    if features & bit:
                        info['oem_features'].append(name)
    except Exception as e:
        if _DEBUG:
            print(f"[!] OEM info parse error: {e}")
    
    return info


def display_oem_info(info: Dict[str, Any]):
    """Display OEM device information."""
    print(f"\n[+] OEM Device Information:")
    print(f"    Model:              {info['device_model']}")
    print(f"    Hardware Revision:  {info['hardware_revision']}")
    print(f"    Bootloader Version: {info['bootloader_version']}")
    print(f"    Baseband Version:   {info['baseband_version']}")
    print(f"    Serial Number:      {info['serial_number']}")
    
    if info['oem_features']:
        print(f"    Features:           {', '.join(info['oem_features'])}")
    else:
        print(f"    Features:           None detected")


# =============================================================================
# FIXED: Configuration management
# =============================================================================
def oem_config(dev, args: List[str], force: bool = False, verbose: bool = False):
    """OEM configuration management."""
    if not args:
        print("[!] Specify configuration operation")
        print("[*] Usage: oem config <get|set|list|delete> [key] [value]")
        return
    
    operation = args[0].lower()
    
    if operation == 'get' and len(args) > 1:
        key = args[1]
        print(f"\n[*] Getting config: {key}")
        
        payload = struct.pack("<BB", OEMOpcode.CONFIG, ConfigOp.GET)
        payload += key.encode('ascii')[:32].ljust(32, b'\x00')
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="CONFIG")
        success, status_name, extra = is_success(resp)
        
        if success and extra:
            value = extra.decode('ascii', errors='ignore').rstrip('\x00').strip()
            print(f"[+] {key} = {value}")
        else:
            print(f"[!] Config query failed: {status_name}")
    
    elif operation == 'set' and len(args) > 2:
        key = args[1]
        value = args[2]
        print(f"\n[*] Setting config: {key} = {value}")
        
        if not force:
            try:
                response = input("    Confirm? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    print("[*] Cancelled")
                    return
            except EOFError:
                print("[!] Interactive input not available")
                return
        
        payload = struct.pack("<BB", OEMOpcode.CONFIG, ConfigOp.SET)
        payload += key.encode('ascii')[:32].ljust(32, b'\x00')
        payload += value.encode('ascii')[:32].ljust(32, b'\x00')
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="CONFIG")
        success, status_name, extra = is_success(resp)
        
        if success:
            print(f"[+] {key} set successfully")
        else:
            print(f"[!] Config set failed: {status_name}")
    
    elif operation == 'list':
        print("\n[*] Listing configuration...")
        payload = struct.pack("<BB", OEMOpcode.CONFIG, ConfigOp.LIST)
        
        resp = dispatch_command(dev, "OEM", payload, fallback_cmd="CONFIG")
        success, status_name, extra = is_success(resp)
        
        if success and extra:
            print(f"[+] Configuration data ({len(extra)} bytes):")
            print(format_config_hex(extra))
        else:
            print(f"[!] Config list failed: {status_name}")
    
    else:
        print(f"[!] Unknown config operation: {operation}")
        print("[*] Valid operations: get, set, list, delete")


def format_config_hex(data: bytes) -> str:
    """Format configuration data for display."""
    lines = []
    for i in range(0, min(len(data), 256), 32):
        chunk = data[i:i+32]
        hex_str = chunk.hex()
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"    {i:04x}: {hex_str:<64} |{ascii_str}|")
    if len(data) > 256:
        lines.append(f"    ... ({len(data) - 256} more bytes)")
    return '\n'.join(lines)


# =============================================================================
# FIXED: Keys management
# =============================================================================
def oem_keys(dev, args: List[str], force: bool = False, verbose: bool = False):
    """Manage OEM signing keys."""
    operation = args[0].upper() if args else "LIST"
    print(f"\n[*] Key operation: {operation}")
    
    payload = bytearray([OEMOpcode.KEYS])
    payload.extend(operation.encode('ascii')[:16].ljust(16, b'\x00'))
    
    resp = dispatch_command(dev, "OEM", bytes(payload), fallback_cmd="KEYS")
    success, status_name, extra = is_success(resp)
    
    if success:
        print("[+] Key operation completed")
        if verbose and extra:
            print(f"    Data: {extra[:256].hex()}")
    else:
        print(f"[!] Key operation failed: {status_name}")


# =============================================================================
# FIXED: Debug operations
# =============================================================================
def oem_debug(dev, args: List[str], force: bool = False, verbose: bool = False):
    """OEM debugging operations."""
    operation = args[0].upper() if args else "STATUS"
    print(f"\n[*] Debug: {operation}")
    
    payload = bytearray([OEMOpcode.DEBUG])
    payload.extend(operation.encode('ascii')[:16].ljust(16, b'\x00'))
    
    resp = dispatch_command(dev, "OEM", bytes(payload), fallback_cmd="DEBUG")
    success, status_name, extra = is_success(resp)
    
    if success:
        print("[+] Debug operation completed")
        if verbose and extra:
            print(f"    Output: {extra.decode('ascii', errors='replace')[:500]}")
    else:
        print(f"[!] Debug operation failed: {status_name}")


# =============================================================================
# FIXED: Help display
# =============================================================================
def print_oem_help():
    """Display OEM command help."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    OEM COMMAND HELP                          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  SUBCOMMANDS:                                                ║
║                                                              ║
║  Bootloader Operations:                                      ║
║    unlock              Unlock bootloader (ERASES DATA!)      ║
║    lock                Lock bootloader                       ║
║                                                              ║
║  Security Operations:                                        ║
║    warranty [set|clear]  Manage warranty bit                 ║
║    secureboot [enable|disable]  Configure secure boot        ║
║    keys [operation]    Manage signing keys                   ║
║                                                              ║
║  Device Management:                                          ║
║    provision [type]    Device provisioning                   ║
║    customize <params>  Device customization                  ║
║    info                Show device information               ║
║                                                              ║
║  Configuration:                                              ║
║    config get <key>    Get configuration value               ║
║    config set <k> <v>  Set configuration value               ║
║    config list         List all configuration                ║
║                                                              ║
║  Debugging:                                                  ║
║    debug [command]     OEM debugging operations              ║
║    debug STATUS        Check debug status                    ║
║                                                              ║
║  Other:                                                      ║
║    help                Show this help                        ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  FLAGS:                                                      ║
║    --force, -f         Skip confirmation prompts             ║
║    --verbose, -v       Verbose output with scan details      ║
║    --loader <file>     Inject qslcl.bin before command       ║
╠══════════════════════════════════════════════════════════════╣
║  SAFETY WARNINGS:                                            ║
║    🔴 Unlock ERASES ALL USER DATA                           ║
║    🔴 Warranty changes may VOID WARRANTY                     ║
║    🔴 Secure boot changes affect SYSTEM SECURITY             ║
║    🔴 Provisioning may FACTORY RESET device                  ║
╠══════════════════════════════════════════════════════════════╣
║  EXAMPLES:                                                   ║
║    qslcl oem unlock                                          ║
║    qslcl oem lock --force                                    ║
║    qslcl oem warranty                                        ║
║    qslcl oem secureboot enable                               ║
║    qslcl oem info --verbose                                  ║
║    qslcl oem config get bootloader.status                    ║
╚══════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# FIXED: Subcommand dispatch table
# =============================================================================
OEM_SUBCOMMANDS = {
    'unlock': oem_unlock,
    'unlock-bootloader': oem_unlock,
    'lock': oem_lock,
    'lock-bootloader': oem_lock,
    'warranty': oem_warranty,
    'warranty-bit': oem_warranty,
    'secureboot': oem_secureboot,
    'secure-boot': oem_secureboot,
    'provision': oem_provision,
    'provisioning': oem_provision,
    'customize': oem_customize,
    'customization': oem_customize,
    'info': oem_info,
    'device-info': oem_info,
    'config': oem_config,
    'configuration': oem_config,
    'key': oem_keys,
    'keys': oem_keys,
    'signing-keys': oem_keys,
    'debug': oem_debug,
    'debugging': oem_debug,
    'help': lambda *args: print_oem_help(),
    '?': lambda *args: print_oem_help(),
}


# =============================================================================
# FIXED: Main OEM command function
# =============================================================================
def cmd_oem(args=None) -> int:
    """
    QSLCL OEM Command v2.0 (FIXED)
    
    Manages OEM operations including:
    - Bootloader unlock/lock with memory region scanning
    - Warranty bit management
    - Secure boot configuration
    - Device provisioning and customization
    - Configuration and key management
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print("[!] OEM: No arguments provided")
        print_oem_help()
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
    for attr in ['oem_subcommand', 'subcommand']:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                subcommand = val.lower().strip()
                break
    
    if not subcommand:
        print("[!] No subcommand specified")
        print_oem_help()
        return 1
    
    # Extract other args
    oem_args = getattr(args, 'oem_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    # =========================================================================
    # Check OEM command availability
    # =========================================================================
    if _use_qslcl and _QSLCLCMD_DB:
        has_oem = find_command("OEM") is not None
        if not has_oem and _DEBUG:
            print("[!] OEM command not in QSLCLCMD database")
            print("[*] Will use fallback commands")
    
    # =========================================================================
    # Dispatch subcommand
    # =========================================================================
    handler = OEM_SUBCOMMANDS.get(subcommand)
    
    if handler:
        try:
            handler(dev, oem_args, force, verbose)
            return 0
        except Exception as e:
            print(f"[!] OEM operation failed: {type(e).__name__}: {e}")
            if verbose and _DEBUG:
                traceback.print_exc()
            return 1
    else:
        print(f"[!] Unknown OEM subcommand: '{subcommand}'")
        print_oem_help()
        return 1


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_oem_arguments(parser) -> None:
    """Add OEM-specific arguments to an argument parser."""
    parser.add_argument(
        'oem_subcommand',
        nargs='?',
        help='OEM subcommand (unlock, lock, warranty, secureboot, info, config, etc.)'
    )
    parser.add_argument(
        'oem_args',
        nargs='*',
        help='Additional arguments for the OEM subcommand'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with memory scanning details'
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
    print("[*] oem.py - QSLCL OEM Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py oem <subcommand> [options]")
    print()
    print_oem_help()