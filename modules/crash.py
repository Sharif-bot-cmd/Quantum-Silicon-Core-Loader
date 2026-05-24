#!/usr/bin/env python3
"""
crash.py - QSLCL CRASH Command Module v2.2 (REWRITTEN)
Silent crash injection - Like MediaTek preloader crash but platform-agnostic
No kernel panics, no visible alerts - just silent execution halt
"""

import os
import sys
import struct
import time
import random
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
TIMEOUT = 5.0  # Short timeout - crash is immediate
MAX_ITER = 50

# Silent crash opcodes (minimal, stealthy)
OP_SILENT_HALT = 0x01      # Silent execution halt (no panic)
OP_PRELOADER_STYLE = 0x02  # MediaTek preloader-style crash
OP_BAD_BRANCH = 0x03       # Branch to invalid address
OP_INVALID_INSN = 0x04     # Execute invalid instruction
OP_REGISTER_CORRUPT = 0x05 # Corrupt critical register
OP_STACK_POISON = 0x06     # Poison stack pointer
OP_RETURN_HOOK = 0x07      # Hook return address to bad location
OP_DIVERSION = 0x08        # Diversion attack (redirect execution)
OP_MEM_FENCE = 0x09        # Memory fence violation
OP_TIMING_BOMB = 0x0A      # Delayed execution halt
OP_CACHE_POISON = 0x0B     # Poison instruction cache
OP_TLB_SHOOTDOWN = 0x0C    # TLB invalidation crash
OP_VECTOR_OVERRIDE = 0x0D  # Override exception vector
OP_DOUBLE_FAULT = 0x0E     # Double fault (silent on some architectures)

# Crash characteristics
CRASH_STYLES = {
    'silent': {
        'desc': 'No alert, no panic - just stops responding',
        'visible': False,
        'recoverable': True,
        'detectable': False,
    },
    'preloader': {
        'desc': 'MediaTek preloader style - silent USB disconnect',
        'visible': False,
        'recoverable': True,
        'detectable': False,
    },
    'halt': {
        'desc': 'Execution halt - device freezes with no output',
        'visible': False,
        'recoverable': True,
        'detectable': False,
    },
    'usb_kill': {
        'desc': 'USB controller crash - device disappears from bus',
        'visible': True,  # USB disconnects
        'recoverable': True,
        'detectable': True,  # Can see USB removal
    },
}

# Crash targets by SoC
SOC_CRASH_VECTORS = {
    'APPLE': {
        'preferred': 'SILENT_HALT',
        'vectors': [0x00000000, 0xFFFFFFF0, 0xFFFF0000],
        'registers': ['LR', 'PC', 'SP'],
    },
    'QUALCOMM': {
        'preferred': 'PRELOADER_STYLE',
        'vectors': [0x00000000, 0xFC000000, 0xFE000000],
        'registers': ['PC', 'LR', 'R14'],
    },
    'MEDIATEK': {
        'preferred': 'PRELOADER_STYLE',  # Their preloader crashes silently
        'vectors': [0x00000000, 0x00100000, 0x20000000],
        'registers': ['PC', 'LR', 'R15'],
    },
    'SAMSUNG': {
        'preferred': 'BAD_BRANCH',
        'vectors': [0x00000000, 0x80000000],
        'registers': ['PC', 'LR'],
    },
    'GENERIC': {
        'preferred': 'SILENT_HALT',
        'vectors': [0x00000000, 0xFFFFFFFF],
        'registers': ['PC', 'SP'],
    },
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    """Safety confirmation"""
    if force:
        return True
    print(f"\n[!] {msg}")
    try:
        return input(f"    Type '{req}': ") == req
    except (EOFError, KeyboardInterrupt):
        return False


def detect_soc(dev) -> str:
    """Auto-detect SoC family from device"""
    # Try to identify from VID
    if hasattr(dev, 'vid'):
        vid_map = {
            0x05AC: 'APPLE',
            0x05C6: 'QUALCOMM',
            0x0E8D: 'MEDIATEK',
            0x04E8: 'SAMSUNG',
            0x1F3A: 'ALLWINNER',
            0x2207: 'ROCKCHIP',
        }
        return vid_map.get(dev.vid, 'GENERIC')
    
    # Try from product string
    product = getattr(dev, 'product', '').upper()
    if 'APPLE' in product or 'IPHONE' in product or 'IPAD' in product:
        return 'APPLE'
    if 'QUALCOMM' in product or 'QCOM' in product:
        return 'QUALCOMM'
    if 'MEDIATEK' in product or 'MTK' in product:
        return 'MEDIATEK'
    if 'SAMSUNG' in product or 'EXYNOS' in product:
        return 'SAMSUNG'
    
    return 'GENERIC'


def crash_cmd(dev, opcode: int, data: bytes = b"", timeout: float = TIMEOUT) -> Tuple[bool, str, bytes]:
    """Send crash command - expects NO response (silent crash)"""
    payload = struct.pack("<B", opcode) + data
    
    try:
        if "CRASH" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "CRASH", payload, timeout=timeout)
        else:
            pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
            dev.write(pkt)
            _, resp = dev.read(timeout=timeout)
        
        # For silent crashes, we EXPECT no response or timeout
        # That means success!
        if resp is None:
            return True, "SILENT_CRASH", b""
        
        # If we got a response, crash might have failed
        status = decode_runtime_result(resp)
        return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        
    except Exception as e:
        # Exception/timeout is EXPECTED for silent crashes
        # The device stopped responding - that's success!
        if "timeout" in str(e).lower() or "no response" in str(e).lower():
            return True, "SILENT_CRASH", b""
        return False, str(e), b""


def verify_crash(dev, timeout: float = 3.0) -> dict:
    """
    Verify device is crashed (silently)
    Returns dict with crash status and details
    """
    result = {
        'crashed': False,
        'responsive': False,
        'usb_present': False,
        'silent': True,
        'recovery_needed': True,
    }
    
    # Try to ping the device
    try:
        if "PING" in QSLCLCMD_DB:
            resp = qslcl_dispatch(dev, "PING", b"", timeout=timeout)
            if resp:
                result['responsive'] = True
                result['crashed'] = False
                return result
    except:
        pass
    
    # No response = crashed
    result['responsive'] = False
    result['crashed'] = True
    
    # Check if USB device still present
    try:
        devs = scan_all()
        for d in devs:
            if hasattr(d, 'identifier') and d.identifier == getattr(dev, 'identifier', None):
                result['usb_present'] = True
                result['silent'] = True  # USB present but not responding = silent crash
                return result
    except:
        pass
    
    result['usb_present'] = False
    result['silent'] = False  # USB disconnected = visible crash
    
    return result


def wait_for_recovery(dev, timeout: float = 30.0, check_interval: float = 1.0) -> bool:
    """
    Wait for device to recover from silent crash
    Returns True if recovered
    """
    print(f"\n[*] Waiting for recovery ({timeout}s)...")
    start = time.time()
    
    while time.time() - start < timeout:
        elapsed = time.time() - start
        remaining = timeout - elapsed
        
        # Progress indicator
        bar_len = 30
        filled = int(bar_len * elapsed / timeout)
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"\r    [{bar}] {remaining:.1f}s", end="", flush=True)
        
        try:
            # Try to ping
            if "PING" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "PING", b"", timeout=1.0)
                if resp:
                    print(f"\n[+] Recovered after {elapsed:.1f}s")
                    return True
        except:
            pass
        
        # Try to rescan for device
        devs = scan_all()
        for d in devs:
            if hasattr(d, 'identifier') and d.identifier == getattr(dev, 'identifier', None):
                # Device still present but not responding - still crashed
                pass
        
        time.sleep(check_interval)
    
    print(f"\n[!] No recovery detected after {timeout}s")
    print("[*] Manual power cycle may be required")
    return False


# =============================================================================
# SILENT CRASH FUNCTIONS
# =============================================================================

def silent_halt(dev, force: bool = False, timeout: int = 5) -> bool:
    """Silent execution halt - device stops responding with no alert"""
    if not force:
        if not confirm(
            "⚠️  SILENT HALT - Device will freeze with no output\n"
            "Power cycle required to recover!\n"
            "Use only on devices you own!",
            'HALT', force
        ):
            return False
    
    print("\n[*] Triggering silent halt...")
    success, name, _ = crash_cmd(dev, OP_SILENT_HALT, timeout=timeout)
    
    if success:
        print("[+] Silent halt triggered - device frozen")
        verify = verify_crash(dev, timeout=2.0)
        if verify['crashed']:
            print("    Confirmed: device not responding")
        return True
    
    print(f"[!] Halt may have failed: {name}")
    return False


def preloader_style(dev, force: bool = False, timeout: int = 5) -> bool:
    """
    MediaTek preloader-style silent crash
    USB stays connected but device stops responding
    """
    if not force:
        if not confirm(
            "⚠️  PRELOADER-STYLE CRASH - Like MediaTek BROM crash\n"
            "Device will appear connected but not respond\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'PRELOADER', force
        ):
            return False
    
    print("\n[*] Triggering preloader-style crash...")
    
    # Auto-detect SoC for optimized vector
    soc = detect_soc(dev)
    vectors = SOC_CRASH_VECTORS.get(soc, SOC_CRASH_VECTORS['GENERIC'])['vectors']
    
    # Try multiple vectors for better success
    for vector in vectors[:3]:
        data = struct.pack("<I", vector)
        success, name, _ = crash_cmd(dev, OP_PRELOADER_STYLE, data, timeout=timeout)
        if success:
            print(f"[+] Preloader crash at vector 0x{vector:08X}")
            return True
        time.sleep(0.1)
    
    # Fallback to default
    success, name, _ = crash_cmd(dev, OP_PRELOADER_STYLE, timeout=timeout)
    if success:
        print("[+] Preloader crash triggered")
        return True
    
    print(f"[!] Crash failed: {name}")
    return False


def bad_branch(dev, target: int = None, force: bool = False, timeout: int = 5) -> bool:
    """Branch to invalid address - causes silent execution redirection"""
    if target is None:
        soc = detect_soc(dev)
        vectors = SOC_CRASH_VECTORS.get(soc, SOC_CRASH_VECTORS['GENERIC'])['vectors']
        target = vectors[0] if vectors else 0x00000000
    
    if not force:
        if not confirm(
            f"⚠️  BAD BRANCH - Redirect to 0x{target:08X}\n"
            "Device will jump to invalid code\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'BRANCH', force
        ):
            return False
    
    print(f"\n[*] Branching to invalid address: 0x{target:08X}")
    data = struct.pack("<I", target)
    success, name, _ = crash_cmd(dev, OP_BAD_BRANCH, data, timeout=timeout)
    
    if success:
        print("[+] Bad branch executed - device crashed")
        return True
    
    print(f"[!] Branch failed: {name}")
    return False


def invalid_instruction(dev, insn: int = None, force: bool = False, timeout: int = 5) -> bool:
    """Execute invalid instruction - causes undefined behavior"""
    if insn is None:
        # Architecture-specific invalid instructions
        soc = detect_soc(dev)
        if soc == 'APPLE':
            insn = 0xD4200000  # BRK #0 on ARM64
        elif soc in ('QUALCOMM', 'MEDIATEK'):
            insn = 0xE7F000F0  # Undefined instruction on ARM
        else:
            insn = 0x00000000  # Null instruction
    
    if not force:
        if not confirm(
            f"⚠️  INVALID INSTRUCTION - Execute 0x{insn:08X}\n"
            "Device will hit undefined opcode\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'INSN', force
        ):
            return False
    
    print(f"\n[*] Executing invalid instruction: 0x{insn:08X}")
    data = struct.pack("<I", insn)
    success, name, _ = crash_cmd(dev, OP_INVALID_INSN, data, timeout=timeout)
    
    if success:
        print("[+] Invalid instruction executed - device crashed")
        return True
    
    print(f"[!] Instruction failed: {name}")
    return False


def register_corruption(dev, reg: str = None, value: int = None, force: bool = False, timeout: int = 5) -> bool:
    """Corrupt critical register - causes execution derailment"""
    soc = detect_soc(dev)
    registers = SOC_CRASH_VECTORS.get(soc, SOC_CRASH_VECTORS['GENERIC'])['registers']
    target_reg = reg.upper() if reg else registers[0] if registers else 'PC'
    
    if value is None:
        value = 0xDEADBEEF
    
    if not force:
        if not confirm(
            f"⚠️  REGISTER CORRUPTION - {target_reg} = 0x{value:08X}\n"
            "Device will have corrupted execution state\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'REG', force
        ):
            return False
    
    print(f"\n[*] Corrupting register: {target_reg} = 0x{value:08X}")
    data = target_reg.encode()[:4].ljust(4, b'\x00') + struct.pack("<I", value)
    success, name, _ = crash_cmd(dev, OP_REGISTER_CORRUPT, data, timeout=timeout)
    
    if success:
        print(f"[+] {target_reg} corrupted - device crashed")
        return True
    
    print(f"[!] Corruption failed: {name}")
    return False


def timing_bomb(dev, delay_ms: int = 100, force: bool = False, timeout: int = 10) -> bool:
    """
    Delayed silent crash - crashes after specified milliseconds
    Useful for testing recovery timing
    """
    delay_ms = max(10, min(10000, delay_ms))
    
    if not force:
        if not confirm(
            f"⚠️  TIMING BOMB - Will crash in {delay_ms}ms\n"
            "Device will stop responding after delay\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'BOMB', force
        ):
            return False
    
    print(f"\n[*] Setting timing bomb: {delay_ms}ms delay")
    data = struct.pack("<I", delay_ms)
    success, name, _ = crash_cmd(dev, OP_TIMING_BOMB, data, timeout=timeout + (delay_ms / 1000))
    
    if success:
        print(f"[+] Timing bomb set - device will crash in {delay_ms}ms")
        # Wait for crash to happen
        time.sleep(delay_ms / 1000)
        verify = verify_crash(dev, timeout=2.0)
        if verify['crashed']:
            print("    Confirmed: device crashed as scheduled")
        return True
    
    print(f"[!] Timing bomb failed: {name}")
    return False


def double_fault(dev, force: bool = False, timeout: int = 5) -> bool:
    """
    Double fault - causes immediate silent halt on most architectures
    Most reliable method across different SoCs
    """
    if not force:
        if not confirm(
            "⚠️  DOUBLE FAULT - Most reliable silent crash\n"
            "Device will halt immediately\n"
            "Power cycle required!\n"
            "Use only on devices you own!",
            'DFAULT', force
        ):
            return False
    
    print("\n[*] Triggering double fault...")
    success, name, _ = crash_cmd(dev, OP_DOUBLE_FAULT, timeout=timeout)
    
    if success:
        print("[+] Double fault triggered - device halted")
        return True
    
    print(f"[!] Double fault failed: {name}")
    return False


def auto_crash(dev, force: bool = False, timeout: int = 5) -> bool:
    """Auto-select best crash method for detected SoC"""
    soc = detect_soc(dev)
    preferred = SOC_CRASH_VECTORS.get(soc, SOC_CRASH_VECTORS['GENERIC'])['preferred']
    
    print(f"\n[*] Auto-selected crash method for {soc}: {preferred}")
    
    methods = {
        'SILENT_HALT': silent_halt,
        'PRELOADER_STYLE': preloader_style,
        'BAD_BRANCH': bad_branch,
    }
    
    method = methods.get(preferred, silent_halt)
    return method(dev, force, timeout)


# =============================================================================
# SUBCOMMANDS
# =============================================================================

def cmd_list(dev, args, force, timeout):
    """List silent crash methods"""
    print("\n[*] Silent Crash Methods:\n")
    print("  ┌─────────────────┬────────────────────────────────────────────┐")
    print("  │ Method          │ Description                                │")
    print("  ├─────────────────┼────────────────────────────────────────────┤")
    print("  │ silent          │ Silent halt - device freezes with no alert │")
    print("  │ preloader       │ MediaTek preloader-style silent crash      │")
    print("  │ branch          │ Branch to invalid address                  │")
    print("  │ invalid         │ Execute invalid instruction                │")
    print("  │ register        │ Corrupt critical register                  │")
    print("  │ timing          │ Delayed crash (timing bomb)                │")
    print("  │ double          │ Double fault - most reliable               │")
    print("  │ auto            │ Auto-select best for your SoC              │")
    print("  └─────────────────┴────────────────────────────────────────────┘")
    
    print("\n[*] Crash Characteristics:")
    for name, info in CRASH_STYLES.items():
        print(f"    {name:<12} {info['desc']}")
    
    return True


def cmd_silent(dev, args, force, timeout):
    """Silent halt crash"""
    return silent_halt(dev, force, timeout)


def cmd_preloader(dev, args, force, timeout):
    """Preloader-style crash (like MediaTek)"""
    return preloader_style(dev, force, timeout)


def cmd_branch(dev, args, force, timeout):
    """Bad branch crash"""
    target = int(args[0], 16) if args and args[0].startswith('0x') else (int(args[0]) if args else None)
    return bad_branch(dev, target, force, timeout)


def cmd_invalid(dev, args, force, timeout):
    """Invalid instruction crash"""
    insn = int(args[0], 16) if args and args[0].startswith('0x') else (int(args[0]) if args else None)
    return invalid_instruction(dev, insn, force, timeout)


def cmd_register(dev, args, force, timeout):
    """Register corruption crash"""
    reg = args[0] if args else None
    val = int(args[1], 16) if len(args) > 1 and args[1].startswith('0x') else (int(args[1]) if len(args) > 1 else None)
    return register_corruption(dev, reg, val, force, timeout)


def cmd_timing(dev, args, force, timeout):
    """Timing bomb crash"""
    delay = int(args[0]) if args else 100
    return timing_bomb(dev, delay, force, timeout + (delay // 1000))


def cmd_double(dev, args, force, timeout):
    """Double fault crash"""
    return double_fault(dev, force, timeout)


def cmd_auto(dev, args, force, timeout):
    """Auto-select best crash method"""
    return auto_crash(dev, force, timeout)


def cmd_verify(dev, args, force, timeout):
    """Verify crash state"""
    print("\n[*] Verifying crash state...")
    
    result = verify_crash(dev, timeout=3.0)
    
    if result['crashed']:
        print("[+] Device is crashed")
        print(f"    Responsive: {'No' if not result['responsive'] else 'Yes'}")
        print(f"    USB present: {'Yes' if result['usb_present'] else 'No'}")
        print(f"    Crash type: {'Silent' if result['silent'] else 'Visible'}")
    else:
        print("[+] Device is responsive (not crashed)")
    
    return result['crashed']


def cmd_recover(dev, args, force, timeout):
    """Wait for device to recover from crash"""
    wait_time = int(args[0]) if args else 30
    recovered = wait_for_recovery(dev, wait_time)
    
    if recovered:
        print("[+] Device recovered!")
    else:
        print("[!] Device did not recover - manual power cycle needed")
    
    return recovered


def cmd_test(dev, args, force, timeout):
    """Test suite - try all crash methods"""
    print("\n[*] Crash Test Suite")
    print("    Testing each method for 5 seconds...\n")
    
    methods = [
        ('silent', silent_halt),
        ('preloader', preloader_style),
        ('double', double_fault),
        ('auto', auto_crash),
    ]
    
    results = {}
    
    for name, method in methods:
        print(f"\n  Testing: {name}")
        try:
            success = method(dev, force=True, timeout=3)
            results[name] = success
            
            if success:
                print(f"    ✓ {name} - SUCCESS")
                # Wait a bit before next test
                time.sleep(2)
            else:
                print(f"    ✗ {name} - FAILED")
        except Exception as e:
            print(f"    ✗ {name} - ERROR: {e}")
            results[name] = False
        
        # Re-scan for device if needed
        devs = scan_all()
        if devs:
            dev = devs[0]
    
    # Summary
    print("\n[*] Test Summary:")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"    Passed: {passed}/{total} ({passed*100//total if total else 0}%)")
    
    for name, success in results.items():
        print(f"    {'✓' if success else '✗'} {name}")
    
    return passed > 0


# =============================================================================
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
    'list': cmd_list, 'ls': cmd_list, 'methods': cmd_list,
    'silent': cmd_silent, 'halt': cmd_silent, 'freeze': cmd_silent,
    'preloader': cmd_preloader, 'mtk': cmd_preloader, 'brom': cmd_preloader,
    'branch': cmd_branch, 'jump': cmd_branch,
    'invalid': cmd_invalid, 'illegal': cmd_invalid, 'udf': cmd_invalid,
    'register': cmd_register, 'reg': cmd_register,
    'timing': cmd_timing, 'bomb': cmd_timing, 'delayed': cmd_timing,
    'double': cmd_double, 'dfault': cmd_double,
    'auto': cmd_auto, 'smart': cmd_auto,
    'verify': cmd_verify, 'check': cmd_verify, 'status': cmd_verify,
    'recover': cmd_recover, 'wait': cmd_recover,
    'test': cmd_test, 'suite': cmd_test,
}


# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_crash(args=None) -> int:
    """
    QSLCL CRASH - Silent crash injection (like MediaTek preloader)
    
    Examples:
        crash list                      - List crash methods
        crash silent                    - Silent halt (device freezes)
        crash preloader                 - Preloader-style silent crash
        crash branch 0x00000000         - Branch to invalid address
        crash invalid 0xDEADBEEF        - Execute invalid instruction
        crash register PC 0xDEADBEEF    - Corrupt register
        crash timing 500                - Crash after 500ms delay
        crash double                    - Double fault (most reliable)
        crash auto                      - Auto-select best method
        crash verify                    - Check if device crashed
        crash recover 30                - Wait 30s for recovery
        crash test                      - Test all methods
    
    ⚠️  These are SILENT crashes - device will freeze with no alert!
    ⚠️  Power cycle required to recover!
    ⚠️  Use only on devices you own!
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: crash <list|silent|preloader|branch|invalid|register|timing|double|auto|verify|recover|test>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'crash_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    cargs = getattr(args, 'crash_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    timeout = max(3, getattr(args, 'timeout', 10) or 10)
    
    if not sub or sub in ('help', '?'):
        print("[*] Crash Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<12} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    # Global safety confirmation for any crash operation
    if sub not in ('list', 'verify', 'recover', 'test'):
        if not force:
            if not confirm(
                "⚠️  SILENT CRASH OPERATION\n"
                "Device will FREEZE with NO ALERT\n"
                "Power cycle REQUIRED to recover\n"
                "Data loss possible\n\n"
                "Use only on devices you own!",
                'CRASH', force
            ):
                return 0
    
    try:
        return 0 if handler(dev, cargs, force, timeout) else 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] crash.py - QSLCL CRASH Command Module (Silent) v2.2")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py crash <subcommand> [args]")