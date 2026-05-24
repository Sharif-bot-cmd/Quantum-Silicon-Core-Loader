#!/usr/bin/env python3
"""
bypass.py - QSLCL BYPASS Command Module v2.1 (CLEANED)
Security bypass engine with auto-detection and enforcement point analysis
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
TIMEOUT = 20.0

# Opcodes
OP_TEST = 0x00
OP_DEVICE_INFO = 0x01
OP_MEMORY_SCAN = 0x02
OP_ENFORCEMENT = 0x03
OP_REGION_CHECK = 0x04
OP_APPLE = 0x11
OP_SOC = 0x20
OP_SECUREBOOT = 0x21
OP_APRR = 0x30
OP_SEP = 0x31
OP_KPP = 0x32
OP_AMFI = 0x33
OP_SANDBOX = 0x34
OP_CSR = 0x35
OP_TEMP = 0x40
OP_QUANTUM = 0x50

# NEW OPCODES - Add these:
OP_WATCHDOG = 0x60        # Watchdog disable
OP_SMMU = 0x61            # SMMU bypass
OP_TRUSTZONE = 0x62       # TrustZone bypass
OP_SECURE_MONITOR = 0x63  # Secure monitor bypass
OP_FUSE = 0x64            # Fuse read/bypass
OP_OTP = 0x65             # OTP (One-Time Programmable) access
OP_DEBUG_LOCK = 0x66      # Debug lock disable
OP_EFUSE = 0x67           # eFuse control
OP_BOOTROM = 0x68         # BootROM access
OP_FIRMWARE = 0x69        # Firmware extraction
OP_HARDWARE_ID = 0x6A     # Hardware ID reading
OP_CHIP_REV = 0x6B        # Chip revision detection
OP_TEMP_SENSOR = 0x6C     # Temperature sensor read
OP_VOLTAGE_CTRL = 0x6D    # Voltage control
OP_CLOCK_CTRL = 0x6E      # Clock control
OP_POWER_MGMT = 0x6F      # Power management
OP_DMA_ENGINE = 0x70      # DMA engine control
OP_CRYPTO_ENGINE = 0x71   # Crypto engine bypass
OP_RNG_ENGINE = 0x72      # RNG engine access
OP_PCIE_CONFIG = 0x73     # PCIe configuration
OP_USB4_TUNNEL = 0x74     # USB4 v2.0 tunnel control
OP_PAM4_ENCODE = 0x75     # PAM4 encoding control
OP_ATTESTATION = 0x76     # Attestation bypass
OP_CMA_MEASURE = 0x77     # Component measurement
OP_DPP_CONFIG = 0x78      # Data Protection Profile config
OP_QUANTUM_RNG = 0x79     # Quantum RNG access
OP_AI_ACCEL = 0x7A        # AI accelerator control
OP_NPU_CTRL = 0x7B        # NPU control
OP_GPU_CTRL = 0x7C        # GPU control
OP_DISPLAY_ENGINE = 0x7D  # Display engine control
OP_AUDIO_DSP = 0x7E       # Audio DSP control
OP_SENSOR_HUB = 0x7F      # Sensor hub access

SOC_FAMILIES = {
    # Apple Silicon
    'APPLE': {
        'features': ['SEP', 'APRR', 'KPP', 'AMFI', 'SANDBOX', 'PAC', 'DIT', 'PPL', 'SCEP'],
        'base': 0x80000000,
        'watchdog_offsets': [0x20E00000, 0x20E01000, 0x20E02000],
        'versions': ['A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A18', 'M1', 'M2', 'M3', 'M4'],
        'encryption_required': ['A18', 'M4']
    },
    # Qualcomm
    'QUALCOMM': {
        'features': ['TRUSTZONE', 'SECUREBOOT', 'QFP', 'HLOS', 'TZAPP', 'QTEE', 'SMMU'],
        'base': 0xFC400000,
        'watchdog_offsets': [0x02000000, 0x02000004, 0x02000008, 0x0200000C],
        'versions': ['SDM845', 'SM8150', 'SM8250', 'SM8350', 'SM8450', 'SM8550', 'SM8650', 'SM8750'],
        'encryption_required': []
    },
    # MediaTek
    'MEDIATEK': {
        'features': ['TRUSTZONE', 'SECUREBOOT', 'TEE', 'DAM', 'MSDC', 'PMIC'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10000000, 0x10000004, 0x1C000000, 0x1C000004, 0x1C000008],
        'versions': ['MT6765', 'MT6785', 'MT6833', 'MT6853', 'MT6873', 'MT6893', 'MT6983', 'MT6985'],
        'encryption_required': []
    },
    # Samsung Exynos
    'SAMSUNG': {
        'features': ['TRUSTZONE', 'KNOX', 'RKP', 'DEFEX', 'SEFOR', 'TIMA'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10060000, 0x10060004, 0x10070000, 0x10070004],
        'versions': ['Exynos2100', 'Exynos2200', 'Exynos2400', 'Exynos2500'],
        'encryption_required': []
    },
    # Huawei HiSilicon
    'HISILICON': {
        'features': ['TRUSTZONE', 'HISE', 'TEE', 'ITEE', 'SECBOOT'],
        'base': 0x80000000,
        'watchdog_offsets': [0xE0000000, 0xE0000004, 0xE000A000],
        'versions': ['Kirin980', 'Kirin990', 'Kirin9000', 'Kirin9010'],
        'encryption_required': []
    },
    # Google Tensor
    'TENSOR': {
        'features': ['TRUSTZONE', 'TITAN', 'M2', 'SECUREBOOT', 'AVB'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10000000, 0x10000004, 0x10000008],
        'versions': ['Tensor1', 'Tensor2', 'Tensor3', 'Tensor4'],
        'encryption_required': []
    },
    # NVIDIA Tegra
    'NVIDIA': {
        'features': ['TRUSTZONE', 'SE', 'FUSE', 'ODM', 'MINERVA'],
        'base': 0x80000000,
        'watchdog_offsets': [0x60005000, 0x60005004, 0x60005100],
        'versions': ['TegraX1', 'TegraX2', 'TegraOrin', 'TegraThor'],
        'encryption_required': []
    },
    # Rockchip
    'ROCKCHIP': {
        'features': ['TRUSTZONE', 'OTP', 'DDR', 'PMU'],
        'base': 0x80000000,
        'watchdog_offsets': [0x20000000, 0x20000004, 0x20004000],
        'versions': ['RK3588', 'RK3588S', 'RK3568', 'RK3399'],
        'encryption_required': []
    },
    # Allwinner
    'ALLWINNER': {
        'features': ['TRUSTZONE', 'SID', 'SMHC'],
        'base': 0x80000000,
        'watchdog_offsets': [0x01C20000, 0x01C20004, 0x01C20CA0],
        'versions': ['A64', 'H6', 'H616', 'H728'],
        'encryption_required': []
    },
    # Broadcom
    'BROADCOM': {
        'features': ['TRUSTZONE', 'BSE', 'AVS'],
        'base': 0x80000000,
        'watchdog_offsets': [0x18000000, 0x18000004, 0x18001000],
        'versions': ['BCM2711', 'BCM2712', 'BCM4908'],
        'encryption_required': []
    },
    # Intel
    'INTEL': {
        'features': ['TXT', 'SGX', 'TDX', 'BOOTGUARD', 'ME'],
        'base': 0x80000000,
        'watchdog_offsets': [0xFED00000, 0xFED00004, 0xFED01000],
        'versions': ['TGL', 'ADL', 'RPL', 'MTL', 'ARL'],
        'encryption_required': []
    },
    # AMD
    'AMD': {
        'features': ['SMM', 'SVM', 'SEV', 'PSP', 'FTPM'],
        'base': 0x80000000,
        'watchdog_offsets': [0xFEB00000, 0xFEB00004],
        'versions': ['Zen3', 'Zen4', 'Zen5'],
        'encryption_required': []
    },
    # Generic ARM
    'GENERIC_ARM': {
        'features': ['SECUREBOOT', 'TRUSTZONE', 'MEMORY_PROTECTION'],
        'base': 0x80000000,
        'watchdog_offsets': [0x40000000, 0x40000004, 0x40001000],
        'versions': ['Cortex-A', 'Cortex-M', 'Cortex-R', 'Neoverse'],
        'encryption_required': []
    },
    # RISC-V
    'RISCV': {
        'features': ['PMP', 'SMEPMP', 'SMSEC', 'PMPMPU'],
        'base': 0x80000000,
        'watchdog_offsets': [0x10000000, 0x10000004, 0x1000A000],
        'versions': ['U74', 'S76', 'S85', 'P550', 'P650'],
        'encryption_required': []
    },
    # Generic (Fallback)
    'GENERIC': {
        'features': ['SECUREBOOT', 'MEMORY_PROTECTION'],
        'base': 0x80000000,
        'watchdog_offsets': [0x80000000, 0x80001000, 0x80002000],
        'versions': [],
        'encryption_required': []
    },
}

# Module cache
_MEMORY_CACHE: Dict[str, Dict] = {}
_ENFORCEMENT_CACHE: Dict[str, List] = {}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def confirm(msg: str, req: str, force: bool) -> bool:
    if force: return True
    print(f"\n[!] {msg}")
    try: return input(f"    Type '{req}': ") == req
    except: return False

def bypass_cmd(dev, payload: bytes) -> Tuple[bool, str, bytes]:
    """Send bypass command"""
    for attempt in range(2):
        try:
            if "BYPASS" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "BYPASS", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt == 0: time.sleep(0.1)
    
    return False, "NO_RESPONSE", b""

def cache_key(dev) -> str:
    return getattr(dev, 'serial', None) or getattr(dev, 'identifier', 'default')

def run_bypass(dev, opcode: int, name: str, data: bytes = b"", force: bool = False) -> bool:
    """Execute bypass with consistent output"""
    payload = struct.pack("<B", opcode) + data
    ok, status_name, _ = bypass_cmd(dev, payload)
    
    if ok:
        print(f"[+] {name} bypass successful")
    else:
        print(f"[!] {name} bypass failed: {status_name}")
    
    return ok

# =============================================================================
# AUTO-DETECTION
# =============================================================================
def identify_device(dev) -> dict:
    """Identify device type and SOC"""
    info = {'device_name': 'Unknown', 'soc_family': 'GENERIC'}
    
    try:
        ok, _, data = bypass_cmd(dev, struct.pack("<B", OP_DEVICE_INFO))
        if ok and data and len(data) >= 56:
            info['device_name'] = data[0:32].decode('ascii', 'ignore').rstrip('\x00').strip()
            soc_name = data[32:48].decode('ascii', 'ignore').rstrip('\x00').strip()
            
            soc_upper = soc_name.upper()
            if any(k in soc_upper for k in ['APPLE', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A18']):
                info['soc_family'] = 'APPLE'
            elif any(k in soc_upper for k in ['QUALCOMM', 'SD', 'MSM', 'QCM', 'SM']):
                info['soc_family'] = 'QUALCOMM'
            elif any(k in soc_upper for k in ['EXYNOS', 'S5E']):
                info['soc_family'] = 'SAMSUNG'
            elif any(k in soc_upper for k in ['KIRIN', 'HI3']):
                info['soc_family'] = 'HISILICON'
    except: pass
    
    return info

def scan_offsets(dev, info: dict) -> dict:
    """Scan for memory offsets"""
    keys = ['secure_boot', 'memory_protection', 'crypto_engine',
            'kernel_integrity', 'enclave', 'code_signing', 'recovery']
    offsets = {k: {'found': False, 'address': 0} for k in keys}
    
    try:
        base = SOC_FAMILIES.get(info.get('soc_family', 'GENERIC'), {}).get('base', 0x80000000)
        payload = struct.pack("<B", OP_MEMORY_SCAN) + struct.pack("<II", base, 0x10000000)
        ok, _, data = bypass_cmd(dev, payload)
        
        if ok and data and len(data) >= 28:
            vals = struct.unpack("<7I", data[:28])
            for i, v in enumerate(vals):
                if i < len(keys) and v > 0:
                    offsets[keys[i]] = {'found': True, 'address': v}
        
        # Heuristic fallback
        patterns = {
            'APPLE': [(0x80000000, 'secure_boot'), (0x80200000, 'enclave')],
            'QUALCOMM': [(0xFC400000, 'secure_boot'), (0xFD000000, 'memory_protection')],
            'GENERIC': [(0x80000000, 'secure_boot'), (0x81000000, 'memory_protection')],
        }
        for addr, key in patterns.get(info.get('soc_family', 'GENERIC'), patterns['GENERIC']):
            if not offsets[key]['found']:
                ok2, _, d2 = bypass_cmd(dev, struct.pack("<BII", OP_REGION_CHECK, addr, 0x1000))
                if ok2 and d2 and len(d2) >= 4 and struct.unpack("<I", d2[:4])[0]:
                    offsets[key] = {'found': True, 'address': addr}
    except: pass
    
    return offsets

def detect_points(dev, offsets: dict) -> List[dict]:
    """Detect enforcement points"""
    points = []
    
    for otype, odata in offsets.items():
        if odata.get('found'):
            payload = struct.pack("<B", OP_ENFORCEMENT) + struct.pack("<I", odata['address'])
            ok, _, data = bypass_cmd(dev, payload)
            if ok and data and len(data) >= 16:
                etype = data[0:4].decode('ascii', 'ignore').rstrip('\x00').strip()
                level = struct.unpack("<I", data[4:8])[0]
                desc = data[8:16].decode('ascii', 'ignore').rstrip('\x00').strip()
                if etype:
                    points.append({'type': etype, 'address': odata['address'],
                                  'level': level, 'desc': desc})
    
    return points

def auto_detect(dev, verbose: bool = True) -> dict:
    """Run comprehensive auto-detection"""
    if verbose: print("\n[*] Auto-Detection:")
    
    # Phase 1: Device ID
    if verbose: print("    Phase 1: Device identification...")
    info = identify_device(dev)
    if verbose: print(f"      {info.get('device_name', '?')} ({info.get('soc_family', '?')})")
    
    # Phase 2: Memory offsets
    if verbose: print("    Phase 2: Memory scan...")
    offsets = scan_offsets(dev, info)
    found = sum(1 for o in offsets.values() if o['found'])
    if verbose: print(f"      {found} offsets found")
    
    # Phase 3: Enforcement points
    if verbose: print("    Phase 3: Enforcement points...")
    points = detect_points(dev, offsets)
    if verbose: print(f"      {len(points)} points detected")
    
    # Phase 4: Security assessment
    score = sum(p.get('level', 0) for p in points)
    if score > 80: security = "VERY HIGH"
    elif score > 60: security = "HIGH"
    elif score > 30: security = "MEDIUM"
    else: security = "LOW"
    if verbose: print(f"    Security: {security}")
    
    results = {
        'device': info, 'offsets': offsets, 'points': points,
        'security': security, 'score': score,
    }
    
    # Cache
    key = cache_key(dev)
    _MEMORY_CACHE[key] = results
    _ENFORCEMENT_CACHE[key] = points
    
    return results

# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(dev, args, force):
    """List bypass methods"""
    print(f"""
[*] Bypass Methods:

    === DETECTION ===
    detect/scan        Auto-detection scan
    offsets            Show memory offsets
    enforce/points     Show enforcement points

    === SOC BYPASSES ===
    apple [SOC]        Apple A12+ bypass (A12/A13/A14/A15/A16/A17/A18/M1/M2/M3)
    soc [type]         Universal SOC bypass (APPLE/QUALCOMM/MEDIATEK/SAMSUNG/TENSOR...)
    trustzone [mode]   TrustZone/TEE secure world bypass
    secmon [mode]      Secure monitor (EL3) bypass
    smmu               SMMU memory protection bypass

    === BOOT & FIRMWARE ===
    secureboot         Secure boot bypass
    bootrom [addr]     BootROM (mask ROM) access
    firmware [region]  Firmware extraction
    watchdog           Watchdog timer disable (auto-detects SoC)

    === APPLE-SPECIFIC ===
    aprr               APRR bypass (Apple)
    sep                SEP bypass (Apple)
    kpp                KPP bypass (Apple)
    amfi [mode]        AMFI bypass (Apple)
    sandbox            Sandbox bypass
    csr                CSR bypass

    === HARDWARE ACCESS ===
    fuse [bank]        Fuse read/bypass
    efuse [action]     eFuse control (READ/PROGRAM)
    otp [offset]       OTP memory access
    debuglock          Debug lock disable (JTAG/SWD)
    hardwareid         Read hardware ID
    chiprev            Read chip revision
    voltage [rail] [mv] Voltage control
    clock [domain] [hz] Clock control
    power [action]     Power management
    dma [channel]      DMA engine control

    === CRYPTO & RNG ===
    crypto [algo]      Crypto engine bypass
    rng [length]       RNG engine access
    qrng [length]      Quantum RNG access

    === USB4 v2.0 ===
    usb4 [action]      USB4 tunnel control
    pam4 [mode]        PAM4 encoding control

    === SECURITY & ATTESTATION ===
    attest             Attestation bypass
    cma [component]    CMA measurement access
    dpp [action]       DPP configuration

    === HARDWARE ACCELERATORS ===
    ai [action]        AI accelerator control
    npu [action]       NPU control
    gpu [action]       GPU control
    display [action]   Display engine control
    audio [action]     Audio DSP control
    sensor [sensor]    Sensor hub access

    === SPECIAL ===
    quantum [level]    Quantum Core Loader bypass
    temp               Temporary bypasses
    future [id]        Future bypass placeholder
    test               Test bypass engine

⚠️  Use only on devices you own or have explicit permission!
""")
    return True

def cmd_detect(dev, args, force):
    """Auto-detection"""
    results = auto_detect(dev, True)
    print(f"\n[+] Results:")
    print(f"    Device:   {results['device'].get('device_name','?')}")
    print(f"    Family:   {results['device'].get('soc_family','?')}")
    print(f"    Security: {results['security']}")
    print(f"    Offsets:  {sum(1 for o in results['offsets'].values() if o['found'])} found")
    print(f"    Points:   {len(results['points'])} detected")
    return True

def cmd_offsets(dev, args, force):
    """Show detected offsets"""
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    
    if not offsets:
        offsets = scan_offsets(dev, identify_device(dev))
    
    print(f"\n[+] Memory Offsets:")
    for k, v in offsets.items():
        if v.get('found'):
            print(f"    {k:<24} 0x{v['address']:08X}")
        else:
            print(f"    {k:<24} NOT FOUND")
    return True

def cmd_enforce(dev, args, force):
    """Show enforcement points"""
    key = cache_key(dev)
    points = _ENFORCEMENT_CACHE.get(key, [])
    
    if not points:
        offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
        if not offsets:
            offsets = scan_offsets(dev, identify_device(dev))
        points = detect_points(dev, offsets)
    
    print(f"\n[+] Enforcement Points ({len(points)}):")
    for p in points:
        print(f"    {p['type']:<16} @ 0x{p['address']:08X} L{p.get('level', 0)}")
        if p.get('desc'): print(f"      {p['desc']}")
    return True

def cmd_apple(dev, args, force):
    """Apple security bypass"""
    soc = args[0].upper() if args else "A12"
    
    if not confirm(
        f"⚡ APPLE SECURITY BYPASS: {soc}+\n"
        "This bypasses Apple hardware security mechanisms!\n"
        "Use only on devices you own!", 'APPLEBY', force
    ): return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = scan_offsets(dev, {'soc_family': 'APPLE'})
    
    data = soc.encode()[:8].ljust(8, b'\x00')
    for k in ['enclave', 'memory_protection', 'kernel_integrity', 'code_signing']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return run_bypass(dev, OP_APPLE, f"Apple {soc}", data, force)

def cmd_soc(dev, args, force):
    """Universal SOC bypass"""
    soc_type = args[0].upper() if args else "GENERIC"
    
    if not confirm(
        f"⚡ SOC BYPASS: {soc_type}\n"
        "This bypasses SOC-level security!\n"
        "Use only on devices you own!", 'SOCBYPASS', force
    ): return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    if not offsets:
        offsets = scan_offsets(dev, {'soc_family': soc_type})
    
    data = soc_type.encode()[:8].ljust(8, b'\x00')
    for k in ['secure_boot', 'memory_protection', 'crypto_engine']:
        data += struct.pack("<I", offsets.get(k, {}).get('address', 0))
    
    return run_bypass(dev, OP_SOC, f"SOC {soc_type}", data, force)

def cmd_secureboot(dev, args, force):
    """Secure boot bypass"""
    if not confirm("⚡ SECURE BOOT BYPASS - Bypasses boot verification!", 'QSLCLLOAD', force):
        return False
    
    key = cache_key(dev)
    offsets = _MEMORY_CACHE.get(key, {}).get('offsets', {})
    addr = offsets.get('secure_boot', {}).get('address', 0x80001000) if offsets else 0x80001000
    
    return run_bypass(dev, OP_SECUREBOOT, "Secure Boot", struct.pack("<I", addr), force)

def cmd_aprr(dev, args, force):
    return run_bypass(dev, OP_APRR, "APRR", b"", force)

def cmd_sep(dev, args, force):
    return run_bypass(dev, OP_SEP, "SEP", b"", force)

def cmd_kpp(dev, args, force):
    return run_bypass(dev, OP_KPP, "KPP", b"", force)

def cmd_amfi(dev, args, force):
    mode = args[0] if args else "full"
    return run_bypass(dev, OP_AMFI, "AMFI", mode.encode()[:8].ljust(8, b'\x00'), force)

def cmd_sandbox(dev, args, force):
    return run_bypass(dev, OP_SANDBOX, "Sandbox", b"", force)

def cmd_csr(dev, args, force):
    return run_bypass(dev, OP_CSR, "CSR", b"", force)

def cmd_temp(dev, args, force):
    return run_bypass(dev, OP_TEMP, "Temporary", b"", force)

def cmd_quantum(dev, args, force):
    level = args[0] if args else "standard"
    data = level.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_QUANTUM, "Quantum", data, force)

def cmd_watchdog(dev, args, force):
    """Disable watchdog timer (auto-detects offsets)"""
    if not confirm("⚡ WATCHDOG DISABLE - May cause system instability!", 'WDOGDIS', force):
        return False
    
    # Auto-detect SoC type
    info = identify_device(dev)
    soc_family = info.get('soc_family', 'GENERIC')
    soc_data = SOC_FAMILIES.get(soc_family, SOC_FAMILIES['GENERIC'])
    
    # Try known watchdog offsets for this SoC
    offsets = soc_data.get('watchdog_offsets', [])
    data = struct.pack("<I", len(offsets))
    for off in offsets:
        data += struct.pack("<I", off)
    
    return run_bypass(dev, OP_WATCHDOG, f"Watchdog ({soc_family})", data, force)

def cmd_smmu(dev, args, force):
    """SMMU (System Memory Management Unit) bypass"""
    if not confirm("⚡ SMMU BYPASS - Removes memory protection!", 'SMMUBYPASS', force):
        return False
    return run_bypass(dev, OP_SMMU, "SMMU", b"", force)

def cmd_trustzone(dev, args, force):
    """TrustZone/TEE secure world bypass"""
    if not confirm("⚡ TRUSTZONE BYPASS - Accesses secure world!", 'TRUSTZONE', force):
        return False
    mode = args[0] if args else "full"
    data = mode.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_TRUSTZONE, "TrustZone", data, force)

def cmd_secure_monitor(dev, args, force):
    """Secure monitor (EL3) bypass"""
    if not confirm("⚡ SECURE MONITOR BYPASS - Highest privilege level!", 'SECMON', force):
        return False
    return run_bypass(dev, OP_SECURE_MONITOR, "Secure Monitor", b"", force)

def cmd_fuse(dev, args, force):
    """Fuse read/bypass (read factory settings)"""
    if not confirm("⚡ FUSE ACCESS - Reads permanent factory settings!", 'FUSERD', force):
        return False
    bank = int(args[0], 16) if args else 0
    return run_bypass(dev, OP_FUSE, "Fuse", struct.pack("<I", bank), force)

def cmd_otp(dev, args, force):
    """OTP (One-Time Programmable) access"""
    if not confirm("⚡ OTP ACCESS - One-time programmable memory!", 'OTPRD', force):
        return False
    offset = int(args[0], 16) if args else 0
    return run_bypass(dev, OP_OTP, "OTP", struct.pack("<I", offset), force)

def cmd_debug_lock(dev, args, force):
    """Debug lock disable (JTAG/SWD)"""
    if not confirm("⚡ DEBUG LOCK DISABLE - Enables debug interfaces!", 'DBGLOCK', force):
        return False
    return run_bypass(dev, OP_DEBUG_LOCK, "Debug Lock", b"", force)

def cmd_efuse(dev, args, force):
    """eFuse control (read/program)"""
    if not confirm("⚠️ EFUSE PROGRAMMING - PERMANENT changes possible!", 'EFUSEPROG', force):
        return False
    action = args[0] if args else "read"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_EFUSE, "eFuse", data, force)

def cmd_bootrom(dev, args, force):
    """BootROM access (mask ROM)"""
    if not confirm("⚠️ BOOTROM ACCESS - Very dangerous!", 'BOOTROMACC', force):
        return False
    addr = int(args[0], 16) if args else 0
    return run_bypass(dev, OP_BOOTROM, "BootROM", struct.pack("<I", addr), force)

def cmd_firmware(dev, args, force):
    """Firmware extraction"""
    if not confirm("⚡ FIRMWARE EXTRACTION - Dumps protected firmware!", 'FWEXTRACT', force):
        return False
    region = args[0] if args else "all"
    data = region.encode()[:16].ljust(16, b'\x00')
    return run_bypass(dev, OP_FIRMWARE, "Firmware", data, force)

def cmd_hardware_id(dev, args, force):
    """Read hardware ID/Chip ID"""
    return run_bypass(dev, OP_HARDWARE_ID, "Hardware ID", b"", force)

def cmd_chip_rev(dev, args, force):
    """Read chip revision"""
    return run_bypass(dev, OP_CHIP_REV, "Chip Revision", b"", force)

def cmd_temp_sensor(dev, args, force):
    """Read temperature sensor"""
    sensor_id = int(args[0]) if args else 0
    return run_bypass(dev, OP_TEMP_SENSOR, "Temperature", struct.pack("<I", sensor_id), force)

def cmd_voltage_ctrl(dev, args, force):
    """Voltage control"""
    if not confirm("⚠️ VOLTAGE CONTROL - May damage hardware!", 'VOLTCTRL', force):
        return False
    rail = args[0] if args else "core"
    mv = int(args[1]) if len(args) > 1 else 0
    data = rail.encode()[:8].ljust(8, b'\x00') + struct.pack("<I", mv)
    return run_bypass(dev, OP_VOLTAGE_CTRL, "Voltage", data, force)

def cmd_clock_ctrl(dev, args, force):
    """Clock control (frequency scaling)"""
    if not confirm("⚠️ CLOCK CONTROL - May cause instability!", 'CLKCTRL', force):
        return False
    domain = args[0] if args else "cpu"
    freq = int(args[1]) if len(args) > 1 else 0
    data = domain.encode()[:8].ljust(8, b'\x00') + struct.pack("<I", freq)
    return run_bypass(dev, OP_CLOCK_CTRL, "Clock", data, force)

def cmd_power_mgmt(dev, args, force):
    """Power management control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_POWER_MGMT, "Power Management", data, force)

def cmd_dma_engine(dev, args, force):
    """DMA engine control"""
    channel = int(args[0]) if args else 0
    return run_bypass(dev, OP_DMA_ENGINE, "DMA", struct.pack("<I", channel), force)

def cmd_crypto_engine(dev, args, force):
    """Crypto engine bypass"""
    if not confirm("⚡ CRYPTO ENGINE BYPASS - Accesses hardware crypto!", 'CRYPTOBYP', force):
        return False
    algo = args[0] if args else "all"
    data = algo.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_CRYPTO_ENGINE, "Crypto Engine", data, force)

def cmd_rng_engine(dev, args, force):
    """RNG engine access"""
    length = int(args[0]) if args else 32
    return run_bypass(dev, OP_RNG_ENGINE, "RNG", struct.pack("<I", length), force)

def cmd_pcie_config(dev, args, force):
    """PCIe configuration space access"""
    bus = int(args[0], 16) if args else 0
    devfn = int(args[1], 16) if len(args) > 1 else 0
    reg = int(args[2], 16) if len(args) > 2 else 0
    data = struct.pack("<III", bus, devfn, reg)
    return run_bypass(dev, OP_PCIE_CONFIG, "PCIe", data, force)

def cmd_usb4_tunnel(dev, args, force):
    """USB4 v2.0 tunnel control"""
    action = args[0] if args else "create"
    tunnel_type = args[1] if len(args) > 1 else "pcie"
    data = action.encode()[:4].ljust(4, b'\x00') + tunnel_type.encode()[:4].ljust(4, b'\x00')
    return run_bypass(dev, OP_USB4_TUNNEL, "USB4 Tunnel", data, force)

def cmd_pam4_encode(dev, args, force):
    """PAM4 encoding control (USB4 v2.0)"""
    mode = args[0] if args else "auto"
    data = mode.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_PAM4_ENCODE, "PAM4 Encoding", data, force)

def cmd_attestation(dev, args, force):
    """Attestation bypass"""
    if not confirm("⚡ ATTESTATION BYPASS - Falsifies hardware proofs!", 'ATTESTBYP', force):
        return False
    return run_bypass(dev, OP_ATTESTATION, "Attestation", b"", force)

def cmd_cma_measure(dev, args, force):
    """Component Measurement Architecture (CMA) access"""
    component = args[0] if args else "all"
    data = component.encode()[:16].ljust(16, b'\x00')
    return run_bypass(dev, OP_CMA_MEASURE, "CMA", data, force)

def cmd_dpp_config(dev, args, force):
    """Data Protection Profile (DPP) configuration"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_DPP_CONFIG, "DPP", data, force)

def cmd_quantum_rng(dev, args, force):
    """Quantum RNG access (for future quantum-resistant crypto)"""
    length = int(args[0]) if args else 64
    return run_bypass(dev, OP_QUANTUM_RNG, "Quantum RNG", struct.pack("<I", length), force)

def cmd_ai_accel(dev, args, force):
    """AI accelerator control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_AI_ACCEL, "AI Accelerator", data, force)

def cmd_npu_ctrl(dev, args, force):
    """NPU (Neural Processing Unit) control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_NPU_CTRL, "NPU", data, force)

def cmd_gpu_ctrl(dev, args, force):
    """GPU control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_GPU_CTRL, "GPU", data, force)

def cmd_display_engine(dev, args, force):
    """Display engine control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_DISPLAY_ENGINE, "Display", data, force)

def cmd_audio_dsp(dev, args, force):
    """Audio DSP control"""
    action = args[0] if args else "status"
    data = action.encode()[:8].ljust(8, b'\x00')
    return run_bypass(dev, OP_AUDIO_DSP, "Audio DSP", data, force)

def cmd_sensor_hub(dev, args, force):
    """Sensor hub access (accelerometer, gyro, etc.)"""
    sensor = args[0] if args else "all"
    data = sensor.encode()[:16].ljust(16, b'\x00')
    return run_bypass(dev, OP_SENSOR_HUB, "Sensor Hub", data, force)

def cmd_future(dev, args, force):
    """Generic future bypass (extensible)"""
    feature_id = int(args[0], 16) if args else 0
    print(f"[*] Future bypass: feature 0x{feature_id:02X}")
    print("[*] This is a placeholder for future security features")
    return True

def cmd_test(dev, args, force):
    ok, name, _ = bypass_cmd(dev, struct.pack("<B", OP_TEST))
    status = 'ACTIVE' if ok else f'INACTIVE ({name})'
    print(f"[{'✓' if ok else '✗'}] Bypass engine: {status}")
    return ok


# =============================================================================
# EXPANDED DISPATCH TABLE
# =============================================================================

HANDLERS = {
    'watchdog': cmd_watchdog, 'wdog': cmd_watchdog,
    'smmu': cmd_smmu,
    'trustzone': cmd_trustzone, 'tz': cmd_trustzone, 'tee': cmd_trustzone,
    'secmon': cmd_secure_monitor, 'el3': cmd_secure_monitor,
    'fuse': cmd_fuse, 'efuse': cmd_efuse,
    'otp': cmd_otp,
    'debuglock': cmd_debug_lock, 'jtag': cmd_debug_lock, 'swd': cmd_debug_lock,
    'bootrom': cmd_bootrom, 'maskrom': cmd_bootrom,
    'firmware': cmd_firmware, 'fw': cmd_firmware,
    'hardwareid': cmd_hardware_id, 'chipid': cmd_hardware_id,
    'chiprev': cmd_chip_rev, 'revision': cmd_chip_rev,
    'temp': cmd_temp_sensor, 'temperature': cmd_temp_sensor,
    'voltage': cmd_voltage_ctrl, 'volt': cmd_voltage_ctrl,
    'clock': cmd_clock_ctrl, 'clk': cmd_clock_ctrl, 'frequency': cmd_clock_ctrl,
    'power': cmd_power_mgmt, 'pm': cmd_power_mgmt,
    'dma': cmd_dma_engine,
    'crypto': cmd_crypto_engine, 'crypt': cmd_crypto_engine,
    'rng': cmd_rng_engine, 'random': cmd_rng_engine,
    'pcie': cmd_pcie_config,
    'usb4': cmd_usb4_tunnel, 'usb4tunnel': cmd_usb4_tunnel,
    'pam4': cmd_pam4_encode,
    'attest': cmd_attestation, 'attestation': cmd_attestation,
    'cma': cmd_cma_measure,
    'dpp': cmd_dpp_config,
    'qrng': cmd_quantum_rng, 'quantumrng': cmd_quantum_rng,
    'ai': cmd_ai_accel, 'aiaceel': cmd_ai_accel,
    'npu': cmd_npu_ctrl,
    'gpu': cmd_gpu_ctrl,
    'display': cmd_display_engine, 'dpc': cmd_display_engine,
    'audio': cmd_audio_dsp, 'dsp': cmd_audio_dsp,
    'sensor': cmd_sensor_hub, 'hub': cmd_sensor_hub,
    'future': cmd_future,
}

# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_bypass(args=None) -> int:
    """
    QSLCL BYPASS - Security bypass engine
    
    Examples:
        bypass detect                    - Auto-detect device and security
        bypass offsets                   - Show memory offsets
        bypass enforce                   - Show enforcement points
        bypass apple A12                 - Apple A12+ bypass
        bypass soc QUALCOMM              - Qualcomm SOC bypass
        bypass secureboot                - Secure boot bypass
        bypass quantum standard          - Quantum Core Loader bypass
        bypass test                      - Test bypass engine
    
    ⚠️  Use only on devices you own or have explicit permission!
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: bypass <detect|offsets|enforce|apple|soc|secureboot|quantum|test>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'bypass_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    bargs = getattr(args, 'bypass_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] Bypass Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip().split('\n')[0]
                print(f"    {name:<15} {doc}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    # Global confirmation for bypass operations
    if sub not in ('list', 'detect', 'offsets', 'enforce', 'test', 'scan', 'auto'):
        if not force:
            if not confirm(
                "⚡ SECURITY BYPASS ENGINE\n"
                "Use only on devices you own or have explicit permission!\n"
                "Unauthorized use may violate laws.", 'QSLCLBYPASS', force
            ):
                return 0
    
    # Auto-detect if needed
    if sub not in ('list', 'detect', 'scan', 'auto'):
        auto_detect(dev, verbose=False)
    
    try:
        return 0 if handler(dev, bargs, force) else 1
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
    print("[*] bypass.py - QSLCL BYPASS Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py bypass <subcommand> [args]")