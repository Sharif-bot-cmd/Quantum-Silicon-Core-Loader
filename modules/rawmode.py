#!/usr/bin/env python3
"""
rawmode.py - QSLCL RAWMODE Command Module v2.1 (CLEANED)
Privilege escalation and raw hardware access with safety controls
"""

import os
import sys
import struct
import time
import hashlib
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
TIMEOUT = 10.0
MAX_RETRIES = 2
MAX_MONITOR = 300

# Opcodes
OP_CAPABILITIES = 0x01
OP_STATUS = 0x02
OP_UNLOCK = 0x03
OP_LOCK = 0x04
OP_SET_FEATURE = 0x05
OP_CONFIGURE = 0x06
OP_ESCALATE = 0x07
OP_MONITOR = 0x08
OP_AUDIT = 0x09
OP_RESET = 0x0A
OP_BACKDOOR = 0x0B          # Backdoor access (undocumented)
OP_PERSIST = 0x0C           # Persistence installation
OP_STEALTH = 0x0D           # Stealth mode (hide activity)
OP_SPOOF = 0x0E             # Identity spoofing
OP_PATCH = 0x0F             # Runtime patching
OP_INJECT = 0x10            # Code injection
OP_HOOK = 0x11              # Function hooking
OP_DUMP_SECURE = 0x12       # Secure memory dump
OP_BYPASS_ALL = 0x13        # Bypass all security
OP_UNDO = 0x14              # Undo RAWMODE changes
OP_SAVE_STATE = 0x15        # Save current state
OP_RESTORE_STATE = 0x16     # Restore saved state
OP_JAILBREAK = 0x17         # Jailbreak trigger
OP_BOOTROM_WRITE = 0x18     # BootROM write (very dangerous)
OP_SEP_BYPASS = 0x19        # Secure Enclave bypass (Apple)
OP_TRUSTZONE_BYPASS = 0x1A  # TrustZone bypass (ARM)
OP_SMMU_DISABLE = 0x1B      # SMMU disable

PRIV_LEVELS = {
    0: ("USER", "Normal user mode, limited access, app sandbox"),
    1: ("PRIVILEGED", "System services, drivers, limited kernel access"),
    2: ("SUPERVISOR", "OS kernel, memory management, process control"),
    3: ("HYPERVISOR", "VM control, hardware virtualization, VMM access"),
    4: ("ROOT", "Bare metal, all hardware access, full system control"),
    5: ("BOOTROM", "Boot ROM level, unrestricted, permanent changes possible"),
    6: ("SECURE_MONITOR", "Secure monitor (EL3 on ARM), highest privilege"),
    7: ("DEBUG", "Debug mode with JTAG/SWD access"),
}

PRIV_DANGEROUS = {3, 4, 5, 6}  # HYPERVISOR and above
PRIV_IRREVERSIBLE = {5, 6}      # BOOTROM and SECURE_MONITOR can cause permanent changes

# =============================================================================
# EXPANDED RAWMODE FEATURES (More comprehensive)
# =============================================================================

FEATURES = {
    # Hardware access features
    "MMU_BYPASS":       {"desc": "Bypass MMU protection", "risk": "HIGH", "priv": 2},
    "DMA_ENABLE":       {"desc": "Enable Direct Memory Access", "risk": "HIGH", "priv": 2},
    "JTAG_ENABLE":      {"desc": "Enable JTAG debugging", "risk": "MEDIUM", "priv": 1},
    "SWD_ENABLE":       {"desc": "Enable Serial Wire Debug", "risk": "MEDIUM", "priv": 1},
    "REGISTER_ACCESS":  {"desc": "Access protected registers", "risk": "MEDIUM", "priv": 1},
    "BOOTROM_ACCESS":   {"desc": "Access boot ROM regions", "risk": "CRITICAL", "priv": 4},
    "SECURE_MEMORY":    {"desc": "Access secure memory regions", "risk": "CRITICAL", "priv": 3},
    
    # Security bypass features
    "SECURITY_DISABLE": {"desc": "Disable security features", "risk": "CRITICAL", "priv": 3},
    "SIGNATURE_BYPASS": {"desc": "Bypass signature verification", "risk": "CRITICAL", "priv": 3},
    "AMFI_DISABLE":     {"desc": "Disable Apple Mobile File Integrity", "risk": "HIGH", "priv": 2},
    "SANDBOX_BYPASS":   {"desc": "Bypass sandbox restrictions", "risk": "HIGH", "priv": 2},
    "CSR_DISABLE":      {"desc": "Disable System Integrity Protection", "risk": "CRITICAL", "priv": 3},
    "KPP_BYPASS":       {"desc": "Bypass Kernel Patch Protection", "risk": "HIGH", "priv": 3},
    "SEP_BYPASS":       {"desc": "Bypass Secure Enclave (Apple)", "risk": "CRITICAL", "priv": 4},
    "TRUSTZONE_BYPASS": {"desc": "Bypass TrustZone (ARM)", "risk": "CRITICAL", "priv": 4},
    
    # Debug and trace features
    "DEBUG_ENABLE":     {"desc": "Enable debug features", "risk": "MEDIUM", "priv": 2},
    "TRACE_ENABLE":     {"desc": "Enable instruction tracing", "risk": "LOW", "priv": 1},
    "PERF_MONITOR":     {"desc": "Enable performance monitoring", "risk": "LOW", "priv": 1},
    "ETM_ENABLE":       {"desc": "Enable Embedded Trace Macrocell", "risk": "MEDIUM", "priv": 2},
    
    # Persistence features
    "PERSIST_ENABLE":   {"desc": "Install persistent backdoor", "risk": "CRITICAL", "priv": 4},
    "BOOT_HOOK":        {"desc": "Install boot-time hook", "risk": "CRITICAL", "priv": 4},
    "FIRMWARE_PATCH":   {"desc": "Patch firmware permanently", "risk": "CRITICAL", "priv": 5},
    
    # Stealth features
    "STEALTH_MODE":     {"desc": "Hide RAWMODE activity", "risk": "HIGH", "priv": 2},
    "LOG_CLEAR":        {"desc": "Clear audit logs", "risk": "HIGH", "priv": 2},
    "EVIDENCE_REMOVE":  {"desc": "Remove forensic evidence", "risk": "CRITICAL", "priv": 3},
    
    # Apple-specific (A12+)
    "APRR_BYPASS":      {"desc": "Bypass APRR (Apple)", "risk": "HIGH", "priv": 3},
    "PAC_DISABLE":      {"desc": "Disable Pointer Authentication", "risk": "HIGH", "priv": 3},
    "DIT_DISABLE":      {"desc": "Disable Data Independent Timing", "risk": "MEDIUM", "priv": 2},
    "PPL_BYPASS":       {"desc": "Bypass Page Protection Layer", "risk": "HIGH", "priv": 3},
    
    # Qualcomm-specific
    "TZ_BYPASS":        {"desc": "Bypass TrustZone (Qualcomm)", "risk": "CRITICAL", "priv": 3},
    "QFP_BYPASS":       {"desc": "Bypass Qualcomm Firewall", "risk": "HIGH", "priv": 2},
    "SMMU_DISABLE":     {"desc": "Disable SMMU", "risk": "HIGH", "priv": 3},
    
    # MediaTek-specific
    "DA_BYPASS":        {"desc": "Bypass Download Agent auth", "risk": "HIGH", "priv": 2},
    "BROM_UNLOCK":      {"desc": "Unlock BootROM features", "risk": "CRITICAL", "priv": 4},
    
    # USB4 v2.0 features
    "USB4_TUNNEL":      {"desc": "Enable USB4 tunneling", "risk": "MEDIUM", "priv": 1},
    "PAM4_OVERRIDE":    {"desc": "Override PAM4 encoding", "risk": "LOW", "priv": 1},
    
    # Future/experimental
    "QUANTUM_BYPASS":   {"desc": "Quantum-resistant bypass", "risk": "HIGH", "priv": 3},
    "AI_OVERRIDE":      {"desc": "Override AI security", "risk": "HIGH", "priv": 3},
}

RISK_COLORS = {'LOW': '', 'MEDIUM': '', 'HIGH': '', 'CRITICAL': ''}
RISK_DANGEROUS = {'HIGH', 'CRITICAL'}


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


def priv_name(level: int) -> str:
    return PRIV_LEVELS.get(level, (f"LEVEL_{level}",))[0]


def priv_desc(level: int) -> str:
    return PRIV_LEVELS.get(level, (f"LEVEL_{level}", "Unknown"))[1]


def priv_from_name(name: str) -> Optional[int]:
    name = name.upper().strip()
    for num, (n, _) in PRIV_LEVELS.items():
        if n == name:
            return num
    return None


def raw_cmd(dev, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
    """Send RAWMODE command"""
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if "RAWMODE" in QSLCLCMD_DB:
                resp = qslcl_dispatch(dev, "RAWMODE", payload, timeout=TIMEOUT)
            else:
                pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                dev.write(pkt)
                _, resp = dev.read(timeout=TIMEOUT)
            
            if resp:
                status = decode_runtime_result(resp)
                return status.get("severity") == "SUCCESS", status.get("name", "?"), status.get("extra", b"")
        except:
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.3)
    
    return False, "NO_RESPONSE", b""


def parse_status(data: bytes) -> dict:
    """Parse status data"""
    result = {'mode': '?', 'priv_name': 'USER', 'priv_num': 0, 'security': '?', 'features': []}
    try:
        if len(data) >= 16:
            result['mode'] = data[0:8].decode('ascii', errors='ignore').rstrip('\x00').strip() or '?'
            result['priv_name'] = data[8:12].decode('ascii', errors='ignore').rstrip('\x00').strip() or 'USER'
            result['security'] = data[12:16].decode('ascii', errors='ignore').rstrip('\x00').strip() or '?'
            result['priv_num'] = priv_from_name(result['priv_name'])
            if result['priv_num'] is None:
                result['priv_num'] = 0
        
        if len(data) >= 20:
            bits = struct.unpack("<I", data[16:20])[0]
            for i, name in enumerate(sorted(FEATURES)):
                if i < 32 and (bits >> i) & 1:
                    result['features'].append(name)
    except:
        pass
    return result


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================
class Session:
    """RAWMODE session with state tracking"""
    
    def __init__(self, dev, verbose=False):
        self.dev = dev
        self.verbose = verbose
        self.priv_level = 0
        self.features = []
        self.audit_log = []
        self.start = time.time()
        
        seed = f"{getattr(dev, 'identifier', '?')}{time.time()}{os.urandom(4).hex()}"
        self.id = hashlib.sha256(seed.encode()).hexdigest()[:16]
        
        self._log("SESSION_START", f"Session {self.id}")
        if verbose:
            print(f"[*] Session: {self.id}")
    
    @property
    def priv_name(self):
        return priv_name(self.priv_level)
    
    def _log(self, event: str, desc: str, severity: str = "INFO"):
        entry = (time.time(), event, severity, desc)
        self.audit_log.append(entry)
        if self.verbose or severity in ("WARNING", "ERROR", "CRITICAL"):
            print(f"  [{entry[0] % 86400:5.1f}s] [{severity:<8}] {event}: {desc}")
    
    def has_priv(self, required: int) -> bool:
        return self.priv_level >= required
    
    def set_priv(self, level: int):
        old = self.priv_name
        self.priv_level = level
        self._log("PRIV_CHANGE", f"{old} -> {self.priv_name}", 
                  "WARNING" if level > self.priv_level else "INFO")
    
    def enable_feature(self, name: str):
        feat = FEATURES.get(name.upper(), {})
        if name not in self.features:
            self.features.append(name)
            self._log("FEATURE_ON", name, 
                      "WARNING" if feat.get('risk') in RISK_DANGEROUS else "INFO")
    
    def execute(self, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
        return raw_cmd(self.dev, opcode, data)
    
    def close(self):
        elapsed = time.time() - self.start
        self._log("SESSION_END", f"{elapsed:.1f}s, priv={self.priv_name}, features={len(self.features)}")
        if self.verbose:
            print(f"\n[*] Session closed: {self.id}")


# =============================================================================
# SUBCOMMANDS
# =============================================================================
def cmd_list(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """List capabilities, features, and privilege levels"""
    print(f"\n[*] RAWMODE Feature Reference:\n")
    
    # Group features by category
    categories = {
        'Hardware Access': ['MMU_BYPASS', 'DMA_ENABLE', 'JTAG_ENABLE', 'SWD_ENABLE', 'REGISTER_ACCESS', 'BOOTROM_ACCESS', 'SECURE_MEMORY'],
        'Security Bypass': ['SECURITY_DISABLE', 'SIGNATURE_BYPASS', 'AMFI_DISABLE', 'SANDBOX_BYPASS', 'CSR_DISABLE', 'KPP_BYPASS', 'SEP_BYPASS', 'TRUSTZONE_BYPASS'],
        'Debug & Trace': ['DEBUG_ENABLE', 'TRACE_ENABLE', 'PERF_MONITOR', 'ETM_ENABLE'],
        'Persistence': ['PERSIST_ENABLE', 'BOOT_HOOK', 'FIRMWARE_PATCH'],
        'Stealth': ['STEALTH_MODE', 'LOG_CLEAR', 'EVIDENCE_REMOVE'],
        'Apple-Specific': ['APRR_BYPASS', 'PAC_DISABLE', 'DIT_DISABLE', 'PPL_BYPASS'],
        'Qualcomm-Specific': ['TZ_BYPASS', 'QFP_BYPASS', 'SMMU_DISABLE'],
        'MediaTek-Specific': ['DA_BYPASS', 'BROM_UNLOCK'],
        'USB4 v2.0': ['USB4_TUNNEL', 'PAM4_OVERRIDE'],
        'Experimental': ['QUANTUM_BYPASS', 'AI_OVERRIDE'],
    }
    
    for category, feat_list in categories.items():
        print(f"    [{category}]")
        for name in feat_list:
            if name in FEATURES:
                info = FEATURES[name]
                print(f"        {name:<20} Risk:{info['risk']:<10} Level:{priv_name(info['priv']):<12} {info['desc']}")
        print()
    
    print(f"\n[*] Privilege Levels:")
    for level in sorted(PRIV_LEVELS):
        dangerous = " ⚠️ DANGEROUS" if level in PRIV_DANGEROUS else ""
        irreversible = " 💀 IRREVERSIBLE" if level in PRIV_IRREVERSIBLE else ""
        print(f"    {level}: {PRIV_LEVELS[level][0]:<16} {PRIV_LEVELS[level][1]}{dangerous}{irreversible}")
    
    print(f"\n[*] Advanced Operations:")
    print(f"    backdoor      Attempt backdoor access")
    print(f"    persist       Install persistence (survives reboot)")
    print(f"    stealth       Hide RAWMODE activity")
    print(f"    spoof         Spoof device identity")
    print(f"    patch         Apply runtime memory patch")
    print(f"    jailbreak     Trigger jailbreak (Apple)")
    print(f"    sep           Bypass Secure Enclave (Apple A12+)")
    print(f"    undo          Revert RAWMODE changes")
    print(f"    save          Save current state")
    print(f"    restore       Restore saved state")
    
    print(f"\n[*] Session: {session.id}")
    session._log("LIST", "Capabilities displayed")
    return 0

def cmd_status(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Show current status"""
    print(f"\n[*] Querying status...")
    
    success, name, data = session.execute(OP_STATUS)
    
    if success:
        status = parse_status(data)
        print(f"    Mode:      {status['mode']}")
        print(f"    Privilege: {status['priv_name']} ({priv_desc(status['priv_num'])})")
        print(f"    Security:  {status['security']}")
        print(f"    Features:  {', '.join(status['features']) if status['features'] else 'None'}")
        print(f"    Session:   {session.id}")
        print(f"    Duration:  {time.time()-session.start:.1f}s")
        
        if verbose:
            print(f"\n    Audit Log ({len(session.audit_log)} entries):")
            for ts, event, sev, desc in session.audit_log[-10:]:
                print(f"      [{ts%86400:5.1f}s] [{sev:<8}] {event}: {desc}")
        
        session._log("STATUS", "Status queried")
        return 0
    
    print(f"[!] Status query failed: {name}")
    return 1


def cmd_unlock(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Unlock RAWMODE (full access)"""
    print(f"\n{'='*55}")
    print(f"  ⛔ RAWMODE UNLOCK - FULL SYSTEM ACCESS ⛔")
    print(f"{'='*55}")
    
    msg = (
        "UNLOCK GRANTS COMPLETE SYSTEM CONTROL:\n\n"
        "  🔴 Removes ALL security protections\n"
        "  🔴 Grants bare-metal hardware access\n"
        "  🔴 Can PERMANENTLY BRICK the device\n"
        "  🔴 Voids ALL warranties\n\n"
        "  ⚠️  For AUTHORIZED SECURITY RESEARCH ONLY\n"
        "  ⚠️  You assume ALL responsibility"
    )
    
    if not confirm(msg, 'UNLOCK', force):
        session._log("UNLOCK", "Cancelled by user")
        return 0
    
    method = args[0].upper() if args else "DEFAULT"
    auth_data = b""
    if len(args) > 1:
        raw = args[1]
        try:
            if raw.startswith('0x') or raw.startswith('0X'):
                auth_data = bytes.fromhex(raw[2:])
            elif len(raw) % 2 == 0:
                auth_data = bytes.fromhex(raw)
            else:
                auth_data = raw.encode()
        except:
            auth_data = raw.encode()
    
    payload = method.encode()[:8].ljust(8, b'\x00')
    payload += struct.pack("<I", len(auth_data)) + auth_data
    
    success, name, data = session.execute(OP_UNLOCK, payload)
    
    if success:
        print(f"\n[+] RAWMODE unlocked!")
        if len(data) >= 8:
            priv = data[0:8].decode('ascii', errors='ignore').rstrip('\x00').strip()
            level = priv_from_name(priv)
            if level is not None:
                session.set_priv(level)
            print(f"    Privilege: {priv}")
        session._log("UNLOCK", "Full access granted", "CRITICAL")
        return 0
    
    print(f"[!] Unlock failed: {name}")
    session._log("UNLOCK", f"Failed: {name}", "ERROR")
    return 1


def cmd_lock(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Lock RAWMODE"""
    level = args[0].upper() if args else "FULL"
    print(f"\n[*] Locking RAWMODE ({level})...")
    
    payload = level.encode()[:8].ljust(8, b'\x00')
    success, name, _ = session.execute(OP_LOCK, payload)
    
    if success:
        print("[+] Locked")
        session.set_priv(0)
        session.features.clear()
        session._log("LOCK", f"Level: {level}")
        return 0
    
    print(f"[!] Lock failed: {name}")
    return 1


def cmd_set(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Enable a RAWMODE feature"""
    if not args:
        print("[!] Specify feature to enable")
        print(f"[*] Available: {', '.join(sorted(FEATURES))}")
        return 1
    
    name = args[0].upper()
    feat = FEATURES.get(name)
    
    if not feat:
        print(f"[!] Unknown: {name}")
        print(f"[*] Valid: {', '.join(sorted(FEATURES))}")
        return 1
    
    value = args[1] if len(args) > 1 else "1"
    
    print(f"\n[*] Enabling: {name}")
    print(f"    {feat['desc']}")
    print(f"    Risk: {feat['risk']}, Requires: {priv_name(feat['priv'])}")
    
    if not session.has_priv(feat['priv']):
        print(f"[!] Insufficient privilege: need {priv_name(feat['priv'])}, have {session.priv_name}")
        return 1
    
    if feat['risk'] in RISK_DANGEROUS:
        if not confirm(f"DANGEROUS: {name} - {feat['desc']}\nMay compromise security or brick device!", 'DANGER', force):
            session._log("FEATURE", f"Cancelled: {name}")
            return 0
    
    try:
        val_int = int(value, 0)
    except ValueError:
        val_int = 1
    
    payload = struct.pack("<BI", sorted(FEATURES).index(name), val_int)
    success, name_str, _ = session.execute(OP_SET_FEATURE, payload)
    
    if success:
        print(f"[+] {name} enabled")
        session.enable_feature(name)
        return 0
    
    print(f"[!] Failed: {name_str}")
    session._log("FEATURE", f"Failed: {name}", "ERROR")
    return 1


def cmd_configure(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Configure RAWMODE parameter"""
    if len(args) < 2:
        print("[!] Usage: rawmode configure <KEY> <VALUE>")
        return 1
    
    key = args[0].upper()
    val = args[1]
    
    print(f"\n[*] Configuring: {key} = {val}")
    
    payload = key.encode()[:16].ljust(16, b'\x00')
    try:
        if val.startswith('0x') or val.startswith('0X'):
            payload += struct.pack("<I", int(val, 16))
        else:
            payload += struct.pack("<I", int(val))
    except ValueError:
        payload += val.encode()[:16].ljust(16, b'\x00')
    
    success, name, _ = session.execute(OP_CONFIGURE, payload)
    
    if success:
        print("[+] Configuration applied")
        session._log("CONFIGURE", f"{key}={val}")
        return 0
    
    print(f"[!] Failed: {name}")
    return 1


def cmd_escalate(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Escalate privilege level"""
    if not args:
        print("[!] Specify target privilege level")
        print(f"[*] Levels: {', '.join(PRIV_LEVELS[n][0] for n in sorted(PRIV_LEVELS))}")
        return 1
    
    target_name = args[0].upper()
    target = priv_from_name(target_name)
    
    if target is None:
        print(f"[!] Invalid: {target_name}")
        return 1
    
    if target <= session.priv_level:
        print(f"[!] Already at {session.priv_name} or higher")
        return 0
    
    print(f"\n[*] Escalating: {session.priv_name} -> {target_name}")
    
    if target in PRIV_DANGEROUS:
        msg = (
            f"ESCALATE TO {target_name}:\n\n"
            f"  {priv_desc(target)}\n\n"
            f"  🔴 Complete system control\n"
            f"  🔴 Bypasses ALL security\n"
            f"  🔴 Can permanently modify hardware\n"
            f"  🔴 IRREVERSIBLE changes possible"
        )
        if not confirm(msg, 'ESCALATE', force):
            session._log("ESCALATE", f"Cancelled: {target_name}")
            return 0
    
    payload = target_name.encode()[:8].ljust(8, b'\x00')
    success, name, _ = session.execute(OP_ESCALATE, payload)
    
    if success:
        print(f"[+] Escalated to {target_name}")
        session.set_priv(target)
        return 0
    
    print(f"[!] Escalation failed: {name}")
    session._log("ESCALATE", f"Failed: {target_name}", "ERROR")
    return 1


def cmd_monitor(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Monitor system activity"""
    monitor_type = args[0].upper() if args else "SYSTEM"
    duration = min(int(args[1]) if len(args) > 1 else 10, MAX_MONITOR)
    
    print(f"\n[*] Monitoring {monitor_type} for {duration}s...")
    print("[*] Ctrl+C to stop")
    
    payload = monitor_type.encode()[:8].ljust(8, b'\x00')
    payload += struct.pack("<I", duration)
    
    try:
        success, name, data = session.execute(OP_MONITOR, payload)
        if success:
            print(f"\n[+] Complete")
            if verbose and data:
                print(f"    Data: {len(data)} bytes")
            session._log("MONITOR", f"{monitor_type} for {duration}s")
            return 0
        print(f"[!] Failed: {name}")
        return 1
    except KeyboardInterrupt:
        print(f"\n[*] Stopped")
        session._log("MONITOR", f"Interrupted: {monitor_type}")
        return 0


def cmd_audit(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """View audit log"""
    audit_type = args[0].upper() if args else "ALL"
    
    print(f"\n[*] Audit Log ({len(session.audit_log)} entries):")
    for ts, event, sev, desc in session.audit_log[-30:]:
        print(f"  [{ts%86400:5.1f}s] [{sev:<8}] {event:<16} {desc}")
    
    session._log("AUDIT", f"Type: {audit_type}")
    return 0


def cmd_reset(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Reset RAWMODE state"""
    reset_type = args[0].upper() if args else "SOFT"
    
    print(f"\n[*] Reset: {reset_type}")
    
    if reset_type in ("HARD", "FULL", "BOOTLOADER"):
        if not confirm(f"{reset_type} RESET - will reboot device and clear all state!", 'RESET', force):
            session._log("RESET", f"Cancelled: {reset_type}")
            return 0
    
    payload = reset_type.encode()[:8].ljust(8, b'\x00')
    success, name, _ = session.execute(OP_RESET, payload)
    
    if success:
        print(f"[+] Reset initiated")
        if reset_type in ("HARD", "FULL"):
            session.set_priv(0)
            session.features.clear()
        session._log("RESET", f"Type: {reset_type}", "WARNING")
        return 0
    
    print(f"[!] Failed: {name}")
    return 1

# =============================================================================
# MISSING SUBCOMMANDS
# =============================================================================

def cmd_backdoor(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Access undocumented backdoor (if exists)"""
    print(f"\n[*] Attempting backdoor access...")
    
    backdoor_type = args[0].upper() if args else "DEFAULT"
    
    if not confirm(
        f"⚠️ BACKDOOR ACCESS: {backdoor_type}\n"
        "This attempts to use undocumented backdoor channels.\n"
        "May trigger security alerts!\n"
        "Use only on devices you own!",
        'BACKDOOR', force
    ):
        return 0
    
    payload = backdoor_type.encode()[:16].ljust(16, b'\x00')
    success, name, data = session.execute(OP_BACKDOOR, payload)
    
    if success:
        print(f"[+] Backdoor access granted")
        if data and verbose:
            print(f"    Response: {data[:32].hex()}")
        session._log("BACKDOOR", f"Type: {backdoor_type}", "CRITICAL")
        return 0
    
    print(f"[!] Backdoor failed: {name}")
    return 1


def cmd_persist(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Install persistence (survives reboot)"""
    print(f"\n[*] Installing persistence...")
    print("    WARNING: This will survive reboots and may be PERMANENT!")
    
    persist_type = args[0].upper() if args else "BOOT"
    payload = persist_type.encode()[:16].ljust(16, b'\x00')
    
    if not confirm(
        f"⚠️ PERSISTENCE INSTALLATION: {persist_type}\n"
        "This installs code that survives reboots!\n"
        "May be DETECTED by security software!\n"
        "Use only on devices you own!",
        'PERSIST', force
    ):
        return 0
    
    success, name, data = session.execute(OP_PERSIST, payload)
    
    if success:
        print(f"[+] Persistence installed")
        session._log("PERSIST", f"Type: {persist_type}", "CRITICAL")
        return 0
    
    print(f"[!] Persistence failed: {name}")
    return 1


def cmd_stealth(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Enable stealth mode (hide activity)"""
    print(f"\n[*] Enabling stealth mode...")
    
    level = args[0].upper() if args else "FULL"
    
    if not confirm(
        f"⚠️ STEALTH MODE: {level}\n"
        "This hides RAWMODE activity from monitoring.\n"
        "May violate security policies!\n"
        "Use only on devices you own!",
        'STEALTH', force
    ):
        return 0
    
    payload = level.encode()[:16].ljust(16, b'\x00')
    success, name, data = session.execute(OP_STEALTH, payload)
    
    if success:
        print(f"[+] Stealth mode enabled (level: {level})")
        session._log("STEALTH", f"Level: {level}", "CRITICAL")
        return 0
    
    print(f"[!] Stealth mode failed: {name}")
    return 1


def cmd_spoof(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Spoof device identity"""
    if len(args) < 2:
        print("[!] Usage: rawmode spoof <TYPE> <VALUE>")
        print("    Types: VID, PID, SERIAL, PRODUCT, MANUFACTURER")
        return 1
    
    spoof_type = args[0].upper()
    value = args[1]
    
    print(f"\n[*] Spoofing: {spoof_type} = {value}")
    
    if not confirm(
        f"⚠️ IDENTITY SPOOFING\n"
        f"This changes device identification to: {spoof_type}={value}\n"
        "May violate laws!\n"
        "Use only on devices you own!",
        'SPOOF', force
    ):
        return 0
    
    payload = spoof_type.encode()[:8].ljust(8, b'\x00')
    payload += value.encode()[:64].ljust(64, b'\x00')
    
    success, name, data = session.execute(OP_SPOOF, payload)
    
    if success:
        print(f"[+] Spoofing applied")
        session._log("SPOOF", f"{spoof_type}={value}", "CRITICAL")
        return 0
    
    print(f"[!] Spoofing failed: {name}")
    return 1


def cmd_patch_runtime(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Apply runtime patch to memory"""
    if len(args) < 2:
        print("[!] Usage: rawmode patch <ADDRESS> <DATA>")
        return 1
    
    try:
        addr = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
        data = bytes.fromhex(args[1]) if len(args[1]) % 2 == 0 else args[1].encode()
    except ValueError as e:
        print(f"[!] Invalid address or data: {e}")
        return 1
    
    print(f"\n[*] Patching at 0x{addr:08X}: {data[:16].hex()}...")
    
    if not confirm(
        f"⚠️ RUNTIME PATCH\n"
        f"Address: 0x{addr:08X}\n"
        f"Data: {data[:16].hex()}\n"
        "Modifies live memory!\n"
        "May crash device!\n"
        "Use only on devices you own!",
        'PATCH', force
    ):
        return 0
    
    payload = struct.pack("<I", addr) + struct.pack("<I", len(data)) + data
    success, name, extra = session.execute(OP_PATCH, payload)
    
    if success:
        print(f"[+] Patch applied")
        session._log("PATCH", f"0x{addr:08X} len={len(data)}", "WARNING")
        return 0
    
    print(f"[!] Patch failed: {name}")
    return 1


def cmd_jailbreak(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Trigger jailbreak (Apple-specific)"""
    print(f"\n[*] Triggering jailbreak sequence...")
    
    jb_type = args[0].upper() if args else "A12"
    
    if not confirm(
        f"⚠️ JAILBREAK TRIGGER: {jb_type}\n"
        "This attempts to jailbreak the device!\n"
        "Voids warranty!\n"
        "May cause boot loop!\n"
        "Use only on devices you own!",
        'JAILBREAK', force
    ):
        return 0
    
    payload = jb_type.encode()[:16].ljust(16, b'\x00')
    success, name, data = session.execute(OP_JAILBREAK, payload)
    
    if success:
        print(f"[+] Jailbreak triggered")
        session._log("JAILBREAK", f"Type: {jb_type}", "CRITICAL")
        return 0
    
    print(f"[!] Jailbreak failed: {name}")
    return 1


def cmd_sep_bypass(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Bypass Secure Enclave (Apple A12+)"""
    print(f"\n[*] Attempting SEP bypass...")
    
    if not confirm(
        f"⚠️ SECURE ENCLAVE BYPASS\n"
        "This bypasses Apple's Secure Enclave!\n"
        "May break Touch ID/Face ID!\n"
        "Use only on devices you own!",
        'SEPBYPASS', force
    ):
        return 0
    
    success, name, data = session.execute(OP_SEP_BYPASS)
    
    if success:
        print(f"[+] SEP bypassed")
        session._log("SEP_BYPASS", "Secure Enclave bypassed", "CRITICAL")
        return 0
    
    print(f"[!] SEP bypass failed: {name}")
    return 1


def cmd_undo(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Undo RAWMODE changes"""
    print(f"\n[*] Undoing RAWMODE changes...")
    
    if not confirm(
        f"⚠️ UNDO CHANGES\n"
        "This reverts RAWMODE modifications.\n"
        "Some changes may be PERMANENT!\n",
        'UNDO', force
    ):
        return 0
    
    success, name, data = session.execute(OP_UNDO)
    
    if success:
        print(f"[+] Changes undone")
        session.set_priv(0)
        session.features.clear()
        session._log("UNDO", "All changes reverted", "WARNING")
        return 0
    
    print(f"[!] Undo failed: {name}")
    return 1


def cmd_save_state(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Save current state for later restoration"""
    filename = args[0] if args else f"rawmode_state_{session.id[:8]}.bin"
    
    print(f"\n[*] Saving state to: {filename}")
    
    success, name, data = session.execute(OP_SAVE_STATE)
    
    if success and data:
        try:
            with open(filename, 'wb') as f:
                f.write(data)
            print(f"[+] State saved: {filename} ({len(data)} bytes)")
            session._log("SAVE_STATE", filename)
            return 0
        except Exception as e:
            print(f"[!] Save failed: {e}")
            return 1
    
    print(f"[!] State capture failed: {name}")
    return 1


def cmd_restore_state(session: Session, args: List[str], force: bool, verbose: bool) -> int:
    """Restore previously saved state"""
    if not args:
        print("[!] Specify state file")
        return 1
    
    filename = args[0]
    
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Cannot read: {e}")
        return 1
    
    print(f"\n[*] Restoring state from: {filename} ({len(data)} bytes)")
    
    if not confirm(
        f"⚠️ RESTORE STATE\n"
        "This restores previously saved RAWMODE state.\n"
        "May overwrite current configuration!\n",
        'RESTORE', force
    ):
        return 0
    
    payload = struct.pack("<I", len(data)) + data
    success, name, extra = session.execute(OP_RESTORE_STATE, payload)
    
    if success:
        print(f"[+] State restored")
        session._log("RESTORE_STATE", filename, "WARNING")
        return 0
    
    print(f"[!] Restore failed: {name}")
    return 1

# =============================================================================
# EXPANDED DISPATCH TABLE (With all new commands)
# =============================================================================
HANDLERS = {
    # Existing
    'list': cmd_list, 'ls': cmd_list, 'show': cmd_list,
    'status': cmd_status, 'stat': cmd_status, 'info': cmd_status,
    'unlock': cmd_unlock, 'auth': cmd_unlock,
    'lock': cmd_lock, 'disable': cmd_lock,
    'set': cmd_set, 'enable': cmd_set, 'on': cmd_set,
    'configure': cmd_configure, 'config': cmd_configure, 'cfg': cmd_configure,
    'escalate': cmd_escalate, 'priv': cmd_escalate,
    'monitor': cmd_monitor, 'watch': cmd_monitor,
    'audit': cmd_audit, 'log': cmd_audit, 'history': cmd_audit,
    'reset': cmd_reset, 'restart': cmd_reset,
    
    # NEW - Advanced features
    'backdoor': cmd_backdoor, 'hidden': cmd_backdoor,
    'persist': cmd_persist, 'persistence': cmd_persist,
    'stealth': cmd_stealth, 'hide': cmd_stealth,
    'spoof': cmd_spoof, 'fake': cmd_spoof,
    'patch': cmd_patch_runtime, 'hotpatch': cmd_patch_runtime,
    'jailbreak': cmd_jailbreak, 'jb': cmd_jailbreak,
    'sep': cmd_sep_bypass, 'sepbypass': cmd_sep_bypass, 'secureenclave': cmd_sep_bypass,
    'undo': cmd_undo, 'revert': cmd_undo,
    'save': cmd_save_state, 'snapshot': cmd_save_state,
    'restore': cmd_restore_state, 'load': cmd_restore_state,
}

# =============================================================================
# MAIN COMMAND
# =============================================================================
def cmd_rawmode(args=None) -> int:
    """
    QSLCL RAWMODE - Privilege escalation and raw hardware access
    
    Examples:
        rawmode list                    - List features and capabilities
        rawmode status -v               - Show current status (verbose)
        rawmode unlock                  - Unlock full access
        rawmode escalate ROOT           - Escalate to ROOT level
        rawmode set JTAG_ENABLE 1       - Enable JTAG
        rawmode monitor SYSTEM 30       - Monitor for 30 seconds
        rawmode audit                   - View audit log
        rawmode lock                    - Lock RAWMODE
        rawmode reset SOFT              - Soft reset
    
    Privilege Levels:
        USER < PRIVILEGED < SUPERVISOR < HYPERVISOR < ROOT < BOOTROM
    """
    
    if args is None:
        print("[!] No arguments")
        print("[*] Usage: rawmode <list|status|unlock|lock|set|configure|escalate|monitor|audit|reset>")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    sub = (getattr(args, 'rawmode_subcommand', '') or getattr(args, 'subcmd', '')).lower().strip()
    rargs = getattr(args, 'rawmode_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    if not sub or sub in ('help', '?'):
        print("[*] RAWMODE Commands:")
        for name, func in sorted(set(HANDLERS.items()), key=lambda x: x[0]):
            if '_' not in name:
                doc = (func.__doc__ or '').strip()
                print(f"    {name:<12} {doc}")
        print(f"\n[*] Features: {', '.join(sorted(FEATURES))}")
        print(f"[*] Levels: {' < '.join(PRIV_LEVELS[n][0] for n in sorted(PRIV_LEVELS))}")
        return 0
    
    handler = HANDLERS.get(sub)
    if not handler:
        print(f"[!] Unknown: {sub}")
        return 1
    
    session = Session(dev, verbose=verbose)
    
    try:
        return handler(session, rargs, force, verbose)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        session._log("INTERRUPT", "User interrupted", "WARNING")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        session._log("ERROR", str(e), "CRITICAL")
        if verbose and _DEBUG:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        session.close()


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] rawmode.py - QSLCL RAWMODE Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py rawmode <subcommand> [args]")