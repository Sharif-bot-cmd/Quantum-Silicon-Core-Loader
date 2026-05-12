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

# Privilege levels
PRIV_LEVELS = {
    0: ("USER", "Normal user mode, limited access"),
    1: ("PRIVILEGED", "System services, some drivers"),
    2: ("SUPERVISOR", "OS kernel, memory management"),
    3: ("HYPERVISOR", "VM control, hardware virtualization"),
    4: ("ROOT", "Bare metal, all hardware access"),
    5: ("BOOTROM", "Boot ROM level, unrestricted"),
}

PRIV_DANGEROUS = {3, 4, 5}  # HYPERVISOR and above

# RAWMODE features
FEATURES = {
    "MMU_BYPASS":       {"desc": "Bypass MMU protection", "risk": "HIGH", "priv": 2},
    "SECURITY_DISABLE": {"desc": "Disable security features", "risk": "CRITICAL", "priv": 3},
    "JTAG_ENABLE":      {"desc": "Enable JTAG debugging", "risk": "MEDIUM", "priv": 1},
    "BOOTROM_ACCESS":   {"desc": "Access boot ROM regions", "risk": "CRITICAL", "priv": 4},
    "DMA_ENABLE":       {"desc": "Enable Direct Memory Access", "risk": "HIGH", "priv": 2},
    "REGISTER_ACCESS":  {"desc": "Access protected registers", "risk": "MEDIUM", "priv": 1},
    "DEBUG_ENABLE":     {"desc": "Enable debug features", "risk": "MEDIUM", "priv": 2},
    "TRACE_ENABLE":     {"desc": "Enable tracing", "risk": "LOW", "priv": 1},
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
    """List capabilities and features"""
    print(f"\n[*] RAWMODE Feature Reference:\n")
    for name, info in sorted(FEATURES.items()):
        print(f"    {name:<18} Risk:{info['risk']:<10} Level:{priv_name(info['priv']):<12} {info['desc']}")
    
    print(f"\n[*] Privilege Levels:")
    for level in sorted(PRIV_LEVELS):
        dangerous = " ⚠ DANGEROUS" if level in PRIV_DANGEROUS else ""
        print(f"    {level}: {PRIV_LEVELS[level][0]:<12} {PRIV_LEVELS[level][1]}{dangerous}")
    
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
# DISPATCH TABLE
# =============================================================================
HANDLERS = {
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