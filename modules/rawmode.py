#!/usr/bin/env python3
"""
rawmode.py - QSLCL RAWMODE Command Module v2.0 (FIXED)
Fixed: Import handling, session management, security warnings,
       privilege escalation safety, audit logging, error recovery
"""

import os
import sys
import re
import struct
import time
import hashlib
import traceback
from datetime import datetime
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
_parse_address_fn = None
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
# FIXED: Parse address fallback
# =============================================================================
def _parse_address(addr_str: str) -> int:
    """Parse address string in various formats."""
    if not isinstance(addr_str, str):
        if isinstance(addr_str, int):
            return addr_str
        raise ValueError(f"Cannot parse address from {type(addr_str)}")
    
    addr_str = addr_str.strip()
    if not addr_str:
        raise ValueError("Empty address string")
    
    addr_lower = addr_str.lower()
    if addr_lower.startswith('0x'):
        return int(addr_str[2:], 16)
    elif addr_lower.startswith('$'):
        return int(addr_str[1:], 16)
    
    try:
        return int(addr_str, 16)
    except ValueError:
        try:
            return int(addr_str, 10)
        except ValueError:
            raise ValueError(f"Invalid address format: '{addr_str}'")


# =============================================================================
# FIXED: Constants
# =============================================================================
RAWMODE_TIMEOUT = 10.0
MAX_RETRIES = 2
MAX_MONITOR_DURATION = 300  # 5 minutes max
SESSION_ID_LENGTH = 16

# =============================================================================
# FIXED: Privilege Levels
# =============================================================================
class PrivilegeLevel:
    """Privilege level definitions with numeric ordering."""
    USER = 0
    PRIVILEGED = 1
    SUPERVISOR = 2
    HYPERVISOR = 3
    ROOT = 4
    BOOTROM = 5
    
    NAMES = {
        0: "USER",
        1: "PRIVILEGED",
        2: "SUPERVISOR",
        3: "HYPERVISOR",
        4: "ROOT",
        5: "BOOTROM",
    }
    
    DESCRIPTIONS = {
        0: "Normal user mode, limited access",
        1: "System services, some drivers",
        2: "OS kernel, memory management",
        3: "VM control, hardware virtualization",
        4: "Bare metal, all hardware access",
        5: "Boot ROM level, unrestricted",
    }
    
    # Privilege hierarchy: higher number = more access
    ORDER = list(range(6))
    
    @classmethod
    def get_name(cls, level: int) -> str:
        return cls.NAMES.get(level, f"LEVEL_{level}")
    
    @classmethod
    def get_description(cls, level: int) -> str:
        return cls.DESCRIPTIONS.get(level, "Unknown privilege level")
    
    @classmethod
    def from_name(cls, name: str) -> Optional[int]:
        """Get numeric level from name string."""
        name_upper = name.upper().strip()
        for num, n in cls.NAMES.items():
            if n == name_upper:
                return num
        return None
    
    @classmethod
    def is_valid(cls, level: int) -> bool:
        return level in cls.NAMES
    
    @classmethod
    def is_dangerous(cls, level: int) -> bool:
        """Check if privilege level is considered dangerous."""
        return level >= cls.HYPERVISOR
    
    @classmethod
    def get_all_names(cls) -> List[str]:
        return [cls.NAMES[i] for i in cls.ORDER if i in cls.NAMES]


# =============================================================================
# FIXED: RAWMODE Features
# =============================================================================
class RawmodeFeature:
    """RAWMODE feature definitions."""
    FEATURES = {
        "MMU_BYPASS": {
            "opcode": 0xA1,
            "description": "Bypass Memory Management Unit protection",
            "risk": "HIGH",
            "requires_level": PrivilegeLevel.SUPERVISOR,
        },
        "SECURITY_DISABLE": {
            "opcode": 0xA2,
            "description": "Disable security features (TrustZone, Secure Boot)",
            "risk": "CRITICAL",
            "requires_level": PrivilegeLevel.HYPERVISOR,
        },
        "JTAG_ENABLE": {
            "opcode": 0xA3,
            "description": "Enable JTAG debugging interface",
            "risk": "MEDIUM",
            "requires_level": PrivilegeLevel.PRIVILEGED,
        },
        "BOOTROM_ACCESS": {
            "opcode": 0xA4,
            "description": "Access boot ROM regions",
            "risk": "CRITICAL",
            "requires_level": PrivilegeLevel.ROOT,
        },
        "DMA_ENABLE": {
            "opcode": 0xA5,
            "description": "Enable Direct Memory Access",
            "risk": "HIGH",
            "requires_level": PrivilegeLevel.SUPERVISOR,
        },
        "REGISTER_ACCESS": {
            "opcode": 0xA6,
            "description": "Access protected hardware registers",
            "risk": "MEDIUM",
            "requires_level": PrivilegeLevel.PRIVILEGED,
        },
        "DEBUG_ENABLE": {
            "opcode": 0xA7,
            "description": "Enable debug features and breakpoints",
            "risk": "MEDIUM",
            "requires_level": PrivilegeLevel.SUPERVISOR,
        },
        "TRACE_ENABLE": {
            "opcode": 0xA8,
            "description": "Enable instruction and memory tracing",
            "risk": "LOW",
            "requires_level": PrivilegeLevel.PRIVILEGED,
        },
    }
    
    RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    
    @classmethod
    def get(cls, name: str) -> Optional[Dict]:
        return cls.FEATURES.get(name.upper())
    
    @classmethod
    def is_valid(cls, name: str) -> bool:
        return name.upper() in cls.FEATURES
    
    @classmethod
    def is_dangerous(cls, name: str) -> bool:
        """Check if feature is considered dangerous."""
        feature = cls.get(name)
        if not feature:
            return False
        return feature["risk"] in ("HIGH", "CRITICAL")
    
    @classmethod
    def get_all_names(cls) -> List[str]:
        return sorted(cls.FEATURES.keys())
    
    @classmethod
    def get_by_risk(cls, max_risk: str = "CRITICAL") -> List[str]:
        """Get features up to a certain risk level."""
        max_risk_val = cls.RISK_ORDER.get(max_risk, 3)
        return [
            name for name, info in cls.FEATURES.items()
            if cls.RISK_ORDER.get(info["risk"], 0) <= max_risk_val
        ]


# =============================================================================
# FIXED: RAWMODE Commands
# =============================================================================
class RawmodeCommand:
    """RAWMODE command opcodes."""
    CAPABILITIES = 0x01
    STATUS = 0x02
    UNLOCK = 0x03
    LOCK = 0x04
    SET_FEATURE = 0x05
    CONFIGURE = 0x06
    ESCALATE = 0x07
    MONITOR = 0x08
    AUDIT = 0x09
    RESET = 0x0A
    LIST_FEATURES = 0x0B
    
    NAMES = {
        0x01: "CAPABILITIES",
        0x02: "STATUS",
        0x03: "UNLOCK",
        0x04: "LOCK",
        0x05: "SET_FEATURE",
        0x06: "CONFIGURE",
        0x07: "ESCALATE",
        0x08: "MONITOR",
        0x09: "AUDIT",
        0x0A: "RESET",
        0x0B: "LIST_FEATURES",
    }


# =============================================================================
# FIXED: Color codes for terminal output
# =============================================================================
class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    @classmethod
    def risk_color(cls, risk: str) -> str:
        return {
            'LOW': cls.GREEN,
            'MEDIUM': cls.YELLOW,
            'HIGH': cls.RED,
            'CRITICAL': cls.BRIGHT_RED,
        }.get(risk.upper(), cls.RESET)
    
    @classmethod
    def severity_color(cls, severity: str) -> str:
        return {
            'INFO': cls.GREEN,
            'WARNING': cls.YELLOW,
            'ERROR': cls.RED,
            'CRITICAL': cls.BRIGHT_RED,
        }.get(severity.upper(), cls.RESET)


# =============================================================================
# FIXED: Interactive confirmation with danger awareness
# =============================================================================
def confirm_dangerous_action(prompt: str, required_text: str, 
                              force: bool = False) -> bool:
    """
    Request confirmation for dangerous actions.
    
    Args:
        prompt: Warning message to display
        required_text: Text user must type exactly to confirm
        force: If True, skip confirmation
    
    Returns:
        bool: True if confirmed
    """
    if force:
        print(f"\n{Colors.YELLOW}[!] Force mode: Skipping safety confirmation{Colors.RESET}")
        return True
    
    print(f"\n{Colors.BRIGHT_RED}{prompt}{Colors.RESET}")
    
    try:
        response = input(f"\n    Type '{required_text}' to confirm: ")
        return response == required_text
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Colors.YELLOW}[!] Interactive input not available{Colors.RESET}")
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
# FIXED: RAWMODE dispatch
# =============================================================================
def dispatch_rawmode(dev, opcode: int, data: bytes = b"", 
                     timeout: float = None) -> Tuple[bool, str, bytes]:
    """
    Dispatch a RAWMODE command.
    
    Returns:
        Tuple[bool, str, bytes]: (success, status_name, extra_data)
    """
    if not _use_qslcl:
        return False, "NO_QSLCL_SUPPORT", b""
    
    if timeout is None:
        timeout = RAWMODE_TIMEOUT
    
    cmd_name = RawmodeCommand.NAMES.get(opcode, "UNKNOWN")
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            # Check if RAWMODE command exists
            if find_command("RAWMODE"):
                resp = _qslcl_dispatch(dev, "RAWMODE", payload, timeout=timeout)
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
                print(f"[!] RAWMODE dispatch attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.3 * (attempt + 1))
    
    return False, "NO_RESPONSE", b""


# =============================================================================
# FIXED: Audit logging
# =============================================================================
class AuditLogger:
    """Centralized audit logging for RAWMODE operations."""
    
    def __init__(self):
        self.entries: List[Dict] = []
    
    def log(self, event_type: str, severity: str, description: str,
            details: Dict = None) -> Dict:
        """Add an audit entry."""
        entry = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity.upper(),
            "description": description,
            "details": details or {},
        }
        self.entries.append(entry)
        return entry
    
    def get_recent(self, count: int = 10) -> List[Dict]:
        """Get most recent entries."""
        return self.entries[-count:]
    
    def get_by_severity(self, min_severity: str = "WARNING") -> List[Dict]:
        """Get entries at or above a severity level."""
        severity_order = ["INFO", "WARNING", "ERROR", "CRITICAL"]
        min_idx = severity_order.index(min_severity.upper()) if min_severity.upper() in severity_order else 0
        
        return [
            e for e in self.entries
            if severity_order.index(e["severity"]) >= min_idx
        ]
    
    def count(self) -> int:
        return len(self.entries)
    
    def print_recent(self, count: int = 10):
        """Print recent audit entries."""
        recent = self.get_recent(count)
        if not recent:
            print(f"  {Colors.CYAN}(no audit entries){Colors.RESET}")
            return
        
        for entry in recent:
            ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%H:%M:%S")
            color = Colors.severity_color(entry["severity"])
            print(f"  [{ts}] {color}[{entry['severity']:<8}]{Colors.RESET} "
                  f"{entry['event_type']:<16} {entry['description']}")


# =============================================================================
# FIXED: RAWMODE Session Manager
# =============================================================================
class RawmodeSession:
    """Manages RAWMODE sessions with state tracking and audit logging."""
    
    def __init__(self, dev, verbose: bool = False, timeout: float = RAWMODE_TIMEOUT):
        self.dev = dev
        self.verbose = verbose
        self.timeout = timeout
        
        # Generate unique session ID
        seed = f"{getattr(dev, 'identifier', 'unknown')}{time.time()}{os.urandom(8).hex()}"
        self.session_id = hashlib.sha256(seed.encode()).hexdigest()[:SESSION_ID_LENGTH]
        
        # Session state
        self.privilege_level_num = PrivilegeLevel.USER
        self.features_enabled: List[str] = []
        self.start_time = time.time()
        self.active = True
        
        # Audit logger
        self.audit = AuditLogger()
        
        self.audit.log("SESSION_START", "INFO", 
                       f"Session {self.session_id} started",
                       {"session_id": self.session_id})
        
        if verbose:
            print(f"\n{Colors.CYAN}[*] RAWMODE Session: {self.session_id}{Colors.RESET}")
    
    @property
    def privilege_level(self) -> str:
        return PrivilegeLevel.get_name(self.privilege_level_num)
    
    def has_privilege(self, required_level: int) -> bool:
        """Check if session has sufficient privilege."""
        return self.privilege_level_num >= required_level
    
    def update_privilege(self, new_level: int):
        """Update privilege level with audit."""
        old_name = self.privilege_level
        old_num = self.privilege_level_num
        self.privilege_level_num = new_level
        new_name = self.privilege_level
        
        self.audit.log(
            "PRIVILEGE_CHANGE",
            "WARNING" if new_level > old_num else "INFO",
            f"Privilege changed: {old_name} -> {new_name}",
            {"old_level": old_num, "new_level": new_num}
        )
    
    def enable_feature(self, feature_name: str):
        """Track enabled feature."""
        feature = RawmodeFeature.get(feature_name)
        if not feature:
            return
        
        if feature_name not in self.features_enabled:
            self.features_enabled.append(feature_name)
            self.audit.log(
                "FEATURE_ENABLED",
                "WARNING" if RawmodeFeature.is_dangerous(feature_name) else "INFO",
                f"Feature enabled: {feature_name}",
                {"feature": feature_name, "risk": feature.get("risk")}
            )
    
    def disable_feature(self, feature_name: str):
        """Track disabled feature."""
        if feature_name in self.features_enabled:
            self.features_enabled.remove(feature_name)
            self.audit.log("FEATURE_DISABLED", "INFO", 
                          f"Feature disabled: {feature_name}")
    
    def close(self):
        """Close session with final audit."""
        if not self.active:
            return
        
        duration = time.time() - self.start_time
        self.audit.log(
            "SESSION_END",
            "INFO",
            f"Session ended after {duration:.1f}s, "
            f"privilege={self.privilege_level}, "
            f"features={len(self.features_enabled)}",
            {
                "duration": duration,
                "final_privilege": self.privilege_level,
                "features_enabled": self.features_enabled.copy(),
                "total_audit_entries": self.audit.count(),
            }
        )
        self.active = False
        
        if self.verbose:
            print(f"\n{Colors.CYAN}[*] Session closed: {self.session_id}{Colors.RESET}")
    
    def execute(self, opcode: int, data: bytes = b"") -> Tuple[bool, str, bytes]:
        """Execute a RAWMODE command with session context."""
        success, status_name, extra = dispatch_rawmode(
            self.dev, opcode, data, self.timeout
        )
        return success, status_name, extra


# =============================================================================
# FIXED: Data parsing functions
# =============================================================================
def parse_capability_data(data: bytes) -> Dict[str, Any]:
    """Parse capability data from device response."""
    capabilities = {
        'device_name': 'Unknown',
        'architecture': 'Unknown',
        'security_level': 'Unknown',
        'rawmode_support': True,
        'features': [],
        'privilege_levels': [],
        'hardware_access': 'Unknown',
    }
    
    try:
        if not data or len(data) < 32:
            return capabilities
        
        capabilities['device_name'] = data[0:16].decode('ascii', errors='ignore').rstrip('\x00').strip()
        capabilities['architecture'] = data[16:24].decode('ascii', errors='ignore').rstrip('\x00').strip()
        capabilities['security_level'] = data[24:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
        
        # Parse feature bitmap
        if len(data) >= 36:
            feature_bits = struct.unpack("<I", data[32:36])[0]
            all_features = RawmodeFeature.get_all_names()
            for i, name in enumerate(all_features):
                if i < 32 and (feature_bits >> i) & 1:
                    feat_info = RawmodeFeature.get(name)
                    capabilities['features'].append({
                        'name': name,
                        'description': feat_info.get('description', ''),
                        'risk': feat_info.get('risk', 'LOW'),
                        'requires_level': feat_info.get('requires_level', 0),
                        'enabled': False,
                    })
        
        # Parse privilege levels
        if len(data) >= 40:
            priv_bits = struct.unpack("<I", data[36:40])[0]
            for level in range(6):
                if (priv_bits >> level) & 1:
                    capabilities['privilege_levels'].append({
                        'level': level,
                        'name': PrivilegeLevel.get_name(level),
                        'description': PrivilegeLevel.get_description(level),
                        'current': False,
                    })
    
    except Exception as e:
        if _DEBUG:
            print(f"[!] Capability parse error: {e}")
    
    return capabilities


def parse_status_data(data: bytes) -> Dict[str, Any]:
    """Parse status data from device response."""
    status = {
        'mode': 'UNKNOWN',
        'privilege_level_name': 'USER',
        'privilege_level_num': 0,
        'security_state': 'UNKNOWN',
        'features_enabled': [],
        'hardware_access': 'UNKNOWN',
        'session_active': False,
    }
    
    try:
        if not data or len(data) < 16:
            return status
        
        status['mode'] = data[0:8].decode('ascii', errors='ignore').rstrip('\x00').strip() or 'UNKNOWN'
        status['privilege_level_name'] = data[8:12].decode('ascii', errors='ignore').rstrip('\x00').strip() or 'USER'
        status['security_state'] = data[12:16].decode('ascii', errors='ignore').rstrip('\x00').strip() or 'UNKNOWN'
        
        # Map privilege level name to number
        for num, name in PrivilegeLevel.NAMES.items():
            if name == status['privilege_level_name']:
                status['privilege_level_num'] = num
                break
        
        # Parse enabled features
        if len(data) >= 20:
            features_bits = struct.unpack("<I", data[16:20])[0]
            all_features = RawmodeFeature.get_all_names()
            for i, name in enumerate(all_features):
                if i < 32 and (features_bits >> i) & 1:
                    status['features_enabled'].append(name)
        
        # Parse hardware access
        if len(data) >= 24:
            hw_access_val = struct.unpack("<I", data[20:24])[0]
            status['hardware_access'] = {
                0: 'NONE', 1: 'LIMITED', 2: 'FULL', 3: 'UNRESTRICTED'
            }.get(hw_access_val, 'UNKNOWN')
        
        # Session active flag
        if len(data) >= 25:
            status['session_active'] = bool(data[24])
    
    except Exception as e:
        if _DEBUG:
            print(f"[!] Status parse error: {e}")
    
    return status


# =============================================================================
# FIXED: Display functions
# =============================================================================
def display_capabilities(capabilities: Dict, verbose: bool = False):
    """Display RAWMODE capabilities."""
    print(f"\n{Colors.BOLD}[+] RAWMODE Capabilities:{Colors.RESET}")
    
    info_rows = [
        ["Device", capabilities.get('device_name', 'Unknown')],
        ["Architecture", capabilities.get('architecture', 'Unknown')],
        ["Security Level", capabilities.get('security_level', 'Unknown')],
        ["Hardware Access", capabilities.get('hardware_access', 'Unknown')],
    ]
    
    col_width = max(len(r[0]) for r in info_rows)
    for label, value in info_rows:
        print(f"    {label:<{col_width}} : {value}")
    
    # Available features
    features = capabilities.get('features', [])
    if features:
        print(f"\n{Colors.BOLD}[+] Available Features ({len(features)}):{Colors.RESET}")
        for feat in features:
            name = feat.get('name', '?')
            desc = feat.get('description', '')
            risk = feat.get('risk', 'LOW')
            status_icon = f"{Colors.GREEN}✓{Colors.RESET}" if feat.get('enabled') else " "
            
            color = Colors.risk_color(risk)
            print(f"    [{status_icon}] {color}{name:<20}{Colors.RESET} {desc}")
            
            if verbose:
                req_level = feat.get('requires_level', 0)
                print(f"         Risk: {color}{risk}{Colors.RESET}, "
                      f"Requires: {PrivilegeLevel.get_name(req_level)}")
    
    # Supported privilege levels
    priv_levels = capabilities.get('privilege_levels', [])
    if priv_levels:
        print(f"\n{Colors.BOLD}[+] Supported Privilege Levels:{Colors.RESET}")
        for priv in priv_levels:
            current = f" {Colors.GREEN}← CURRENT{Colors.RESET}" if priv.get('current') else ""
            print(f"    Level {priv['level']}: {priv['name']:<15} {priv.get('description', '')}{current}")


def display_status(status_data: Dict, session: RawmodeSession, verbose: bool = False):
    """Display RAWMODE status."""
    print(f"\n{Colors.BOLD}[+] RAWMODE Status:{Colors.RESET}")
    
    mode = status_data.get('mode', 'UNKNOWN')
    priv_name = status_data.get('privilege_level_name', 'USER')
    priv_num = status_data.get('privilege_level_num', 0)
    security = status_data.get('security_state', 'UNKNOWN')
    hw_access = status_data.get('hardware_access', 'UNKNOWN')
    active = status_data.get('session_active', False)
    
    # Color code privilege level
    priv_color = Colors.RED if PrivilegeLevel.is_dangerous(priv_num) else Colors.GREEN
    
    info_rows = [
        ["Mode", mode],
        ["Privilege", f"{priv_color}{priv_name}{Colors.RESET}"],
        ["Security State", security],
        ["Hardware Access", hw_access],
        ["Session Active", f"{Colors.GREEN}Yes{Colors.RESET}" if active else "No"],
        ["Session ID", session.session_id],
        ["Duration", f"{time.time() - session.start_time:.1f}s"],
    ]
    
    col_width = max(len(r[0]) for r in info_rows)
    for label, value in info_rows:
        print(f"    {label:<{col_width}} : {value}")
    
    # Enabled features
    features = status_data.get('features_enabled', [])
    if features:
        print(f"\n{Colors.BOLD}[+] Enabled Features ({len(features)}):{Colors.RESET}")
        for name in features:
            feat_info = RawmodeFeature.get(name)
            risk = feat_info.get('risk', 'LOW') if feat_info else 'LOW'
            desc = feat_info.get('description', '') if feat_info else ''
            color = Colors.risk_color(risk)
            print(f"    {color}✓ {name:<20}{Colors.RESET} {desc}")
    else:
        print(f"\n    {Colors.CYAN}No features enabled{Colors.RESET}")
    
    # Audit summary
    if verbose and session.audit.count() > 0:
        print(f"\n{Colors.BOLD}[+] Recent Audit Events:{Colors.RESET}")
        session.audit.print_recent(5)


# =============================================================================
# FIXED: Subcommand implementations
# =============================================================================
def rawmode_list(session: RawmodeSession, args: List[str], 
                 force: bool = False, verbose: bool = False) -> int:
    """List available RAWMODE features and capabilities."""
    print(f"\n{Colors.CYAN}[*] Querying RAWMODE capabilities...{Colors.RESET}")
    
    success, status_name, extra = session.execute(RawmodeCommand.CAPABILITIES)
    
    if success:
        capabilities = parse_capability_data(extra)
        display_capabilities(capabilities, verbose)
        session.audit.log("CAPABILITIES_QUERY", "INFO", "Capabilities retrieved")
        return 0
    else:
        print(f"{Colors.RED}[!] Query failed: {status_name}{Colors.RESET}")
        session.audit.log("CAPABILITIES_QUERY", "ERROR", f"Failed: {status_name}")
        return 1


def rawmode_status(session: RawmodeSession, args: List[str],
                   force: bool = False, verbose: bool = False) -> int:
    """Get current RAWMODE status."""
    print(f"\n{Colors.CYAN}[*] Querying RAWMODE status...{Colors.RESET}")
    
    success, status_name, extra = session.execute(RawmodeCommand.STATUS)
    
    if success:
        status_data = parse_status_data(extra)
        display_status(status_data, session, verbose)
        session.audit.log("STATUS_QUERY", "INFO", "Status retrieved")
        return 0
    else:
        print(f"{Colors.RED}[!] Status query failed: {status_name}{Colors.RESET}")
        session.audit.log("STATUS_QUERY", "ERROR", f"Failed: {status_name}")
        return 1


def rawmode_unlock(session: RawmodeSession, args: List[str],
                   force: bool = False, verbose: bool = False) -> int:
    """Authenticate and unlock RAWMODE privileges."""
    print(f"\n{Colors.BOLD}========================================")
    print(f"  RAWMODE UNLOCK - FULL SYSTEM ACCESS")
    print(f"========================================{Colors.RESET}")
    
    # Build auth data
    auth_method = "DEFAULT"
    auth_data = b""
    
    if args:
        auth_method = args[0].upper()
        if len(args) > 1:
            raw = args[1]
            if raw.startswith("0x") or raw.startswith("0X"):
                try:
                    auth_data = bytes.fromhex(raw[2:])
                except ValueError:
                    auth_data = raw.encode('utf-8')
            elif len(raw) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', raw):
                try:
                    auth_data = bytes.fromhex(raw)
                except ValueError:
                    auth_data = raw.encode('utf-8')
            else:
                auth_data = raw.encode('utf-8')
    
    # Extreme safety warning
    warning = (
        "========================================\n"
        "  ⛔ CRITICAL SAFETY WARNING ⛔\n"
        "========================================\n"
        "\n"
        "  RAWMODE UNLOCK GRANTS COMPLETE SYSTEM CONTROL:\n"
        "  \n"
        "  🔴 Removes ALL software security protections\n"
        "  🔴 Grants bare-metal hardware access\n"
        "  🔴 Can PERMANENTLY BRICK the device\n"
        "  🔴 Voids ALL warranties\n"
        "  🔴 May violate laws in some jurisdictions\n"
        "  \n"
        "  ⚠️  This is for AUTHORIZED SECURITY RESEARCH ONLY\n"
        "  ⚠️  You assume ALL responsibility for consequences"
    )
    
    if not confirm_dangerous_action(warning, 'UNLOCK', force):
        session.audit.log("UNLOCK", "INFO", "Cancelled by user")
        return 0
    
    # Build and send command
    payload = auth_method.encode('ascii')[:8].ljust(8, b'\x00')
    payload += struct.pack("<I", len(auth_data))
    payload += auth_data
    
    success, status_name, extra = session.execute(RawmodeCommand.UNLOCK, payload)
    
    if success:
        print(f"\n{Colors.GREEN}[+] RAWMODE unlocked successfully!{Colors.RESET}")
        
        # Parse unlock response
        try:
            if len(extra) >= 8:
                priv_name = extra[0:8].decode('ascii', errors='ignore').rstrip('\x00').strip()
                priv_num = PrivilegeLevel.from_name(priv_name)
                if priv_num is not None:
                    session.update_privilege(priv_num)
                print(f"    Privilege Level: {Colors.RED}{priv_name}{Colors.RESET}")
        except Exception:
            pass
        
        session.audit.log("UNLOCK", "CRITICAL", "RAWMODE unlocked - full access granted")
        return 0
    else:
        print(f"{Colors.RED}[!] Unlock failed: {status_name}{Colors.RESET}")
        session.audit.log("UNLOCK", "ERROR", f"Failed: {status_name}")
        return 1


def rawmode_lock(session: RawmodeSession, args: List[str],
                 force: bool = False, verbose: bool = False) -> int:
    """Lock RAWMODE and reduce privileges."""
    lock_level = args[0].upper() if args else "FULL"
    print(f"\n{Colors.CYAN}[*] Locking RAWMODE ({lock_level})...{Colors.RESET}")
    
    payload = lock_level.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = session.execute(RawmodeCommand.LOCK, payload)
    
    if success:
        print(f"{Colors.GREEN}[+] RAWMODE locked successfully{Colors.RESET}")
        session.update_privilege(PrivilegeLevel.USER)
        session.features_enabled.clear()
        session.audit.log("LOCK", "INFO", f"RAWMODE locked: {lock_level}")
        return 0
    else:
        print(f"{Colors.RED}[!] Lock failed: {status_name}{Colors.RESET}")
        session.audit.log("LOCK", "ERROR", f"Failed: {status_name}")
        return 1


def rawmode_set(session: RawmodeSession, args: List[str],
                force: bool = False, verbose: bool = False) -> int:
    """Enable/configure a RAWMODE feature."""
    if not args:
        print(f"{Colors.RED}[!] Specify feature to enable{Colors.RESET}")
        print(f"[*] Available: {', '.join(RawmodeFeature.get_all_names())}")
        return 1
    
    feature_name = args[0].upper()
    feature = RawmodeFeature.get(feature_name)
    
    if not feature:
        print(f"{Colors.RED}[!] Unknown feature: {feature_name}{Colors.RESET}")
        print(f"[*] Available: {', '.join(RawmodeFeature.get_all_names())}")
        return 1
    
    value = args[1] if len(args) > 1 else "1"
    
    print(f"\n{Colors.CYAN}[*] Setting feature: {feature_name} = {value}{Colors.RESET}")
    print(f"    Description: {feature['description']}")
    print(f"    Risk: {Colors.risk_color(feature['risk'])}{feature['risk']}{Colors.RESET}")
    print(f"    Requires: {PrivilegeLevel.get_name(feature['requires_level'])}")
    
    # Check privilege
    if not session.has_privilege(feature['requires_level']):
        print(f"{Colors.RED}[!] Insufficient privilege for {feature_name}{Colors.RESET}")
        print(f"[*] Current: {session.privilege_level}, "
              f"Required: {PrivilegeLevel.get_name(feature['requires_level'])}")
        return 1
    
    # Danger confirmation for high-risk features
    if RawmodeFeature.is_dangerous(feature_name):
        warning = (
            f"========================================\n"
            f"  ⚠️  DANGEROUS FEATURE: {feature_name}\n"
            f"========================================\n"
            f"\n"
            f"  Risk Level: {feature['risk']}\n"
            f"  {feature['description']}\n"
            f"\n"
            f"  This may:\n"
            f"  - Compromise device security\n"
            f"  - Cause system instability\n"
            f"  - Void warranties\n"
            f"  - BRICK the device\n"
        )
        
        if not confirm_dangerous_action(warning, 'DANGER', force):
            session.audit.log("FEATURE_SET", "INFO", f"Cancelled: {feature_name}")
            return 0
    
    # Build and send command
    try:
        value_int = _parse_address(value)
    except ValueError:
        value_int = 1
    
    payload = struct.pack("<B", feature['opcode']) + struct.pack("<I", value_int)
    success, status_name, extra = session.execute(RawmodeCommand.SET_FEATURE, payload)
    
    if success:
        print(f"{Colors.GREEN}[+] Feature {feature_name} enabled{Colors.RESET}")
        session.enable_feature(feature_name)
        return 0
    else:
        print(f"{Colors.RED}[!] Failed: {status_name}{Colors.RESET}")
        session.audit.log("FEATURE_SET", "ERROR", f"Failed: {feature_name}")
        return 1


def rawmode_configure(session: RawmodeSession, args: List[str],
                      force: bool = False, verbose: bool = False) -> int:
    """Configure RAWMODE parameters."""
    if len(args) < 2:
        print(f"{Colors.RED}[!] Specify key and value{Colors.RESET}")
        print("[*] Usage: rawmode configure <KEY> <VALUE>")
        return 1
    
    key = args[0].upper()
    value_str = args[1]
    
    print(f"\n{Colors.CYAN}[*] Configuring: {key} = {value_str}{Colors.RESET}")
    
    # Build value bytes
    payload = key.encode('ascii')[:16].ljust(16, b'\x00')
    
    try:
        if value_str.startswith('0x') or value_str.startswith('0X'):
            payload += struct.pack("<I", int(value_str, 16))
        elif value_str.replace('.', '', 1).replace('-', '', 1).isdigit():
            if '.' in value_str:
                payload += struct.pack("<f", float(value_str))
            else:
                payload += struct.pack("<I", int(value_str))
        else:
            payload += value_str.encode('ascii')[:16].ljust(16, b'\x00')
    except ValueError:
        payload += value_str.encode('ascii')[:16].ljust(16, b'\x00')
    
    success, status_name, extra = session.execute(RawmodeCommand.CONFIGURE, payload)
    
    if success:
        print(f"{Colors.GREEN}[+] Configuration applied{Colors.RESET}")
        session.audit.log("CONFIGURE", "INFO", f"Set {key}={value_str}")
        return 0
    else:
        print(f"{Colors.RED}[!] Configuration failed: {status_name}{Colors.RESET}")
        session.audit.log("CONFIGURE", "ERROR", f"Failed: {key}")
        return 1


def rawmode_escalate(session: RawmodeSession, args: List[str],
                     force: bool = False, verbose: bool = False) -> int:
    """Escalate privileges to higher level."""
    if not args:
        print(f"{Colors.RED}[!] Specify target privilege level{Colors.RESET}")
        print(f"[*] Levels: {', '.join(PrivilegeLevel.get_all_names())}")
        return 1
    
    target_name = args[0].upper()
    target_level = PrivilegeLevel.from_name(target_name)
    
    if target_level is None:
        print(f"{Colors.RED}[!] Invalid level: {target_name}{Colors.RESET}")
        print(f"[*] Valid: {', '.join(PrivilegeLevel.get_all_names())}")
        return 1
    
    current_level = session.privilege_level_num
    
    if target_level <= current_level:
        print(f"{Colors.YELLOW}[!] Already at {session.privilege_level} or higher{Colors.RESET}")
        return 0
    
    print(f"\n{Colors.CYAN}[*] Escalating: {session.privilege_level} -> {target_name}{Colors.RESET}")
    
    # Danger confirmation for high privilege levels
    if PrivilegeLevel.is_dangerous(target_level):
        warning = (
            f"========================================\n"
            f"  ⛔ EXTREME PRIVILEGE ESCALATION ⛔\n"
            f"========================================\n"
            f"\n"
            f"  Target: {target_name}\n"
            f"  {PrivilegeLevel.get_description(target_level)}\n"
            f"\n"
            f"  🔴 Complete system control\n"
            f"  🔴 Bypasses ALL security\n"
            f"  🔴 Can permanently modify hardware\n"
            f"  🔴 IRREVERSIBLE changes possible\n"
        )
        
        if not confirm_dangerous_action(warning, 'ESCALATE', force):
            session.audit.log("ESCALATE", "INFO", f"Cancelled: {target_name}")
            return 0
    
    payload = target_name.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = session.execute(RawmodeCommand.ESCALATE, payload)
    
    if success:
        print(f"\n{Colors.GREEN}[+] Privilege escalated to {Colors.RED}{target_name}{Colors.RESET}")
        session.update_privilege(target_level)
        return 0
    else:
        print(f"{Colors.RED}[!] Escalation failed: {status_name}{Colors.RESET}")
        session.audit.log("ESCALATE", "ERROR", f"Failed: {target_name}")
        return 1


def rawmode_monitor(session: RawmodeSession, args: List[str],
                    force: bool = False, verbose: bool = False) -> int:
    """Monitor system activity."""
    monitor_type = args[0].upper() if args else "SYSTEM"
    duration = min(int(args[1]) if len(args) > 1 else 10, MAX_MONITOR_DURATION)
    
    print(f"\n{Colors.CYAN}[*] Monitoring {monitor_type} for {duration}s...{Colors.RESET}")
    print(f"[*] Press Ctrl+C to stop early")
    
    payload = monitor_type.encode('ascii')[:8].ljust(8, b'\x00')
    payload += struct.pack("<I", duration)
    
    try:
        success, status_name, extra = session.execute(
            RawmodeCommand.MONITOR, payload, timeout=float(duration + 10)
        )
        
        if success:
            print(f"\n{Colors.GREEN}[+] Monitoring completed{Colors.RESET}")
            if verbose and extra:
                print(f"    Data size: {len(extra)} bytes")
            session.audit.log("MONITOR", "INFO", f"{monitor_type} for {duration}s")
            return 0
        else:
            print(f"{Colors.RED}[!] Monitor failed: {status_name}{Colors.RESET}")
            session.audit.log("MONITOR", "ERROR", f"Failed: {monitor_type}")
            return 1
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Monitoring stopped by user{Colors.RESET}")
        session.audit.log("MONITOR", "INFO", f"Interrupted: {monitor_type}")
        return 0


def rawmode_audit(session: RawmodeSession, args: List[str],
                  force: bool = False, verbose: bool = False) -> int:
    """View audit logs."""
    audit_type = args[0].upper() if args else "ALL"
    
    print(f"\n{Colors.CYAN}[*] Audit Log ({audit_type}){Colors.RESET}")
    
    # Show local session audit
    print(f"\n{Colors.BOLD}[+] Local Session Audit ({session.audit.count()} entries):{Colors.RESET}")
    session.audit.print_recent(20)
    
    # Query device audit if available
    payload = audit_type.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = session.execute(RawmodeCommand.AUDIT, payload)
    
    if success and extra:
        print(f"\n{Colors.BOLD}[+] Device Audit Log:{Colors.RESET}")
        try:
            # Parse device audit log (32-byte entries)
            entries = []
            for i in range(0, min(len(extra), 320), 32):
                if i + 32 <= len(extra):
                    chunk = extra[i:i+32]
                    timestamp = struct.unpack("<I", chunk[0:4])[0]
                    event = chunk[4:12].decode('ascii', errors='ignore').rstrip('\x00')
                    severity = chunk[12:16].decode('ascii', errors='ignore').rstrip('\x00')
                    desc = chunk[16:32].decode('ascii', errors='ignore').rstrip('\x00')
                    
                    ts_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S") if timestamp else "N/A"
                    color = Colors.severity_color(severity)
                    print(f"  [{ts_str}] {color}[{severity:<8}]{Colors.RESET} {event:<12} {desc}")
        except Exception:
            print(f"  {Colors.CYAN}(binary audit data: {len(extra)} bytes){Colors.RESET}")
    
    session.audit.log("AUDIT_QUERY", "INFO", f"Type: {audit_type}")
    return 0


def rawmode_reset(session: RawmodeSession, args: List[str],
                  force: bool = False, verbose: bool = False) -> int:
    """Reset RAWMODE state or system."""
    reset_type = args[0].upper() if args else "SOFT"
    
    print(f"\n{Colors.CYAN}[*] Reset type: {reset_type}{Colors.RESET}")
    
    # Danger confirmation for destructive resets
    if reset_type in ("HARD", "FULL", "BOOTLOADER", "BOOTROM"):
        warning = (
            f"========================================\n"
            f"  ⚠️  {reset_type} RESET\n"
            f"========================================\n"
            f"\n"
            f"  This will:\n"
            f"  - {'Reboot the device' if reset_type in ('HARD', 'FULL') else ''}\n"
            f"  - Clear all RAWMODE state\n"
            f"  - {'Enter bootloader mode' if reset_type == 'BOOTLOADER' else ''}\n"
            f"  - Require reconnection\n"
        )
        
        if not confirm_dangerous_action(warning, 'RESET', force):
            session.audit.log("RESET", "INFO", f"Cancelled: {reset_type}")
            return 0
    
    payload = reset_type.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = session.execute(RawmodeCommand.RESET, payload)
    
    if success:
        print(f"{Colors.GREEN}[+] Reset initiated{Colors.RESET}")
        
        if reset_type in ("HARD", "FULL"):
            session.update_privilege(PrivilegeLevel.USER)
            session.features_enabled.clear()
        
        session.audit.log("RESET", "WARNING", f"Type: {reset_type}")
        return 0
    else:
        print(f"{Colors.RED}[!] Reset failed: {status_name}{Colors.RESET}")
        session.audit.log("RESET", "ERROR", f"Failed: {reset_type}")
        return 1


# =============================================================================
# FIXED: Subcommand dispatch table
# =============================================================================
RAWMODE_SUBCOMMANDS = {
    'list': rawmode_list,
    'ls': rawmode_list,
    'show': rawmode_list,
    
    'status': rawmode_status,
    'stat': rawmode_status,
    'info': rawmode_status,
    
    'unlock': rawmode_unlock,
    'auth': rawmode_unlock,
    'authenticate': rawmode_unlock,
    
    'lock': rawmode_lock,
    'disable': rawmode_lock,
    'off': rawmode_lock,
    
    'set': rawmode_set,
    'enable': rawmode_set,
    'on': rawmode_set,
    
    'configure': rawmode_configure,
    'config': rawmode_configure,
    'cfg': rawmode_configure,
    
    'escalate': rawmode_escalate,
    'priv': rawmode_escalate,
    'privilege': rawmode_escalate,
    
    'monitor': rawmode_monitor,
    'watch': rawmode_monitor,
    'trace': rawmode_monitor,
    
    'audit': rawmode_audit,
    'log': rawmode_audit,
    'history': rawmode_audit,
    
    'reset': rawmode_reset,
    'restart': rawmode_reset,
    'reboot': rawmode_reset,
    
    'help': None,  # Handled specially
    '?': None,
}


# =============================================================================
# FIXED: Help display
# =============================================================================
def print_rawmode_help():
    """Display RAWMODE command help."""
    print(f"""
{Colors.BOLD}RAWMODE - Privilege Escalation & Hardware Access Module{Colors.RESET}
{'='*60}

{Colors.BOLD}USAGE:{Colors.RESET}
  qslcl rawmode <subcommand> [args] [options]

{Colors.BOLD}SUBCOMMANDS:{Colors.RESET}

  {Colors.CYAN}Information:{Colors.RESET}
    list, ls, show          List available features and capabilities
    status, stat, info      Show current RAWMODE status
    audit, log, history     View audit and security logs

  {Colors.CYAN}Access Control:{Colors.RESET}
    unlock [method] [data]  Authenticate and unlock RAWMODE
    lock [level]            Lock RAWMODE (reduce privileges)
    escalate <level>        Escalate to higher privilege level

  {Colors.CYAN}Feature Management:{Colors.RESET}
    set <feature> [value]   Enable/configure a RAWMODE feature
    configure <key> <value> Set RAWMODE configuration parameter

  {Colors.CYAN}Operations:{Colors.RESET}
    monitor [type] [dur]    Monitor system activity
    reset [type]            Reset RAWMODE or system

{Colors.BOLD}PRIVILEGE LEVELS:{Colors.RESET}
  USER        - Normal user mode (default)
  PRIVILEGED  - Elevated system access
  SUPERVISOR  - Kernel-level access
  HYPERVISOR  - Virtualization control
  {Colors.RED}ROOT        - Complete system control{Colors.RESET}
  {Colors.RED}BOOTROM     - Boot ROM level (unrestricted){Colors.RESET}

{Colors.BOLD}AVAILABLE FEATURES:{Colors.RESET}
  MMU_BYPASS      - Bypass MMU protection
  SECURITY_DISABLE- Disable security features
  JTAG_ENABLE     - Enable JTAG debugging
  BOOTROM_ACCESS  - Access boot ROM
  DMA_ENABLE      - Enable DMA
  REGISTER_ACCESS - Access protected registers
  DEBUG_ENABLE    - Enable debug features
  TRACE_ENABLE    - Enable tracing

{Colors.BOLD}OPTIONS:{Colors.RESET}
  --force, -f     Skip safety confirmations {Colors.RED}(DANGEROUS){Colors.RESET}
  --verbose, -v   Verbose output
  --timeout N     Command timeout (default: 10s)
  --loader FILE   Load qslcl.bin first
  --wait N        Wait N seconds for device

{Colors.BOLD}EXAMPLES:{Colors.RESET}
  qslcl rawmode list
  qslcl rawmode status -v
  qslcl rawmode unlock
  qslcl rawmode escalate ROOT --force
  qslcl rawmode set JTAG_ENABLE 1
  qslcl rawmode monitor SYSTEM 30
  qslcl rawmode audit

{Colors.RED}{Colors.BOLD}⚠️  SAFETY WARNINGS:{Colors.RESET}
  - RAWMODE can {Colors.RED}PERMANENTLY BRICK{Colors.RESET} devices
  - All operations are {Colors.RED}LOGGED{Colors.RESET} for auditing
  - Use {Colors.YELLOW}--force{Colors.RESET} only when absolutely necessary
  - For {Colors.BRIGHT_RED}AUTHORIZED RESEARCH ONLY{Colors.RESET}
""")


# =============================================================================
# FIXED: Main command function
# =============================================================================
def cmd_rawmode(args=None) -> int:
    """
    QSLCL RAWMODE Command v2.0 (FIXED)
    
    Manages privilege escalation and hardware access with:
    - Comprehensive safety warnings and confirmation
    - Session-based state management
    - Full audit logging
    - Feature management with risk levels
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # Input validation
    # =========================================================================
    if args is None:
        print(f"{Colors.RED}[!] No arguments provided{Colors.RESET}")
        print_rawmode_help()
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
            print(f"{Colors.RED}[!] Device scan failed: {e}{Colors.RESET}")
            return 1
        
        if not devs:
            print(f"{Colors.RED}[!] No device connected{Colors.RESET}")
            return 1
        
        dev = devs[0]
        print(f"{Colors.CYAN}[*] Device: {dev.product} ({dev.vendor}){Colors.RESET}")
    else:
        print(f"{Colors.RED}[!] Cannot access device in standalone mode{Colors.RESET}")
        return 1
    
    # =========================================================================
    # Loader injection
    # =========================================================================
    if hasattr(args, 'loader') and args.loader:
        try:
            _auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"{Colors.RED}[!] Loader injection failed: {e}{Colors.RESET}")
            return 1
    
    # =========================================================================
    # Extract subcommand
    # =========================================================================
    subcommand = None
    for attr in ['rawmode_subcommand', 'subcommand']:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                subcommand = val.lower().strip()
                break
    
    if not subcommand:
        print(f"{Colors.RED}[!] No subcommand specified{Colors.RESET}")
        print_rawmode_help()
        return 1
    
    if subcommand in ('help', '?', '-h', '--help'):
        print_rawmode_help()
        return 0
    
    # Extract other args
    rawmode_args = getattr(args, 'rawmode_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    timeout = getattr(args, 'timeout', RAWMODE_TIMEOUT)
    
    # =========================================================================
    # Initialize session
    # =========================================================================
    session = RawmodeSession(dev, verbose=verbose, timeout=timeout)
    
    try:
        handler = RAWMODE_SUBCOMMANDS.get(subcommand)
        
        if handler is None:
            print(f"{Colors.RED}[!] Unknown subcommand: {subcommand}{Colors.RESET}")
            print_rawmode_help()
            return 1
        
        return handler(session, rawmode_args, force, verbose)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Operation interrupted{Colors.RESET}")
        session.audit.log("INTERRUPT", "WARNING", "User interrupted operation")
        return 1
    
    except Exception as e:
        print(f"{Colors.RED}[!] RAWMODE operation failed: {type(e).__name__}: {e}{Colors.RESET}")
        session.audit.log("ERROR", "CRITICAL", f"Exception: {type(e).__name__}: {e}")
        if verbose and _DEBUG:
            traceback.print_exc()
        return 1
    
    finally:
        session.close()


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_rawmode_arguments(parser) -> None:
    """Add RAWMODE-specific arguments to an argument parser."""
    parser.add_argument(
        'rawmode_subcommand',
        nargs='?',
        help='RAWMODE subcommand (list, status, unlock, lock, set, configure, '
             'escalate, monitor, audit, reset)'
    )
    parser.add_argument(
        'rawmode_args',
        nargs='*',
        help='Additional arguments for the subcommand'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with detailed information'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Bypass safety confirmation prompts (DANGEROUS)'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=RAWMODE_TIMEOUT,
        help=f'Command timeout in seconds (default: {RAWMODE_TIMEOUT})'
    )
    return parser


# =============================================================================
# Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] rawmode.py - QSLCL RAWMODE Command Module v2.0")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py rawmode <subcommand> [options]")
    print()
    print_rawmode_help()