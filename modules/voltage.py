#!/usr/bin/env python3
"""
voltage.py - QSLCL VOLTAGE Command Module v2.0 (FIXED)
Fixed: Import handling, voltage safety, PMIC access, monitoring,
       calibration stubs, error recovery, data parsing
"""

import os
import sys
import re
import struct
import time
import signal
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
VOLTAGE_TIMEOUT = 5.0
MAX_RETRIES = 3
DEFAULT_VERIFY_TOLERANCE_UV = 20000  # 20mV
MAX_RAILS = 50
MAX_VOLTAGE_UV = 5000000  # 5V maximum
MIN_VOLTAGE_UV = 0

# =============================================================================
# FIXED: ANSI color codes
# =============================================================================
class Colors:
    """Terminal color codes."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BRIGHT_RED = '\033[91;1m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    @classmethod
    def status_color(cls, status: str) -> str:
        status_upper = status.upper().strip()
        if status_upper in ('OK', 'NORMAL', 'STABLE', 'ON'):
            return cls.GREEN
        elif status_upper in ('WARNING', 'HIGH', 'LOW', 'STANDBY'):
            return cls.YELLOW
        else:
            return cls.RED


# =============================================================================
# FIXED: Voltage opcodes
# =============================================================================
class VoltageOpcode:
    """Voltage command opcodes."""
    CAPABILITIES = 0x00
    READ = 0x10
    SET = 0x20
    SET_FV_PAIR = 0x30
    MONITOR = 0x40
    CALIBRATE = 0x50
    RESET = 0x60
    PMIC_READ = 0x70
    PMIC_WRITE = 0x71


# =============================================================================
# FIXED: Voltage safety ranges (in microvolts)
# =============================================================================
VOLTAGE_SAFETY_RANGES: Dict[str, Tuple[int, int, str]] = {
    'VDD_CORE':     (700000, 1350000, "0.70V-1.35V"),
    'VDD_CPU':      (650000, 1250000, "0.65V-1.25V"),
    'VDD_CPU_BIG':  (650000, 1250000, "0.65V-1.25V"),
    'VDD_CPU_LITTLE': (600000, 1100000, "0.60V-1.10V"),
    'VDD_GPU':      (600000, 1150000, "0.60V-1.15V"),
    'VDD_DDR':      (1050000, 1400000, "1.05V-1.40V"),
    'VDD_MEM':      (850000, 1150000, "0.85V-1.15V"),
    'VDD_IO':       (1500000, 3400000, "1.50V-3.40V"),
    'VDD_AON':      (850000, 1150000, "0.85V-1.15V"),
    'VDD_SRAM':     (700000, 1000000, "0.70V-1.00V"),
    'VDD_PLL':      (800000, 1200000, "0.80V-1.20V"),
    'VDD_MODEM':    (800000, 1200000, "0.80V-1.20V"),
    'VDD_DSP':      (700000, 1100000, "0.70V-1.10V"),
}

CRITICAL_RAIL_KEYWORDS = ['CORE', 'CPU', 'SOC', 'DDR', 'BOOT']


# =============================================================================
# FIXED: Find command helper
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
# FIXED: Voltage dispatch helper
# =============================================================================
def dispatch_voltage(dev, opcode: int, data: bytes = b"", 
                     timeout: float = None) -> Tuple[bool, str, bytes]:
    """
    Dispatch a voltage command.
    
    Returns:
        Tuple[bool, str, bytes]: (success, status_name, extra_data)
    """
    if not _use_qslcl:
        return False, "NO_QSLCL_SUPPORT", b""
    
    if timeout is None:
        timeout = VOLTAGE_TIMEOUT
    
    payload = struct.pack("<B", opcode) + data
    
    for attempt in range(MAX_RETRIES):
        try:
            if find_command("VOLTAGE"):
                resp = _qslcl_dispatch(dev, "VOLTAGE", payload, timeout=timeout)
            else:
                resp = _qslcl_dispatch(dev, "VOLTAGE", payload, timeout=timeout)
            
            if resp:
                status = _decode_runtime_result(resp)
                severity = status.get("severity", "ERROR")
                name = status.get("name", "UNKNOWN")
                extra = status.get("extra", b"")
                return severity == "SUCCESS", name, extra
        
        except Exception as e:
            if _DEBUG:
                print(f"[!] Voltage dispatch attempt {attempt+1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.2 * (attempt + 1))
    
    return False, "NO_RESPONSE", b""


# =============================================================================
# FIXED: Interactive confirmation
# =============================================================================
def confirm_dangerous(prompt: str, required: str, force: bool = False) -> bool:
    """Request confirmation for dangerous operations."""
    if force:
        print(f"\n{Colors.YELLOW}[!] Force mode: Skipping confirmation{Colors.RESET}")
        return True
    
    print(f"\n{Colors.BRIGHT_RED}{prompt}{Colors.RESET}")
    try:
        response = input(f"    Type '{required}' to confirm: ")
        return response == required
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Colors.YELLOW}[!] Input not available{Colors.RESET}")
        return False


# =============================================================================
# FIXED: Parse voltage value from string
# =============================================================================
def parse_voltage_value(value_str: str, unit: str = "V") -> Tuple[bool, int, str]:
    """
    Parse a voltage value string into microvolts.
    
    Returns:
        Tuple[bool, int, str]: (success, microvolts, error_message)
    """
    value_str = value_str.strip()
    unit = unit.upper().strip()
    
    try:
        # Handle scientific notation
        clean = ''.join(c for c in value_str if c.isdigit() or c in '.-eE')
        if not clean:
            return False, 0, f"No numeric value in '{value_str}'"
        
        value = float(clean)
        
        # Convert to microvolts
        if unit in ('V', 'VOLTS'):
            uv = int(value * 1_000_000)
        elif unit in ('MV', 'MILLIVOLTS'):
            uv = int(value * 1_000)
        elif unit in ('UV', 'MICROVOLTS'):
            uv = int(value)
        else:
            return False, 0, f"Unknown unit: {unit}. Use V, mV, or uV"
        
        # Sanity check
        if uv < MIN_VOLTAGE_UV or uv > MAX_VOLTAGE_UV:
            return False, uv, f"Voltage {value}{unit} outside 0-5V range"
        
        return True, uv, ""
        
    except (ValueError, OverflowError) as e:
        return False, 0, f"Invalid voltage: {e}"


# =============================================================================
# FIXED: Parse frequency value from string
# =============================================================================
def parse_frequency(freq_str: str) -> Tuple[bool, int, str]:
    """
    Parse frequency string into Hz.
    
    Returns:
        Tuple[bool, int, str]: (success, hertz, error_message)
    """
    freq_str = freq_str.upper().strip()
    
    multipliers = {
        'HZ': 1, 'H': 1,
        'KHZ': 1_000, 'K': 1_000, 'KH': 1_000,
        'MHZ': 1_000_000, 'M': 1_000_000, 'MH': 1_000_000,
        'GHZ': 1_000_000_000, 'G': 1_000_000_000, 'GH': 1_000_000_000,
    }
    
    # Extract numeric part
    numeric = ''.join(c for c in freq_str if c.isdigit() or c in '.-')
    suffix = ''.join(c for c in freq_str if c.isalpha())
    
    if not numeric:
        return False, 0, f"No numeric value in '{freq_str}'"
    
    try:
        value = float(numeric)
        multiplier = multipliers.get(suffix, 1)
        hz = int(value * multiplier)
        
        if hz <= 0:
            return False, 0, "Frequency must be positive"
        
        return True, hz, ""
    except (ValueError, OverflowError) as e:
        return False, 0, f"Invalid frequency: {e}"


# =============================================================================
# FIXED: Voltage safety validation
# =============================================================================
def validate_voltage_safety(rail_name: str, voltage_uv: int) -> Tuple[bool, str]:
    """
    Check if voltage is within safe operating range.
    
    Returns:
        Tuple[bool, str]: (is_safe, message)
    """
    # Check against known safety ranges
    rail_upper = rail_name.upper()
    
    for known_rail, (min_uv, max_uv, range_str) in VOLTAGE_SAFETY_RANGES.items():
        if known_rail in rail_upper or rail_upper in known_rail:
            if min_uv <= voltage_uv <= max_uv:
                return True, f"Within safe range ({range_str})"
            else:
                voltage_v = voltage_uv / 1_000_000
                return False, f"Out of range: {voltage_v:.3f}V not in {range_str}"
    
    # Unknown rail - basic sanity check
    if voltage_uv < 500_000:  # Below 0.5V
        voltage_v = voltage_uv / 1_000_000
        return False, f"Unusually low for unknown rail ({voltage_v:.3f}V)"
    
    if voltage_uv > 4_000_000:  # Above 4V
        voltage_v = voltage_uv / 1_000_000
        return False, f"Unusually high for unknown rail ({voltage_v:.3f}V)"
    
    return True, "Unknown rail - proceed with caution"


def is_critical_rail(rail_name: str) -> bool:
    """Check if a rail name indicates a critical voltage rail."""
    rail_upper = rail_name.upper()
    return any(keyword in rail_upper for keyword in CRITICAL_RAIL_KEYWORDS)


# =============================================================================
# FIXED: Voltage data parsing
# =============================================================================
def parse_voltage_data(data: bytes) -> Dict[str, Any]:
    """Parse single voltage reading from response data."""
    result = {
        'voltage_uv': -1,
        'voltage_v': -1.0,
        'status': 'UNKNOWN',
        'current_ma': 0,
        'temperature_c': 0,
    }
    
    try:
        if not data or len(data) < 12:
            return result
        
        result['voltage_uv'] = struct.unpack("<I", data[0:4])[0]
        result['voltage_v'] = result['voltage_uv'] / 1_000_000.0
        result['status'] = data[4:8].decode('ascii', errors='ignore').rstrip('\x00').strip() or 'UNKNOWN'
        
        if len(data) >= 12:
            result['current_ma'] = struct.unpack("<I", data[8:12])[0]
        
        if len(data) >= 16:
            result['temperature_c'] = struct.unpack("<i", data[12:16])[0] / 1000.0
        
    except (struct.error, UnicodeDecodeError) as e:
        if _DEBUG:
            print(f"[!] Voltage data parse error: {e}")
    
    return result


def parse_all_voltages(data: bytes) -> Dict[str, Dict[str, Any]]:
    """Parse multiple voltage readings from response data."""
    voltages = {}
    
    if not data or len(data) < 16:
        return voltages
    
    try:
        pos = 0
        rail_count = 0
        
        while pos + 16 <= len(data) and rail_count < MAX_RAILS:
            name_bytes = data[pos:pos+8]
            rail_name = name_bytes.decode('ascii', errors='ignore').rstrip('\x00').strip()
            
            voltage_uv = struct.unpack("<I", data[pos+8:pos+12])[0]
            status_bytes = data[pos+12:pos+16]
            status = status_bytes.decode('ascii', errors='ignore').rstrip('\x00').strip() or 'UNKNOWN'
            
            if rail_name and len(rail_name) >= 2:
                voltages[rail_name] = {
                    'voltage_uv': voltage_uv,
                    'voltage_v': voltage_uv / 1_000_000.0,
                    'status': status,
                }
                rail_count += 1
            
            pos += 16
    
    except (struct.error, UnicodeDecodeError) as e:
        if _DEBUG:
            print(f"[!] Multi-voltage parse error: {e}")
    
    return voltages


# =============================================================================
# FIXED: Display functions
# =============================================================================
def display_voltage_reading(rail_name: str, data: Dict[str, Any], timestamp: float = 0):
    """Display a single voltage reading."""
    voltage_v = data.get('voltage_v', data.get('voltage_uv', 0) / 1_000_000.0)
    status = data.get('status', 'UNKNOWN')
    current_ma = data.get('current_ma', 0)
    temp_c = data.get('temperature_c', 0)
    
    color = Colors.status_color(status)
    ts_prefix = f"[{timestamp:6.1f}s] " if timestamp > 0 else ""
    
    parts = [f"{ts_prefix}{rail_name}: {color}{voltage_v:.3f}V [{status}]{Colors.RESET}"]
    
    if current_ma > 0:
        if current_ma >= 1000:
            parts.append(f"{current_ma/1000:.1f}A")
        else:
            parts.append(f"{current_ma}mA")
    
    if temp_c != 0:
        parts.append(f"{temp_c:.1f}°C")
    
    print(" ".join(parts))


def display_all_voltages(voltages: Dict[str, Dict], timestamp: float = 0) -> bool:
    """Display all voltage readings."""
    if not voltages:
        ts_str = f"[{timestamp:6.1f}s] " if timestamp > 0 else ""
        print(f"{ts_str}No voltage data")
        return False
    
    ts_prefix = f"[{timestamp:6.1f}s] " if timestamp > 0 else ""
    print(ts_prefix, end="")
    
    for rail_name in sorted(voltages.keys()):
        data = voltages[rail_name]
        voltage_v = data.get('voltage_v', 0)
        status = data.get('status', 'UNKNOWN')
        color = Colors.status_color(status)
        print(f"{rail_name}:{color}{voltage_v:.3f}V{Colors.RESET} ", end="")
    
    print()
    return True


# =============================================================================
# FIXED: Voltage rail capabilities database
# =============================================================================
def get_default_voltage_rails() -> List[Dict[str, Any]]:
    """Get default voltage rail definitions for various architectures."""
    return [
        {'name': 'VDD_CORE', 'description': 'Core logic voltage', 
         'current_uv': 1100000, 'target_uv': 1100000, 
         'min_uv': 800000, 'max_uv': 1300000, 'enabled': True},
        {'name': 'VDD_CPU', 'description': 'CPU voltage',
         'current_uv': 1000000, 'target_uv': 1000000,
         'min_uv': 700000, 'max_uv': 1200000, 'enabled': True},
        {'name': 'VDD_GPU', 'description': 'GPU voltage',
         'current_uv': 900000, 'target_uv': 900000,
         'min_uv': 700000, 'max_uv': 1100000, 'enabled': True},
        {'name': 'VDD_DDR', 'description': 'DRAM voltage',
         'current_uv': 1200000, 'target_uv': 1200000,
         'min_uv': 1100000, 'max_uv': 1350000, 'enabled': True},
        {'name': 'VDD_MEM', 'description': 'Memory controller voltage',
         'current_uv': 1000000, 'target_uv': 1000000,
         'min_uv': 900000, 'max_uv': 1100000, 'enabled': True},
        {'name': 'VDD_IO', 'description': 'I/O voltage',
         'current_uv': 1800000, 'target_uv': 1800000,
         'min_uv': 1500000, 'max_uv': 3300000, 'enabled': True},
        {'name': 'VDD_AON', 'description': 'Always-on domain',
         'current_uv': 1000000, 'target_uv': 1000000,
         'min_uv': 900000, 'max_uv': 1100000, 'enabled': True},
    ]


def get_default_power_domains() -> List[Dict[str, str]]:
    """Get default power domain definitions."""
    return [
        {'name': 'PD_CPU', 'description': 'CPU power domain', 'state': 'ON'},
        {'name': 'PD_GPU', 'description': 'GPU power domain', 'state': 'ON'},
        {'name': 'PD_DSP', 'description': 'DSP power domain', 'state': 'OFF'},
        {'name': 'PD_MODEM', 'description': 'Modem power domain', 'state': 'ON'},
        {'name': 'PD_DISPLAY', 'description': 'Display power domain', 'state': 'ON'},
        {'name': 'PD_AUDIO', 'description': 'Audio power domain', 'state': 'ON'},
        {'name': 'PD_SENSORS', 'description': 'Sensors power domain', 'state': 'OFF'},
        {'name': 'PD_CAMERA', 'description': 'Camera power domain', 'state': 'OFF'},
    ]


def query_voltage_capabilities(dev, verbose: bool = False) -> Dict[str, Any]:
    """Query device voltage capabilities."""
    capabilities = {
        'pmic_name': 'Unknown PMIC',
        'architecture': 'Unknown',
        'voltage_control': 'Basic',
        'voltage_rails': [],
        'power_domains': [],
    }
    
    if not _use_qslcl:
        capabilities['voltage_rails'] = get_default_voltage_rails()
        capabilities['power_domains'] = get_default_power_domains()
        return capabilities
    
    success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.CAPABILITIES)
    
    if success and extra:
        try:
            if len(extra) >= 16:
                capabilities['pmic_name'] = extra[0:16].decode('ascii', errors='ignore').rstrip('\x00').strip()
            if len(extra) >= 32:
                capabilities['architecture'] = extra[16:32].decode('ascii', errors='ignore').rstrip('\x00').strip()
        except Exception:
            pass
    
    # Fill defaults if query didn't return rails
    if not capabilities['voltage_rails']:
        capabilities['voltage_rails'] = get_default_voltage_rails()
    if not capabilities['power_domains']:
        capabilities['power_domains'] = get_default_power_domains()
    
    return capabilities


def verify_voltage_setting(dev, rail_name: str, expected_uv: int, 
                           tolerance_uv: int = DEFAULT_VERIFY_TOLERANCE_UV,
                           max_attempts: int = 3) -> bool:
    """Verify voltage was set correctly with retries."""
    
    for attempt in range(max_attempts):
        time.sleep(0.05 * (attempt + 1))
        
        data = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.READ, data)
        
        if not success:
            continue
        
        voltage_data = parse_voltage_data(extra)
        actual_uv = voltage_data.get('voltage_uv', -1)
        
        if actual_uv < 0:
            continue
        
        difference = abs(actual_uv - expected_uv)
        
        if difference <= tolerance_uv:
            actual_v = actual_uv / 1_000_000.0
            expected_v = expected_uv / 1_000_000.0
            print(f"  {Colors.GREEN}✓ Verified: {actual_v:.3f}V (target: {expected_v:.3f}V){Colors.RESET}")
            return True
        
        if attempt < max_attempts - 1:
            actual_v = actual_uv / 1_000_000.0
            expected_v = expected_uv / 1_000_000.0
            print(f"  Attempt {attempt+1}: {actual_v:.3f}V ≠ {expected_v:.3f}V")
    
    actual_v = actual_uv / 1_000_000.0 if 'actual_uv' in dir() else "?"
    expected_v = expected_uv / 1_000_000.0
    print(f"  {Colors.RED}✗ Verification failed after {max_attempts} attempts{Colors.RESET}")
    return False


# =============================================================================
# FIXED: Command implementations
# =============================================================================
def voltage_list(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """List voltage rails and power domains."""
    print(f"\n{Colors.CYAN}[*] Voltage System Overview{Colors.RESET}")
    
    capabilities = query_voltage_capabilities(dev, verbose)
    
    print(f"    PMIC:          {capabilities.get('pmic_name', 'Unknown')}")
    print(f"    Architecture:  {capabilities.get('architecture', 'Unknown')}")
    print(f"    Control:       {capabilities.get('voltage_control', 'Basic')}")
    
    # Rails
    rails = capabilities.get('voltage_rails', [])
    if rails:
        print(f"\n{Colors.BOLD}[+] Voltage Rails ({len(rails)}):{Colors.RESET}")
        print(f"    {'#':<3} {'Status':<6} {'Name':<18} {'Current':<10} {'Range':<20} Description")
        print(f"    {'-'*3} {'-'*6} {'-'*18} {'-'*10} {'-'*20} {'-'*20}")
        
        for i, rail in enumerate(rails, 1):
            status = "✓" if rail.get('enabled', False) else "✗"
            name = rail.get('name', '?')
            current = rail.get('current_uv', 0)
            current_v = f"{current/1_000_000:.3f}V" if current > 0 else "N/A"
            min_v = f"{rail.get('min_uv', 0)/1_000_000:.2f}"
            max_v = f"{rail.get('max_uv', 0)/1_000_000:.2f}"
            voltage_range = f"{min_v}V-{max_v}V" if rail.get('min_uv', 0) > 0 else "Unknown"
            desc = rail.get('description', '')[:20]
            
            print(f"    {i:<3} [{status}]  {name:<18} {current_v:<10} {voltage_range:<20} {desc}")
    
    # Power domains
    domains = capabilities.get('power_domains', [])
    if domains:
        print(f"\n{Colors.BOLD}[+] Power Domains ({len(domains)}):{Colors.RESET}")
        state_icons = {'ON': '🟢', 'OFF': '🔴', 'STANDBY': '🟡', 'SLEEP': '💤'}
        
        for i, domain in enumerate(domains, 1):
            state = domain.get('state', 'UNKNOWN')
            icon = state_icons.get(state, '❓')
            name = domain.get('name', '?')
            desc = domain.get('description', '')
            print(f"    {i:2d}. {icon} {name:<20} {desc}")
    
    return 0


def voltage_read(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Read voltage values."""
    if not args or (len(args) == 1 and args[0].upper() == 'ALL'):
        print(f"\n{Colors.CYAN}[*] Reading all voltage rails...{Colors.RESET}")
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.READ)
        
        if success:
            voltages = parse_all_voltages(extra)
            if voltages:
                print()
                for name in sorted(voltages.keys()):
                    display_voltage_reading(name, voltages[name])
                print(f"\n{Colors.GREEN}[+] {len(voltages)} rails read{Colors.RESET}")
                return 0
            else:
                # Try individual reads
                print(f"{Colors.YELLOW}[*] Bulk read returned no data, trying individual reads...{Colors.RESET}")
                capabilities = query_voltage_capabilities(dev, verbose)
                rails = capabilities.get('voltage_rails', [])
                
                for rail in rails:
                    name = rail['name']
                    data = name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
                    success, _, extra = dispatch_voltage(dev, VoltageOpcode.READ, data)
                    if success:
                        vdata = parse_voltage_data(extra)
                        display_voltage_reading(name, vdata)
                
                return 0
        
        print(f"{Colors.RED}[!] Read failed: {status_name}{Colors.RESET}")
        return 1
    
    # Read specific rail
    rail_name = args[0].upper()
    print(f"\n{Colors.CYAN}[*] Reading: {rail_name}{Colors.RESET}")
    
    data = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
    success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.READ, data)
    
    if success:
        voltage_data = parse_voltage_data(extra)
        if voltage_data.get('voltage_uv', -1) >= 0:
            display_voltage_reading(rail_name, voltage_data)
            return 0
    
    print(f"{Colors.RED}[!] Read failed: {status_name}{Colors.RESET}")
    return 1


def voltage_set(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Set voltage to specific value."""
    if len(args) < 2:
        print(f"{Colors.RED}[!] Usage: voltage set <rail> <value> [unit]{Colors.RESET}")
        print("[*] Example: voltage set VDD_CPU 1.1 V")
        return 1
    
    rail_name = args[0].upper()
    voltage_str = args[1]
    unit = args[2].upper() if len(args) > 2 else "V"
    
    # Parse voltage
    ok, target_uv, error = parse_voltage_value(voltage_str, unit)
    if not ok:
        print(f"{Colors.RED}[!] {error}{Colors.RESET}")
        return 1
    
    target_v = target_uv / 1_000_000.0
    print(f"\n{Colors.CYAN}[*] Setting {rail_name} to {target_v:.3f}V ({target_uv}µV){Colors.RESET}")
    
    # Safety validation
    safe, msg = validate_voltage_safety(rail_name, target_uv)
    if not safe:
        print(f"{Colors.RED}[!] Safety: {msg}{Colors.RESET}")
        if not force:
            return 1
    
    # Critical rail warning
    if is_critical_rail(rail_name):
        if not confirm_dangerous(
            f"⚠️  CRITICAL RAIL: {rail_name}\n"
            f"Setting to {target_v:.3f}V may damage the device!\n"
            f"Incorrect voltage can cause PERMANENT HARDWARE DAMAGE.",
            'VOLTAGE', force
        ):
            return 0
    
    # Dispatch
    payload = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
    payload += struct.pack("<I", target_uv)
    
    success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.SET, payload)
    
    if success:
        print(f"{Colors.GREEN}[+] Voltage set: {rail_name} = {target_v:.3f}V{Colors.RESET}")
        
        if verbose:
            tolerance = getattr(args, 'tolerance', DEFAULT_VERIFY_TOLERANCE_UV) if hasattr(args, 'tolerance') else DEFAULT_VERIFY_TOLERANCE_UV
            verify_voltage_setting(dev, rail_name, target_uv, tolerance)
        return 0
    else:
        print(f"{Colors.RED}[!] Set failed: {status_name}{Colors.RESET}")
        return 1


def voltage_monitor(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Monitor voltage rails in real-time."""
    monitor_rail = args[0].upper() if args else "ALL"
    duration = max(1, min(3600, float(args[1]) if len(args) > 1 else 30))
    interval = max(0.1, min(60, float(args[2]) if len(args) > 2 else 1.0))
    
    print(f"\n{Colors.CYAN}[*] Monitoring {monitor_rail} for {duration}s (every {interval}s){Colors.RESET}")
    print(f"[*] Press Ctrl+C to stop")
    print(f"\n{' Timestamp':<12} Readings")
    print(f"{'-'*12} {'-'*60}")
    
    interrupted = False
    
    def handler(signum, frame):
        nonlocal interrupted
        interrupted = True
    
    old_handler = signal.signal(signal.SIGINT, handler)
    
    start = time.time()
    samples = 0
    
    try:
        while (time.time() - start) < duration and not interrupted:
            elapsed = time.time() - start
            
            if monitor_rail == "ALL":
                success, _, extra = dispatch_voltage(dev, VoltageOpcode.READ, timeout=2.0)
                if success:
                    voltages = parse_all_voltages(extra)
                    display_all_voltages(voltages, elapsed)
                else:
                    print(f"[{elapsed:6.1f}s] Read failed")
            else:
                data = monitor_rail.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
                success, _, extra = dispatch_voltage(dev, VoltageOpcode.READ, data, timeout=2.0)
                if success:
                    vdata = parse_voltage_data(extra)
                    display_voltage_reading(monitor_rail, vdata, elapsed)
                else:
                    print(f"[{elapsed:6.1f}s] {monitor_rail}: Read failed")
            
            samples += 1
            
            # Calculate sleep
            remaining = start + (samples * interval) - time.time()
            if remaining > 0:
                time.sleep(remaining)
    
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_handler)
    
    total = time.time() - start
    print(f"\n{Colors.CYAN}[*] Monitoring complete: {samples} samples in {total:.1f}s{Colors.RESET}")
    return 0


def voltage_scale(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Scale voltage by factor or set frequency-voltage pair."""
    if len(args) < 2:
        print(f"{Colors.RED}[!] Usage: voltage scale <rail> <factor> or <rail> <freq> <volt>{Colors.RESET}")
        return 1
    
    rail_name = args[0].upper()
    
    if len(args) == 2:
        # Simple scaling factor
        try:
            factor = float(args[1])
            if factor <= 0:
                print(f"{Colors.RED}[!] Scale factor must be positive{Colors.RESET}")
                return 1
            if factor > 1.5 and not force:
                print(f"{Colors.YELLOW}[!] Scale factor {factor}x may be dangerous{Colors.RESET}")
                if not confirm_dangerous(f"Scale {rail_name} by {factor}x?", 'YES', force):
                    return 0
        except ValueError:
            print(f"{Colors.RED}[!] Invalid scale factor: {args[1]}{Colors.RESET}")
            return 1
        
        # Read current voltage
        data = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.READ, data)
        
        if not success:
            print(f"{Colors.RED}[!] Cannot read current voltage: {status_name}{Colors.RESET}")
            return 1
        
        vdata = parse_voltage_data(extra)
        current_uv = vdata.get('voltage_uv', 0)
        
        if current_uv <= 0:
            print(f"{Colors.RED}[!] Invalid current voltage reading{Colors.RESET}")
            return 1
        
        current_v = current_uv / 1_000_000.0
        new_uv = int(current_uv * factor)
        new_v = new_uv / 1_000_000.0
        
        print(f"[*] {rail_name}: {current_v:.3f}V → {new_v:.3f}V (×{factor})")
        
        # Safety check
        safe, msg = validate_voltage_safety(rail_name, new_uv)
        if not safe and not force:
            print(f"{Colors.RED}[!] {msg}{Colors.RESET}")
            return 1
        
        # Set new voltage
        payload = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        payload += struct.pack("<I", new_uv)
        
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.SET, payload)
        
        if success:
            print(f"{Colors.GREEN}[+] Scaled to {new_v:.3f}V{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.RED}[!] Scale failed: {status_name}{Colors.RESET}")
            return 1
    
    elif len(args) >= 3:
        # Frequency-voltage pair
        freq_str = args[1]
        volt_str = args[2]
        unit = args[3].upper() if len(args) > 3 else "V"
        
        ok_freq, freq_hz, freq_err = parse_frequency(freq_str)
        ok_volt, volt_uv, volt_err = parse_voltage_value(volt_str, unit)
        
        if not ok_freq:
            print(f"{Colors.RED}[!] {freq_err}{Colors.RESET}")
            return 1
        if not ok_volt:
            print(f"{Colors.RED}[!] {volt_err}{Colors.RESET}")
            return 1
        
        freq_mhz = freq_hz / 1_000_000
        volt_v = volt_uv / 1_000_000
        
        print(f"[*] Setting F-V pair: {rail_name} @ {freq_mhz:.0f}MHz = {volt_v:.3f}V")
        
        # Safety
        safe, msg = validate_voltage_safety(rail_name, volt_uv)
        if not safe and not force:
            print(f"{Colors.RED}[!] {msg}{Colors.RESET}")
            return 1
        
        payload = rail_name.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        payload += struct.pack("<I", freq_hz)
        payload += struct.pack("<I", volt_uv)
        
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.SET_FV_PAIR, payload)
        
        if success:
            print(f"{Colors.GREEN}[+] F-V pair set successfully{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.RED}[!] Failed: {status_name}{Colors.RESET}")
            return 1
    
    return 1


def voltage_limits(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Show voltage limits."""
    rail_filter = args[0].upper() if args else None
    
    print(f"\n{Colors.BOLD}[+] Voltage Safety Ranges:{Colors.RESET}\n")
    print(f"    {'Rail':<20} {'Min':<10} {'Max':<10} {'Range':<16}")
    print(f"    {'-'*20} {'-'*10} {'-'*10} {'-'*16}")
    
    found = False
    for rail_name, (min_uv, max_uv, range_str) in sorted(VOLTAGE_SAFETY_RANGES.items()):
        if rail_filter and rail_filter not in rail_name:
            continue
        found = True
        min_v = f"{min_uv/1_000_000:.2f}V"
        max_v = f"{max_uv/1_000_000:.2f}V"
        print(f"    {rail_name:<20} {min_v:<10} {max_v:<10} {range_str:<16}")
    
    if not found:
        print(f"    No matching rails for filter: {rail_filter}")
    
    return 0


def voltage_calibrate(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Calibrate voltage measurement."""
    cal_type = args[0].upper() if args else "AUTO"
    print(f"\n{Colors.CYAN}[*] Calibrating: {cal_type}{Colors.RESET}")
    
    data = cal_type.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.CALIBRATE, data)
    
    if success:
        print(f"{Colors.GREEN}[+] Calibration complete{Colors.RESET}")
        return 0
    else:
        print(f"{Colors.RED}[!] Calibration failed: {status_name}{Colors.RESET}")
        return 1


def voltage_reset(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Reset voltages to defaults."""
    scope = args[0].upper() if args else "ALL"
    print(f"\n{Colors.CYAN}[*] Resetting voltages: {scope}{Colors.RESET}")
    
    if scope in ("ALL", "HARD") and is_critical_rail("CORE"):
        if not confirm_dangerous("Reset ALL voltages to defaults?", 'RESET', force):
            return 0
    
    data = scope.encode('ascii')[:8].ljust(8, b'\x00')
    success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.RESET, data)
    
    if success:
        print(f"{Colors.GREEN}[+] Voltages reset{Colors.RESET}")
        return 0
    else:
        print(f"{Colors.RED}[!] Reset failed: {status_name}{Colors.RESET}")
        return 1


def voltage_pmic(dev, args: List[str], force: bool = False, verbose: bool = False) -> int:
    """Direct PMIC register access."""
    if len(args) < 2:
        print(f"{Colors.RED}[!] Usage: voltage pmic <reg> <read|write> [value]{Colors.RESET}")
        return 1
    
    reg_str = args[0]
    operation = args[1].lower()
    
    try:
        reg_addr = int(reg_str, 16) if reg_str.startswith('0x') else int(reg_str)
        if not (0 <= reg_addr <= 0xFF):
            print(f"{Colors.RED}[!] Register address out of range (0x00-0xFF){Colors.RESET}")
            return 1
    except ValueError:
        print(f"{Colors.RED}[!] Invalid register: {reg_str}{Colors.RESET}")
        return 1
    
    if operation == 'read':
        print(f"[*] Reading PMIC register 0x{reg_addr:02X}")
        data = struct.pack("<B", reg_addr)
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.PMIC_READ, data)
        
        if success and len(extra) >= 1:
            print(f"{Colors.GREEN}[+] Register 0x{reg_addr:02X} = 0x{extra[0]:02X}{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.RED}[!] PMIC read failed: {status_name}{Colors.RESET}")
            return 1
    
    elif operation == 'write':
        if len(args) < 3:
            print(f"{Colors.RED}[!] Specify value to write{Colors.RESET}")
            return 1
        
        try:
            val_str = args[2]
            value = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
            if not (0 <= value <= 0xFF):
                print(f"{Colors.RED}[!] Value out of range (0x00-0xFF){Colors.RESET}")
                return 1
        except ValueError:
            print(f"{Colors.RED}[!] Invalid value: {args[2]}{Colors.RESET}")
            return 1
        
        if not force:
            if not confirm_dangerous(
                f"Write 0x{value:02X} to PMIC register 0x{reg_addr:02X}?\n"
                "Incorrect PMIC writes can DAMAGE hardware!",
                'PMIC', force
            ):
                return 0
        
        data = struct.pack("<BB", reg_addr, value)
        success, status_name, extra = dispatch_voltage(dev, VoltageOpcode.PMIC_WRITE, data)
        
        if success:
            print(f"{Colors.GREEN}[+] Wrote 0x{value:02X} to register 0x{reg_addr:02X}{Colors.RESET}")
            return 0
        else:
            print(f"{Colors.RED}[!] PMIC write failed: {status_name}{Colors.RESET}")
            return 1
    
    else:
        print(f"{Colors.RED}[!] Unknown operation: {operation}. Use 'read' or 'write'{Colors.RESET}")
        return 1


# =============================================================================
# FIXED: Subcommand dispatch table
# =============================================================================
VOLTAGE_SUBCOMMANDS = {
    'list': voltage_list,
    'ls': voltage_list,
    'rails': voltage_list,
    
    'read': voltage_read,
    'get': voltage_read,
    'measure': voltage_read,
    
    'set': voltage_set,
    'write': voltage_set,
    'adjust': voltage_set,
    
    'monitor': voltage_monitor,
    'watch': voltage_monitor,
    'log': voltage_monitor,
    
    'scale': voltage_scale,
    'vscale': voltage_scale,
    'dvs': voltage_scale,
    
    'limits': voltage_limits,
    'range': voltage_limits,
    'spec': voltage_limits,
    
    'calibrate': voltage_calibrate,
    'cal': voltage_calibrate,
    
    'reset': voltage_reset,
    'default': voltage_reset,
    'normal': voltage_reset,
    
    'pmic': voltage_pmic,
    'register': voltage_pmic,
    'reg': voltage_pmic,
}


# =============================================================================
# FIXED: Help display
# =============================================================================
def print_voltage_help():
    """Display voltage command help."""
    print(f"""
{Colors.BOLD}VOLTAGE - Power Management & Voltage Control Module{Colors.RESET}
{'='*60}

{Colors.BOLD}USAGE:{Colors.RESET}
  qslcl voltage <subcommand> [args] [options]

{Colors.BOLD}SUBCOMMANDS:{Colors.RESET}

  {Colors.CYAN}Information:{Colors.RESET}
    list, ls, rails          List voltage rails and power domains
    read [rail]              Read voltage (ALL if omitted)
    limits [rail]            Show voltage safety ranges

  {Colors.CYAN}Control:{Colors.RESET}
    set <rail> <value> [V|mV|uV]  Set voltage
    scale <rail> <factor>         Scale by factor (1.1 = +10%)
    scale <rail> <freq> <volt>    Set frequency-voltage pair

  {Colors.CYAN}Monitoring:{Colors.RESET}
    monitor [rail] [time] [interval]  Monitor in real-time

  {Colors.CYAN}Maintenance:{Colors.RESET}
    calibrate [type]          Calibrate measurement
    reset [scope]             Reset to defaults
    pmic <reg> read|write [v] Direct PMIC access

{Colors.BOLD}COMMON RAILS:{Colors.RESET}
  VDD_CORE, VDD_CPU, VDD_GPU, VDD_DDR, VDD_MEM, VDD_IO, VDD_AON

{Colors.BOLD}SAFETY:{Colors.RESET}
  {Colors.RED}⚠ Critical rails require explicit confirmation{Colors.RESET}
  {Colors.RED}⚠ Use --force only with extreme caution{Colors.RESET}

{Colors.BOLD}EXAMPLES:{Colors.RESET}
  qslcl voltage list
  qslcl voltage read VDD_CPU
  qslcl voltage set VDD_CPU 1.1 V
  qslcl voltage monitor ALL 30 1
  qslcl voltage scale VDD_GPU 0.95
  qslcl voltage pmic 0x10 read
""")


# =============================================================================
# FIXED: Main command function
# =============================================================================
def cmd_voltage(args=None) -> int:
    """
    QSLCL VOLTAGE Command v2.0 (FIXED)
    
    Returns:
        int: 0 on success, 1 on failure, 130 on interrupt
    """
    
    if args is None:
        print(f"{Colors.RED}[!] No arguments provided{Colors.RESET}")
        print_voltage_help()
        return 1
    
    if not _use_qslcl:
        _warn_standalone()
    
    # Device discovery
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
        print(f"{Colors.RED}[!] Cannot access device{Colors.RESET}")
        return 1
    
    # Loader injection
    if hasattr(args, 'loader') and args.loader:
        try:
            _auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"{Colors.RED}[!] Loader injection failed: {e}{Colors.RESET}")
            return 1
    
    # Extract subcommand
    subcommand = None
    for attr in ['voltage_subcommand', 'subcommand']:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val:
                subcommand = val.lower().strip()
                break
    
    if not subcommand or subcommand in ('help', '?', '-h', '--help'):
        print_voltage_help()
        return 0
    
    voltage_args = getattr(args, 'voltage_args', []) or getattr(args, 'args', []) or []
    force = getattr(args, 'force', False)
    verbose = getattr(args, 'verbose', False)
    
    handler = VOLTAGE_SUBCOMMANDS.get(subcommand)
    
    if not handler:
        print(f"{Colors.RED}[!] Unknown subcommand: {subcommand}{Colors.RESET}")
        print_voltage_help()
        return 1
    
    try:
        return handler(dev, voltage_args, force, verbose)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.RESET}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {type(e).__name__}: {e}{Colors.RESET}")
        if verbose and _DEBUG:
            traceback.print_exc()
        return 1


# =============================================================================
# FIXED: Argument extensions
# =============================================================================
def add_voltage_arguments(parser) -> None:
    """Add voltage-specific arguments."""
    parser.add_argument('voltage_subcommand', nargs='?', help='Subcommand')
    parser.add_argument('voltage_args', nargs='*', help='Additional arguments')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--force', '-f', action='store_true', help='Bypass safety checks')
    parser.add_argument('--tolerance', type=int, default=DEFAULT_VERIFY_TOLERANCE_UV,
                       help=f'Verification tolerance in µV (default: {DEFAULT_VERIFY_TOLERANCE_UV})')
    return parser


if __name__ == "__main__":
    print("[*] voltage.py - QSLCL VOLTAGE Command Module v2.0")
    print_voltage_help()