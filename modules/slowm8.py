#!/usr/bin/env python3
# slowm8.py - QSLCL USB Stress Tester v2.2.1 (FIXED)
# Auto-detects devices, adapts timing, finds bugs, and injects test code

import os
import sys
import struct
import time
import json
import random
import threading
import hashlib
import zlib  # FIXED: Added missing import
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict

# =============================================================================
# IMPORTS - With proper fallbacks
# =============================================================================
try:
    import usb.core
    import usb.util
    USB_AVAILABLE = True
except ImportError:
    USB_AVAILABLE = False
    print("[!] Warning: PyUSB not available. SlowM8 will be limited.")

try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
        qslcl_dispatch,
        decode_runtime_result,
        encode_qslcl_structure,
        QSLCLCMD_DB,
        QSLCLSPT_DB,
        parse_standard_header,
        open_transport,
        QSLCLDevice,
        set_debug,
        _DEBUG
    )
    QSLCL_AVAILABLE = True
except ImportError:
    try:
        from .qslcl import (
            scan_all,
            auto_loader_if_needed,
            qslcl_dispatch,
            decode_runtime_result,
            encode_qslcl_structure,
            QSLCLCMD_DB,
            QSLCLSPT_DB,
            parse_standard_header,
            open_transport,
            QSLCLDevice,
            set_debug,
            _DEBUG
        )
        QSLCL_AVAILABLE = True
    except ImportError:
        print("[!] WARNING: Cannot import qslcl core module")
        QSLCL_AVAILABLE = False
        
        # Provide stub functions for testing
        def scan_all(): return []
        def auto_loader_if_needed(args, dev): pass
        def qslcl_dispatch(dev, cmd, payload=b"", timeout=2.0): return None
        def decode_runtime_result(resp): return {"severity": "UNKNOWN", "code": 0xFFFF, "name": "UNKNOWN"}
        def encode_qslcl_structure(magic, body, flags=0): return b""
        def parse_standard_header(data): return None
        def open_transport(dev): return None, False
        _DEBUG = False
        class QSLCLDevice: pass

# =============================================================================
# FIXED: Global debug variable
# =============================================================================
_DEBUG_SLOWM8 = False

def debug_print(msg: str):
    """Print debug message if debugging is enabled"""
    if _DEBUG_SLOWM8 or (QSLCL_AVAILABLE and _DEBUG):
        print(msg)

# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class SlowM8Config:
    """Configuration for slowm8 stress testing - FULLY AUTOMATED"""
    # Timing parameters - auto-adjusted
    min_delay_ms: float = 0.5
    max_delay_ms: float = 50.0
    initial_delay_ms: float = 5.0
    
    # Auto-detection flags
    adaptive_timing: bool = True
    auto_detect_mode: bool = True
    device_response_time: float = 0.0
    timing_multiplier: float = 1.0
    
    # A19+ specific
    a19_mode: bool = False
    encryption_detected: bool = False
    
    # Stress patterns
    packet_count: int = 100
    burst_size: int = 10
    burst_delay_ms: float = 500.0
    random_delays: bool = True
    progressive_slowdown: bool = False
    repeat_packets: int = 1
    fuzz_mutations: int = 0
    
    # Bug confirmation
    confirm_bugs: bool = True
    code_injection_enabled: bool = True
    max_injection_size: int = 512
    injection_timeout: float = 5.0
    bug_threshold: int = 3
    
    # Tracking
    found_bugs: list = field(default_factory=list)
    confirmed_bugs: list = field(default_factory=list)
    injection_attempts: int = 0
    injection_successes: int = 0
    delays_used: list = field(default_factory=list)

# =============================================================================
# USB SETUP PACKET DATABASE
# =============================================================================

SLOWM8_SETUP_PACKETS = {
    "GET_STATUS": struct.pack("<BBHHH", 0x80, 0x00, 0x0000, 0x0000, 2),
    "CLEAR_FEATURE": struct.pack("<BBHHH", 0x00, 0x01, 0x0000, 0x0000, 0),
    "SET_FEATURE": struct.pack("<BBHHH", 0x00, 0x03, 0x0001, 0x0000, 0),
    "SET_ADDRESS": struct.pack("<BBHHH", 0x00, 0x05, 0x0001, 0x0000, 0),
    "GET_DESCRIPTOR_DEVICE": struct.pack("<BBHHH", 0x80, 0x06, 0x0100, 0x0000, 18),
    "GET_DESCRIPTOR_CONFIG": struct.pack("<BBHHH", 0x80, 0x06, 0x0200, 0x0000, 9),
    "GET_CONFIGURATION": struct.pack("<BBHHH", 0x80, 0x08, 0x0000, 0x0000, 1),
    "SET_CONFIGURATION": struct.pack("<BBHHH", 0x00, 0x09, 0x0001, 0x0000, 0),
    "GET_INTERFACE": struct.pack("<BBHHH", 0x81, 0x0A, 0x0000, 0x0000, 1),
    "SET_INTERFACE": struct.pack("<BBHHH", 0x01, 0x0B, 0x0000, 0x0000, 0),
    "GET_REPORT": struct.pack("<BBHHH", 0xA1, 0x01, 0x0100, 0x0000, 64),
    "SET_REPORT": struct.pack("<BBHHH", 0x21, 0x09, 0x0200, 0x0000, 64),
    "SET_IDLE": struct.pack("<BBHHH", 0x21, 0x0A, 0x0000, 0x0000, 0),
    "QSLCL_HELLO": struct.pack("<BBHHH", 0xC0, 0xF0, 0x5153, 0x4C43, 8),
    "QSLCL_CAPS": struct.pack("<BBHHH", 0xC0, 0xF1, 0x0001, 0x0000, 32),
    "QSLCL_RAWMODE": struct.pack("<BBHHH", 0x40, 0xF2, 0x0001, 0x0000, 4),
    "MALFORMED_ZERO_LEN": struct.pack("<BBHHH", 0x00, 0x00, 0x0000, 0x0000, 0),
    "MALFORMED_MAX_LEN": struct.pack("<BBHHH", 0xFF, 0xFF, 0xFFFF, 0xFFFF, 0xFFFF),
    "MALFORMED_INVALID_REQ": struct.pack("<BBHHH", 0xFF, 0xEE, 0xDEAD, 0xBEEF, 0xFFFF),
}

# =============================================================================
# USB FUZZER
# =============================================================================

class USBFuzzer:
    """Generate malformed USB setup packets for stress testing"""
    
    @staticmethod
    def corrupt_byte(data: bytes, position: int = None) -> bytes:
        data_list = list(data)
        if position is None:
            position = random.randint(0, len(data_list) - 1)
        data_list[position] = random.randint(0, 255)
        return bytes(data_list)
    
    @staticmethod
    def flip_bit(data: bytes, bit_position: int = None) -> bytes:
        data_list = list(data)
        if bit_position is None:
            bit_position = random.randint(0, (len(data) * 8) - 1)
        byte_idx = bit_position // 8
        bit_idx = bit_position % 8
        if byte_idx < len(data_list):
            data_list[byte_idx] ^= (1 << bit_idx)
        return bytes(data_list)
    
    @staticmethod
    def set_invalid_magic(data: bytes) -> bytes:
        if len(data) >= 4:
            data_list = list(data)
            data_list[0:4] = [random.randint(0, 255) for _ in range(4)]
            return bytes(data_list)
        return data
    
    @staticmethod
    def corrupt_length(data: bytes) -> bytes:
        if len(data) >= 8:
            data_list = list(data)
            extreme_values = [0x0000, 0xFFFF, 0x7FFF, 0x8000]
            new_len = random.choice(extreme_values)
            data_list[6:8] = [(new_len >> 8) & 0xFF, new_len & 0xFF]
            return bytes(data_list)
        return data
    
    @staticmethod
    def set_invalid_request_type(data: bytes) -> bytes:
        if len(data) >= 1:
            data_list = list(data)
            invalid_types = [0xFF, 0x80, 0x40, 0x20, 0xE0, 0xC0]
            data_list[0] = random.choice(invalid_types)
            return bytes(data_list)
        return data
    
    @staticmethod
    def fuzz_packet(data: bytes, mutations: int = 1) -> bytes:
        result = data
        for _ in range(mutations):
            mutation_type = random.choice([
                "corrupt_byte", "flip_bit", "corrupt_length", "invalid_request_type"
            ])
            if mutation_type == "corrupt_byte":
                result = USBFuzzer.corrupt_byte(result)
            elif mutation_type == "flip_bit":
                result = USBFuzzer.flip_bit(result)
            elif mutation_type == "corrupt_length":
                result = USBFuzzer.corrupt_length(result)
            elif mutation_type == "invalid_request_type":
                result = USBFuzzer.set_invalid_request_type(result)
        return result

# =============================================================================
# MAIN PACKET SENDER - FIXED VERSION
# =============================================================================

class SlowPacketSender:
    """Send packets with auto-detection, timing control, and bug confirmation"""
    
    def __init__(self, dev: QSLCLDevice, config: SlowM8Config):
        self.dev = dev
        self.config = config
        self.stats = {
            "sent": 0, "failed": 0, "responses": 0,
            "timeouts": 0, "crc_errors": 0, "malformed_responses": 0
        }
        self.timing_data = []
        self.running = False
        self._bug_counter = 0
        self._handle = None
        self._serial_mode = False
        
        # FIXED: Open transport if not already open
        self._ensure_handle()
    
    def _ensure_handle(self):
        """FIXED: Ensure device handle is open"""
        if self.dev.handle is None:
            self._handle, self._serial_mode = open_transport(self.dev)
            if self._handle:
                self.dev.handle = self._handle
                self.dev.serial_mode = self._serial_mode
                debug_print("[*] Device handle opened")
        else:
            self._handle = self.dev.handle
            self._serial_mode = getattr(self.dev, 'serial_mode', False)
    
    # =========================================================================
    # AUTO-DETECTION - FIXED with proper exception handling
    # =========================================================================
    
    def _auto_detect_device_mode(self) -> str:
        """Auto-detect device mode without hardcoded PIDs"""
        self._ensure_handle()
        
        if self._handle is None:
            debug_print("[!] No device handle for auto-detection")
            return "unknown"
        
        try:
            # Method 1: USB Class Detection
            cfg = self._handle.get_active_configuration()
            for intf in cfg:
                if intf.bInterfaceClass == 0xFE and intf.bInterfaceSubClass == 0x01:
                    debug_print("[*] Mode: DFU (0xFE/0x01)")
                    return "dfu"
                if intf.bInterfaceClass == 0x0A:
                    debug_print("[*] Mode: CDC (EDL/BROM)")
                    return "cdc"
                if intf.bInterfaceClass == 0xFF:
                    debug_print("[*] Mode: Vendor-specific")
                    return "vendor"
        except usb.core.USBError as e:
            debug_print(f"[!] USB class detection error: {e}")
        except Exception as e:
            debug_print(f"[!] Class detection: {e}")
        
        try:
            # Method 2: Response time analysis
            test_packet = b"\x80\x06\x01\x00\x00\x00\x12\x00"
            start = time.time()
            self._handle.ctrl_transfer(0x80, 0x06, 0x0100, 0x0000, 18, timeout=50)
            elapsed = (time.time() - start) * 1000
            
            if elapsed > 30:
                debug_print(f"[*] Mode: Encrypted DFU (A19+) - {elapsed:.1f}ms")
                return "dfu_encrypted"
            else:
                debug_print(f"[*] Mode: Standard USB - {elapsed:.1f}ms")
                return "usb_standard"
        except usb.core.USBError as e:
            debug_print(f"[!] USB response error: {e}")
        except:
            pass
        
        debug_print("[*] Mode: Unknown")
        return "unknown"
    
    def _auto_detect_device_timing(self):
        """Auto-detect device capabilities without hardcoded PIDs"""
        self._ensure_handle()
        
        print("[*] Auto-detecting device timing capabilities...")
        
        if self._handle is None:
            print("[!] No device handle for timing detection")
            return
        
        test_packets = [
            b"\x80\x06\x01\x00\x00\x00\x12\x00",  # GET_DESCRIPTOR
            b"\x80\x00\x00\x00\x00\x00\x02\x00",  # GET_STATUS
            b"\x00\x05\x00\x00\x00\x00\x00\x00",  # SET_ADDRESS
        ]
        
        response_times = []
        
        for packet in test_packets:
            try:
                start = time.time()
                response = self._handle.ctrl_transfer(
                    bmRequestType=packet[0],
                    bRequest=packet[1],
                    wValue=int.from_bytes(packet[2:4], 'little'),
                    wIndex=int.from_bytes(packet[4:6], 'little'),
                    data_or_wLength=int.from_bytes(packet[6:8], 'little'),
                    timeout=100
                )
                elapsed = (time.time() - start) * 1000
                response_times.append(elapsed)
            except usb.core.USBError as e:
                if "timeout" in str(e).lower():
                    debug_print(f"[!] Timeout on test packet: {packet[:8].hex()}")
                else:
                    debug_print(f"[!] USB error: {e}")
            except Exception as e:
                debug_print(f"[!] Test packet error: {e}")
                continue
        
        if response_times:
            avg_response = sum(response_times) / len(response_times)
            self.config.device_response_time = avg_response
            
            # Detect A19+ (encryption)
            if avg_response > 50:
                self.config.a19_mode = True
                self.config.encryption_detected = True
                print(f"[*] A19+ encryption detected ({avg_response:.1f}ms)")
            elif avg_response > 20:
                print(f"[*] Standard device ({avg_response:.1f}ms)")
            else:
                print(f"[*] Fast device ({avg_response:.1f}ms)")
            
            # Auto-adjust timing
            if avg_response < 5:
                self.config.timing_multiplier = 0.3
            elif avg_response < 15:
                self.config.timing_multiplier = 0.6
            elif avg_response < 30:
                self.config.timing_multiplier = 1.0
            elif avg_response < 60:
                self.config.timing_multiplier = 1.5
            else:
                self.config.timing_multiplier = 2.0
            
            self.config.min_delay_ms = max(0.5, avg_response * 0.1)
            self.config.max_delay_ms = min(100.0, avg_response * 2.0)
            
            print(f"[*] Timing: {self.config.timing_multiplier:.1f}x | "
                  f"Min: {self.config.min_delay_ms:.1f}ms | "
                  f"Max: {self.config.max_delay_ms:.1f}ms")
        else:
            print("[!] Auto-detect failed, using safe defaults")
            self.config.device_response_time = 10.0
    
    # =========================================================================
    # TIMING
    # =========================================================================
    
    def _calculate_delay(self, packet_index: int, total_packets: int) -> float:
        """Calculate delay with auto-detection"""
        
        # Auto-detect on first packet
        if self.config.auto_detect_mode and packet_index == 0:
            self._auto_detect_device_timing()
        
        if not self.config.random_delays:
            return self.config.initial_delay_ms / 1000.0
        
        base_delay = random.uniform(
            self.config.min_delay_ms / 1000.0,
            self.config.max_delay_ms / 1000.0
        )
        
        # Adaptive timing
        if self.config.adaptive_timing and self.config.device_response_time > 0:
            response_factor = min(self.config.device_response_time / 10.0, 5.0)
            base_delay *= response_factor
            base_delay = min(base_delay, 0.5)
        
        # A19+ specific
        if self.config.a19_mode:
            base_delay *= 0.5
            if self.config.encryption_detected:
                base_delay += random.uniform(0.001, 0.005)
        
        # Progressive slowdown
        if self.config.progressive_slowdown:
            progress = packet_index / total_packets if total_packets > 0 else 0
            base_delay *= (1 + progress * 2)
        
        # Burst mode
        if self.config.burst_size > 0:
            if packet_index % self.config.burst_size == 0 and packet_index > 0:
                base_delay += self.config.burst_delay_ms / 1000.0
        
        delay = max(0.0001, min(1.0, base_delay))
        self.config.delays_used.append(delay)
        return delay
    
    # =========================================================================
    # SENDING PACKETS - FIXED with proper exception handling
    # =========================================================================
    
    def send_setup_packet(self, packet: bytes, packet_name: str = "unknown") -> Optional[bytes]:
        """Send a single setup packet with proper exception handling"""
        self._ensure_handle()
        
        if len(packet) != 8:
            self.stats["failed"] += 1
            return None
        
        if self._handle is None:
            self.stats["failed"] += 1
            return None
        
        try:
            bmRequestType, bRequest, wValue, wIndex, wLength = struct.unpack("<BBHHH", packet)
            
            response = self._handle.ctrl_transfer(
                bmRequestType=bmRequestType,
                bRequest=bRequest,
                wValue=wValue,
                wIndex=wIndex,
                data_or_wLength=wLength,
                timeout=int(self.config.max_delay_ms * 2)
            )
            
            self.stats["sent"] += 1
            self.stats["responses"] += 1
            return response
            
        except usb.core.USBError as e:
            error_str = str(e).lower()
            if "timeout" in error_str:
                self.stats["timeouts"] += 1
            elif "pipe" in error_str or "stall" in error_str:
                self.stats["failed"] += 1
                # FIXED: Clear stall if possible
                try:
                    if self._handle:
                        self._handle.clear_halt(0x00)  # Clear endpoint 0 halt
                except:
                    pass
            else:
                self.stats["failed"] += 1
            debug_print(f"[!] USB error: {e}")
            return None
        except Exception as e:
            self.stats["failed"] += 1
            debug_print(f"[!] Unexpected error: {e}")
            return None
    
    def _read_usb_bulk(self, size: int = 64) -> bytes:
        """Read from USB bulk IN endpoint with proper exception handling"""
        self._ensure_handle()
        
        if self._handle is None:
            return b""
        
        try:
            cfg = self._handle.get_active_configuration()
            intf = cfg[(0, 0)]
            for ep in intf.endpoints():
                if (usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN and
                    usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                    return self._handle.read(ep.bEndpointAddress, size, timeout=100)
        except usb.core.USBError as e:
            if "timeout" not in str(e).lower():
                debug_print(f"[!] Bulk read error: {e}")
        except Exception as e:
            debug_print(f"[!] Bulk read exception: {e}")
        return b""
    
    # =========================================================================
    # BUG DETECTION - FIXED with better error handling
    # =========================================================================
    
    def _detect_device_reset(self) -> bool:
        """Detect if device has reset"""
        self._ensure_handle()
        
        if self._handle is None:
            return True
        
        try:
            self._handle.ctrl_transfer(0x80, 0x06, 0x0100, 0x0000, 18, timeout=100)
            return False
        except usb.core.USBError as e:
            if "pipe" in str(e).lower() or "stall" in str(e).lower():
                return True
            # Try to recover
            try:
                self._handle.clear_halt(0x00)
            except:
                pass
            return False
        except:
            return True
    
    def _analyze_anomaly_for_bug(self, anomaly: dict) -> dict:
        """Analyze anomaly to determine if it's a real bug"""
        bug_report = {
            "is_bug": False,
            "confidence": 0.0,
            "type": "unknown",
            "payload": None,
            "trigger_packet": None,
            "description": ""
        }
        
        # Check 1: Memory corruption
        if anomaly.get('response_len', 0) > 4096 and anomaly.get('expected_len', 0) < 100:
            bug_report["is_bug"] = True
            bug_report["confidence"] += 0.8
            bug_report["type"] = "memory_corruption"
            bug_report["description"] = f"Large response: {anomaly['response_len']} bytes"
        
        # Check 2: Crash/Reset
        if anomaly.get('device_reset', False):
            bug_report["is_bug"] = True
            bug_report["confidence"] += 0.9
            bug_report["type"] = "crash"
            bug_report["description"] = "Device reset detected"
        
        # Check 3: Timeout anomalies
        if anomaly.get('timeout', False) and anomaly.get('packet_count', 0) > 10:
            bug_report["is_bug"] = True
            bug_report["confidence"] += 0.6
            bug_report["type"] = "timeout_vulnerability"
            bug_report["description"] = "Repeated timeouts"
        
        # Check 4: Timing anomalies
        if anomaly.get('response_time_ms', 0) > 500 and anomaly.get('normal_response_time', 0) < 50:
            bug_report["is_bug"] = True
            bug_report["confidence"] += 0.7
            bug_report["type"] = "timing_anomaly"
            bug_report["description"] = f"Slow response: {anomaly['response_time_ms']:.1f}ms"
        
        # Check 5: Malformed response
        if anomaly.get('malformed_response', False):
            bug_report["is_bug"] = True
            bug_report["confidence"] += 0.5
            bug_report["type"] = "parsing_bug"
            bug_report["description"] = "Malformed response"
        
        if bug_report["is_bug"]:
            bug_report["trigger_packet"] = anomaly.get('packet', b'')
            bug_report["payload"] = anomaly.get('response', b'')
            self.config.found_bugs.append(bug_report)
            
            debug_print(f"[!] Bug: {bug_report['type']} (conf: {bug_report['confidence']:.1%})")
            debug_print(f"    {bug_report['description']}")
        
        return bug_report
    
    def _check_for_anomalies(self, packet: bytes, response: Optional[bytes],
                             response_time: float, packet_index: int) -> Optional[dict]:
        """Enhanced anomaly detection with bug analysis"""
        anomaly = None
        
        # Large response
        if response and len(response) > 1024 and len(packet) < 64:
            anomaly = {
                "packet": packet,
                "response": response,
                "response_time_ms": response_time,
                "response_len": len(response),
                "expected_len": 0,
                "packet_count": packet_index,
                "normal_response_time": self.config.device_response_time,
                "malformed_response": False,
                "timeout": False,
                "device_reset": False
            }
        
        # Slow response
        if response_time > 500:
            if anomaly is None:
                anomaly = {}
            anomaly["response_time_ms"] = response_time
            anomaly["normal_response_time"] = self.config.device_response_time
        
        # Timeout
        if not response and packet_index > 0:
            if anomaly is None:
                anomaly = {}
            anomaly["timeout"] = True
        
        # Device reset
        if self._detect_device_reset():
            if anomaly is None:
                anomaly = {}
            anomaly["device_reset"] = True
        
        # Malformed response
        if response and len(response) >= 4:
            if response[0] in (0xFF, 0x00) and response[1] in (0xFF, 0x00):
                if anomaly is None:
                    anomaly = {}
                anomaly["malformed_response"] = True
        
        if anomaly:
            bug_report = self._analyze_anomaly_for_bug(anomaly)
            
            if bug_report["is_bug"]:
                self._bug_counter += 1
                
                if self._bug_counter >= self.config.bug_threshold:
                    debug_print(f"[*] Bug threshold reached ({self._bug_counter})")
                    debug_print("[*] Attempting custom code injection...")
                    
                    injection_result = self._inject_test_code(bug_report)
                    
                    if injection_result["confirmed"]:
                        print(f"[+] BUG CONFIRMED! Injection succeeded")
                        print(f"    Code size: {injection_result['code_size']} bytes")
                        print(f"    Execution time: {injection_result['execution_time']:.3f}s")
                    else:
                        print(f"[*] Bug detected but injection not confirmed")
                        print(f"    Attempts: {self.config.injection_attempts}")
                        print(f"    Successes: {self.config.injection_successes}")
            
            return bug_report
        
        return None
    
    # =========================================================================
    # CODE INJECTION - FIXED
    # =========================================================================
    
    def _build_injection_payload(self, bug_report: dict) -> bytes:
        """Build custom injection payload based on bug type"""
        bug_type = bug_report.get("type", "unknown")
        payload = bytearray()
        
        if bug_type == "memory_corruption":
            payload.extend(b"WRITE_TEST")
            payload.extend(struct.pack("<I", 0xDEADBEEF))
            payload.extend(b"READ_TEST")
            payload.extend(struct.pack("<I", 0x00000000))
            payload.extend(b"VERIFY")
            payload.extend(struct.pack("<I", 0xDEADBEEF))
            
        elif bug_type == "crash":
            payload.extend(b"CRASH_TEST")
            payload.extend(struct.pack("<I", 0xDEADBEEF))
            payload.extend(b"RECOVER")
            payload.extend(struct.pack("<I", 500))
            
        elif bug_type == "timeout_vulnerability":
            payload.extend(b"TIMEOUT_TEST")
            payload.extend(struct.pack("<I", 1000))
            payload.extend(b"PING")
            payload.extend(b"\x00" * 4)
            
        elif bug_type == "timing_anomaly":
            payload.extend(b"TIMING_TEST")
            payload.extend(struct.pack("<I", 10))
            payload.extend(b"LOOP")
            payload.extend(struct.pack("<I", 100))
            
        elif bug_type == "parsing_bug":
            payload.extend(b"PARSE_TEST")
            payload.extend(struct.pack("<I", 0xFFFFFFFF))
            payload.extend(struct.pack("<I", 0xDEADBEEF))
            payload.extend(b"NESTED")
            payload.extend(struct.pack("<I", 0x12345678))
            
        else:
            payload.extend(b"TEST")
            payload.extend(os.urandom(32))
        
        # FIXED: zlib is now imported
        payload.extend(b"INJECT")
        payload.extend(struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF))
        
        return bytes(payload[:self.config.max_injection_size])
    
    def _read_injection_response(self, timeout: float = 5.0) -> Optional[bytes]:
        """Read response from injection with proper timeout"""
        self._ensure_handle()
        
        if self._handle is None:
            return None
        
        deadline = time.time() + timeout
        response = bytearray()
        
        while time.time() < deadline:
            try:
                if self._serial_mode:
                    chunk = self._handle.read(256)
                else:
                    chunk = self._read_usb_bulk(64)
                
                if chunk:
                    response.extend(chunk)
                    if len(response) >= 20:
                        header = parse_standard_header(response)
                        if header and header.get('crc_valid', False):
                            return header.get('body', bytes(response))
                    if b"INJECT_OK" in response:
                        return bytes(response)
                    if len(response) > 4096:
                        break
            except usb.core.USBError as e:
                if "timeout" in str(e).lower():
                    continue
                debug_print(f"[!] Read error: {e}")
                break
            except Exception as e:
                debug_print(f"[!] Read exception: {e}")
                break
        
        return bytes(response) if response else None
    
    def _inject_test_code(self, bug_report: dict) -> dict:
        """Inject custom test code to confirm the bug"""
        result = {
            "success": False,
            "injection_type": "none",
            "response": None,
            "code_size": 0,
            "execution_time": 0.0,
            "confirmed": False
        }
        
        self.config.injection_attempts += 1
        
        if not self.config.code_injection_enabled:
            return result
        
        if not bug_report.get("is_bug", False):
            return result
        
        injection_payload = self._build_injection_payload(bug_report)
        if not injection_payload:
            return result
        
        self._ensure_handle()
        
        if self._handle is None:
            return result
        
        try:
            start_time = time.time()
            
            # Try QSLCL data frame first
            if hasattr(self.dev, 'write') and callable(self.dev.write):
                frame = encode_qslcl_structure(
                    b"QSLCLDAT",
                    injection_payload,
                    flags=0x01
                )
                self.dev.write(frame)
            else:
                # Fallback to control transfer
                self._handle.ctrl_transfer(
                    bmRequestType=0x40,
                    bRequest=0xF0,
                    wValue=0x0001,
                    wIndex=0x0000,
                    data_or_wLength=injection_payload[:64],
                    timeout=2000
                )
            
            response = self._read_injection_response(timeout=self.config.injection_timeout)
            
            result["execution_time"] = time.time() - start_time
            result["response"] = response
            result["code_size"] = len(injection_payload)
            
            if response:
                if b"INJECT_OK" in response or b"\x00\x00\x00\x00" in response[:4]:
                    result["success"] = True
                    result["confirmed"] = True
                    self.config.injection_successes += 1
                    self.config.confirmed_bugs.append(bug_report)
                else:
                    result["success"] = True
                    result["confirmed"] = False
                    
        except usb.core.USBError as e:
            debug_print(f"[!] USB injection error: {e}")
            result["success"] = False
        except Exception as e:
            debug_print(f"[!] Injection failed: {e}")
            result["success"] = False
        
        return result
    
    # =========================================================================
    # STRESS TEST
    # =========================================================================
    
    def run_stress_test(self, duration_seconds: int = 30):
        """Run continuous stress test with bug detection and injection"""
        self.running = True
        start_time = time.time()
        packet_index = 0
        
        # Auto-detect device mode
        dev_mode = self._auto_detect_device_mode()
        print(f"[*] Device mode: {dev_mode.upper()}")
        
        # Auto-detect timing
        self._auto_detect_device_timing()
        
        print(f"[*] Starting slowm8 stress test for {duration_seconds} seconds...")
        print(f"[*] Auto-detected timing: min={self.config.min_delay_ms:.1f}ms, max={self.config.max_delay_ms:.1f}ms")
        print(f"[*] Bug threshold: {self.config.bug_threshold} anomalies before injection")
        print()
        
        packet_names = list(SLOWM8_SETUP_PACKETS.keys())
        
        try:
            while self.running and (time.time() - start_time) < duration_seconds:
                packet_name = packet_names[packet_index % len(packet_names)]
                packet = SLOWM8_SETUP_PACKETS[packet_name]
                
                # Apply fuzzing
                if self.config.fuzz_mutations > 0:
                    packet = USBFuzzer.fuzz_packet(packet, self.config.fuzz_mutations)
                    packet_name = f"fuzzed_{packet_name}"
                
                # Calculate delay
                delay = self._calculate_delay(packet_index, duration_seconds * 10)
                time.sleep(delay)
                
                # Send packet
                send_time = time.time()
                response = self.send_setup_packet(packet, packet_name)
                response_time = (time.time() - send_time) * 1000
                
                # Record timing
                timing_entry = {
                    "index": packet_index,
                    "name": packet_name,
                    "delay_ms": delay * 1000,
                    "response_time_ms": response_time if response else None,
                    "response_len": len(response) if response else 0,
                    "success": response is not None
                }
                self.timing_data.append(timing_entry)
                
                # Check for anomalies
                if response is not None or packet_index > 0:
                    self._check_for_anomalies(packet, response, response_time, packet_index)
                
                # Progress indicator
                if packet_index % 50 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Progress: {elapsed:.1f}s / {duration_seconds}s, "
                          f"sent={self.stats['sent']}, "
                          f"bugs={self._bug_counter}")
                
                # Repeat packets
                for _ in range(self.config.repeat_packets - 1):
                    self.send_setup_packet(packet, f"repeat_{packet_name}")
                
                packet_index += 1
                
        except KeyboardInterrupt:
            print("\n[*] Stress test interrupted by user")
        except Exception as e:
            print(f"[!] Stress test error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
        
        return self.stats, self.timing_data
    
    # =========================================================================
    # RESULTS
    # =========================================================================
    
    def print_results(self, stats: dict, timing_data: list, duration: float):
        """Print formatted results with bug injection summary"""
        print("\n" + "=" * 60)
        print("SLOWM8 STRESS TEST RESULTS")
        print("=" * 60)
        
        print(f"\n[STATISTICS]")
        print(f"  Packets sent:      {stats['sent']}")
        print(f"  Successful:        {stats['responses']}")
        print(f"  Failed:            {stats['failed']}")
        print(f"  Timeouts:          {stats['timeouts']}")
        print(f"  Success rate:      {(stats['responses']/stats['sent']*100) if stats['sent']>0 else 0:.1f}%")
        
        print(f"\n[TIMING]")
        if timing_data:
            delays = [d['delay_ms'] for d in timing_data if d.get('delay_ms')]
            if delays:
                print(f"  Avg delay:         {sum(delays)/len(delays):.2f}ms")
                print(f"  Min delay:         {min(delays):.2f}ms")
                print(f"  Max delay:         {max(delays):.2f}ms")
        
        print(f"\n[BUGS]")
        print(f"  Bugs detected:     {len(self.config.found_bugs)}")
        print(f"  Bugs confirmed:    {len(self.config.confirmed_bugs)}")
        print(f"  Injection attempts:{self.config.injection_attempts}")
        print(f"  Injection success: {self.config.injection_successes}")
        
        if self.config.confirmed_bugs:
            print(f"\n[CONFIRMED BUGS]")
            for i, bug in enumerate(self.config.confirmed_bugs[:5]):
                print(f"  {i+1}. {bug.get('type', 'unknown')} (conf: {bug.get('confidence', 0):.1%})")
                print(f"      {bug.get('description', 'No description')}")
            if len(self.config.confirmed_bugs) > 5:
                print(f"  ... and {len(self.config.confirmed_bugs) - 5} more")
        
        if self.config.injection_attempts > 0:
            success_rate = (self.config.injection_successes / self.config.injection_attempts) * 100 if self.config.injection_attempts > 0 else 0
            print(f"\n[INJECTION]")
            print(f"  Success rate:      {success_rate:.1f}%")
            print(f"  Payload size:      up to {self.config.max_injection_size} bytes")
        
        print(f"\n[DURATION]")
        print(f"  Total time:        {duration:.2f} seconds")
        print(f"  Packets/sec:       {stats['sent'] / duration:.1f}")
        print("\n" + "=" * 60)

# =============================================================================
# COMMAND FUNCTION
# =============================================================================

def cmd_slowm8(args):
    """Execute slowm8 USB stress test"""
    print("\n" + "=" * 60)
    print("SLOWM8 - USB Stress Tester (Auto-Detect + Bug Injection)")
    print("Experimental - Use at your own risk")
    print("=" * 60 + "\n")
    
    # FIXED: Set debug flag
    global _DEBUG_SLOWM8
    if hasattr(args, 'debug') and args.debug:
        _DEBUG_SLOWM8 = True
        if QSLCL_AVAILABLE:
            try:
                set_debug(True)
            except:
                pass
    
    # Scan for device
    if not QSLCL_AVAILABLE:
        print("[!] QSLCL module not available. Cannot scan for devices.")
        return 1
    
    devs = scan_all()
    if not devs:
        print("[!] No device detected")
        print("[*] Make sure your device is connected in DFU/EDL/BROM mode")
        return 1
    
    dev = devs[0]
    print(f"[+] Device found: {dev.product} (VID:PID={dev.vid:04X}:{dev.pid:04X})")
    
    # Load QSLCL binary if specified
    if hasattr(args, 'loader') and args.loader:
        print(f"[*] Loading QSLCL binary: {args.loader}")
        auto_loader_if_needed(args, dev)
        time.sleep(1)
    
    # Setup configuration
    config = SlowM8Config()
    
    # Parse arguments
    if hasattr(args, 'min_delay') and args.min_delay is not None:
        config.min_delay_ms = args.min_delay
    if hasattr(args, 'max_delay') and args.max_delay is not None:
        config.max_delay_ms = args.max_delay
    if hasattr(args, 'packets') and args.packets:
        config.packet_count = args.packets
    if hasattr(args, 'burst_size') and args.burst_size is not None:
        config.burst_size = args.burst_size
    if hasattr(args, 'fuzz') and args.fuzz:
        config.fuzz_mutations = args.fuzz
    if hasattr(args, 'progressive') and args.progressive:
        config.progressive_slowdown = True
    if hasattr(args, 'no_random') and args.no_random:
        config.random_delays = False
    if hasattr(args, 'duration') and args.duration:
        duration = args.duration
    else:
        duration = 30
    
    # Bug injection options
    if hasattr(args, 'no_injection') and args.no_injection:
        config.confirm_bugs = False
        config.code_injection_enabled = False
    if hasattr(args, 'injection_size') and args.injection_size:
        config.max_injection_size = args.injection_size
    if hasattr(args, 'bug_threshold') and args.bug_threshold:
        config.bug_threshold = args.bug_threshold
    
    # Create packet sender
    sender = SlowPacketSender(dev, config)
    
    # Run stress test
    target_mode = getattr(args, 'target_mode', 'auto')
    print(f"[*] Target: {target_mode.upper()}")
    print(f"[*] Fuzz mutations: {config.fuzz_mutations}")
    print(f"[*] Bug injection: {'Enabled' if config.code_injection_enabled else 'Disabled'}")
    print()
    
    start_time = time.time()
    stats, timing_data = sender.run_stress_test(duration)
    end_time = time.time()
    
    # Print results
    sender.print_results(stats, timing_data, end_time - start_time)
    
    # Save results if requested
    if hasattr(args, 'output') and args.output:
        output_data = {
            "timestamp": time.time(),
            "stats": stats,
            "timing_data": timing_data[:1000],  # Limit size
            "bugs": {
                "detected": len(sender.config.found_bugs),
                "confirmed": len(sender.config.confirmed_bugs),
                "injection_attempts": sender.config.injection_attempts,
                "injection_successes": sender.config.injection_successes
            },
            "config": {
                "min_delay_ms": config.min_delay_ms,
                "max_delay_ms": config.max_delay_ms,
                "fuzz_mutations": config.fuzz_mutations,
                "bug_threshold": config.bug_threshold,
                "injection_enabled": config.code_injection_enabled
            }
        }
        try:
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"[*] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results: {e}")
    
    return 0

# =============================================================================
# COMMAND REGISTRATION
# =============================================================================

def register_slowm8(subparsers):
    """Register slowm8 command with argument parser"""
    slowm8_parser = subparsers.add_parser(
        "slowm8",
        help="USB stress tester with auto-detection and bug injection"
    )
    
    # Timing options
    slowm8_parser.add_argument("--min-delay", type=float, default=None,
                               help="Minimum delay between packets (ms) - auto-detected if not set")
    slowm8_parser.add_argument("--max-delay", type=float, default=None,
                               help="Maximum delay between packets (ms) - auto-detected if not set")
    slowm8_parser.add_argument("--duration", type=int, default=30,
                               help="Test duration in seconds")
    slowm8_parser.add_argument("--packets", type=int, default=100,
                               help="Number of packets to send")
    
    # Stress patterns
    slowm8_parser.add_argument("--burst-size", type=int, default=10,
                               help="Packets per burst (0=disable)")
    slowm8_parser.add_argument("--progressive", action="store_true",
                               help="Progressively slow down transmission")
    slowm8_parser.add_argument("--no-random", action="store_true",
                               help="Disable random delays")
    
    # Fuzzing
    slowm8_parser.add_argument("--fuzz", type=int, default=0,
                               help="Number of fuzz mutations per packet")
    slowm8_parser.add_argument("--corrupt", nargs="+", choices=["magic", "crc", "size", "flags"],
                               help="Corrupt specific packet fields")
    
    # Bug injection
    slowm8_parser.add_argument("--no-injection", action="store_true",
                               help="Disable automatic code injection")
    slowm8_parser.add_argument("--injection-size", type=int, default=512,
                               help="Max injection payload size (bytes)")
    slowm8_parser.add_argument("--bug-threshold", type=int, default=3,
                               help="Number of bugs before injection attempts")
    
    # Target
    slowm8_parser.add_argument("--target-mode", default="auto",
                               choices=["auto", "dfu", "edl", "brom"],
                               help="Target low-level mode")
    
    # Output
    slowm8_parser.add_argument("--output", "-o", type=str,
                               help="Save results to JSON file")
    
    # Standard QSLCL args
    slowm8_parser.add_argument("--loader", help="Load QSLCL binary first")
    slowm8_parser.add_argument("--debug", action="store_true", help="Debug output")
    
    slowm8_parser.set_defaults(func=cmd_slowm8)
    
    return slowm8_parser

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="slowm8 - USB Stress Tester")
    parser.add_argument("--min-delay", type=float, default=None)
    parser.add_argument("--max-delay", type=float, default=None)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--fuzz", type=int, default=0)
    parser.add_argument("--loader", help="QSLCL binary to load")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--no-injection", action="store_true")
    parser.add_argument("--bug-threshold", type=int, default=3)
    parser.add_argument("--output", type=str, help="Save results to JSON")
    
    args = parser.parse_args()
    
    # Create dummy args for standalone mode
    class DummyArgs:
        pass
    
    cmd_args = DummyArgs()
    for key in vars(args):
        setattr(cmd_args, key, getattr(args, key))
    cmd_args.packets = 100
    cmd_args.burst_size = 10
    cmd_args.corrupt = None
    cmd_args.progressive = False
    cmd_args.no_random = False
    cmd_args.target_mode = "auto"
    cmd_args.injection_size = 512
    
    sys.exit(cmd_slowm8(cmd_args))