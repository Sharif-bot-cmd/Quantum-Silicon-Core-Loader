#!/usr/bin/env python3
# slowm8.py - QSLCL USB Stress Tester (Experimental)
# Simulates slow USB transfer patterns, malformed packets, and timing attacks
# Inspired by checkm8 but focused on USB stress testing, not exploitation

import os
import sys
import struct
import time
import json
import random
import threading
import hashlib
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict

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
        QSLCLSPT_DB,
        _DEBUG,
        parse_standard_header,
        open_transport,
        QSLCLDevice
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
            QSLCLSPT_DB,
            _DEBUG,
            parse_standard_header,
            open_transport,
            QSLCLDevice
        )
    except ImportError:
        print("[!] CRITICAL: Cannot import qslcl core module")
        sys.exit(1)

# =============================================================================
# SLOWM8 Configuration
# =============================================================================

@dataclass
class SlowM8Config:
    """Configuration for slowm8 stress testing"""
    # Timing parameters
    min_delay_ms: float = 1.0
    max_delay_ms: float = 100.0
    initial_delay_ms: float = 10.0
    
    # Packet modification
    corrupt_crc: bool = False
    corrupt_magic: bool = False
    corrupt_size: bool = False
    corrupt_flags: bool = False
    
    # Stress patterns
    packet_count: int = 100
    burst_size: int = 10
    burst_delay_ms: float = 500.0
    
    # Advanced options
    random_delays: bool = True
    progressive_slowdown: bool = False
    repeat_packets: int = 1
    fuzz_mutations: int = 0
    
    # Target selection
    target_mode: str = "dfu"  # dfu, edl, brom, auto
    use_qslcl_spt: bool = True  # Use QSLCLSPT database
    
    def __post_init__(self):
        self.delays_used = []

# =============================================================================
# USB Setup Packet Database (QSLCLSPT compatible)
# =============================================================================

# Standard USB setup packets that QSLCLSPT would contain
SLOWM8_SETUP_PACKETS = {
    # Standard USB requests
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
    
    # HID requests
    "GET_REPORT": struct.pack("<BBHHH", 0xA1, 0x01, 0x0100, 0x0000, 64),
    "SET_REPORT": struct.pack("<BBHHH", 0x21, 0x09, 0x0200, 0x0000, 64),
    "SET_IDLE": struct.pack("<BBHHH", 0x21, 0x0A, 0x0000, 0x0000, 0),
    
    # Vendor requests (QSLCL specific)
    "QSLCL_HELLO": struct.pack("<BBHHH", 0xC0, 0xF0, 0x5153, 0x4C43, 8),
    "QSLCL_CAPS": struct.pack("<BBHHH", 0xC0, 0xF1, 0x0001, 0x0000, 32),
    "QSLCL_RAWMODE": struct.pack("<BBHHH", 0x40, 0xF2, 0x0001, 0x0000, 4),
    
    # Malformed packets for fuzzing
    "MALFORMED_ZERO_LEN": struct.pack("<BBHHH", 0x00, 0x00, 0x0000, 0x0000, 0),
    "MALFORMED_MAX_LEN": struct.pack("<BBHHH", 0xFF, 0xFF, 0xFFFF, 0xFFFF, 0xFFFF),
    "MALFORMED_INVALID_REQ": struct.pack("<BBHHH", 0xFF, 0xEE, 0xDEAD, 0xBEEF, 0xFFFF),
}

# =============================================================================
# USB Fuzzing Mutators
# =============================================================================

class USBFuzzer:
    """Generate malformed USB setup packets for stress testing"""
    
    @staticmethod
    def corrupt_byte(data: bytes, position: int = None) -> bytes:
        """Corrupt a random byte in the packet"""
        data_list = list(data)
        if position is None:
            position = random.randint(0, len(data_list) - 1)
        data_list[position] = random.randint(0, 255)
        return bytes(data_list)
    
    @staticmethod
    def flip_bit(data: bytes, bit_position: int = None) -> bytes:
        """Flip a single bit in the packet"""
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
        """Replace magic bytes with invalid values"""
        if len(data) >= 4:
            # Replace first 4 bytes with random garbage
            data_list = list(data)
            data_list[0:4] = [random.randint(0, 255) for _ in range(4)]
            return bytes(data_list)
        return data
    
    @staticmethod
    def corrupt_length(data: bytes) -> bytes:
        """Set wLength to extreme values"""
        if len(data) >= 8:
            # wLength is bytes 6-7
            data_list = list(data)
            extreme_values = [0x0000, 0xFFFF, 0x7FFF, 0x8000, 0xFFFFFFFF]
            new_len = random.choice(extreme_values)
            data_list[6:8] = [(new_len >> 8) & 0xFF, new_len & 0xFF]
            return bytes(data_list)
        return data
    
    @staticmethod
    def set_invalid_request_type(data: bytes) -> bytes:
        """Set bmRequestType to invalid values"""
        if len(data) >= 1:
            data_list = list(data)
            invalid_types = [0xFF, 0x80, 0x40, 0x20, 0xE0, 0xC0]
            data_list[0] = random.choice(invalid_types)
            return bytes(data_list)
        return data
    
    @staticmethod
    def fuzz_packet(data: bytes, mutations: int = 1) -> bytes:
        """Apply multiple mutations to a packet"""
        result = data
        for _ in range(mutations):
            mutation_type = random.choice([
                "corrupt_byte",
                "flip_bit", 
                "corrupt_length",
                "invalid_request_type"
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
# Packet Sender with Timing Control
# =============================================================================

class SlowPacketSender:
    """Send packets with controlled timing and stress patterns"""
    
    def __init__(self, dev: QSLCLDevice, config: SlowM8Config):
        self.dev = dev
        self.config = config
        self.stats = {
            "sent": 0,
            "failed": 0,
            "responses": 0,
            "timeouts": 0,
            "crc_errors": 0,
            "malformed_responses": 0
        }
        self.timing_data = []
        self.running = False
    
    def _calculate_delay(self, packet_index: int, total_packets: int) -> float:
        """Calculate delay based on configuration"""
        if not self.config.random_delays:
            return self.config.initial_delay_ms / 1000.0
        
        base_delay = random.uniform(
            self.config.min_delay_ms / 1000.0,
            self.config.max_delay_ms / 1000.0
        )
        
        if self.config.progressive_slowdown:
            # Gradually increase delay
            progress = packet_index / total_packets
            slowdown_factor = 1 + (progress * 2)  # Up to 3x slower
            base_delay *= slowdown_factor
        
        # Burst mode: send multiple packets quickly then pause
        if self.config.burst_size > 0:
            if packet_index % self.config.burst_size == 0 and packet_index > 0:
                base_delay += self.config.burst_delay_ms / 1000.0
        
        delay = max(0.0001, min(1.0, base_delay))
        self.config.delays_used.append(delay)
        return delay
    
    def send_setup_packet(self, packet: bytes, packet_name: str = "unknown") -> Optional[bytes]:
        """Send a single setup packet via control transfer"""
        if len(packet) != 8:
            if _DEBUG:
                print(f"[!] Invalid packet length: {len(packet)} bytes (expected 8)")
            self.stats["failed"] += 1
            return None
        
        try:
            bmRequestType, bRequest, wValue, wIndex, wLength = struct.unpack("<BBHHH", packet)
            
            # Send control transfer
            response = self.dev.handle.ctrl_transfer(
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
            if "timeout" in str(e).lower():
                self.stats["timeouts"] += 1
            else:
                self.stats["failed"] += 1
            if _DEBUG:
                print(f"[!] USB error for {packet_name}: {e}")
            return None
        except Exception as e:
            self.stats["failed"] += 1
            if _DEBUG:
                print(f"[!] Error sending {packet_name}: {e}")
            return None
    
    def send_qslcl_structure(self, magic: bytes, body: bytes, flags: int = 0) -> bool:
        """Send QSLCL structured frame"""
        try:
            frame = encode_qslcl_structure(magic, body, flags)
            
            if self.dev.serial_mode:
                self.dev.handle.write(frame)
            else:
                # Find bulk OUT endpoint
                cfg = self.dev.handle.get_active_configuration()
                intf = cfg[(0, 0)]
                for ep in intf.endpoints():
                    if (usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT and
                        usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK):
                        self.dev.handle.write(ep.bEndpointAddress, frame, timeout=5000)
                        break
            
            self.stats["sent"] += 1
            return True
            
        except Exception as e:
            self.stats["failed"] += 1
            if _DEBUG:
                print(f"[!] Failed to send QSLCL frame: {e}")
            return False
    
    def run_stress_test(self, duration_seconds: int = 30):
        """Run continuous stress test"""
        self.running = True
        start_time = time.time()
        packet_index = 0
        
        print(f"[*] Starting slowm8 stress test for {duration_seconds} seconds...")
        print(f"[*] Config: min_delay={self.config.min_delay_ms}ms, max_delay={self.config.max_delay_ms}ms")
        print(f"[*] Random delays: {self.config.random_delays}")
        print(f"[*] Progressive slowdown: {self.config.progressive_slowdown}")
        print()
        
        packet_names = list(SLOWM8_SETUP_PACKETS.keys())
        
        try:
            while self.running and (time.time() - start_time) < duration_seconds:
                # Select packet (cycle through or random)
                packet_name = packet_names[packet_index % len(packet_names)]
                packet = SLOWM8_SETUP_PACKETS[packet_name]
                
                # Apply fuzzing if configured
                if self.config.fuzz_mutations > 0:
                    packet = USBFuzzer.fuzz_packet(packet, self.config.fuzz_mutations)
                    packet_name = f"fuzzed_{packet_name}"
                
                # Apply corruption based on config
                if self.config.corrupt_magic:
                    packet = USBFuzzer.set_invalid_magic(packet)
                    packet_name = f"corrupt_magic_{packet_name}"
                if self.config.corrupt_crc:
                    # For QSLCL frames, corrupt CRC
                    pass  # Handled separately
                if self.config.corrupt_size:
                    packet = USBFuzzer.corrupt_length(packet)
                    packet_name = f"corrupt_size_{packet_name}"
                if self.config.corrupt_flags:
                    # Corrupt flags byte
                    if len(packet) >= 1:
                        packet_list = list(packet)
                        packet_list[0] ^= 0xFF
                        packet = bytes(packet_list)
                        packet_name = f"corrupt_flags_{packet_name}"
                
                # Send packet with timing
                delay = self._calculate_delay(packet_index, duration_seconds * 10)
                time.sleep(delay)
                
                # Record timing
                send_time = time.time()
                response = self.send_setup_packet(packet, packet_name)
                response_time = (time.time() - send_time) * 1000
                
                self.timing_data.append({
                    "index": packet_index,
                    "name": packet_name,
                    "delay_ms": delay * 1000,
                    "response_time_ms": response_time if response else None,
                    "response_len": len(response) if response else 0,
                    "success": response is not None
                })
                
                # Progress indicator
                if packet_index % 50 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Progress: {elapsed:.1f}s / {duration_seconds}s, "
                          f"sent={self.stats['sent']}, "
                          f"responses={self.stats['responses']}, "
                          f"timeouts={self.stats['timeouts']}")
                
                # Repeat packets if configured
                for _ in range(self.config.repeat_packets - 1):
                    self.send_setup_packet(packet, f"repeat_{packet_name}")
                
                packet_index += 1
                
        except KeyboardInterrupt:
            print("\n[*] Stress test interrupted by user")
        finally:
            self.running = False
        
        return self.stats, self.timing_data

# =============================================================================
# QSLCLSPT Integration
# =============================================================================

def load_packets_from_qslcl_spt(dev: QSLCLDevice) -> List[bytes]:
    """Load setup packets from QSLCLSPT block in loaded binary"""
    packets = []
    
    try:
        if QSLCLSPT_DB and 'spt' in QSLCLSPT_DB:
            # QSLCLSPT block exists in loaded binary
            # Parse body to extract packets
            spt_data = QSLCLSPT_DB['spt']
            if isinstance(spt_data, dict) and 'body' in spt_data:
                body = spt_data['body']
                if len(body) >= 2:
                    count = struct.unpack("<H", body[:2])[0]
                    pos = 2
                    for i in range(count):
                        if pos + 12 <= len(body):
                            # Extract packet from index
                            # Actual packet data would be elsewhere
                            pass
        else:
            # Fallback to built-in packets
            packets = list(SLOWM8_SETUP_PACKETS.values())
            
    except Exception as e:
        if _DEBUG:
            print(f"[!] Failed to load from QSLCLSPT: {e}")
        packets = list(SLOWM8_SETUP_PACKETS.values())
    
    return packets

# =============================================================================
# Result Reporting
# =============================================================================

def print_slowm8_results(stats: dict, timing_data: list, duration: float):
    """Print formatted results"""
    print("\n" + "=" * 60)
    print("SLOWM8 STRESS TEST RESULTS")
    print("=" * 60)
    
    print(f"\n[STATISTICS]")
    print(f"  Packets sent:      {stats['sent']}")
    print(f"  Successful:        {stats['responses']}")
    print(f"  Failed:            {stats['failed']}")
    print(f"  Timeouts:          {stats['timeouts']}")
    print(f"  CRC errors:        {stats['crc_errors']}")
    print(f"  Malformed resp:    {stats['malformed_responses']}")
    
    if stats['sent'] > 0:
        success_rate = (stats['responses'] / stats['sent']) * 100
        print(f"  Success rate:      {success_rate:.1f}%")
    
    print(f"\n[TIMING ANALYSIS]")
    if timing_data:
        delays = [d['delay_ms'] for d in timing_data]
        response_times = [d['response_time_ms'] for d in timing_data if d['response_time_ms']]
        
        print(f"  Avg delay:         {sum(delays)/len(delays):.2f}ms")
        print(f"  Min delay:         {min(delays):.2f}ms")
        print(f"  Max delay:         {max(delays):.2f}ms")
        
        if response_times:
            print(f"  Avg response time: {sum(response_times)/len(response_times):.2f}ms")
            print(f"  Min response:      {min(response_times):.2f}ms")
            print(f"  Max response:      {max(response_times):.2f}ms")
    
    print(f"\n[TEST DURATION]")
    print(f"  Total time:        {duration:.2f} seconds")
    print(f"  Packets/sec:       {stats['sent'] / duration:.1f}")
    
    # Find interesting anomalies
    print(f"\n[ANOMALIES DETECTED]")
    anomalies = []
    for d in timing_data:
        if d.get('response_time_ms') and d['response_time_ms'] > 100:
            anomalies.append(f"  Slow response: {d['name']} took {d['response_time_ms']:.0f}ms")
        elif d.get('response_len', 0) > 1024:
            anomalies.append(f"  Large response: {d['name']} returned {d['response_len']} bytes")
    
    if anomalies:
        for a in anomalies[:10]:
            print(a)
        if len(anomalies) > 10:
            print(f"  ... and {len(anomalies) - 10} more")
    else:
        print("  No significant anomalies detected")
    
    print("\n" + "=" * 60)

def save_slowm8_results(stats: dict, timing_data: list, filename: str):
    """Save results to JSON file"""
    output = {
        "timestamp": time.time(),
        "stats": stats,
        "timing_data": timing_data,
        "summary": {
            "total_sent": stats['sent'],
            "success_rate": (stats['responses'] / stats['sent'] * 100) if stats['sent'] > 0 else 0,
            "avg_delay_ms": sum(d['delay_ms'] for d in timing_data) / len(timing_data) if timing_data else 0,
        }
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"[*] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")

# =============================================================================
# MAIN SLOWM8 COMMAND
# =============================================================================

def cmd_slowm8(args):
    """Execute slowm8 USB stress test"""
    print("\n" + "=" * 60)
    print("SLOWM8 - USB Stress Tester for QSLCL")
    print("Experimental - Use at your own risk")
    print("=" * 60 + "\n")
    
    # Scan for device
    devs = scan_all()
    if not devs:
        print("[!] No device detected")
        print("[*] Make sure your device is connected in DFU/EDL/BROM mode")
        return 1
    
    dev = devs[0]
    print(f"[+] Device found: {dev.product} (VID:PID={dev.vid:04X}:{dev.pid:04X})")
    
    # Load QSLCL binary if specified
    if args.loader:
        print(f"[*] Loading QSLCL binary: {args.loader}")
        auto_loader_if_needed(args, dev)
        time.sleep(1)
    
    # Setup configuration
    config = SlowM8Config()
    
    # Parse arguments
    if args.min_delay:
        config.min_delay_ms = args.min_delay
    if args.max_delay:
        config.max_delay_ms = args.max_delay
    if args.packets:
        config.packet_count = args.packets
    if args.burst_size:
        config.burst_size = args.burst_size
    if args.fuzz:
        config.fuzz_mutations = args.fuzz
    if args.corrupt:
        if 'magic' in args.corrupt:
            config.corrupt_magic = True
        if 'crc' in args.corrupt:
            config.corrupt_crc = True
        if 'size' in args.corrupt:
            config.corrupt_size = True
        if 'flags' in args.corrupt:
            config.corrupt_flags = True
    if args.progressive:
        config.progressive_slowdown = True
    if args.no_random:
        config.random_delays = False
    if args.duration:
        duration = args.duration
    else:
        duration = 30
    
    # Create packet sender
    sender = SlowPacketSender(dev, config)
    
    # Run stress test
    print(f"[*] Starting slowm8 stress test...")
    print(f"[*] Target: {args.target_mode.upper() if args.target_mode else 'AUTO'}")
    print(f"[*] Fuzz mutations: {config.fuzz_mutations}")
    print(f"[*] Corruptions: magic={config.corrupt_magic}, crc={config.corrupt_crc}, "
          f"size={config.corrupt_size}, flags={config.corrupt_flags}")
    print()
    
    start_time = time.time()
    stats, timing_data = sender.run_stress_test(duration)
    end_time = time.time()
    
    # Print results
    print_slowm8_results(stats, timing_data, end_time - start_time)
    
    # Save results if requested
    if args.output:
        save_slowm8_results(stats, timing_data, args.output)
    
    return 0

# =============================================================================
# COMMAND REGISTRATION (to be added to qslcl.py)
# =============================================================================

def register_slowm8(subparsers):
    """Register slowm8 command with argument parser"""
    slowm8_parser = subparsers.add_parser(
        "slowm8",
        help="USB stress tester (experimental, like checkm8 but slow)"
    )
    
    # Timing options
    slowm8_parser.add_argument("--min-delay", type=float, default=1.0,
                               help="Minimum delay between packets (ms)")
    slowm8_parser.add_argument("--max-delay", type=float, default=100.0,
                               help="Maximum delay between packets (ms)")
    slowm8_parser.add_argument("--duration", type=int, default=30,
                               help="Test duration in seconds")
    slowm8_parser.add_argument("--packets", type=int, default=100,
                               help="Number of packets to send (if duration not used)")
    
    # Stress patterns
    slowm8_parser.add_argument("--burst-size", type=int, default=10,
                               help="Packets per burst (0=disable)")
    slowm8_parser.add_argument("--progressive", action="store_true",
                               help="Progressively slow down transmission")
    slowm8_parser.add_argument("--no-random", action="store_true",
                               help="Disable random delays (use fixed timing)")
    
    # Fuzzing options
    slowm8_parser.add_argument("--fuzz", type=int, default=0,
                               help="Number of fuzz mutations per packet")
    slowm8_parser.add_argument("--corrupt", nargs="+", choices=["magic", "crc", "size", "flags"],
                               help="Corrupt specific packet fields")
    
    # Target selection
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