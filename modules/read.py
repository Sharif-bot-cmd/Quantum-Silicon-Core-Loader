#!/usr/bin/env python3
"""
read.py - QSLCL READ Command Module v2.1 (CLEANED)
Universal memory/storage reading with resume, verification, and format conversion
"""

import os
import sys
import time
import struct
import hashlib
import json
from typing import Optional, Dict, List, Any

# =============================================================================
# IMPORTS - With proper fallbacks
# =============================================================================
try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
        load_partitions,
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
            load_partitions,
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
DEFAULT_CHUNK = 65536          # 64KB default read chunk
MAX_RETRIES = 5                # Max retries per chunk
MAX_CONSECUTIVE_FAILS = 10     # Abort after this many failures
MAX_BACKOFF = 30.0             # Maximum backoff cap
READ_TIMEOUT = 15.0            # Read operation timeout

KNOWN_SIGNATURES = {
    b'ANDROID!': 'Android boot image',
    b'\x7fELF': 'ELF executable',
    b'MZ': 'Windows PE/DOS executable',
    b'QSLCL': 'QSLCL binary block',
    b'\x89PNG': 'PNG image',
    b'\xFF\xD8\xFF': 'JPEG image',
    b'PK\x03\x04': 'ZIP archive',
    b'\x1F\x8B': 'GZIP archive',
    b'%PDF': 'PDF document',
    b'BM': 'BMP image',
    b'RIFF': 'WAV/AVI media',
    b'ID3': 'MP3 audio',
}


# =============================================================================
# TARGET RESOLUTION (Minimal built-in)
# =============================================================================
def resolve_target(target: str, partitions: list, dev) -> Optional[dict]:
    """Resolve read target to address and size"""
    # Try hex address
    try:
        if target.lower().startswith('0x'):
            addr = int(target, 16)
            return {'address': addr, 'size': 0x1000000, 'partition': None}
    except (ValueError, AttributeError):
        pass
    
    # Try integer
    try:
        addr = int(target)
        if addr > 0:
            return {'address': addr, 'size': 0x1000000, 'partition': None}
    except ValueError:
        pass
    
    # Try partition name
    for part in partitions:
        if part.get('name', '').lower() == target.lower():
            return {'address': part['offset'], 'size': part['size'], 'partition': part}
    
    # Try partition+offset (e.g., "boot+0x1000")
    if '+' in target:
        name, offset_str = target.split('+', 1)
        try:
            offset = int(offset_str.strip(), 16 if offset_str.strip().lower().startswith('0x') else 10)
        except ValueError:
            offset = 0
        
        for part in partitions:
            if part.get('name', '').lower() == name.strip().lower():
                return {
                    'address': part['offset'] + offset,
                    'size': part['size'] - offset,
                    'partition': part,
                    'offset_in_partition': offset
                }
    
    return None


def parse_size(size_str: str) -> int:
    """Parse size string: 1M, 512K, 2G, 0x1000, 4096"""
    if not size_str:
        return 0
    
    size_str = str(size_str).strip().upper()
    
    try:
        if size_str.startswith('0X'):
            return int(size_str, 16)
        return int(size_str)
    except ValueError:
        pass
    
    multipliers = {'K': 1024, 'KB': 1024, 'M': 1024*1024, 'MB': 1024*1024,
                   'G': 1024**3, 'GB': 1024**3}
    
    for suffix, mul in multipliers.items():
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[:-len(suffix)]) * mul)
            except ValueError:
                continue
    
    try:
        return int(size_str)
    except ValueError:
        return 0


def format_size(size_bytes: int) -> str:
    """Human-readable size"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.1f} MB"
    return f"{size_bytes/(1024**3):.2f} GB"


# =============================================================================
# PROGRESS BAR
# =============================================================================
class ProgressBar:
    def __init__(self, total, prefix='', suffix='', length=50):
        self.total = max(total, 1)
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
        self.start_time = time.time()
    
    def __enter__(self):
        self.update(0)
        return self
    
    def __exit__(self, *args):
        print()
    
    def update(self, progress):
        self.current += progress
        pct = 100 * self.current / self.total
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '─' * (self.length - filled)
        
        elapsed = max(time.time() - self.start_time, 0.001)
        rate = self.current / elapsed
        eta = (self.total - self.current) / max(rate, 1)
        
        print(f'\r{self.prefix} |{bar}| {pct:5.1f}% {format_size(rate)}/s ETA:{eta:.0f}s {self.suffix}', 
              end='', flush=True)


# =============================================================================
# MAIN READ COMMAND
# =============================================================================
def cmd_read(args=None) -> int:
    """
    QSLCL READ - Universal memory/storage reader
    
    Examples:
        read boot                    - Read entire boot partition
        read boot boot.img           - Read boot partition to file
        read 0x10000000 1M           - Read 1MB from address
        read boot+0x1000 64K         - Read 64KB from offset in partition
        read system --resume         - Resume interrupted read
        read system --format hex     - Output as hex dump
        read boot --scan             - Scan for known file signatures
    """
    
    if args is None:
        print("[!] No arguments provided")
        print("[*] Usage: read <target> [size|output] [options]")
        return 1
    
    # Device discovery
    devs = scan_all()
    if not devs:
        print("[!] No QSLCL-compatible device detected")
        return 1
    
    dev = devs[0]
    print(f"[*] Device: {dev.product}")
    
    # Loader injection
    if getattr(args, 'loader', None):
        auto_loader_if_needed(args, dev)
    
    # Extract arguments
    target = getattr(args, 'target', None)
    if not target:
        print("[!] No target specified")
        print("[*] Examples: read boot, read 0x10000000 1M, read system system.img")
        return 1
    
    # Resolve partitions
    partitions = []
    try:
        partitions = load_partitions(dev) if getattr(args, 'auto_detect', True) else []
    except:
        pass
    
    # Resolve target
    target_info = resolve_target(target, partitions, dev)
    if not target_info:
        print(f"[!] Cannot resolve target: '{target}'")
        if partitions:
            print(f"\n[*] Available partitions ({len(partitions)}):")
            for p in sorted(partitions, key=lambda x: x['offset']):
                print(f"    {p['name']:<16} 0x{p['offset']:08X}  {format_size(p['size'])}")
        return 1
    
    address = target_info['address']
    max_size = target_info.get('size', 0)
    part_info = target_info.get('partition')
    
    print(f"[+] Target: 0x{address:08X}")
    if part_info:
        print(f"    Partition: {part_info['name']} (base 0x{part_info['offset']:08X}, {format_size(part_info['size'])})")
        if 'offset_in_partition' in target_info:
            print(f"    Offset: +0x{target_info['offset_in_partition']:X}")
    
    # Determine size
    size_arg = getattr(args, 'size', None)
    
    # Check if positional arg2 is size or output filename
    output_file = getattr(args, 'output', None)
    if hasattr(args, 'arg2') and args.arg2:
        arg2 = args.arg2
        # If looks like a size (numeric or hex), treat as size
        if arg2 and (arg2[0].isdigit() or arg2.lower().startswith('0x') or 
                     arg2.upper().endswith(('K', 'M', 'G', 'B'))):
            size_arg = arg2
        elif not output_file:
            output_file = arg2
    
    # Parse size
    if size_arg:
        size = parse_size(str(size_arg))
        if size <= 0:
            print(f"[!] Invalid size: {size_arg}")
            return 1
    elif max_size > 0:
        size = max_size
    else:
        print("[!] Cannot determine size - please specify")
        return 1
    
    # Validate size
    if max_size > 0 and size > max_size:
        print(f"[!] Size {format_size(size)} exceeds available {format_size(max_size)}, truncating")
        size = max_size
    
    if size <= 0:
        print("[!] Resulting size is zero")
        return 1
    
    print(f"[+] Size: {format_size(size)} (0x{size:X})")
    
    # Determine output file
    if not output_file:
        if part_info:
            output_file = f"{part_info['name']}.bin"
        else:
            output_file = f"dump_0x{address:08X}.bin"
        print(f"[*] Auto output: {output_file}")
    
    # Check existing file
    resume_mode = getattr(args, 'resume', False)
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK)
    format_type = getattr(args, 'format', 'raw')
    scan_mode = getattr(args, 'scan', False)
    no_verify = getattr(args, 'no_verify', False)
    
    if os.path.exists(output_file) and not resume_mode:
        existing = os.path.getsize(output_file)
        print(f"[!] '{output_file}' exists ({format_size(existing)})")
        if input("[?] Overwrite? (y/N): ").lower() != 'y':
            print("[*] Cancelled")
            return 0
        os.remove(output_file)
    
    # Resume offset
    start_offset = 0
    if resume_mode and os.path.exists(output_file):
        start_offset = os.path.getsize(output_file)
        if start_offset >= size:
            print(f"[*] Already complete: {format_size(start_offset)}")
            return 0
        print(f"[*] Resuming from {format_size(start_offset)}")
    
    chunk_size = max(512, min(chunk_size, 16*1024*1024))
    
    print(f"\n[+] READ Configuration:")
    print(f"    Chunk: {format_size(chunk_size)}")
    print(f"    Output: {output_file}")
    print(f"    Format: {format_type}")
    print(f"    Verify: {'Yes' if not no_verify else 'No'}")
    if scan_mode:
        print(f"    Scan:   Yes ({len(KNOWN_SIGNATURES)} signatures)")
    print()
    
    # =========================================================================
    # EXECUTE READ
    # =========================================================================
    mode = 'ab' if start_offset > 0 else 'wb'
    bytes_read = start_offset
    consecutive_fails = 0
    scan_findings = []
    
    try:
        with open(output_file, mode) as f:
            remaining = size - start_offset
            
            with ProgressBar(remaining, prefix='Reading', suffix='Complete') as progress:
                
                while bytes_read < size:
                    addr = address + bytes_read
                    chunk = min(chunk_size, size - bytes_read)
                    
                    if chunk <= 0:
                        break
                    
                    try:
                        # Build READ command
                        payload = struct.pack("<II", addr, chunk)
                        
                        # Use QSLCLCMD if available, otherwise raw
                        if "READ" in QSLCLCMD_DB:
                            resp = qslcl_dispatch(dev, "READ", payload, timeout=READ_TIMEOUT)
                        else:
                            pkt = encode_qslcl_structure(b"QSLCLCMD", payload)
                            dev.write(pkt)
                            _, resp = dev.read(timeout=READ_TIMEOUT)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            data = status.get("extra", b"")
                            
                            if data:
                                f.write(data)
                                f.flush()
                                
                                data_len = len(data)
                                bytes_read += data_len
                                progress.update(data_len)
                                consecutive_fails = 0
                                
                                # Scan for signatures
                                if scan_mode and data:
                                    for sig, desc in KNOWN_SIGNATURES.items():
                                        pos = 0
                                        while True:
                                            found = data.find(sig, pos)
                                            if found == -1:
                                                break
                                            scan_findings.append({
                                                'offset': address + bytes_read - data_len + found,
                                                'signature': desc,
                                                'magic': sig.hex().upper()
                                            })
                                            pos = found + 1
                            else:
                                consecutive_fails += 1
                        else:
                            consecutive_fails += 1
                        
                        if consecutive_fails >= MAX_CONSECUTIVE_FAILS:
                            print(f"\n[!] Too many failures, aborting at {format_size(bytes_read)}")
                            break
                        
                        # Retry backoff
                        if consecutive_fails > 0:
                            backoff = min(0.5 * (2 ** consecutive_fails), MAX_BACKOFF)
                            time.sleep(backoff)
                    
                    except KeyboardInterrupt:
                        print(f"\n[!] Interrupted at {format_size(bytes_read)}")
                        f.flush()
                        print(f"[*] Partial data saved. Use --resume to continue.")
                        return 0
                    
                    except Exception as e:
                        print(f"\n[!] Error at 0x{addr:08X}: {e}")
                        consecutive_fails += 1
                        if consecutive_fails >= MAX_CONSECUTIVE_FAILS:
                            break
        
        # =====================================================================
        # POST-PROCESSING
        # =====================================================================
        if bytes_read > 0:
            actual = os.path.getsize(output_file)
            
            # Verify
            if not no_verify:
                print(f"\n[*] Verification:")
                print(f"    Expected: {format_size(bytes_read)}")
                print(f"    Actual:   {format_size(actual)}")
                
                if actual == bytes_read:
                    print(f"    Status:   ✓ PASS")
                    
                    # SHA256 for files < 100MB
                    if actual <= 100 * 1024 * 1024:
                        with open(output_file, 'rb') as f:
                            fhash = hashlib.sha256(f.read()).hexdigest()
                        print(f"    SHA256:   {fhash[:32]}...")
                else:
                    print(f"    Status:   ✗ MISMATCH ({format_size(abs(actual - bytes_read))} difference)")
            
            # Format conversion
            if format_type != 'raw':
                convert_format(output_file, format_type)
            
            # Scan report
            if scan_mode and scan_findings:
                unique = {}
                for item in scan_findings:
                    key = item['offset']
                    if key not in unique:
                        unique[key] = item
                
                print(f"\n[*] Scan found {len(unique)} signatures:")
                for item in sorted(unique.values(), key=lambda x: x['offset'])[:20]:
                    print(f"    0x{item['offset']:08X}  {item['signature']}")
            
            # Summary
            print(f"\n{'='*50}")
            print(f"[✓] READ Complete")
            print(f"    Source: 0x{address:08X}")
            print(f"    Read:   {format_size(bytes_read)}")
            if bytes_read < size:
                print(f"    Status: PARTIAL ({bytes_read*100/size:.1f}%)")
                print(f"    Resume: qslcl read {target} --resume --output {output_file}")
            else:
                print(f"    Status: COMPLETE")
            print(f"    Output: {output_file}")
            print(f"{'='*50}")
            
            return 0
        else:
            print("[!] No data could be read")
            try:
                os.remove(output_file)
            except:
                pass
            return 1
    
    except KeyboardInterrupt:
        print(f"\n[!] Cancelled")
        if os.path.exists(output_file):
            sz = os.path.getsize(output_file)
            if sz > 0:
                print(f"[*] Partial: {format_size(sz)} saved to {output_file}")
        return 0
    
    except IOError as e:
        print(f"\n[!] I/O error: {e}")
        return 1
    
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return 1


# =============================================================================
# FORMAT CONVERSION
# =============================================================================
def convert_format(input_file: str, format_type: str):
    """Convert raw dump to requested format"""
    if format_type == 'hex':
        output = os.path.splitext(input_file)[0] + '.hex'
        try:
            with open(input_file, 'rb') as fin, open(output, 'w') as fout:
                fout.write(f"; Hex dump of {input_file}\n")
                fout.write(f"; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                offset = 0
                while True:
                    chunk = fin.read(16)
                    if not chunk:
                        break
                    hex_str = ' '.join(f'{b:02X}' for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    fout.write(f"{offset:08X}: {hex_str:<48} |{ascii_str}|\n")
                    offset += len(chunk)
            
            print(f"[+] Hex dump: {output}")
        except Exception as e:
            print(f"[!] Hex conversion failed: {e}")
    
    elif format_type == 'json':
        output = os.path.splitext(input_file)[0] + '.json'
        try:
            with open(input_file, 'rb') as f:
                header = f.read(64)
                f.seek(0)
                sha = hashlib.sha256()
                while True:
                    chunk = f.read(1024*1024)
                    if not chunk:
                        break
                    sha.update(chunk)
            
            # Detect type
            detected = []
            for sig, desc in KNOWN_SIGNATURES.items():
                if sig in header[:len(sig)]:
                    detected.append(desc)
            
            meta = {
                'file': os.path.basename(input_file),
                'size': os.path.getsize(input_file),
                'sha256': sha.hexdigest(),
                'header_hex': header[:32].hex().upper(),
                'header_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[:32]),
                'detected': detected or ['Unknown'],
                'generated': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            with open(output, 'w') as f:
                json.dump(meta, f, indent=2)
            
            print(f"[+] JSON metadata: {output}")
        except Exception as e:
            print(f"[!] JSON conversion failed: {e}")
    
    elif format_type == 'disasm':
        try:
            import capstone
            output = os.path.splitext(input_file)[0] + '.asm'
            
            with open(input_file, 'rb') as fin, open(output, 'w') as fout:
                fout.write(f"; Disassembly of {input_file}\n")
                fout.write(f"; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for arch_name, (arch, mode) in [
                    ('ARM', (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)),
                    ('ARM64', (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)),
                    ('x86', (capstone.CS_ARCH_X86, capstone.CS_MODE_32)),
                    ('x86_64', (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
                ]:
                    try:
                        md = capstone.Cs(arch, mode)
                        md.detail = True
                        
                        fout.write(f"\n; === {arch_name} ===\n\n")
                        
                        fin.seek(0)
                        data = fin.read(1024*1024)  # Cap at 1MB
                        
                        for insn in md.disasm(data, 0):
                            fout.write(f"0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}\n")
                    except:
                        fout.write(f"; {arch_name} disassembly unavailable\n")
            
            print(f"[+] Disassembly: {output}")
        except ImportError:
            print("[!] Install capstone for disassembly: pip install capstone")
        except Exception as e:
            print(f"[!] Disassembly failed: {e}")


# =============================================================================
# MODULE ENTRY
# =============================================================================
if __name__ == "__main__":
    print("[*] read.py - QSLCL READ Command Module")
    print("[*] This module is imported by qslcl.py")
    print("[*] Usage: python qslcl.py read <target> [options]")