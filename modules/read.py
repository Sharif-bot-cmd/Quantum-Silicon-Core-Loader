#!/usr/bin/env python3
"""
read.py - QSLCL READ Command Module v2.0 (FIXED)
Fixed: Import handling, error recovery, type safety, edge cases, progress tracking
"""

import os
import sys
import time
import struct
import hashlib
import json
from typing import Optional, Dict, List, Any, Tuple

# =============================================================================
# FIXED: Proper relative imports with fallbacks
# =============================================================================
try:
    from qslcl import (
        scan_all,
        auto_loader_if_needed,
        load_partitions,
        qslcl_dispatch,
        decode_runtime_result,
        ProgressBar,
        _DEBUG
    )
except ImportError:
    # Fallback for direct module execution or testing
    try:
        from .qslcl import (
            scan_all,
            auto_loader_if_needed,
            load_partitions,
            qslcl_dispatch,
            decode_runtime_result,
            ProgressBar,
            _DEBUG
        )
    except ImportError:
        print("[!] CRITICAL: Cannot import qslcl core module")
        print("[*] Ensure qslcl.py is in the same directory or Python path")
        sys.exit(1)

# =============================================================================
# FIXED: Proper target resolution imports
# =============================================================================
try:
    from qslcl import resolve_target, detect_memory_regions, parse_size_string
except ImportError:
    try:
        from .qslcl import resolve_target, detect_memory_regions, parse_size_string
    except ImportError:
        # Minimal fallback implementations
        def resolve_target(target, partitions, memory_regions, dev):
            """Minimal target resolver fallback"""
            # Try to parse as hex address
            try:
                if target.startswith('0x') or target.startswith('0X'):
                    address = int(target, 16)
                    return {
                        'address': address,
                        'size': 0x1000000,  # Default 16MB
                        'partition_info': None,
                        'region_info': None
                    }
            except (ValueError, AttributeError):
                pass
            
            # Try partition name match
            for part in partitions:
                if part.get('name', '').lower() == target.lower():
                    return {
                        'address': part['offset'],
                        'size': part['size'],
                        'partition_info': part,
                        'region_info': None
                    }
            
            return None

        def detect_memory_regions(dev):
            """Minimal memory region detector"""
            return []

        def parse_size_string(size_str: str) -> int:
            """Parse size string like '1M', '512K', '0x1000'"""
            if not isinstance(size_str, str):
                return int(size_str)
            
            size_str = size_str.strip().upper()
            
            try:
                if size_str.startswith('0X'):
                    return int(size_str, 16)
                return int(size_str)
            except ValueError:
                pass
            
            multipliers = {
                'K': 1024,
                'KB': 1024,
                'M': 1024 * 1024,
                'MB': 1024 * 1024,
                'G': 1024 * 1024 * 1024,
                'GB': 1024 * 1024 * 1024,
            }
            
            for suffix, multiplier in multipliers.items():
                if size_str.endswith(suffix):
                    try:
                        number = float(size_str[:-len(suffix)])
                        return int(number * multiplier)
                    except ValueError:
                        continue
            
            try:
                return int(size_str)
            except ValueError:
                return 0


# =============================================================================
# FIXED: Constants for better maintainability
# =============================================================================
DEFAULT_CHUNK_SIZE = 65536      # 64KB default read chunk
MAX_RETRIES = 5                 # Maximum retry attempts per chunk
MAX_CONSECUTIVE_FAILURES = 10   # Maximum consecutive failures before abort
INITIAL_BACKOFF = 0.5           # Initial backoff in seconds
MAX_BACKOFF = 30.0              # Maximum backoff cap
READ_TIMEOUT = 15.0             # Read operation timeout
LARGE_READ_THRESHOLD = 10 * 1024 * 1024  # 10MB threshold for progress optimization

# Known file format patterns for scanning
KNOWN_PATTERNS = {
    b'ANDROID!': 'Android boot image',
    b'\x7fELF': 'ELF executable',
    b'MZ': 'Windows PE executable',
    b'APFS': 'Apple File System',
    b'HFS': 'Hierarchical File System (HFS+)',
    b'BM': 'BMP image',
    b'\xFF\xD8\xFF': 'JPEG image',
    b'\x89PNG': 'PNG image',
    b'PK\x03\x04': 'ZIP archive',
    b'\x1F\x8B': 'GZIP archive',
    b'BZh': 'BZIP2 archive',
    b'\xFD7zXZ': 'XZ archive',
    b'Rar!\x1A\x07': 'RAR archive',
    b'QSLCL': 'QSLCL binary block',
    b'\x00\x00\x00\x18ftyp': 'MP4 video',
    b'ID3': 'MP3 audio',
    b'OggS': 'OGG audio',
    b'RIFF': 'WAV audio / AVI video',
    b'%PDF': 'PDF document',
    b'\xD0\xCF\x11\xE0': 'MS Office document (OLE2)',
}


# =============================================================================
# FIXED: Main command function with comprehensive error handling
# =============================================================================
def cmd_read(args=None) -> int:
    """
    QSLCL READ Command v2.0 (FIXED)
    
    Reads data from device memory/partitions/storage with:
    - Proper error recovery with exponential backoff
    - Resume support for interrupted operations
    - Multiple output formats (raw, hex, json, disasm)
    - Pattern scanning mode
    - Integrity verification
    - Comprehensive progress reporting
    
    Returns:
        int: 0 on success, 1 on failure
    """
    
    # =========================================================================
    # FIXED: Input validation
    # =========================================================================
    if args is None:
        print("[!] READ: No arguments provided")
        print("[*] Usage: read <target> [size] [output] [--options]")
        return 1
    
    # =========================================================================
    # FIXED: Device discovery with better error handling
    # =========================================================================
    try:
        devs = scan_all()
    except Exception as e:
        print(f"[!] Device scan failed: {e}")
        return 1
    
    if not devs:
        print("[!] No QSLCL-compatible device detected")
        print("[*] Ensure device is connected and in proper mode")
        return 1
    
    dev = devs[0]
    print(f"[*] Using device: {dev.product} ({dev.vendor})")
    
    # =========================================================================
    # FIXED: Proper loader injection
    # =========================================================================
    if hasattr(args, 'loader') and args.loader:
        try:
            auto_loader_if_needed(args, dev)
        except Exception as e:
            print(f"[!] Loader injection failed: {e}")
            return 1
    
    # =========================================================================
    # FIXED: Extract arguments with proper defaults
    # =========================================================================
    target = getattr(args, 'target', None)
    output_file = getattr(args, 'output', None)
    size_arg = getattr(args, 'size', None)
    chunk_size = getattr(args, 'chunk_size', DEFAULT_CHUNK_SIZE)
    no_verify = getattr(args, 'no_verify', False)
    format_type = getattr(args, 'format', 'raw')
    scan_mode = getattr(args, 'scan', False)
    auto_detect = getattr(args, 'auto_detect', True)
    resume_mode = getattr(args, 'resume', False)
    
    # FIXED: Validate chunk_size
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        print(f"[!] Invalid chunk size: {chunk_size}, using default: {DEFAULT_CHUNK_SIZE}")
        chunk_size = DEFAULT_CHUNK_SIZE
    
    # FIXED: Clamp chunk size to reasonable range
    chunk_size = max(512, min(chunk_size, 16 * 1024 * 1024))  # 512B to 16MB
    
    # =========================================================================
    # FIXED: Target validation
    # =========================================================================
    if not target:
        print("[!] READ: No target specified")
        print("[*] Examples:")
        print("    read boot                    - Read boot partition")
        print("    read 0x10000000 1M           - Read 1MB from address")
        print("    read boot+0x1000 64K         - Read from partition offset")
        print("    read system system.img       - Read system partition to file")
        return 1
    
    print(f"[*] READ: target='{target}', size={size_arg}, chunk={chunk_size}")
    
    # =========================================================================
    # FIXED: Target resolution with proper error handling
    # =========================================================================
    partitions = []
    memory_regions = []
    
    if auto_detect:
        try:
            partitions = load_partitions(dev)
        except Exception as e:
            if _DEBUG:
                print(f"[!] Partition detection failed: {e}")
            print("[!] Partition detection failed, will try address-based access")
        
        try:
            memory_regions = detect_memory_regions(dev)
        except Exception as e:
            if _DEBUG:
                print(f"[!] Memory region detection failed: {e}")
    
    try:
        target_info = resolve_target(target, partitions, memory_regions, dev)
    except Exception as e:
        print(f"[!] Target resolution error: {e}")
        target_info = None
    
    if not target_info:
        print(f"[!] Could not resolve target: '{target}'")
        
        # FIXED: Show helpful information
        if partitions:
            print(f"\n[*] Available partitions ({len(partitions)}):")
            for part in sorted(partitions, key=lambda p: p.get('offset', 0)):
                name = part.get('name', 'unknown')
                offset = part.get('offset', 0)
                size = part.get('size', 0)
                print(f"    {name:<16} offset=0x{offset:08X}  size=0x{size:08X} ({format_size(size)})")
        
        if memory_regions:
            print(f"\n[*] Available memory regions ({len(memory_regions)}):")
            for region in memory_regions:
                name = region.get('name', 'unknown')
                start = region.get('start', 0)
                size = region.get('size', 0)
                perms = region.get('permissions', '???')
                print(f"    {name:<16} start=0x{start:016X}  size=0x{size:08X}  perms={perms}")
        
        if not partitions and not memory_regions:
            print("[*] Try specifying an explicit address: read 0x10000000 1M")
        
        return 1
    
    # =========================================================================
    # FIXED: Extract resolved target info with validation
    # =========================================================================
    address = target_info.get('address')
    max_possible_size = target_info.get('size', 0)
    partition_info = target_info.get('partition_info')
    region_info = target_info.get('region_info')
    
    if address is None:
        print("[!] Invalid target address resolved")
        return 1
    
    # FIXED: Validate address
    if address < 0:
        print(f"[!] Invalid negative address: {address}")
        return 1
    
    print(f"\n[+] Target resolved:")
    print(f"    Address: 0x{address:08X}")
    
    if partition_info:
        part_name = partition_info.get('name', 'unknown')
        part_offset = partition_info.get('offset', 0)
        part_size = partition_info.get('size', 0)
        print(f"    Partition: {part_name}")
        print(f"    Partition base: 0x{part_offset:08X}")
        print(f"    Partition size: 0x{part_size:08X} ({format_size(part_size)})")
        
        # Calculate offset within partition
        offset_in_partition = address - part_offset
        if offset_in_partition > 0:
            print(f"    Offset in partition: 0x{offset_in_partition:08X}")
    
    if region_info:
        region_name = region_info.get('name', 'unknown')
        region_start = region_info.get('start', 0)
        region_size = region_info.get('size', 0)
        print(f"    Memory region: {region_name}")
        print(f"    Region start: 0x{region_start:016X}")
        print(f"    Region size: 0x{region_size:08X} ({format_size(region_size)})")
        if 'permissions' in region_info:
            print(f"    Permissions: {region_info['permissions']}")
    
    # =========================================================================
    # FIXED: Size determination with proper bounds checking
    # =========================================================================
    size = 0
    
    if size_arg is not None:
        # Parse size argument
        try:
            if isinstance(size_arg, (int, float)):
                size = int(size_arg)
            elif isinstance(size_arg, str):
                size = parse_size_string(size_arg)
            else:
                print(f"[!] Invalid size type: {type(size_arg)}")
                return 1
        except (ValueError, TypeError) as e:
            print(f"[!] Invalid size argument '{size_arg}': {e}")
            return 1
        
        # FIXED: Validate size
        if size <= 0:
            print(f"[!] Invalid size: {size} (must be positive)")
            return 1
        
        # FIXED: Warn if size exceeds available space
        if max_possible_size > 0 and size > max_possible_size:
            print(f"[!] Warning: Requested size {format_size(size)} exceeds available {format_size(max_possible_size)}")
            print(f"[*] Truncating to maximum available size")
            size = max_possible_size
    else:
        # FIXED: Use maximum available size only if known
        if max_possible_size > 0:
            size = max_possible_size
            print(f"[*] Using maximum available size: {format_size(size)}")
        else:
            print("[!] Cannot determine size automatically")
            print("[*] Please specify size: read <target> <size>")
            return 1
    
    # FIXED: Final size validation
    if size <= 0:
        print("[!] Resulting size is zero or negative")
        return 1
    
    # FIXED: Sanity check on size (warn if very large)
    if size > 1024 * 1024 * 1024:  # 1GB
        print(f"[!] WARNING: Requested read size is very large ({format_size(size)})")
        print(f"[*] This may take significant time and storage space")
        response = input("[?] Continue? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Operation cancelled")
            return 0
    
    # =========================================================================
    # FIXED: Output file handling
    # =========================================================================
    output_given = False
    
    # Get output from either --output or positional arg2
    if output_file:
        output_given = True
    elif hasattr(args, 'arg2') and args.arg2:
        # FIXED: Check if arg2 is actually a filename, not a size
        arg2 = args.arg2
        # If arg2 looks like a size (starts with digit or 0x), it's probably not a filename
        if arg2 and not (arg2[0].isdigit() or arg2.lower().startswith('0x')):
            output_file = arg2
            output_given = True
    
    if not output_given or not output_file:
        # FIXED: Generate automatic output filename
        if partition_info:
            base_name = partition_info.get('name', 'memory')
        elif region_info:
            base_name = region_info.get('name', 'memory')
        else:
            base_name = f"addr_0x{address:08X}"
        
        # Sanitize base name for filesystem
        base_name = ''.join(c for c in base_name if c.isalnum() or c in '_-')
        if not base_name:
            base_name = 'read_dump'
        
        format_extensions = {
            'raw': '.bin',
            'hex': '.hex',
            'json': '.json',
            'disasm': '.asm',
        }
        ext = format_extensions.get(format_type, '.bin')
        output_file = f"{base_name}{ext}"
        
        print(f"[*] Auto-generated output filename: {output_file}")
    
    # FIXED: Validate output path
    output_dir = os.path.dirname(output_file) or '.'
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            print(f"[!] Cannot create output directory '{output_dir}': {e}")
            return 1
    
    # FIXED: Check disk space
    try:
        if os.path.exists(output_dir):
            stat = os.statvfs(output_dir)
            free_space = stat.f_frsize * stat.f_bavail
            if free_space < size * 1.1:  # Need 10% extra
                print(f"[!] WARNING: Low disk space ({format_size(free_space)} free, {format_size(size)} needed)")
                response = input("[?] Continue anyway? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    print("[*] Operation cancelled")
                    return 0
    except Exception:
        pass  # Can't check disk space, continue anyway
    
    # Check if output file exists
    if os.path.exists(output_file) and not resume_mode:
        existing_size = os.path.getsize(output_file)
        print(f"[!] File '{output_file}' already exists ({format_size(existing_size)})")
        response = input("[?] Overwrite? (y/N): ")
        if response.lower() not in ('y', 'yes'):
            print("[*] Operation cancelled")
            return 0
        # Remove existing file for clean write
        try:
            os.remove(output_file)
        except Exception as e:
            print(f"[!] Cannot remove existing file: {e}")
            return 1
    
    # =========================================================================
    # FIXED: SCAN MODE
    # =========================================================================
    if scan_mode:
        return run_scan_mode(dev, address, size, output_file, chunk_size)
    
    # =========================================================================
    # FIXED: RESUME MODE
    # =========================================================================
    start_offset = 0
    if resume_mode and os.path.exists(output_file):
        try:
            start_offset = os.path.getsize(output_file)
            if start_offset > 0:
                print(f"[*] Resume mode: continuing from offset 0x{start_offset:08X} ({format_size(start_offset)})")
                
                # Check if already complete
                if start_offset >= size:
                    print("[*] File already complete, nothing to read")
                    print(f"[+] Output: {output_file} ({format_size(start_offset)})")
                    return 0
                
                # Adjust remaining size
                remaining_size = size - start_offset
                print(f"[*] Remaining to read: {format_size(remaining_size)}")
        except Exception as e:
            print(f"[!] Cannot resume: {e}")
            print("[*] Starting from beginning")
            start_offset = 0
    
    # =========================================================================
    # FIXED: MAIN READ OPERATION
    # =========================================================================
    print(f"\n[+] READ Configuration:")
    print(f"    Source: 0x{address:08X}")
    print(f"    Size: 0x{size:08X} ({format_size(size)})")
    print(f"    Chunk: 0x{chunk_size:08X} ({format_size(chunk_size)})")
    print(f"    Output: {output_file}")
    print(f"    Format: {format_type}")
    print(f"    Verify: {'Yes' if not no_verify else 'No'}")
    print()
    
    try:
        # Open file for writing (append mode for resume)
        mode = 'ab' if resume_mode and start_offset > 0 else 'wb'
        
        with open(output_file, mode) as f:
            bytes_read = start_offset
            retry_count = 0
            consecutive_failures = 0
            last_progress_report = time.time()
            last_successful_read = time.time()
            
            # FIXED: Handle zero-size edge case
            if size <= 0:
                print("[!] Size is zero, nothing to read")
                return 1
            
            # FIXED: Use context manager for progress bar
            total_to_read = size - start_offset
            progress_prefix = 'Resuming' if start_offset > 0 else 'Reading'
            
            with ProgressBar(total_to_read, prefix=progress_prefix, 
                           suffix='Complete', length=50) as progress:
                
                # Update progress for already-read data
                if start_offset > 0:
                    progress.update(0)  # Initialize, already-read bytes counted
                
                while bytes_read < size:
                    # Calculate chunk parameters
                    chunk_addr = address + bytes_read
                    remaining = size - bytes_read
                    current_chunk = min(chunk_size, remaining)
                    
                    # FIXED: Should not happen but guard against zero
                    if current_chunk <= 0:
                        break
                    
                    try:
                        # FIXED: Build read payload with proper byte order
                        read_payload = struct.pack("<II", chunk_addr, current_chunk)
                        
                        # FIXED: Dispatch with proper timeout
                        resp = qslcl_dispatch(dev, "READ", read_payload, timeout=READ_TIMEOUT)
                        
                        if resp:
                            # Parse response
                            status = decode_runtime_result(resp)
                            
                            if status.get("severity") == "SUCCESS":
                                data = status.get("extra", b"")
                                
                                if not data:
                                    # Empty but successful response - might be end of readable memory
                                    print(f"\n[!] Empty response at 0x{chunk_addr:08X} - possible end of readable region")
                                    consecutive_failures += 1
                                else:
                                    actual_len = len(data)
                                    
                                    # FIXED: Handle short reads
                                    if actual_len < current_chunk:
                                        if _DEBUG:
                                            print(f"\n[!] Short read at 0x{chunk_addr:08X}: "
                                                  f"requested {current_chunk}, got {actual_len}")
                                    
                                    # FIXED: Write data with error handling
                                    try:
                                        f.write(data)
                                        f.flush()
                                    except IOError as e:
                                        print(f"\n[!] Write error: {e}")
                                        print("[!] Disk may be full or file may be locked")
                                        break
                                    
                                    bytes_read += actual_len
                                    progress.update(actual_len)
                                    
                                    # Reset failure counters on success
                                    retry_count = 0
                                    consecutive_failures = 0
                                    last_successful_read = time.time()
                                    
                                    # FIXED: Periodic progress report for large reads
                                    if bytes_read > LARGE_READ_THRESHOLD:
                                        now = time.time()
                                        if now - last_progress_report > 5.0:  # Every 5 seconds
                                            elapsed = now - last_successful_read
                                            rate = actual_len / max(elapsed, 0.001)
                                            print(f"\n[*] Read {format_size(bytes_read)}/{format_size(size)} "
                                                  f"({bytes_read*100/size:.1f}%) - {format_size(rate)}/s")
                                            last_progress_report = now
                            
                            elif status.get("severity") == "WARNING":
                                print(f"\n[!] Warning at 0x{chunk_addr:08X}: {status.get('name', 'Unknown')}")
                                # Warnings might still have data
                                data = status.get("extra", b"")
                                if data:
                                    try:
                                        f.write(data)
                                        f.flush()
                                        bytes_read += len(data)
                                        progress.update(len(data))
                                    except IOError:
                                        break
                                consecutive_failures += 1
                            
                            else:
                                # Error response
                                error_name = status.get('name', 'Unknown error')
                                error_code = status.get('code', 'N/A')
                                print(f"\n[!] Read error at 0x{chunk_addr:08X}: {error_name} (code: {error_code})")
                                retry_count += 1
                                consecutive_failures += 1
                        
                        else:
                            # No response received
                            print(f"\n[!] No response at 0x{chunk_addr:08X}")
                            retry_count += 1
                            consecutive_failures += 1
                        
                        # FIXED: Handle retries with exponential backoff (capped)
                        if consecutive_failures > 0 and retry_count > 0:
                            if retry_count >= MAX_RETRIES:
                                print(f"\n[!] Max retries ({MAX_RETRIES}) exceeded at 0x{chunk_addr:08X}")
                                print(f"[*] Read interrupted at {format_size(bytes_read)}/{format_size(size)}")
                                break
                            
                            # Exponential backoff with cap
                            backoff = min(INITIAL_BACKOFF * (2 ** (retry_count - 1)), MAX_BACKOFF)
                            if _DEBUG:
                                print(f"[*] Backoff: {backoff:.2f}s (retry {retry_count}/{MAX_RETRIES})")
                            time.sleep(backoff)
                        
                        # FIXED: Check for too many consecutive failures
                        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                            print(f"\n[!] Too many consecutive failures ({consecutive_failures})")
                            print(f"[*] Read interrupted at {format_size(bytes_read)}/{format_size(size)}")
                            break
                    
                    except KeyboardInterrupt:
                        print(f"\n\n[!] READ interrupted by user")
                        try:
                            f.flush()
                        except:
                            pass
                        print(f"[*] Partial data saved: {format_size(bytes_read)} -> {output_file}")
                        print(f"[*] To resume: use --resume flag")
                        return 0  # Partial success
                    
                    except Exception as e:
                        print(f"\n[!] Exception at 0x{chunk_addr:08X}: {type(e).__name__}: {e}")
                        if _DEBUG:
                            import traceback
                            traceback.print_exc()
                        retry_count += 1
                        consecutive_failures += 1
                        
                        if retry_count >= MAX_RETRIES:
                            print(f"[!] Max retries exceeded after exceptions")
                            break
                        
                        time.sleep(1.0)
        
        # =====================================================================
        # FIXED: POST-READ PROCESSING
        # =====================================================================
        if bytes_read > 0:
            # Verify file size
            try:
                actual_file_size = os.path.getsize(output_file)
            except OSError:
                actual_file_size = 0
            
            if actual_file_size == 0:
                print("[!] Output file is empty - read failed")
                try:
                    os.remove(output_file)
                except:
                    pass
                return 1
            
            # Format conversion if requested
            if format_type != 'raw':
                try:
                    convert_to_format(output_file, format_type)
                except Exception as e:
                    print(f"[!] Format conversion failed: {e}")
            
            # Verification
            if not no_verify:
                verify_read_result(output_file, bytes_read, start_offset)
            
            # Print summary
            print_read_summary(
                address=address,
                bytes_read=bytes_read,
                requested_size=size,
                output_file=output_file,
                partition_info=partition_info,
                start_offset=start_offset
            )
            
            # FIXED: Return success even for partial reads
            if bytes_read < size:
                print(f"\n[*] Partial read completed ({bytes_read*100/size:.1f}%)")
                print(f"[*] To resume: qslcl read {target} --resume --output {output_file}")
                return 0  # Partial success
            
            return 0
        else:
            print("[!] READ failed: No data could be read")
            print("[*] Possible causes:")
            print("    - Device disconnected or unresponsive")
            print("    - Invalid address or protected region")
            print("    - Hardware fault or timeout")
            
            # Clean up empty file
            try:
                if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
                    os.remove(output_file)
            except:
                pass
            
            return 1
    
    except KeyboardInterrupt:
        print(f"\n[!] Operation cancelled by user")
        if os.path.exists(output_file):
            size_on_disk = os.path.getsize(output_file)
            if size_on_disk > 0:
                print(f"[*] Partial data saved to {output_file} ({format_size(size_on_disk)})")
                print(f"[*] To resume: use --resume flag")
        return 0
    
    except IOError as e:
        print(f"\n[!] I/O error: {e}")
        print("[*] Check disk space and permissions")
        return 1
    
    except Exception as e:
        print(f"\n[!] Unexpected error during READ: {type(e).__name__}: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        
        # Clean up on catastrophic failure
        try:
            if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
                os.remove(output_file)
        except:
            pass
        
        return 1


# =============================================================================
# FIXED: Scan mode implementation
# =============================================================================
def run_scan_mode(dev, start_address: int, size: int, 
                  output_file: str, chunk_size: int) -> int:
    """
    Scan mode: read memory and detect known file patterns.
    
    Returns:
        int: 0 on success, 1 on failure
    """
    print(f"\n[*] SCAN MODE: Reading with pattern detection")
    print(f"    Range: 0x{start_address:08X} - 0x{start_address + size:08X}")
    print(f"    Output: {output_file}")
    print(f"    Patterns: {len(KNOWN_PATTERNS)} known signatures")
    print()
    
    found_items = []
    bytes_read = 0
    consecutive_failures = 0
    
    try:
        with open(output_file, 'wb') as f:
            with ProgressBar(size, prefix='Scanning', suffix='Complete', length=50) as progress:
                
                while bytes_read < size:
                    chunk_addr = start_address + bytes_read
                    remaining = size - bytes_read
                    current_chunk = min(chunk_size, remaining)
                    
                    if current_chunk <= 0:
                        break
                    
                    try:
                        # Read chunk
                        read_payload = struct.pack("<II", chunk_addr, current_chunk)
                        resp = qslcl_dispatch(dev, "READ", read_payload, timeout=READ_TIMEOUT)
                        
                        if resp:
                            status = decode_runtime_result(resp)
                            if status.get("severity") == "SUCCESS":
                                data = status.get("extra", b"")
                                if data:
                                    # Write to file
                                    f.write(data)
                                    
                                    # FIXED: Scan for all known patterns
                                    for pattern, description in KNOWN_PATTERNS.items():
                                        search_pos = 0
                                        while True:
                                            found_pos = data.find(pattern, search_pos)
                                            if found_pos == -1:
                                                break
                                            absolute_offset = bytes_read + found_pos
                                            found_items.append({
                                                'pattern': pattern,
                                                'description': description,
                                                'offset': start_address + absolute_offset,
                                                'size': len(pattern)
                                            })
                                            search_pos = found_pos + 1
                                    
                                    bytes_read += len(data)
                                    progress.update(len(data))
                                    consecutive_failures = 0
                                else:
                                    consecutive_failures += 1
                            else:
                                consecutive_failures += 1
                        else:
                            consecutive_failures += 1
                        
                        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                            print(f"\n[!] Too many consecutive failures, scan aborted")
                            break
                    
                    except KeyboardInterrupt:
                        print(f"\n[!] Scan interrupted by user")
                        break
                    
                    except Exception as e:
                        print(f"\n[!] Scan error at 0x{chunk_addr:08X}: {e}")
                        consecutive_failures += 1
                        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                            break
    
    except Exception as e:
        print(f"\n[!] Scan mode critical error: {e}")
        return 1
    
    # FIXED: Report findings
    print(f"\n{'='*60}")
    print(f"[+] SCAN completed: {format_size(bytes_read)} scanned")
    print(f"{'='*60}")
    
    if found_items:
        # Deduplicate overlapping findings
        unique_items = []
        seen_offsets = set()
        
        for item in sorted(found_items, key=lambda x: x['offset']):
            # Allow findings within 16 bytes of each other (might be same pattern)
            if item['offset'] not in seen_offsets:
                # Mark nearby offsets as seen
                for o in range(item['offset'], item['offset'] + 32):
                    seen_offsets.add(o)
                unique_items.append(item)
        
        print(f"\n[*] Found {len(unique_items)} unique patterns:\n")
        print(f"    {'Offset':<16} {'Size':<10} {'Description':<40}")
        print(f"    {'-'*66}")
        
        for item in unique_items:
            offset_str = f"0x{item['offset']:08X}"
            size_str = f"{item['size']}B"
            print(f"    {offset_str:<16} {size_str:<10} {item['description']:<40}")
        
        # Show hex dump of first finding
        if unique_items:
            print(f"\n[*] First finding details (at 0x{unique_items[0]['offset']:08X}):")
            try:
                with open(output_file, 'rb') as f:
                    f.seek(unique_items[0]['offset'] - start_address)
                    preview = f.read(64)
                    print_hex_dump(preview, unique_items[0]['offset'])
            except:
                pass
    else:
        print("\n[*] No known patterns found in scanned region")
    
    print(f"\n[+] Full data saved to: {output_file}")
    return 0


# =============================================================================
# FIXED: Format conversion with better error handling
# =============================================================================
def convert_to_format(input_file: str, format_type: str) -> bool:
    """
    Convert raw binary dump to requested format.
    
    Args:
        input_file: Path to raw binary file
        format_type: Target format (hex, json, disasm)
    
    Returns:
        bool: True on success
    """
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return False
    
    file_size = os.path.getsize(input_file)
    if file_size == 0:
        print("[!] Input file is empty, skipping conversion")
        return False
    
    print(f"[*] Converting {format_size(file_size)} to {format_type.upper()}...")
    
    try:
        if format_type == 'hex':
            return _convert_to_hex(input_file, file_size)
        elif format_type == 'json':
            return _convert_to_json(input_file, file_size)
        elif format_type == 'disasm':
            return _convert_to_disasm(input_file, file_size)
        else:
            print(f"[!] Unknown format: {format_type}")
            return False
    
    except Exception as e:
        print(f"[!] Format conversion failed: {e}")
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return False


def _convert_to_hex(input_file: str, file_size: int) -> bool:
    """Convert to hex dump format"""
    output_file = os.path.splitext(input_file)[0] + '.hex'
    
    try:
        with open(input_file, 'rb') as fin, open(output_file, 'w') as fout:
            fout.write(f"; Hex dump of {input_file}\n")
            fout.write(f"; Size: {file_size} bytes ({format_size(file_size)})\n")
            fout.write(f"; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            bytes_written = 0
            chunk_size = 16 * 1024  # Read 16KB at a time
            
            while bytes_written < file_size:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                
                for i in range(0, len(chunk), 16):
                    line_data = chunk[i:i+16]
                    hex_str = ' '.join(f'{b:02X}' for b in line_data)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line_data)
                    offset = bytes_written + i
                    fout.write(f"{offset:08X}: {hex_str:<48} |{ascii_str}|\n")
                
                bytes_written += len(chunk)
        
        print(f"[+] Hex dump saved to: {output_file}")
        return True
    
    except Exception as e:
        print(f"[!] Hex conversion failed: {e}")
        return False


def _convert_to_json(input_file: str, file_size: int) -> bool:
    """Convert to JSON metadata format"""
    output_file = os.path.splitext(input_file)[0] + '.json'
    
    try:
        with open(input_file, 'rb') as f:
            # Read first 64 bytes for analysis
            header = f.read(64)
            
            # Calculate hashes (streaming for large files)
            sha256_hash = hashlib.sha256()
            f.seek(0)
            chunk_size = 1024 * 1024  # 1MB chunks
            bytes_hashed = 0
            while bytes_hashed < file_size:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)
                bytes_hashed += len(chunk)
        
        # Detect known patterns
        detected_magics = []
        for magic, description in KNOWN_PATTERNS.items():
            if magic in header:
                detected_magics.append({
                    'magic': magic.hex().upper(),
                    'description': description
                })
        
        metadata = {
            'filename': os.path.basename(input_file),
            'size': file_size,
            'size_formatted': format_size(file_size),
            'sha256': sha256_hash.hexdigest(),
            'header_hex': header[:32].hex().upper() if len(header) >= 32 else header.hex().upper(),
            'header_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[:32]),
            'detected_patterns': detected_magics,
            'generated': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(output_file, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        
        print(f"[+] JSON metadata saved to: {output_file}")
        return True
    
    except Exception as e:
        print(f"[!] JSON conversion failed: {e}")
        return False


def _convert_to_disasm(input_file: str, file_size: int) -> bool:
    """Convert to disassembly format"""
    output_file = os.path.splitext(input_file)[0] + '.asm'
    
    try:
        import capstone
    except ImportError:
        print("[!] Capstone library required for disassembly")
        print("[*] Install: pip install capstone")
        return False
    
    try:
        with open(input_file, 'rb') as fin, open(output_file, 'w') as fout:
            fout.write(f"; Disassembly of {input_file}\n")
            fout.write(f"; Size: {file_size} bytes\n")
            fout.write(f"; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Try ARM and x86 disassembly
            for arch_name, arch_const in [('ARM', capstone.CS_ARCH_ARM), 
                                           ('ARM64', capstone.CS_ARCH_ARM64),
                                           ('x86', capstone.CS_ARCH_X86)]:
                try:
                    md = capstone.Cs(arch_const, capstone.CS_MODE_ARM if 'ARM' in arch_name 
                                    else capstone.CS_MODE_32 if arch_name == 'x86'
                                    else capstone.CS_MODE_64)
                    md.detail = True
                    
                    fout.write(f"\n; === {arch_name} Disassembly ===\n\n")
                    
                    fin.seek(0)
                    chunk_size = 64 * 1024
                    offset = 0
                    
                    while offset < min(file_size, 1024 * 1024):  # Cap at 1MB
                        code = fin.read(chunk_size)
                        if not code:
                            break
                        
                        for insn in md.disasm(code, offset):
                            fout.write(f"0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}\n")
                        
                        offset += len(code)
                
                except Exception as e:
                    fout.write(f"; {arch_name} disassembly failed: {e}\n")
        
        print(f"[+] Disassembly saved to: {output_file}")
        return True
    
    except Exception as e:
        print(f"[!] Disassembly conversion failed: {e}")
        return False


# =============================================================================
# FIXED: Verification function
# =============================================================================
def verify_read_result(output_file: str, expected_bytes: int, 
                       start_offset: int = 0) -> bool:
    """
    Verify read operation integrity.
    
    Args:
        output_file: Path to output file
        expected_bytes: Total bytes that should have been read
        start_offset: Starting offset (for resume mode)
    
    Returns:
        bool: True if verification passed
    """
    if not os.path.exists(output_file):
        print("[!] Verification failed: Output file not found")
        return False
    
    try:
        actual_size = os.path.getsize(output_file)
    except OSError as e:
        print(f"[!] Cannot access output file: {e}")
        return False
    
    expected_on_disk = expected_bytes  # Total bytes read (including resumed)
    
    print(f"\n[*] Verification:")
    print(f"    Expected on disk: {format_size(expected_on_disk)}")
    print(f"    Actual on disk:   {format_size(actual_size)}")
    
    if actual_size != expected_on_disk:
        diff = abs(actual_size - expected_on_disk)
        print(f"[!] Size mismatch! Difference: {format_size(diff)}")
        
        if actual_size < expected_on_disk:
            print(f"    Missing: {format_size(expected_on_disk - actual_size)}")
        else:
            print(f"    Extra: {format_size(actual_size - expected_on_disk)}")
        return False
    
    print("[+] Size verification: PASS")
    
    # Calculate checksum (sampled for large files)
    try:
        with open(output_file, 'rb') as f:
            if actual_size <= 100 * 1024 * 1024:  # Full hash for files < 100MB
                file_hash = hashlib.sha256(f.read()).hexdigest()
                print(f"[+] SHA256: {file_hash}")
            else:
                # Sampled hash for large files
                sha256_hash = hashlib.sha256()
                sample_points = [0, actual_size // 4, actual_size // 2, 
                               3 * actual_size // 4, actual_size - 4096]
                
                for point in sample_points:
                    if point >= 0 and point < actual_size:
                        f.seek(point)
                        sample = f.read(4096)
                        sha256_hash.update(sample)
                
                sampled_hash = sha256_hash.hexdigest()
                print(f"[+] SHA256 (sampled): {sampled_hash}")
                print(f"[*] Note: Sampled hash used for large file (>100MB)")
    except Exception as e:
        print(f"[!] Checksum calculation failed: {e}")
    
    # Check for null data (potential uninitialized memory)
    try:
        with open(output_file, 'rb') as f:
            sample_size = min(16384, actual_size)  # Check up to 16KB
            
            # Read from beginning
            f.seek(0)
            sample_begin = f.read(sample_size // 2)
            
            # Read from middle
            f.seek(actual_size // 2)
            sample_mid = f.read(sample_size // 2)
            
            combined_sample = sample_begin + sample_mid
            
            if combined_sample:
                null_count = combined_sample.count(b'\x00')
                ff_count = combined_sample.count(b'\xFF')
                null_pct = (null_count / len(combined_sample)) * 100
                ff_pct = (ff_count / len(combined_sample)) * 100
                
                if null_pct > 95:
                    print(f"[!] WARNING: Very high null content ({null_pct:.1f}%)")
                    print(f"[!] Data may be uninitialized or erased memory")
                elif null_pct > 70:
                    print(f"[!] High null content ({null_pct:.1f}%) - suspect data quality")
                elif null_pct < 5:
                    print(f"[+] Normal data density (null: {null_pct:.1f}%, 0xFF: {ff_pct:.1f}%)")
                else:
                    print(f"[*] Mixed content (null: {null_pct:.1f}%, 0xFF: {ff_pct:.1f}%)")
    except Exception as e:
        if _DEBUG:
            print(f"[!] Data quality check failed: {e}")
    
    return True


# =============================================================================
# FIXED: Summary function
# =============================================================================
def print_read_summary(address: int, bytes_read: int, requested_size: int,
                       output_file: str, partition_info: Optional[Dict] = None,
                       start_offset: int = 0) -> None:
    """Print comprehensive read operation summary."""
    
    print(f"\n{'='*60}")
    print(f"[+] READ Operation Complete")
    print(f"{'='*60}")
    
    # Source information
    print(f"\n[*] Source:")
    print(f"    Address: 0x{address:08X}")
    
    if partition_info:
        part_name = partition_info.get('name', 'unknown')
        part_offset = partition_info.get('offset', 0)
        print(f"    Partition: {part_name}")
        
        relative_offset = address - part_offset
        if relative_offset > 0:
            print(f"    Offset in partition: 0x{relative_offset:08X} ({format_size(relative_offset)})")
    
    # Transfer statistics
    print(f"\n[*] Transfer:")
    print(f"    Requested: {format_size(requested_size)} (0x{requested_size:08X})")
    print(f"    Read:      {format_size(bytes_read)} (0x{bytes_read:08X})")
    
    if bytes_read > 0:
        if bytes_read < requested_size:
            completion_pct = (bytes_read / requested_size) * 100
            print(f"    Completion: {completion_pct:.1f}%")
            print(f"    Remaining:  {format_size(requested_size - bytes_read)}")
        elif bytes_read > requested_size:
            print(f"    Read more than requested (+{format_size(bytes_read - requested_size)})")
        else:
            print(f"    Complete: 100%")
    
    if start_offset > 0:
        print(f"    Resumed from: {format_size(start_offset)}")
    
    # Output file information
    print(f"\n[*] Output:")
    print(f"    File: {output_file}")
    
    if os.path.exists(output_file):
        try:
            file_size = os.path.getsize(output_file)
            print(f"    Size: {format_size(file_size)}")
            
            # File type detection
            if file_size >= 8:
                with open(output_file, 'rb') as f:
                    magic = f.read(8)
                    print(f"    Magic: {magic.hex().upper()}")
                    
                    # Try to identify file type
                    for pattern, desc in KNOWN_PATTERNS.items():
                        if magic.startswith(pattern):
                            print(f"    Type: {desc}")
                            break
                    
                    # Show ASCII preview
                    ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in magic[:32])
                    print(f"    Preview: '{ascii_preview}'")
        except Exception as e:
            print(f"    Warning: Cannot read output file: {e}")
    else:
        print(f"    Warning: Output file not found!")
    
    print(f"\n{'='*60}")


# =============================================================================
# FIXED: Utility functions
# =============================================================================
def format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    if size_bytes < 0:
        return f"-{format_size(-size_bytes)}"
    
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.1f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"


def print_hex_dump(data: bytes, base_address: int = 0) -> None:
    """Print hex dump with ASCII representation."""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"    {base_address + i:08X}: {hex_str:<48} |{ascii_str}|")


# =============================================================================
# FIXED: Module entry point
# =============================================================================
if __name__ == "__main__":
    print("[*] read.py - QSLCL READ Command Module")
    print("[*] This module is designed to be imported by qslcl.py")
    print("[*] Usage: python qslcl.py read <target> [options]")