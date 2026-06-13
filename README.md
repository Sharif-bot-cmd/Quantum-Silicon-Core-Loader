# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf** (deprecated)

Assistant Module: **qslcl.bin (v0.7.3)**

Universal Controller: **qslcl.py (v2.2.0)**

> **Legally Protected Research** - This project operates under established legal frameworks for security research, right to repair, and academic freedom. [Learn more](./PROTECTION_MATRIX.md)

---

# Overview

**Quantum Silicon Core Loader (QSLCL)** is a post-bootloader, post-vendor, post-os execution layer operating directly at the silicon boundary.

It executes beyond traditional security models and is capable of surviving firmware transitions, negotiating trust, and interpreting device state without CVEs or patches.

QSLCL runs in:

* **Qualcomm EDL / Firehose**
* **MediaTek BROM / Preloader**
* **Apple DFU** (Dynamic detection - no hardcoded PIDs)
* **Engineering / META / Diagnostic Modes**
* **Any USB/Serial exposed interface**

> **"You don't run QSLCL — silicon interprets it."**

---

## What's New in **v0.7.3 / v2.2.0**

### New Features

| Feature | Description |
|---------|-------------|
| **`slowm8` command** | USB stress tester inspired by checkm8 but focused on timing attacks and fuzzing. Experimental - tests how devices handle slow/malformed packets |
| **`--jitter` flag** | Adds random timing variation during USB upload (simple, progressive, burst, or custom ranges) |
| **QSLCLSPT integration** | `slowm8` now uses the existing setup packet database for targeted stress testing |
| **Enhanced error recovery** | Better handling of USB timeouts and malformed responses |

### Improvements

- Removed unnecessary BRUTEFORCE command in qslcl.bin (handled by other modules)
- Revised bruteforce and bypass commands for accuracy
- Added jitter support to all commands that upload the loader
- Improved USB4 v2.0 detection on A18+ devices

```
QSLCL Binary Layout (v0.7.3):
┌─────────────────────────────────────────────┐
│ 0x000000  QSLCLBIN (Main Header + Ptrs)     │
│ 0x000200+ QSLCLCMD (28 Commands)            │
│ 0x004000+ QSLCLDIS (Dispatch Table)         │
│ 0x005000+ QSLCLUSB (USB Micro-Engine)       │
│ 0x006000+ QSLCLBLK (64 Endpoints)           │
│ 0x007000+ QSLCLBST (Bootstrap Engine)       │
│ 0x008000+ QSLCLVM5 (Nano-Kernel)            │
│ 0x009000+ QSLCLSPT (USB Setup Packets)      │
│ 0x00A000+ QSLCLRTF (Runtime Fault Table)    │
│ 0x00B000+ QSLCLENC (Encryption Layer)       │
│ 0x00C000+ QSLCLDAT (Data Protocol)          │
│ 0x00D000+ QSLCLSYN (Sync Block)             │
│ 0x00E000+ QSLCLHDR (Certificate)            │
│ 0x00F000+ QSLCLINT (Integrity Footer)       │
│ 0x010000+ USB4V2MC (USB4 v2.0 80Gbps)      │
└─────────────────────────────────────────────┘

Total Size: ~72KB (44% reduction from 128KB)
Commands: 28 (added TEST, FUZZ)
```

**How it works (automatic):**
```bash
# Build with quantum architecture (recommended)
python build.py qslcl.bin --arch quantum --encrypt --usb4-v2

# Or generic build
python build.py qslcl.bin

# Just run normally - watchdog disables automatically!
python qslcl.py hello --loader=qslcl.bin

# Expected output:
# [+] Loader uploaded.
# [*] Auto-disabling watchdog...
# [*] Detected SoC type: APPLE
# [*] Checking 10 candidate offsets...
# [*] Watchdog detected at 0x20E00000 = 0x00000001
# [+] Watchdog disabled at offset 0x20E00000
# [*] Exposing QSLCL in USB configuration...
```

---

# Complete Command List (v2.2.0)

**Core Memory Operations:**
| Command | Description |
|---------|-------------|
| `read` | Partitions reading |
| `write` | Partitions writing |
| `erase` | Secure erasure with multiple patterns (zero, FF, checker, random) |
| `peek` | Memory inspection with type interpretation and pointer analysis |
| `poke` | Precision memory writes with bit operations (AND/OR/XOR) |
| `patch` | Binary patching with backup, verification, and dry-run support |
| `dump` | Bulk memory dumping with compression, verification, and metadata |

**Device Interaction:**
| Command | Description |
|---------|-------------|
| `hello` | Device handshake and capability detection |
| `ping` | Round-trip latency testing |
| `getinfo` | Shows device, DFU mode, watchdog, loader features |

**System Control:**
| Command | Description |
|---------|-------------|
| `reset` | System reset (soft/hard/recovery/bootloader/EDL/factory) |
| `power` | Power management (status/on/off/cycle/sleep/wake) |
| `config` | Configuration management (get/set/list/backup/restore/reset) |

**Voltage & Hardware:**
| Command | Description |
|---------|-------------|
| `voltage` | Voltage read/set/monitor/scale with safety ranges |
| `rawstate` | Low-level hardware state inspection and manipulation |

**Security & Analysis:**
| Command | Description |
|---------|-------------|
| `rawmode` | Privilege escalation with session audit logging |
| `bypass` | Security bypass with auto-detection and enforcement analysis |
| `verify` | System verification (checksum/signature/integrity/security/hardware/firmware) |
| `footer` | Footer analysis with validation and security assessment |

**Diagnostic & Testing:**
| Command | Description |
|---------|-------------|
| `crash` | Controlled crash injection with recovery monitoring |
| `glitch` | Hardware fault injection with parameter scanning |
| `bruteforce` | Automated testing (scan/pattern/fuzz/dictionary/replay) |
| **`slowm8`** | **NEW** - USB stress tester with fuzzing and timing attacks |

**Manufacturing & ODM:**
| Command | Description |
|---------|-------------|
| `oem` | OEM operations (bootloader unlock/lock, warranty, secure boot, panic) |
| `odm` | ODM operations (provisioning, testing, calibration, customization) |

---

# Installation & Quick Start

## Requirements

```bash
pip install pyserial pyusb
pip install pycryptodome   # optional, for crypto operations
pip install capstone        # optional, for disassembly
```

## Basic Usage

```bash
# Build with quantum architecture (recommended)
python build.py qslcl.bin --arch quantum --usb4-v2 --encrypt --debug

# Or standard generic build
python build.py qslcl.bin

# Get detailed device information
python qslcl.py getinfo --loader=qslcl.bin

# Expected output:
# ==================================================
# QSLCL DEVICE INFORMATION
# ==================================================
# [DEVICE]
#   Transport: USB
#   VID:PID: 05AC:1281
#   Product: iPhone 15 Pro
#   USB Class: 0xFE (Application Specific)
# 
# [DFU MODE]
#   Status: ACTIVE
#   Generation: A12 or newer (ARM64e, PAC enabled)
# 
# [WATCHDOG]
#   Detected SoC: Apple A-series
#   Typical offset: 0x20E00000
# 
# [QSLCL LOADER]
#   Architecture: quantum
#   Binary size: 73728 bytes (72 KB)
#   Features: Encryption, USB4 v2.0 80Gbps
# ==================================================

# Auto-DFU boot + Loader + Hello (All-in-One)
python qslcl.py hello --loader=qslcl.bin --dfu-boot

# Just boot into DFU mode (like palera1n)
python qslcl.py --dfu-boot

# Test basic functionality
python qslcl.py hello --loader=qslcl.bin --usb4
python qslcl.py ping --loader=qslcl.bin
```

## Jitter Support (v2.2.0)

Add random timing variation during USB upload to avoid detection or test timing robustness:

```bash
# Simple random jitter (5-25ms)
python qslcl.py hello --loader=qslcl.bin --jitter simple

# Progressive jitter (slows down as upload progresses)
python qslcl.py hello --loader=qslcl.bin --jitter progressive

# Burst pattern (fast bursts with pauses)
python qslcl.py hello --loader=qslcl.bin --jitter burst

# Custom range (1ms to 50ms random)
python qslcl.py hello --loader=qslcl.bin --jitter 0.001-0.05

# Combine with other flags
python qslcl.py ping --loader=qslcl.bin --jitter progressive --debug
```

## SlowM8 USB Stress Tester (v2.2.0) - NEW

Experimental USB stress tester inspired by checkm8 but focused on timing attacks and fuzzing:

```bash
# Basic slowm8 test (30 seconds)
python qslcl.py slowm8 --loader=qslcl.bin

# With fuzzing (3 mutations per packet)
python qslcl.py slowm8 --loader=qslcl.bin --fuzz 3 --duration 60

# Corrupt specific packet fields
python qslcl.py slowm8 --loader=qslcl.bin --corrupt magic size flags

# Progressive slowdown (starts fast, gets slower)
python qslcl.py slowm8 --loader=qslcl.bin --progressive --duration 120

# Maximum stress (aggressive fuzzing)
python qslcl.py slowm8 --loader=qslcl.bin --fuzz 10 --corrupt magic crc size flags --duration 300

# Save results to JSON for analysis
python qslcl.py slowm8 --loader=qslcl.bin --output slowm8_results.json

# Expected output:
# ============================================================
# SLOWM8 STRESS TEST RESULTS
# ============================================================
# 
# [STATISTICS]
#   Packets sent:      1250
#   Successful:        1180
#   Failed:            70
#   Timeouts:          45
#   Success rate:      94.4%
# 
# [TIMING ANALYSIS]
#   Avg delay:         12.3ms
#   Avg response time: 8.7ms
# 
# [ANOMALIES DETECTED]
#   Slow response: fuzzed_GET_DESCRIPTOR took 156ms
#   Large response: corrupt_size_SET_ADDRESS returned 2048 bytes
```

## SlowM8 Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--min-delay` | Minimum delay between packets (ms) | 1.0 |
| `--max-delay` | Maximum delay between packets (ms) | 100.0 |
| `--duration` | Test duration in seconds | 30 |
| `--packets` | Number of packets (if duration not used) | 100 |
| `--burst-size` | Packets per burst (0=disable) | 10 |
| `--progressive` | Progressively slow down transmission | False |
| `--no-random` | Disable random delays (use fixed timing) | False |
| `--fuzz` | Number of fuzz mutations per packet | 0 |
| `--corrupt` | Corrupt specific fields (magic/crc/size/flags) | None |
| `--target-mode` | Target mode (auto/dfu/edl/brom) | auto |
| `--output` | Save results to JSON file | None |

## Quantum Architecture Build (v0.7.1+)

```bash
# Build with quantum optimizations
python build.py qslcl.bin --arch quantum --debug

# Expected output:
# [*] Building QSLCL v0.7.3 Command System
#     Architecture: quantum -> QUANTUM OPTIMIZED
# [*] Applying quantum architecture optimizations...
# [+] Quantum optimizations applied
#     Marker: QUANTUM at 0x...
#     Flags: 0x80000000
# [*] Quantum optimizations complete
# 
# [*] QSLCL Binary v0.7.3 Build Complete
#     Final Size: 73728 bytes (72.0 KB)
#     Commands: 28
```

## Automatic Watchdog Disabler (v2.1.4+)

The watchdog disabler runs **automatically** on every USB connection - no flags needed!

```bash
# Just run any command - watchdog disables automatically
python qslcl.py hello --loader=qslcl.bin

# Expected output (watchdog section):
# [+] Loader uploaded.
# [*] Auto-disabling watchdog...
# [*] Detected SoC type: APPLE
# [*] Checking 10 candidate offsets...
# [*] Watchdog detected at 0x20E00000 = 0x00000001
# [+] Watchdog disabled at offset 0x20E00000

# Supported SoCs (auto-detected by VID):
# - Apple (0x05AC): A series offsets
# - Qualcomm (0x05C6): EDL offsets
# - MediaTek (0x0E8D): BROM offsets
# - Samsung (0x04E8): Exynos offsets
# - Broadcom (0x14E4): BCM offsets
# - Rockchip (0x2207): RK offsets
# - Allwinner (0x1F3A): Sunxi offsets
# - NVIDIA (0x10DE): Tegra offsets
```

## Auto-DFU Boot Feature (v2.1.3+)

```bash
# Method 1: Standalone DFU boot (like palera1n)
python qslcl.py --dfu-boot

# Expected output:
# ============================================================
#          QSLCL DFU Boot Helper (like palera1n)
# ============================================================
# 
# [*] Scanning for iOS devices in normal mode...
# [+] Found 1 iOS device(s) in normal mode:
#     1. iPhone 15 Pro
#        UDID: 00008030-001A2D5E0A30803A
#        USB: Bus 1, Addr 5
# 
# [*] Selected: iPhone 15 Pro
# 
# [*] This will boot your device into DFU mode.
# [*] Your device screen will go BLACK (this is normal).
# 
# Continue? (y/N): y
# 
# ============================================================
#                    ENTER DFU MODE
# ============================================================
# 
# To enter DFU mode, follow these steps EXACTLY:
# 
#   1. Press and HOLD the POWER button for 3 seconds
#   2. While still holding POWER, also HOLD the VOLUME DOWN button
#   3. Keep holding BOTH buttons for exactly 10 seconds
#   4. RELEASE the POWER button but KEEP holding VOLUME DOWN
#   5. Wait 5-10 seconds - device should enter DFU mode
# 
# [+] Device entered DFU mode successfully!
# [+] Device now in DFU mode! (VID:PID=05AC:1281)

# Method 2: Combined with QSLCL commands
python qslcl.py hello --loader=qslcl.bin --dfu-boot

# Method 3: With custom DFU timeout (default 30 seconds)
python qslcl.py hello --loader=qslcl.bin --dfu-boot --dfu-timeout 45
```

## USB4 v2.0 80Gbps Usage (v0.6.7+)

```bash
# Build with USB4 v2.0 support
python build.py qslcl.bin --usb4-v2 --debug

# Run with USB4 v2.0 80Gbps mode
python qslcl.py hello --loader=qslcl.bin --usb4 --debug

# Expected output:
# [*] Loading: qslcl.bin
# [+] Loader uploaded.
# [*] Checking USB4 v2.0 80Gbps support...
# [+] USB4 v2.0 device detected:
#     Max Bandwidth: 80000 Mbps (80 Gbps)
#     Supported Tunnels: PCIe, DisplayPort, USB3
#     PAM Encoding: PAM4
#     Security: CMA + DPP enabled
# [*] USB4 v2.0 microcode present in loader
# [*] USB4 v2.0 80Gbps mode initialized
```

## USB Exposure Feature (v2.1.1+)

```bash
# Loader automatically exposes QSLCL in USB descriptors
python qslcl.py hello --loader=qslcl.bin

# Expected output:
# [*] Loading: qslcl.bin
# [+] Loader uploaded.
# [*] Exposing QSLCL in USB configuration...
# [+] QSLCL identified in USB:
#     Product: QSLCL Loader 
#     Serial: QSLCL-05AC-1281-67A3F2C8
#     Protocol: 0x51 ('Q')
#     Vendor Magic: 0x51534C43

# Verify exposure with system tools
$ lsusb -v -d 05AC:1281 | grep -E "(iProduct|iSerial)"
  iProduct                2 QSLCL Loader v2.2.0
  iSerial                 3 QSLCL-05AC-1281-67A3F2C8
```

## Encryption Layer Usage (v0.6.5+)

```bash
# Build with encryption enabled
python build.py qslcl.bin --encrypt --debug

# Check encryption status (shown automatically on load)
python qslcl.py hello --loader=qslcl.bin

# Expected output:
# [*] QSLCL Loader Modules Detected:
#   ├─ QSLCLBIN: quantum arch, 73728 bytes (72KB)
#   ├─ QSLCLCMD: 28 commands
#   ├─ QSLCLEND: 64 endpoints
#   ├─ QSLCLENC: v1.0
#   │   ChaCha20=✓, AES-GCM=✓
#   ├─ QSLCLDAT: Data protocol v1.0
#   ├─ QSLCLSYN: Sync block, 4 frame types
#   ├─ USB4V2MC: USB4 v2.0 80Gbps microcode
#   │   Version: 2.0
#   │   Max Bandwidth: 80000 Mbps (80 Gbps)
#   │   Tunnels: PCIe, DP, USB3
#   │   Security: CMA + DPP + Attestation
#   └─ QSLCLHDR: 1 certificate blocks
```

---

# Device Compatibility

| Vendor   | Mode             | Detection Method            | USB Exposure | USB4 v2.0 | Auto-DFU | Watchdog | Encryption | Jitter | slowm8 | Status |
|----------|------------------|-----------------------------|--------------|-----------|----------|----------|------------|--------|--------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | ✅ Auto      | ⚠️ 40Gbps | ✅ Auto  | ✅ Auto  | No         | ✅     | ✅     | ✅ |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | ✅ Auto  | ✅ Auto  | **Required** | ✅  | ✅     | ✅ |
| Apple    | Normal Mode iOS  | USB Class + Product String  | N/A         | N/A      | ✅ Auto  | N/A     | N/A        | N/A    | N/A    | ✅ |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| Samsung  | EUB              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| Broadcom | BCM Boot         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| Rockchip | Mask ROM         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅     | ✅     | ✅ |
| Intel    | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅     | ✅     | ✅ |
| AMD      | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅     | ✅     | ✅ |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ⚠️ Limited  | ❌ No     | N/A      | ⚠️ Limited| Optional | ✅   | ⚠️    | ✅ |
| Any      | Serial COM       | UART auto sync              | N/A         | N/A      | N/A      | N/A     | No         | N/A    | N/A    | ✅ |

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.7.3 / v2.2.0** | 2026 | **`slowm8` command** - USB stress tester with fuzzing, **`--jitter` flag** - timing randomization, QSLCLSPT integration |
| **v0.7.2 / v2.1.9** | 2026 | **TEST & FUZZ commands** - Diagnostic self-test and fuzzing engine, **Enhanced getinfo** - Device info, DFU detection, watchdog status |
| **v0.7.1 / v2.1.8** | 2026 | **Quantum Architecture** - `--arch quantum`, opcode randomization, SHA512 signatures, 72KB binary |
| **v0.7.0 / v2.1.7** | 2026 | **oem panic** - Emergency recovery subcommand |
| v0.6.9 / v2.1.6 | 2026 | Command removal - Removed `mode` command, 26 total commands |
| v0.6.8 / v2.1.5 | 2026 | Size optimization - 128KB → 80KB, 37.5% smaller |
| v0.6.7 / v2.1.4 | 2026 | Auto-DFU Boot - Like palera1n, one-click DFU entry |
| v0.6.7 / v2.1.3 | 2026 | USB4 v2.0 80Gbps - PAM4 encoding, 4-lane aggregation |
| v0.6.6 / v2.1.2 | 2026 | USB QSLCL Exposure - Auto-identifies in USB descriptors |
| v0.6.6 / v2.1.1 | 2026 | Code cleanup - 40% reduction, QSLCLDATA/SYNC blocks |
| v0.6.5 / v2.1.0 | 2026 | QSLCLENC encryption layer - ChaCha20/AES for A18+ |
| v0.6.4 / v2.0.2 | 2026 | Dynamic DFU detection, QSLCLRESP fixes |
| v0.6.3 / v2.0.1 | 2026 | Complete module rewrite |
| v0.5.x / v1.x | 2025 | Legacy versions |

---

## Automatic Watchdog Disabler Technical Details (v2.1.4+)

### Supported Watchdog Offsets by SoC

| SoC Family | Watchdog Offsets |
|------------|------------------|
| Apple (A series) | 0x20E00000, 0x20E01000, 0x20E02000+ |
| Qualcomm | 0x02000000, 0x02000004, 0x02000008, 0x0200000C, 0x02000010 |
| MediaTek | 0x10000000, 0x10000004, 0x10000008, 0x1C000000+ |
| Samsung Exynos | 0x10060000, 0x10060004, 0x10060008, 0x10070000+ |
| Broadcom | 0x18000000, 0x18000004, 0x18000008, 0x18001000+ |
| Rockchip | 0x20000000, 0x20000004, 0x20004000+ |
| Allwinner | 0x01C20000, 0x01C20004, 0x01C20CA0+ |
| NVIDIA Tegra | 0x60005000, 0x60005004, 0x60005100+ |

### Disable Methods

| Method | Description |
|--------|-------------|
| Write Zero | Write 0x00000000 to watchdog register |
| Write Ones | Write 0xFFFFFFFF to watchdog register |
| Write Magic | Write 0xDEADBEEF to watchdog register |
| Write Sequence | Write multiple values in sequence |
| Bit Clear | Read, clear specific bit, write back |
| Bit Set | Read, set specific bit, write back |

---

## Jitter Technical Details (v2.2.0)

| Mode | Behavior | Use Case |
|------|----------|----------|
| `simple` | Random delay between 5-25ms | Basic timing variation |
| `progressive` | Delay increases with upload progress | Testing timeout handling |
| `burst` | Fast bursts (3-8 packets) then pause | Stress testing buffer handling |
| `min-max` | Custom range (e.g., `0.001-0.05`) | Fine-tuned control |

---

## SlowM8 Technical Details (v2.2.0)

| Feature | Description |
|---------|-------------|
| **Packet fuzzing** | Randomly mutates USB setup packets (bit flips, byte corruption) |
| **Field corruption** | Specifically targets magic bytes, CRC, size, flags |
| **Timing attacks** | Variable delays, burst patterns, progressive slowdown |
| **QSLCLSPT integration** | Uses your existing setup packet database |
| **JSON output** | Saves detailed results for analysis |
| **Anomaly detection** | Flags slow responses, large replies, timeouts |

---

## Size Optimization Details (v0.7.3)

| Metric | v0.6.8 | v0.7.3 | Reduction |
|--------|--------|--------|-----------|
| Binary size | 81,920 bytes | **73,728 bytes** | **10% smaller** |
| Total from 128KB | 37.5% | **44%** | **Even leaner** |
| Upload time | ~0.3s | ~0.27s | **10% faster** |
| RAM usage | 80KB | **72KB** | **8KB saved** |
| Commands | 26 | **28** | **+2 new commands** |

---

## Important: RAM-Only Execution (A12+)

On Apple A12+ devices, QSLCL executes entirely from RAM. **No modifications are permanent.**

After reboot:
- Device returns to stock condition
- All bypasses/resets/rawmode states are cleared
- No persistent changes to flash

**Commands like `bypass`, `rawmode`, `crash`, `glitch`, `test`, `fuzz`, `slowm8` are TEMPORARY on A12+.**

This is intentional:
- Safe for research and testing
- No permanent brick risk
- Works within Apple's security model

For non-Apple devices (Qualcomm EDL, MediaTek BROM, etc.), behavior varies by bootloader. Some may allow flash writes.

---

## CRITICAL WARNING

**QSLCL CAN PERMANENTLY BRICK (DESTROY) YOUR DEVICE IF USED INCORRECTLY.**

| Safety Level | Operations | Risk |
|-------------|-----------|------|
| **SAFE** | EDL mode, DFU mode, BROM mode, Serial boot modes, TEST, FUZZ, slowm8 | Minimal |
| **CAUTION** | Writing to user partitions, voltage changes | Moderate |
| **DANGEROUS** | Writing to iROM, BootROM, NOR flash boot sectors | High |
| **BRICK RISK** | Overwriting protected bootloaders (iBoot, SBL, U-Boot SPL) | Critical |

**YOU HAVE BEEN WARNED. THE AUTHOR IS NOT RESPONSIBLE FOR BRICKED DEVICES.**

---

## Legal & Ethical Framework

**Quantum Silicon Core Loader (QSLCL)** operates within established legal and ethical boundaries:

### Permitted Uses:
- **Device Owners**: Modifying hardware you legally own
- **Researchers**: Security analysis and academic study
- **Repair Technicians**: Right to Repair implementations
- **Students**: Learning hardware architecture and security
- **Developers**: Creating interoperable software and tools

### Auto-DFU Legal Note:
The DFU boot feature uses **standard USB DFU Class Specification** (0xFE/0x01) and standard iOS recovery mode triggers. It provides button instructions to the user and requires explicit consent.

### Watchdog Disabler Legal Note:
The watchdog disabler modifies hardware registers on **your own device** to prevent automatic resets during debugging and analysis. This is standard practice in embedded systems development.

### SlowM8 Legal Note:
The `slowm8` stress tester sends standard USB setup packets (some malformed) to **your own device** for research purposes. This is no different from standard USB compliance testing.

### Prohibited Uses:
- Unauthorized access to others' devices
- Circumventing security on non-owned hardware
- Malicious or destructive applications
- Violation of applicable laws and regulations

> **Use responsibly. With great power comes great responsibility.**

---

# Support & Troubleshooting

## Common Issues

**Watchdog Not Disabling:**
```bash
python qslcl.py hello --loader=qslcl.bin --debug
```

**getinfo shows no loader:**
```bash
python qslcl.py getinfo --loader=qslcl.bin
```

**Encryption Layer Not Found:**
```bash
python build.py qslcl.bin --encrypt --debug
```

**USB4 v2.0 Not Detected:**
```bash
python qslcl.py slowm8 --debug
python build.py qslcl.bin --usb4-v2 --debug
```

**slowm8 not working:**
```bash
# Make sure slowm8.py is in the same directory
ls slowm8.py

# Run with debug
python qslcl.py slowm8 --loader=qslcl.bin --debug

# Check QSLCLSPT availability
python qslcl.py getinfo --loader=qslcl.bin | grep -i "setup"
```

**Memory Operation Errors:**
```bash
python qslcl.py read boot boot.img --chunk-size 32768 --loader=qslcl.bin
```

**Jitter not applying:**
```bash
# Jitter only works with --loader flag
python qslcl.py hello --loader=qslcl.bin --jitter simple --debug
```

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication where every memory operation, every privilege escalation, every hardware interaction, every binary patch, every bootstrap execution, every USB4 v2.0 80Gbps tunnel, every PAM4-encoded transaction, every one-click DFU boot, every automatic watchdog disabler, every quantum-optimized byte, every diagnostic test, every fuzzing iteration, every USB stress test with slowm8, every jitter-timed upload, every malformed packet, every timing attack, and now a lean 72KB binary with 28 commands becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping, quantum-resistant encryption, structured data protocols, automatic USB self-identification, USB4 v2.0 80Gbps support, palera1n-like DFU automation, zero-configuration watchdog bypass, enhanced device information, the new quantum architecture for advanced entropy and opcode randomization, and now experimental USB stress testing with slowm8."**

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 4468461).

## Mirrors

- GitHub: https://github.com/Sharif-bot-cmd/Quantum-Silicon-Core-Loader
- Codeberg: https://codeberg.org/Sharif_Muhaymin/Quantum-Silicon-Core-Loader
