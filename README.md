# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf** (deprecated)

Assistant Module: **qslcl.bin (v0.7.4)**

Universal Controller: **qslcl.py (v2.2.1)**

> **Legally Protected Research** - This project operates under established legal frameworks for security research, right to repair, and academic freedom. [Learn more](./PROTECTION_MATRIX.md)

---

# Overview

**Quantum Silicon Core Loader (QSLCL)** is a post-bootloader, post-vendor, post-os layer operating directly at the silicon boundary.

It executes beyond traditional security models and is capable of surviving firmware transitions, negotiating trust, and interpreting device state without CVEs or patches.

QSLCL runs in:

* **Qualcomm EDL / Firehose**
* **MediaTek BROM / Preloader**
* **Apple DFU** (Dynamic detection - no hardcoded PIDs)
* **Engineering / META / Diagnostic Modes**
* **Any USB/Serial exposed interface**

> **"You don't run QSLCL — silicon interprets it."**

---

## What's New in **v0.7.4 / v2.2.1**

### QSLCLRESP Improvements (v0.7.4)
- Enhanced response frame parsing with better error handling
- Improved CRC validation for response frames
- Added support for extended status codes
- Faster response times in high-load scenarios

### Slowm8 Improvements (v2.2.1)
- **Auto-detection:** No more hardcoded PIDs - works on ANY device
- **Adaptive timing:** Automatically adjusts delays based on device response
- **A19+ support:** Detects encryption and adapts timing accordingly
- **Bug confirmation:** Automatically injects test code when bugs are found
- **Custom injection payloads:** Different payloads for different bug types
- **JSON output:** Save detailed results for analysis

```
QSLCL Binary Layout (v0.7.4):
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

# Complete Command List (v2.2.1)

**Core Memory Operations:**
| Command | Description |
|---------|-------------|
| `read` | Memory reading with resume support, verification, hex/json/disasm output |
| `write` | Memory writing with protection checks, pattern fill, verification |
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
| `slowm8` | **NEW** - USB stress tester with auto-detection and bug injection |

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

## Slowm8 - USB Stress Tester (v2.2.1)

**New and improved!** Slowm8 now auto-detects devices and adapts timing automatically:

```bash
# Basic stress test - auto-detects everything
python qslcl.py slowm8 --loader=qslcl.bin

# With fuzzing (3 mutations per packet)
python qslcl.py slowm8 --loader=qslcl.bin --fuzz 3 --duration 60

# Corrupt specific packet fields
python qslcl.py slowm8 --loader=qslcl.bin --corrupt magic size flags

# Progressive slowdown (starts fast, gets slower)
python qslcl.py slowm8 --loader=qslcl.bin --progressive --duration 120

# Disable auto-injection (just detect bugs, don't inject)
python qslcl.py slowm8 --loader=qslcl.bin --no-injection

# Custom bug threshold (inject after 5 anomalies)
python qslcl.py slowm8 --loader=qslcl.bin --bug-threshold 5

# Save results to JSON
python qslcl.py slowm8 --loader=qslcl.bin --output slowm8_results.json

# Maximum stress (aggressive fuzzing + injection)
python qslcl.py slowm8 --loader=qslcl.bin --fuzz 10 --duration 300 --corrupt magic crc size flags

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
# [BUGS]
#   Bugs detected:     3
#   Bugs confirmed:    2
#   Injection attempts:1
#   Injection success: 1
# 
# [CONFIRMED BUGS]
#   1. memory_corruption (conf: 80%)
#       Unexpected large response: 2048 bytes
#   2. memory_corruption (conf: 75%)
#       Unexpected large response: 4096 bytes
# 
# [INJECTION]
#   Success rate:      100.0%
#   Payload size:      up to 512 bytes
```

### Slowm8 Auto-Detection Features

| Feature | What It Does |
|---------|--------------|
| **Device mode detection** | Auto-detects DFU, EDL, BROM, or standard USB |
| **Timing auto-calibration** | Measures device response time and adjusts delays |
| **A19+ encryption detection** | Detects encrypted DFU and adapts timing |
| **Bug threshold** | Injects test code after N anomalies (default: 3) |
| **Custom injection payloads** | Different payloads for different bug types |
| **JSON output** | Save detailed results for analysis |

### Slowm8 Options

| Option | Description | Default |
|--------|-------------|---------|
| `--min-delay` | Minimum delay between packets (ms) | Auto-detected |
| `--max-delay` | Maximum delay between packets (ms) | Auto-detected |
| `--duration` | Test duration in seconds | 30 |
| `--packets` | Number of packets to send | 100 |
| `--burst-size` | Packets per burst (0=disable) | 10 |
| `--progressive` | Progressively slow down | False |
| `--no-random` | Disable random delays | False |
| `--fuzz` | Number of fuzz mutations per packet | 0 |
| `--corrupt` | Corrupt specific fields | None |
| `--no-injection` | Disable automatic code injection | False |
| `--injection-size` | Max injection payload size | 512 |
| `--bug-threshold` | Bugs before injection | 3 |
| `--output` | Save results to JSON | None |

---

## Jitter Support (v2.1.9+)

Add random timing variation during USB upload:

```bash
# Simple random jitter (5-25ms)
python qslcl.py hello --loader=qslcl.bin --jitter simple

# Progressive jitter (slows down as upload progresses)
python qslcl.py hello --loader=qslcl.bin --jitter progressive

# Burst pattern (fast bursts with pauses)
python qslcl.py hello --loader=qslcl.bin --jitter burst

# Custom range (1ms to 50ms random)
python qslcl.py hello --loader=qslcl.bin --jitter 0.001-0.05
```

---

# Device Compatibility

| Vendor   | Mode             | Detection Method            | USB Exposure | USB4 v2.0 | Auto-DFU | Watchdog | Encryption | Slowm8 | Status |
|----------|------------------|-----------------------------|--------------|-----------|----------|----------|------------|--------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | ✅ Auto      | ⚠️ 40Gbps | ✅ Auto  | ✅ Auto  | No         | ✅     | ✅ |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | ✅ Auto  | ✅ Auto  | **Required** | ✅  | ✅ |
| Apple    | Normal Mode iOS  | USB Class + Product String  | N/A         | N/A      | ✅ Auto  | N/A     | N/A        | N/A    | ✅ |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| Samsung  | EUB              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| Broadcom | BCM Boot         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| Rockchip | Mask ROM         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅     | ✅ |
| Intel    | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅     | ✅ |
| AMD      | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅     | ✅ |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ⚠️ Limited  | ❌ No     | N/A      | ⚠️ Limited| Optional | ✅   | ✅ |
| Any      | Serial COM       | UART auto sync              | N/A         | N/A      | N/A      | N/A     | No         | N/A    | ✅ |

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.7.4 / v2.2.1** | 2026 | **QSLCLRESP improvements** - Better error handling, faster responses, extended status codes. **Slowm8 auto-detection** - No PIDs, adaptive timing, A19+ support, bug confirmation with code injection, JSON output |
| **v0.7.3 / v2.2.0** | 2026 | **`slowm8` command** - USB stress tester with fuzzing, **`--jitter` flag** - timing randomization |
| **v0.7.2 / v2.1.9** | 2026 | **TEST & FUZZ commands** - Diagnostic self-test and fuzzing engine, **Enhanced getinfo** |
| **v0.7.1 / v2.1.8** | 2026 | **Quantum Architecture** - `--arch quantum`, opcode randomization, 72KB binary |
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

## Slowm8 Technical Details (v2.2.1)

### Auto-Detection Flow

```
1. Device connected
   ↓
2. Auto-detect mode (DFU/EDL/BROM/USB)
   ↓
3. Measure response time
   ↓
4. Detect encryption (A19+)
   ↓
5. Auto-adjust timing (min/max delays)
   ↓
6. Run stress test
   ↓
7. Detect anomalies
   ↓
8. Analyze for bugs (confidence scoring)
   ↓
9. If threshold reached → Inject test code
   ↓
10. Confirm bug and report
```

### Bug Types Detected

| Bug Type | Detection Method | Injection Payload |
|----------|------------------|-------------------|
| Memory corruption | Unexpected large response | Read/write/verify test |
| Crash | Device reset detected | Crash test + recovery |
| Timeout vulnerability | Repeated timeouts | Timeout test + ping |
| Timing anomaly | Slow responses | Timing sensitivity test |
| Parsing bug | Malformed response | Nested structure test |

---

## Important: RAM-Only Execution (A12+)

On Apple A12+ devices, QSLCL executes entirely from RAM. **No modifications are permanent.**

After reboot:
- Device returns to stock condition
- All bypasses/resets/rawmode states are cleared
- No persistent changes to flash

**Commands like `bypass`, `rawmode`, `crash`, `glitch`, `test`, `fuzz`, `slowm8` are TEMPORARY on A12+.**

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

### Prohibited Uses:
- Unauthorized access to others' devices
- Circumventing security on non-owned hardware
- Malicious or destructive applications
- Violation of applicable laws and regulations

> **Use responsibly. With great power comes great responsibility.**

---

# Support & Troubleshooting

## Common Issues

**Slowm8 not detecting device:**
```bash
# Make sure device is in DFU/EDL/BROM mode
python qslcl.py getinfo --loader=qslcl.bin

# Run with debug
python qslcl.py slowm8 --loader=qslcl.bin --debug
```

**Bug injection not working:**
```bash
# Increase timeout
python qslcl.py slowm8 --loader=qslcl.bin --duration 60 --debug

# Disable injection to see if bugs are detected
python qslcl.py slowm8 --loader=qslcl.bin --no-injection --debug
```

**QSLCLRESP errors:**
```bash
# Rebuild with latest
python build.py qslcl.bin --arch quantum --debug

# Check response parsing
python qslcl.py hello --loader=qslcl.bin --debug
```

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication where every memory operation, every privilege escalation, every hardware interaction, every binary patch, every bootstrap execution, every USB4 v2.0 80Gbps tunnel, every PAM4-encoded transaction, every one-click DFU boot, every automatic watchdog disabler, every quantum-optimized byte, every diagnostic test, every fuzzing iteration, every USB stress test with slowm8, every jitter-timed upload, every malformed packet, every timing attack, every auto-detected device, every adaptive delay, every bug confirmation with code injection, and now a lean 72KB binary with 28 commands becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping, quantum-resistant encryption, structured data protocols, automatic USB self-identification, USB4 v2.0 80Gbps support, palera1n-like DFU automation, zero-configuration watchdog bypass, enhanced device information, the new quantum architecture for advanced entropy and opcode randomization, and now experimental USB stress testing with slowm8 that auto-detects and confirms bugs on ANY SoC."**

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Mirrors

- GitHub: https://github.com/Sharif-bot-cmd/Quantum-Silicon-Core-Loader
- Codeberg: https://codeberg.org/Sharif_Muhaymin/Quantum-Silicon-Core-Loader