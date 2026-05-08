# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf**

Assistant Module: **qslcl.bin (v0.6.5)**

Universal Controller: **qslcl.py (v2.0.2)**

> **Legally Protected Research** - This project operates under established legal frameworks for security research, right to repair, and academic freedom. [Learn more](./PROTECTION_MATRIX.md)

---

# Overview

**Quantum Silicon Core Loader (QSLCL)** is a post-bootloader, post-vendor, post-exploit execution layer operating directly at the silicon boundary.

It executes beyond traditional security models and is capable of surviving firmware transitions, negotiating trust, and interpreting device state without CVEs or patches.

QSLCL runs in:

* **Qualcomm EDL / Firehose**
* **MediaTek BROM / Preloader**
* **Apple DFU** (Dynamic detection - no hardcoded PIDs)
* **Engineering / META / Diagnostic Modes**
* **Any USB/Serial exposed interface**

> **"You don't run QSLCL — silicon interprets it."**

---

# What's New in **v0.6.5 / v2.0.2** 🔐

## QSLCLENC - Future-Proof Encryption Layer

**Problem:** Apple may add USB encryption to DFU mode in A18+ and newer devices, breaking all existing tools.

**Solution:** Added QSLCLENC - a universal encryption layer that supports **ChaCha20-Poly1305** and **AES-256-GCM** ciphers.

### New Features:

| Feature | Description |
|---------|-------------|
| **Dynamic Cipher Negotiation** | Automatically selects best available cipher |
| **Perfect Forward Secrecy** | Session keys never reuse |
| **Anti-Replay Protection** | Nonce-based frame verification |
| **Zero Overwrite Injection** | Encrypts at EOF, preserves all existing blocks |
| **Micro-VM Crypto Routines** | Architecture-neutral encryption |

### Supported Encryption Algorithms:

```python
# QSLCLENC automatically supports:
✅ ChaCha20-Poly1305  (Apple's likely choice for A18+)
✅ AES-256-GCM        (Fallback for compatibility)
✅ Session Key Exchange (No hardcoded keys)
✅ HMAC Integrity Check (Prevents tampering)
```

### New Commands:

```bash
# Display encryption layer information
python qslcl.py encryption --loader=qslcl.bin

# Build with encryption support
python build.py qslcl.bin --encrypt
```

### New Block Type: QSLCLENC

```
QSLCL Binary Layout (v0.6.5):
┌─────────────────────────────────────────────┐
│ 0x00000000  QSLCLBIN (Main Header)          │
│ 0x00001000  QSLCLCMD (47 Commands)          │
│ 0x00002000  QSLCLEND (64 Endpoints)         │
│ 0x00003000  QSLCLBST (Bootstrap)            │
│ 0x00004000  QSLCLDISP (Dispatch)            │
│ 0x00005000  QSLCLRTF (Runtime Faults)       │
│ 0x00006000  QSLCLVM5 (Microservices)        │
│ 0x00007000  QSLCLHDR (Certificate)          │
│ 0x00008000  QSLCLRESP (Response Builder)    │
│ ★ 0x00009000  QSLCLENC (NEW - Encryption) ★ │
└─────────────────────────────────────────────┘
```

### Why This Matters for A18+:

| Without QSLCLENC | With QSLCLENC |
|-----------------|----------------|
| ❌ Device rejects plaintext USB | ✅ Frames encrypted before send |
| ❌ Tool fails silently | ✅ Auto-negotiates encryption |
| ❌ Requires complete rewrite | ✅ Minor update only |
| ❌ No forward compatibility | ✅ Future-proof by design |

---

# What's New in **v2.0.1** (Previous)

## 🔥 Dynamic DFU Detection (Major Improvement)

**Problem:** Previous versions used hardcoded Apple DFU PIDs (0x1227, 0x1226, 0x1222, 0x1281) which would fail on newer devices.

**Solution:** Implemented USB DFU Class Specification detection:

- **Universal DFU Detection** - Identifies ANY DFU mode device using USB class 0xFE (Application Specific) and subclass 0x01 (Device Firmware Upgrade)
- **Vendor-Agnostic** - Works with Apple, Google, Samsung, OnePlus, and any other DFU-capable device
- **Future-Proof** - No hardcoded PIDs needed; detects by USB standard compliance
- **Autonomous Fallback** - Gracefully handles devices that don't fully comply with DFU spec

**Technical Implementation:**
```python
def universal_dfu_detection(dev):
    # Detects DFU by:
    # 1. Interface Class 0xFE = Application Specific
    # 2. Interface Subclass 0x01 = Device Firmware Upgrade  
    # 3. Protocol 0x01/0x02 = Runtime/Download mode
```

**What this means for you:**
- ✅ iPhone 16, 17, 18+ work immediately (no code changes needed)
- ✅ iPad DFU modes auto-detected
- ✅ Generic Android DFU devices supported
- ✅ No more "device not recognized" errors for new hardware

---

# What's New in **v2.0.0**

## Massive Module Rewrite
Complete rewrite of all 20+ command modules with comprehensive fixes:

- **Fixed Import System** - Proper fallback chain: absolute → relative → standalone across all modules
- **Unified Command Dispatch** - Consistent `_dispatch()` with `_find_cmd()` helper for QSLCLCMD database lookup
- **Removed QSLCLPAR References** - All legacy references eliminated, consolidated to QSLCLCMD system
- **Standardized Handler Signatures** - All handlers follow consistent `(dev, args, force, ...) -> bool` pattern
- **Enhanced Safety System** - `_confirm()` with proper EOFError/KeyboardInterrupt handling across all modules
- **Color-Coded Output** - Consistent `Colors` class across all modules for terminal output
- **Progress Bar Fallbacks** - Local `ProgressBar` implementation when QSLCL version unavailable
- **Structured Dispatch Tables** - Dictionary-based handler dispatch with alias support in every module
- **Complete Error Recovery** - Retry logic, exponential backoff, and graceful fallbacks throughout

---

# Complete Command List

**Core Memory Operations:**
| Command | Description |
|---------|-------------|
| `read` | Advanced memory reading with resume support |
| `write` | Professional memory writing with protection checks |
| `erase` | Secure data erasure with multiple patterns |
| `peek` | Memory inspection with type detection |
| `poke` | Precision memory writing with bit operations |
| `patch` | Advanced binary patching with verification |
| `dump` | Memory dumping with compression and verification |

**System Commands:**
| Command | Description |
|---------|-------------|
| `hello` | Device handshake and identification |
| `ping` | Latency testing and connectivity |
| `getinfo` | Comprehensive device information |
| `partitions` | Partition table listing |
| `endpoints` | USB endpoint listing (supports DFU devices) |
| `encryption` | **NEW** - Display encryption layer information |
| `config` | Configuration management |
| `config-list` | List configuration capabilities |

**Advanced Operations:**
| Command | Description |
|---------|-------------|
| `rawmode` | Privilege escalation with session management |
| `reset` | System reset with multiple types |
| `bruteforce` | Multi-strategy system exploration |
| `bypass` | Security bypass with auto-detection |
| `glitch` | Hardware fault injection framework |
| `verify` | System integrity verification |

**Specialized Commands:**
| Command | Description |
|---------|-------------|
| `oem` | OEM bootloader unlock/lock functions |
| `odm` | ODM manufacturing and customization |
| `mode` | System mode management |
| `power` | Power domain and battery control |
| `voltage` | Voltage regulation and monitoring |
| `crash` | Controlled crash injection testing |
| `crash-test` | Automated crash test suites |
| `footer` | Footer analysis and validation |
| `rawstate` | Hardware state inspection |

---

# Installation & Quick Start

## Requirements

```bash
pip install pyserial pyusb
pip install pycryptodome   # optional, for crypto operations
pip install capstone        # optional, for disassembly
pip install requests tqdm   # optional
```

## Basic Usage

```bash
# Build with encryption support (NEW)
python build.py qslcl.bin --encrypt --debug

# Test basic functionality
python qslcl.py hello --loader=qslcl.bin
python qslcl.py getinfo --loader=qslcl.bin
python qslcl.py ping --loader=qslcl.bin

# List available commands and endpoints
python qslcl.py endpoints --loader=qslcl.bin
python qslcl.py encryption --loader=qslcl.bin  # NEW - show encryption layer
```

## Encryption Layer Usage (v0.6.5+)

```bash
# Build with encryption enabled
python build.py qslcl.bin --encrypt --debug

# Check encryption status
python qslcl.py encryption --loader=qslcl.bin

# Expected output:
# [*] Found QSLCLENC structured block at 0x8A00 (256 bytes)
# [*] QSLCLENC: Encryption layer v1.0
#     Capabilities: 0x0000001F
#       - ChaCha20-Poly1305: ✓
#       - AES-256-GCM: ✓
#     Integrity: ✓ Valid
```

## DFU Mode Detection (v2.0.1+)

```bash
# Automatic DFU detection - no manual PID configuration needed
python qslcl.py endpoints --debug

# Expected output for DFU devices:
# [*] DFU device detected: Apple Inc. (0x05AC:0xXXXX) - DFU Mode (Download)
# [*] USB Endpoints (1 total):
#      DFU Device    BIDIR     0x00       CTRL    64
```

## Professional Usage

```bash
# Complete memory operations
python qslcl.py read boot boot.img --loader=qslcl.bin
python qslcl.py write boot modified_boot.img --loader=qslcl.bin --verify
python qslcl.py dump system --size 100M --compress --verify --loader=qslcl.bin

# With encryption (auto-detected if QSLCLENC present)
python qslcl.py read 0x80000000 --size 1M -o dump.bin --loader=qslcl.bin

# Configuration management
python qslcl.py config get debug_level
python qslcl.py config set timeout 10000
python qslcl.py config backup my_config.json

# Security analysis
python qslcl.py bypass detect --loader=qslcl.bin
python qslcl.py verify security --verbose --loader=qslcl.bin
python qslcl.py footer --type SECURITY --validate --loader=qslcl.bin

# System control
python qslcl.py reset soft --loader=qslcl.bin
python qslcl.py power status --loader=qslcl.bin
python qslcl.py mode set DEBUG --loader=qslcl.bin
```

---

# Device Compatibility

| Vendor   | Mode             | Detection Method            | Encryption | Status |
|----------|------------------|-----------------------------|------------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | Optional   | ✅ Enhanced |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | Optional   | ✅ Enhanced |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | No         | ✅ v2.0.1 |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | **Required** | ⚠️ v0.6.5 ready |
| Google   | DFU              | Dynamic USB DFU Class       | Optional   | ✅ New |
| Samsung  | DFU              | Dynamic USB DFU Class       | Optional   | ✅ New |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | Optional   | ✅ Universal |
| Any      | Serial COM       | UART auto sync              | No         | ✅ Universal |

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.6.5 / v2.0.2** | 2026 | **QSLCLENC encryption layer** - ChaCha20/AES, future-proof for A18+ |
| v0.6.4 / v2.0.1 | 2026 | Dynamic DFU detection, QSLCLRESP fixes |
| v0.6.3 / v2.0.0 | 2026 | Complete module rewrite, 47 commands |
| v0.5.x / v1.x | 2025 | Legacy versions |

---

## CRITICAL WARNING

**QSLCL CAN PERMANENTLY BRICK (DESTROY) YOUR DEVICE IF USED INCORRECTLY.**

| Safety Level | Operations | Risk |
|-------------|-----------|------|
| ✅ **SAFE** | EDL mode, DFU mode, BROM mode, Serial boot modes | Minimal |
| ⚠️ **CAUTION** | Writing to user partitions, voltage changes | Moderate |
| ❌ **DANGEROUS** | Writing to iROM, BootROM, NOR flash boot sectors | High |
| 💀 **BRICK RISK** | Overwriting protected bootloaders (iBoot, SBL, U-Boot SPL) | Critical |

**YOU HAVE BEEN WARNED. THE AUTHOR IS NOT RESPONSIBLE FOR BRICKED DEVICES.**

---

## Encryption Layer Technical Details

### Architecture

```
Without QSLCLENC:
QSLCLCMD → USB → Device (plaintext, detectable)

With QSLCLENC:
QSLCLCMD → [ENCRYPT] → QSLCLENC → USB → Device → [DECRYPT] → Execute
           ↑                                    ↑
    Session key negotiated              ChaCha20 verified
    at startup                          Poly1305 MAC checked
```

### Supported Cipher Suites

| Cipher | Key Size | MAC | Hardware Acceleration |
|--------|----------|-----|----------------------|
| ChaCha20-Poly1305 | 256-bit | Poly1305 | ARMv8.2-A+ (Apple Silicon) |
| AES-256-GCM | 256-bit | GMAC | AES-NI / ARMv8 Crypto Extensions |

### Integrity Protection

- **CRC32** - Frame header integrity
- **HMAC-SHA256** - Session authentication  
- **Poly1305** - Per-packet authentication (ChaCha20 mode)
- **SHA256 Footer** - Full encryption block verification

---

## Legal & Ethical Framework

**Quantum Silicon Core Loader (QSLCL)** operates within established legal and ethical boundaries:

### Permitted Uses:
- **Device Owners**: Modifying hardware you legally own
- **Researchers**: Security analysis and academic study
- **Repair Technicians**: Right to Repair implementations
- **Students**: Learning hardware architecture and security
- **Developers**: Creating interoperable software and tools

### Encryption Layer Legal Note:
The QSLCLENC encryption layer is designed for **research and interoperability**, not to defeat lawful access. It uses standard, publicly documented algorithms (ChaCha20, AES-256-GCM) with no backdoors.

### Prohibited Uses:
- Unauthorized access to others' devices
- Circumventing security on non-owned hardware
- Malicious or destructive applications
- Violation of applicable laws and regulations

> **Use responsibly. With great power comes great responsibility.**

---

# Support & Troubleshooting

## Common Issues

**Parser Detection Problems:**
```bash
# If modules aren't detected, check binary structure
python qslcl.py hello --loader=qslcl.bin
```

**Encryption Layer Not Found:**
```bash
# Build with encryption enabled
python build.py qslcl.bin --encrypt --debug

# Verify encryption block
python qslcl.py encryption --loader=qslcl.bin
```

**DFU Device Not Detected (v2.0.1+ fixed):**
```bash
# Enable debug to see DFU detection
python qslcl.py endpoints --debug

# If still not detected, check:
# 1. Device is actually in DFU mode
# 2. USB cable supports data (MFI for Apple)
# 3. Run with sudo/administrator privileges
```

**Memory Operation Errors:**
```bash
# Use smaller chunk sizes for problematic devices
python qslcl.py read boot boot.img --chunk-size 32768 --loader=qslcl.bin

# For patching issues, resume interrupted operations
python qslcl.py dump 0x10000000 --size 1M --resume --loader=qslcl.bin
```

## Debug Information

```bash
# Enable debug output
python build.py --debug --encrypt
python qslcl.py hello --loader=qslcl.bin --debug

# Verbose output for complex operations
python qslcl.py rawmode list --verbose --loader=qslcl.bin

# Debug DFU detection specifically
python qslcl.py endpoints --debug 2>&1 | grep -i dfu

# Debug encryption layer
python qslcl.py encryption --loader=qslcl.bin --debug
```

---

# Module Architecture (v2.0.2)

All command modules follow a consistent architecture:

```
modules/
├── read.py          # Memory reading with resume/verify
├── write.py         # Memory writing with protection
├── erase.py         # Secure erasure patterns
├── peek.py          # Memory inspection
├── poke.py          # Precision writes
├── dump.py          # Bulk memory dumping
├── patch.py         # Binary patching
├── oem.py           # OEM operations
├── odm.py           # ODM operations
├── rawmode.py       # Privilege escalation
├── voltage.py       # Voltage control
├── verify.py        # System verification
├── reset.py         # System reset
├── rawstate.py      # Hardware state
├── power.py         # Power management
├── mode.py          # Mode management
├── glitch.py        # Fault injection
├── footer.py        # Footer analysis
├── crash.py         # Crash injection
├── config.py        # Configuration
├── bypass.py        # Security bypass
└── bruteforce.py    # Automated testing
```

Each module features:
- **Standardized imports** with proper fallback chains
- **Unified dispatch** via `_dispatch()` helper
- **Dictionary-based handlers** with alias support
- **Consistent error handling** with retry logic
- **Color-coded output** via shared `Colors` class
- **Progress tracking** with local fallback

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication — where every memory operation, every privilege escalation, every hardware interaction, every binary patch, and every bootstrap execution becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping and now, quantum-resistant encryption."**

## Key Philosophy

* **Universal Execution** - One binary, all architectures, 47 complete commands
* **Silicon Intimacy** - Direct hardware conversation with bit-level precision
* **Adaptive Intelligence** - Environment-aware behavior with safety enforcement
* **Professional Grade** - Enterprise-level memory operations with verification
* **Advanced Patching** - Professional binary modification with read-back verification
* **Modular Architecture** - Consistent, maintainable command modules
* **Ethical Empowerment** - Capability with responsibility and safety controls
* **Future-Proof Detection** - USB DFU Class compliance (v2.0.1)
* **Encryption Ready** - ChaCha20/AES for A18+ compatibility (v0.6.5)

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 3932406).