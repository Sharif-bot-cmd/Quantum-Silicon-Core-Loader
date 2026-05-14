# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf**

Assistant Module: **qslcl.bin (v0.6.6)**

Universal Controller: **qslcl.py (v2.1.1)**

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

### What's New in **v2.1.1**

- **Automatic USB QSLCL Exposure** - Device identifies as "QSLCL Loader" in USB descriptors (like MediaTek DA)
- **Multi-Method USB Identification** - 6 fallback methods to ensure QSLCL appears in `lsusb`
- **Auto-Verification** - Confirms exposure and displays product/serial strings
- **Vendor Magic Registration** - QSLCL USB magic (0x51534C43) exposed via control transfer
- **Protocol Identifier** - bInterfaceProtocol set to 0x51 ('Q') for instant recognition

### What's New in **v2.1.0** (Previous)

- **Complete Code Cleanup** - Removed ~40% redundant code across all modules
- **Standardized Architecture** - Every module follows identical patterns
- **Direct QSLCLCMD Integration** - All modules use `QSLCLCMD_DB` for command dispatch
- **Unified Progress Bar** - Single `ProgressBar` class across all operations
- **Simplified Safety System** - Consistent `confirm()` function with force override
- **Removed ANSI Colors** - Clean output compatible with all terminals
- **Streamlined Imports** - Single `try/except` import chain per module

### What's New in **qslcl.bin v0.6.6**

- **QSLCLDATA Protocol** - Chunked data transfer with ACK/sequence handling
- **QSLCLSYNC Block** - Transport framing and synchronization
- **QSLCLDAT Block** - Data transfer protocol micro-VM handler
- **Improved Pointer Tables** - All block offsets properly cross-referenced
- **Integrity Footer** - CRC32 + SHA512 + HMAC signature at end of binary
- **26 Commands** (cleaned from 34) - Only commands with actual module support

```
QSLCL Binary Layout (v0.6.6):
┌─────────────────────────────────────────────┐
│ 0x000000  QSLCLBIN (Main Header + Ptrs)     │
│ 0x000200+ QSLCLCMD (26 Commands)            │
│ 0x004000+ QSLCLDIS (Dispatch Table)         │
│ 0x005000+ QSLCLUSB (USB Micro-Engine)       │
│ 0x006000+ QSLCLBLK (64 Endpoints)           │
│ 0x007000+ QSLCLBST (Bootstrap Engine)       │
│ 0x008000+ QSLCLVM5 (Nano-Kernel)            │
│ 0x009000+ QSLCLSPT (USB Setup Packets)      │
│ 0x00A000+ QSLCLRTF (Runtime Fault Table)    │
│ 0x00B000+ QSLCLENC (Encryption Layer)       │
│ 0x00C000+ QSLCLDAT (Data Protocol) ★ NEW    │
│ 0x00D000+ QSLCLSYN (Sync Block) ★ NEW       │
│ 0x00E000+ QSLCLHDR (Certificate)            │
│ 0x00F000+ QSLCLINT (Integrity Footer) ★ NEW │
└─────────────────────────────────────────────┘
```

### USB QSLCL Exposure (v2.1.1):

When QSLCL loads, the device automatically identifies itself in USB descriptors:

| Without Exposure | With Exposure (v2.1.1) |
|-----------------|------------------------|
| ❌ Generic "DFU Device" | ✅ "QSLCL Loader v2.1.0" |
| ❌ Random serial number | ✅ "QSLCL-VID-PID-TIMESTAMP" |
| ❌ No protocol identifier | ✅ bInterfaceProtocol = 0x51 ('Q') |
| ❌ Undetectable by scanners | ✅ Visible to `lsusb` and analyzers |

**Detection by other tools:**
```bash
$ lsusb -v -d 05AC:1281 | grep -E "(iProduct|iSerial|bInterfaceProtocol)"
  iProduct                2 QSLCL Loader v2.1.0
  iSerial                 3 QSLCL-05AC-1281-67A3F2C8
  bInterfaceProtocol     81    <-- 0x51 = 'Q'
```

### Encryption Layer (v0.6.5+):

| Without QSLCLENC | With QSLCLENC |
|-----------------|----------------|
| ❌ Device rejects plaintext USB | ✅ Frames encrypted before send |
| ❌ Tool fails silently | ✅ Auto-negotiates encryption |
| ❌ Requires complete rewrite | ✅ Minor update only |
| ❌ No forward compatibility | ✅ Future-proof by design |

---

# What's New in **v2.0.1** (Legacy)

## 🔥 Dynamic DFU Detection (Major Improvement)

**Problem:** Previous versions used hardcoded Apple DFU PIDs (0x1227, 0x1226, 0x1222, 0x1281) which would fail on newer devices.

**Solution:** Implemented USB DFU Class Specification detection:

- **Universal DFU Detection** - Identifies ANY DFU mode device using USB class 0xFE (Application Specific) and subclass 0x01 (Device Firmware Upgrade)
- **Vendor-Agnostic** - Works with Apple, Google, Samsung, OnePlus, and any other DFU-capable device
- **Future-Proof** - No hardcoded PIDs needed; detects by USB standard compliance
- **Autonomous Fallback** - Gracefully handles devices that don't fully comply with DFU spec

---

# Complete Command List (v2.1.1)

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
| `getinfo` | Comprehensive device information retrieval |
| `partitions` | Partition table detection (MBR/GPT parsing) |
| `usb-identify` | Check QSLCL USB exposure status (NEW in v2.1.1) |

**System Control:**
| Command | Description |
|---------|-------------|
| `reset` | System reset (soft/hard/recovery/bootloader/EDL/factory) |
| `power` | Power management (status/on/off/cycle/sleep/wake) |
| `mode` | Mode management (normal/recovery/bootloader/download/EDL) |
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

**Manufacturing & ODM:**
| Command | Description |
|---------|-------------|
| `oem` | OEM operations (bootloader unlock/lock, warranty, secure boot) |
| `odm` | ODM operations (provisioning, testing, calibration, customization) |

**Advanced Testing:**
| Command | Description |
|---------|-------------|
| `crash` | Controlled crash injection with recovery monitoring |
| `glitch` | Hardware fault injection with parameter scanning |
| `bruteforce` | Automated testing (scan/pattern/fuzz/dictionary/replay) |

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
# Build with encryption support
python build.py qslcl.bin --encrypt --debug

# Test basic functionality (auto-exposes QSLCL in USB)
python qslcl.py hello --loader=qslcl.bin
python qslcl.py getinfo --loader=qslcl.bin
python qslcl.py ping --loader=qslcl.bin

# Check USB exposure status
python qslcl.py usb-identify

# List available commands
python qslcl.py hello --loader=qslcl.bin
```

## USB Exposure Feature (v2.1.1)

```bash
# Loader automatically exposes QSLCL in USB descriptors
python qslcl.py hello --loader=qslcl.bin

# Expected output:
# [*] Loading: qslcl.bin
# [+] Loader uploaded.
# [*] Exposing QSLCL in USB configuration...
# [+] QSLCL identified in USB:
#     Product: QSLCL Loader v2.1.0
#     Serial: QSLCL-05AC-1281-67A3F2C8
#     Protocol: 0x51 ('Q')
#     Vendor Magic: 0x51534C43

# Verify exposure with system tools
$ lsusb -v -d 05AC:1281 | grep -E "(iProduct|iSerial)"
  iProduct                2 QSLCL Loader v2.1.0
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
#   ├─ QSLCLBIN: generic arch, 131072 bytes
#   ├─ QSLCLCMD: 26 commands
#   ├─ QSLCLEND: 64 endpoints
#   ├─ QSLCLENC: v1.0
#   │   ChaCha20=✓, AES-GCM=✓
#   ├─ QSLCLDAT: Data protocol v1.0
#   ├─ QSLCLSYN: Sync block, 4 frame types
#   └─ QSLCLHDR: 1 certificate blocks
```

## DFU Mode Detection (v2.0.1+)

```bash
# Automatic DFU detection - no manual PID configuration needed
python qslcl.py hello --debug

# Expected output for DFU devices:
# [*] DFU device detected: Apple Inc. (0x05AC:0xXXXX) - DFU Mode (Download)
```

## Professional Usage

```bash
# Complete memory operations
python qslcl.py read boot boot.img --loader=qslcl.bin
python qslcl.py write boot modified_boot.img --loader=qslcl.bin
python qslcl.py dump system --size 100M --compress --verify --loader=qslcl.bin

# Configuration management
python qslcl.py config get debug_level
python qslcl.py config set timeout 10000
python qslcl.py config backup my_config.json

# Security analysis
python qslcl.py bypass detect --loader=qslcl.bin
python qslcl.py verify security --verbose --loader=qslcl.bin
python qslcl.py footer --type SECURITY --validate --loader=qslcl.bin

# Hardware testing
python qslcl.py voltage monitor ALL 30 1
python qslcl.py glitch scan --loader=qslcl.bin
python qslcl.py crash test basic 3 5 --loader=qslcl.bin

# USB exposure verification
python qslcl.py usb-identify
```

---

# Device Compatibility

| Vendor   | Mode             | Detection Method            | USB Exposure | Encryption | Status |
|----------|------------------|-----------------------------|--------------|------------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Auto      | Optional   | ✅ |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Auto      | Optional   | ✅ |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | ✅ Auto      | No         | ✅ |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | ✅ Auto      | **Required** | ⚠️ Ready |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ Auto      | Optional   | ✅ |
| Samsung  | EUB              | Dynamic USB DFU Class       | ✅ Auto      | Optional   | ✅ |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ⚠️ Limited  | Optional   | ✅ |
| Any      | Serial COM       | UART auto sync              | N/A         | No         | ✅ |

---

# Module Architecture (v2.1.1)

All command modules follow a clean, consistent architecture:

```
modules/
├── read.py          # Memory reading with resume/verify/format conversion
├── write.py         # Memory writing with safety checks/verification
├── erase.py         # Secure erasure with multiple patterns
├── peek.py          # Memory inspection with type/pointer analysis
├── poke.py          # Precision writes with bit operations
├── dump.py          # Bulk memory dumping with compression/metadata
├── patch.py         # Binary patching with backup/verification
├── oem.py           # OEM bootloader/warranty/secure boot
├── odm.py           # ODM provisioning/testing/calibration
├── rawmode.py       # Privilege escalation with session audit
├── voltage.py       # Voltage control/monitoring/limits
├── verify.py        # System verification (multi-stage)
├── reset.py         # System reset (10+ types)
├── rawstate.py      # Hardware state inspection
├── power.py         # Power management (12 subcommands)
├── mode.py          # Mode management (18 modes)
├── glitch.py        # Hardware fault injection
├── footer.py        # Footer analysis/validation
├── crash.py         # Controlled crash injection/testing
├── config.py        # Configuration with schema validation
├── bypass.py        # Security bypass with auto-detection
└── bruteforce.py    # Automated testing/fuzzing/dictionary
```

Each module features:
- **Single import chain** - Clean `try/except` with fallback
- **Direct QSLCLCMD integration** - No wrapper functions
- **Unified dispatch** - `module_cmd()` pattern with DB lookup
- **Consistent safety** - `confirm()` with force override
- **Progress tracking** - Single `ProgressBar` class
- **Clean output** - No ANSI codes, universal terminal compatibility

---

# USB Exposure Technical Details (v2.1.1)

## How It Works

When `--loader=qslcl.bin` is specified, QSLCL automatically:

1. **Uploads the loader** to the device (existing behavior)
2. **Exposes QSLCL in USB descriptors** using 6 fallback methods:
   - iProduct string descriptor → "QSLCL Loader v2.1.0"
   - iSerial string descriptor → "QSLCL-VID-PID-TIMESTAMP"
   - Vendor control transfer (0xF0) → Returns QSLCL magic (0x51534C43)
   - bInterfaceProtocol → Set to 0x51 ('Q')
   - Device qualifier modification (SuperSpeed)
   - Configuration descriptor update

3. **Verifies exposure** and displays results

## Why This Matters

Like MediaTek's "DA" (Download Agent) or Qualcomm's "Sahara" protocol, QSLCL now:

- **Identifies itself** in USB enumeration
- **Is detectable** by USB analyzers and system tools
- **Provides visual confirmation** that the loader is active
- **Enables automation** by other tools that scan for QSLCL

## Verification Commands

```bash
# Check exposure status
python qslcl.py usb-identify

# System-level verification
lsusb -v -d VID:PID | grep -E "(iProduct|iSerial)"
sudo lsusb -v -d 05AC:1281 | grep "QSLCL"
```

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.6.6 / v2.1.1** | 2026 | **USB QSLCL Exposure** - Auto-identifies in USB descriptors, 6 fallback methods |
| **v0.6.6 / v2.1.0** | 2026 | **Code cleanup** - 40% reduction, QSLCLDATA/SYNC blocks, 26 commands |
| v0.6.5 / v2.0.2 | 2026 | QSLCLENC encryption layer - ChaCha20/AES for A18+ |
| v0.6.4 / v2.0.1 | 2026 | Dynamic DFU detection, QSLCLRESP fixes |
| v0.6.3 / v2.0.0 | 2026 | Complete module rewrite |
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

### Data Protocol (v0.6.6+)

```
Host                           Device
  |                              |
  |--- QSLCLDATA frame --------->|  Chunked data with sequence
  |<-- QSLCLDACK ----------------|  Acknowledgment
  |--- QSLCLDATA frame (more) -->|  Multi-frame transfer
  |<-- QSLCLDACK ----------------|
  |                              |
  |--- QSLCLSYN frame ---------->|  Transport sync
  |<-- QSLCLSYN -----------------|  Frame type negotiation
```

### USB Exposure Protocol (v2.1.1)

```
Host                           Device (after --loader)
  |                              |
  |--- USB Enumeration --------->|
  |<-- iProduct = "QSLCL Loader"|  Auto-exposed
  |<-- iSerial = "QSLCL-..."    |
  |<-- bInterfaceProtocol = 0x51|
  |                              |
  |--- Vendor Ctrl (0xF0) ------>|
  |<-- Magic 0x51534C43 ---------|  QSLCL verification
```

---

## Legal & Ethical Framework

**Quantum Silicon Core Loader (QSLCL)** operates within established legal and ethical boundaries:

### Permitted Uses:
- **Device Owners**: Modifying hardware you legally own
- **Researchers**: Security analysis and academic study
- **Repair Technicians**: Right to Repair implementations
- **Students**: Learning hardware architecture and security
- **Developers**: Creating interoperable software and tools

### USB Exposure Legal Note:
The USB self-identification feature (iProduct/iSerial) is a **standard USB feature** used by countless devices. QSLCL simply identifies itself like any compliant USB device, similar to:
- MediaTek's "DA" (Download Agent)
- Qualcomm's "Sahara" protocol
- Any vendor's USB product string

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
python qslcl.py hello --loader=qslcl.bin --debug
```

**Encryption Layer Not Found:**
```bash
python build.py qslcl.bin --encrypt --debug
```

**DFU Device Not Detected:**
```bash
python qslcl.py hello --debug
```

**USB Exposure Not Working:**
```bash
# Check if device supports runtime descriptor changes
python qslcl.py usb-identify --debug

# Exposure is optional - loader still works without it
# Some devices may not support runtime USB changes
```

**Memory Operation Errors:**
```bash
python qslcl.py read boot boot.img --chunk-size 32768 --loader=qslcl.bin
```

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication — where every memory operation, every privilege escalation, every hardware interaction, every binary patch, and every bootstrap execution becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping, quantum-resistant encryption, structured data protocols, and now automatic USB self-identification like MediaTek DA."**

## Key Philosophy

* **Universal Execution** - One binary, all architectures, 26 essential commands
* **Silicon Intimacy** - Direct hardware conversation with bit-level precision
* **Clean Architecture** - 40% less code, 100% more maintainable
* **Professional Grade** - Enterprise-level memory operations with verification
* **Future-Proof Detection** - USB DFU Class compliance
* **Encryption Ready** - ChaCha20/AES for A18+ compatibility
* **Data Protocol** - Structured bulk transfers with integrity
* **USB Self-Identification** - QSLCL visible in device descriptors (NEW v2.1.1)
* **Ethical Empowerment** - Capability with responsibility and safety controls

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 4368109).