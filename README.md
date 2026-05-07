# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf**

Assistant Module: **qslcl.bin (v0.6.4)**

Universal Controller: **qslcl.py (v2.0.1)**

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

# What's New in **v2.0.1**

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

# qslcl.py — Universal Controller **v2.0.1**

## Complete Command List

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
# Test basic functionality
python qslcl.py hello --loader=qslcl.bin
python qslcl.py getinfo --loader=qslcl.bin
python qslcl.py ping --loader=qslcl.bin

# List available commands and endpoints (now shows DFU devices)
python qslcl.py --loader=qslcl.bin endpoints
python qslcl.py config list --loader=qslcl.bin
```

## DFU Mode Detection (v2.0.1)

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

## Advanced Usage

```bash
# With authentication
python qslcl.py hello --loader=qslcl.bin --auth

# Wait for device detection (useful for DFU mode entry)
python qslcl.py getinfo --loader=qslcl.bin --wait 10

# Professional patching workflow
python qslcl.py read boot boot.img --loader=qslcl.bin
# Modify boot.img externally
python qslcl.py patch boot file boot_patched.img --loader=qslcl.bin --verify

# Crash testing (USE WITH CAUTION!)
python qslcl.py crash-test basic 3 5 --loader=qslcl.bin

# Hardware state inspection
python qslcl.py rawstate monitor CLK_CTL 0.5 30 --loader=qslcl.bin
python qslcl.py rawstate read CPUID --loader=qslcl.bin

# DFU-specific operations (auto-detected)
python qslcl.py read 0x8000000 --size 1M -o dfu_dump.bin --loader=qslcl.bin
```

---

# Device Compatibility

| Vendor   | Mode             | Detection Method            | Status |
|----------|------------------|-----------------------------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Enhanced |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Enhanced |
| Apple    | DFU              | **Dynamic USB DFU Class**   | ✅ v2.0.1 (No hardcoded PIDs) |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ New |
| Samsung  | DFU              | Dynamic USB DFU Class       | ✅ New |
| OnePlus  | DFU              | Dynamic USB DFU Class       | ✅ New |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ✅ Universal |
| Any      | Serial COM       | UART auto sync              | ✅ Universal |

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

### Legal Basis:
This tool enables exercises of:
- **First Sale Doctrine** rights (modification of owned property)
- **Right to Repair** principles (globally recognized)
- **Academic Research** exemptions (security studies)
- **Educational Use** protections (learning purposes)

> **Use responsibly. With great power comes great responsibility.**

---

# Support & Troubleshooting

## Common Issues

**Parser Detection Problems:**
```bash
# If modules aren't detected, check binary structure
python qslcl.py hello --loader=qslcl.bin
```

**Device Connection Issues:**
```bash
# Use wait parameter for slow devices
python qslcl.py hello --loader=qslcl.bin --wait 5
```

**DFU Device Not Detected (v2.0.1 fixed):**
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

**Verification Failures:**
```bash
# Increase retries for unreliable connections
python qslcl.py write boot image.bin --loader=qslcl.bin --retries 5

# Skip verification for known-good operations
python qslcl.py patch 0x100000 file patch.bin --no-verify --loader=qslcl.bin
```

## Getting Help

1. **Open a GitHub issue** with detailed information
2. **Include your device model** and connection method
3. **Provide command logs** and output with `--debug`
4. **Include qslcl.bin size and SHA256 hash**
5. **Specify Python version and OS**
6. **Include architecture information** from `getinfo`

## Debug Information

```bash
# Enable debug output
python build.py --debug
python qslcl.py hello --loader=qslcl.bin --debug

# Verbose output for complex operations
python qslcl.py rawmode list --verbose --loader=qslcl.bin

# Test specific functionality
python qslcl.py verify list --loader=qslcl.bin
python qslcl.py bypass test --loader=qslcl.bin

# Debug DFU detection specifically
python qslcl.py endpoints --debug 2>&1 | grep -i dfu
```

---

# Module Architecture (v2.0.1)

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

# Technical Deep Dive: DFU Detection (v2.0.1)

## How It Works

```python
def universal_dfu_detection(dev):
    """
    Detects ANY DFU mode device using USB DFU Class Specification
    """
    # USB DFU Class Specification defines:
    # - bInterfaceClass: 0xFE (Application Specific)
    # - bInterfaceSubClass: 0x01 (Device Firmware Upgrade)
    # - bInterfaceProtocol: 0x01 (Runtime) or 0x02 (Download)
    
    cfg = dev.get_active_configuration()
    for intf in cfg:
        if (intf.bInterfaceClass == 0xFE and 
            intf.bInterfaceSubClass == 0x01):
            return {
                'mode': 'DFU',
                'protocol': 'DFU Mode (Download)' if intf.bInterfaceProtocol == 0x02 else 'DFU Mode (Runtime)',
                'vendor': vendor_name,
                'vid': dev.idVendor,
                'pid': dev.idProduct
            }
    return None
```

## Why This Matters

| Version | Detection Method | Future Device Support |
|---------|-----------------|----------------------|
| v2.0.0 and earlier | Hardcoded PID list | ❌ Requires code update for each new device |
| v2.0.1 | USB DFU Class Specification | ✅ Works with any compliant DFU device |

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication — where every memory operation, every privilege escalation, every hardware interaction, every binary patch, and every bootstrap execution becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping."**

## Key Philosophy

* **Universal Execution** - One binary, all architectures, 30+ complete commands
* **Silicon Intimacy** - Direct hardware conversation with bit-level precision
* **Adaptive Intelligence** - Environment-aware behavior with safety enforcement
* **Professional Grade** - Enterprise-level memory operations with verification
* **Advanced Patching** - Professional binary modification with read-back verification
* **Modular Architecture** - Consistent, maintainable command modules
* **Ethical Empowerment** - Capability with responsibility and safety controls
* **Future-Proof Detection** - USB DFU Class compliance (v2.0.1)

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Version History

| Version | Key Changes |
|---------|-------------|
| v2.0.1 | **Dynamic DFU detection** - No hardcoded PIDs, USB Class compliance |
| v2.0.0 | Complete module rewrite, 20+ commands, unified dispatch |
| v1.2.6 | Legacy version with static PID detection |

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 3932406).