# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf**

Assistant Module: **qslcl.bin (v0.6.7)**

Universal Controller: **qslcl.py (v2.1.4)**

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

## What's New in **v2.1.4**

### 🔥 Automatic Watchdog Disabler (No User Intervention)

- **Zero-Configuration** - Automatically detects and disables watchdog on every connection
- **Multi-SoC Support** - Works on Apple, Qualcomm, MediaTek, Samsung, Broadcom, Rockchip, Allwinner, NVIDIA
- **Smart Offset Detection** - Tries known watchdog register offsets per SoC
- **Multiple Disable Methods** - Write-zero, write-sequence, bit-clear, and more
- **Verification Read-Back** - Confirms watchdog is actually disabled
- **No Flags or Commands** - Runs silently in background, no user action needed
- **Graceful Failure** - If no watchdog detected, continues normally

**How it works (automatic):**
```bash
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
### 🔧 Binary Layout (v0.6.7)

```
QSLCL Binary Layout (v0.6.7):
┌─────────────────────────────────────────────┐
│ 0x000000  QSLCLBIN (Main Header + Ptrs)     │
│ 0x000200+ QSLCLCMD (27 Commands)            │
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
```

---

# Complete Command List (v2.1.4)

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
| `usb-identify` | Check QSLCL USB exposure status |
| `usb4` | USB4 v2.0 80Gbps status and control |
| `dfu-boot` | **Boot iOS device into DFU mode (NEW in v2.1.3)** |

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
# Build with USB4 v2.0 and encryption support
python build.py qslcl.bin --usb4-v2 --encrypt --debug

# Auto-DFU boot + Loader + Hello (All-in-One)
python qslcl.py hello --loader=qslcl.bin --dfu-boot

# Just boot into DFU mode (like palera1n)
python qslcl.py dfu-boot

# Test basic functionality (auto-exposes QSLCL in USB)
python qslcl.py hello --loader=qslcl.bin --usb4
python qslcl.py getinfo --loader=qslcl.bin
python qslcl.py ping --loader=qslcl.bin

# Check USB exposure status
python qslcl.py usb-identify

# Check USB4 v2.0 80Gbps status
python qslcl.py usb4
```

## Automatic Watchdog Disabler (v2.1.4)

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

## Auto-DFU Boot Feature (v2.1.3)

```bash
# Method 1: Standalone DFU boot (like palera1n)
python qslcl.py dfu-boot

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

# Method 4: With debug output
python qslcl.py dfu-boot --debug
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

# Check USB4 status separately
python qslcl.py usb4
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
#     Product: QSLCL Loader v2.1.4
#     Serial: QSLCL-05AC-1281-67A3F2C8
#     Protocol: 0x51 ('Q')
#     Vendor Magic: 0x51534C43

# Verify exposure with system tools
$ lsusb -v -d 05AC:1281 | grep -E "(iProduct|iSerial)"
  iProduct                2 QSLCL Loader v2.1.4
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
#   ├─ QSLCLCMD: 27 commands
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

| Vendor   | Mode             | Detection Method            | USB Exposure | USB4 v2.0 | Auto-DFU | Watchdog | Encryption | Status |
|----------|------------------|-----------------------------|--------------|-----------|----------|----------|------------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅ |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅ |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | ✅ Auto      | ⚠️ 40Gbps | ✅ Auto  | ✅ Auto  | No         | ✅ |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | ✅ Auto  | ✅ Auto  | **Required** | ✅ |
| Apple    | Normal Mode iOS  | USB Class + Product String  | N/A         | N/A      | ✅ Auto  | N/A     | N/A        | ✅ |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅ |
| Samsung  | EUB              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | N/A      | ✅ Auto  | Optional   | ✅ |
| Broadcom | BCM Boot         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅ |
| Rockchip | Mask ROM         | VID detection               | ✅ Auto      | ❌ No     | N/A      | ✅ Auto  | Optional   | ✅ |
| Intel    | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅ |
| AMD      | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | N/A      | N/A     | Optional   | ✅ |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ⚠️ Limited  | ❌ No     | N/A      | ⚠️ Limited| Optional | ✅ |
| Any      | Serial COM       | UART auto sync              | N/A         | N/A      | N/A      | N/A     | No         | ✅ |

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.6.7 / v2.1.4** | 2026 | **Automatic Watchdog Disabler** - Zero-config, multi-SoC support, 9+ SoC families, auto-detection, no flags needed |
| **v0.6.7 / v2.1.3** | 2026 | **Auto-DFU Boot** - Like palera1n, one-click DFU entry with button guide, UDID detection, auto-reconnection |
| **v0.6.7 / v2.1.2** | 2026 | **USB4 v2.0 80Gbps** - PAM4 encoding, 4-lane aggregation, PCIe/DP/USB3 tunneling, CMA/DPP security |
| **v0.6.6 / v2.1.1** | 2026 | **USB QSLCL Exposure** - Auto-identifies in USB descriptors, 6 fallback methods |
| **v0.6.6 / v2.1.0** | 2026 | **Code cleanup** - 40% reduction, QSLCLDATA/SYNC blocks, 26 commands |
| v0.6.5 / v2.0.2 | 2026 | QSLCLENC encryption layer - ChaCha20/AES for A18+ |
| v0.6.4 / v2.0.1 | 2026 | Dynamic DFU detection, QSLCLRESP fixes |
| v0.6.3 / v2.0.0 | 2026 | Complete module rewrite |
| v0.5.x / v1.x | 2025 | Legacy versions |

---

## Automatic Watchdog Disabler Technical Details (v2.1.4)

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
| Write Sequence | Write multiple values in sequence (0x12345678, 0x87654321, 0x5A5A5A5A) |
| Bit Clear | Read, clear specific bit, write back |
| Bit Set | Read, set specific bit, write back |

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

## Legal & Ethical Framework

**Quantum Silicon Core Loader (QSLCL)** operates within established legal and ethical boundaries:

### Permitted Uses:
- **Device Owners**: Modifying hardware you legally own
- **Researchers**: Security analysis and academic study
- **Repair Technicians**: Right to Repair implementations
- **Students**: Learning hardware architecture and security
- **Developers**: Creating interoperable software and tools

### Auto-DFU Legal Note:
The DFU boot feature uses **standard USB DFU Class Specification** (0xFE/0x01) and standard iOS recovery mode triggers. It provides button instructions to the user and requires explicit consent - it does not automatically manipulate devices without permission.

### Watchdog Disabler Legal Note:
The watchdog disabler modifies hardware registers on **your own device** to prevent automatic resets during debugging and analysis. This is a standard practice in embedded systems development and hardware security research.

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
# Run with debug to see what's happening
python qslcl.py hello --loader=qslcl.bin --debug

# Watchdog disabler runs automatically - check output for:
# [*] Detected SoC type: XXX
# [*] Watchdog detected at 0xXXXXXXXX
```

**Auto-DFU Not Detecting Device:**
```bash
# Make sure device is connected and unlocked
# Trust this computer when prompted on device
python qslcl.py dfu-boot --debug
```

**Device Won't Enter DFU Mode:**
```bash
# Try adjusting timeout (default 30 seconds)
python qslcl.py dfu-boot --dfu-timeout 45

# Or manually enter DFU mode:
# 1. Press Power + Volume Down for exactly 10 seconds
# 2. Release Power, keep holding Volume Down
# 3. Screen should be BLACK
```

**Parser Detection Problems:**
```bash
python qslcl.py hello --loader=qslcl.bin --debug
```

**Encryption Layer Not Found:**
```bash
python build.py qslcl.bin --encrypt --debug
```

**USB4 v2.0 Not Detected:**
```bash
# Check if device supports USB4 v2.0
python qslcl.py usb4 --debug

# Rebuild with USB4 v2.0 support
python build.py qslcl.bin --usb4-v2 --debug
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
```

**Memory Operation Errors:**
```bash
python qslcl.py read boot boot.img --chunk-size 32768 --loader=qslcl.bin
```

---

# Final Words

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication — where every memory operation, every privilege escalation, every hardware interaction, every binary patch, every bootstrap execution, every USB4 v2.0 80Gbps tunnel, every PAM4-encoded transaction, every one-click DFU boot, and now every automatic watchdog disabler becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping, quantum-resistant encryption, structured data protocols, automatic USB self-identification, USB4 v2.0 80Gbps support, palera1n-like DFU automation, and zero-configuration watchdog bypass."**

## Key Philosophy

* **Universal Execution** - One binary, all architectures, 27 essential commands
* **Silicon Intimacy** - Direct hardware conversation with bit-level precision
* **Clean Architecture** - 40% less code, 100% more maintainable
* **Professional Grade** - Enterprise-level memory operations with verification
* **Future-Proof Detection** - USB DFU Class compliance
* **Encryption Ready** - ChaCha20/AES for A18+ compatibility
* **Data Protocol** - Structured bulk transfers with integrity
* **USB Self-Identification** - QSLCL visible in device descriptors
* **80Gbps Throughput** - USB4 v2.0 PAM4 encoding with 4-lane aggregation
* **Hardware Tunneling** - PCIe/DP/USB3 over USB4 fabric
* **Silicon Attestation** - CMA + DPP hardware-level security
* **One-Click DFU Boot** - Like palera1n, automatic DFU entry with button guide
* **Zero-Config Watchdog** - Automatic detection and disabling on every connection (NEW v2.1.4)
* **Ethical Empowerment** - Capability with responsibility and safety controls

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 4368109).