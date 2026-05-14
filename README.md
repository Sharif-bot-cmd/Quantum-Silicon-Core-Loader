# **Quantum Silicon Core Loader**

Primary Core: **qslcl.elf**

Assistant Module: **qslcl.bin (v0.6.7)**

Universal Controller: **qslcl.py (v2.1.2)**

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

## What's New in **v2.1.2**

### 🔥 USB4 v2.0 80Gbps Support (Major Feature)

- **USB4V2MC Block** - Native USB4 v2.0 microcode for 80Gbps operation
- **PAM4 Encoding** - 2-bit per symbol encoding for 80Gbps throughput
- **4-Lane Aggregation** - Full bandwidth utilization across all lanes
- **PCIe/DP/USB3 Tunneling** - Direct tunnel creation over USB4 fabric
- **CMA + DPP Security** - Component Measurement Architecture & Data Protection Profile
- **Hardware Attestation** - Cryptographic proof of device state
- **Automatic Detection** - `--usb4` flag auto-negotiates 80Gbps mode
- **Backward Compatible** - Graceful fallback to USB 3.x/4.0 when USB4 v2.0 unavailable


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
│ 0x010000+ USB4V2MC (USB4 v2.0 80Gbps) ★ NEW│
└─────────────────────────────────────────────┘
```

### USB4 v2.0 80Gbps Support (v0.6.7+):

When built with `--usb4-v2`, QSLCL unlocks 80Gbps communication:

| Without USB4 | With USB4 v2.0 (v0.6.7) |
|--------------|-------------------------|
| ❌ 40Gbps maximum | ✅ **80Gbps throughput** |
| ❌ NRZ encoding | ✅ **PAM4 encoding** (2-bit/symbol) |
| ❌ 2 lanes max | ✅ **4-lane aggregation** |
| ❌ No hardware tunneling | ✅ **PCIe/DP/USB3 tunnels** |
| ❌ Basic security | ✅ **CMA + DPP + Attestation** |
| ❌ Microsecond latency | ✅ **Sub-microsecond latency** |

---

# Complete Command List (v2.1.2)

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
| `usb4` | **USB4 v2.0 80Gbps status and control (NEW)** |

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

# Test basic functionality (auto-exposes QSLCL in USB)
python qslcl.py hello --loader=qslcl.bin --usb4
python qslcl.py getinfo --loader=qslcl.bin
python qslcl.py ping --loader=qslcl.bin

# Check USB exposure status
python qslcl.py usb-identify

# Check USB4 v2.0 80Gbps status
python qslcl.py usb4

# List available commands
python qslcl.py hello --loader=qslcl.bin
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
# [*] Exposing QSLCL in USB configuration...
# [+] QSLCL identified in USB:
#     Product: QSLCL Loader v2.1.2
#     Serial: QSLCL-05AC-1281-67A3F2C8
#     Protocol: 0x51 ('Q')

# Check USB4 status separately
python qslcl.py usb4

# Expected output:
# [*] Checking USB4 v2.0 status...
# [+] USB4 v2.0 supported:
#     Bandwidth: 80000 Mbps
#     Tunnels: PCIe, DisplayPort, USB3
#     Encoding: PAM4
#     Security: Enabled
#     Current Mode: 80 Gbps
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
#     Product: QSLCL Loader v2.1.2
#     Serial: QSLCL-05AC-1281-67A3F2C8
#     Protocol: 0x51 ('Q')
#     Vendor Magic: 0x51534C43

# Verify exposure with system tools
$ lsusb -v -d 05AC:1281 | grep -E "(iProduct|iSerial)"
  iProduct                2 QSLCL Loader v2.1.2
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

| Vendor   | Mode             | Detection Method            | USB Exposure | USB4 v2.0 | Encryption | Status |
|----------|------------------|-----------------------------|--------------|-----------|------------|--------|
| Qualcomm | EDL              | Sahara + Firehose handshake | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| MediaTek | BROM / Preloader | 0xA0 preloader ping         | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| Apple    | DFU (A12-A17)    | Dynamic USB DFU Class       | ✅ Auto      | ⚠️ 40Gbps | No         | ✅ |
| Apple    | DFU (A18+)       | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | **Required** | ✅ |
| Google   | DFU              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| Samsung  | EUB              | Dynamic USB DFU Class       | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| Intel   | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| AMD     | USB4 v2.0 Host   | Native USB4 detection       | ✅ Auto      | ✅ 80Gbps | Optional   | ✅ |
| Generic  | USB CDC/Bulk     | Endpoint auto-discovery     | ⚠️ Limited  | ❌ No     | Optional   | ✅ |
| Any      | Serial COM       | UART auto sync              | N/A         | N/A      | No         | ✅ |

---

# USB4 v2.0 Technical Details (v0.6.7 / v2.1.2)

## Architecture

```
Standard USB Mode:
QSLCLCMD → USB 3.x/4.0 (40Gbps) → Device

USB4 v2.0 80Gbps Mode:
QSLCLCMD → [PAM4 Encoder] → [4-Lane MUX] → [80Gbps Tunnel] → Device
           ↑                  ↑                ↑
    PAM4 Encoding        Lane Aggregation   PCIe/DP/USB3
```

## PAM4 Encoding (80Gbps)

| Feature | NRZ (USB3/4.0) | PAM4 (USB4 v2.0) |
|---------|----------------|------------------|
| Bits per symbol | 1 bit | **2 bits** |
| Bandwidth | 20Gbps/lane | **40Gbps/lane** |
| 4-lane total | 40Gbps | **160Gbps** (theoretical) |
| Actual throughput | 40Gbps | **80Gbps** (real-world) |

## Tunnel Types

| Tunnel | Purpose | Bandwidth | Latency |
|--------|---------|-----------|---------|
| PCIe | Direct memory access | 80Gbps | <1µs |
| DisplayPort | Video/Display | 80Gbps | <1µs |
| USB3 | Legacy USB | 20Gbps | <10µs |

## Security Features

| Feature | Description |
|---------|-------------|
| CMA | Component Measurement Architecture - Hardware fingerprinting |
| DPP | Data Protection Profile - Per-tunnel encryption |
| Attestation | Cryptographic proof of device state |
| Replay Protection | Sequence number enforcement |

---

# Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **v0.6.7 / v2.1.2** | 2026 | **USB4 v2.0 80Gbps** - PAM4 encoding, 4-lane aggregation, PCIe/DP/USB3 tunneling, CMA/DPP security, attestation |
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

> **"Quantum Silicon Core Loader represents the pinnacle of universal device communication — where every memory operation, every privilege escalation, every hardware interaction, every binary patch, every bootstrap execution, every USB4 v2.0 80Gbps tunnel, and every PAM4-encoded transaction becomes an extension of silicon consciousness through our perfected micro-VM architecture with dynamic bootstrapping, quantum-resistant encryption, structured data protocols, automatic USB self-identification, and now USB4 v2.0 80Gbps support."**

## Key Philosophy

* **Universal Execution** - One binary, all architectures, 27 essential commands
* **Silicon Intimacy** - Direct hardware conversation with bit-level precision
* **Clean Architecture** - 40% less code, 100% more maintainable
* **Professional Grade** - Enterprise-level memory operations with verification
* **Future-Proof Detection** - USB DFU Class compliance
* **Encryption Ready** - ChaCha20/AES for A18+ compatibility
* **Data Protocol** - Structured bulk transfers with integrity
* **USB Self-Identification** - QSLCL visible in device descriptors
* **80Gbps Throughput** - USB4 v2.0 PAM4 encoding with 4-lane aggregation (NEW v0.6.7)
* **Hardware Tunneling** - PCIe/DP/USB3 over USB4 fabric (NEW v0.6.7)
* **Silicon Attestation** - CMA + DPP hardware-level security (NEW v0.6.7)
* **Ethical Empowerment** - Capability with responsibility and safety controls

**YouTube**: [https://www.youtube.com/@EntropyVector](https://www.youtube.com/@EntropyVector)

---

## Legal & Support
- [LEGAL_NOTICE.md](./LEGAL_NOTICE.md) - Legal positioning and protections
- [SUPPORT_REQUEST.md](./SUPPORT_REQUEST.md) - Communication history and good-faith efforts

## Legal & Transparency

This project maintains transparent legal documentation and has established official communication with GitHub Support (Ticket: 4368109).