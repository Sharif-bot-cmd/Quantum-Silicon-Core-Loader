# Quantum Silicon Core Loader — v5.4

Primary Core: **qslcl.elf**  
Assistant Module: **qslcl.bin**  
Universal Controller: **qslcl.py (v1.0.8)**  

---

## 🧬 Overview

**Quantum Silicon Core Loader (QSLCL)** is a post-bootloader, post-vendor, post-exploit execution layer designed to operate directly at the silicon boundary.  

It runs beyond conventional security domains, survives firmware states, and negotiates trust without requiring CVEs.

QSLCL executes from RAM/ROM, attaches to any serial/USB transport, and operates in:

- EDL (Qualcomm)
- BROM / Preloader (MediaTek)
- DFU (Apple)
- Meta / Engineering Mode
- Diagnostic & Vendor Maintenance Modes  
- Any device exposing COM/USB endpoints

"**You don't execute QSLCL. Silicon interprets it.**"

---

# 🚀 What's New in **v5.4**

- **Advanced OEM/ODM Integration** - Full factory-level command support with intelligent SOC detection
- **Universal Bootloader Lock/Unlock** - Auto-detection of lock regions across Qualcomm, MediaTek, Exynos, Kirin, and Unisoc platforms
- **Enhanced Mode Switching** - Dynamic mode discovery and triggering from QSLCL loader modules
- **Cross-Platform Calibration** - Sensor, display, and hardware calibration suite
- **Intelligent Memory Region Scanning** - Adaptive lock flag detection without hardcoded addresses

---

# 🐍 **qslcl.py — Controller v1.0.8 Upgrades**

## 🔓 **Advanced OEM Commands**

# Universal bootloader unlock/lock with auto-detection
```
python qslcl.py oem unlock --loader=qslcl.bin
python qslcl.py oem lock --loader=qslcl.bin
```
# SOC-agnostic lock region detection (0x00000000-0xFFFFFFFF scanning)

# Supports: Qualcomm, MediaTek, Exynos, Kirin, Unisoc platforms


## 🏭 **Factory ODM Features**
```bash
# Diagnostic mode control
python qslcl.py odm enable diag --loader=qslcl.bin
python qslcl.py odm enable meta --loader=qslcl.bin
python qslcl.py odm enable jtag --loader=qslcl.bin
```

# Hardware testing suite
```
python qslcl.py odm test display --loader=qslcl.bin
python qslcl.py odm test sensor --loader=qslcl.bin
python qslcl.py odm test all --loader=qslcl.bin
```

# Factory calibration
```
python qslcl.py odm calibrate touch --loader=qslcl.bin
python qslcl.py odm calibrate all --loader=qslcl.bin
```

# FRP and factory management
```
python qslcl.py odm frp --loader=qslcl.bin
python qslcl.py odm factory_reset --loader=qslcl.bin
```

## 🔄 **Smart Mode Management**
```bash
# Discover available modes from your qslcl.bin
python qslcl.py mode list --loader=qslcl.bin
```

# Check current device mode
```
python qslcl.py mode status --loader=qslcl.bin
```

# Trigger device modes with auto-routing
```
python qslcl.py mode qslcl --loader=qslcl.bin
```

## 🛠 **Technical Enhancements**
- **Intelligent Parser Loader** - Improved QSLCL.bin module parsing with multi-phase scanning
- **SOC-Type Auto-Detection** - Dynamic platform identification for adaptive command routing
- **Enhanced Memory Operations** - Sector-size aware read/write with alignment handling
- **Universal Transport Layer** - Robust USB/Serial communication with error recovery

---

# 📦 INSTALLATION

```bash
# Core dependencies
pip install pyserial pyusb

# Optional: For enhanced performance
pip install requests tqdm
```

---

# 🔌 CONNECT YOUR DEVICE

| Vendor     | Mode                     | Detection Method               |
|------------|--------------------------|--------------------------------|
| Qualcomm   | EDL / Firehose-ready     | Automatic Sahara/Firehose      |
| MediaTek   | BROM / Preloader         | BROM handshake (0xA0)          |
| Apple      | DFU                      | DFU signature detection        |
| Generic    | USB Serial/CDC           | Bulk endpoint discovery        |
| Any        | COM Port                 | Universal serial detection     |

**QSLCL automatically detects and adapts to your device's transport protocol.**

---

# ▶ HOW TO RUN

## 🎪 **Basic Communication**

# Device discovery and handshake
```
python qslcl.py hello --loader=qslcl.bin
```
# Ping with latency measurement
```
python qslcl.py ping --loader=qslcl.bin
```
# Get comprehensive device info
```
python qslcl.py getinfo --loader=qslcl.bin
```
## 🔓 **Bootloader Security**

# Universal unlock (auto-detects SOC and lock regions)
```
python qslcl.py oem unlock --loader=qslcl.bin
```
# Re-lock bootloader
```
python qslcl.py oem lock --loader=qslcl.bin
```
# Verify lock state
```
python qslcl.py oem verify_lock --loader=qslcl.bin
```

## 🏭 **Factory Operations**

# Enable engineering modes
```
python qslcl.py odm enable diag --loader=qslcl.bin
python qslcl.py odm enable engineering --loader=qslcl.bin
```

# Comprehensive hardware testing
```
python qslcl.py odm test all --loader=qslcl.bin
```
# Sensor calibration
```
python qslcl.py odm calibrate gyro --loader=qslcl.bin
python qslcl.py odm calibrate all --loader=qslcl.bin
```

## 🔍 **Memory Operations**

# Read from partition or address
```
python qslcl.py read boot --loader=qslcl.bin
python qslcl.py read 0x880000 --size=0x1000 -o dump.bin --loader=qslcl.bin
```

# Write data to device
```
python qslcl.py write boot firmware.bin --loader=qslcl.bin
python qslcl.py write 0x880000 "AABBCCDD" --loader=qslcl.bin
```
# Direct memory access
```
python qslcl.py peek 0x880000 --loader=qslcl.bin
python qslcl.py poke 0x880000 0x12345678 --loader=qslcl.bin
```
# Bulk memory operations
```
python qslcl.py dump 0x0 0x10000 full_dump.bin --loader=qslcl.bin
python qslcl.py erase boot --loader=qslcl.bin
```
## 🔄 **Device Mode Control**

# List available modes from your loader
```
python qslcl.py mode list --loader=qslcl.bin
```
# Check current mode
```
python qslcl.py mode status --loader=qslcl.bin
```

## ⚡ **Advanced Features**

# Privilege escalation
```
python qslcl.py rawmode unrestricted --loader=qslcl.bin
python qslcl.py rawstate --loader=qslcl.bin
```
# Hardware testing
```
python qslcl.py bruteforce 0x00-0xFF --threads=8 --output=hits.txt --loader=qslcl.bin
python qslcl.py glitch --level=3 --iter=100 --window=200 --sweep=50 --loader=qslcl.bin
```
# System control
```
python qslcl.py reset --force-reset --loader=qslcl.bin
```
# Configuration management
```
python qslcl.py config SECURE_BOOT 0 --loader=qslcl.bin
python qslcl.py config-list --loader=qslcl.bin
```

## 🔬 **Diagnostic Commands**

# Partition discovery
```
python qslcl.py partitions --loader=qslcl.bin
```
# Footer block analysis
```
python qslcl.py footer --hex --raw --save footer.bin --loader=qslcl.bin
```

## 🛠 **Advanced Usage Examples**

### Multi-Threaded Bruteforce
```bash
python qslcl.py bruteforce 0x1000-0x1FFF --threads=16 --rawmode --output=scan_results.txt --loader=qslcl.bin
```

### Automated Memory Dumping
```bash
# Dump multiple partitions automatically
for part in boot recovery system; do
    python qslcl.py read $part -o ${part}.img --loader=qslcl.bin
done
```

### Factory Testing Suite
```bash
# Run complete factory diagnostic
python qslcl.py odm test all --loader=qslcl.bin

# Calibrate all sensors
python qslcl.py odm calibrate all --loader=qslcl.bin

# Enable full debugging
python qslcl.py odm enable diag --loader=qslcl.bin
python qslcl.py odm enable jtag --loader=qslcl.bin
python qslcl.py rawmode unrestricted --loader=qslcl.bin
```

---

# 🏗 ARCHITECTURE

## Core Components
- **QSLCL Binary (qslcl.bin)** - Universal micro-VM bytecode loader
- **Python Controller (qslcl.py)** - Multi-protocol device communicator
- **SOC Table** - Dynamic architecture detection and adaptation
- **Runtime Fault System** - Real-time error handling and recovery

## Protocol Support
- **USB 2.0/3.0** - Full specification compliance
- **Serial/UART** - Universal baud rate adaptation
- **Qualcomm EDL** - Sahara/Firehose protocol
- **MediaTek BROM** - Preloader communication
- **Apple DFU** - Device Firmware Update mode

## New v5.4 Features
- **Universal Lock Detection** - Cross-platform bootloader flag scanning
- **ODM Command Suite** - Factory-level testing and calibration
- **Smart Mode Routing** - Dynamic mode command discovery and execution
- **Enhanced Parser** - Improved QSLCL.bin module extraction and validation

---

# ⚠ LEGAL & ETHICAL NOTICE

## ✅ Permitted Uses
- Security Research & Education
- Device Diagnostics & Repair
- Firmware Development & Analysis
- Hardware Freedom & Ownership Rights
- Academic Research & Teaching

## ❌ Prohibited Uses
- Malware Injection & Distribution
- Unauthorized Device Access
- Intellectual Property Theft
- Law Violation Activities
- Harmful or Destructive Actions

**Use only on hardware you legally own or have explicit permission to test.**

> **"With great power comes great responsibility. QSLCL provides the former - you must provide the latter."**

---

# 🧩 Final Words

> **"Quantum Silicon Core Loader doesn't just bypass security —  
> it redefines the execution layer silicon trusts."** - Sharif Muhaymin

## 📺 YouTube Channel
For tutorials, demonstrations, and advanced usage:
**https://www.youtube.com/@EntropyVector**

if you have problem or issue when using this tool feel free to suggest.
