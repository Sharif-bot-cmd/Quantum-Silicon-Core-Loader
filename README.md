# Quantum Silicon Core Loader — v5.3

Primary Core: **qslcl.elf**  
Assistant Module: **qslcl.bin**  
Universal Controller: **qslcl.py (v1.0.6)**  

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

# 🚀 What's New in **v5.3**

- **Enhanced Protocol Headers** - Upgraded QSLCLRTF, QSLCLVM5, QSLCLUSB markers for improved packet reliability
- **Universal Bootstrap Engine** - 100% functional cross-architecture micro-VM bytecode
- **Advanced USB Protocol Stack** - Complete USB 2.0/3.0 specification compliance
- **RAWMODE Privilege Escalation** - Enhanced engineering protocol negotiation
- **Self-Healing Integrity** - Multi-layer runtime fault recovery system

---

# 🐍 **qslcl.py — Controller v1.0.6 Upgrades**

## 🔧 **Critical Fixes**
- **Fixed USB/Serial Auto-Detection** - Proper endpoint discovery and device initialization
- **Enhanced Parser Engine** - Corrected QSLCLEND/ENG, QSLCLPAR, and QSLCLRTF structure parsing
- **Robust Loader Upload** - Lenient module requirements with graceful fallbacks
- **Fixed Communication Protocols** - Proper bulk endpoint handling for USB devices
- **Auto-Transport Management** - Devices automatically open communication channels

## 🎯 **New Features**
- **Universal Device Router** - Hybrid protocol adaptation for Qualcomm, MTK, Apple DFU
- **Smart Partition Resolution** - GPT/PMT/LK table parsing with dynamic target resolution
- **Enhanced Runtime Fault Decoder** - Comprehensive QSLCLRTF v5.1 compliance
- **Thread-Safe Bruteforce** - Multi-threaded scanning with hit detection and logging
- **Certificate Authentication** - QSLCLHDR block validation with HMAC verification

## 📊 **Improved Diagnostics**
- **Colorized Runtime Status** - Visual severity indicators (SUCCESS/WARNING/ERROR/CRITICAL)
- **Module Discovery** - Automatic loader structure analysis and capability reporting
- **Sector Size Detection** - Universal page size detection across all SOC architectures
- **Device Information** - Comprehensive hardware capability enumeration

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
```bash
# Device discovery and handshake
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

## 🔍 **Memory Operations**
```bash
# Read from partition or address
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

## ⚡ **Advanced Features**
```bash
# Privilege escalation
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
```bash
# Partition discovery
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

### Configuration Management
```bash
# Disable secure boot
python qslcl.py config SECURE_BOOT 0 --loader=qslcl.bin

# Enable debug mode
python qslcl.py config DEBUG_LEVEL 3 --loader=qslcl.bin

# Set custom baud rate
python qslcl.py config UART_SPEED 1500000 --loader=qslcl.bin
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

---
