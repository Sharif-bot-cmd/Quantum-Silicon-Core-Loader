# Quantum Silicon Core Loader — v5.4

Primary Core: **qslcl.elf**  
Assistant Module: **qslcl.bin**  
Universal Controller: **qslcl.py (v1.0.9)**  

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

# 🐍 **qslcl.py — Controller v1.0.9 Upgrades**

## 🎯 **Advanced Command Suite**

### 🔓 **Enhanced OEM Commands**
```bash
# Universal bootloader unlock/lock with auto-detection
python qslcl.py oem unlock --loader=qslcl.bin
python qslcl.py oem lock --loader=qslcl.bin
```

# SOC-agnostic lock region detection (0x00000000-0xFFFFFFFF scanning)

# Supports: Qualcomm, MediaTek, Exynos, Kirin, Unisoc platforms

### 🏭 **Factory ODM Features**
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

### ⚡ **Advanced System Control**
```bash
# Comprehensive system verification
python qslcl.py verify integrity --loader=qslcl.bin
python qslcl.py verify signature --loader=qslcl.bin
python qslcl.py verify security --loader=qslcl.bin
python qslcl.py verify comprehensive --loader=qslcl.bin
```

# Power management and control
```
python qslcl.py power status --loader=qslcl.bin
python qslcl.py power on VDD_GPU --loader=qslcl.bin
python qslcl.py power off VDD_CAMERA --loader=qslcl.bin
python qslcl.py power monitor 60 --loader=qslcl.bin
```

# Voltage and power regulation
```
python qslcl.py voltage read --loader=qslcl.bin
python qslcl.py voltage set VDD_CPU 1.2 --loader=qslcl.bin
python qslcl.py voltage monitor 30 --loader=qslcl.bin
```

# Security bypass mechanisms
```
python qslcl.py bypass frp --loader=qslcl.bin
python qslcl.py bypass secure_boot --loader=qslcl.bin
python qslcl.py bypass scan --loader=qslcl.bin
```

### 💥 **Advanced Fault Injection**
```bash
# Voltage glitching
python qslcl.py glitch voltage UNDERVOLT 3 100 VDD_CORE --loader=qslcl.bin
```

# Clock glitching 
```
python qslcl.py glitch clock CPU 100 50 BURST --loader=qslcl.bin
```
# EM glitching
```
python qslcl.py glitch em 4 20 100 10,15 --loader=qslcl.bin
```

# Laser fault injection
```
python qslcl.py glitch laser 80 10 1064 CPU_CORE --loader=qslcl.bin
```

# Automated parameter scanning
```
python qslcl.py glitch scan VOLTAGE 1-10 1 50 --loader=qslcl.bin
```

# Automatic glitch discovery
```
python qslcl.py glitch auto BYPASS 60 AGGRESSIVE --loader=qslcl.bin
```

### **System Verification & Crash Testing**
```bash
# System integrity verification
python qslcl.py verify integrity --loader=qslcl.bin
```

# Digital signature validation
```
python qslcl.py verify signature BOOTLOADER --loader=qslcl.bin
```

# Security policy auditing
```
python qslcl.py verify security --loader=qslcl.bin
```

# Controlled crash testing
```
python qslcl.py crash test --loader=qslcl.bin
python qslcl.py crash preloader --loader=qslcl.bin
python qslcl.py crash kernel --loader=qslcl.bin
```

# Comprehensive verification
```
python qslcl.py verify comprehensive --loader=qslcl.bin
python qslcl.py verify report --loader=qslcl.bin
```

### 🔄 **Smart Mode Management**
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
python qslcl.py mode QSLCL --loader=qslcl.bin
```

## 🛠 **Technical Enhancements v1.0.9**

- **Intelligent Parser Loader** - Improved QSLCL.bin module parsing with multi-phase scanning
- **SOC-Type Auto-Detection** - Dynamic platform identification for adaptive command routing
- **Enhanced Memory Operations** - Sector-size aware read/write with alignment handling
- **Universal Transport Layer** - Robust USB/Serial communication with error recovery
- **Advanced Fault Injection** - Comprehensive glitching capabilities (voltage, clock, EM, laser)
- **System Verification Suite** - Complete integrity and security validation
- **Power Management** - Advanced voltage and power domain control
- **Safety Features** - Confirmation prompts and validation for dangerous operations

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

## New v1.0.9 Features
- **Advanced Fault Injection** - Voltage, clock, EM, and laser glitching
- **Comprehensive Verification** - System integrity and security validation
- **Power Management** - Advanced voltage and power domain control
- **Security Bypass** - Automated security mechanism circumvention
- **Crash Testing** - Controlled system crash simulation
- **Automated Scanning** - Parameter optimization and discovery
- **Safety Systems** - Confirmation prompts and validation

---

# ⚠ LEGAL & ETHICAL NOTICE

## ✅ Permitted Uses
- Security Research & Education
- Device Diagnostics & Repair
- Firmware Development & Analysis
- Hardware Freedom & Ownership Rights
- Academic Research & Teaching
- Vulnerability Research & Defense

## ❌ Prohibited Uses
- Malware Injection & Distribution
- Unauthorized Device Access
- Intellectual Property Theft
- Law Violation Activities
- Harmful or Destructive Actions

**Use only on hardware you legally own or have explicit permission to test.**

> **"With great power comes great responsibility. QSLCL provides the former - you must provide the latter."**

---

# 🆘 SUPPORT & ISSUES

If you encounter problems or have suggestions while using this tool, please:

1. **Check existing issues** on GitHub
2. **Provide detailed information** about your setup
3. **Include error messages** and logs
4. **Specify your device model** and SOC

**I'll address issues and implement solutions as needed.**

---

# 🧩 Final Words

> **"Quantum Silicon Core Loader doesn't just bypass security —  
> it redefines the execution layer silicon trusts."** - Sharif Muhaymin

## 📺 YouTube Channel
For tutorials, demonstrations, and advanced usage:
**https://www.youtube.com/@EntropyVector**

if you encounter problem or issue feel free to suggest to solve it.
