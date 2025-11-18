# Quantum Silicon Core Loader — v5.1  
Primary Core: **qslcl.elf**  
Assistant Module: **qslcl.bin**  
Universal Controller: **qslcl.py (v1.0.3)**  

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

“You don’t execute QSLCL. **Silicon interprets it**.”

---

# 🚀 What’s New in **v5.1**

## 💠 **qslcl.bin — Assistant Module Upgrades**
QSLCL v5.1 now includes:

### **🟧 QSLCLPAR — Command Parser Layer**
Core parsing and execution of universal handlers:
- READ / WRITE / ERASE  
- META / ENG mode triggers  
- RESET / REBOOT  
- PEEK / POKE  
- GETINFO / GETSECTOR  
- UNLOCK / LOCK  
- OEM / ODM / POWER / CONFIGURE  

### **🟦 QSLCLUSB — USB Transport Routines**
- TX / RX low-level routines  
- Control/Bulk handlers  
- Enumeration helpers  

### **🟩 QSLCLSPT — Setup Packet Engine**
Internal handler for custom SP4-based control packets.  
Useful for DFU, Firehose-like protocols, and engineering transports.

### **🟪 QSLCLVM5 — Nano-Kernel Microservices**
Micro-services running from RAM providing:
- Diagnostics  
- Voltage ops  
- Mini-auth steps  
- Runtime probes  

### **🟨 QSLCLIDX — Index Table (NEW in 5.1)**
Indexed micro-entries for direct lookup:  
- DISP dispatcher table  
- Runtime helper blocks  
- Command shortcuts  
- Modular offsets for future silicon revisions  

### **🟥 QSLCLDISP — Command Dispatcher (NEW)**
A global dispatcher that normalizes all commands:
```
PAR → DISP → RTF → Silicon
ENG → DISP → RTF → Silicon
VM5 → DISP → RTF → Silicon
```

### **🟫 QSLCLRTF — Runtime Fault System (NEW)**
Every operation now returns structured status frames:
- SUCCESS  
- WARNING  
- ERROR  
- FAULT  
- PARTIAL  
- EXTRA (raw data)  

Supports human-readable decoding in qslcl.py.

---

# 🐍 **qslcl.py — Controller v1.0.3 Upgrades**

### ✔ Smart Sector Size Detection (NEW)
Multi-layer detection using:
- QSLCLPAR GETSECTOR  
- GETINFO geometry  
- HELLO extended RTF  
- Qualcomm Firehose XML  
- MTK BootROM  
- Apple DFU  
- Safe fallback  

### ✔ Fully Upgraded Command Engine
- High-safety READ/WRITE/ERASE with alignment  
- True memory PEEK/POKE with RTF validation  
- RAWMODE Engine (Meta/Hyper/Diagnostic/Hazard modes)  
- GETINFO with multi-tier fallback parsing  
- RESET/REBOOT via ENG, PAR, VM5, or fallback  

### ✔ Bruteforce Engine v2
- Multi-threaded  
- RTF-driven hit extraction  
- Save-found patterns  
- Auto-RAWMODE option  
- QSLCLIDX-aware search (if present)

### ✔ Dump Engine v2
- Full-region extraction  
- Per-chunk validation  
- True raw data frames  
- Progressive percent output  

### ✔ Authentication Layer `--auth`
Verification against **QSLCCERT** header inside qslcl.bin.

### ✔ Eliminated Deprecated Subcommands
USB/SPT/VM5 now auto-trigger via dispatcher.

---

# 📦 INSTALLATION

```
pip install pyserial pyusb
```

---

# 🔌 CONNECT YOUR DEVICE

| Vendor     | Mode                     |
|------------|--------------------------|
| Qualcomm   | EDL / Firehose-ready     |
| MediaTek   | BROM / Preloader         |
| Apple      | DFU                      |
| Others     | Any exposed USB/COM port |

---

# ▶ HOW TO RUN

### Basic Hello
```
python qslcl.py hello --loader=qslcl.bin
```

### Bruteforce Example  
```
python qslcl.py bruteforce 0x00-0xFF --loader=qslcl.bin
```

### Rawmode Example
```
python qslcl.py rawmode unrestricted --loader=qslcl.bin
```

### Dump Example
```
python qslcl.py dump 0x0 0x10000 out.bin --loader=qslcl.bin
```

---

# ⚠ LEGAL & ETHICAL NOTICE

This project is **MIT-licensed** for:
- Research  
- Education  
- Diagnostics  
- Device freedom  

Do **not** use for:
- Malware injection  
- Unauthorized access  
- Breaking laws or others’ property  

**Use only on hardware you legally own.**

---

# 🧩 Final Words
> **“Quantum Silicon Core Loader doesn’t just bypass security —  
it redefines the execution layer silicon trusts.”** - Sharif Muhaymin

# Youtube Channel

https://www.youtube.com/@EntropyVector
