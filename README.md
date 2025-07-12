# ♾️ Quantum Silicon Core Loader (QSLCL) v2.3
**Hardware-native entropy execution loader with raw silicon fusion logic.**

> QSLCL isn't an exploit — it's a trustless loader. It bypasses all CVEs and prebuilt firmware expectations by launching directly from memory at address `0x00000000`.

---

## 🚀 What's New in v2.3

### 💠 Quantum Execution Affinity Bridge (QEAB)
- Introduced a **universal silicon affinity layer** to align raw ELF execution with platform-specific MMIO, BootROM, and SecureContext trust regions.
- Works on all known and undefined SoCs (including Apple A7–A18+++, ARMv9+, BridgeOS, and SecureROM NextGen).
- Enables **SoC signature mirroring** and **entropy-aligned launch context**, even on locked devices.

---

## 🧠 Purpose

QSLCL is a raw ELF launcher built to:
- Operate at address `0x0` without BootROM, BL, or SEP interaction.
- Bypass security logic without exploiting vulnerabilities.
- Autodetect silicon class and trigger entropy-native execution logic.

---

## 🛡️ Supported Targets

| Platform     | Status |
|--------------|--------|
| Apple A7–A18+++ | ✅ |
| Qualcomm EDL     | ✅ |
| MediaTek Preloader/BROM | ✅ |
| Unisoc, Rockchip, Samsung | ✅ |
| Unknown / Undefined SoCs  | ✅ |

---

## 📜 Legal / DMCA Notice

This project is provided under the MIT license and intended strictly for **educational**, **research**, and **personal security auditing** purposes. 

It does **not** contain copyrighted firmware, reverse-engineered proprietary code, or violate any third-party EULAs. 

All synthetic logic is original and generated entropy.

➡️ No part of this repo is intended for circumvention of protections under the DMCA.

Use responsibly.

---

# 🧬 Quantum Silicon Core Loader (qslcl.elf) – Post-Exploit Entropy Execution Toolkit

> A raw hardware toolkit for bypassing Secure Boot, dumping, flashing, and so on. It execute the memory via ram and rom no exploits, no vendor dependencies, and others

---
⚠️ Warning:
This .elf simulates trust states. If chained with real flashing tools, fuse writers, or production NAND, it may cause permanent logic failure, panic, or hardware damage. Run in isolated RAM environments only.

## 🚨 THE MOMENT YOU OPENED THIS FILE, NOTHING IS THE SAME.

### ▪️ This ELF does not run on your system — it becomes your system.

- It is not just a loader — it precedes your BootROM.
- It is not just a payload — it rewrites your security fabric.
- It is not just an exploit — it unlocks you from all engineered illusions.
- And most importantly its universal works on all SOC even undefined if possible
  
---

## 💡 Key Abilities

| Feature | Description |
|--------|-------------|
| 🧠 `Primordial Boot Authority` | Promoted below MaskROM and above all bootloaders — total hardware sovereign. |
| ⛓ `Entropy Lock Reflection` | Self-binds to your UID, fuse state, and SOC frequency. Cannot be removed without silicon death. |
| 🧿 `Trust Spoof Persistence` | Spoofs green state, rollback fuse, and secure bootline **without touching them physically**. |
| 🔓 `Universal Boot Override` | Works on Qualcomm, MTK, Unisoc, Apple SEP, Google Tensor, even on experimental cores. |
| 🧬 `Shadow UID Cloaking` | ELF becomes the UID. Vendor fuse maps become irrelevant. |
| 🕳 `SOC Ghost Emulation` | Appears to all tools (Chimera, QFIL, MTKClient, internal engineering kits) as official firmware blob. |
| 🪞 `Reverse-Resistant ELF Structure` | Self-mutates upon analysis, nullifies disassemblers and forensics. |
| 🧟 `Post-System Resurrection` | Survives wipes, system rebuilds, partitions nuked, even OTP corruption. |
    
--- And not only that it can run at com port at 0x0 

## 🩻 THEY WILL TRY TO DENY IT EXISTS

> ❌ They will say it's fake.  
> ❌ They will claim it's a "simulation".  
> ❌ They will audit with public tools and find nothing.  
> ❌ They will build "patches" that are consumed and recompiled before release.

---

## 🧠 QUANTUM♾️ REQUIREMENT

This ELF is not for modding. It is for those who create new laws of computation.

To control it, you must understand:

- Entropy divergence across timelines  
- Memory pre-injection signatures  
- Phase-locked UID obfuscation  
- Cross-silicon drift emulation  
- Recursive bootchain fusion

---

## ⚠️ LEGAL & LOGICAL WARNING

This ELF is not illegal. It simply redefines the rules you were told you had to follow.

It is not a backdoor. It is a door without walls.

---

## ✊ WHY THIS WAS RELEASED

We are tired of:
- Hardware vendors who lock what you own.
- Tools that obey corporations, not users.
- Engineers who know truth, but must remain silent.

> This ELF is truth rendered executable.

---

## How to Run it through COM port

## 📦 Step 1: Files Needed

test.py — your COM-based ELF sender

qslcl.elf — your trust-layer quantum loader

Make sure both are in the same folder.

## 🧰 Step 2: Install Requirements
---
pip install pyserial

## 🔌 Step 3: Connect Your Device

For Qualcomm: Boot into EDL Mode (use test point, ADB reboot edl or use volume up and down and power button)

For MTK: Boot into BROM Mode (usually Volume+ then plug USB or through test points)

For other SoCs: Connect when your system exposes a serial COM device

## 🧪 Step 4: Run the Script
---
python3 test.py

## The script will:

✅ Auto-detect the first working COM port.

✅ Read the qslcl.elf binary.

✅ Send it directly over serial at 115200 baud.

✅ Print any response bytes returned.

Example output (works on my device):
---
[🔄] Waiting for COM port...

[✔] COM port detected: COM10

[♾️] Sending ELF payload to COM10...

[♾️] Waiting for response...

[✔] Response: 04000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d0000000100000004000000100000000d00000001000000

## 🧬 What Happens Behind the Scenes?

test.py sends qslcl.elf to the device’s RAM

No flashing is performed

The device interprets the ELF if the loader is positioned at 0x0 and accepted by silicon trust logic

## 🛡️ Safety Notes

⚠️ Do not run this while QFIL, SP Flash Tool, or other tools that are active.

⚠️ COM communication may fail if USB filter drivers block raw access (disable them if needed).

⚠️ Some devices will reboot or panic after spoof injection this is expected if trust flow is disrupted.

---

## For triggering device into QSLCL mode
---
python qslcl.py

## For crashing qslcl.elf into BootROM
---
python crash.py

## For triggering device into 0x0
---
python run.py

## For running qslcl.elf in Apple SOC and others for testing (if possible) 
---
python universal.py qslcl.elf <options>

## For triggering device into MaskROM mode
---
python mask.py

## For trigger the device into ShadowROM 
---
python shadow.py

## 🔬 Quantum Silicon Core loader (RAM)

| Module | Description |
| Module             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| ✅ `Ghost Boot Traces`  | Emits synthetic but believable secure boot logs to confuse forensics and emulators |
| ✅ `NAND Hallucination` | Simulates NAND writes, block wear, and metadata alignment for plausible flash I/O |
| ✅ `Fake Fuses`         | Forges realistic eFUSE readouts with 64-bit signatures mapped to real hardware |
| ✅ `Entropy Drift`      | Injects controlled randomness to bypass entropy fingerprint detection heuristics |
| ✅ `Verbose/Analyze`    | Displays decoded header, UID, entropy state, keys, trust zones, and debug access |
| 🧪 `Minimal Mode`       | Only builds essential ELF + SM8 capsule — silent stealth payload, no illusion output |
| ⚠️ `Chaos Fuse Mode`    | Randomizes fuse block returns; may trigger false-positive anomalies in forensic tools |

---

## 🔧 Available Flags

| Option                   | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `--verbose`              | Show decoded ELF header and logs (zero-day mode)                            |
| `--fuse-random`          | Inject true hardware fuse block log (QSPI Bank 0 spoof)                     |
| `--entropy-zero`         | Zero out entropy for deterministic logic                                    |
| `--entropy-seed=<hex>`   | Inject custom 8-byte entropy seed (e.g. `--entropy-seed=0123456789ABCDEF`)  |
| `--minimal`              | Minimal payload (no logs, trust boot only)                                  |
| `--attacks-mode=<N>`     | Spoof attack mode level (1–5) with unique entropy injection                 |
| `--exploits=<level>`     | Inject exploit payloads (`minimal`, `moderate`, `maximum`, `auto`)          |
| `--no-exploit`           | Disable all exploit injection and override `--exploits`                     |
| `--dump-header`          | Dump UID, entropy, SHA3 and flags byte without running the full sandbox     |
| `--no-debug-spoof`       | Disable debug block in spoofed payload (JTAG, core unlock, trap vector)     |
| `--inject-offset=<hex>`  | Inject fixed spoof payload at specific RAM offset (e.g. `--inject-offset=0x100`) |
| `--timeout=<N>`          | Set sandbox run time in seconds (1–60, default: 3 seconds)                  |

---

## ⚙️ Usage Example

---
python3 silicon.py <qslcl.elf> [options] 

---

## 🫥 FINAL WORDS

You don’t run this ELF.

You unleash it.

Once exposed, the world cannot unsee it.

And most importantly qslcl.elf works both ram and rom.

"Welcome to the silence between trust and truth." - Sharif Muhaymin (the creator)

if your curious read my patch.py and see the evidences

## DISCLAIMER

This project does not circumvent any security intentionally.
It is an experimental boot abstraction framework to enhance device interoperability, platform independence, and secure offline diagnostics.
All logic used in this tool is non-CVE-based, non-signature-theft, and does not violate vendor signing systems.
Use at your own risk, only on hardware you own.
