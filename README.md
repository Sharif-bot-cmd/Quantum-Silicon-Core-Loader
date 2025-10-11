# Quantum Silicon Core Loader  — v3.0 ♾️

> The first post-BootROM, post-IMG4, post-exploit Quantum-Class Loader that executes directly from `0x0` across all SoCs — Apple A12+++, Qualcomm, MTK, and even undefined or future architectures.

## 🔥 What’s New in v2.9?

🧩 Core Improvements

- Improved internal entropy handling and adaptive behavior precision.

- Optimized SOC table parsing and memory alignment routines.

- Minor latency reductions during self-heal and integrity verification.

- Enhanced cross-architecture opcode balancing and filler efficiency.

⚙️ Build System

- Streamlined build pipeline with cleaner output and audit summaries.

- Reduced redundant operations for faster image generation.

- Minor adjustments in post-build hashing and digest embedding logic.

🔒 Stability & Reliability

- Improved error handling and fallback resilience.

- Refined USB descriptor embedding sequence for safer offset control.

- Minor checksum alignment fixes for universal compatibility.

- Enhanced robustness in mutation and polymorphic entropy layers.

🧠 Codebase Quality

- Better modular structure — clearer function separation.

- Minor cleanup of unused parameters and redundant logic.

- Improved debug verbosity and trace consistency.
 
---

## 📜 Legal / DMCA Notice

This project is provided under the MIT license and intended strictly for **educational**, **research**, **personal security auditing**, and **freedom on their devices**. 

It does **not** contain copyrighted firmware, reverse-engineered proprietary code, or violate any third-party EULAs. 

All synthetic logic is original and generated entropy.

➡️ No part of this repo is intended for circumvention of protections under the DMCA.

Use responsibly.

---

# 🧬 Quantum Silicon Core Loader (qslcl.elf) – Post-Exploit Entropy Execution Toolkit

> A raw hardware toolkit for bypassing Secure Boot, dumping, flashing, and so on. It execute the memory via ram and rom no exploits, no vendor dependencies, and others

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

## For running qslcl.elf in Apple dfu mode (A12+++, A18+++)
---
python dfu.py 

## For triggering device into MaskROM mode
---
python mask.py

## For trigger the device into ShadowROM 
---
python shadow.py

## For running voltage attack procedure (improvised glitch attack)
---
python voltage.py

## For triggering the device into JTAG mode
---
python jtag.py

## For triggering device into deep factory mode
---
python deep_factory.py

## To flash shellcode.bin
---
python flash.py

## For triggering the device into ROM Emergency mode
---
python rem.py

---

## 🫥 FINAL WORDS

You don’t run this ELF.

You unleash it.

Once exposed, the world cannot unsee it.

And most importantly qslcl.elf works both ram and rom.

"Welcome to the silence between trust and truth." - Sharif Muhaymin (the creator)

## DISCLAIMER

This project does not circumvent any security intentionally.
It is an experimental boot abstraction framework to enhance device interoperability, platform independence, and secure offline diagnostics.
All logic used in this tool is non-CVE-based, non-signature-theft, and does not violate vendor signing systems.
Use at your own risk, only on hardware you own.
