# Reverse-Engineering & Verification Methodology

This document details the multi-stage reverse-engineering and verification methodology employed throughout the investigation of the legacy BMW WinKFP / EDIABAS flashing toolchain.

---

## 1. Overview of the Research Pipeline

```text
+-----------------------------------------------------------------+
| 1. Static Reverse Engineering & Decompilation (Ghidra 12.1.4)   |
|    - Target binaries: winkfpt.exe, ebas32.dll, OBD32.dll        |
|    - Function discovery, string references, calling conventions  |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| 2. CPU Emulation & Ground Truth Execution (Unicorn x86 Engine)  |
|    - Map original PE sections at original ImageBase             |
|    - Hook Import Address Table (IAT) for file I/O & heap        |
|    - Execute raw x86 machine instructions in controlled sandboxes|
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| 3. Clean-Room Independent Reconstruction (Pure Python 3)        |
|    - Re-implement cryptographic routines, parsers, and schedulers|
|    - Zero proprietary code; strictly behavioral reimplementation|
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| 4. Differential Validation & Verification Tri-State (L4/L5)     |
|    - Event-by-event and byte-for-byte differential comparisons  |
|    - KATs (Known-Answer Tests) with synthetic fixtures          |
|    - Production trace parsing & semantic validation             |
+-----------------------------------------------------------------+
```

---

## 2. Reverse-Engineering Stages

### 2.1 Static Reverse Engineering & Headless Decompilation
* **Tooling**: Ghidra 12.1.4 with custom native decompiler builds.
* **Scope**: Analysis of `winkfpt.exe` (Win32 GUI application), `ebas32.dll` (EDIABAS runtime engine), and `OBD32.dll` (K-Line serial transport driver).
* **Technique**:
  * Cross-referencing diagnostic job strings (e.g., `NG_AUTHENTISIERUNG_START`, `FLASH_SCHREIBEN`, `STATUS_DLE_VERSION`, `NORMALER_DATENVERKEHR`).
  * Tracing control flow from WinKFP's central authentication orchestrator (`FUN_0041c920`) and VDLE dispatcher (`FUN_004a1f80`).
  * Identifying cryptographic constants: MD5 IV tables and round constants at `0x605160`, 3DES permutation tables, and RSA modular exponentiation loops.

### 2.2 Dynamic CPU Emulation via Unicorn
To obtain irrefutable ground truth without executing complex legacy 32-bit Windows software on host operating systems:
* **Tooling**: `unicorn` x86 emulator + `pefile`.
* **Environment**:
  * The Windows PE headers and sections (`.text`, `.data`, `.rdata`, `.bss`) of `winkfpt.exe` are mapped at base address `0x00400000`.
  * Execution starts directly at target function entry points (e.g., `FUN_004617c0`, `FUN_004b95a0`, `FUN_004a5b60`).
  * An emulated bump allocator handles heap allocations.
  * CRT file I/O imports (`fopen`, `fread`, `fseek`, `fgetc`) are intercepted via IAT stub hooks and served via an in-memory Virtual File System (VFS).

### 2.3 Clean-Room Independent Reconstruction
* All protocol and algorithm implementations in `reconstruction/` are written from scratch in Python 3.
* Algorithms are implemented purely based on observed mathematical behavior, documented byte layouts, and timing specifications.
* No decompiled C source code or binary snippets are incorporated into the reconstruction modules.

---

## 3. Verification & Validation Techniques

### 3.1 Known-Answer Tests (KAT)
* **Cryptographic Algorithms**:
  * MD5 known-answer tests against RFC 1321 test vectors.
  * Simple cipher round evaluations against fixed seeds.
  * 3DES-EDE-ECB decryption tests against FIPS PUB 46-3 test vectors.
  * RSA-512 modular exponentiation verification against known key pairs.
* **RNG Determinism**:
  * Verification of the MSVC linear congruential generator `s * 0x343FD + 0x269EC3` (`srand(1) -> 41`).

### 3.2 Differential Execution Harnesses
* **VDLE Differential (`tests/differential/vdle/`)**:
  * Drives both the original `winkfpt.exe` machine code (in Unicorn) and the Python reconstruction against an identical simulated ECU (`EdiabasSim`).
  * Compares the resulting sequence of `(device, job, args, payload)` events.
  * Evaluated across 11 comprehensive operational scenarios (DF1 through DF11), including OPPS mode, block size edge cases (chunk 16 vs XXL chunk 256), keep-alive failures, and WAS recovery restarts.
* **OBD32 Differential (`tests/differential/ediabas/`)**:
  * Original `OBD32.dll` machine code drives a virtual COM head in Unicorn.
  * Verifies baud rate switching (9600 8E1 vs 8N1), XOR frame checksum calculations, and command dispatch against pure-Python `obd_ifh.py`.

### 3.3 Semantic Authentication Verification
* Authentication keys sent in `NG_AUTHENTISIERUNG_START` are dynamic: they depend on ECU-generated seeds and runtime nonces.
* A strict SHA-256 byte check between different runs would produce a false negative.
* Replaced with **semantic validation**: the test harness takes the logged seed, serial number, and nonce, recomputes the expected key using the known key material, and verifies that the payload matches the mathematical expectation.

### 3.4 Trace Parsing & Sanitization
* The EDIABAS API trace engine records comprehensive call logs (`api.trc`).
* The trace parser in `tools/bench_diff/` reconstructs the event sequence (`job`, `args`, `payload_bytes`, `JOB_STATUS`).
* **Sanitization Protocol**:
  * Real vehicle identification numbers (VINs) are searched and replaced with synthetic equivalents (`WBAXXXXXXXXXXXXXXXX`).
  * Customer identifiers, ECU serial numbers, and private key payloads are redacted to preserve privacy and confidentiality while maintaining complete protocol integrity.
