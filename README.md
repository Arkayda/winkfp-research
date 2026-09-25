# WinKFP Reverse Engineering & Protocol Reconstruction

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Verification: L4/L5 Proven](https://img.shields.io/badge/Verification-L4%2FL5%20Proven-success.svg)](docs/EVIDENCE.md)
[![Safety Interlock: Hard-Gated](https://img.shields.io/badge/Safety-Hard--Gated-critical.svg)](docs/ARCHITECTURE.md)

This repository contains the reverse-engineering analysis, technical documentation, clean-room protocol reconstructions, and differential validation suites for the BMW WinKFP automotive ECU flashing software and its associated EDIABAS subsystem.

---

## 1. Executive Summary & Purpose

Modern automotive control units (ECUs) rely on complex vendor-specific diagnostic and bootloader protocols for firmware updating and calibration programming. For decades, BMW's proprietary engineering tools (`WinKFP`, `NFS`, `EDIABAS`, and `INPA`) have served as the de facto standard for flashing engine (DME/DDE) and transmission (EGS, e.g., ZF 6HP) controllers. However, the precise cryptographic handshakes, transport packaging, keepalive timings, and failure-recovery behaviors remained closed and undocumented.

The goal of this research project is to:
1. **Deconstruct the internal protocol stack** of WinKFP (`winkfpt.exe`, `ebas32.dll`, `api32.dll`, `OBD32.dll`, `nfs.exe`) using static binary analysis (Ghidra).
2. **Reconstruct clean-room Python implementations** for the cryptographic authentication (`KrApi`), key storage (`AS2` 3DES containers), flash transport orchestration (`VDLE`), and bus interfacing (`EDIABAS`/`IFH`).
3. **Differentially validate the reconstructions** against the original x86 machine code via hardware-free instruction-level emulation (Unicorn x86) and known-answer test (KAT) suites.
4. **Formalize safety interlocks** preventing unauthorized or dangerous vehicle execution without rigorous precondition verification.

---

## 2. Repository Scope & Critical Boundaries

> [!IMPORTANT]
> **Independent Research Repository**: `winkfp-research` is a standalone public research archive. It is **NOT** a submodule, branch, package, or component of `open6hp` or any active flashing tool.

* **No Physical ECU Flashing**: This repository is an analytical research archive and testbed. Physical in-vehicle ECU flashing has **NOT** been performed (see [Evidence Model](#5-evidence-and-validation-model)).
* **Clean-Room & Free of Proprietary OEM Assets**: In accordance with intellectual property laws and automotive security guidelines, this repository contains **NO proprietary OEM binaries** (`.exe`, `.dll`, `.prg`, `.ipo`, `.0da`), **NO BMW SP-Daten archives**, **NO proprietary ECU firmware images**, and **NO production cryptographic key databases** (`SGIDC.as2`, `SGIDD.as2`). All tests and examples execute against synthetic test vectors or dynamically utilize local user-supplied binaries via differential hooks.
* **Privacy Sanitization**: All communication traces and log artifacts have been scrubbed of sensitive identifiers, vehicle identification numbers (VINs), serial numbers, and private key material.

---

## 3. Architecture Overview

The WinKFP protocol stack operates across several distinct software layers, reverse-engineered and reconstructed as follows:

```mermaid
graph TD
    subgraph "Reverse Engineered WinKFP Binaries"
        WINKFPT["winkfpt.exe<br/>(VDLE Orchestrator)"]
        KRAPI["KrApi / Crypto<br/>(FUN_004b9f50, FUN_004b9e30)"]
        KEYSTORE["GetAuthKey<br/>(FUN_004b8fe0 / AS2 Containers)"]
        EBAS["ebas32.dll / api32.dll<br/>(EDIABAS Runtime)"]
        OBD["OBD32.dll<br/>(IFH Serial / K-Line Driver)"]
    end

    subgraph "Clean-Room Reconstruction (reconstruction/)"
        VDLE_CORE["reconstruction.vdle<br/>(Block Framing, OPPS Setup)"]
        CRYPTO_CORE["reconstruction.crypto<br/>(Symmetric MD5, RSA-1024, Simple)"]
        AUTH_CORE["reconstruction.auth<br/>(AS2 3DES Decryption, Key Lookup)"]
        EDIABAS_CORE["reconstruction.ediabas<br/>(MockBus & API Adapter)"]
        IFH_CORE["reconstruction.transport<br/>(OBD IFH, XOR Checksum, Timings)"]
        RUNNER["reconstruction.runner<br/>(FlashRunner & Hard-Gated Safety)"]
    end

    subgraph "Validation Tiers"
        KAT["tests/kat/<br/>Known-Answer Tests (L3)"]
        GOLDEN["tests/golden/<br/>Protocol Golden Tests (L3/L4)"]
        DIFF["tests/differential/<br/>Unicorn x86 Differential (L4/L5)"]
    end

    WINKFPT --> VDLE_CORE
    KRAPI --> CRYPTO_CORE
    KEYSTORE --> AUTH_CORE
    EBAS --> EDIABAS_CORE
    OBD --> IFH_CORE

    VDLE_CORE --> RUNNER
    CRYPTO_CORE --> RUNNER
    AUTH_CORE --> RUNNER
    EDIABAS_CORE --> RUNNER

    RUNNER --> KAT
    RUNNER --> GOLDEN
    WINKFPT -.-> DIFF
    RUNNER -.-> DIFF
```

---

## 4. Key Reverse-Engineered Protocols & Algorithms

Detailed technical specifications are located in [`docs/reverse-engineering/`](docs/reverse-engineering/):

### 4.1 KrApi Cryptographic Algorithms
WinKFP implements three distinct cryptographic challenge-response authentication algorithms:
* **Symmetric MD5 Mode** (`FUN_004b9f50`): Uses an 8-byte ECU seed, a 4-byte tester nonce, a 4-byte ECU serial, and a 16-byte shared key (`T_SMA`, `T_SMB`, or `T_SMC`). Produces a 16-byte response key (`SG-Schluessel`). Reconstructed in [`reconstruction/crypto/symmetric.py`](reconstruction/crypto/symmetric.py).
* **Asymmetric RSA-1024 Mode** (`FUN_004b9e30`): Computes `MD5(nonce + serial[:4] + seed)`, converts the digest into an integer, and calculates raw modular exponentiation $S = m^e \pmod n$ using static 1024-bit RSA public keys. Post-processes the result through a 32-bit per-dword byteswap (`FUN_004b8a70`). Reconstructed in [`reconstruction/crypto/asymmetric.py`](reconstruction/crypto/asymmetric.py).
* **Simple Mode** (`FUN_004ba080`): A lightweight 8-byte permutation and key-mixing routine used on legacy control units. Reconstructed in [`reconstruction/crypto/simple.py`](reconstruction/crypto/simple.py).

### 4.2 Key Storage & AS2 Container Parsing
* Runtime keys are read from 3DES-encrypted flat files (`SGIDC.as2`, `SGIDD.as2`) via `GetAuthKey` (`FUN_004b8fe0`).
* The encryption utilizes 3DES in ECB mode with a hardcoded static key.
* Records follow fixed column alignment: `$K <ecu_name:20><ident:4><field6:6><hex_payload>`. Reconstructed in [`reconstruction/auth/key_containers/as2_keys.py`](reconstruction/auth/key_containers/as2_keys.py).

### 4.3 VDLE Flash Protocol & Block Framing
* **Sequence**: `INIT_VDLE` $\rightarrow$ `LOADTABLE` $\rightarrow$ `REQUEST_SEGMENTINFO` $\rightarrow$ `SEND_SEGMENT` $\rightarrow$ `FLASH_SCHREIBEN_STATUS`.
* **Block Framing**: Differential execution under Unicorn proved that `FLASH_SCHREIBEN` blocks are formatted with a strict **21-byte header**, followed by the chunk payload and a `0x03` terminator byte:
  ```text
  01 01 00 00 | 00 00 00 00 | 00 FF 00 00 | 00 | [len LE16] | [len LE16] | [addr LE32] | [payload...] | 03
  ```
  *(Notice: The payload length is stored twice as LE16, and the target address is little-endian).*
* **XXL Threshold**: Blocks with size $> 254$ bytes dynamically switch to the `FLASH_SCHREIBEN_XXL` job. Reconstructed in [`reconstruction/vdle/core.py`](reconstruction/vdle/core.py).

### 4.4 EDIABAS Interface & OBD IFH Driver
* `OBD32.dll` implements diagnostic telegram transport over serial K-Line and D-CAN interfaces.
* Reconstructs port initialization, 9600 8E1 (DS2) and 115200 8N1 (KWP) communication, P4 inter-message gaps, telegram framing, and longitudinal redundancy XOR checksum validation. Reconstructed in [`reconstruction/obd_ifh.py`](reconstruction/obd_ifh.py).

### 4.5 Safety Gates & Hard-Gated Interlocks
Flash execution is hard-gated by the `SafetyContext` and provenance-tracked `Limits` structure:
* Refuses execution without a valid limits policy file bound by SHA-256 digest.
* Continuously checks battery voltage ($V_{bat}$), ignition status, programming voltage flags, and ZB number assembly match before sending the first byte to the ECU. Reconstructed in [`reconstruction/safety/hypotheses.py`](reconstruction/safety/hypotheses.py).

---

## 5. Evidence and Validation Model

The project tracks experimental rigor across eight standardized tiers defined in [`docs/EVIDENCE.md`](docs/EVIDENCE.md):

| Tier | Name | Description | Current Status |
|:---|:---|:---|:---:|
| **L0** | Ghidra Static Decompilation | C decompilation and disassembly analysis | **Complete** (45 files) |
| **L1** | Algorithm Extraction | Pure Python algorithmic model | **Complete** |
| **L2** | Known-Answer Tests (KAT) | Verified against static reference vectors | **Complete** (15 tests) |
| **L3** | Golden State Machine | Verified against mock EDIABAS buses | **Complete** (10 tests) |
| **L4** | Software Differential | Compared event-for-event against emulated x86 code | **Complete** (8 tests) |
| **L5** | Trace Integration | Differentially matched against historical EDIABAS traces | **Complete** |
| **L6** | Bench Contact (Write-Free) | Diagnostic/auth handshake on physical bench ECU | *Prototyped* |
| **L7** | Physical ECU Writing | Modifying non-volatile flash on physical ECU | **NOT PERFORMED** |

> [!CAUTION]
> **No Physical In-Vehicle Flashing**: Writing to automotive flash memory carries severe bricking and safety risks. Physical ECU flash modification (L7) has deliberately **not** been executed.

---

## 6. Repository Layout

```text
winkfp-research/
├── docs/                           # Technical documentation & RE reports
│   ├── ARCHITECTURE.md             # End-to-end system architecture
│   ├── EVIDENCE.md                 # L0–L7 experimental validation framework
│   ├── METHODOLOGY.md              # Reverse engineering & differential methods
│   ├── PROPRIETARY_MATERIAL.md     # Policy on excluded OEM assets
│   ├── QUARANTINE.md               # Audit history & asset filtering
│   ├── research-source-map.md      # Mapping to historical source workspace
│   ├── history/                    # Historical research progression (Rev 1–18.1)
│   └── reverse-engineering/        # In-depth subsystem specifications
├── analysis/                       # Ghidra decompilation artifacts (45 C files)
│   ├── crypto/                     # Symmetric, asymmetric, and simple algorithms
│   ├── auth/                       # GetAuthKey and AS2 container loaders
│   ├── vdle/                       # VDLE orchestration, block framing, OPPS
│   ├── ediabas/                    # EDIABAS runtime and API handlers
│   └── obd32/                      # OBD32.dll IFH serial driver
├── reconstruction/                 # Clean-room Python protocol implementations
│   ├── crypto/                     # Symmetric MD5, RSA-1024, Simple XOR
│   ├── auth/                       # AS2 3DES parser, key store, retry chain
│   ├── vdle/                       # VDLE flash engine, block builder, OPPS setup
│   ├── ediabas/                    # MockBus, EDIABAS ctypes API adapter
│   ├── transport/                  # OBD IFH driver, telegram framing, timings
│   ├── safety/                     # SafetyContext, Limits policy, interlocks
│   └── runner.py                   # Master FlashRunner orchestration engine
├── tests/                          # Automated verification suites
│   ├── kat/                        # Known-answer tests (crypto, auth, keys)
│   ├── golden/                     # Protocol state machine golden tests
│   ├── differential/               # Unicorn x86 differential runners
│   ├── fixtures/                   # Synthetic containers, limits, and images
│   └── run_tests.py                # Master test runner
├── tools/                          # Analysis, diffing, and sanitization tools
│   ├── bench_diff/                 # L1/L2 event log differential runner
│   ├── trace_parser/               # EDIABAS *.trc parser and VIN sanitizer
│   └── analysis/                   # Master password decoder & SP-Daten scanner
├── traces/                         # Sanitized and expected event logs
│   ├── sanitized/                  # Privacy-sanitized EDIABAS traces
│   └── expected/                   # Standardized benchmark JSONL logs
└── examples/                       # Runnable demonstration scripts
    ├── synthetic_auth/             # Key derivation demo with synthetic vectors
    ├── vdle/                       # VDLE block framing and mock flashing demo
    └── differential/               # Bench log differential comparison demo
```

---

## 7. Reproducibility & Getting Started

### Prerequisites
- Python 3.10 or newer (tested through Python 3.14).
- *Optional for differential execution*: `unicorn` and `pefile` (`pip install unicorn pefile`).

### Running the Test Suite
The repository includes a unified master test runner:

```bash
# Run all verification suites (KAT, Golden, Differential):
python3 tests/run_tests.py

# In a minimal environment without Unicorn or OEM binaries:
# (KAT and Golden tests pass; Differential tests skip cleanly)
python3 tests/run_tests.py
```

### Running Runnable Examples
All examples operate fully independently using synthetic data fixtures:

```bash
# 1. Cryptographic Authentication Demo:
python3 examples/synthetic_auth/demo_auth.py

# 2. VDLE Flash Engine & Block Framing Demo:
python3 examples/vdle/demo_vdle.py

# 3. Differential Event Log Comparison Demo:
python3 examples/differential/demo_diff.py
```

### Running Differential Tests Against Original Binaries (Lab Environment)
If you possess the original binaries in your local research lab, specify their path to execute instruction-level differential verification:

```bash
export WINKFPT_EXE="/path/to/winkfpt.exe"
export OBD32_DLL="/path/to/OBD32.dll"
python3 tests/run_tests.py --tier differential
```

---

## 8. Responsible Disclosure & Security

Automotive control systems operate safety-critical vehicle dynamics. Flashing untrusted code or corrupting non-volatile flash memory can render a vehicle inoperable or unsafe.
- Review [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidelines and safety policies.
- Always observe strict battery voltage maintenance and programming preconditions.

---

## 9. Citation & Academic Attribution

If you utilize this research, reverse-engineering methodology, or reconstructed protocol stack in academic work or software engineering projects, please cite:

```bibtex
@misc{winkfp_research_2026,
  author = {winkfp-research contributors},
  title = {WinKFP Reverse Engineering & Protocol Reconstruction Archive},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/winkfp-research/winkfp-research}}
}
```
See [`CITATION.cff`](CITATION.cff) for full machine-readable metadata.

---

## 10. License & Legal Notice

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE) for details.

*BMW, WinKFP, EDIABAS, and INPA are registered trademarks of Bayerische Motoren Werke AG (BMW AG). This research repository is an independent reverse-engineering study conducted for interoperability, protocol analysis, and educational purposes under applicable legal provisions. This project is NOT affiliated with, sponsored by, or endorsed by BMW AG or ZF Friedrichshafen AG.*
