# WinKFP Reverse Engineering & Protocol Reconstruction

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Verification: L4/L5/L6 (Read-Only) Proven](https://img.shields.io/badge/Verification-L4%2FL5%2FL6%20(Read--Only)%20Proven-success.svg)](docs/EVIDENCE.md)
[![Safety Interlock: Hard-Gated](https://img.shields.io/badge/Safety-Hard--Gated-critical.svg)](docs/ARCHITECTURE.md)
[![Test Suite: 257 Passed](https://img.shields.io/badge/Tests-257%20Passed-brightgreen.svg)](tests/)

This repository contains the reverse-engineering analysis, technical documentation, clean-room protocol reconstructions, differential validation suites, and offline diagnostic replay layers for the BMW WinKFP automotive ECU flashing software and its associated EDIABAS subsystem, focused on the BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`).

---

## 1. Executive Summary & Purpose

Modern automotive control units (ECUs) rely on complex vendor-specific diagnostic and bootloader protocols for firmware updating and calibration programming. For decades, BMW's proprietary engineering tools (`WinKFP`, `NFS`, `EDIABAS`, and `INPA`) have served as the standard toolchain for flashing engine (DME/DDE) and transmission (EGS, e.g., ZF 6HP) controllers. However, the precise cryptographic handshakes, transport packaging, keepalive timings, and failure-recovery behaviors remained closed and undocumented.

The goal of this research project is to:
1. **Deconstruct the internal protocol stack** of WinKFP (`winkfpt.exe`, `ebas32.dll`, `api32.dll`, `OBD32.dll`, `nfs.exe`) and SGBD diagnostic scripts (`10FLASH.prg`, `03GKE195.ipo`) using static binary analysis (Ghidra).
2. **Reconstruct clean-room Python implementations** for cryptographic authentication (`KrApi`), key storage (`AS2` 3DES containers), flash transport orchestration (`VDLE`), and diagnostic bus interfacing (`EDIABAS`/`IFH`).
3. **Establish a canonical, decoupled read-only diagnostic runtime and replay layer** (`CanonicalPipeline`, `EdiabasJobReplayEngine`, `DiagnosticTransport`, `KdcanDiagnosticAdapter`) for querying ECU identification records offline with fail-closed validation.
4. **Differentially validate the reconstructions** against original x86 machine code via hardware-free instruction-level emulation (Unicorn x86), known-answer test (KAT) suites, immutable hardware trace fixtures, and scripted transport backends.
5. **Formalize safety interlocks** preventing unauthorized or dangerous vehicle execution without rigorous precondition verification.

---

## 2. Repository Scope & Critical Boundaries

> [!IMPORTANT]
> **Independent Research Repository**: `winkfp-research` is a standalone public research archive. It is **NOT** a submodule, branch, package, or component of `open6hp` or any active flashing tool. It does not import, depend on, or modify `open6hp`.

* **Physical Read-Only K+DCAN Validation (L6)**: Read-only diagnostic identification queries have been validated against physical ZF 6HP EGS hardware (target `0x18`) via K+DCAN (`115200 8N1`), recorded into immutable hardware traces in `traces/hardware/*.json`.
* **No Physical ECU Flashing (L7)**: Physical in-vehicle or bench ECU reprogramming, firmware flashing, and bootloader manipulation have **NOT** been validated on physical hardware (see [Evidence Model](#6-evidence-and-validation-model)).
* **Strict Read-Only Runtime Scope**:
  - The runtime execution layer is restricted strictly to read-only diagnostic identification jobs (`IDENT`, `PHYSIKALISCHE_HW_NR_LESEN`, `SERIENNUMMER_LESEN`, `AIF_LESEN`, `AIF_READ_BENCH_ALIAS`, `ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, `DATEN_REFERENZ_LESEN`).
  - Write operations, flash memory erasing (`0x31 0x01` / `0x31 0x02`), flash block downloading (`0x34`, `0x36`, `0x37`), ECU reset (`0x11`), diagnostic session transitions (`0x10`), and security access / routine authentication (`0x27`, `0x31 0x07`, `0x31 0x08`) remain **STRICTLY EXCLUDED** from the read-only runtime and are blocked fail-closed before any dispatch.
* **Hardware Quarantine for Diagnostic Adapters**:
  - The K+DCAN transport adapter (`KdcanDiagnosticAdapter`) is validated offline using in-memory scripted simulation (`ScriptedKdcanBackend`).
  - Physical serial communication is hardware-quarantined by default with `auto_open: bool = False`. No serial port (e.g. `/dev/cu.usbserial-A50285BI`) is opened automatically during transceive operations.
* **Artifact Separation & Redistribution Policy**:
  - **No Original Proprietary Binaries**: No original proprietary OEM binaries (`.exe`, `.dll`, `.prg`, `.ipo`, `.0da`), BMW SP-Daten archives, proprietary ECU firmware images, or production key containers (`SGIDC.as2`, `SGIDD.as2`) are distributed in this repository.
  - **Reverse-Engineering Analysis (`analysis/`)**: Contains behavioral reverse-engineering observations, decompiler-derived C pseudocode, and structural annotations derived from proprietary binaries for research and interoperability analysis.
  - **Independent Reconstruction (`reconstruction/`)**: Contains independently authored Python reimplementations modeling the observed protocols and algorithms.
  - **Public RSA Parameters**: The repository contains public RSA parameters ($N, E$) recovered during reverse engineering. No private RSA exponent or private signing key is included.
* **Privacy Sanitization**: All communication traces and log artifacts have been scrubbed of sensitive identifiers, vehicle identification numbers (VINs), serial numbers, and private key material.

### 2.1 Demarcation of Subsystems: Diagnostic Runtime vs Flash Model

The repository maintains an unambiguous architectural boundary between the physical/offline-validated diagnostic runtime and the offline-only flash orchestration model:

| Architectural Property | Canonical Read-Only Diagnostic Runtime | Reconstructed Flash Orchestration Model |
|---|---|---|
| **Primary Packages** | `reconstruction/ediabas/`, `reconstruction/transport/kdcan/` | `reconstruction/runner.py`, `reconstruction/vdle/`, `reconstruction/auth/` |
| **Proven Evidence Level** | **L6** (Physical bench proven) / **L5** (Trace replay) | **L4** (Differential x86 emulation) / **L3** (KAT test vectors) |
| **Target Scope** | ZF 6HP EGS (target `0x18`) over K+DCAN (`115200 8N1`) | Theoretical IPO orchestration (`CI62F1`, `10FLASH.prg`) |
| **Operational Scope** | Read-only identification queries (`IDENT`, `PHYSIKALISCHE_HW_NR_LESEN`, `AIF_READ_BENCH_ALIAS`, `TESTER_PRESENT`) | Flashing state machine (`INIT_VDLE`, `LOADTABLE`, `SEND_SEGMENT`, `SECURITY_ACCESS`, `FLASH_SCHREIBEN`) |
| **Physical Hardware Status** | Validated on bench hardware; single-transaction execution | **L7 UNVALIDATED**: Zero physical ECU flashing, zero erase, zero write |
| **Hardware Safety Gate** | Quarantined (`auto_open=False`); explicit confirmation required | Hard-gated: prohibited from physical bus dispatch fail-closed |
| **Intended Role** | Production-grade verifiable diagnostic query and replay layer | Pure clean-room reverse-engineering and research model |

---

## 3. Architecture Overview

The WinKFP research stack models diagnostic orchestration and protocol execution across several distinct software layers:

```
+-------------------------------------------------------------------------+
|                        EDIABAS Job API Layer                            |
|             (execute_job / EdiabasJobReplayEngine)                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 1: SGBD Job Definition & Catalog                 |
|                (SgbdJobDefinition, 10FLASH.prg Semantics)               |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 2: Canonical Request Builder                     |
|           (build_request -> Canonical DS2 Wire Request Frame)           |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|              Stage 3: Diagnostic Transport Boundary                     |
|        transceive_ds2(wire_frame: bytes, timeout: float) -> bytes       |
|  [FixtureTransport | MockTransport | KdcanDiagnosticAdapter (Offline)]  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 4: Fail-Closed Response Validator                |
|      (Format Byte, Length, Addressing, Checksum, Expected SID/SubID)    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 5: SGBD Semantic Parser                          |
|         (decode_10flash_* -> Typed Fields, Structured Dict)             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 6: Provenanced EdiabasJobResult                  |
|    (Fields, Status, EvidenceDomain, Target/Tester Provenance, Axes)     |
+-------------------------------------------------------------------------+
```

---

## 4. Canonical EDIABAS Replay, Diagnostic Transport & K+DCAN Adapter

Milestones 5.12 and 5.13 established a decoupled, offline-first transport architecture separating high-level SGBD diagnostic logic from wire communication.

### 4.1 DiagnosticTransport Protocol Contract

The communication boundary is defined in `reconstruction/ediabas/transport.py` as a pure byte-level Python Protocol (`@runtime_checkable`):

```python
class DiagnosticTransport(Protocol):
    """Pure byte-level transport protocol for DS2 diagnostic communication."""

    def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes:
        """Transmit a canonical DS2 wire frame and receive raw DS2 response frame."""
        ...
```

* **Separation of Concerns**:
  - `DiagnosticTransport` knows **nothing** about WinKFP jobs (`IDENT`, `AIF_LESEN`), SGBD bytecode routines, result field names, or evidence classifications.
  - It receives a complete physical DS2 wire request frame (including trailing checksum) and returns the raw physical DS2 response frame (including trailing checksum).
  - Physical serial communication (`SerialKdcanTransport`) remains strictly isolated in `reconstruction.transport.kdcan.serial` and is never imported or instantiated during offline replay.

### 4.2 Offline Transport Implementations

1. **`FixtureTransport`** (`reconstruction/ediabas/transport.py`): Replays canonical responses from immutable physical trace fixtures (`traces/hardware/*.json`), raw hex strings, or trace dictionaries. Supports `strict_tx_match=True` to verify that the outgoing request generated by the pipeline matches the recorded trace bit-for-bit, and maintains a complete audit trail in `transport.history`.
2. **`MockTransport`** (`reconstruction/ediabas/transport.py`): Provides deterministic synthetic responses, request-to-response mapping tables, timeout injection (`always_timeout=True`), dynamic callback handlers, and transport error injection for testing fail-closed execution paths.

### 4.3 K+DCAN DiagnosticTransport Adapter & Scripted Backend

Milestone 5.13 introduces the bridge between native K+DCAN transport primitives and the canonical `DiagnosticTransport` boundary:

1. **`KdcanDiagnosticAdapter`** (`reconstruction/transport/kdcan/adapter.py`):
   - Adapts any `KdcanTransport` backend into a `DiagnosticTransport`.
   - **Pure Byte-Level Boundary**: Passes `wire_frame: bytes` directly to `backend.transceive_raw()` and returns raw response bytes without modification or re-encoding.
   - **Zero Job Knowledge**: The adapter contains zero SGBD job logic, zero catalog queries, and no awareness of WinKFP commands.
   - **Hardware Quarantine**: Initialized with `auto_open: bool = False` by default. It never automatically opens OS serial ports unless explicitly instructed.
   - **Exception Translation**: Cleanly translates backend `TimeoutError` and `KdcanError("timeout")` into `TransportTimeoutError`, and framing/bus failures into `TransportError`.
2. **`ScriptedKdcanBackend`** (`reconstruction/transport/kdcan/adapter.py`):
   - Offline scriptable `KdcanTransport` subclass enabling deterministic in-memory wire simulation without physical serial ports.
3. **Direct Wire Primitive (`transceive_raw`)**:
   - Added to `KdcanTransport`, `SerialKdcanTransport`, and `TracedKdcanTransport` to ensure byte-exact transmission without implicit payload re-encoding.

### 4.4 Protocol Representations: Logical Telegram vs Wire Frame

The architecture strictly distinguishes between two independent protocol representations:
- **`logical_request`** (`EdiabasTelegram.raw_buffer`): The logical telegram buffer as managed by the EDIABAS kernel (`_TEL_AUFTRAG`), containing the header and payload, but **without** the trailing physical transport checksum byte.
- **`canonical_ds2_request`** (`EdiabasTelegram.to_wire_frame()`): The complete physical DS2 wire frame including the trailing additive 8-bit checksum appended by the bus driver.

### 4.5 CanonicalPipeline & EdiabasJobReplayEngine

- **`CanonicalPipeline`** (`reconstruction/ediabas/pipeline.py`): Unifies job metadata lookup, request building, transport dispatch, fail-closed validation, and semantic decoding. Catches `TransportTimeoutError` into `status="ERROR_TIMEOUT"` and `TransportError` into `status="ERROR_TRANSPORT"`.
- **`EdiabasJobReplayEngine`** (`reconstruction/ediabas/replay.py`): Top-level EDIABAS-compatible execution engine reproducing SGBD job flows, modeling canonical arguments (e.g. `AIF_NUMMER: int = 0`), and enforcing target address provenance.
- **Upstream Safety Rejection**: Unsupported or dangerous jobs (e.g. `FLASH_PROGRAMMIEREN`) are rejected strictly upstream by the catalog resolver before transport dispatch. Automated tests confirm `transport.transceive_ds2()` is **never reached** (0 frames dispatched).

---

## 5. Evidence Taxonomy & Ground Truth

### 5.1 Evidence Domains (`EvidenceDomain`)

The replay engine strictly isolates execution evidence across three non-overlapping domains:
1. **`PHYSICAL_EGS_FIXTURE`**: Immutable physical bench traces recorded from physical ZF 6HP EGS hardware. Canonical target address is strictly `0x18`.
2. **`FACTORY_TRACE`**: Historical factory session trace recorded from an official WinKFP/EDIABAS flashing session (`traces/sanitized/sanitized_flash_session.trc`). Canonical target address is strictly `0x78`. Replay strictly forbids silently rewriting target `0x78` to `0x18` or confusing factory observations with physical EGS execution.
3. **`SYNTHETIC_OFFLINE`**: Synthetic test fixtures and mock transports used for unit testing and negative path validation.

### 5.2 Four Orthogonal Truth Axes

Every job execution result (`SgbdJobResult` and `EdiabasJobResult`) tracks four independent boolean truth axes:
* **`sgbd_supported`**: Defined as a supported routine in the `10FLASH.prg` SGBD driver.
* **`factory_trace_observed`**: Directly observed in historical factory flash session traces.
* **`physical_trace_exists`**: Verified against an immutable physical bench hardware trace.
* **`directly_resolved`**: Verified direct identification routine on target hardware.

### 5.3 Ground Truth vs UNKNOWN Matrix

| Job Name | IPO Procedure | SGBD Routine | Diagnostic Service | Subfunction / Common ID | Request Frame (DS2 to 0x18) | Expected Response SID | Wire Ground Truth | Evidence Classification |
|---|---|---|:---:|:---:|:---:|:---:|:---:|---|
| **`IDENT`** | `Ident` | `IDENT` (`0x00453A`) | `$1A` | `$80` | `82 18 F1 1A 80 25` | `5A 80` | Physical EGS 0x18 | `DIRECTLY_RESOLVED` |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | `PhysHwNrLesen` | `PHYSIKALISCHE_HW_NR_LESEN` (`0x012E45`) | `$1A` | `$87` (fallback: `$80`) | `82 18 F1 1A 87 2C` | `5A 87` | Physical EGS 0x18 | `DIRECTLY_RESOLVED` |
| **`AIF_READ_BENCH_ALIAS`** | *(Reconstruction)* | *(Direct primitive)* | `$1A` | `$86` | `82 18 F1 1A 86 2B` | `5A 86` | Physical EGS 0x18 | `OBSERVED_WIRE / RECONSTRUCTION_ALIAS` |
| **`TESTER_PRESENT`** | *(Keepalive)* | *(Primitive)* | `$3E` | `$00` | `82 18 F1 3E 00 C9` | `7F 3E 12` | Physical EGS 0x18 | `OBSERVED_WIRE` (NRC 0x12) |
| **`SERIENNUMMER_LESEN`** | `SgSerienNr` | `SERIENNUMMER_LESEN` (`0x00D172`) | `$1A` | `$89` (fallback: `$80`) | `82 18 F1 1A 89 2E` | `5A 89` | Physical EGS 0x18 (Milestone 5.17) | `DIRECTLY_RESOLVED` |
| **`AIF_LESEN`** | `AifLesen` | `AIF_LESEN` (`0x028DDE`) | `$23` | *(MemAddress + Len)* | `86 18 F1 23 00 00 00 07 12 CB` | `63` | Physical EGS 0x18 (Milestone 5.16) | `DIRECTLY_RESOLVED` |
| **`ZIF_LESEN`** | `ZifLesen` | `ZIF_LESEN` (`0x00E60F`) | `$22` | `$2503` (fallback: `$1A $91`, `$80`) | `83 18 F1 22 25 03 D6` | `62 25 03` | Physical EGS 0x18 (Milestone 5.17) | `DIRECTLY_RESOLVED` |
| **`ZIF_BACKUP_LESEN`** | `ZifBackupLesen` | `ZIF_BACKUP_LESEN` (`0x01126C`) | `$22` | `$2500` (fallback: `$1A $80`) | `83 18 F1 22 25 00 D3` | `62 25 00` | Physical EGS 0x18 (Milestone 5.17) | `DIRECTLY_RESOLVED` |
| **`HARDWARE_REFERENZ_LESEN`** | `HwReferenzLesen` | `HARDWARE_REFERENZ_LESEN` (`0x0143FA`) | `$22` | `$2502` (fallback: `$1A $80`) | `83 18 F1 22 25 02 D5` | `62 25 02` | Factory trace line 11620 | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`DATEN_REFERENZ_LESEN`** | `DatenReferenzLesen` | `DATEN_REFERENZ_LESEN` (`0x015A66`) | `$22` | `$2504` | `83 18 F1 22 25 04 D7` | `62 25 04` | Factory trace line 11588 | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |

> [!NOTE]
> **AIF Provenance & Service Separation**:
> - **`AIF_LESEN`**: Confirmed by SGBD disassembly (`10FLASH.prg` routine `0x028DDE`) to use KWP2000 service `$23 00 00 00 07 12` (`ReadMemoryByAddress`). Physically confirmed on ZF 6HP EGS bench in Milestone 5.16 (positive response SID `$63`, `AIF_ZB_NR = 7592132`, `AIF_DATUM = 04.12.2008`).
> - **`AIF_READ_BENCH_ALIAS`**: Direct bench diagnostic probe using KWP2000 service `$1A 0x86` (`ReadECUIdentification`). Physically observed on real ZF 6HP EGS hardware and byte-for-byte fixture validated (`20260926_173201_egs_aif.json`).
> - The two services are strictly separated: passing a `1A 86` response into `AIF_LESEN` fails closed with `ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86`. Official AIF_LESEN and AIF_READ_BENCH_ALIAS are NOT the same evidence line.

---

## 6. Evidence and Validation Model

The project tracks experimental rigor across the canonical eight-tier taxonomy defined in [`docs/EVIDENCE.md`](docs/EVIDENCE.md):

| Level | Designation | Description | Current Status |
|:---:|---|---|:---:|
| **L0** | Static observation | Raw strings, symbol names, table entries in disassembled binaries | Validated (45 functions) |
| **L1** | Decompiled / disassembled behavior | Control flow and data structures analyzed via Ghidra/IDA decompiler output | Validated (45 C files in `analysis/`) |
| **L2** | Independent reconstruction | Python reimplementation of algorithms and protocols | Validated (`reconstruction/`) |
| **L3** | Known-answer / execution validation | Deterministic KAT unit tests comparing against known test vectors | Validated (63 KAT tests) |
| **L4** | Differential trace validation | Execution of original OEM machine code under Unicorn x86 compared against reconstruction | Validated (16 differential test suites) |
| **L5** | Real EDIABAS integration | Reconstructed engine interacting with EDIABAS API or parsing historical EDIABAS traces | Validated (`traces/sanitized/`, `traces/hardware/`) |
| **L6** | Real ECU contact (Read-Only) | Read-only diagnostic identification query set executed on physical ZF 6HP EGS bench (target `0x18`) via K+DCAN (`115200 8N1`) | Validated (4 hardware trace fixtures) |
| **L7** | Real ECU programming | Complete flashing of ECU firmware block on a physical vehicle or hardware bench | Not validated |

> [!CAUTION]
> **No Physical In-Vehicle Flashing**: Writing to automotive flash memory carries severe bricking and safety risks. While read-only diagnostic identification queries on physical bench hardware achieve **L6**, **no physical ECU programming (L7)** has been validated on physical hardware in this repository. All write operations, flash block downloading (`0x34`, `0x36`, `0x37`), memory erasing (`0x31 0x01` / `0x31 0x02`), ECU reset (`0x11`), session transitions (`0x10`), and security access / routine authentication (`0x27`, `0x31 0x07`, `0x31 0x08`) remain **STRICTLY EXCLUDED** from the runtime and are blocked fail-closed before any dispatch.

---

## 7. Cryptographic Algorithms & Reverse-Engineered Protocols

Detailed technical specifications are located in [`docs/reverse-engineering/`](docs/reverse-engineering/):

### 7.1 KrApi Cryptographic Algorithms
WinKFP implements distinct challenge-response authentication algorithms:
* **Symmetric MD5 Mode** (`FUN_004b9f50`): Uses an 8-byte ECU seed, a 4-byte tester nonce, a 4-byte ECU serial, and a 16-byte shared key (`T_SMA`, `T_SMB`, or `T_SMC`). Produces a 16-byte response key (`SG-Schluessel`). Reconstructed in [`reconstruction/crypto/symmetric/`](reconstruction/crypto/symmetric/).
* **Asymmetric Authentication (RSA-1024 vs RSA-512)**:
  - **KrApi Static Asymmetric Mode** (`FUN_004b9e30`): Computes `MD5(nonce + serial[:4] + seed)`, converts the digest into an integer, and calculates raw modular exponentiation $S = m^e \pmod n$ using static 1024-bit RSA public keys (`RSA_KEYS` slots 3, 4, 5). Post-processes the result through a 32-bit per-dword byteswap (`FUN_004b8a70`). Reconstructed in [`reconstruction/crypto/asymmetric/`](reconstruction/crypto/asymmetric/).
  - **AS2 Container Asymmetric Mode**: Container-based per-ECU keys (e.g. for `GKE191` in `SGIDC.as2`) utilize 512-bit RSA public keys (136-byte / `0x88` structure: 64-byte $N$, 64-byte $E$, word count `0x10`). Reconstructed in [`reconstruction/security.py`](reconstruction/security.py).
* **Simple Mode** (`FUN_004ba080`): A lightweight 8-byte permutation and key-mixing routine used on legacy control units. Reconstructed in [`reconstruction/crypto/simple/`](reconstruction/crypto/simple/).

### 7.2 Key Storage & AS2 Container Parsing
* Runtime keys are read from 3DES-encrypted flat files (`SGIDC.as2`, `SGIDD.as2`) via `GetAuthKey` (`FUN_004b8fe0`).
* The encryption utilizes 3DES in ECB mode with a hardcoded static key.
* Records follow fixed column alignment: `$K <ecu_name:20><ident:4><field6:6><hex_payload>`. Reconstructed in [`reconstruction/as2_keys.py`](reconstruction/as2_keys.py).

### 7.3 VDLE Flash Protocol & Block Framing
* **Sequence**: `INIT_VDLE` $\rightarrow$ `LOADTABLE` $\rightarrow$ `REQUEST_SEGMENTINFO` $\rightarrow$ `SEND_SEGMENT` $\rightarrow$ `FLASH_SCHREIBEN_STATUS`.
* **Block Framing**: Differential execution under Unicorn proved that `FLASH_SCHREIBEN` blocks are formatted with a strict **21-byte header**, followed by the chunk payload and a `0x03` terminator byte:
  ```text
  01 01 00 00 | 00 00 00 00 | 00 FF 00 00 | 00 | [len LE16] | [len LE16] | [addr LE32] | [payload...] | 03
  ```
  *(Notice: The payload length is stored twice as LE16, and the target address is little-endian).*
* **XXL Threshold**: Blocks with size $> 254$ bytes dynamically switch to the `FLASH_SCHREIBEN_XXL` job. Reconstructed in [`reconstruction/vdle/core.py`](reconstruction/vdle/core.py).

### 7.4 EDIABAS Interface & OBD IFH Driver
* `OBD32.dll` implements diagnostic telegram transport over serial K-Line and D-CAN interfaces.
* Reconstructs port initialization, 9600 8E1 (DS2) and 115200 8N1 (KWP) communication, P4 inter-message gaps, telegram framing, and longitudinal redundancy XOR checksum validation. Reconstructed in [`reconstruction/obd_ifh.py`](reconstruction/obd_ifh.py).

### 7.5 Safety Gates & Hard-Gated Interlocks
Flash execution is hard-gated by the `SafetyContext` and provenance-tracked `Limits` structure:
* Refuses execution without a valid limits policy file bound by SHA-256 digest.
* Continuously checks battery voltage ($V_{bat}$), ignition status, programming voltage flags, and ZB number assembly match before sending the first byte to the ECU. Reconstructed in [`reconstruction/safety/hypotheses.py`](reconstruction/safety/hypotheses.py).

### 7.6 Offline Flash Image & Calibration Reconnaissance (Milestone 5.18)
* **Scope**: Pure offline structural reconnaissance of BMW E60 / GKE195 flash artifacts (`A7592133.0da`, `7591971A.0pa`, `GKE195.DAT`). Zero hardware I/O; zero source file mutation.
* **Intel Hex Dual Addressing**: Parsed standard records (`00`, `01`, `02`, `04`) and BMW custom block trailers (`0x10`), mapping 173,088 payload bytes across 6 calibration segments.
* **Structural Candidates**: Discovered 2,952 monotonic axis candidates (16-bit little-endian) and 7,786 candidate 1D/2D calibration tables.
* **Distinction**: All detected tables are classified as **STRUCTURAL MAP CANDIDATES** with provenance `[R]`; none are promoted to SEMANTICALLY IDENTIFIED MAPS. Engineering units remain strictly `UNKNOWN` `[U]` pending external A2L/ASAP2 calibration definitions.
* **Checksum & CVN Verification**: Confirmed CARB Mode $09 CVN `0000F41E` at binary offset `0x000500EE` `[C]`, file addition checksum `$CHECKSUMME 2352 H` `[C]`, and RSA-1024 bootloader signature at `0x00050000` `[C]`.
* Reconstructed in [`reconstruction/calibration/`](reconstruction/calibration/) and documented in [`docs/evidence/flash_image_calibration_reconnaissance_milestone_5_18.md`](docs/evidence/flash_image_calibration_reconnaissance_milestone_5_18.md).

### 7.7 Forensic Provenance Resolution of ZB 7592132 & Software Lineage (Milestone 5.19)
* **Scope**: Pure offline forensic resolution of BMW E60 530d LCI (M57D30TU2 / ZF 6HP28) EGS software lineage and flash artifacts. Zero hardware access; zero source mutation.
* **Assembly ZB 7592132**: Verified as BMW Software Assembly Part Number (`ZB-Nummer` / `ZUSB` / `Zusammenbaunummer`), NOT a serial number. Mapped to SGBD `GKE195` (address `0x18`), programmed HW `7591972` (IDENT `0x1A 0x80`), physical mechatronic HW `7569980` (`0x1A 0x87`), and software `7592133DA`.
* **Target Calibration Artifact**: `A7592133.0da` is definitively proven as the target calibration image for `E60 M57D30TU2` (Option 205 Steptronic), matching physical bench AIF (`ZB 7592132`, `SW 7592133`), IDENT (`1A 80`), and ZIF (`0479S90T641Z`).
* **Associated Base Executive Lineage**: `7591971A.0pa` is classified as `RELATED_BASE_PROGRAM_GS19_11` / `DONOR_REFERENCE`. It represents the shared ZF GS19.11 mechatronic executive architecture; its internal descriptor tables point directly to the calibration segments of `A7592133.0da`. Its presence in the repository does not imply the vehicle uses a 6HP19 transmission.
* **SGBD Corpus Analysis**: Confirms `GKE195` for heavy-torque ZF 6HP28 (750 Nm) and `GKE215` for medium-torque 6HP19TU/21 (450 Nm). An exhaustive search across the BMW SP-Daten, EDIABAS, and KMM corpus found zero occurrences of `GKE196`.
* Reconstructed in [`reconstruction/ecu/`](reconstruction/ecu/) and documented in [`docs/evidence/zb_7592132_egs_software_lineage_milestone_5_19.md`](docs/evidence/zb_7592132_egs_software_lineage_milestone_5_19.md).

### 7.8 EGS 6HP28 Calibration Map Reconstruction (Milestone 5.20)
* **Scope**: Offline structural calibration map reconstruction for target BMW E60 / M57D30TU2 / ZF 6HP28 (`GKE195`). Zero hardware I/O.
* **Segment 4 Pointer Directory**: Audited the canonical 36,704-byte table (`0x00076000 - 0x0007EF60`), establishing 9,176 Big-Endian 32-bit entries indexing calibration payload objects across Segments 1, 2, and 3.
* **Structural Map and Axis Categorization**: Recovered 7,786 structural table candidates and 2,952 monotonic breakpoint sequences, defining candidate axis-table associations.
* Reconstructed in [`reconstruction/calibration/recon_v520.py`](reconstruction/calibration/recon_v520.py) and documented in [`docs/evidence/calibration_map_reconstruction_milestone_5_20.md`](docs/evidence/calibration_map_reconstruction_milestone_5_20.md).

### 7.9 Calibration Object Validation & Semantic Reconstruction (Milestone 5.21)
* **Scope**: Pure offline validation of calibration objects, code/descriptor references, axis ownership, runtime execution roles, and scaling constants. Zero hardware access; zero source mutation.
* **Segment 4 Accounting Identities**: Replaced heuristics with exact mathematical identities:
  $$\text{directory\_entries (9,176)} = \text{unique\_target\_addresses (6,017)} + \text{alias\_entries (3,159)}$$
  $$\text{directory\_entries (9,176)} = \text{payload\_pointers (8,451)} + \text{indirect\_directory\_pointers (720)} + \text{gap\_pointers (5)}$$
* **Map Descriptor Block Discovered at `0x000454A0`**: In base program `7591971A.0pa`, a formal multi-axis descriptor block binds:
  - **Axis X:** `0x00063AD6` (12-point signed monotonic array `[-10, 50, ..., 700]`) [PROVEN]
  - **Axis Y:** `0x00063AF0` (8-point unsigned monotonic array `[100, 1500, ..., 5500]`) [PROVEN]
  - **Table Payload:** `0x0006418A` ($12 \times 8 = 96$ word 2D table, 24 bytes/row stride) [PROVEN]
* **7-Stage Runtime Execution Pipeline**: Reconstructed the end-to-end execution chain with partitioned confidence:
  $$\text{INPUT} \longrightarrow \text{INDEX} \longrightarrow \text{AXIS LOOKUP} \longrightarrow \text{TABLE ACCESS} \longrightarrow \text{INTERPOLATION} \longrightarrow \text{SCALE/OFFSET} \longrightarrow \text{OUTPUT}$$
  - `pipeline_definition`: **`PROVEN`** (Mathematically and structurally verified).
  - `structural_pipeline`: **`STRONGLY_SUPPORTED`** (Descriptor bindings and geometry).
  - `runtime_execution_pipeline`: **`UNCONFIRMED`** (Stages 4, 6, 7 lack dynamic instruction traces).
  - Overall Execution Role: **`SUPPORTED`**.
* **Tri-Layer Scaling Constants Separation**: Strict segregation of numeric constants into Layer A (Binary Evidence), Layer B (External Corroboration), and Layer C (Semantic Hypothesis):
  - `0x02EE` (750): Layer A binary uint16; Layer B ZF 6HP28 750 Nm capacity (5x occurrences match 5 shift elements); Layer C `transmission_torque_related` [SUPPORTED].
  - `0x01F4` (500): Layer A binary uint16; Layer B BMW M57D30TU2 500 Nm rating; Layer C `engine_torque_related` [SUPPORTED].
  - `0x1A90` (6800): Layer A binary uint16; Layer B external gas-engine/turbine overspeed context; Layer C strictly **`UNKNOWN`** [UNCONFIRMED].
* **Strict Epistemic Ceilings & Negative Evidence**:
  - $10 \times 13$ tables (260 bytes @ 16-bit) remain strictly **`UNCONFIRMED`** dimensional matches without speculative "shift map" claims.
  - Flash boundary gap pointers (`0x0005FFF4`, `0x0005FFFE`) and false monotonic ASCII strings are explicitly preserved as **`REJECTED`**.
  - All 12 mandatory JSON artifacts plus comprehensive manifest [artifact_manifest_v521.json](file:///Users/blogman/winkfp-research/artifacts/calibration/artifact_manifest_v521.json) generated deterministically.
* Reconstructed in [`reconstruction/calibration/recon_v521.py`](reconstruction/calibration/recon_v521.py) and documented in [`docs/evidence/calibration_object_validation_milestone_5_21.md`](docs/evidence/calibration_object_validation_milestone_5_21.md).

---

## 8. Repository Layout

```text
winkfp-research/
├── artifacts/                      # Reconstructed deterministic JSON artifacts
│   └── calibration/                # Milestone 5.20 and 5.21 calibration catalogs & manifests
├── docs/                           # Technical documentation & RE reports
│   ├── ARCHITECTURE.md             # End-to-end system architecture
│   ├── EVIDENCE.md                 # L0–L7 experimental validation framework
│   ├── METHODOLOGY.md              # Reverse engineering & differential methods
│   ├── PROPRIETARY_MATERIAL.md     # Policy on excluded OEM assets
│   ├── QUARANTINE.md               # Audit history & asset filtering
│   ├── research-source-map.md      # Mapping to historical source workspace
│   ├── evidence/                   # Forensic milestone evidence artifacts (5.0–5.21)
│   ├── history/                    # Historical research progression (Rev 1–18.1)
│   └── reverse-engineering/        # In-depth subsystem specifications
├── analysis/                       # Ghidra decompilation artifacts (45 C files)
│   ├── crypto/                     # Symmetric, asymmetric, and simple algorithms
│   ├── auth/                       # GetAuthKey and AS2 container loaders
│   ├── vdle/                       # VDLE orchestration, block framing, OPPS
│   ├── ediabas/                    # EDIABAS runtime and API handlers
│   └── obd32/                      # OBD32.dll IFH serial driver
├── reconstruction/                 # Clean-room Python protocol implementations
│   ├── calibration/                # Hex parser, canonical index, axis validation, semantic recon
│   ├── crypto/                     # Symmetric MD5, RSA-1024, Simple XOR
│   ├── auth/                       # AS2 3DES parser, key store, retry chain
│   ├── vdle/                       # VDLE flash engine, block builder, OPPS setup
│   ├── ediabas/                    # CanonicalPipeline, ReplayEngine, SGBD decoders, Transport
│   ├── transport/                  # K+DCAN framing, serial transport, adapter, mock backend
│   ├── safety/                     # SafetyContext, Limits policy, interlocks
│   └── runner.py                   # Master FlashRunner orchestration engine
├── tests/                          # Automated verification suites
│   ├── kat/                        # Known-answer tests (crypto, auth, keys, probe)
│   ├── golden/                     # Golden tests (state machine, pipeline, replay, calibration)
│   ├── differential/               # Differential suites (Unicorn x86, SGBD parity)
│   ├── fixtures/                   # Synthetic containers, limits, and images
│   └── run_tests.py                # Master test runner (256 tests)
├── tools/                          # Analysis, diffing, and probe tools
│   ├── kdcan_hardware_probe.py     # Safe read-only physical hardware probe
│   ├── run_calibration_reconstruction_v520.py # Milestone 5.20 calibration reconstruction CLI
│   ├── run_calibration_validation_v521.py     # Milestone 5.21 validation CLI
│   ├── bench_diff/                 # L1/L2 event log differential runner
│   ├── trace_parser/               # EDIABAS *.trc parser and VIN sanitizer
│   └── analysis/                   # Master password decoder & SP-Daten scanner
├── traces/                         # Sanitized and physical event logs
│   ├── sanitized/                  # Privacy-sanitized EDIABAS factory traces
│   ├── hardware/                   # Immutable physical bench traces (SHA-256 bound)
│   └── expected/                   # Standardized benchmark JSONL logs
└── examples/                       # Runnable demonstration scripts
    ├── synthetic_auth/             # Key derivation demo with synthetic vectors
    ├── vdle/                       # VDLE block framing and mock flashing demo
    └── differential/               # Bench log differential comparison demo
```

---

## 9. Reproducibility & Test Execution

### Prerequisites
- Python 3.10 or newer (tested through Python 3.14).
- *Optional for differential execution*: `unicorn` and `pefile` (`pip install unicorn pefile`).

### Running the Test Suite
The repository includes a unified master test runner executing all verification tiers:

```bash
# Run all verification suites (KAT, Golden, Differential):
.venv/bin/python3 tests/run_tests.py
```

Current test execution summary:
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          : 178 run, 178 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 257 tests in ~54s | 257 passed | 0 skipped | 0 failed
======================================================================
```

### Running Runnable Examples
All examples operate fully independently using synthetic data fixtures:

```bash
# 1. Cryptographic Authentication Demo:
.venv/bin/python3 examples/synthetic_auth/demo_auth.py

# 2. VDLE Flash Engine & Block Framing Demo:
.venv/bin/python3 examples/vdle/demo_vdle.py

# 3. Differential Event Log Comparison Demo:
.venv/bin/python3 examples/differential/demo_diff.py
```

---

## 10. Responsible Disclosure & Security

Automotive control systems operate safety-critical vehicle dynamics. Flashing untrusted code or corrupting non-volatile flash memory can render a vehicle inoperable or unsafe.
- Review [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidelines and safety policies.
- Always observe strict battery voltage maintenance and programming preconditions.

---

## 11. Citation & Academic Attribution

If you utilize this research, reverse-engineering methodology, or reconstructed protocol stack in academic work or software engineering projects, please cite:

```bibtex
@misc{winkfp_research_2026,
  author = {winkfp-research contributors},
  title = {WinKFP Reverse Engineering & Protocol Reconstruction Archive},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/Arkayda}}
}
```
See [`CITATION.cff`](CITATION.cff) for full machine-readable metadata.

---

## 12. License & Legal Notice

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE) for details.

*BMW, WinKFP, EDIABAS, and INPA are registered trademarks of Bayerische Motoren Werke AG (BMW AG). This research repository is an independent reverse-engineering study conducted for interoperability, protocol analysis, and educational purposes under applicable legal provisions. This project is NOT affiliated with, sponsored by, or endorsed by BMW AG or ZF Friedrichshafen AG.*
