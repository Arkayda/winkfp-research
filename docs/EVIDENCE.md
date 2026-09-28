# Evidence Model & Verification Status

This document defines the epistemological framework used across `winkfp-research` to classify technical claims, validation levels, and experimental findings.

---

## 1. Evidence Hierarchy (L0 to L7)

The project employs an eight-tier validation scale:

| Level | Designation | Description | Verification Criterion |
|---|---|---|---|
| **L0** | **Static observation** | Raw strings, symbol names, table entries, or PE header fields seen in disassembled binaries. | Verified presence in binary image at documented offset. |
| **L1** | **Decompiled / disassembled behavior** | Control flow and data structures analyzed via Ghidra/IDA decompiler output. | Documented C pseudocode with cross-references to original virtual addresses in `analysis/`. |
| **L2** | **Independent reconstruction** | Reimplementation of algorithms and protocols in clean, autonomous Python. | Code runs autonomously without proprietary OEM dependencies in `reconstruction/`. |
| **L3** | **Known-answer / execution validation** | Deterministic test vectors comparing inputs and outputs of reconstructed algorithms. | Passes deterministic unit tests (KAT suites and golden state machines). |
| **L4** | **Differential trace validation** | Execution of original OEM machine code under CPU emulation (Unicorn x86) compared against reconstruction. | Event-for-event and byte-for-byte exact equality between original binary and reconstruction. |
| **L5** | **Real EDIABAS integration** | Reconstructed engine interacting with the standard EDIABAS API (`api32.dll`) or parsing real production traces. | Seamless execution against EDIABAS boundary or bit-for-bit replay of historical EDIABAS trace files. |
| **L6** | **Real ECU contact** | Read-only diagnostic handshake (identification, authentication negotiation, session status) on a physical ECU bench. | Real hardware CAN / K-Line transceiver trace demonstrating accepted diagnostic session. |
| **L7** | **Real ECU programming** | Complete flashing of an ECU firmware block on a physical vehicle or hardware bench. | Successful post-flash verification, execution of flashed code, and ECU operational restart. |

---

## 2. Subsystem Validation Matrix

The following table documents the **highest proven evidence level** achieved in this research repository for each major subsystem:

| Subsystem | Highest Level | Current Status | Ground Truth Source & Verification Artifact |
|---|:---:|---|---|
| **KrApi: Symmetric Auth (MD5)** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004b9f50` emulated in Unicorn vs `reconstruction/crypto/symmetric/`. Byte-exact matching. |
| **KrApi: Simple Cipher** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004ba1b0` / `004ba080` emulated in Unicorn vs `reconstruction/crypto/simple/`. Byte-exact matching. |
| **KrApi: Static Asymmetric Auth (RSA-1024)** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004b9e30` / `004bb780` emulated in Unicorn vs `reconstruction/crypto/asymmetric/` with 128-byte public modulus/exponent. Proven in `tests/differential/auth/`. |
| **AS2 Container: Asymmetric Key (RSA-512)** | **L4** | `VALIDATED` | Container-derived 136-byte RSA-512 key blobs parsed via `reconstruction/as2_keys.py` and validated against binary `FUN_004bd0e0` / `FUN_004b8bc0`. |
| **KrApi: MSVC RNG** | **L4** | `VALIDATED` | Original `FUN_005cafa9` / `005cafbb` LCG step emulated in Unicorn; canonical vector `srand(1) -> 41` verified. |
| **Key Containers: AS2 Grammar & 3DES** | **L4** | `VALIDATED` | Original `FUN_004b8fe0` (`GetAuthKey`) executed under Unicorn with OS IAT hooks, reading `$K` records vs `reconstruction/as2_keys.py`. |
| **VDLE: INIT_VDLE & OPPS Setup** | **L4** | `VALIDATED` | Original `FUN_004a5b60` emulated in Unicorn against mock EDIABAS; event stream identical across DF1–DF11. |
| **VDLE: Block Framing (21-byte header)** | **L4** | `VALIDATED` | Original `FUN_004668b0` execution traces confirm 21-byte header (`01 01 00 00 ...`) and LE/BE address/size fields. |
| **VDLE: Chunking & XXL Threshold** | **L4** | `VALIDATED` | `FLASH_SCHREIBEN_XXL` selection threshold (`blocksize > 0xFE`) proven on live boundary; tail chunks verified. |
| **VDLE: WAS / RESEND_SEGMENT Recovery** | **L4** | `VALIDATED` | Original failure handling (`DF8`–`DF11`) reproduces in-session failure latching and resume logic. |
| **TesterPresent / Keep-Alive** | **L4** | `VALIDATED` | Original `FUN_004a5960` synchronous single-threaded scheduler verified under Unicorn across 8 failure/success branches. |
| **OBD32 / IFH K-Line Driver** | **L4** | `VALIDATED` | Original `OBD32.dll` machine code running in Unicorn driving virtual serial port matches `reconstruction/obd_ifh.py`. |
| **EDIABAS API Layer** | **L5** | `VALIDATED` | Parsing and diffing real production `api.trc` (2.4 MB flash session) using `tools/bench_diff/`. |
| **Safety Interlocks (`ID_CHECK`)** | **L2** | `INFERRED` | Binary conditions parsed; parameter thresholds are documented as engineering hypotheses (`Limits`). |
| **Physical ECU Contact (Read-Only)** | **L6** | `VALIDATED` | Read-only diagnostic identification query set executed on physical ZF 6HP EGS bench (target `0x18`) via K+DCAN (`115200 8N1`). Verified by immutable trace fixtures in `traces/hardware/`: `20260926_174811_egs_ident.json` (`IDENT`), `20260926_175924_egs_physical_hw_nr.json` (`PHYSIKALISCHE_HW_NR_LESEN`), `20260926_173201_egs_aif.json` (`AIF_READ_BENCH_ALIAS`), `20260926_174033_egs_tester_present.json` (`TESTER_PRESENT`), Milestone 5.16 physical correlation of official `AIF_LESEN` (`0x23`), and Milestone 5.17 physical correlation batch (`SERIENNUMMER_LESEN`, `ZIF_LESEN`, `ZIF_BACKUP_LESEN`). |
| **Physical ECU Reprogramming** | **L7** | **Not validated** | Complete flashing of an ECU firmware block on a physical vehicle or hardware bench. No physical vehicle or bench ECU flashing, erase, reset, or flash writing has been performed. Strictly not validated. |

---

## 3. Subsystem Demarcation: Diagnostic Runtime vs Flash Orchestration Model

The repository establishes an explicit provenance and operational boundary between two fundamentally different codebases:

### 3.1 Canonical Read-Only Diagnostic Runtime (`reconstruction/ediabas/`, `reconstruction/transport/kdcan/`)
- **Evidence Level**: **L6** (Physical bench proven) & **L5** (Historical trace replay).
- **Subsystems**: `CanonicalPipeline`, `EdiabasJobReplayEngine`, `DiagnosticTransport`, `KdcanDiagnosticAdapter`, `SerialKdcanTransport`.
- **Hardware Contact**: Validated on physical ZF 6HP EGS bench (target `0x18`) over K+DCAN (`115200 8N1`).
- **Permitted Operations (Physical L6 Scope)**: Strictly read-only identification queries confirmed on physical hardware: `IDENT` (`1A 80`), `PHYSIKALISCHE_HW_NR_LESEN` (`1A 87`), official `AIF_LESEN` (`0x23`), `AIF_READ_BENCH_ALIAS` (`1A 86`), `SERIENNUMMER_LESEN` (`1A 89`), `ZIF_LESEN` (`22 2503`), `ZIF_BACKUP_LESEN` (`22 2500`), and `TESTER_PRESENT` observation (`3E 00`).
- **AIF Job Disambiguation**:
  - `AIF_LESEN`: Official SGBD routine utilizing KWP2000 service `$23 00 00 00 07 12` (`ReadMemoryByAddress`). Confirmed via SGBD disassembly and physically validated on target hardware in Milestone 5.16 (SID `$63`, ZB `7592132`, Date `04.12.2008`).
  - `AIF_READ_BENCH_ALIAS`: Physical bench query utilizing service `$1A 0x86` (`ReadECUIdentification`). Observed and byte-for-byte fixture-validated against physical ZF 6HP EGS bench hardware (`20260926_173201_egs_aif.json`). Not equivalent to official SGBD `AIF_LESEN`.
- **Safety Interlocks**: Serial ports quarantined (`auto_open=False` default); explicit `--confirm-readonly-hardware` required; single-transaction enforcement (TX=1, RX=1, retries=0); fail-closed on unevidenced targets or unmapped jobs.

### 3.2 Reconstructed Flash Orchestration Model (`reconstruction/runner.py`, `reconstruction/vdle/`, `reconstruction/auth/`)
- **Evidence Level**: **L4** (Differential x86 emulation in Unicorn) & **L3** (Deterministic KAT test vectors).
- **Subsystems**: `FlashRunner`, `VDLE` chunking engine, `KrApi` symmetric/asymmetric authentication, AS2 key parser.
- **Hardware Contact**: **L7 UNVALIDATED**: Zero physical vehicle or bench ECU flashing, zero erase, zero write.
- **Role**: Clean-room offline research and interoperability model of proprietary WinKFP flashing algorithms.
- **Safety Boundary**: Prohibited from dispatching against physical hardware; flash write jobs (`FLASH_SCHREIBEN`, `FLASH_LOESCHEN`, `SEND_SEGMENT`) are blocked fail-closed before wire transmission.

---

## 4. Explicit Hardware Scope Disclaimer

> [!WARNING]
> While software differential tests against original BMW machine code achieve **L4**, trace parsers achieve **L5**, and read-only diagnostic identification queries on physical bench hardware achieve **L6**, **physical ECU reprogramming (L7) has NOT been validated on physical hardware in this repository**.
>
> All write, flash block download (`0x34`, `0x36`, `0x37`), memory erase (`0x31 0x01` / `0x31 0x02`), ECU reset (`0x11`), session transition (`0x10`), and security access / routine authentication (`0x27`, `0x31 0x07`, `0x31 0x08`) operations remain **STRICTLY EXCLUDED** from the runtime and are blocked fail-closed before any dispatch. Reconstructed code should be treated as reverse-engineering prototypes, NOT production flasher software.
