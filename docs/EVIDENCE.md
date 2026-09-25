# Evidence Model & Verification Status

This document defines the epistemological framework used across `winkfp-research` to classify technical claims, validation levels, and experimental findings.

---

## 1. Evidence Hierarchy (L0 to L7)

The project employs an eight-tier validation scale:

| Level | Designation | Description | Verification Criterion |
|---|---|---|---|
| **L0** | **Static Observation** | Raw strings, symbol names, table entries, or PE header fields seen in disassembled binaries. | Verified presence in binary image at documented offset. |
| **L1** | **Decompiled Behavior** | Control flow and data structures analyzed via Ghidra/IDA decompiler output. | Documented C pseudocode with cross-references to original virtual addresses. |
| **L2** | **Independent Reconstruction** | Clean-room reimplementation of algorithms and protocols in Python. | Code runs autonomously without proprietary OEM dependencies. |
| **L3** | **Known-Answer Test (KAT)** | Deterministic test vectors comparing inputs and outputs of reconstructed algorithms. | Passes deterministic unit tests (e.g., FIPS test vectors, fixed cryptographic seeds). |
| **L4** | **Differential Trace Validation** | Execution of original OEM machine code under CPU emulation (Unicorn) compared against reconstruction. | Event-for-event and byte-for-byte exact equality between original binary and reconstruction. |
| **L5** | **Real EDIABAS Integration** | Reconstructed engine interacting with the standard EDIABAS API (`api32.dll`) or parsing real production traces. | Seamless execution against EDIABAS boundary or bit-for-bit replay of historical EDIABAS trace files. |
| **L6** | **Physical ECU Contact** | Read-only diagnostic handshake (identification, authentication negotiation, session status) on a physical ECU bench. | Real hardware CAN / K-Line transceiver trace demonstrating accepted diagnostic session. |
| **L7** | **Physical ECU Reprogramming** | Complete flashing of an ECU firmware block on a physical vehicle or hardware bench. | Successful post-flash verification, execution of flashed code, and ECU operational restart. |

---

## 2. Subsystem Validation Matrix

The following table documents the **highest proven evidence level** achieved in this research repository for each major subsystem:

| Subsystem | Highest Level | Current Status | Ground Truth Source & Verification Artifact |
|---|:---:|---|---|
| **KrApi: Symmetric Auth (MD5)** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004b9f50` emulated in Unicorn vs `reconstruction/crypto/symmetric/`. Byte-exact matching. |
| **KrApi: Simple Cipher** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004ba1b0` / `004ba080` emulated in Unicorn vs `reconstruction/crypto/simple/`. Byte-exact matching. |
| **KrApi: Asymmetric Auth (RSA-512)** | **L4** | `VALIDATED` | Original `winkfpt.exe` `FUN_004b9e30` / `004bb780` emulated in Unicorn vs `reconstruction/crypto/asymmetric/`. Proven in `tests/differential/auth/`. |
| **KrApi: MSVC RNG** | **L4** | `VALIDATED` | Original `FUN_005cafa9` / `005cafbb` LCG step emulated in Unicorn; canonical vector `srand(1) -> 41` verified. |
| **Key Containers: AS2 Grammar & 3DES** | **L4** | `VALIDATED` | Original `FUN_004b8fe0` (`GetAuthKey`) executed under Unicorn with OS IAT hooks, reading `$K` records vs `reconstruction/auth/key_containers/`. |
| **VDLE: INIT_VDLE & OPPS Setup** | **L4** | `VALIDATED` | Original `FUN_004a5b60` emulated in Unicorn against mock EDIABAS; event stream identical across DF1–DF11. |
| **VDLE: Block Framing (21-byte header)** | **L4** | `VALIDATED` | Original `FUN_004668b0` execution traces confirm 21-byte header (`01 01 00 00 ...`) and LE/BE address/size fields. |
| **VDLE: Chunking & XXL Threshold** | **L4** | `VALIDATED` | `FLASH_SCHREIBEN_XXL` selection threshold (`blocksize > 0xFE`) proven on live boundary; tail chunks verified. |
| **VDLE: WAS / RESEND_SEGMENT Recovery** | **L4** | `VALIDATED` | Original failure handling (`DF8`–`DF11`) reproduces in-session failure latching and resume logic. |
| **TesterPresent / Keep-Alive** | **L4** | `VALIDATED` | Original `FUN_004a5960` synchronous single-threaded scheduler verified under Unicorn across 8 failure/success branches. |
| **OBD32 / IFH K-Line Driver** | **L4** | `VALIDATED` | Original `OBD32.dll` machine code running in Unicorn driving virtual serial port matches `reconstruction/ediabas/ifh/`. |
| **EDIABAS API Layer** | **L5** | `VALIDATED` | Parsing and diffing real production `api.trc` (2.4 MB flash session) using `tools/bench_diff/`. |
| **Safety Interlocks (`ID_CHECK`)** | **L2** | `INFERRED` | Binary conditions parsed; parameter thresholds are documented as engineering hypotheses (`Limits`). |
| **Physical ECU Contact** | **L6** | **NOT YET VALIDATED** | Hardware bench harness implemented in `tools/bench_diff/bench_scenario.py`, but physical bench execution is pending. |
| **Physical ECU Reprogramming** | **L7** | **NOT YET VALIDATED** | No claim of vehicle or bench flashing is made. Physical flashing is strictly on the future hardware roadmap. |

---

## 3. Explicit Hardware Scope Disclaimer

> [!WARNING]
> While software differential tests against original BMW machine code achieve **L4** and trace parsers achieve **L5**, **no physical ECU contact (L6) or ECU flashing (L7) has been performed in this repository**.
>
> All test results documented herein reflect software emulation, pure-Python execution, and differential comparisons against captured trace files. Reconstructed code should be treated as reverse-engineering prototypes, NOT production flasher software.
