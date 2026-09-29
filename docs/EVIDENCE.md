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
| **Calibration Object Validation (5.20/5.21)** | **L2** (Code) / **L3** (KAT/Golden) | `VALIDATED (OFFLINE)` | Pure offline reconstruction of 9,176 Segment 4 objects, multi-axis descriptor at `0x000454A0`, 7-stage execution pipeline, and tri-layer scaling in `reconstruction/calibration/`. Zero hardware I/O. |
| **Calibration Runtime Code-Path (5.22)** | **L2** (Code) / **L3** (Golden) | `VALIDATED (OFFLINE)` | Static executable code-path, TriCore instruction model, 1D curve topology refinement at `0x000454A0`, 10-node execution graph, false-positive filtering in `reconstruction/calibration/`. Zero hardware I/O. |
| **Calibration Function Reconstruction (5.23)** | **L2** (Code) / **L3** (Golden) | `VALIDATED (OFFLINE)` | Calibration code candidate `CALCODE_CANDIDATE_0001`, basic block entry at `0x00086000`, callgraph, register flow, 1D curve-to-axis domain pairing, machine arithmetic, and negative evidence in `reconstruction/calibration/`. Zero hardware I/O. |
| **Descriptor Consumer Discovery (5.24)** | **L2** (Code) / **L3** (Golden) | `VALIDATED (OFFLINE)` | Exhaustive TriCore instruction scanner across Segments 8..15, candidate classification, false-positive control, secondary candidate array evaluation, and Stop Condition Case C confirmation in `reconstruction/calibration/`. Zero hardware I/O. |
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

### 3.3 EGS 6HP28 Target Provenance vs Shared GS19.11 Base Lineage (Milestones 5.18 & 5.19)
- **Target ECU Provenance**: BMW E60 530d LCI (M57D30TU2, GA6HP28Z, 750 Nm rating, Option 205 Steptronic). Target assembly part number: `ZB 7592132` (`ZUSB` / `Zusammenbaunummer`), accompanied by programmed HW `7591972` (IDENT `0x1A 0x80`), physical mechatronic HW `7569980` (`0x1A 0x87`), and software `7592133DA`.
- **Target Calibration Artifact**: `A7592133.0da` is definitively proven as the target calibration data for `E60 M57D30TU2`, verified against the physical bench EGS AIF, IDENT, and ZIF (`0479S90T641Z`).
- **Associated/Shared GS19.11 Base Executive Lineage**: `7591971A.0pa` is classified as `RELATED_BASE_PROGRAM_GS19_11` / `DONOR_REFERENCE`. It represents the shared ZF GS19.11 mechatronic executive architecture; its internal descriptor tables point directly to the calibration segments of `A7592133.0da`. Its presence in the repository does not imply the target vehicle has a 6HP19 transmission.
- **SGBD Families**: `GKE195` (heavy-torque 6HP28) vs `GKE215` (medium-torque 6HP19TU/21). An exhaustive search across the BMW SP-Daten, EDIABAS, and KMM corpus found zero occurrences of `GKE196`.

### 3.4 Calibration Object Validation & Semantic Reconstruction (Milestones 5.20 & 5.21)
- **Target Calibration Artifact**: `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`).
- **Associated Base Executive Reference**: `spdaten_gke/E60/data/GKE215/7591971A.0pa` strictly as `RELATED_BASE_PROGRAM_GS19_11 / DONOR_REFERENCE`.
- **Segment 4 Pointer Directory**: Load address canonically proven as `0x00076000 - 0x0007EF60` (36,704 bytes, 9,176 entries). Exact accounting: $9,176 = 6,017\text{ unique} + 3,159\text{ aliases} = 8,451\text{ payload} + 720\text{ indirect directory} + 5\text{ gap pointers}$.
- **Multi-Axis Map Descriptor**: Block at `0x000454A0` in base program binds Axis X (`0x00063AD6`, 12-pt signed), Axis Y (`0x00063AF0`, 8-pt unsigned), and Table (`0x0006418A`, 12x8 elements, 96 words).
- **7-Stage Runtime Execution Pipeline**: $\text{INPUT} \rightarrow \text{INDEX} \rightarrow \text{AXIS LOOKUP} \rightarrow \text{TABLE ACCESS} \rightarrow \text{INTERPOLATION} \rightarrow \text{SCALE/OFFSET} \rightarrow \text{OUTPUT}$. Partitioned confidence: `pipeline_definition: PROVEN`, `structural_pipeline: STRONGLY_SUPPORTED`, `runtime_execution_pipeline: UNCONFIRMED`, `overall_role: SUPPORTED`.
- **Tri-Layer Scaling Separation**: Layer A (Binary Evidence), Layer B (External Corroboration), Layer C (Semantic Hypothesis). Constant 6800 Layer C is strictly `UNKNOWN` (`UNCONFIRMED`); external turbine overspeed discussions relegated to Layer B.
- **Epistemic Discipline**: $10 \times 13$ tables remain `UNCONFIRMED` dimensional matches; boundary gap pointers (`0x0005FFF4`, `0x0005FFFE`) and false monotonic strings are cataloged as `REJECTED`. 100% offline, zero hardware I/O.

### 3.5 Calibration Runtime & Code-Path Reconstruction (Milestone 5.22)
- **Target Calibration Artifact**: `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`, 489,258 bytes, verified from local filesystem).
- **Associated Base Executive Reference**: `spdaten_gke/E60/data/GKE215/7591971A.0pa` (SHA-256: `63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3`, 1,942,502 bytes, verified from local filesystem) strictly as `RELATED_BASE_PROGRAM_GS19_11 / DONOR_REFERENCE`.
- **Processor Architecture & Code Regions**: Application firmware (Segments 8–15 in `7591971A.0pa`, `0x00080000`–`0x000FE8F0`) is proven Infineon TriCore TC1796 / TC1766 machine code. TriCore instruction length rule verified: `b0 & 1 == 0` specifies 16-bit (2-byte) instructions, `b0 & 1 == 1` specifies 32-bit (4-byte) instructions. Instructions are little-endian; data tables and calibration values are big-endian.
- **Physical Flash Segment Bounds**: Flash segment table at `0x00044240` definitively maps logical blocks to physical flash: Bootloader (`0x00030000`–`0x0004FFFB`, anchor `0x0004FFFC`), Calibration (`0x000500E8`–`0x00075FFF`, CARB CVN anchor `0x000500E4`), Application (`0x00080000`–`0x000FFEA7`, anchor `0x000FFEA8`).
- **Reference Graph Deepening & False-Positive Rejections**:
  - Raw 32-bit byte scans straddling instruction boundaries (`0x000F55A8`, `0x000F4ACE`) are proven instruction-boundary artifacts and rejected as `ALIGNMENT_ARTIFACT`.
  - Static records at `0x0004381C`, `0x0006D7BC`, and `0x0006D9AC` are classified as `STATIC_ADDRESS_TABLE` / data pointers, not code instructions.
- **`MAP_DESC_0001` Descriptor Bounds & 1D Curve Topology Refinement**:
  - Fields 2–11 at `0x000454A0` encode 5 explicit `[START, END]` bounding pairs with observed target-local object format in `A7592133.0da` ($\text{span} = \text{metadata} (2\text{ bytes}) + N \times 2\text{ bytes}$): Axis X (`0x00063AD6`–`0x00063AEF`, 26 B: 2 B header `0x000C` + 24 B payload = 12-pt signed int16 `[-10, 50, ..., 700]`, semantic status: `UNCONFIRMED`), Axis Y (`0x00063AF0`–`0x00063B01`, 18 B: 2 B header `0x0008` + 16 B payload = 8-pt unsigned uint16 `[100, 1500, ..., 5500]`, semantic status: `UNCONFIRMED`), Target 3 (`0x0006418A`–`0x000641A3`, 26 B: 2 B header `0x000C` + 24 B payload = 12-pt signed int16 `[-15, 50, ..., 700]`), Target 4 (`0x000641A4`–`0x000641BD`, 26 B: 2 B header `0x000C` + 24 B payload = 12-pt signed int16 `[70, 75, ..., 700]`), and Target 5 (`0x000641BE`–`0x000641CF`, 18 B: 2 B header `0x0008` + 16 B payload = 8-pt unsigned uint16 `[100, 1500, ..., 5500]`).
  - Target 3 is refined from the Milestone 5.20 $12 \times 8$ 2D table assumption into a **1D Characteristic Curve (`KL`)** of 12 points, resolving why 2D bilinear interpolation was unconfirmed in 5.21 (logged in `change_log_v522.json`). Targets 4 and 5 are likewise 1D curves.
- **10-Node Static Execution Graph**:
  $$\text{ENTRY} \rightarrow \text{INPUT} \rightarrow \text{AXIS\_SEARCH} \rightarrow \text{INDEX\_CALCULATION} \rightarrow \text{TABLE\_ADDRESS} \rightarrow \text{CELL\_READ} \rightarrow \text{INTERPOLATION} \rightarrow \text{SCALE\_OFFSET} \rightarrow \text{OUTPUT} \rightarrow \text{CONSUMER}$$
- **Strict Epistemic Ceilings & Confidence Partitioning**:
  - Axis interval search and index arithmetic: `STRONGLY_SUPPORTED`.
  - 1D linear piecewise interpolation structural support: `SUPPORTED`; runtime opcode execution: `UNCONFIRMED`.
  - Scaling constants (750, 500, 6800): Layer A binary uint16 verified; Layer C for 6800 remains strictly **`UNKNOWN / UNCONFIRMED`**.
  - Downstream output consumer: `UNCONFIRMED`.
  - 14 deterministic JSON artifacts generated in `artifacts/calibration/*v522*.json`. 100% offline, zero hardware I/O.

### 3.6 Calibration Function Reconstruction & Engineering Semantics (Milestone 5.23)
- **Target Calibration Artifact**: `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`, 489,258 bytes, verified from local filesystem).
- **Associated Base Executive Reference**: `spdaten_gke/E60/data/GKE215/7591971A.0pa` (SHA-256: `63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3`, 1,942,502 bytes, verified from local filesystem) strictly as `RELATED_BASE_PROGRAM_GS19_11 / DONOR_REFERENCE`.
- **Calibration Candidate Identity & Boundary**: Reconstructed `CALCODE_CANDIDATE_0001_AXIS_CURVE_LOOKUP` at code location `0x00086000` (proven `BASIC_BLOCK_ENTRY` reached by fallthrough from `0x00085FFE`; standalone procedure boundary `UNCONFIRMED`; verified callers list empty `[]` as adjacent instructions `0x00086002` [fallthrough] and `0x0009C580` [unaligned intra-instruction offset] were rejected as callers), consuming `MAP_DESC_0001` at `0x000454A0` and dispatch candidate tables at `0x0004BD00` / `0x0004BD80`.
- **Domain Linkages & Curve Dependencies**:
  - Target 1 (Axis X, 12 signed int16 points `[-10..700]` at `0x00063AD6`) serves as the input domain for Target 3 (Curve 1, 12 signed int16 points with negative boundary offset at `0x0006418A`) and Target 4 (Curve 2, 12 signed int16 points with bounded lower floor at `0x000641A4`).
  - Target 2 (Axis Y, 8 unsigned uint16 points `[100..5500]` at `0x00063AF0`) serves as the input domain for Target 5 (Curve 3, 8 unsigned uint16 points, identity transfer at `0x000641BE`).
  - Descriptor `MAP_DESC_0001` at `0x000454A0` holds exact 32-bit pointers resolving to Segment 6 target objects; synthetic `0x000455xx` addresses rejected as unmapped memory gap.
- **Machine Arithmetic & Transformation Pipeline**:
  - TriCore register flow traces input arguments `%d4` and `%d5` into axis search interval calculation.
  - Piecewise linear interpolation structure supported; machine opcode execution remains strictly `UNCONFIRMED`.
  - Scalar constants 750 (`0x00050612` repeated 5x) and 500 (`0x0005065A` / `0x0005066C`) verified in Segment 5 (historical labels `0x000505BA`/`0x000505BC` corrected); runtime clamp semantics downgraded to `UNCONFIRMED` due to absence of machine comparison/saturation instruction.
- **Strict Epistemic Ceilings & Negative Evidence**:
  - Downstream output consumer and physical engineering units remain strictly **`UNKNOWN / UNCONFIRMED`**.
  - Negative evidence cataloged in `rejected_semantic_hypotheses_v523.json` (2D KF map assumption, unevidenced RPM/torque labels, constant 6800 as proven turbine ceiling, 0x455xx synthetic targets, 0x86002/0x9C580 caller edges, unproven clamp semantics).
  - 18 deterministic JSON artifacts in `artifacts/calibration/*v523*.json` under non-circular manifest policy (`self_hash_policy: "EXCLUDED"`). 100% offline, zero hardware I/O.

### 3.7 Descriptor Consumer Discovery & Executable Consumer Reconstruction (Milestone 5.24)
- **Target Calibration Artifact**: `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`, 489,258 bytes, verified from local filesystem).
- **Associated Base Executive Reference**: `spdaten_gke/E60/data/GKE215/7591971A.0pa` (SHA-256: `63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3`, 1,942,502 bytes, verified from local filesystem) strictly as `RELATED_BASE_PROGRAM_GS19_11 / DONOR_REFERENCE`.
- **Declared Scanner Coverage**:
  - Full enumeration across explicitly declared reference-encoding classes (`MOVH_A`, `LEA`, `ADDIH_A`, `ADDI`, `BOL_OFF16`, `BO_OFF10`, `ABS_OFF18`, `RLC_CONST16`, `MOV_U`, `MOV_H`, `MOV`) and memory segments (Executable Segments 8–15: 511,856 bytes; Data Segments 0–7 in PA and 0–5 in DA).
  - Explicit three-category taxonomy: `unsupported_instruction_encodings` (`[]`), `unsupported_analysis_patterns` (`["DYNAMIC_INDIRECT_JUMP_TABLE", "MULTI_REGISTER_POLYNOMIAL_ARITHMETIC"]`), and `unsupported_address_generation_models` (`["UNMAPPED_PERIPHERAL_BUS_BRIDGE"]`).
- **Segment Numbering Reconciliation**:
  - Canonical 0-based IntelHexParser segment index is **Segment 2** (`0x00060000..0x0006FFF0`, 65,520 bytes, range semantics `[START, END)`); reconciled against historical 5.23 address-space high-nibble convention (`0x0006xxxx` -> "Segment 6") as a **`NUMBERING_SCHEME_DIFFERENCE`**.
- **Candidate References & False-Positive Control**:
  - 10 descriptor internal fields proven as big-endian pointers (`DATA_REFERENCE`).
  - Synthetic unmapped addresses `0x00045500..0x00045558` rejected as `REJECTED_SYNTHETIC_ADDRESS`.
  - Apparent offset `0x54C8` candidate at `0x000C1A04` (`st.b %d4, [%a15 + 0x54c8]`) formally rejected as `CONSTANT_COLLISION` (store into dynamic RAM structure via `%a15`, cannot reference read-only flash descriptor field).
- **Secondary Structure Candidates (Two-Level Epistemic Model)**:
  - Pointer arrays at `0x0004BD00` / `0x0004BD80` (PA Segment 4) and `0x0007CA50` / `0x0007CAC8` (DA Segment 4) verified under strict two-level model (`pointer_relationship = PROVEN`, `semantic_role = UNCONFIRMED`); classified strictly as `SECONDARY_STRUCTURE_CANDIDATE`.
- **Preservation of 0x00086000 Status**:
  - Retained strictly as `BASIC_BLOCK_ENTRY`, `procedure_identity = UNCONFIRMED`, `function_entry = UNCONFIRMED`, `verified_callers = []`.
- **Stop Condition Outcome: Case C Formally Confirmed**:
  - Under the declared scanner coverage, zero executable instructions reference `MAP_DESC_0001` or its fields.
  - Result: `case_result = CASE_C_NO_EXECUTABLE_CONSUMER`, `forensic_status = EXECUTABLE_CONSUMER_NOT_FOUND`.
  - All 8 deterministic JSON artifacts generated in `artifacts/calibration/*v524*.json`. 100% offline, zero hardware I/O.

---

## 4. Explicit Hardware Scope Disclaimer

> [!WARNING]
> While software differential tests against original BMW machine code achieve **L4**, trace parsers achieve **L5**, and read-only diagnostic identification queries on physical bench hardware achieve **L6**, **physical ECU reprogramming (L7) has NOT been validated on physical hardware in this repository**.
>
> All write, flash block download (`0x34`, `0x36`, `0x37`), memory erase (`0x31 0x01` / `0x31 0x02`), ECU reset (`0x11`), session transition (`0x10`), and security access / routine authentication (`0x27`, `0x31 0x07`, `0x31 0x08`) operations remain **STRICTLY EXCLUDED** from the runtime and are blocked fail-closed before any dispatch. Reconstructed code should be treated as reverse-engineering prototypes, NOT production flasher software.
