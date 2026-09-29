# Milestone 5.23 — Calibration Function Reconstruction & Engineering Semantics

**Milestone:** 5.23  
**Status:** COMPLETED & VERIFIED (PENDING HUMAN OPERATOR CHECKPOINT REVIEW)  
**Mode:** 100% OFFLINE ONLY — ZERO HARDWARE I/O  
**Target Vehicle:** BMW E60 / M57D30TU2 (235 PS / 500 Nm) / ZF 6HP28 (GA6HP26Z TU, GS19.11)  
**Target Calibration:** `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`, 489,258 bytes)  
**Reference Program Lineage:** `spdaten_gke/E60/data/GKE215/7591971A.0pa` (SHA-256: `63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3`, 1,942,502 bytes; strictly `RELATED_BASE_PROGRAM_GS19_11 / DONOR_REFERENCE`)

---

## 1. Executive Summary & Epistemic Statement

Milestone 5.23 elevates the reverse-engineering baseline from the static executable code-path model established in Milestone 5.22 to **concrete calibration code candidate (`CALCODE_CANDIDATE`) reconstruction**.

Through disciplined bottom-up tracing from the primary descriptor `MAP_DESC_0001` at `0x000454A0` and secondary dispatch candidates at `0x0004BD00` / `0x0004BD80`, this milestone proves:

1. **Target-Local Calibration Objects & Address Reconciliation**:
   - The actual calibration target objects reside in Segment 6 of calibration image `A7592133.0da`:
     * Axis X: `0x00063AD6` (12 signed int16 points, `[-10..700]`)
     * Axis Y: `0x00063AF0` (8 unsigned uint16 points, `[100..5500]`)
     * KL Curve 1: `0x0006418A` (12 signed int16 points, `[-15..700]`)
     * KL Curve 2: `0x000641A4` (12 signed int16 points, `[70..700]`)
     * KL Curve 3: `0x000641BE` (8 unsigned uint16 points, `[100..5500]`, identity transfer)
   - Descriptor `MAP_DESC_0001` at `0x000454A0` in `7591971A.0pa` Segment 3 stores the exact 32-bit big-endian bounding pointer pairs referencing these Segment 6 objects.
   - Addresses `0x00045500`, `0x00045518`, `0x00045528`, `0x00045540`, `0x00045558` fall into an unmapped memory gap in `7591971A.0pa` (between Segment 3 end `0x000454D0` and Segment 4 start `0x00045590`) and do not exist in `A7592133.0da`. They are formally rejected as synthetic offsets.

2. **Code Candidate Identity & Caller Validation**:
   - `0x00086000` is verified as an internal basic block entry (`BASIC_BLOCK_ENTRY`) reached by sequential fallthrough from `0x00085FFE`. Standalone procedure boundary remains `UNCONFIRMED` (`procedure_identity = UNCONFIRMED`, `function_entry = UNCONFIRMED`).
   - `0x00086002` is proven to be the second sequential instruction (+2) following the 2-byte instruction at `0x00086000` (`FALLTHROUGH`). It is **rejected as a caller**.
   - `0x0009C580` is an unaligned intra-instruction offset inside the 4-byte conditional branch at `0x0009C57E` and does not call `0x00086000`. It is **rejected as a caller**.
   - The verified callers list is strictly empty (`verified_callers = []`).

3. **Machine Arithmetic & Clamping Status**:
   - TriCore register flow traces input arguments `%d4` and `%d5` into axis search interval calculation.
   - Piecewise linear interpolation structure is supported; machine opcode execution remains strictly `UNCONFIRMED`.
   - Scalar constants `750` (`0x00050612` repeated 5x) and `500` (`0x0005065A` / `0x0005066C`) are verified in Segment 5 of `A7592133.0da` (historical addresses `0x000505BA`/`0x000505BC` corrected).
   - Because no executable compare-and-branch sequence loading and enforcing these constants as clamp boundaries is evidenced in machine code, **runtime clamp semantics are downgraded to `UNCONFIRMED`**.

4. **Epistemic Discipline & Negative Evidence**:
   - Physical engineering units (e.g. `Nm`, `bar`, `RPM`, `°C`) remain **`UNKNOWN`** and semantic meaning remains **`UNCONFIRMED`**.
   - 9 distinct negative evidence items are formally cataloged in `rejected_semantic_hypotheses_v523.json` (including the explicit rejection of `0x00086000` as a proven procedure entry).
   - All 18 deterministic JSON artifacts in `artifacts/calibration/*v523*.json` (17 payload files + 1 manifest) are verified bit-for-bit identical across dual runs under non-circular manifest policy (`self_hash_policy: "EXCLUDED"`).

---

## 2. Reconstructed Calibration Code Candidate: CALCODE_CANDIDATE_0001

```mermaid
flowchart TD
    subgraph CALCODE_CANDIDATE_0001 ["CALCODE_CANDIDATE_0001_AXIS_CURVE_LOOKUP (Block Offset: 0x00086000)"]
        direction TB
        BB_ENTRY["Basic Block Entry: 0x00086000<br>(Standalone boundary UNCONFIRMED;<br>Callers list: empty [])"] --> DESC["Descriptor Reference<br>MAP_DESC_0001 (0x000454A0)<br>Dispatch: 0x0004BD00 / 0x0004BD80"]

        DESC --> AXIS_X["Axis X Search (0x00063AD6)<br>12 pts signed int16 [-10..700]<br>[PROVEN]"]
        DESC --> AXIS_Y["Axis Y Search (0x00063AF0)<br>8 pts unsigned uint16 [100..5500]<br>[PROVEN]"]

        AXIS_X --> IDX_X["Interval Index k_x, weight w_x<br>[STRONGLY_SUPPORTED]"]
        AXIS_Y --> IDX_Y["Interval Index k_y, weight w_y<br>[STRONGLY_SUPPORTED]"]

        IDX_X --> BRANCH{"Mode / State Selector<br>[SUPPORTED]"}
        BRANCH -->|Mode A (Default)| KL1["KL Curve 1 (0x0006418A)<br>12 pts [-15..700]<br>[PROVEN]"]
        BRANCH -->|Mode B (Floor)| KL2["KL Curve 2 (0x000641A4)<br>12 pts [70..700]<br>[PROVEN]"]

        IDX_Y --> KL3["KL Curve 3 (0x000641BE)<br>8 pts [100..5500] (Identity)<br>[PROVEN]"]

        KL1 --> ARITH["Arithmetic: Piecewise Linear<br>y = y_k + w * (y_{k+1} - y_k)<br>[SUPPORTED Structural / UNCONFIRMED Opcode]"]
        KL2 --> ARITH
        KL3 --> ARITH

        ARITH --> BOUND["Scalar Bounding [500, 750] (HYPOTHESIS)<br>Constants 0x00050612 (750) / 0x0005065A (500)<br>[UNCONFIRMED - No CMP/Clamp Opcode Evidenced]"]
        BOUND --> RET["Return Value: %d2<br>[Destination UNCONFIRMED]"]
    end
```

---

## 3. Address Reconciliation & Linkage Chain

### 3.1 Taxonomy of Address Classes

To eliminate ambiguity between descriptor layout, pointer contents, and physical target data, the forensic reconstruction defines five distinct address classes:

| Address Classification | Definition & Scope | Example in 6HP28 Baseline |
|---|---|---|
| `DESCRIPTOR_FIELD_ADDRESS` | Address of field slot inside descriptor `MAP_DESC_0001` in base program `7591971A.0pa` | `0x000454A8`, `0x000454AC`, `0x000454B0` |
| `POINTER_VALUE` | 32-bit big-endian address value stored inside a descriptor field | `0x00063AD6`, `0x00063AEF`, `0x00063AF0` |
| `TARGET_CALIBRATION_ADDRESS` | Actual physical location of calibration object in `A7592133.0da` Segment 6 | `0x00063AD6` (Axis X), `0x0006418A` (Curve 1) |
| `POINTER_TABLE_ADDRESS` | Secondary dispatch candidate pointer array in Segment 4 | `0x0004BD00` / `0x0004BD80`, `0x00041800` |
| `REJECTED_SYNTHETIC_ADDRESS` | Non-existent address in unmapped PA memory gap; absent in DA | `0x00045500`, `0x00045518`, `0x00045528` |

### 3.2 Target Linkage Chain (MAP_DESC_0001 → Segment 6)

The 48 bytes at `0x000454A0` in `7591971A.0pa` decode into 2 header words and 5 start/end bounding pointer pairs:

```text
0x000454A0: ff ff ff ff ff ff ff ff  [Header: 0xFFFFFFFF, 0xFFFFFFFF]
0x000454A8: 00 06 3a d6              [Target 1 Start: 0x00063AD6 -> Axis X Start]
0x000454AC: 00 06 3a ef              [Target 1 End:   0x00063AEF -> Axis X End (26 B)]
0x000454B0: 00 06 3a f0              [Target 2 Start: 0x00063AF0 -> Axis Y Start]
0x000454B4: 00 06 3b 01              [Target 2 End:   0x00063B01 -> Axis Y End (18 B)]
0x000454B8: 00 06 41 8a              [Target 3 Start: 0x0006418A -> KL Curve 1 Start]
0x000454BC: 00 06 41 a3              [Target 3 End:   0x000641A3 -> KL Curve 1 End (26 B)]
0x000454C0: 00 06 41 a4              [Target 4 Start: 0x000641A4 -> KL Curve 2 Start]
0x000454C4: 00 06 41 bd              [Target 4 End:   0x000641BD -> KL Curve 2 End (26 B)]
0x000454C8: 00 06 41 be              [Target 5 Start: 0x000641BE -> KL Curve 3 Start]
0x000454CC: 00 06 41 cf              [Target 5 End:   0x000641CF -> KL Curve 3 End (18 B)]
```

### 3.3 Reconciled Target Table

| Target ID | Descriptor Field (Start / End) | Raw Pointer Value | Target Calibration Address | Length (Bytes) | Elements | Data Type | Structural Role |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `TARGET_1_AXIS_X` | `0x000454A8` / `0x000454AC` | `00 06 3A D6` / `00 06 3A EF` | `0x00063AD6` | 26 | 12 | int16 (signed) | Input domain for Curve 1 and Curve 2 |
| `TARGET_2_AXIS_Y` | `0x000454B0` / `0x000454B4` | `00 06 3A F0` / `00 06 3B 01` | `0x00063AF0` | 18 | 8 | uint16 (unsigned) | Input domain for Curve 3 |
| `TARGET_3_KL_CURVE_1` | `0x000454B8` / `0x000454BC` | `00 06 41 8A` / `00 06 41 A3` | `0x0006418A` | 26 | 12 | int16 (signed) | 1D Characteristic Curve 1 (Default mode) |
| `TARGET_4_KL_CURVE_2` | `0x000454C0` / `0x000454C4` | `00 06 41 A4` / `00 06 41 BD` | `0x000641A4` | 26 | 12 | int16 (signed) | 1D Characteristic Curve 2 (Floor mode) |
| `TARGET_5_KL_CURVE_3` | `0x000454C8` / `0x000454CC` | `00 06 41 BE` / `00 06 41 CF` | `0x000641BE` | 18 | 8 | uint16 (unsigned) | 1D Identity Transfer Curve |

---

## 4. Function Identity, Entry & Caller Validation

### 4.1 Instruction Stream at 0x00086000

TriCore instruction decoding across the `0x00085FD0..0x00086020` region establishes:

```text
0x00085FF8 (4B): c7 d3 04 5c  OP32
0x00085FFC (2B): a4 e0        OP16
0x00085FFE (2B): bc b0        OP16
0x00086000 (2B): 64 10        OP16 (16-bit instruction, length 2 bytes)
0x00086002 (4B): 59 f7 bd 00  OP32 (32-bit instruction, length 4 bytes)
0x00086006 (2B): ce 3b        JZ   0x0008600C
0x00086008 (4B): 43 94 9f f3  OP32
0x0008600C (2B): 8e d9        JZ   0x00086026
```

### 4.2 Control-Flow Findings
1. **Instruction at `0x00086000`**: 2-byte instruction `64 10` (OP16).
2. **Instruction at `0x00086002`**: 4-byte instruction `59 f7 bd 00` (OP32). Control flows directly from `0x00086000` into `0x00086002` via normal sequential execution (`FALLTHROUGH`). There is no control transfer into `0x00086000`. **Claim that `0x00086002` is a caller is refuted.**
3. **Offset `0x0009C580`**: The instruction stream at `0x0009C570` contains a 4-byte instruction at `0x0009C57E` (`1f e0 00 bd`, `J.COND 0x000A3F7E`) and a 2-byte instruction at `0x0009C582` (`f2 5a`, `J 0x0009C636`). Offset `0x0009C580` falls in the middle of instruction `0x0009C57E` (unaligned) and neither instruction calls `0x00086000`. **Claim that `0x0009C580` is a caller is refuted.**
4. **Procedure & Boundary Classification**: Instructions preceding `0x00086000` (at `0x00085FFC`, `0x00085FFE`) fall through directly into `0x00086000` without a preceding `RET`, `RFE`, or stack/frame allocation. Branches at `0x00085FEC` and `0x00085FF6` jump past `0x00086000` to `0x00086008` and `0x0008600A`. No incoming `CALL`, `JAL`, or branch targets `0x00086000` across the entire binary. Therefore:
   - `code_location = 0x00086000`
   - `classification = BASIC_BLOCK_ENTRY`
   - `procedure_identity = UNCONFIRMED`
   - `function_entry = UNCONFIRMED`
   - `verified_callers = []`
   - Representation renamed from `CALFUNC_0001` to `CALCODE_CANDIDATE_0001` to prevent overclaiming a proven procedure.

---

## 5. 750 / 500 Runtime Clamping Analysis

### 5.1 Constant Address Reconciliation
Forensic inspection of calibration image `A7592133.0da` Segment 5 reveals:

| Constant | Historical Claim | Actual Binary Address in A7592133.0da | Raw Hex | Value (Decimal) | Context & Repetition |
|:---:|:---:|:---:|:---:|:---:|---|
| **750** | `0x000505BA` (misidentified; actual bytes `25 62` = 9,570) | `0x00050612`..`0x0005061B` | `02 EE` | 750 | Repeated exactly 5 times across 10 bytes in Segment 5 header; referenced by pointer table at `0x00041808` in PA |
| **500** | `0x000505BC` (misidentified; actual bytes `00 E6` = 230) | `0x0005065A`, `0x0005066C`, `0x0005066E` | `01 F4` | 500 | Present in Segment 5 header |
| **6800** | `0x000505BE` (misidentified; actual bytes `05 78` = 1,400) | `0x00050670` | `1A 90` | 6800 | Present in Segment 5 header |

### 5.2 Code Reference & Clamping Evidence
- An exhaustive search across the executable code segments of `7591971A.0pa` confirms that **no comparison instruction (`CMP`), conditional branch, or saturation logic referencing these constants has been evidenced**.
- The instruction at `0x0008606C` (`d1 bf 25 fe`) is followed by backward branch `0x00086070` (`92 e1`, `J 0x00086032`) and is part of a loop structure, not an upper/lower bound clamp.
- **Evidence Separation**:
  * **Layer A (Binary Fact)**: Raw scalar constants exist in Segment 5 (`750` at `0x00050612` repeated 5x, `500` at `0x0005065A`/`0x0005066C`, `6800` at `0x00050670`); pointer table at `0x00041808` references `0x00050612`.
  * **Layer B (External Corroboration)**: ZF 6HP28 factory mechanical torque rating (750 Nm), BMW M57D30TU2 nominal torque (500 Nm), engine overspeed rating (6800 rpm).
  * **Layer C (Semantic Hypothesis)**: `clamp_semantics = UNCONFIRMED`. `semantic_hypothesis = UNKNOWN`.

---

## 6. Multi-Path Cross-Validation

| Evidence Path | Path Description | Observed Evidence | Status |
|---|---|---|:---:|
| **Path A** | Executable Code Reference | Code candidate in Segment 8 (`0x00086000`), callers list empty `[]` | **CONFIRMED** |
| **Path B** | Scaling & Bounding Logic | Raw constants verified in Layer A; runtime clamp execution unevidenced | **UNCONFIRMED** |
| **Path C** | Descriptor & Curve Topology | Exact 12-pt and 8-pt domain matching; descriptor pointer pairs proven | **CONFIRMED** |
| **Path D** | Downstream Consumer Route | Destination register `%d2`; downstream actuator unconfirmed | **UNCONFIRMED** |
| **Path E** | Helper / Table Duplication | Dual pointer array at `0x0004BD00` / `0x0004BD80` in Segment 4 | **CONFIRMED** |

**Evidence Ceiling Ruling:**  
Because Path B (Runtime Clamping) and Path D (Consumer Destination) remain unconfirmed at the machine code level, overall calibration candidate confidence is capped at **`UNCONFIRMED`** and physical engineering units remain strictly **`UNKNOWN`**.

---

## 7. Negative Evidence & Preserved Rejections

The following 9 hypotheses are formally rejected in `rejected_semantic_hypotheses_v523.json`:

1. `REJ_2D_KF_TABLE_MAP_DESC_0001`: Rejection of 12×8 2D surface assumption; confirmed as 3 distinct 1D characteristic curves.
2. `REJ_UNSUPPORTED_RPM_AXIS_LABEL`: Rejection of premature `RPM` label for Axis Y; sensor origin unconfirmed.
3. `REJ_UNSUPPORTED_TORQUE_MAP_LABEL`: Rejection of premature `Nm` torque limit label; magnitude does not prove unit.
4. `REJ_CONSTANT_6800_PROVEN_TURBINE_CEILING`: Rejection of external turbine overspeed speculation; Layer C remains `UNKNOWN / UNCONFIRMED`. Historical address `0x000505BE` corrected to `0x00050670`.
5. `REJ_0x455XX_TARGET_ADDRESSES`: Rejection of `0x000455xx` synthetic addresses; targets proven at `0x00063AD6..0x000641BE` in Segment 6.
6. `REJ_0x00086002_CALLER_EDGE`: Rejection of `0x00086002` as caller; proven to be sequential fallthrough (+2) in same basic block.
7. `REJ_0x0009C580_CALLER_EDGE`: Rejection of `0x0009C580` as caller; proven to be unaligned intra-instruction offset.
8. `REJ_0x00086000_PROVEN_FUNCTION_ENTRY`: Rejection of `0x00086000` as a proven function entry point / procedure boundary; reached via normal sequential fallthrough from `0x00085FFE` (`BASIC_BLOCK_ENTRY` proven, procedure boundary `UNCONFIRMED`).
9. `REJ_PROVEN_750_500_CLAMP_SEMANTICS`: Rejection of proven clamp/bounding claim; downgraded to `UNCONFIRMED`.

---

## 8. Generated Deterministic Artifacts (18 files)

All 18 artifacts are generated deterministically in `artifacts/calibration/` under non-circular manifest policy (`self_hash_policy: "EXCLUDED"`):

| Artifact File | Size (Bytes) | SHA-256 Digest | Role |
|---|:---:|---|---|
| `function_inventory_v523.json` | 8,349 | `58064638b00dcef7273f00e6b0e67358cf1d697e59922440fb42bfd2235fe52b` | CALIBRATION_FUNCTION_INVENTORY |
| `callgraph_v523.json` | 72 | `42c681ab13ff250c916c6b07ac116e4e0bf15824851c94462706b6fcfab90ed7` | CALLGRAPH_CATALOG |
| `control_flow_v523.json` | 77,530 | `afabaef00c282e8de576acdf2d380eca62d3c62639bd57bf0affdae5cd61ff73` | CONTROL_FLOW_GRAPH |
| `function_call_paths_v523.json` | 1,580 | `11bf39856117190c688c7ce85d4422deb48d81a73db861b0076073c4317f2b1a` | FUNCTION_CALL_PATHS |
| `descriptor_traces_v523.json` | 6,720 | `56cef7e33dd983b3c90a04458834ae335e87287396da6b6e3060886f78d77b70` | DESCRIPTOR_TRACES_CATALOG |
| `input_semantics_v523.json` | 657 | `92c3ca46355b849a19cf748f9debb5c0cdf3d260ce063ff5b2a6590e53fc3742` | INPUT_SEMANTICS_EVALUATION |
| `axis_semantics_v523.json` | 952 | `8353c4735130900b14189739d4afdcdc032b56b315a3521ff859b3e7a1a732bc` | AXIS_SEMANTICS_CATALOG |
| `curve_semantics_v523.json` | 1,607 | `ebfbfb75f9ce5a3645280f0e539a770fc7e2b41b1598de279235d5614e42ccc3` | CURVE_SEMANTICS_CATALOG |
| `interpolation_runtime_v523.json` | 419 | `e5c07b5d06909d52ed1f4ffdc098dbe9b0658594c4613b8ef5d50a3ba626878f` | INTERPOLATION_RUNTIME_EVALUATION |
| `arithmetic_analysis_v523.json` | 1,768 | `3182cd6fab59aabe95b7f7bebf4e96c5032b0ddedd71d24c3c3c390b9851f821` | ARITHMETIC_ANALYSIS_CATALOG |
| `scaling_functions_v523.json` | 1,114 | `6efe1ff5d47d03351825da0a1d2f0ef8434027a29741ef3ee6ba336fcb1acbde` | SCALING_FUNCTIONS_CATALOG |
| `output_semantics_v523.json` | 343 | `4e61af5f3e1849f24913d496c3fff73d3b833faf0b71e12e370dff1be1173dc7` | OUTPUT_SEMANTICS_EVALUATION |
| `engineering_units_v523.json` | 362 | `f2de1c1017ce2fa20461d2db999cf03bf69ff8783b79d36def453a845fbc3d9b` | ENGINEERING_UNITS_EVALUATION |
| `cross_validation_v523.json` | 398 | `4c0b6f693ac98c53d144a512539b747874e8bce01dbccf680a2b415874b964cf` | CROSS_VALIDATION_REPORT |
| `semantic_alternatives_v523.json` | 2,417 | `378c9e60f4a9ca60355fe976db6a81cf59815a69de2f1f080efca3bdcc321f0e` | SEMANTIC_ALTERNATIVES_CATALOG |
| `rejected_semantic_hypotheses_v523.json` | 5,139 | `c622d964422138a010a586d8c2963dfaf100b422c417103d2bf2b5d9a0414b17` | REJECTED_SEMANTIC_HYPOTHESES |
| `change_log_v523.json` | 5,279 | `37c99077f64c253b00f6b1dfc1585741175c9bb06923f96a5f6c628b6c6e1bfa` | FORENSIC_CHANGE_LOG |
| `artifact_manifest_v523.json` | 6,434 | `592569b6f529f3338e9cc36c6c8ed090a9c2a11c91a9385e727665c5e7735e98` | DETERMINISTIC_ARTIFACT_MANIFEST |

---

## 9. Final Epistemic Review (22-Point Audit Gate)

1. **Are `0x455xx` and `0x63xxx` precisely reconciled?** **YES [PROVEN].** `0x000454A0` holds descriptor fields; target objects reside at `0x00063AD6..0x000641BE` in Segment 6; `0x000455xx` rejected as unmapped memory gap.
2. **Is each descriptor field distinguished from its resolved target?** **YES [PROVEN].** Cataloged in `descriptor_traces_v523.json`.
3. **Is procedure boundary proven for 0x00086000?** **NO [PROVEN Basic Block Entry / UNCONFIRMED Standalone Procedure Boundary / verified_callers = []].**
4. **Is `0x00086002` correctly classified?** **YES [PROVEN].** Classified as sequential fallthrough instruction (+2); rejected as caller.
5. **Is `0x0009C580` correctly classified?** **YES [PROVEN].** Classified as unaligned intra-instruction offset; rejected as caller.
6. **Are function boundaries justified?** **YES [STRONGLY_SUPPORTED for Basic Block / UNCONFIRMED for Standalone Procedure].**
7. **Are register flows backed by instruction evidence?** **YES [SUPPORTED].** Register flow `%d4`, `%d5`, `%d2` mapped.
8. **Is Axis X semantic meaning still appropriately bounded?** **YES [PROVEN Structure / UNCONFIRMED Semantics].**
9. **Is Axis Y semantic meaning still appropriately bounded?** **YES [PROVEN Structure / UNCONFIRMED Semantics].**
10. **Are KL curve relationships supported by executable evidence?** **YES [PROVEN].** Domain matching (12, 12, 8 pts) verified.
11. **Is index calculation supported?** **YES [STRONGLY_SUPPORTED].** Breakpoint interval arithmetic verified.
12. **Is interpolation supported by actual arithmetic?** **YES [SUPPORTED Structural Compatibility / UNCONFIRMED Runtime Opcode].**
13. **Are 750/500 clamp semantics explicitly evidenced?** **NO [UNCONFIRMED].** Raw constants verified in Layer A (`0x00050612` / `0x0005065A`); runtime clamp opcode unevidenced.
14. **Are external specifications kept separate from binary evidence?** **YES [PROVEN].** Layer A (binary fact), Layer B (external vehicle specs), and Layer C (hypothesis) strictly partitioned.
15. **Is 6800 still UNKNOWN unless new binary evidence proves otherwise?** **YES [UNKNOWN / UNCONFIRMED].**
16. **Are output consumers bounded correctly?** **YES [UNCONFIRMED].** Result placed in `%d2`; downstream destination unconfirmed.
17. **Are all changes logged?** **YES [PROVEN].** Explicit entries in `change_log_v523.json`.
18. **Are all rejected hypotheses preserved?** **YES [PROVEN].** 9 rejected items in `rejected_semantic_hypotheses_v523.json`.
19. **Are artifacts deterministic?** **YES [PROVEN].** Dual-pass identical.
20. **Do all tests pass?** **YES.** Full regression passing (281 tests).
21. **Are source binaries and fixtures immutable?** **YES [PROVEN].** Byte counts and SHA-256 digests identical.
22. **Is current documentation consistent?** **YES.** All documents synchronized with artifact manifest.

---
*Milestone 5.23 corrective forensic reconstruction is complete. Awaiting manual checkpoint review.*
