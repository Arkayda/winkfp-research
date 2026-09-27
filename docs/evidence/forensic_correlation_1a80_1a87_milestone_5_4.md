# Forensic Correlation: 1A80 <-> 1A87 <-> Factory 1A87 (Milestone 5.4)

**Classification**: OFF-HARDWARE FORENSIC CORRELATION REPORT  
**Scope**: Off-Hardware Forensic Correlation of Diagnostic Identifiers (`0x1A 0x80`, `0x1A 0x87`) on Physical EGS (`0x18`) and Factory Trace (`10FLASH` / `0x78`)  
**Safety Gate**: STRICTLY OFF-HARDWARE (Zero hardware access, zero serial port opening, raw traces preserved unchanged)  

---

## 1. Objective & Evaluated Evidence Sources

The purpose of this milestone is to determine whether the repeated physical ZF 6HP EGS value:
$$\texttt{00 00 07 56 99 80} \quad (\text{numerical value: } \mathbf{7569980})$$
can be assigned a documented semantic meaning, or whether only structural correlation can be established.

### Evidence Sources Inspected
1. **Sanitized Factory Trace** (`traces/sanitized/sanitized_flash_session.trc`):
   - Examined all occurrences of `1A 87`, `PHYSIKALISCHE_HW_NR_LESEN`, `IDENT`, and all 7-digit numeric part numbers.
2. **Physical EGS Wire Traces** (`traces/hardware/`):
   - `20260926_174811_egs_ident.json` (Milestone 5.2 live physical `1A 80` capture).
   - `20260926_175924_egs_physical_hw_nr.json` (Milestone 5.3 live physical `1A 87` capture).
   - `20260926_173201_egs_aif.json` (Milestone 5.0 live physical `1A 86` capture).
3. **Decompiled WinKFP Machine Code** (`analysis/`):
   - `analysis/ediabas/`, `analysis/vdle/`, `analysis/kr_api/`.
4. **SP-Daten & SGBD Research Tools** (`tools/analysis/spdaten_scan.py`, `reconstruction/safety/id_check.py`):
   - VDLE IPO constants, SGBD encryption routines, and configuration tables.
5. **Existing Repository Documentation & Correlation Matrix**:
   - `docs/evidence/job_wire_correlation_milestone_2.md`
   - `docs/evidence/physical_ident_correlation_milestone_5_2.md`
   - `docs/evidence/physical_hw_nr_correlation_milestone_5_3.md`

---

## 2. Comparison of Observed Wire Behaviors

### 2.1 Physical EGS Observations (Target `0x18`, SGBD `0479S90T641Z`)

#### A. Physical `1A 80` Response (`traces/hardware/20260926_174811_egs_ident.json`)
* **Request**: `82 18 F1 1A 80 25`
* **Response Payload (60 bytes)**:
  ```text
  5A 80 00 00 07 59 19 72 10 05 02 04 53 4C 20 08 10 30 08 00 1D 45 C3 40 01 02 03 0A 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5A
  ```
* **Key Observations**:
  - Contains `00 00 07 59 19 72` $\rightarrow$ `7591972` (offset 2..7).
  - Contains `07 56 99 80` $\rightarrow$ **`7569980`** (offset 36..41).
  - Contains ASCII text fragments `"0479S90"` and `"T641Z"` (offset 46..64).

#### B. Physical `1A 87` Response (`traces/hardware/20260926_175924_egs_physical_hw_nr.json`)
* **Request**: `82 18 F1 1A 87 2C`
* **Response Wire (24 bytes)**:
  ```text
  94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0
  ```
* **Key Observations**:
  - Exact payload length: 20 bytes.
  - Structure: **Three identical 6-byte blocks**:
    $$\texttt{00 00 07 56 99 80} \quad \times 3 \quad (\text{numerical value: } \mathbf{7569980})$$
  - Checksum: `0xE0` (VALID).

---

### 2.2 Factory Trace Observations (Target `0x78` / `10FLASH`)

#### A. Factory `1A 80` (`sanitized_flash_session.trc`, line 11750)
* **Job**: `IDENT`
* **Request**: `82 78 F1 1A 80 85`
* **Response**: `9F F1 78 5A 80 00 00 09 19 92 60 05 01 05 D0 47 55 20 08 10 07 56 00 17 67 0B 00 C4 03 03 1E 00 00 00 73`
* **EDIABAS Field Assignment**:
  - `ID_BMW_NR = "9199260"` (from `00 00 09 19 92 60`)
  - `ID_HW_NR = "05"`
  - `ID_DATUM = "07.10.2008"`

#### B. Factory `1A 87` (`sanitized_flash_session.trc`, lines 11801, 13219)
* **Job**: `PHYSIKALISCHE_HW_NR_LESEN`
* **Request**: `82 78 F1 1A 87 8C`
* **Response (24 bytes)**:
  ```text
  94 F1 78 5A 87 00 00 09 16 56 72 00 00 09 16 56 72 00 00 09 16 56 72 93
  ```
* **EDIABAS Field Assignment**:
  - Structure: **Three identical 6-byte blocks**:
    $$\texttt{00 00 09 16 56 72} \quad \times 3$$
  - `PHYSIKALISCHE_HW_NR = "9165672"`

---

## 3. Evaluation of Semantic Hypotheses (A, B, C, D)

### Hypothesis A: `7569980` is directly identified as a physical hardware number
* **Evaluation**: **UNPROVEN / REJECTED AS DIRECT CLAIM**.
* **Reasoning**:
  - Direct identification requires either:
    1. An original SGBD driver definition (`0479S90T641Z.PRG` / `.GRP`) mapping the output of `1A 87` to the result field `PHYSIKALISCHE_HW_NR`; OR
    2. A target-specific factory trace on address `0x18` showing the job call and result assignment.
  - Neither artifact is present in the repository. The factory mapping `PHYSIKALISCHE_HW_NR_LESEN -> 1A 87` exists solely for target `0x78` (`10FLASH`).
  - Transferring the field name `PHYSIKALISCHE_HW_NR` across different ECUs solely on the basis of a shared KWP2000 service/record identifier violates evidentiary discipline.

### Hypothesis B: `7569980` is some other documented identification field
* **Evaluation**: **UNPROVEN / REJECTED AS DIRECT CLAIM**.
* **Reasoning**:
  - No alternative field label (such as `ID_HW_NR`, `HW_REFERENZ`, `ID_SW_NR_OSV`, etc.) is directly associated with `7569980` in repository source code or data sets.
  - In AIF (`1A 86`), the recorded software number was `SW_NUMBER = 7592133` and assembly number was `ZB_NUMBER = 7592132`. `7569980` is distinctly different.

### Hypothesis C: Only structural correlation is established
* **Evaluation**: **CONFIRMED / ACCEPTED**.
* **Direct Evidence**:
  1. **Telegram Length & Framing Homology**:
     Both target `0x78` (`10FLASH`) and target `0x18` (physical EGS) respond to `1A 87` with an identical frame length of **24 bytes** (header `0x94` = 20 payload bytes).
  2. **Triple-Repetition Structure**:
     Both responses format the payload as `5A 87` followed by **three consecutive, identical 6-byte numeric blocks**:
     - `10FLASH` (`0x78`): `00 00 09 16 56 72` $\times 3$
     - Physical EGS (`0x18`): `00 00 07 56 99 80` $\times 3$
  3. **Cross-Service Correlation on Physical EGS**:
     The exact 7-digit numerical value **`7569980`** (`07 56 99 80`) observed in the `1A 87` response is also present within the `1A 80` identification record at offset 36..41 on the same physical ECU.

### Hypothesis D: Meaning remains UNKNOWN
* **Evaluation**: **CONFIRMED / ACCEPTED**.
* **Direct Evidence**:
  - In the absence of direct SGBD bytecode execution or OEM documentation specifically for `0479S90T641Z`, the functional semantic meaning of `7569980` on EGS `0x18` cannot be declared as established fact.
  - The classification must remain strictly:
    $$\mathbf{UNKNOWN[target=0479S90T641Z]} \quad \text{or} \quad \mathbf{INFERRED}$$

---

## 4. Strict Evidence Classification Matrix

| Dimension | Physical EGS Bench (`0x18`) | Factory Trace (`10FLASH` / `0x78`) | Evidence Classification |
|---|---|---|---|
| **Wire Frame `1A 87`** | `82 18 F1 1A 87 2C` $\rightarrow$ `94 F1 18 5A 87 (7569980 x 3) E0` | `82 78 F1 1A 87 8C` $\rightarrow$ `94 F1 78 5A 87 (9165672 x 3) 93` | **`OBSERVED_WIRE`** |
| **Payload Structural Homology** | 20-byte payload with 3x identical 6-byte blocks | 20-byte payload with 3x identical 6-byte blocks | **`STRUCTURAL_HOMOLOGY`** (Hypothesis C) |
| **Cross-Service Correlation (`1A 80` $\leftrightarrow$ `1A 87`)** | `7569980` present in both `1A 80` and `1A 87` | N/A (different targets) | **`OBSERVED_WIRE_CORRELATION`** |
| **Job Name Mapping on `0x78`** | N/A | `PHYSIKALISCHE_HW_NR_LESEN` | **`OBSERVED_JOB_MAPPING[target=10FLASH]`** |
| **Job Name Mapping on `0x18`** | Unobserved | Unobserved | **`UNKNOWN[target=0479S90T641Z]`** |
| **Semantic Meaning of `7569980`** | Unproven directly | `9165672` is `PHYSIKALISCHE_HW_NR` | **`UNKNOWN / INFERRED`** (Hypothesis D) |

---

## 5. Summary Conclusion

1. **Hypotheses Selected**:
   Evidence strictly and conclusively supports **C (Structural correlation is established)** and **D (Semantic meaning remains UNKNOWN)**. Hypotheses A and B are rejected due to lack of direct SGBD/trace evidence on target `0x18`.
2. **Preservation of Raw Wire Authority**:
   - `traces/hardware/20260926_174811_egs_ident.json` and `traces/hardware/20260926_175924_egs_physical_hw_nr.json` remain authoritative and unmodified.
   - The relationship:
     $$\text{EGS } \texttt{1A 80} \longrightarrow \texttt{7569980}$$
     $$\text{EGS } \texttt{1A 87} \longrightarrow \texttt{7569980} \times 3$$
     is documented as an observed wire property without imposing unsupported OEM job semantics.
3. **Safety Verification**:
   - Zero physical communication took place during Milestone 5.4.
   - The serial port was not opened.
