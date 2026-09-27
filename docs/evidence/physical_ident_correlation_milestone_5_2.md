# Physical Identification Primitive (1A 80) & Factory Trace Correlation (Milestone 5.2)

**Classification**: RESEARCH EVIDENCE REPORT  
**Scope**: Read-Only Identification Diagnostic Validation (`0x1A 0x80`) & Factory Forensic Correlation  
**Target ECU**: BMW E60 ZF 6HP EGS (Diagnostic Address: `0x18`, SGBD: `0479S90T641Z`)  
**Safety Gate**: STRICTLY READ-ONLY (No flash, no programming, no session change, no authentication, no reset)  

---

## 1. Physical EGS Wire Request Specification (`1A 80`)

### 1.1 Wire Request Formulation
The read-only identification primitive queries KWP2000 service `0x1A` (ReadECUIdentification) with record local identifier `0x80` (Standard Identification Record):

```text
TX: 82 18 F1 1A 80 25
```

### 1.2 Mathematical Telegram Breakdown
* **Header Byte (`0x82`)**: DS2/BMW-FAST short header (`0x80 | 0x02`), payload length = 2 bytes.
* **Target Address (`0x18`)**: ZF 6HP EGS transmission mechatronic controller.
* **Tester Address (`0xF1`)**: Standard BMW diagnostic tester address.
* **Service Payload (`1A 80`)**:
  - `0x1A`: KWP2000 `SID_READ_ECU_IDENTIFICATION`.
  - `0x80`: Diagnostic Record Identification Local Identifier (`recordIdentifier = 0x80`).
* **Additive Checksum (`0x25`)**:
  $$\text{Checksum} = (0x82 + 0x18 + 0xF1 + 0x1A + 0x80) \pmod{256} = 0x225 \pmod{256} = 0x25$$
  Calculated deterministically via repository transport framing (`reconstruction.transport.kdcan.framing`).

---

## 2. Factory Trace Evidence (`10FLASH` / `0x78`)

### 2.1 Factory Job Observation
In the historical sanitized factory trace (`traces/sanitized/sanitized_flash_session.trc`, line 11750), service `1A 80` is emitted under the high-level EDIABAS job `IDENT` against flash gateway target `0x78`:

```text
JOB: IDENT
TX:  82 78 F1 1A 80 85
RX:  9F F1 78 5A 80 00 00 09 19 92 60 05 01 05 D0 47 55 20 08 10 07 56 00 17 67 0B 00 C4 03 03 1E 00 00 00 73
```

### 2.2 Factory Result Field Mapping (Target `10FLASH`)
In `10FLASH`, the EDIABAS SGBD interprets the `5A 80` response into standard identification fields:
* `ID_BMW_NR`: `"9199260"` (extracted from BCD bytes `00 00 09 19 92 60` at offset +2)
* `ID_HW_NR`: `"05"` (extracted from byte `05` at offset +8)
* `ID_COD_INDEX`: `+1` (byte `01` at offset +9)
* `ID_DIAG_INDEX`: `+1488` (`0x05D0` at offset +10)
* `ID_VAR_INDEX`: `+18261` (`0x4755` at offset +12)
* `ID_DATUM`: `"07.10.2008"` (from BCD bytes `20 08 10 07`)
* `ID_LIEF_NR`: `+56` (Siemens VDO Automotive)
* `ID_SW_NR_FSV`: `"11.0.196"`

Notice that in factory `10FLASH`, the leading 7-digit numeric value is **`ID_BMW_NR`** (BMW part number / Teilenummer), **not** a `ZB_NUMBER`.

---

## 3. Physical EGS Validation Results (Milestone 5.2 Phase 3)

### 3.1 Live Wire Capture
* **Trace File**: `traces/hardware/20260926_174811_egs_ident.json`
* **Raw TX Wire**: `82 18 F1 1A 80 25`
* **Raw RX Wire**:
  ```text
  BC F1 18 5A 80 00 00 07 59 19 72 10 05 02 04 53 4C 20 08 10 30 08 00 1D 45 C3 40 01 02 03 0A 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5A D9
  ```
* **Frame Metrics**:
  - Total frame length: 64 bytes (`0xBC` = header byte with length 60)
  - Destination: `0xF1`, Source: `0x18` (ZF 6HP EGS)
  - Service response: `0x5A 0x80` (Positive Response to ReadECUIdentification `0x1A` with record `0x80`)
  - Checksum: `0xD9` (**VALID**)
  - Round-Trip Time (RTT): **80.01 ms**
  - Golden Comparison: **`UNKNOWN`** (as required; no fabricated reference)

### 3.2 Raw Payload Dissection
Payload length: 60 bytes.
```text
Offset  00..01: 5A 80                                               (SID + Record ID)
Offset  02..07: 00 00 07 59 19 72                                   (Numeric field: 7591972)
Offset  08..12: 10 05 02 04                                         (Indices / configuration bytes)
Offset  13..15: 53 4C 20                                            (ASCII: "SL ")
Offset  16..18: 08 10 30                                            (Date candidate: 2008.10.30)
Offset  19..35: 08 00 1D 45 C3 40 01 02 03 0A 00 00 00 00 00       (ECU internal parameters)
Offset  36..41: 07 56 99 80 00                                      (Numeric field: 7569980)
Offset  42..45: 40 59 38 30                                         (Intermediate marker)
Offset  46..52: 30 34 37 39 53 39 30                                (ASCII: "0479S90")
Offset  53..59: 30 34 37 39 53 39 30                                (ASCII: "0479S90")
Offset  60..64: 54 36 34 31 5A                                      (ASCII: "T641Z")
```

---

## 4. Forensic Analysis: 1A 80 vs 1A 86 (AIF) Non-Equivalence

### 4.1 Comparison of Numeric Identifiers
A critical distinction exists between the fields returned by `1A 80` (Standard Identification) and `1A 86` (AIF):

| Metric / Field | AIF (`1A 86`) Physical Record | Ident (`1A 80`) Physical Record | Forensic Finding |
|---|---|---|---|
| **Primary Number** | `ZB_NUMBER = 7592132` (bytes `00 00 07 59 21 32`) | `7591972` (bytes `00 00 07 59 19 72`) | **DIFFERENT NUMBERS**. `7591972` $\neq$ `7592132`. |
| **Secondary Number** | `SW_NUMBER = 7592133` (bytes `00 00 07 59 21 33`) | `7569980` (bytes `07 56 99 80 00`) | **DIFFERENT NUMBERS**. `7569980` $\neq$ `7592133`. |
| **Date Field** | `2008.12.04` (Programming Date) | `2008.10.30` (`08 10 30`, Manufacturing/Assembly Date) | **DIFFERENT DATES**. Manufacturing precedes flash date by ~5 weeks. |
| **SGBD String** | `0479S90T641Z` | `0479S90` + `0479S90` + `T641Z` | **COMMON DESCRIPTOR FRAGMENTS** |

### 4.2 Forensic Explanation
1. **`7591972` is NOT `ZB_NUMBER`**:
   - In BMW nomenclature, `ZB_NUMBER` (Zusammenbaunummer) is the programmed assembly ID updated during WinKFP flashing. The AIF record explicitly records this as `7592132`.
   - In `10FLASH`, the byte position offset +2 corresponds to `ID_BMW_NR` (BMW part number / Sachnummer). On the ZF 6HP EGS, `7591972` represents the underlying hardware part number or unprogrammed base ECU part number.
2. **`7569980` is NOT `SW_NUMBER`**:
   - The AIF software number is `7592133`.
   - The number `7569980` in the `1A 80` payload is a distinct BMW component/hardware index (such as base OS, bootloader, or mechatronic hardware revision), not the application flash software number.
3. **No Field Equivalence Assumption**:
   - Field positions cannot be assumed semantically equivalent across different service identifiers (`0x80` vs `0x86`) or across different ECUs (`0x78` vs `0x18`).
   - Any claim that `7591972` or `7569980` "fully match" AIF `ZB` or `SW` is factually incorrect and unsupported by wire evidence.

### 4.3 Common Textual Fragments
* The ASCII strings `"0479S90"` and `"T641Z"` appear in both `1A 80` and `1A 86`.
* These strings correspond to the SGBD variant identifier (`0479S90T641Z`) for this ZF 6HP transmission controller family.
* These are preserved as separate textual observations, without inferring field-level equivalence.

---

## 5. Strict Target-Scoped Evidence Taxonomy

| Dimension | Physical EGS Bench (`0x18`) | Factory Trace (`10FLASH` / `0x78`) | Evidence Classification |
|---|---|---|---|
| **Wire Telegram** | `82 18 F1 1A 80 25` $\rightarrow$ `BC F1 18 5A 80 ... 5A D9` | `82 78 F1 1A 80 85` $\rightarrow$ `9F F1 78 5A 80 ...` | **`OBSERVED_WIRE`** (bench) vs **`OBSERVED_WIRE`** (trace) |
| **High-level Job** | None (direct wire probe) | `IDENT` | **`OBSERVED_JOB_MAPPING[target=10FLASH]`** |
| **Job Mapping on EGS** | Unproven on `0479S90T641Z` | Standard EDIABAS definition | **`UNKNOWN[target=0479S90T641Z]`** |
| **Field Semantics (1A 80 $\leftrightarrow$ AIF ZB/SW)** | Different values (`7591972`/`7569980` vs `7592132`/`7592133`) | `ID_BMW_NR`, `ID_HW_NR` | **`UNKNOWN / INFERRED`** (unsupported) |

---

## 6. Conclusions & Next Steps

1. **Physical Validation Succeeded**:
   The physical ZF 6HP EGS mechatronic cleanly accepts read-only service `1A 80` without errors, returning a valid 64-byte frame with correct checksum (`0xD9`) in 80.01 ms.
2. **Evidence Boundaries Maintained**:
   - The live physical capture is preserved as **`OBSERVED_WIRE`**.
   - Factory job mapping remains strictly scoped as **`OBSERVED_JOB_MAPPING[target=10FLASH]`**.
   - Semantic mapping between `1A 80` fields and `1A 86` ZB/SW fields is rejected as **`UNKNOWN / INFERRED`** due to distinct numerical values.
3. **Safety Boundaries Maintained**:
   - Exactly one read-only request transmitted.
   - Zero modifying or session commands executed.
   - Zero serial port communication after completion of Milestone 5.2.
