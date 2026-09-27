# Physical Hardware-Number Read (1A 87) & Factory Trace Correlation (Milestone 5.3)

**Classification**: RESEARCH EVIDENCE REPORT  
**Scope**: Read-Only Physical Hardware Number Inquiry (`0x1A 0x87`) & Factory Correlation  
**Target ECU**: BMW E60 ZF 6HP EGS (Diagnostic Address: `0x18`, SGBD: `0479S90T641Z`)  
**Safety Gate**: STRICTLY READ-ONLY (No flash, no programming, no session change, no authentication, no reset, exactly ONE request)  

---

## 1. Physical EGS Wire Request Specification (`1A 87`)

### 1.1 Wire Request Formulation
The read-only diagnostic inquiry transmits KWP2000 service `0x1A` (ReadECUIdentification) with record local identifier `0x87` (Physical Hardware Number inquiry):

```text
TX: 82 18 F1 1A 87 2C
```

### 1.2 Mathematical Telegram Breakdown
* **Header Byte (`0x82`)**: DS2/BMW-FAST short header (`0x80 | 0x02`), payload length = 2 bytes.
* **Target Address (`0x18`)**: ZF 6HP EGS transmission mechatronic controller.
* **Tester Address (`0xF1`)**: Standard BMW diagnostic tester address.
* **Service Payload (`1A 87`)**:
  - `0x1A`: KWP2000 `SID_READ_ECU_IDENTIFICATION`.
  - `0x87`: Diagnostic Record Identification Local Identifier (`recordIdentifier = 0x87`).
* **Additive Checksum (`0x2C`)**:
  $$\text{Checksum} = (0x82 + 0x18 + 0xF1 + 0x1A + 0x87) \pmod{256} = 0x22C \pmod{256} = 0x2C$$
  Calculated deterministically via repository transport framing (`reconstruction.transport.kdcan.framing`).

---

## 2. Factory Trace Evidence (`10FLASH` / `0x78`)

### 2.1 Factory Job Observation
In the historical sanitized factory trace (`traces/sanitized/sanitized_flash_session.trc`, line 11800), service `1A 87` is emitted under the high-level EDIABAS job `PHYSIKALISCHE_HW_NR_LESEN` against flash gateway target `0x78`:

```text
JOB: PHYSIKALISCHE_HW_NR_LESEN
TX:  82 78 F1 1A 87 8C
RX:  94 F1 78 5A 87 00 00 09 16 56 72 00 00 09 16 56 72 00 00 09 16 56 72 93
```

### 2.2 Factory Result Field Interpretation
* In `10FLASH`, the EDIABAS SGBD interprets the repeated 6-byte field `00 00 09 16 56 72` as:
  $$\texttt{PHYSIKALISCHE\_HW\_NR} = \text{"9165672"}$$
* **Classification**: **`OBSERVED_JOB_MAPPING[target=10FLASH]`**
  - Confirms that on target `10FLASH`, EDIABAS job `PHYSIKALISCHE_HW_NR_LESEN` executes wire request `1A 87`.
  - It is **NOT** a physical golden reference for EGS `0x18`.

---

## 3. Physical EGS Validation Results (Milestone 5.3 Phase 3)

### 3.1 Live Wire Capture
* **Trace File**: `traces/hardware/20260926_175924_egs_physical_hw_nr.json`
* **Raw TX Wire**: `82 18 F1 1A 87 2C`
* **Raw RX Wire**:
  ```text
  94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0
  ```
* **Frame Metrics**:
  - Total frame length: 24 bytes (`0x94` = header byte with length 20 payload bytes)
  - Destination: `0xF1`, Source: `0x18` (ZF 6HP EGS)
  - Service response: `0x5A 0x87` (Positive Response to ReadECUIdentification `0x1A` with record `0x87`)
  - Checksum: `0xE0` (**VALID**)
  - Round-Trip Time (RTT): **48.29 ms**
  - Golden Comparison: **`UNKNOWN`** (refuses to fabricate reference from factory traces)

### 3.2 Raw Payload Dissection
Payload length: 20 bytes.
```text
Offset  00..01: 5A 87                                (SID + Record ID)
Offset  02..07: 00 00 07 56 99 80                    (Repeated block #1: 7569980)
Offset  08..13: 00 00 07 56 99 80                    (Repeated block #2: 7569980)
Offset  14..19: 00 00 07 56 99 80                    (Repeated block #3: 7569980)
```

---

## 4. Forensic Analysis & Structural Correlation

### 4.1 Structural Pattern Matching
The wire telegram structure returned by the physical EGS (`0x18`) exhibits an exact structural match with the factory `10FLASH` `1A 87` telegram:
* Both telegrams contain a total length of 24 bytes (20 payload bytes).
* Both telegrams contain **three identical 6-byte blocks** following the `5A 87` response header:
  - `10FLASH` (`0x78`): `00 00 09 16 56 72` $\times 3$ (interpreted in `10FLASH` SGBD as `9165672`).
  - Physical EGS (`0x18`): `00 00 07 56 99 80` $\times 3$ (numerical value `7569980`).

### 4.2 Cross-Correlation with Milestone 5.2 (`1A 80`)
* In Milestone 5.2, the physical response to `1A 80` contained the exact byte sequence:
  ```text
  ... 00 00 00 00 00 07 56 99 80 00 40 59 ...
  ```
* The number `7569980` is thus present in both the `1A 80` identification record and the `1A 87` inquiry record.
* However, in accordance with the Semantic Interpretation Rule:
  - The number `7569980` is preserved as an **`OBSERVED_WIRE`** physical value.
  - No assumption is made that this represents `PHYSIKALISCHE_HW_NR` on EGS `0x18` without independent SGBD validation.
  - The factory mapping remains strictly `OBSERVED_JOB_MAPPING[target=10FLASH]`.

---

## 5. Strict Target-Scoped Evidence Taxonomy Matrix

| Dimension | Physical EGS Bench (`0x18`) | Factory Trace (`10FLASH` / `0x78`) | Evidence Classification |
|---|---|---|---|
| **Target ECU** | ZF 6HP EGS (`0x18`) | Flash Gateway / ECU (`0x78`) | **DIFFERENT TARGET** |
| **SGBD** | `0479S90T641Z` | `10FLASH` | **DIFFERENT SGBD** |
| **Wire Service** | `0x1A 0x87` | `0x1A 0x87` | **MATCHING WIRE SERVICE** |
| **TX Telegram** | `82 18 F1 1A 87 2C` | `82 78 F1 1A 87 8C` | **TARGET ADDRESS DIFFERENCE** |
| **RX Structure** | 24 bytes (3x `7569980`) | 24 bytes (3x `9165672`) | **STRUCTURAL HOMOLOGY** |
| **Job Association** | None (Raw wire probe) | `PHYSIKALISCHE_HW_NR_LESEN` | **JOB PROVENANCE UNPROVEN ON EGS** |
| **Evidence Class** | **`OBSERVED_WIRE`** | **`OBSERVED_JOB_MAPPING`** | **STRICTLY INDEPENDENT** |

---

## 6. Execution & Safety Verification

1. **Single Request**: Exactly one physical DS2 frame `82 18 F1 1A 87 2C` was transmitted.
2. **Zero Retries / Zero Escalation**: No retry was attempted; communication concluded cleanly after response reception.
3. **Safety Compliance**: Zero transmission of `0x10`, `0x27`, `0x31`, `0x11`, reset, flash, authentication, or memory write services.
4. **Transport Closed**: Serial port `/dev/cu.usbserial-A50285BI` was closed immediately upon trace persistence.
