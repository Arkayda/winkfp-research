# Milestone 5.15 — Physical SGBD Semantic Correlation: PHYSIKALISCHE_HW_NR_LESEN (1A87)

- **Document Status**: Official Architecture & Evidence Delivery
- **Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)
- **Target Address**: `0x18` (Physical EGS)
- **Tester / Source Address**: `0xF1`
- **Diagnostic Job**: `PHYSIKALISCHE_HW_NR_LESEN` (`0x1A 0x87`)
- **Execution Mode**: Single-Transaction, Hardware-Controlled, Read-Only
- **Canonical Execution Chain**:
  `PHYSIKALISCHE_HW_NR_LESEN` $\longrightarrow$ `CanonicalPipeline` $\longrightarrow$ `DiagnosticTransport` $\longrightarrow$ `KdcanDiagnosticAdapter` $\longrightarrow$ `SerialKdcanTransport` $\longrightarrow$ physical K+DCAN $\longrightarrow$ ZF 6HP EGS
- **Artifact Log**: `logs/sgbd_semantic_correlation/20260928_143540_physical_sgbd_semantic_correlation_1a87.json`

---

## 1. Executive Summary & Provenance

Milestone 5.15 validates the end-to-end semantic correlation of the canonical diagnostic pipeline against the physical ZF 6HP EGS transmission controller for the established SGBD job:
$$\text{GKE195 / 10FLASH SGBD Semantics} \longrightarrow \text{PHYSIKALISCHE\_HW\_NR\_LESEN} \longrightarrow \text{Request 1A 87} \longrightarrow \text{Physical Response 5A 87} \longrightarrow \text{PECUHN = 7569980}$$

### 1.1 Provenance Hierarchy
1. **SGBD Provenance**:
   - ECU Family: `GKE195`
   - SGBD File: `10FLASH.prg`
   - Job Routine: `PHYSIKALISCHE_HW_NR_LESEN`
   - Diagnostic Service: KWP2000 Service `0x1A` (ReadEcuIdentification), Subfunction `0x87` (Physical Hardware Number)
2. **Canonical Execution Chain**:
   - `CanonicalPipeline.execute_transport()` builds the DS2 physical wire request `82 18 F1 1A 87 2C`.
   - Protocol boundary `DiagnosticTransport` fulfilled by `KdcanDiagnosticAdapter`.
   - Physical I/O executed via `SerialKdcanTransport` over FTDI USB-serial K+DCAN adapter.
   - Raw wire response validated by `ResponseValidator` (framing, addressing, length, SID).
   - Validated payload decoded by SGBD semantic parser (`decode_10flash_phys_hw_nr`).
3. **Double Verification (Wire vs Semantic)**:
   - **Wire Match**: Exact byte-for-byte match with canonical hardware trace fixture (`24 / 24` bytes, 0 differences).
   - **Semantic Match**: Parsed `PHYSIKALISCHE_HW_NR` equals expected value `7569980` with 3-block PECUHN agreement.

---

## 2. Hard Safety & Architectural Guarantees

1. **Explicit Hardware Opening Sequence**:
   - `SerialKdcanTransport` constructor does **NOT** open the serial port implicitly.
   - Opening sequence strictly enforced:
     $$\text{pre-flight} \longrightarrow \text{confirm-readonly-hardware} \longrightarrow \text{verify port exists} \longrightarrow \text{construct backend} \longrightarrow \text{explicitly open backend} \longrightarrow \text{1 transceive} \longrightarrow \text{close in finally}$$
2. **Hard Invariants**:
   - **TX Count**: Exactly $1$.
   - **RX Count**: Exactly $1$.
   - **Retries**: $0$.
   - **Reopen Attempts**: $0$.
   - **Fallback Requests**: $0$.
   - **Prohibited Operations**: $0$ (no `TesterPresent`, no session control `0x10`, no `SecurityAccess` `0x27`/`0x31 0x07`, no erase `0x31 0x01`, no block transfer `0x34`/`0x36`/`0x37`, no reset `0x11`).
3. **Unconditional Port Teardown**:
   - Immediate serial port teardown guaranteed via unconditional `finally` block in `validate_physical_sgbd_correlation.py`.
4. **Canonical Fixture Immutability**:
   - Reference fixture `traces/hardware/20260926_175924_egs_physical_hw_nr.json` is immutable and never overwritten.
   - SHA-256 digest verified before and after execution: `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15`.

---

## 3. Pre-Flight Verification Audit

All pre-flight checks were executed and validated before any serial port interaction:

| Check ID | Verification Item | Expected Value | Actual Value | Status |
| :--- | :--- | :--- | :--- | :--- |
| **PF-1** | Git Checkpoint & Clean Tree | Verified Git HEAD commit | `0a50b42b0da04d67e13978b0f25f586ddc4048e1` | **PASS** |
| **PF-2** | Canonical Fixtures Integrity | SHA-256 of all 4 frozen hardware traces | Bit-for-bit match on all 4 files | **PASS** |
| **PF-3** | Canonical Request Wire Frame | `82 18 F1 1A 87 2C` | `82 18 F1 1A 87 2C` | **PASS** |
| **PF-4** | Target & Tester Addressing | Target: `0x18`, Tester: `0xF1` | Target: `0x18`, Tester: `0xF1` | **PASS** |
| **PF-5** | Selected Job Name | `PHYSIKALISCHE_HW_NR_LESEN` | `PHYSIKALISCHE_HW_NR_LESEN` | **PASS** |
| **PF-6** | Dangerous Services Exclusion | 0 dangerous jobs in `CanonicalPipeline` | 0 dangerous jobs in catalog | **PASS** |
| **PF-7** | Automatic Keepalive / Session | Disabled (single transaction only) | Disabled (no background hooks) | **PASS** |
| **PF-8** | Constructor Non-Opening | `transport._ser is None` on init | Confirmed `_ser is None` | **PASS** |
| **PF-9** | Hardware Safety Flag | `--confirm-readonly-hardware` required | Flag validated | **PASS** |
| **PF-10** | Physical Port Existence | Port device node present in `/dev/` | `/dev/cu.usbserial-A50285BI` present | **PASS** |

---

## 4. Transaction Telemetry & Golden Fixture Comparison

### 4.1 Verification Metrics Summary

| Metric | Target / Constraint | Observed Value | Status |
| :--- | :--- | :--- | :--- |
| **TX Transmit Count** | Exactly 1 | 1 | **COMPLIANT** |
| **RX Receive Count** | Exactly 1 | 1 | **COMPLIANT** |
| **Retry Count** | 0 | 0 | **COMPLIANT** |
| **Reopen Attempts** | 0 | 0 | **COMPLIANT** |
| **Fallback Requests** | 0 | 0 | **COMPLIANT** |
| **Prohibited Operations** | 0 | 0 | **COMPLIANT** |
| **Serial Port Teardown** | Immediate close in `finally` | Confirmed closed | **COMPLIANT** |
| **Pure Serial RTT** | Nominal 40–80 ms | 55.44 ms | **COMPLIANT** |
| **Canonical Fixture Hash** | `6ce9ec9978369605...` | `6ce9ec9978369605...` | **UNCHANGED** |

### 4.2 Canonical Reference Baseline (`traces/hardware/20260926_175924_egs_physical_hw_nr.json`)
- **Timestamp**: `2026-09-26T14:59:24.019561+00:00`
- **Port**: `/dev/cu.usbserial-A50285BI` (FTDI FT232R, 115200 8N1)
- **TX Wire Frame**: `82 18 F1 1A 87 2C`
- **RX Wire Frame**:
  ```text
  94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0
  ```
- **RX Length**: 24 bytes
- **Checksum**: `0xE0` (valid 8-bit additive sum)
- **RTT**: 48.29 ms

### 4.3 Physical Wire Observation (Milestone 5.15)
- **Executed Pipeline Code**:
  ```python
  serial_backend = SerialKdcanTransport(port="/dev/cu.usbserial-A50285BI", baud=115200, response_timeout=1.0)
  adapter = KdcanDiagnosticAdapter(backend=serial_backend, auto_open=False)
  pipeline = CanonicalPipeline()
  serial_backend.open()
  try:
      result = pipeline.execute_transport(
          job_name="PHYSIKALISCHE_HW_NR_LESEN",
          transport=adapter,
          target_address=0x18,
          tester_address=0xF1,
          timeout=1.0,
      )
  finally:
      serial_backend.close()
  ```
- **Exact Request Wire Frame Passed to Adapter**: `82 18 F1 1A 87 2C` (Match: True)
- **Exact Response Wire Frame Recorded in `adapter.response_history`**:
  ```text
  94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0
  ```
- **Byte-for-Byte Differential Match**: **EXACT MATCH (24 / 24 bytes, 0 differences)**
- **Wire Comparison Classification**: **`EXACT_MATCH`**

---

## 5. Semantic Validation & Interpretation

### 5.1 SGBD Semantic Parser Verification
The response payload structure defined in `10FLASH.prg` contains three identical 6-byte PECUHN records:
$$\text{Payload (20B)} = \text{SID } 0\text{x}5\text{A} \parallel 0\text{x}87 \parallel \underbrace{00\ 00\ 07\ 56\ 99\ 80}_{\text{PECUHN Block 1}} \parallel \underbrace{00\ 00\ 07\ 56\ 99\ 80}_{\text{PECUHN Block 2}} \parallel \underbrace{00\ 00\ 07\ 56\ 99\ 80}_{\text{PECUHN Block 3}}$$

| Field | Expected Semantic Value | Observed Semantic Value | Field Status |
| :--- | :--- | :--- | :--- |
| **`PHYSIKALISCHE_HW_NR`** | `7569980` | `7569980` | **MATCH (EXACT)** |
| **`_BLOCK_COUNT`** | `3` | `3` | **MATCH (EXACT)** |
| **`_BLOCK_MATCH`** | `True` | `True` | **MATCH (EXACT)** |
| **`_RAW_BLOCK_HEX`** | `000007569980` | `000007569980` | **MATCH (EXACT)** |
| **`JOB_STATUS`** | `OKAY` | `OKAY` | **MATCH (EXACT)** |

### 5.2 Wire Match vs Semantic Match Disambiguation
- **Wire Match**: Confirms physical wire framing, addressing (`0xF1 -> 0x18` / `0x18 -> 0xF1`), DS2 length encoding (`0x94` = 20-byte payload), response SID (`0x5A`), subfunction (`0x87`), and checksum (`0xE0`) exactly equal the frozen canonical trace.
- **Semantic Match**: Confirms the SGBD interpretation pipeline correctly strips framing, validates 3-block PECUHN repetition, decodes BCD/hex representation into ASCII numeric representation (`7569980`), and populates `result.fields["PHYSIKALISCHE_HW_NR"]`.

Both assertions are satisfied independently and simultaneously.

---

## 6. SGBD Correlation Status & Remaining UNKNOWNs

While `IDENT` (`0x1A 0x80`) and `PHYSIKALISCHE_HW_NR_LESEN` (`0x1A 0x87`) are now fully verified end-to-end on both wire and semantic levels, the project boundaries are clarified as follows:

### 6.1 Confirmed Bench Observation
- **`AIF_READ_BENCH_ALIAS` (1A 86)**:
  - Physical wire observation = **CONFIRMED** (`71 bytes`, `80 F1 18 42 5A 86 40... 0F`).
  - Physical response = **FIXTURE VALIDATED** (`traces/hardware/20260926_173201_egs_aif.json`).
  - Official SGBD `AIF_LESEN` equivalence = **NOT CONFIRMED** (SGBD specifies KWP2000 service `$23`).

### 6.2 Actual Remaining UNKNOWNs
1. **Official `AIF_LESEN` ($23 ReadMemoryByAddress)**:
   - SGBD-confirmed in `10FLASH.prg`.
   - Physical wire execution has not yet been performed; physical wire response remains unconfirmed on this ECU.
2. **`SERIENNUMMER_LESEN` (1A 89)**:
   - Factory trace observed on `10FLASH` (`"080072856"`).
   - Physical behavior on physical bench controller `0479S90T641Z` remains unverified.
3. **`ZIF_LESEN` ($22 2503)**:
   - SGBD mapped via KWP2000 service `0x22`. Physical wire behavior remains unverified on this bench target.
4. **`ZIF_BACKUP_LESEN` ($22 2500)**:
   - SGBD mapped via KWP2000 service `0x22`. Physical wire behavior remains unverified on this bench target.

---

## 7. Explicit Scope Exclusion Statement

> [!CAUTION]
> **Strict Read-Only Semantic Validation Scope**:
> This physical validation confirms **SGBD semantic read correlation only** for `PHYSIKALISCHE_HW_NR_LESEN` (`0x1A 0x87`).
> It does **NOT** validate:
> - WinKFP / EDIABAS programming or flashing sequences;
> - SecurityAccess seed/key exchange (`0x27`, `0x31 0x07`);
> - Flash block download (`0x34`, `0x36`, `0x37`);
> - Flash memory erase (`0x31 0x01` / `0x31 0x02`);
> - Diagnostic session control / programming session switch (`0x10`);
> - ECU reset (`0x11`);
> - Signature verification or checksum authorization;
> - Any modification of ECU non-volatile memory or operational parameters.
