# Milestone 5.16 — Physical Correlation of Official AIF_LESEN ($23)

- **Document Status**: Official Architecture & Evidence Delivery
- **Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)
- **Target Address**: `0x18` (Physical EGS)
- **Tester / Source Address**: `0xF1`
- **Diagnostic Job**: `AIF_LESEN` (KWP2000 Service `0x23` `ReadMemoryByAddress`)
- **Execution Mode**: Single-Transaction, Hardware-Controlled, Read-Only, No Alias/Fallback
- **Canonical Execution Chain**:
  `AIF_LESEN` $\longrightarrow$ `CanonicalPipeline` $\longrightarrow$ `DiagnosticTransport` $\longrightarrow$ `KdcanDiagnosticAdapter` $\longrightarrow$ `SerialKdcanTransport` $\longrightarrow$ physical K+DCAN $\longrightarrow$ ZF 6HP EGS
- **Telemetry Artifact**: `logs/sgbd_semantic_correlation/20260928_145031_physical_official_aif_lesen_23.json`

---

## 1. Executive Summary & Breakthrough Discovery

Milestone 5.16 establishes the **first physical wire correlation** of the official EDIABAS/SGBD job:
$$\text{AIF\_LESEN} \longrightarrow \text{KWP2000 Service 0x23 (ReadMemoryByAddress)} \longrightarrow \text{Request: } 86\ 18\ \text{F1}\ 23\ 00\ 00\ 00\ 07\ 12\ \text{CB} \longrightarrow \text{Positive Response: } 0\text{x}63$$

### 1.1 Key Empirical Findings
1. **ECU Support for Service $23 Confirmed**:
   - The physical ZF 6HP EGS controller natively supports KWP2000 Service `0x23` (`ReadMemoryByAddress`).
   - The ECU responded positively with SID `0x63` within $52.37\text{ ms}$.
   - Result classification: **`POSITIVE_PHYSICAL_CONFIRMATION`**.
2. **SGBD Field Validation**:
   - `AIF_ZB_NR` = `7592132` (exact match with previously established bench AIF ZB-Nummer)
   - `AIF_DATUM` = `04.12.2008` (exact match with flash date `2008.12.04`)
   - `AIF_GROESSE` = `64` (matches AIF block dimension $0\text{x}40 = 64$ bytes)
   - `AIF_PROG_NR` = `1`
3. **Strict Decoupling from 1A86**:
   - **`1A86 fallback attempted = NO`**.
   - **`official AIF_LESEN physical validation = POSITIVE_PHYSICAL_CONFIRMATION`**.
   - Official `AIF_LESEN` ($23) and `AIF_READ_BENCH_ALIAS` ($1A $86) are confirmed as distinct physical operations on this controller.

---

## 2. Critical Semantic Separation: Service 0x23 vs Service 0x1A 0x86

To prevent conflation between diagnostic primitives:

| Dimension | Official `AIF_LESEN` | `AIF_READ_BENCH_ALIAS` |
| :--- | :--- | :--- |
| **KWP2000 Service** | `0x23` (`ReadMemoryByAddress`) | `0x1A` (`ReadEcuIdentification`) |
| **Subfunction / Parameter** | Address `0x000000`, Length `0x07`, Block `0x12` | Identification Record Local ID `0x86` |
| **SGBD Specification** | Official routine in `10FLASH.prg` | Proprietary bench reconstruction probe |
| **Physical TX Wire** | `86 18 F1 23 00 00 00 07 12 CB` (10 bytes) | `82 18 F1 1A 86 2B` (6 bytes) |
| **Physical RX SID** | `0x63` (`93 F1 18 63 40... D3`) | `0x5A` (`80 F1 18 42 5A 86 40... 0F`) |
| **Physical RX Length** | 23 bytes (19 bytes payload) | 71 bytes (66 bytes payload) |
| **Physical Status** | **CONFIRMED (Milestone 5.16)** | **CONFIRMED (Milestone 5.0)** |

Both methods independently read AIF data from physical EGS memory, but they exercise different diagnostic services. No fallback from `0x23` to `1A86` was allowed or attempted.

---

## 3. Pre-Flight Verification Audit

All pre-flight gates were verified before opening the serial port:

| Check ID | Verification Item | Target / Constraint | Observed Value | Status |
| :--- | :--- | :--- | :--- | :--- |
| **PF-1** | Git Checkpoint & Clean Tree | `milestone-5.15-complete` | `90a68651fa629c72bc65df2a7b5e7e647fcf148f` | **PASS** |
| **PF-2** | Canonical Fixtures Integrity | All 4 hardware trace hashes | Bit-for-bit unchanged | **PASS** |
| **PF-3** | Target & Tester Addressing | Target `0x18`, Tester `0xF1` | `0x18` / `0xF1` verified | **PASS** |
| **PF-4** | Selected Job Name | `AIF_LESEN` | `AIF_LESEN` | **PASS** |
| **PF-5** | Selected Diagnostic Service | KWP2000 Service `0x23` | `0x23` | **PASS** |
| **PF-6** | Canonical Request Payload | `23 00 00 00 07 12` | `23 00 00 00 07 12` | **PASS** |
| **PF-7** | Canonical Request Wire Frame | `86 18 F1 23 00 00 00 07 12 CB` | `86 18 F1 23 00 00 00 07 12 CB` | **PASS** |
| **PF-8** | Dangerous Jobs Exclusion | 0 dangerous jobs in pipeline | 0 dangerous jobs in catalog | **PASS** |
| **PF-9** | Keepalive / Session Hooks | Automatic management disabled | Disabled | **PASS** |
| **PF-10** | Fallback Prohibited | No 1A86 fallback configured | Verified None | **PASS** |
| **PF-11** | Constructor Non-Opening | `transport._ser is None` | Confirmed `_ser is None` | **PASS** |
| **PF-12** | Hardware Safety Flag | `--confirm-readonly-hardware` | Verified | **PASS** |
| **PF-13** | Physical Serial Port | `/dev/cu.usbserial-A50285BI` | Present and verified | **PASS** |

---

## 4. Physical Transaction Telemetry

### 4.1 Invariants & Metrics

| Metric | Target / Constraint | Observed Value | Status |
| :--- | :--- | :--- | :--- |
| **TX Transmit Count** | Exactly 1 | 1 | **COMPLIANT** |
| **RX Receive Count** | Exactly 1 | 1 | **COMPLIANT** |
| **Retry Count** | 0 | 0 | **COMPLIANT** |
| **Reopen Attempts** | 0 | 0 | **COMPLIANT** |
| **Fallback Requests** | 0 | 0 | **COMPLIANT** |
| **1A86 Fallback Attempted** | Strictly NO | **NO** | **COMPLIANT** |
| **Prohibited Operations** | 0 | 0 | **COMPLIANT** |
| **Pure Serial RTT** | Nominal 40–80 ms | 52.37 ms | **COMPLIANT** |
| **Port Teardown** | Immediate close in `finally` | Cleanly closed | **COMPLIANT** |

### 4.2 Wire Capture Details
- **Exact TX Wire Frame**:
  ```text
  86 18 F1 23 00 00 00 07 12 CB
  ```
  - Length: `0x86` (6 bytes payload)
  - Target: `0x18` (EGS)
  - Source: `0xF1` (Tester)
  - Payload: `23 00 00 00 07 12`
  - Checksum: `0xCB` (valid 8-bit additive sum)
- **Exact RX Wire Frame**:
  ```text
  93 F1 18 63 40 [XX XX XX XX XX XX XX] 20 08 12 04 00 00 07 59 21 32 D3
  ```
  *(Note: 7-character donor vehicle short VIN masked for public documentation privacy; raw wire length is 23 bytes).*
  - Length: `0x93` (19 bytes payload)
  - Target: `0xF1` (Tester)
  - Source: `0x18` (EGS)
  - Response SID: `0x63` (Positive response to Service `0x23`)
  - Checksum: `0xD3` (valid 8-bit additive sum)

---

## 5. Semantic Field Decoding

Decoded via `reconstruction.ediabas.sgbd.decode_10flash_aif_s23`:

| Field | Decoded Value | SGBD Interpretation |
| :--- | :--- | :--- |
| **`JOB_STATUS`** | `OKAY` | Valid positive response processed |
| **`AIF_ZB_NR`** | `7592132` | Assembly part number (ZB-Nummer) |
| **`AIF_DATUM`** | `04.12.2008` | Programming / Flash date |
| **`AIF_FG_NR`** | `[REDACTED]` | Vehicle identification number (7-char short VIN) |
| **`AIF_GROESSE`** | `64` | User Info Field total allocation size ($0\text{x}40$ bytes) |
| **`AIF_PROG_NR`** | `1` | Flash programming counter |
| **`AIF_BEHOERDEN_NR`**| `0` | Authority specification number |
| **`AIF_HAENDLER_NR`**  | `0` | Dealer number |
| **`AIF_KM`**          | `0` | Odometer at flash time |

---

## 6. SGBD Correlation Status & Remaining UNKNOWNs

With Milestone 5.16 complete, the status of GKE195 jobs is updated:

### 6.1 Confirmed Jobs (Physical Wire & Semantics)
1. **`IDENT` (`0x1A 0x80`)**:
   - Confirmed (Milestone 5.14)
   - `ID_BMW_NR = 7591972`, `ID_SW_NR_FSV = 195.64.1`
2. **`PHYSIKALISCHE_HW_NR_LESEN` (`0x1A 0x87`)**:
   - Confirmed (Milestone 5.15)
   - `PHYSIKALISCHE_HW_NR = 7569980`
3. **`AIF_LESEN` (`0x23`)**:
   - **CONFIRMED (Milestone 5.16)**
   - Positive response SID `0x63`, `AIF_ZB_NR = 7592132`, `AIF_DATUM = 04.12.2008`
4. **`AIF_READ_BENCH_ALIAS` (`0x1A 0x86`)**:
   - Confirmed (Milestone 5.0)
   - 71-byte identification block probe

### 6.2 Actual Remaining UNKNOWNs
1. **`SERIENNUMMER_LESEN` (`1A 89`)**:
   - Factory trace observed on `10FLASH` (`"080072856"`). Physical wire behavior on bench controller `0479S90T641Z` remains unverified.
2. **`ZIF_LESEN` (`$22 2503`)**:
   - SGBD mapped via KWP2000 service `0x22`. Physical wire behavior remains unverified.
3. **`ZIF_BACKUP_LESEN` (`$22 2500`)**:
   - SGBD mapped via KWP2000 service `0x22`. Physical wire behavior remains unverified.

---

## 7. Strict Read-Only Scope Exclusion

> [!CAUTION]
> **Strict Read-Only Semantic Validation Scope**:
> This validation confirms SGBD semantic read correlation only for `AIF_LESEN` (`0x23`).
> It does **NOT** validate:
> - WinKFP / EDIABAS programming or flashing sequences;
> - SecurityAccess seed/key exchange (`0x27`, `0x31 0x07`);
> - Flash block download (`0x34`, `0x36`, `0x37`);
> - Flash memory erase (`0x31 0x01` / `0x31 0x02`);
> - Diagnostic session control / programming session switch (`0x10`);
> - ECU reset (`0x11`);
> - Any modification of ECU non-volatile memory or operational parameters.
