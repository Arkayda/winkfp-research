# Milestone 5.17 — Batch Physical Correlation of Remaining Read-Only SGBD Jobs

- **Document Status**: Official Architecture & Evidence Delivery
- **Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)
- **Target Address**: `0x18` (Physical EGS)
- **Tester / Source Address**: `0xF1`
- **Execution Mode**: Predetermined Batch, Multi-Transaction, Strict Read-Only, No Adaptive Traffic
- **Canonical Execution Chain**:
  `SGBD Job` $\longrightarrow$ `CanonicalPipeline` $\longrightarrow$ `DiagnosticTransport` $\longrightarrow$ `KdcanDiagnosticAdapter` $\longrightarrow$ `SerialKdcanTransport` $\longrightarrow$ physical K+DCAN $\longrightarrow$ ZF 6HP EGS
- **Telemetry Artifact**: [`logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json`](file:///Users/blogman/winkfp-research/logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json)
- **Starting Checkpoint**: `milestone-5.16-complete` (commit `f3229937022d31aa4f15010b12981b042c90c6ff`)

---

## 1. Executive Summary & Major Breakthrough

Milestone 5.17 executes a single predetermined batch of the three remaining read-only SGBD identification jobs against the physical ZF 6HP EGS transmission controller on the bench:
1. `SERIENNUMMER_LESEN` (Service `0x1A 0x89`)
2. `ZIF_LESEN` (Service `0x22 0x2503`)
3. `ZIF_BACKUP_LESEN` (Service `0x22 0x2500`)

### 1.1 Empirical Results Summary
- **100% Positive Response Rate**: All three diagnostic requests received positive responses from the ECU controller.
- **`SERIENNUMMER_LESEN`**:
  - Positive response SID `0x5A`
  - Controller Serial Number: `900405938` (9 ASCII digits)
  - Result: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **`ZIF_LESEN`**:
  - Positive response SID `0x62`
  - Program Reference: `0479S90T641Z` (repeated $3\times$ across the 39-byte payload block)
  - Result: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **`ZIF_BACKUP_LESEN`**:
  - Positive response SID `0x62`
  - Backup Program Reference: `0479S90T641Z` (repeated $3\times$)
  - Base Hardware Part Number: `7591972` (repeated $3\times$, exactly matching `IDENT` `ID_BMW_NR`)
  - Result: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **Total Physical Requests**: Exactly 3 requests emitted, exactly 3 responses received.
- **Safety Invariants**: Retries = 0, Fallback requests = 0, Prohibited operations = 0, Port cleanly closed in `finally`.

---

## 2. Pre-Flight Verification Audit

All pre-flight gates were verified before opening the physical serial interface:

| Gate ID | Verification Check | Target / Invariant | Observed Value | Status |
| :--- | :--- | :--- | :--- | :--- |
| **PF-1** | Git Checkpoint & Clean Tree | `milestone-5.16-complete` | `f3229937022d31aa4f15010b12981b042c90c6ff` | **PASS** |
| **PF-2** | Canonical Fixtures Integrity | SHA-256 of all 4 trace fixtures | Bit-for-bit match | **PASS** |
| **PF-3** | Target and Tester Addressing | Target `0x18`, Tester `0xF1` | `0x18` / `0xF1` | **PASS** |
| **PF-4** | Batch Dimension | Exactly 3 predetermined jobs | 3 jobs | **PASS** |
| **PF-5a** | Request #1 Frame Pre-Assertion | `SERIENNUMMER_LESEN` == `82 18 F1 1A 89 2E` | Bit-for-bit exact match | **PASS** |
| **PF-5b** | Request #2 Frame Pre-Assertion | `ZIF_LESEN` == `83 18 F1 22 25 03 D6` | Bit-for-bit exact match | **PASS** |
| **PF-5c** | Request #3 Frame Pre-Assertion | `ZIF_BACKUP_LESEN` == `83 18 F1 22 25 00 D3` | Bit-for-bit exact match | **PASS** |
| **PF-6** | Dangerous Operations Exclusion | 0 prohibited jobs in catalog | 0 prohibited jobs | **PASS** |
| **PF-7** | Keepalive / Session Hooks | Automatic management disabled | Disabled | **PASS** |
| **PF-8** | Constructor Non-Opening | `transport._ser is None` | Confirmed `_ser is None` | **PASS** |
| **PF-9** | Hardware Safety Flag | `--confirm-readonly-hardware` | Verified present | **PASS** |
| **PF-10**| Physical Serial Port | `/dev/cu.usbserial-A50285BI` | Present and accessible | **PASS** |

---

## 3. Predetermined Batch Execution Telemetry

### 3.1 Batch Metrics & Invariants
- **Total TX Emitted**: 3
- **Total RX Received**: 3
- **Total Retries**: 0
- **Total Reopen Attempts**: 0
- **Total Fallback Requests**: 0
- **Prohibited Operations Count**: 0
- **Physical Transport Teardown**: Confirmed closed in `finally` block.

---

### 3.2 Transaction #1: `SERIENNUMMER_LESEN`

- **Diagnostic Service**: KWP2000 Service `0x1A` (Local Identifier `0x89`)
- **Exact TX Wire Frame**:
  ```text
  82 18 F1 1A 89 2E
  ```
  - Format / Length: `0x82` (2 bytes payload)
  - Target: `0x18` (EGS), Source: `0xF1` (Tester)
  - Payload: `1A 89`
  - Checksum: `0x2E` (valid 8-bit additive sum)
- **Exact RX Wire Frame**:
  ```text
  8B F1 18 5A 89 39 30 30 34 30 35 39 33 38 4D
  ```
  - Format / Length: `0x8B` (11 bytes payload, 15 bytes total frame)
  - Destination: `0xF1` (Tester), Source: `0x18` (EGS)
  - Response SID: `0x5A` (Positive response to Service `0x1A`)
  - Subfunction: `0x89`
  - Serial ASCII Payload: `39 30 30 34 30 35 39 33 38` $\longrightarrow$ `"900405938"`
  - Checksum: `0x4D` (valid 8-bit additive sum: $139 + 241 + 24 + 90 + 137 + 57 + 48 + 48 + 52 + 48 + 53 + 57 + 51 + 56 = 1101 \equiv 0\text{x}4D \pmod{256}$)
- **Pure Serial RTT**: 35.68 ms
- **Validator Status**: `OKAY`
- **Classification**: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **Decoded Semantic Fields**:
  - `SERIENNUMMER`: `"900405938"`
  - `_RAW_SERIAL_HEX`: `"393030343035393338"`
- **Historical Comparison**:
  - Factory trace observed serial on `10FLASH`: `"080072856"`
  - Physical bench ECU serial: `"900405938"`
  - Both adhere to the exact 9-byte ASCII string format specified by `10FLASH.prg`.

---

### 3.3 Transaction #2: `ZIF_LESEN`

- **Diagnostic Service**: KWP2000 Service `0x22` (Common Identifier `0x2503`)
- **Exact TX Wire Frame**:
  ```text
  83 18 F1 22 25 03 D6
  ```
  - Format / Length: `0x83` (3 bytes payload)
  - Target: `0x18` (EGS), Source: `0xF1` (Tester)
  - Payload: `22 25 03`
  - Checksum: `0xD6` (valid 8-bit additive sum)
- **Exact RX Wire Frame**:
  ```text
  A7 F1 18 62 25 03 30 34 37 39 53 39 30 54 36 34 31 5A 30 34 37 39 53 39 30 54 36 34 31 5A 30 34 37 39 53 39 30 54 36 34 31 5A C5
  ```
  - Format / Length: `0xA7` (39 bytes payload, 43 bytes total frame)
  - Destination: `0xF1` (Tester), Source: `0x18` (EGS)
  - Response SID: `0x62` (Positive response to Service `0x22`)
  - Subfunction: `0x2503`
  - Payload Data (39 bytes):
    - Bytes 0..11: `30 34 37 39 53 39 30 54 36 34 31 5A` $\longrightarrow$ `"0479S90T641Z"`
    - Bytes 12..23: `30 34 37 39 53 39 30 54 36 34 31 5A` $\longrightarrow$ `"0479S90T641Z"`
    - Bytes 24..35: `30 34 37 39 53 39 30 54 36 34 31 5A` $\longrightarrow$ `"0479S90T641Z"`
    *(3 repetitions of the 12-byte program reference, analogous to the $3\times$ redundancy in PECUHN / `1A 87`)*
  - Checksum: `0xC5` (valid 8-bit additive sum)
- **Pure Serial RTT**: 79.90 ms
- **Validator Status**: `OKAY`
- **Classification**: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **Decoded Semantic Fields**:
  - `ZIF_PROGRAMM_REFERENZ`: `"0479S90T641Z"`
  - `ZIF_SG_KENNUNG`: `"047"`
  - `ZIF_PROJEKT`: `"9S9"`
  - `ZIF_PROGRAMM_STAND`: `"0T64"`
  - `ZIF_STATUS`: `"0"`
  - `ZIF_BMW_HW`: `""`

---

### 3.4 Transaction #3: `ZIF_BACKUP_LESEN`

- **Diagnostic Service**: KWP2000 Service `0x22` (Common Identifier `0x2500`)
- **Exact TX Wire Frame**:
  ```text
  83 18 F1 22 25 00 D3
  ```
  - Format / Length: `0x83` (3 bytes payload)
  - Target: `0x18` (EGS), Source: `0xF1` (Tester)
  - Payload: `22 25 00`
  - Checksum: `0xD3` (valid 8-bit additive sum)
- **Exact RX Wire Frame**:
  ```text
  B9 F1 18 62 25 00 30 34 37 39 53 39 30 54 36 34 31 5A 30 34 37 39 53 39 30 54 36 34 31 5A 30 34 37 39 53 39 30 54 36 34 31 5A 00 00 07 59 19 72 00 00 07 59 19 72 00 00 07 59 19 72 95
  ```
  - Format / Length: `0xB9` (57 bytes payload, 61 bytes total frame)
  - Destination: `0xF1` (Tester), Source: `0x18` (EGS)
  - Response SID: `0x62` (Positive response to Service `0x22`)
  - Subfunction: `0x2500`
  - Payload Data (57 bytes):
    - Bytes 0..35: $3\times$ `"0479S90T641Z"` (12-byte backup program reference)
    - Bytes 36..53: $3\times$ `00 00 07 59 19 72` (6-byte BCD hardware number $\longrightarrow$ `"7591972"`)
  - Checksum: `0x95` (valid 8-bit additive sum)
- **Pure Serial RTT**: 95.57 ms
- **Validator Status**: `OKAY`
- **Classification**: **`POSITIVE_PHYSICAL_CONFIRMATION`**
- **Decoded Semantic Fields**:
  - `ZIF_BACKUP_PROGRAMM_REFERENZ`: `"0479S90T641Z"`
  - `ZIF_BACKUP_SG_KENNUNG`: `"047"`
  - `ZIF_BACKUP_PROJEKT`: `"9S9"`
  - `ZIF_BACKUP_PROGRAMM_STAND`: `"0T64"`
  - `ZIF_BACKUP_STATUS`: `"0"`
  - `ZIF_BACKUP_BMW_HW`: `""`

---

## 4. Complete Read-Only SGBD Status Matrix

With Milestone 5.17 complete, the physical resolution of the entire canonical read-only SGBD identification catalog for target ZF 6HP EGS (`0x18` / `0479S90T641Z`) is achieved:

| Job Name | Service / Subfunction | Canonical TX Frame | Physical RX Status | Semantic Result | Evidence Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`IDENT`** | `0x1A 0x80` | `82 18 F1 1A 80 25` | `5A 80 <60B Table>` | `ID_BMW_NR=7591972`, `ID_SW_NR_FSV=195.64.1` | **`DIRECTLY_RESOLVED`** |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | `0x1A 0x87` | `82 18 F1 1A 87 2C` | `5A 87 <20B Table>` | `PHYSIKALISCHE_HW_NR=7569980` | **`DIRECTLY_RESOLVED`** |
| **`AIF_LESEN`** | `0x23` | `86 18 F1 23 00 00 00 07 12 CB` | `63 40 <AIF Mem>` | `AIF_ZB_NR=7592132`, `AIF_DATUM=04.12.2008` | **`DIRECTLY_RESOLVED`** |
| **`AIF_READ_BENCH_ALIAS`** | `0x1A 0x86` | `82 18 F1 1A 86 2B` | `5A 86 <66B Payload>` | 71B identification block | **`OBSERVED_WIRE` / `RECONSTRUCTION_ALIAS`** |
| **`SERIENNUMMER_LESEN`** | `0x1A 0x89` | `82 18 F1 1A 89 2E` | `5A 89 <9B Serial>` | `SERIENNUMMER=900405938` | **`DIRECTLY_RESOLVED`** |
| **`ZIF_LESEN`** | `0x22 0x2503` | `83 18 F1 22 25 03 D6` | `62 25 03 <39B Data>` | `ZIF_PROGRAMM_REFERENZ=0479S90T641Z` | **`DIRECTLY_RESOLVED`** |
| **`ZIF_BACKUP_LESEN`** | `0x22 0x2500` | `83 18 F1 22 25 00 D3` | `62 25 00 <57B Data>` | `ZIF_BACKUP_PROGRAMM_REFERENZ=0479S90T641Z` | **`DIRECTLY_RESOLVED`** |

### 4.1 Status of Remaining UNKNOWNs
The set of physical read-only SGBD identification UNKNOWNs is now **COMPLETELY RESOLVED**.
There are **zero remaining unknown read-only identification jobs** for the GKE195 bench target.

---

## 5. Strict Read-Only Scope Exclusion

> [!CAUTION]
> **Strict Read-Only Semantic Validation Scope**:
> This validation establishes read-only identification correlation only.
> It does **NOT** validate or authorize:
> - WinKFP / EDIABAS programming or flashing sequences;
> - SecurityAccess seed/key exchange (`0x27`, `0x31 0x07`);
> - Flash block download (`0x34`, `0x36`, `0x37`);
> - Flash memory erase (`0x31 0x01` / `0x31 0x02`);
> - Diagnostic session control / programming session switch (`0x10`);
> - ECU reset (`0x11`);
> - Any modification of ECU non-volatile memory or operational parameters.
