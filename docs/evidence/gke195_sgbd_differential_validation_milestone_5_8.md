# Offline SGBD Differential Validation — GKE195 / 10FLASH (Milestone 5.8)

**Classification**: RESEARCH DIFFERENTIAL VERIFICATION REPORT  
**Scope**: Field-by-Field Semantic Comparison of Reconstructed Parsers vs Recovered SGBD Bytecode  
**Target ECU**: BMW E60 ZF 6HP EGS (Address: `0x18`, SGBD: `10FLASH.prg`, IPO: `03GKE195.ipo`)  
**Safety Gate**: STRICTLY OFF-HARDWARE (Zero serial port access, zero transmission, zero ECU communication)  

---

## 1. Executive Summary & Objective

The objective of Milestone 5.8 is to validate that the reconstructed offline GKE195 / 10FLASH execution parser produces identical semantic results to the recovered original SGBD bytecode specifications where direct evidence is available.

The comparison is conducted **field-by-field** against:
1. Direct bytecode definitions extracted from `10FLASH.prg` and `03GKE195.ipo`.
2. Immutable physical wire fixtures captured from the bench EGS (`traces/hardware/*.json`).
3. Historical factory execution traces (`traces/sanitized/sanitized_flash_session.trc`).

The comparison does not evaluate high-level pass/fail status alone; every individual data field is evaluated for offset, width, endianness, encoding, conversion rule, validation rule, error behavior, and differential status.

---

## 2. Comparison Methodology & Status Definitions

Every evaluated field is classified under one of six strict, non-collapsible categories:

| Status Category | Definition & Criteria |
|---|---|
| **`EXACT_MATCH`** | Full, identical correspondence in offset, width, byte ordering, conversion logic, and decoded value between reconstructed parser and recovered SGBD bytecode specification. |
| **`STRUCTURAL_MATCH`** | Layout, length, and parsing structure match the SGBD specification, but the value is synthetic, parameterized, or unverified on wire. |
| **`SEMANTIC_MATCH`** | Decoded semantic meaning matches historical observation, but physical wire observation on target `0479S90T641Z` is absent. |
| **`MISMATCH`** | Any discrepancy in offset, width, byte order, decoding rule, or value between reconstructed parser and SGBD specification. |
| **`NOT_APPLICABLE`** | Field is optional or not defined in the specific diagnostic record format. |
| **`UNKNOWN`** | Insufficient bytecode or wire evidence to determine equivalence. Must never be silently resolved. |

---

## 3. Primary Job Differential: IDENT (1A 80)

- **Request Service**: `0x1A` (ReadECUIdentification)
- **Local Identifier**: `0x80` (Standard Identification Table)
- **Request Telegram**: `82 18 F1 1A 80 25`
- **Input Fixture**: [`traces/hardware/20260926_174811_egs_ident.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_174811_egs_ident.json)
- **Raw Wire RX**: `BC F1 18 5A 80 00 00 07 59 19 72 ... 5A D9` (64 bytes total, 60 bytes payload)
- **Evidence Provenance**: Physical EGS wire capture + `10FLASH.prg` decompiled bytecode

### Field-by-Field Differential Matrix

| Field Name | Offset | Width | Endianness | Encoding | Reconstructed Decoded Value | Recovered SGBD Specification | Validation & Conversion Rule | Error Behavior | Status |
|---|---|---|---|---|---|---|---|---|---|
| `ID_BMW_NR` | +2 | 6 B | Big | BCD | `"7591972"` | `"7591972"` | Strip leading zeros from 6-byte BCD (`00 00 07 59 19 72`) | `ERROR_ECU_INCORRECT_LEN` if len < 8 | **`EXACT_MATCH`** |
| `ID_HW_NR` | +8 | 1 B | None | HEX | `"10"` | `"10"` | Format 1 byte as 2-digit hex (`0x10` $\to$ `"10"`) | `ERROR_ECU_INCORRECT_LEN` if len < 9 | **`EXACT_MATCH`** |
| `ID_COD_INDEX` | +9 | 1 B | None | INT | `5` | `5` | Unsigned 8-bit integer (`0x05` $\to$ `5`) | `ERROR_ECU_INCORRECT_LEN` if len < 10 | **`EXACT_MATCH`** |
| `ID_DIAG_INDEX` | +10 | 2 B | Big | INT | `516` | `516` | Unsigned 16-bit big-endian integer (`0x0204` $\to$ `516`) | `ERROR_ECU_INCORRECT_LEN` if len < 12 | **`EXACT_MATCH`** |
| `ID_LIEF_TEXT` | +12 | 3 B | None | ASCII | `"SL "` | `"SL "` | 3-char ASCII string (`53 4C 20` $\to$ Siemens VDO / ZF) | `ERROR_ECU_INCORRECT_LEN` if len < 15 | **`EXACT_MATCH`** |
| `ID_DATUM_JAHR` | +15 | 1 B | None | BCD | `2008` | `2008` | BCD year byte $+ 2000$ (`0x08` $\to$ `2008`) | `ERROR_ECU_INCORRECT_LEN` if len < 16 | **`EXACT_MATCH`** |
| `ID_DATUM_MONAT` | +16 | 1 B | None | BCD | `10` | `10` | BCD month byte (`0x10` $\to$ `10`) | `ERROR_ECU_INCORRECT_LEN` if len < 17 | **`EXACT_MATCH`** |
| `ID_DATUM_TAG` | +17 | 1 B | None | BCD | `30` | `30` | BCD day byte (`0x30` $\to$ `30`) | `ERROR_ECU_INCORRECT_LEN` if len < 18 | **`EXACT_MATCH`** |
| `ID_DATUM` | +15..17 | 3 B | None | BCD | `"30.10.2008"` | `"30.10.2008"` | Formatted composite string `"TT.MM.JJJJ"` | `ERROR_ECU_INCORRECT_LEN` if len < 18 | **`EXACT_MATCH`** |
| `ID_LIEF_NR` | +18 | 1 B | None | INT | `8` | `8` | Unsigned 8-bit integer (`0x08` $\to$ `8`) | `ERROR_ECU_INCORRECT_LEN` if len < 19 | **`EXACT_MATCH`** |
| `ID_SW_NR_MCV` | +19 | 3 B | None | INT | `"0.29.69"` | `"0.29.69"` | 3 bytes formatted as `"A.B.C"` (`00 1D 45` $\to$ `0.29.69`) | `ERROR_ECU_INCORRECT_LEN` if len < 22 | **`EXACT_MATCH`** |
| `ID_SW_NR_FSV` | +22 | 3 B | None | INT | `"195.64.1"` | `"195.64.1"` | 3 bytes formatted as `"A.B.C"` (`C3 40 01` $\to$ `195.64.1`) | `ERROR_ECU_INCORRECT_LEN` if len < 25 | **`EXACT_MATCH`** |
| `ID_SW_NR_OSV` | +25 | 3 B | None | INT | `"2.3.10"` | `"2.3.10"` | 3 bytes formatted as `"A.B.C"` (`02 03 0A` $\to$ `2.3.10`) | `ERROR_ECU_INCORRECT_LEN` if len < 28 | **`EXACT_MATCH`** |
| `ID_SW_NR_RES` | +28 | 3 B | None | INT | `"0.0.0"` | `"0.0.0"` | 3 bytes formatted as `"A.B.C"` (`00 00 00` $\to$ `0.0.0`) | `ERROR_ECU_INCORRECT_LEN` if len < 31 | **`EXACT_MATCH`** |
| `_PECUHN_FALLBACK` | +31 | 6 B | Big | BCD | `"7569980"` | `"7569980"` | Strip leading zeros from 6-byte BCD (`00 00 07 56 99 80`) | Optional if payload len < 37 | **`EXACT_MATCH`** |

* **Total Fields Evaluated**: 15 (12 primary + 3 date components).
* **Mismatches**: **0**.
* **Unknowns**: **0**.
* **Differential Conclusion**: 100% byte-for-byte and semantic identity with `10FLASH.prg:IDENT`.

---

## 4. Primary Job Differential: PHYSIKALISCHE_HW_NR_LESEN (1A 87)

- **Request Service**: `0x1A` (ReadECUIdentification)
- **Local Identifier**: `0x87` (Physical Hardware Number inquiry)
- **Request Telegram**: `82 18 F1 1A 87 2C`
- **Input Fixture**: [`traces/hardware/20260926_175924_egs_physical_hw_nr.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_175924_egs_physical_hw_nr.json)
- **Raw Wire RX**: `94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0` (24 bytes total, 20 bytes payload)
- **Evidence Provenance**: Physical EGS wire capture + `10FLASH.prg` decompiled bytecode

### Field-by-Field Differential Matrix

| Evaluation Dimension | Offset | Width | Reconstructed Parser Behavior | Recovered SGBD Bytecode Rule | Verification Status | Status |
|---|---|---|---|---|---|---|
| **Block 1 Extraction** | +2 | 6 B | Extracts `00 00 07 56 99 80` | Extracts 6 bytes BCD at offset +2 | Byte-for-byte identical | **`EXACT_MATCH`** |
| **Block 2 Extraction** | +8 | 6 B | Extracts `00 00 07 56 99 80` | Extracts 6 bytes BCD at offset +8 | Byte-for-byte identical | **`EXACT_MATCH`** |
| **Block 3 Extraction** | +14 | 6 B | Extracts `00 00 07 56 99 80` | Extracts 6 bytes BCD at offset +14 | Byte-for-byte identical | **`EXACT_MATCH`** |
| **Pairwise Equality Rule** | +2..19 | 18 B | Verifies `block1 == block2 == block3` | SGBD bytecode enforces equality across all 3 blocks | Logic identical | **`EXACT_MATCH`** |
| **Decoded Value** | +2 | 6 B | `"7569980"` (stripped leading zeros) | `"7569980"` (stripped leading zeros) | Value identical | **`EXACT_MATCH`** |
| **Error Branch (Mismatch)** | N/A | N/A | Returns `ERROR_CHECK_PECUHN`, value=`None` | Sets `JOB_STATUS = "ERROR_CHECK_PECUHN"` | Verified via corrupted fixture test | **`EXACT_MATCH`** |
| **Error Branch (Truncated)** | N/A | N/A | Returns `ERROR_ECU_INCORRECT_LEN` if len != 20 | Rejects payload if length != 20 | Verified via truncated fixture test | **`EXACT_MATCH`** |

* **Total Evaluated Checks**: 7.
* **Mismatches**: **0**.
* **Unknowns**: **0**.
* **Differential Conclusion**: Reconstructed implementation reproduces both the positive and negative logic branches of `10FLASH.prg:PHYSIKALISCHE_HW_NR_LESEN`.

---

## 5. Primary Job Differential: SERIENNUMMER_LESEN (1A 89)

- **Request Service**: `0x1A` (ReadECUIdentification)
- **Local Identifier**: `0x89` (Serial Number Read)
- **Factory Telegram**: `8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 D7` (Sanitized trace line 28)
- **Evidence Provenance**: Factory WinKFP trace on target `10FLASH` / `0x78` + SGBD bytecode at `0xD17B`.

### Field-by-Field Differential Matrix

| Field Name | Offset | Width | Reconstructed Decoded Value | Factory Observed Value | SGBD Conversion Rule | Error Behavior | Status |
|---|---|---|---|---|---|---|---|
| `SERIENNUMMER` | +2 | 9 B | `"080072856"` | `"080072856"` | ASCII decode trailing payload, strip nulls and whitespace | `ERROR_ECU_INCORRECT_LEN` if len < 2 | **`SEMANTIC_MATCH`** |

### Evidence Boundary & Isolation
* The decoded value `"080072856"` matches factory evidence on flash gateway `0x78`.
* **Zero Physical Claim**: No physical `1A 89` request was transmitted to the bench EGS (`0x18`).
* Classification is strictly:
  $$\text{DIRECT\_SGBD\_MAPPING[10FLASH]} + \text{OBSERVED\_JOB\_MAPPING[10FLASH]} + \text{UNKNOWN[target=0479S90T641Z]}$$

---

## 6. Protocol Isolation & Secondary Jobs Differential

### 6.1 AIF Distinction: Official `AIF_LESEN` vs Bench Alias `AIF_READ_BENCH_ALIAS`

| Comparison Dimension | Official SGBD Job (`AIF_LESEN`) | Bench Tool Alias (`AIF_READ_BENCH_ALIAS`) | Differential Status |
|---|---|---|---|
| **Diagnostic Service** | KWP2000 Service **`0x23`** (`ReadMemoryByAddress`) | KWP2000 Service **`0x1A`** (`ReadECUIdentification`) | **DISJOINT PROTOCOL SERVICES** |
| **Local / Sub Identifier** | Memory Address (3 bytes) + Length (1 byte) | Local Identifier **`0x86`** (User Info Field record) | **DISJOINT ADDRESSING** |
| **Response SID** | `0x63` (Positive Response to `$23`) | `0x5A` (Positive Response to `$1A`) | **DISJOINT SERVICE RESPONSE** |
| **Payload Structure** | Flash user info memory block ($\ge 32$ bytes) | Identification table (66 bytes) | **STRUCTURALLY DISTINCT** |
| **Behavior on 1A 86 Frame** | Returns `ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86` | Decodes Short VIN, ZB, SW, Date, Tool, Ref | **`EXACT_MATCH` (Rejection Enforced)** |
| **Physical EGS Trace** | None on wire (`UNKNOWN`) | [`traces/hardware/20260926_173201_egs_aif.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_173201_egs_aif.json) | **STRICTLY SEPARATED** |

### 6.2 Secondary Reference Jobs Differential Matrix

| Job Name | Request Telegram | Expected Response | Decoded Primary Field | SGBD Bytecode Rule | Differential Status | Evidence Status |
|---|---|---|---|---|---|---|
| `ZIF_LESEN` | `83 18 F1 22 25 03 <CS>` | `62 25 03 <12B PRGREF>` | `ZIF_PROGRAMM_REFERENZ` | 12-char ASCII program reference | **`STRUCTURAL_MATCH`** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[EGS]` |
| `ZIF_BACKUP_LESEN` | `83 18 F1 22 25 00 <CS>` | `62 25 00 <12B PRGREFB>` | `ZIF_BACKUP_PROGRAMM_REFERENZ` | 12-char ASCII backup reference | **`STRUCTURAL_MATCH`** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[EGS]` |
| `HARDWARE_REFERENZ_LESEN` | `83 18 F1 22 25 02 <CS>` | `62 25 02 <7B HWREF>` | `HARDWARE_REFERENZ` | 7-char ASCII hardware reference | **`STRUCTURAL_MATCH`** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[EGS]` |
| `DATEN_REFERENZ_LESEN` | `83 18 F1 22 25 04 <CS>` | `62 25 04 <17B DREF>` | `DATEN_REFERENZ` | 17-char ASCII data record reference | **`STRUCTURAL_MATCH`** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[EGS]` |

> [!NOTE]
> **Authoritative Service ID Verification**:
> As audited in Milestone 5.8.1, all four secondary reference jobs (`ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, `DATEN_REFERENZ_LESEN`) natively use KWP2000 Service **`0x22` (`ReadDataByCommonIdentifier`)** with common identifiers `$2503`, `$2500`, `$2502`, and `$2504`.
> They must NOT be conflated with:
> - KWP2000 Service `0x23` (`ReadMemoryByAddress`), which is used exclusively by `AIF_LESEN`.
> - KWP2000 Service `0x1A` Subfunction `0x80`, which is the primary request for `IDENT` and serves merely as an SGBD internal error fallback for ZIF and hardware reference reads.

---

## 7. Automated Test Suite Verification

All differential validations were integrated into the master automated test runner under tier `DIFFERENTIAL` ([`tests/differential/ediabas/test_diff_sgbd_gke195.py`](file:///Users/blogman/winkfp-research/tests/differential/ediabas/test_diff_sgbd_gke195.py)).

### Execution Command:
```bash
.venv/bin/python3 tests/run_tests.py
```

### Full Test Runner Output:
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  35 run,  35 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 114 tests in 4.869s | 114 passed | 0 skipped | 0 failed
======================================================================
```

* **KAT Tier**: 63 / 63 passed (cryptographic algorithms, key derivation, framing).
* **Golden Tier**: 35 / 35 passed (offline execution model, trace loading, DS2 validation).
* **Differential Tier**: 16 / 16 passed (OBD32 emulation, SGBD GKE195 field-by-field differential tests).
* **Overall Pass Rate**: **100% (114/114 passed)**.

---

## 8. Physical Trace Immutability Verification

Cryptographic verification confirms that zero physical trace fixtures were altered during Milestone 5.8:

| Trace File | SHA-256 Checksum | Immutability Status |
|---|---|---|
| `traces/hardware/20260926_173201_egs_aif.json` | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **UNMODIFIED** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **UNMODIFIED** |
| `traces/hardware/20260926_174811_egs_ident.json` | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **UNMODIFIED** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **UNMODIFIED** |
