# Milestone 5.9 — Canonical Offline GKE195 Read-Only Job Pipeline

**Status**: COMPLETED (STRICTLY OFF-HARDWARE)  
**Safety Gate**: ZERO HARDWARE ACCESS — ZERO SERIAL PORT OPENINGS — NO BYTES TRANSMITTED  
**Target Family**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg` / `03GKE195.ipo` / Target `0x18`)  
**Date**: 2026-09-26  

---

## 1. Executive Summary

Milestone 5.9 unifies and consolidates the offline execution architecture for all GKE195 / 10FLASH read-only diagnostic identification jobs into a single, deterministic pipeline:

$$\text{SgbdJobDefinition} \longrightarrow \text{Request Builder} \longrightarrow \text{Response Validator} \longrightarrow \text{Semantic Parser} \longrightarrow \text{SgbdJobResult}$$

Prior to this milestone, different diagnostic jobs utilized fragmented helper functions, separate test runners, or duplicated validation logic. Milestone 5.9 establishes:
1. **Single Entry Point**: All read-only identification jobs are registered in a canonical catalog and executed through `CanonicalPipeline.execute(...)`.
2. **Fail-Closed Validation Engine**: `ResponseValidator` validates DS2 framing, target/tester addressing, header lengths, additive 8-bit checksums, response SIDs, subfunctions / common identifiers, and payload boundaries before any semantic parser is invoked.
3. **Strict Wire Protocol Separation**: Preserves the explicit distinction between the official OEM SGBD `AIF_LESEN` job ($23 `ReadMemoryByAddress`) and the bench reconstruction probe alias `AIF_READ_BENCH_ALIAS` ($1A $86 `ReadECUIdentification`). Any attempt to feed a $1A $86 response into `AIF_LESEN` fails closed with `ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86`.
4. **Orthogonal Evidence Classification**: Every job result tracks four independent evidence axes:
   - `sgbd_supported` (Job exists in official SGBD driver bytecode)
   - `factory_trace_observed` (Job execution observed in factory session trace)
   - `physical_trace_exists` (Immutable physical trace fixture exists on bench)
   - `directly_resolved` (High-level job semantic mapping directly proven against target `0479S90T641Z`)

---

## 2. Canonical 4-Stage Pipeline Architecture

```
+-----------------------------------------------------------------------------+
| STAGE 1: SgbdJobDefinition (Metadata & Canonical Constraints)               |
| - Service ID, Subfunction / Common ID, Request Payload                      |
| - Fallback Service & Payload ($1A $80 / $1A $91)                            |
| - Expected Response SID & SubID, Minimum / Exact Length                     |
| - Bound Semantic Parser & Result Field Definitions                          |
| - Orthogonal Evidence Classification Axes                                   |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
| STAGE 2: Request Builder (Deterministic Frame Construction)                 |
| - job_def.build_request(...) or pipeline.build_request(...)                 |
| - Formats DS2 frame (dst=0x18, src=0xF1, format byte, additive checksum)    |
| - Supports primary request vs fallback parameterization                      |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
| STAGE 3: Response Validator (Fail-Closed Gatekeeper)                        |
| 1. Format Byte Verification: (byte[0] & 0xC0) == 0x80                       |
| 2. Header Length Consistency: len(raw_frame) == ds2_body_length + 1         |
| 3. DS2 Addressing Verification: dst == 0xF1, src == 0x18                    |
| 4. Additive Checksum Verification: sum(bytes[:-1]) & 0xFF == byte[-1]       |
| 5. Negative Response Handling: NRC detection (0x7F -> ERROR_ECU_NEGATIVE)   |
| 6. SID & SubID Verification: matches expected SID & SubID / Common ID       |
| 7. Payload Length Boundaries: min_payload_len and exact_payload_len checks  |
+-----------------------------------------------------------------------------+
                                       │
                     [PASS]            │            [FAIL]
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
+------------------------------------+             +------------------------------------+
| STAGE 4: Semantic Parser           |             | Fast Fail-Closed Result            |
| - SGBD decoder extracts typed      |             | - status = <ERROR_CODE>            |
|   fields according to table offset |             | - fields = {}                      |
| - Strips control status variables  |             | - raw_payload preserved            |
| - Returns SgbdJobResult (OKAY)     |             | - errors populated with details    |
+------------------------------------+             +------------------------------------+
```

---

## 3. Canonical Job Catalog & Specification Matrix

The canonical pipeline implements all 9 read-only identification jobs established in the Milestone 5.8.1 audit:

| Job Name | IPO Procedure | SGBD Routine | Diagnostic Service | Subfunction / Common ID | Request Frame (DS2 to 0x18) | Expected Response SID | Wire Ground Truth | Evidence Class |
|---|---|---|:---:|:---:|:---:|:---:|:---:|---|
| **`IDENT`** | `Ident` | `IDENT` (`0x00453A`) | `$1A` | `$80` | `82 18 F1 1A 80 25` | `5A 80` | Physical EGS 0x18 (`20260926_174811_egs_ident.json`) | `DIRECTLY_RESOLVED` |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | `PhysHwNrLesen` | `PHYSIKALISCHE_HW_NR_LESEN` (`0x012E45`) | `$1A` | `$87` (fallback: `$80`) | `82 18 F1 1A 87 2C` | `5A 87` | Physical EGS 0x18 (`20260926_175924_egs_physical_hw_nr.json`) | `DIRECTLY_RESOLVED` |
| **`SERIENNUMMER_LESEN`** | `SgSerienNr` | `SERIENNUMMER_LESEN` (`0x00D172`) | `$1A` | `$89` (fallback: `$80`) | `82 18 F1 1A 89 2E` | `5A 89` | Factory trace line 28 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`AIF_LESEN`** | `AifLesen` | `AIF_LESEN` (`0x028DDE`) | `$23` | *(MemAddress + Len)* | `86 18 F1 23 00 00 00 07 12 CB` | `63` | Factory trace line 11960 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`AIF_READ_BENCH_ALIAS`** | *(Reconstruction)* | *(Direct primitive)* | `$1A` | `$86` | `82 18 F1 1A 86 2B` | `5A 86` | Physical EGS 0x18 (`20260926_173201_egs_aif.json`) | `OBSERVED_WIRE / RECONSTRUCTION_ALIAS` |
| **`ZIF_LESEN`** | `ZifLesen` | `ZIF_LESEN` (`0x00E60F`) | `$22` | `$2503` (fallback: `$1A $91`, `$80`) | `83 18 F1 22 25 03 D6` | `62 25 03` | Factory trace line 11661 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`ZIF_BACKUP_LESEN`** | `ZifBackupLesen` | `ZIF_BACKUP_LESEN` (`0x01126C`) | `$22` | `$2500` (fallback: `$1A $80`) | `83 18 F1 22 25 00 D3` | `62 25 00` | Factory trace line 11706 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`HARDWARE_REFERENZ_LESEN`** | `HwReferenzLesen` | `HARDWARE_REFERENZ_LESEN` (`0x0143FA`) | `$22` | `$2502` (fallback: `$1A $80`) | `83 18 F1 22 25 02 D5` | `62 25 02` | Factory trace line 11620 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |
| **`DATEN_REFERENZ_LESEN`** | `DatenReferenzLesen` | `DATEN_REFERENZ_LESEN` (`0x015A66`) | `$22` | `$2504` | `83 18 F1 22 25 04 D7` | `62 25 04` | Factory trace line 11588 (No physical trace on target) | `DIRECT_SGBD_MAPPING` + `UNKNOWN[target=0479S90T641Z]` |

---

## 4. Response Validator Verification Rules

The `ResponseValidator` implements 7 consecutive fail-closed validation stages:

1. **DS2 Format Byte Verification**:
   - Condition: `(raw_frame[0] & 0xC0) == 0x80`.
   - Failure: Returns `ERROR_DS2_FRAMING` (`"Invalid DS2 format byte"`).
2. **DS2 Encoded Length Verification**:
   - Condition: `len(raw_frame) == ds2_body_length(raw_frame) + 1`.
   - Failure: Returns `ERROR_DS2_FRAMING` (`"Frame length X != expected Y"`).
3. **DS2 Addressing Verification**:
   - Condition: `raw_frame[1] == tester_address (0xF1)` and `raw_frame[2] == target_address (0x18)`.
   - Failure: Returns `ERROR_DS2_ADDRESSING` (`"Address mismatch"`).
4. **Additive Checksum Verification**:
   - Condition: `raw_frame[-1] == (sum(raw_frame[:-1]) & 0xFF)`.
   - Failure: Returns `ERROR_DS2_CHECKSUM` (`"Checksum error: got 0xXX, expected 0xYY"`).
5. **Negative Response Code (NRC) Handling**:
   - Condition: `payload[0] != 0x7F`.
   - Failure: Returns `ERROR_ECU_NEGATIVE_RESPONSE_0x<NRC>` (`"Negative response received with NRC 0xXX"`).
6. **Expected Response SID & SubID / Common ID Verification**:
   - Condition: `payload[0] == expected_response_sid`.
   - Special Rule: If `AIF_LESEN` receives `5A 86`, returns explicit error `ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86`.
   - 1-Byte SubID Condition: `payload[1] == expected_response_subfunction`.
   - 2-Byte Common ID Condition: `payload[1:3] == expected_common_id_bytes`.
   - Failure: Returns `ERROR_ECU_INCORRECT_RESPONSE_ID` or `ERROR_ECU_INCORRECT_SUBID`.
7. **Payload Length Boundary Checks**:
   - Condition: `len(payload) >= min_payload_len` and (if specified) `len(payload) == exact_payload_len`.
   - Failure: Returns `ERROR_ECU_INCORRECT_LEN`.

---

## 5. Automated Verification Results

A dedicated deterministic Golden test suite was developed and integrated into the master test runner:
- **Test File**: `tests/golden/ediabas/test_canonical_pipeline.py`
- **Scenarios Tested**:
  1. `test_01_ident_pipeline_physical_trace`: End-to-end execution of `IDENT` against physical trace fixture `traces/hardware/20260926_174811_egs_ident.json`. Verified all 12 decoded fields.
  2. `test_02_phys_hwnr_pipeline_physical_trace`: End-to-end execution of `PHYSIKALISCHE_HW_NR_LESEN` against physical trace fixture `traces/hardware/20260926_175924_egs_physical_hw_nr.json`.
  3. `test_03_malformed_response_rejection`: Corrupted format byte rejected before parser invocation with `ERROR_DS2_FRAMING`.
  4. `test_04_checksum_rejection`: Bit-flipped checksum byte rejected with `ERROR_DS2_CHECKSUM`.
  5. `test_05_wrong_response_sid`: Unexpected SID (e.g. `0x50` instead of `0x5A`) rejected with `ERROR_ECU_INCORRECT_RESPONSE_ID`.
  6. `test_06_wrong_local_identifier`: Incorrect 1-byte local ID (`0x89` for `IDENT`) and 2-byte common ID (`0x2599` for `ZIF_LESEN`) rejected with `ERROR_ECU_INCORRECT_SUBID`.
  7. `test_07_wrong_ds2_length`: Truncated frame rejected with `ERROR_DS2_FRAMING`.
  8. `test_08_fallback_metadata_preservation`: Request builders generate exact DS2 wire frames for primary and fallback modes across `IDENT`, `PHYSIKALISCHE_HW_NR_LESEN`, `ZIF_LESEN`, and `HARDWARE_REFERENZ_LESEN`.
  9. `test_09_aif_s23_vs_1a86_distinction`: Physical $1A $86 trace rejected by official `AIF_LESEN` with `ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86`, but decoded successfully by `AIF_READ_BENCH_ALIAS`.
  10. `test_10_evidence_axis_independence`: Verified orthogonal independence of all four evidence classification axes across different job types.

### Master Test Suite Output
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  45 run,  45 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 124 tests in 4.578s | 124 passed | 0 skipped | 0 failed
======================================================================
```

---

## 6. Physical Trace Immutability Verification

All four physical hardware trace fixtures remain strictly unmodified with identical cryptographic digests:

| File Path | Expected SHA-256 Digest | Audit Status |
|---|---|:---:|
| `traces/hardware/20260926_173201_egs_aif.json` | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **VERIFIED IDENTICAL** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **VERIFIED IDENTICAL** |
| `traces/hardware/20260926_174811_egs_ident.json` | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **VERIFIED IDENTICAL** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **VERIFIED IDENTICAL** |

---

## 7. Strict Hardware Boundary Affirmation

During Milestone 5.9:
- Zero serial ports were opened.
- Port `/dev/cu.usbserial-A50285BI` was never accessed or queried.
- Zero bytes were transmitted across any physical diagnostic bus.
- All testing and validation were conducted in pure offline mode against immutable recorded fixtures and synthetic corrupted vectors.
