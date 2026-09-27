# Milestone 5.11.1: Final Evidence Matrix Consistency Audit

**Status**: COMPLETED & VERIFIED (Strictly Off-Hardware)  
**Date**: 2026-09-27  
**Scope**: Factory Trace Audit, Orthogonal Evidence Axes Reconciliation, Direct Semantic Resolution Verification  
**Safety Gate**: **ZERO HARDWARE ACCESS**. No serial ports opened, zero diagnostic bytes transmitted, physical trace fixtures unmodified.

---

## 1. Executive Summary & Audit Objective

Milestone 5.11.1 executes a forensic consistency audit of the 9-job Evidence Matrix established in Milestone 5.11.

The audit resolves two critical architectural issues:
1. **Factory Trace Observation Flags**: Five jobs (`AIF_LESEN`, `ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, `DATEN_REFERENZ_LESEN`) were previously flagged as `factory_trace_observed = False` due to pre-5.8 catalog defaults that inspected only the initial identification sequence (lines 1–50 of the factory trace). A forensic re-inspection of the full sanitized factory trace (`traces/sanitized/sanitized_flash_session.trc`) confirms that WinKFP executed all five jobs on target `0x78` between lines 11588 and 11960.
2. **Decoupling Physical Observation from Direct Resolution**: Confirms that the repository models `physical_trace_exists` and `directly_resolved` as independent, orthogonal axes. Physical observation of raw wire bytes does **not** automatically establish direct semantic resolution. This is conclusively proven by `AIF_READ_BENCH_ALIAS`, where `physical_trace_exists = True` but `directly_resolved = False`.

---

## 2. Authoritative Reconciled Evidence Matrix

| Job Name | SGBD | Factory Observed | Physical EGS | Directly Resolved | Differential | Status | Primary Evidence Source |
|:---|:---:|:---:|:---:|:---:|:---:|:---|:---|
| **`IDENT`** | **True** | **True** | **True** (`0x18`) | **True** | **True** (`EXACT_MATCH`) | `IMPLEMENTED` & `DIFFERENTIAL_VALIDATED` & `PHYSICALLY_OBSERVED` & `FACTORY_OBSERVED` | `traces/hardware/20260926_174811_egs_ident.json` + `sanitized_flash_session.trc:12,16` + `10FLASH.prg` |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | **True** | **True** | **True** (`0x18`) | **True** | **True** (`EXACT_MATCH`) | `IMPLEMENTED` & `DIFFERENTIAL_VALIDATED` & `PHYSICALLY_OBSERVED` & `FACTORY_OBSERVED` | `traces/hardware/20260926_175924_egs_physical_hw_nr.json` + `sanitized_flash_session.trc:20` + `10FLASH.prg` |
| **`SERIENNUMMER_LESEN`** | **True** | **True** | **False** | **False** | **True** (`SEMANTIC_MATCH`) | `IMPLEMENTED` & `DIFFERENTIAL_VALIDATED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:28` (`target=0x78`) + `10FLASH.prg:0x493F3` |
| **`AIF_LESEN`** | **True** | **True** | **False** | **False** | **True** (`STRUCTURAL_MATCH` + Isolation) | `IMPLEMENTED` & `DIFFERENTIAL_VALIDATED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:11960` (`target=0x78`) + `10FLASH.prg:0x4F1C2` |
| **`AIF_READ_BENCH_ALIAS`** | **False** | **False** | **True** (`0x18`) | **False** | **True** (Isolation Verified) | `IMPLEMENTED` & `PHYSICALLY_OBSERVED` (`RECONSTRUCTION_ALIAS`) | `traces/hardware/20260926_173201_egs_aif.json` ($1A $86) |
| **`ZIF_LESEN`** | **True** | **True** | **False** | **False** | **True** (`STRUCTURAL_MATCH`) | `IMPLEMENTED` & `DIFFERENTIAL_VALIDATED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:11661` (`target=0x78`) + `10FLASH.prg:0x496FC` |
| **`ZIF_BACKUP_LESEN`** | **True** | **True** | **False** | **False** | **False** (Golden synthetic tested) | `IMPLEMENTED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:11706` (`target=0x78`) + `10FLASH.prg:0x49E2B` |
| **`HARDWARE_REFERENZ_LESEN`**| **True** | **True** | **False** | **False** | **False** (Golden synthetic tested) | `IMPLEMENTED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:11620` (`target=0x78`) + `10FLASH.prg:0x4A81F` |
| **`DATEN_REFERENZ_LESEN`** | **True** | **True** | **False** | **False** | **False** (Golden synthetic tested) | `IMPLEMENTED` & `FACTORY_OBSERVED` | `sanitized_flash_session.trc:11588` (`target=0x78`) + `10FLASH.prg:0x4ACCC` |

---

## 3. Itemized Correction Log

| Job | Previous Value | Corrected Value | Exact Evidence Source | Reason for Correction |
|:---|:---:|:---:|:---|:---|
| **`AIF_LESEN`** | `factory_trace_observed = False` | **`factory_trace_observed = True`** | `traces/sanitized/sanitized_flash_session.trc:11960`<br>Request: `86 78 F1 23 00 00 00 07 12`<br>Response: `93 F1 78 63 12 FF FF FF FF FF ...` | WinKFP executes official SGBD `AIF_LESEN` via KWP2000 service `$23` at line 11960. Reconciles catalog default with Milestone 5.8.1 audit. |
| **`ZIF_LESEN`** | `factory_trace_observed = False` | **`factory_trace_observed = True`** | `traces/sanitized/sanitized_flash_session.trc:11661`<br>Request 1: `83 78 F1 22 25 03`<br>Response 1: `A7 F1 78 62 25 03 30 35 36 31 42 46 ...`<br>Request 2: `82 78 F1 1A 91`<br>Response 2: `94 F1 78 5A 91 00 00 09 19 92 60 ...` | WinKFP executes `ZIF_LESEN` via service `$22 $2503` followed by `$1A $91` at line 11661. Decodes `ZIF_PROGRAMM_REFERENZ = "0561BF1F181A"`. |
| **`ZIF_BACKUP_LESEN`** | `factory_trace_observed = False` | **`factory_trace_observed = True`** | `traces/sanitized/sanitized_flash_session.trc:11706`<br>Request: `83 78 F1 22 25 00`<br>Response: `B9 F1 78 62 25 00 30 35 36 31 42 46 ...` | WinKFP executes `ZIF_BACKUP_LESEN` via service `$22 $2500` at line 11706. Decodes `ZIF_BACKUP_PROGRAMM_REFERENZ = "0561BF1F181A"`. |
| **`HARDWARE_REFERENZ_LESEN`** | `factory_trace_observed = False` | **`factory_trace_observed = True`** | `traces/sanitized/sanitized_flash_session.trc:11620`<br>Request: `83 78 F1 22 25 02`<br>Response: `98 F1 78 62 25 02 30 35 36 31 42 46 31 ...` | WinKFP executes `HARDWARE_REFERENZ_LESEN` via service `$22 $2502` at line 11620. Decodes `HARDWARE_REFERENZ = "0561BF1"`. |
| **`DATEN_REFERENZ_LESEN`** | `factory_trace_observed = False` | **`factory_trace_observed = True`** | `traces/sanitized/sanitized_flash_session.trc:11588`<br>Request: `83 78 F1 22 25 04`<br>Response: `84 F1 78 62 25 04 00 78` | WinKFP executes `DATEN_REFERENZ_LESEN` via service `$22 $2504` at line 11588, returning positive ACK with `JOB_STATUS = "ERROR_NO_DREF"`. |

---

## 4. Orthogonal Axes Audit: Physical Observation vs Direct Semantic Resolution

Issue 2 requires verifying that:
$$\text{physical\_trace\_exists} == \text{True} \centernot\implies \text{directly\_resolved} == \text{True}$$

### Forensic Verification:
1. **Data Model Structure**:
   - `SgbdJobDefinition` in `reconstruction/ediabas/job_model.py` defines `physical_trace_exists` and `directly_resolved` as two separate, uncoupled boolean attributes.
   - Neither attribute is derived from the other in property getters or constructors.
2. **The `AIF_READ_BENCH_ALIAS` Proof**:
   - On physical hardware, emitting probe `1A 86` returns a 71-byte frame containing VIN and ZB data (`traces/hardware/20260926_173201_egs_aif.json`).
   - Thus: `physical_trace_exists = True`.
   - However, bytecode decompilation of `10FLASH.prg` proves that official SGBD job `AIF_LESEN` uses KWP2000 service `$23` (`ReadMemoryByAddress`), not `$1A $86`.
   - The `1A 86` diagnostic frame is a proprietary bench inquiry, not the official SGBD AIF procedure.
   - Therefore: `directly_resolved = False`.
3. **The `IDENT` and `PHYSIKALISCHE_HW_NR_LESEN` Comparison**:
   - For `IDENT` ($1A $80) and `PHYSIKALISCHE_HW_NR_LESEN` ($1A $87), physical trace bytes directly match the SGBD bytecode routines and their decoded table structures field-by-field.
   - Therefore, and only for this reason: `directly_resolved = True`.

### Formal Definition of Axes:
- **`sgbd_supported`**: Bytecode of `10FLASH.prg` explicitly declares and implements the job routine.
- **`factory_trace_observed`**: An authentic OEM/WinKFP diagnostic trace captures execution of the job on the bus.
- **`physical_trace_exists`**: An unprogrammed/active physical EGS unit (`0x18`) has been queried on the test bench and the raw wire capture is persisted to disk.
- **`directly_resolved`**: The semantic field decoding and wire mapping have been proven against physical EGS behavior (not merely observed or inferred).
- **`differentially_validated`**: Bytecode specifications and reconstructed parser outputs have been compared and validated field-by-field in the automated test suite.

---

## 5. Codebase Synchronization

The following files were updated to maintain total consistency across the repository:
1. `reconstruction/ediabas/pipeline.py`:
   - Updated `factory_trace_observed = True` for `AIF_LESEN`, `ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, and `DATEN_REFERENZ_LESEN`.
2. `reconstruction/ediabas/execution_model.py`:
   - Updated `factory_trace_observed = True` across the legacy catalog definitions.
3. `tests/golden/ediabas/test_gke195_job_execution_model.py`:
   - Line 207: Updated assertion for `AIF_LESEN` to `self.assertTrue(aif_def.factory_trace_observed)`.
4. `tests/golden/ediabas/test_ediabas_job_replay.py`:
   - Line 394: Updated assertion for `ZIF_LESEN` in `test_12_evidence_axis_independence` to `self.assertTrue(synth_res.factory_trace_observed)`.
5. `docs/evidence/architecture_freeze_milestone_5_11.md`:
   - Section 5 Evidence Matrix updated to match the reconciled evidence state.

---

## 6. Test Suite Verification & Immutability Audit

### Test Suite Execution Output
```
.venv/bin/python3 tests/run_tests.py
```
Output:
```
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  62 run,  62 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 141 tests in 4.365s | 141 passed | 0 skipped | 0 failed
======================================================================
```

### Physical Trace Fixture SHA-256 Digest Verification
All four immutable hardware trace files were verified against their reference digests:
```
f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d  traces/hardware/20260926_173201_egs_aif.json
cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791  traces/hardware/20260926_174033_egs_tester_present.json
4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462  traces/hardware/20260926_174811_egs_ident.json
6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15  traces/hardware/20260926_175924_egs_physical_hw_nr.json
```

---

## 7. Safety Invariant Confirmation

- Serial device `/dev/cu.usbserial-A50285BI` was **NOT** opened.
- `tools/kdcan_hardware_probe.py` was **NOT** invoked in live mode.
- Zero diagnostic frames were transmitted on physical hardware.
- ECU state was completely untouched.
- All evidence checks and audits were performed 100% strictly OFF-HARDWARE.
