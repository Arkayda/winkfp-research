# Milestone 5.8.1 — Offline Service-ID / Job-Mapping Consistency Audit

**Status**: COMPLETED (STRICTLY OFF-HARDWARE)  
**Safety Gate**: ZERO HARDWARE ACCESS — ZERO SERIAL PORT OPENINGS — NO BYTES TRANSMITTED  
**Date**: 2026-09-26  
**Scope**: Authoritative verification and reconciliation of KWP2000 service identifiers, subfunctions, and job mappings for BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg` / `03GKE195.ipo`).

---

## 1. Executive Summary & Audit Objective

During Milestone 5.8, differential validation confirmed 100% field parity between recovered SGBD bytecode and reconstructed offline execution parsers. However, a discrepancies audit was initiated because the summary text and walkthrough presentation contained conflicting service identifiers:
- `ZIF_LESEN` and `ZIF_BACKUP_LESEN` were informally referenced in the summary table as `(KWP $23)`.
- `HARDWARE_REFERENZ_LESEN` and `DATEN_REFERENZ_LESEN` were informally referenced as `($1A $80)`.

This audit inspects the primary authoritative sources directly:
1. **`03GKE195.ipo`**: BMW PABD sequence script for transmission control module `0x18`.
2. **`10FLASH.prg`**: BMW EDIABAS SGBD binary driver (decoded via XOR `0xF7`).
3. **`traces/sanitized/sanitized_flash_session.trc`**: Factory EDIABAS execution trace.
4. **`reconstruction/ediabas/`**: Standalone clean-room implementations (`sgbd.py`, `execution_model.py`, `differential_validator.py`).
5. **`tests/`**: Master test suite (`test_golden_sgbd_10flash.py`, `test_diff_sgbd_gke195.py`).

**Audit Conclusion**:
The authoritative diagnostic service for `ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, and `DATEN_REFERENZ_LESEN` is **KWP2000 Service `$22` (`ReadDataByCommonIdentifier`)**, using specific 2-byte common identifiers (`$2503`, `$2500`, `$2502`, `$2504`).
The informal references to `$23` and `$1A $80` in the Milestone 5.8 presentation table were drafting transcription errors. The underlying implementation code (`sgbd.py`, `execution_model.py`, `differential_validator.py`) and existing test suites already strictly implemented and tested the authoritative `$22` and `$25xx` definitions.

---

## 2. Canonical Master Service & Job Mapping Table

| Job Name | IPO Procedure | SGBD Routine | Diagnostic Service | Subfunction / Identifier | Wire Request (Target 0x18) | Expected Response SID | Primary Evidence Source | Result Fields Exposed |
|---|---|---|:---:|:---:|:---:|:---:|---|---|
| **`IDENT`** | `Ident` (`SG_IDENT_LESEN`) | `IDENT` (`0x00453A`) | **`$1A`** | `$80` | `82 18 F1 1A 80 25` | `5A 80` | `10FLASH.prg:0x47D00` + Physical trace | `ID_BMW_NR`, `ID_HW_NR`, `ID_COD_INDEX`, `ID_DIAG_INDEX`, `ID_DATUM`, `ID_LIEF_NR`, `ID_LIEF_TEXT`, `ID_SW_NR_MCV`, `ID_SW_NR_FSV`, `ID_SW_NR_OSV`, `ID_SW_NR_RES`, `_PECUHN_FALLBACK` |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | `PhysHwNrLesen` (`SG_PHYS_HWNR_LESEN`) | `PHYSIKALISCHE_HW_NR_LESEN` (`0x012E45`) | **`$1A`** | `$87` (fallback: `$80`) | `82 18 F1 1A 87 2C` | `5A 87` | `10FLASH.prg:0x4A4F7` + Physical trace | `PHYSIKALISCHE_HW_NR`, `JOB_STATUS` |
| **`SERIENNUMMER_LESEN`** | `SgSerienNr` | `SERIENNUMMER_LESEN` (`0x00D172`) | **`$1A`** | `$89` (fallback: `$80`) | `82 18 F1 1A 89 <CS>` | `5A 89` | `10FLASH.prg:0x493F3` + Factory line 28 | `SERIENNUMMER`, `JOB_STATUS` |
| **`AIF_LESEN`** | `AifLesen` (`SG_AIF_LESEN`) | `AIF_LESEN` (`0x028DDE`) | **`$23`** | *(Memory Address + Len)* | `86 18 F1 23 <Addr> <Len> <CS>` | `63` | `10FLASH.prg:0x4F1C2` + Factory line 11960 | `AIF_FG_NR`, `AIF_DATUM`, `AIF_ZB_NR`, `AIF_SW_NR`, `AIF_BEHOERDEN_NR`, `AIF_HAENDLER_NR`, `AIF_KM`, `AIF_PROG_NR`, `AIF_GROESSE` |
| **`AIF_READ_BENCH_ALIAS`** | *(Reconstruction probe)* | *(Direct primitive)* | **`$1A`** | `$86` | `82 18 F1 1A 86 2B` | `5A 86` | `traces/hardware/20260926_173201_egs_aif.json` | `short_vin`, `flash_date`, `zb_number`, `sw_number`, `sgbd`, `tool_marker`, `chassis_prefix` |
| **`ZIF_LESEN`** | `ZifLesen` (`ZIF`) | `ZIF_LESEN` (`0x00E60F`) | **`$22`** | `$2503` (and `$1A $91`, fallback `$1A $80`) | `83 18 F1 22 25 03 <CS>` + `82 18 F1 1A 91 <CS>` | `62 25 03` + `5A 91` | `10FLASH.prg:0x496FC` + Factory line 11661 | `ZIF_PROGRAMM_REFERENZ`, `ZIF_SG_KENNUNG`, `ZIF_PROJEKT`, `ZIF_PROGRAMM_STAND`, `ZIF_STATUS`, `ZIF_BMW_HW` |
| **`ZIF_BACKUP_LESEN`** | `ZifBackupLesen` (`ZIF_BACKUP`) | `ZIF_BACKUP_LESEN` (`0x01126C`) | **`$22`** | `$2500` (fallback: `$1A $80`) | `83 18 F1 22 25 00 <CS>` | `62 25 00` | `10FLASH.prg:0x49E2B` + Factory line 11706 | `ZIF_BACKUP_PROGRAMM_REFERENZ`, `ZIF_BACKUP_SG_KENNUNG`, `ZIF_BACKUP_PROJEKT`, `ZIF_BACKUP_PROGRAMM_STAND`, `ZIF_BACKUP_STATUS`, `ZIF_BACKUP_BMW_HW` |
| **`HARDWARE_REFERENZ_LESEN`** | `HwReferenzLesen` (`HW_REFERENZ`) | `HARDWARE_REFERENZ_LESEN` (`0x0143FA`) | **`$22`** | `$2502` (fallback: `$1A $80`) | `83 18 F1 22 25 02 <CS>` | `62 25 02` | `10FLASH.prg:0x4A81F` + Factory line 11620 | `HARDWARE_REFERENZ`, `HW_REF_SG_KENNUNG`, `HW_REF_PROJEKT`, `HW_REF_STATUS` |
| **`DATEN_REFERENZ_LESEN`** | `DatenReferenzLesen` (`DATEN_REFERENZ`) | `DATEN_REFERENZ_LESEN` (`0x015A66`) | **`$22`** | `$2504` | `83 18 F1 22 25 04 <CS>` | `62 25 04` | `10FLASH.prg:0x4ACCC` + Factory line 11588 | `DATEN_REFERENZ`, `DATEN_REF_SG_KENNUNG`, `DATEN_REF_PROJEKT`, `DATEN_REF_PROGRAMM_STAND`, `DATEN_REF_DATENSATZ`, `DATEN_REF_STATUS` |
| **`FLASH_PROGRAMMIER_STATUS_LESEN`** | `FlashStatusLesen` (`SG_STATUS_LESEN`) | `FLASH_PROGRAMMIER_STATUS_LESEN` (`0x019122`) | **`$31`** | `$0A` | `82 18 F1 31 0A <CS>` | `71 0A` | `10FLASH.prg:0x35150` + `03GKE195.ipo` + Factory line 11724 | `FLASH_PROGRAMMIER_STATUS`, `JOB_STATUS` |
| **`FLASH_ZEITEN_LESEN`** | *(Flash Precondition)* | `FLASH_ZEITEN_LESEN` (`0x0169E6`) | **`$22`** | `$2501` | `83 18 F1 22 25 01 <CS>` | `62 25 01` | `10FLASH.prg:0x35040` | `FLASH_LOESCHZEIT`, `FLASH_SIGNATURTESTZEIT`, `FLASH_RESETZEIT`, `FLASH_AUTHENTISIERZEIT` |
| **`FLASH_BLOCKLAENGE_LESEN`** | *(Flash Precondition)* | `FLASH_BLOCKLAENGE_LESEN` (`0x0178A3`) | **`$22`** | `$2506` | `83 18 F1 22 25 06 <CS>` | `62 25 06` | `10FLASH.prg:0x35084` | `FLASH_BLOCKLAENGE_GESAMT`, `FLASH_BLOCKLAENGE_DATEN` |

---

## 3. Detailed Forensic Inspection of Authoritative Sources

### 3.1 Source 1: `03GKE195.ipo` (PABD Sequence Script)
Decompilation and string inspection of `03GKE195.ipo` (`Downloads/BMW/extracted/E60_daten/sgdat/03GKE195.ipo`) confirms the procedure-to-SGBD bindings:
- Procedure `Ident` invokes SGBD job `, IDENT` (PABD alias: `SG_IDENT_LESEN`).
- Procedure `AifLesen` invokes SGBD job `, AIF_LESEN` (PABD alias: `SG_AIF_LESEN`).
- Procedure `PhysHwNrLesen` invokes SGBD job `, PHYSIKALISCHE_HW_NR_LESEN` (PABD alias: `SG_PHYS_HWNR_LESEN`).
- Procedure `FlashStatusLesen` invokes SGBD job `, FLASH_PROGRAMMIER_STATUS_LESEN` (PABD alias: `SG_STATUS_LESEN`).
- Procedure `HwReferenzLesen` invokes SGBD job `, HARDWARE_REFERENZ_LESEN` (PABD alias: `HW_REFERENZ`).
- Procedure `DatenReferenzLesen` invokes SGBD job `, DATEN_REFERENZ_LESEN` (PABD alias: `DATEN_REFERENZ`).
- Procedure `ZifLesen` invokes SGBD job `, ZIF_LESEN` (PABD alias: `ZIF`).
- Procedure `ZifBackupLesen` invokes SGBD job `, ZIF_BACKUP_LESEN` (PABD alias: `ZIF_BACKUP`).

### 3.2 Source 2: `10FLASH.prg` (EDIABAS SGBD Driver)
In `10FLASH.prg` (decoded via XOR `0xF7`), each job table entry consists of a fixed 68-byte struct (`char name[64]` followed by `uint32_t routine_offset`). The bytecode directly specifies the telegram construction:

#### 1. `ZIF_LESEN` (Routine Offset `0x00E60F`, Metadata Offset `0x496FC`)
* **Metadata Definition**:
  ```text
  JOBNAME:ZIF_LESEN
  JOBCOMMENT:Auslesen des Zulieferinfofeldes
  JOBCOMMENT:KWP2000: $22   ReadDataByCommonIdentifier
  JOBCOMMENT:$2503 ProgrammReferenz
  JOBCOMMENT:und
  JOBCOMMENT:KWP2000: $1A   ReadECUIdentification
  JOBCOMMENT:$91   VehicleManufacturerECUHardware*Number
  JOBCOMMENT:oder alternativ
  JOBCOMMENT:KWP2000: $1A ReadECUIdentification
  JOBCOMMENT:$80 ECUIdentificationDataTable
  ```
* **Bytecode Telegram Construction**:
  - Offset `0x00E617`: constructs `83 FF F1 22 25 03 01` (Service `$22`, Identifier `$2503`).
  - Offset `0x00F17E`: constructs `82 FF F1 1A 91 01` (Service `$1A`, Identifier `$91`).
  - Fallback at `0x00FCC0`: constructs `82 FF F1 1A 80 01` (Service `$1A`, Identifier `$80`).
* **Expected Response SID**: `0x62 0x25 0x03` followed by `0x5A 0x91`.

#### 2. `ZIF_BACKUP_LESEN` (Routine Offset `0x01126C`, Metadata Offset `0x49E2B`)
* **Metadata Definition**:
  ```text
  JOBNAME:ZIF_BACKUP_LESEN
  JOBCOMMENT:Auslesen des Backups des Zulieferinfofeldes
  JOBCOMMENT:ProgrammReferenzBackup         PRGREFB
  JOBCOMMENT:vehicleManufECUHW*NumberBackup VMECUH*NB
  JOBCOMMENT:KWP2000: $22   ReadDataByCommonIdentifier
  JOBCOMMENT:$2500 PRBHW*B
  JOBCOMMENT:oder alternativ
  JOBCOMMENT:KWP2000: $1A ReadECUIdentification
  JOBCOMMENT:$80 ECUIdentificationDataTable
  ```
* **Bytecode Telegram Construction**:
  - Offset `0x011274`: constructs `83 FF F1 22 25 00 01` (Service `$22`, Identifier `$2500`).
  - Fallback at `0x012076`: constructs `82 FF F1 1A 80 01` (Service `$1A`, Identifier `$80`).
* **Expected Response SID**: `0x62 0x25 0x00`.

#### 3. `HARDWARE_REFERENZ_LESEN` (Routine Offset `0x0143FA`, Metadata Offset `0x4A81F`)
* **Metadata Definition**:
  ```text
  JOBNAME:HARDWARE_REFERENZ_LESEN
  JOBCOMMENT:Auslesen der Hardware Referenz
  JOBCOMMENT:KWP2000: $22   ReadDataByCommonIdentifier
  JOBCOMMENT:$2502 HWREF
  JOBCOMMENT:oder alternativ
  JOBCOMMENT:KWP2000: $1A ReadECUIdentification
  JOBCOMMENT:$80 ECUIdentificationDataTable
  ```
* **Bytecode Telegram Construction**:
  - Offset `0x014402`: constructs `83 FF F1 22 25 02 01` (Service `$22`, Identifier `$2502`).
  - Fallback at `0x014F6E`: constructs `82 FF F1 1A 80 01` (Service `$1A`, Identifier `$80`).
* **Expected Response SID**: `0x62 0x25 0x02`.

#### 4. `DATEN_REFERENZ_LESEN` (Routine Offset `0x015A66`, Metadata Offset `0x4ACCC`)
* **Metadata Definition**:
  ```text
  JOBNAME:DATEN_REFERENZ_LESEN
  JOBCOMMENT:Auslesen der Daten Referenz
  JOBCOMMENT:KWP2000: $22   ReadDataByCommonIdentifier
  JOBCOMMENT:$2504 DREF
  ```
* **Bytecode Telegram Construction**:
  - Offset `0x015A6E`: constructs `83 FF F1 22 25 04 01` (Service `$22`, Identifier `$2504`).
* **Expected Response SID**: `0x62 0x25 0x04`.

#### 5. `AIF_LESEN` (Routine Offset `0x028DDE`, Metadata Offset `0x4F1C2`)
* **Metadata Definition**:
  ```text
  JOBNAME:AIF_LESEN
  JOBCOMMENT:Auslesen des Anwender Informations Feldes
  JOBCOMMENT:Standard Flashjob
  JOBCOMMENT:KWP 2000: $23 ReadMemoryByAddress
  ```
* **Bytecode Telegram Construction**:
  - Constructs `86 FF F1 23 <MemAddress(3B)> <MemLen(1B)> <CS>` dynamically.
* **Expected Response SID**: `0x63`.

### 3.3 Source 3: `traces/sanitized/sanitized_flash_session.trc` (Factory Trace)
Direct inspection of the factory flash session trace confirms that WinKFP executed these exact jobs on target `10FLASH` (`0x78`):
1. **`HARDWARE_REFERENZ_LESEN` (Line 11620)**:
   - Request: `83 78 F1 22 25 02` (Service `$22`, Identifier `$2502`)
   - Response (Line 11614): `98 F1 78 62 25 02 30 35 36 31 42 46 31 ...` (Positive SID `$62`)
   - Decoded Result: `HARDWARE_REFERENZ = "0561BF1"`
2. **`ZIF_LESEN` (Line 11661)**:
   - Request 1: `83 78 F1 22 25 03` (Service `$22`, Identifier `$2503`)
   - Response 1 (Line 11654): `A7 F1 78 62 25 03 30 35 36 31 42 46 ...` (Positive SID `$62`)
   - Request 2 (Line 11667): `82 78 F1 1A 91` (Service `$1A`, Identifier `$91`)
   - Response 2 (Line 11663): `94 F1 78 5A 91 00 00 09 19 92 60 ...` (Positive SID `$5A`)
   - Decoded Results: `ZIF_PROGRAMM_REFERENZ = "0561BF1F181A"`, `ZIF_BMW_HW = "9199260"`
3. **`ZIF_BACKUP_LESEN` (Line 11706)**:
   - Request: `83 78 F1 22 25 00` (Service `$22`, Identifier `$2500`)
   - Response (Line 11696): `B9 F1 78 62 25 00 30 35 36 31 42 46 ...` (Positive SID `$62`)
   - Decoded Results: `ZIF_BACKUP_PROGRAMM_REFERENZ = "0561BF1F181A"`, `ZIF_BACKUP_BMW_HW = "9199260"`
4. **`DATEN_REFERENZ_LESEN` (Line 11588)**:
   - Request: `83 78 F1 22 25 04` (Service `$22`, Identifier `$2504`)
   - Response (Line 11586): `84 F1 78 62 25 04 00 78` (Positive SID `$62`, returning `JOB_STATUS = "ERROR_NO_DREF"`)
5. **`AIF_LESEN` (Line 11960)**:
   - Request: `86 78 F1 23 00 00 00 07 12` (Service `$23`, Address `00 00 00`, Length `07`)
   - Response (Line 11956): `93 F1 78 63 12 FF FF FF FF FF ...` (Positive SID `$63`)

---

## 4. Discrepancy Reconciliation Matrix

| Job Name | Erroneous Milestone 5.8 Summary Reference | Authoritative Diagnostic Service & Identifier | Source Proving Correction | Status |
|---|---|---|---|:---:|
| **`ZIF_LESEN`** | `(KWP $23)` | **`$22 25 03`** (plus `$1A 91`) | `10FLASH.prg:0x496FC`, `10FLASH.prg:0x00E617`, `sanitized_flash_session.trc:11661` | **RECONCILED** |
| **`ZIF_BACKUP_LESEN`** | `(KWP $23)` | **`$22 25 00`** | `10FLASH.prg:0x49E2B`, `10FLASH.prg:0x011274`, `sanitized_flash_session.trc:11706` | **RECONCILED** |
| **`HARDWARE_REFERENZ_LESEN`** | `($1A $80)` | **`$22 25 02`** | `10FLASH.prg:0x4A81F`, `10FLASH.prg:0x014402`, `sanitized_flash_session.trc:11620` | **RECONCILED** |
| **`DATEN_REFERENZ_LESEN`** | `($1A $80)` | **`$22 25 04`** | `10FLASH.prg:0x4ACCC`, `10FLASH.prg:0x015A6E`, `sanitized_flash_session.trc:11588` | **RECONCILED** |

### Root Cause Analysis of Discrepancies
1. The codebase implementation (`reconstruction/ediabas/execution_model.py`, `reconstruction/ediabas/sgbd.py`, `reconstruction/ediabas/differential_validator.py`) was already 100% correct and used `$22` and `$25xx`.
2. The discrepancy arose exclusively in the summary markdown table presented in chat and `walkthrough.md`, where:
   - `ZIF_LESEN` and `ZIF_BACKUP_LESEN` were accidentally conflated with `AIF_LESEN` (which legitimately uses KWP `$23`).
   - `HARDWARE_REFERENZ_LESEN` and `DATEN_REFERENZ_LESEN` were accidentally conflated with their fallback service `$1A $80` (or `IDENT`).
3. Factory Trace Promotion:
   - In `docs/evidence/gke195_job_wire_semantic_matrix_milestone_5_6.md`, Section 6.2 originally listed `Fact. Obs. = No` for `ZIF_LESEN`, `ZIF_BACKUP_LESEN`, `HARDWARE_REFERENZ_LESEN`, and `DATEN_REFERENZ_LESEN`.
   - Inspection of lines 11570–11712 of `traces/sanitized/sanitized_flash_session.trc` proves that all four jobs were actively executed against target `10FLASH` during flash programming. Their factory observation status is formally updated to **`Fact. Obs. = Yes`**.

---

## 5. Verification & Test Suite Parity

The full test suite was executed to confirm that no regression or divergence exists:
```bash
.venv/bin/python3 tests/run_tests.py
```

### Execution Output:
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  35 run,  35 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 114 tests in 4.189s | 114 passed | 0 skipped | 0 failed
======================================================================
```

* **Pass Rate**: 114 / 114 tests passed (100%).
* **Physical Trace Fixtures**: SHA-256 hashes of `traces/hardware/*.json` verified 100% identical.
* **Safety Confirmation**: `/dev/cu.usbserial-A50285BI` was never opened; 0 physical bytes transmitted.
