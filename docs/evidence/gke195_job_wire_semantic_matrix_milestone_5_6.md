# Milestone 5.6 — Offline GKE195 Job/Wire Semantic Matrix

**Status**: COMPLETED (STRICTLY OFF-HARDWARE)  
**Safety Status**: ZERO HARDWARE ACCESS — ZERO SERIAL PORT OPENINGS — NO BYTES TRANSMITTED  
**Date**: 2026-09-26  

---

## 1. Executive Summary

Using strictly offline artifacts from the repository and extracted SP-Daten/Standard Tools archives, this milestone establishes the canonical, end-to-end correlation matrix for all identification and status diagnostics for:
- **Vehicle Platform**: BMW E60
- **Transmission Family**: ZF 6HP EGS (`GKE195`, diagnostic address `0x18`, tester `0xF1`)
- **PABD Sequence Script**: `03GKE195.ipo`
- **SGBD Diagnostic Driver**: `10FLASH.prg`
- **Observed Assembly**: `ZB 7592132` / `A7592133.0da` (`$REFERENZ 0479S90T641Z1ZY02`)

This document links:
$$\text{WinKFP Job} \longrightarrow \text{PABD Procedure} \longrightarrow \text{SGBD Routine} \longrightarrow \text{Wire Request} \longrightarrow \text{Wire Response} \longrightarrow \text{SGBD Results} \longrightarrow \text{Physical Observation}$$

---

## 2. Canonical GKE195 Job-to-Wire Table

| Job Name (WinKFP / EDIABAS) | PABD Procedure (`03GKE195.ipo`) | SGBD Routine (`10FLASH.prg`) | Wire Request (Hex Payload) | Wire Response (Expected / Service) | Result Fields Exposed by SGBD | Semantic Meaning & Conversion Rules | Classification |
|---|---|---|---|---|---|---|---|
| `IDENT` | `Ident` (via `SG_IDENT_LESEN`) | `IDENT` | `82 18 F1 1A 80 25` | `5A 80 <60B Table>` | `ID_BMW_NR`, `ID_HW_NR`, `ID_COD_INDEX`, `ID_DIAG_INDEX`, `ID_VAR_INDEX`, `ID_DATUM`, `ID_LIEF_NR`, `ID_LIEF_TEXT`, `ID_SW_NR_MCV`, `ID_SW_NR_FSV`, `ID_SW_NR_OSV`, `ID_SW_NR_RES`, `_PECUHN_FALLBACK` | Base HW part number (`7591972`), HW version index (`"10"`), supplier text (`"SL "`), date (`"30.10.2008"`), software versions (`0.29.69`, `195.64.1`, `2.3.10`), embedded PECUHN (`7569980`). | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `PHYSIKALISCHE_HW_NR_LESEN` | `PhysHwNrLesen` (via `SG_PHYS_HWNR_LESEN`) | `PHYSIKALISCHE_HW_NR_LESEN` | `82 18 F1 1A 87 2C` (fallback: `1A 80`) | `5A 87 <6B PECUHN x 3>` | `PHYSIKALISCHE_HW_NR`, `JOB_STATUS` | Physical ECU unprogrammed controller board HW number (`"7569980"`). Bytecode requires $3\times$ pairwise block match. | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `AIF_LESEN` (SGBD) | `AifLesen` (via `SG_AIF_LESEN`) | `AIF_LESEN` | `86 18 F1 23 <Addr> <Len> <CS>` | `63 <AIF Data>` | `AIF_FG_NR`, `AIF_FG_NR_LANG`, `AIF_DATUM`, `AIF_ZB_NR`, `AIF_SW_NR`, `AIF_BEHOERDEN_NR`, `AIF_HAENDLER_NR`, `AIF_SERIEN_NR`, `AIF_KM`, `AIF_PROG_NR`, `AIF_GROESSE` | User Info Field read via KWP2000 `$23 ReadMemoryByAddress`. Physically confirmed on bench EGS (Milestone 5.16). | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `AIF_READ_BENCH_ALIAS` | *(Reconstruction tool probe)* | *(Direct KWP2000 primitive)* | `82 18 F1 1A 86 2B` | `80 F1 18 42 5A 86 40...` (66B payload / 71B frame) | *(Parsed by bench tool)*: VIN `[REDACTED]`, ZB `7592132`, SW `7592133`, Date `2008.12.04`, Tool `NFS01`, Ref `0479S90T641Z` | Direct KWP2000 `$1A $86` identification record. | **`OBSERVED_WIRE`** / `RECONSTRUCTION_ALIAS` |
| `SERIENNUMMER_LESEN` | `SgSerienNr` | `SERIENNUMMER_LESEN` | `82 18 F1 1A 89 2E` (fallback: `1A 80`) | `5A 89 <Serial ASCII>` | `SERIENNUMMER` | Supplier ECU serial number string (`"900405938"` on bench EGS). | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `ZIF_LESEN` | `ZifLesen` (via `ZIF`) | `ZIF_LESEN` | `83 18 F1 22 25 03 D6` (fallback: `1A 91`) | `62 25 03 <39B PRGREF>` | `ZIF_PROGRAMM_REFERENZ`, `ZIF_SG_KENNUNG`, `ZIF_PROJEKT`, `ZIF_PROGRAMM_STAND`, `ZIF_STATUS`, `ZIF_BMW_HW` | Supplier Info Field: program reference (`"0479S90T641Z"` repeated $3\times$). | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `ZIF_BACKUP_LESEN` | `ZifBackupLesen` (via `ZIF_BACKUP`) | `ZIF_BACKUP_LESEN` | `83 18 F1 22 25 00 D3` (fallback: `1A 80`) | `62 25 00 <57B PRGREFB>` | `ZIF_BACKUP_PROGRAMM_REFERENZ`, `ZIF_BACKUP_SG_KENNUNG`, `ZIF_BACKUP_PROJEKT`, `ZIF_BACKUP_PROGRAMM_STAND`, `ZIF_BACKUP_STATUS`, `ZIF_BACKUP_BMW_HW` | Backup supplier info field (program reference `"0479S90T641Z"` + HW `"7591972"` repeated $3\times$). | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| `HARDWARE_REFERENZ_LESEN` | `HwReferenzLesen` (via `HW_REFERENZ`) | `HARDWARE_REFERENZ_LESEN` | `83 18 F1 22 25 02 <CS>` (fallback: `1A 80`) | `62 25 02 <7B HWREF>` | `HARDWARE_REFERENZ`, `HW_REF_SG_KENNUNG`, `HW_REF_PROJEKT`, `HW_REF_STATUS` | 7-byte ASCII HW reference (`ZZZPPPx`). | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[target=0479S90T641Z]` |
| `DATEN_REFERENZ_LESEN` | `DatenReferenzLesen` (via `DATEN_REFERENZ`) | `DATEN_REFERENZ_LESEN` | `83 18 F1 22 25 04 <CS>` | `62 25 04 <17B DREF>` | `DATEN_REFERENZ`, `DATEN_REF_SG_KENNUNG`, `DATEN_REF_PROJEKT`, `DATEN_REF_PROGRAMM_STAND`, `DATEN_REF_DATENSATZ`, `DATEN_REF_STATUS` | 17-byte ASCII data reference (`ZZZPPPxVBBxhdxxxx`). | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[target=0479S90T641Z]` |
| `FLASH_PROGRAMMIER_STATUS_LESEN` | `FlashStatusLesen` (via `SG_STATUS_LESEN`) | `FLASH_PROGRAMMIER_STATUS_LESEN` | `82 18 F1 31 0A <CS>` | `71 0A <StatusByte>` | `FLASH_PROGRAMMIER_STATUS`, `FLASH_PROGRAMMIER_STATUS_TEXT` | Programming state machine status (0..255) via RoutineControl `$31 $0A`. | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[target=0479S90T641Z]` |
| `FLASH_ZEITEN_LESEN` | *(Flash precondition)* | `FLASH_ZEITEN_LESEN` | `83 18 F1 22 25 01 <CS>` | `62 25 01 <Timers>` | `FLASH_LOESCHZEIT`, `FLASH_SIGNATURTESTZEIT`, `FLASH_RESETZEIT`, `FLASH_AUTHENTISIERZEIT` | Precondition timers for flash erase, signature test, reset, authentication. | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[target=0479S90T641Z]` |
| `FLASH_BLOCKLAENGE_LESEN` | *(Flash precondition)* | `FLASH_BLOCKLAENGE_LESEN` | `83 18 F1 22 25 06 <CS>` | `62 25 06 <MaxLen>` | `FLASH_BLOCKLAENGE_GESAMT`, `FLASH_BLOCKLAENGE_DATEN` | Maximum download block size supported by ECU. | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[target=0479S90T641Z]` |
| `DIAGNOSE_AUFRECHT` | *(Keep-alive loop)* | `DIAGNOSE_AUFRECHT` | `82 18 F1 3E 01 <CS>` (or `C2 EF F1 3E 02`) | `7E 01` (or suppressed) | `JOB_STATUS` | TesterPresent periodic keep-alive (`$3E $01` or `$3E $02`). | `DIRECT_SGBD_MAPPING[10FLASH]` / `OBSERVED_JOB_MAPPING[target=10FLASH]` |
| `TESTER_PRESENT_BENCH` | *(Reconstruction probe)* | *(Direct KWP2000 primitive)* | `82 18 F1 3E 00 C9` | `83 F1 18 7F 3E 12 5B` | *(Parsed by bench tool)*: NRC `0x12` | TesterPresent `$3E $00`: ECU responds with NRC `0x12` (`SubFunctionNotSupported`), confirming presence. | **`OBSERVED_WIRE`** |

---

## 3. Evidence Matrix

| Claim | Evidence Source | Strict Classification |
|---|---|---|
| `10FLASH.prg` is the official SGBD for EGS `0x18` / `GKE195` | `KFCONF10.DA2:292` | **`DIRECT_SGBD_MAPPING`** |
| `03GKE195.ipo` is the official WinKFP sequence script for EGS `0x18` | `KFCONF10.DA2:292` | **`DIRECT_SGBD_MAPPING`** |
| `7592132` (ZB-NR) belongs to `GKE195` and uses `HW-NR 7591972` | `GKE195.DAT:16` | **`DIRECT_SGBD_MAPPING`** |
| `0479S90T641Z` is the calibration `$REFERENZ` of `A7592133.0da` | `A7592133.0da:7, 76` | **`DIRECT_SGBD_MAPPING`** |
| Both `7569980` and `7591972` are valid hardware numbers for `GKE195` | `HWNR.DA2:7076, 7085` | **`DIRECT_SGBD_MAPPING`** |
| Wire request `1A 80` produces identification table matching `IDENT` | `traces/hardware/20260926_174811_egs_ident.json` + `10FLASH.prg` bytecode | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| Wire request `1A 87` produces $3\times$ blocks matching `PHYSIKALISCHE_HW_NR` | `traces/hardware/20260926_175924_egs_physical_hw_nr.json` + `10FLASH.prg` bytecode | **`DIRECTLY RESOLVED`** (`OBSERVED_WIRE` + `DIRECT_SGBD_MAPPING`) |
| Wire request `1A 86` produces AIF record containing ZB/SW/VIN/Ref | `traces/hardware/20260926_173201_egs_aif.json` | **`OBSERVED_WIRE`** (Wire primitive established; SGBD uses `$23`) |
| Wire request `3E 00` produces NRC `0x12` acknowledging tester presence | `traces/hardware/20260926_174033_egs_tester_present.json` | **`OBSERVED_WIRE`** |
| `SERIENNUMMER_LESEN` maps to `1A 89` | `traces/sanitized/sanitized_flash_session.trc:28` + `10FLASH.prg:0xD17B` | `OBSERVED_JOB_MAPPING[target=10FLASH]` (Unverified on EGS `0x18` wire: `UNKNOWN`) |
| `SG_STATUS_LESEN` maps to `31 0A` (CheckProgrammingStatus) | `03GKE195.ipo` + `10FLASH.prg:0x1AF80` | `DIRECT_SGBD_MAPPING[10FLASH]` (Unverified on EGS `0x18` wire: `UNKNOWN`) |
| `SG_STATUS_LESEN` maps to `3E 00` | Speculative early reconstruction assumption | **`REJECTED`** / **`DISPROVEN`** (SGBD explicitly uses `$31 $0A`, not `$3E`) |
| `AIF_LESEN` maps to `1A 86` | Early bench tool mapping | **`RECONSTRUCTION_ALIAS`** (Official SGBD job uses `$23 ReadMemoryByAddress`) |

---

## 4. Physical Trace Cross-Reference

All four physical traces previously captured on hardware remain immutable fixtures on disk:

### 1. Milestone 5.0 — Physical AIF Probe
- **Trace Path**: `traces/hardware/20260926_173201_egs_aif.json`
- **Exact TX Wire**: `82 18 f1 1a 86 2b`
- **Exact RX Wire**: `80 f1 18 42 5a 86 40 [XX XX XX XX XX XX XX] 20 08 12 04 00 00 07 59 21 32 00 00 07 59 21 33 00 00 00 00 00 00 00 02 40 4e 46 53 30 31 00 30 34 37 39 53 39 30 54 36 34 31 5a [XX XX XX XX XX XX XX XX XX XX] ff ff ff 0f` (71 bytes, RTT = 85.01 ms)
- **Decoded Semantics**:
  - Short VIN: `[REDACTED]` (sanitized)
  - ZB Number: `7592132`
  - SW Number: `7592133`
  - Flash Date: `2008.12.04`
  - Calibration Ref: `0479S90T641Z`
  - Tool Marker: `NFS01`
- **Semantic Status**: `OBSERVED_WIRE` (Direct KWP2000 `$1A $86` read).

### 2. Milestone 5.1 — Physical TesterPresent Probe
- **Trace Path**: `traces/hardware/20260926_174033_egs_tester_present.json`
- **Exact TX Wire**: `82 18 f1 3e 00 c9`
- **Exact RX Wire**: `83 f1 18 7f 3e 12 5b` (7 bytes, RTT = 31.96 ms)
- **Decoded Semantics**: Negative Response NRC `0x12` (`SubFunctionNotSupported`), confirming active diagnostic session/bus presence without changing state.
- **Semantic Status**: `OBSERVED_WIRE`.

### 3. Milestone 5.2 — Physical Identification Probe (`1A 80`)
- **Trace Path**: `traces/hardware/20260926_174811_egs_ident.json`
- **Exact TX Wire**: `82 18 f1 1a 80 25`
- **Exact RX Wire**: `bc f1 18 5a 80 00 00 07 59 19 72 10 05 02 04 53 4c 20 08 10 30 08 00 1d 45 c3 40 01 02 03 0a 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5a d9` (64 bytes, RTT = 80.01 ms)
- **Decoded SGBD Semantics (`10FLASH.prg:IDENT`)**:
  - `ID_BMW_NR`: `"7591972"` (Base assembly hardware number)
  - `ID_HW_NR`: `"10"` (Hardware version index)
  - `ID_COD_INDEX`: `5`
  - `ID_DIAG_INDEX`: `516` (`0x0204`)
  - `ID_LIEF_TEXT`: `"SL "` (Supplier Siemens VDO / ZF)
  - `ID_DATUM`: `"30.10.2008"`
  - `ID_SW_NR_MCV`: `"0.29.69"`
  - `ID_SW_NR_FSV`: `"195.64.1"`
  - `ID_SW_NR_OSV`: `"2.3.10"`
  - `ID_SW_NR_RES`: `"0.0.0"`
  - `_PECUHN_FALLBACK`: `"7569980"`
  - Calibration Descriptor: `"0479S90"`, `"T641Z"`
- **Semantic Status**: **`DIRECTLY RESOLVED`**.

### 4. Milestone 5.3 — Physical Hardware-Number Probe (`1A 87`)
- **Trace Path**: `traces/hardware/20260926_175924_egs_physical_hw_nr.json`
- **Exact TX Wire**: `82 18 f1 1a 87 2c`
- **Exact RX Wire**: `94 f1 18 5a 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 e0` (24 bytes, RTT = 48.29 ms)
- **Decoded SGBD Semantics (`10FLASH.prg:PHYSIKALISCHE_HW_NR_LESEN`)**:
  - `PHYSIKALISCHE_HW_NR`: `"7569980"` (PECUHN = *physicalECUHardwareNumber*)
  - 3-Block Validation: `True` (`00 00 07 56 99 80` repeated $3\times$)
- **Semantic Status**: **`DIRECTLY RESOLVED`**.

---

## 5. Sanitized Factory Trace Cross-Reference

Sanitized factory trace `traces/sanitized/sanitized_flash_session.trc` captures WinKFP executing `10FLASH.prg` against target address `0x78`:

| Trace Line | Factory Wire TX | SGBD Job Name | Expected Wire Behavior | Observed on Physical EGS 0x18? | Correlation Notes |
|---|---|---|---|---|---|
| 28 | `82 78 F1 1A 89 8E` | `SERIENNUMMER_LESEN` | `5A 89 <Serial>` | Not tested on wire (`UNKNOWN`) | SGBD bytecode at `0xD172` confirms identical request structure (`82 <ADDR> F1 1A 89`). |
| 35 | `82 78 F1 1A 80 85` | `IDENT` | `5A 80 <IdentTable>` | **YES** (`82 18 F1 1A 80 25`) | Byte-for-byte structural match; fields decoded identically by `10FLASH.prg`. |
| 45 | `82 78 F1 1A 87 8C` | `PHYSIKALISCHE_HW_NR_LESEN` | `5A 87 <PECUHN x 3>` | **YES** (`82 18 F1 1A 87 2C`) | Byte-for-byte structural match ($3\times$ 6-byte blocks). |
| 62 | `87 78 F1 31 07 03 ...` | `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` | `71 07 <Seed>` | Not tested on wire (`UNKNOWN`) | RoutineControl `$31 $07` for seed negotiation. |
| 74 | `92 78 F1 31 08 ...` | `NG_AUTHENTISIERUNG_START` | `71 08 01` | Not tested on wire (`UNKNOWN`) | RoutineControl `$31 $08` for key submission. |
| 82 | `82 78 F1 10 85 ...` | `DIAGNOSE_MODE "ECUPM"` | `50 85` | Not tested on wire (`UNKNOWN`) | Session change after successful authentication. |
| 11588 | `83 78 F1 22 25 04 ...` | `DATEN_REFERENZ_LESEN` | `62 25 04 ...` | Not tested on wire (`UNKNOWN`) | Service `$22 $2504` (returns `ERROR_NO_DREF`). |
| 11620 | `83 78 F1 22 25 02 ...` | `HARDWARE_REFERENZ_LESEN` | `62 25 02 <HWREF>` | Not tested on wire (`UNKNOWN`) | Service `$22 $2502`: returns `"0561BF1"`. |
| 11661 | `83 78 F1 22 25 03 ...` | `ZIF_LESEN` | `62 25 03` + `5A 91` | Not tested on wire (`UNKNOWN`) | Service `$22 $2503` + `$1A $91`: returns `"0561BF1F181A"` and `"9199260"`. |
| 11706 | `83 78 F1 22 25 00 ...` | `ZIF_BACKUP_LESEN` | `62 25 00 <PRGREFB>` | Not tested on wire (`UNKNOWN`) | Service `$22 $2500`: returns backup reference. |
| 11724 | `82 78 F1 31 0A ...` | `FLASH_PROGRAMMIER_STATUS_LESEN` | `71 0A 01` | Not tested on wire (`UNKNOWN`) | RoutineControl `$31 $0A`: status read. |
| 11960 | `86 78 F1 23 00 00 00 07` | `AIF_LESEN` | `63 <AIF Data>` | Not tested on wire (`UNKNOWN`) | Service `$23 ReadMemoryByAddress`: returns `AIF_ZB_NR = "9165672"`. |

---

## 6. Milestone 5.7 — Deterministic Offline Execution Model

In Milestone 5.7, an offline execution model was implemented to programmatically reproduce the semantic path:
$$\text{Job} \longrightarrow \text{IPO Procedure} \longrightarrow \text{10FLASH.prg Parser} \longrightarrow \text{Wire Response Fixture} \longrightarrow \text{Decoded SGBD Result Fields}$$
without physical ECU access, using immutable physical traces as fixtures.

### 6.1 Architecture & Components
- **Job Definition & Result Model**: [`reconstruction/ediabas/job_model.py`](file:///Users/blogman/winkfp-research/reconstruction/ediabas/job_model.py)
  - `SgbdJobDefinition`: Formal definition carrying 4 orthogonal evidence axes (`sgbd_supported`, `factory_trace_observed`, `physical_trace_exists`, `directly_resolved`).
  - `SgbdJobResult`: Structured result holding decoded named fields, status, raw payload, and evidence class.
- **Immutable Trace Loader**: [`reconstruction/ediabas/trace_loader.py`](file:///Users/blogman/winkfp-research/reconstruction/ediabas/trace_loader.py)
  - `TraceFixture`: Verified fixture container with validated DS2 checksum and framing.
  - `load_trace_fixture()`: Strictly read-only JSON loader enforcing DS2 framing (`reconstruction.transport.kdcan.framing.parse`) and 8-bit additive checksums.
- **Job Catalog & Runner**: [`reconstruction/ediabas/execution_model.py`](file:///Users/blogman/winkfp-research/reconstruction/ediabas/execution_model.py)
  - `Gke195JobCatalog`: Canonical registry mapping each read-only identification job to its specification.
  - `Gke195OfflineRunner`: Dispatch engine executing SGBD parsing against trace fixtures.

### 6.2 Master Execution Model & Trace Linkage Table

| Job Name | IPO Procedure | SGBD Routine | Canonical Trace Fixture | Expected Wire Response | Decoded Primary Fields | SGBD Supp. | Fact. Obs. | Phys. Trace | Directly Resolved? | Final Classification |
|---|---|---|---|---|---|---|---|---|---|---|
| `IDENT` | `Ident` | `IDENT` | [`traces/hardware/20260926_174811_egs_ident.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_174811_egs_ident.json) | `5A 80 <60B Table>` | `ID_BMW_NR="7591972"`, `ID_DATUM="30.10.2008"`, `ID_SW_NR_FSV="195.64.1"` | **Yes** | **Yes** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `PHYSIKALISCHE_HW_NR_LESEN` | `PhysHwNrLesen` | `PHYSIKALISCHE_HW_NR_LESEN` | [`traces/hardware/20260926_175924_egs_physical_hw_nr.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_175924_egs_physical_hw_nr.json) | `5A 87 <6B PECUHN x 3>` | `PHYSIKALISCHE_HW_NR="7569980"` (3-block match) | **Yes** | **Yes** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `AIF_READ_BENCH_ALIAS` | *None (Probe)* | *None (Primitive)* | [`traces/hardware/20260926_173201_egs_aif.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_173201_egs_aif.json) | `80 F1 18 42 5A 86 40... 0F` | `short_vin="[REDACTED]"`, `zb_number="7592132"`, `sw_number="7592133"`, `flash_date="2008.12.04"`, `sgbd="0479S90T641Z"` | **No** | **No** | **Yes** | **No** | **`OBSERVED_WIRE` / `RECONSTRUCTION_ALIAS`** |
| `TESTER_PRESENT_BENCH` | *None (Probe)* | *None (Primitive)* | [`traces/hardware/20260926_174033_egs_tester_present.json`](file:///Users/blogman/winkfp-research/traces/hardware/20260926_174033_egs_tester_present.json) | `83 F1 18 7F 3E 12 5B` | `NRC 0x12` (`SubFunctionNotSupported`) | **No** | **No** | **Yes** | **No** | **`OBSERVED_WIRE`** |
| `SERIENNUMMER_LESEN` | `SgSerienNr` | `SERIENNUMMER_LESEN` | [`logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json`](file:///Users/blogman/winkfp-research/logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json) | `5A 89 <Serial>` | `SERIENNUMMER="900405938"` | **Yes** | **Yes** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `AIF_LESEN` | `AifLesen` | `AIF_LESEN` | [`logs/sgbd_semantic_correlation/20260928_145031_physical_official_aif_lesen_23.json`](file:///Users/blogman/winkfp-research/logs/sgbd_semantic_correlation/20260928_145031_physical_official_aif_lesen_23.json) | `93 F1 18 63 40 ... D3` (KWP `$23`) | `AIF_ZB_NR="7592132"`, `AIF_DATUM="04.12.2008"`, `AIF_GROESSE=64` | **Yes** | **No** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `ZIF_LESEN` | `ZifLesen` | `ZIF_LESEN` | [`logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json`](file:///Users/blogman/winkfp-research/logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json) | `62 25 03 <39B PRGREF>` | `ZIF_PROGRAMM_REFERENZ="0479S90T641Z"` | **Yes** | **No** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `ZIF_BACKUP_LESEN` | `ZifBackupLesen` | `ZIF_BACKUP_LESEN` | [`logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json`](file:///Users/blogman/winkfp-research/logs/sgbd_semantic_correlation/20260928_150813_remaining_readonly_sgbd_batch.json) | `62 25 00 <57B PRGREFB>` | `ZIF_BACKUP_PROGRAMM_REFERENZ="0479S90T641Z"`, HW `7591972` | **Yes** | **No** | **Yes** | **Yes** | **`DIRECTLY_RESOLVED`** |
| `HARDWARE_REFERENZ_LESEN` | `HwReferenzLesen` | `HARDWARE_REFERENZ_LESEN` | *None (Offline model)* | `62 25 02 <7B HWREF>` | `HARDWARE_REFERENZ`, `HW_REF_PROJEKT`, etc. | **Yes** | **No** | **No** | **No** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[0479S90T641Z]` |
| `DATEN_REFERENZ_LESEN` | `DatenReferenzLesen` | `DATEN_REFERENZ_LESEN` | *None (Offline model)* | `62 25 04 <17B DREF>` | `DATEN_REFERENZ`, `DATEN_REF_DATENSATZ`, etc. | **Yes** | **No** | **No** | **No** | `DIRECT_SGBD_MAPPING[10FLASH]` / `UNKNOWN[0479S90T641Z]` |

---

## 7. Verification and Deterministic Offline Testing

The test suite incorporates both low-level SGBD decoder unit tests and high-level execution model golden tests:
- SGBD Decoders: [`tests/golden/ediabas/test_golden_sgbd_10flash.py`](file:///Users/blogman/winkfp-research/tests/golden/ediabas/test_golden_sgbd_10flash.py)
- Execution Model: [`tests/golden/ediabas/test_gke195_job_execution_model.py`](file:///Users/blogman/winkfp-research/tests/golden/ediabas/test_gke195_job_execution_model.py)
- Master Test Runner: `.venv/bin/python3 tests/run_tests.py`

### Test Suite Execution Output:
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  35 run,  35 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :   8 run,   8 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 106 tests in 4.153s | 106 passed | 0 skipped | 0 failed
======================================================================
```

---

## 8. Safety Enforcement

- **Strictly Offline**: No serial port handles were instantiated or opened during this milestone.
- **Port Device**: `/dev/cu.usbserial-A50285BI` remained completely closed.
- **Bus Traffic**: Zero bytes transmitted.
- **Physical Traces**: All `.json` trace artifacts in `traces/hardware/` remain byte-preserved read-only fixtures.
