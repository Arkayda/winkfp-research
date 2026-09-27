# Milestone 5.5 — Off-Hardware SGBD Semantic Resolution (Target: `0479S90T641Z`)

**Status**: OFF-HARDWARE ANALYSIS COMPLETE  
**Resolution Category**: **A: DIRECTLY RESOLVED**  
**Safety Status**: ZERO HARDWARE ACCESS — ZERO SERIAL PORT OPENINGS — NO BYTES TRANSMITTED  
**Date**: 2026-09-26  

---

## Executive Summary

Milestones 5.2 and 5.3 established the direct physical bus responses of the target ZF 6HP EGS mechatronic controller (`0x18`) to read-only identification queries:
1. `1A 80` (IDENT): returned 60 bytes containing `... 00 00 07 59 19 72 ... 07 56 99 80 ... 0479S90 ... T641Z`.
2. `1A 87` (Physical HW-Nr): returned 20 bytes payload `5A 87` followed by three identical 6-byte blocks: `00 00 07 56 99 80` $\times 3$.

In Milestone 5.4, the relationship between `7591972` and `7569980` was forensically analyzed, formulating hypotheses C and D.

Milestone 5.5 achieves **full semantic resolution (Category A: DIRECTLY RESOLVED)** using official BMW SP-Daten and EDIABAS runtime SGBD files:
- The target calibration descriptor `0479S90T641Z` belongs to SG-TYP **`GKE195`** (flash calibration file `A7592133.0da` with assembly `ZB 7592132`).
- The official WinKFP configuration table `KFCONF10.DA2:292` maps `GKE195` at address `0x18` to PABD sequence script `03GKE195.ipo` and SGBD diagnostic module **`10FLASH.prg`**.
- SGBD `10FLASH.prg` bytecode decompilation directly defines the exact telegram layouts and assigns:
  - `1A 87` $\rightarrow$ Job `PHYSIKALISCHE_HW_NR_LESEN`: explicitly extracts the 6-byte BCD field `00 00 07 56 99 80` (after validating that all 3 repeated blocks match) and publishes it as **`RESULT: PHYSIKALISCHE_HW_NR`** (type string: `"7569980"`, comment: *"Physikalische Hardware-Nummer"*, defined as PECUHN = *physicalECUHardwareNumber*).
  - `1A 80` $\rightarrow$ Job `IDENT`: explicitly extracts offset +2 (6 bytes BCD `00 00 07 59 19 72`) and publishes it as **`RESULT: ID_BMW_NR`** (type string: `"7591972"`, comment: *"BMW-Teilenummer"*).
- In `GKE195.DAT`, `7591972` is explicitly defined as the base assembly hardware number (`HW-NR`) for `ZB 7592132`.
- In `HWNR.DA2`, **both** `7569980` and `7591972` are officially registered as valid hardware numbers under `;$SG GKE195`.
- Therefore, `7569980` is directly resolved as the **Physical ECU Hardware Number** (`PHYSIKALISCHE_HW_NR`), while `7591972` is the **Programmed Assembly Base Hardware Number** (`ID_BMW_NR` / `HW-NR`).

---

## 1. Exact Source Files Inspected

All files inspected were retrieved from local disk archives; no live bus communication was conducted:

| Source File | Path / Location | Purpose / Evidence Provided |
|---|---|---|
| `KFCONF10.DA2` | `Downloads/BMW/extracted/E60_daten/data/gdaten/KFCONF10.DA2:292` | WinKFP master configuration for EGS `0x18`: links `GKE195` to `03GKE195.ipo` and SGBD `10FLASH.prg`. |
| `GKE195.DAT` | `spdaten_gke/E60/data/GKE195/GKE195.DAT:16` | Assembly table: maps `ZB 7592132` $\rightarrow$ `HW-NR 7591972` $\rightarrow$ `SW-NR 7592133` (`A7592133.0da`). |
| `A7592133.0da` | `spdaten_gke/E60/data/GKE195/A7592133.0da:7, 76` | Calibration container: declares `;;ZL_Referenz: 0479S90T641Z1ZY02` and `$REFERENZ 0479S90T641Z1ZY02 V`. |
| `HWNR.DA2` | `Downloads/BMW/extracted/E60_daten/data/gdaten/HWNR.DA2:7076, 7085` | Hardware number directory: registers both `7569980` and `7591972` under `;$SG GKE195`. |
| `03GKE195.ipo` | `Downloads/BMW/extracted/E60_daten/sgdat/03GKE195.ipo` | PABD sequence script: invokes `PhysHwNrLesen -> PHYSIKALISCHE_HW_NR_LESEN` on the SGBD (`10FLASH.prg`). |
| `10FLASH.prg` | `Downloads/BMW/extracted/E60_daten/ecu/10FLASH.prg` | SGBD binary (decoded via XOR `0xF7`): contains the bytecode and result definitions for `IDENT` and `PHYSIKALISCHE_HW_NR_LESEN`. |
| Physical 1A80 Trace | `traces/hardware/20260926_174811_egs_ident.json` | Immutable captured physical wire trace from Milestone 5.2. |
| Physical 1A87 Trace | `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | Immutable captured physical wire trace from Milestone 5.3. |

---

## 2. SGBD Architecture for Target `0479S90T641Z`

### 2.1 The Nature of `0479S90T641Z`
`0479S90T641Z` is **not** an SGBD `.PRG` filename. It is the calibration reference identifier (`$REFERENZ`) embedded in the header of the official ZF 6HP flash software file `A7592133.0da`:
```text
;;ZL_Referenz:      0479S90T641Z1ZY02
$REFERENZ 0479S90T641Z1ZY02 V
```
The physical EGS at address `0x18` returned this exact string in the trailing bytes of the `1A 80` identification table:
```text
Bytes 41..47: "0479S90"
Bytes 48..54: "0479S90"
Bytes 55..59: "T641Z"
```

### 2.2 SGBD Binding via `KFCONF10.DA2`
Line 292 of `KFCONF10.DA2` establishes the exact SGBD and PABD binding for BMW E60 EGS:
```text
ME SL 18 01 GKE195   03GKE195.ipo   10FLASH.prg   XXFLKP   GKE195.HIS   GKE195.DAT   A   GKE195D.DIR   GKE195.HWH
```
- **`ME`**: Engine/Transmission ECU class (Motor/Getriebe).
- **`SL`**: Supplier ID ("SL" = Siemens VDO / Continental / ZF). Matches physical `1A 80` response `ID_LIEF_TEXT = "SL "`.
- **`18`**: Diagnostic bus address (`0x18` = EGS).
- **`GKE195`**: Electronic Transmission Control SG family.
- **`03GKE195.ipo`**: High-level PABD sequence script.
- **`10FLASH.prg`**: Low-level EDIABAS SGBD driver module.

Therefore, the SGBD responsible for communicating with and decoding data from this physical EGS is **`10FLASH.prg`**.

---

## 3. Bytecode Analysis of `1A 87` (`PHYSIKALISCHE_HW_NR_LESEN`)

### 3.1 Job Definition and Metadata
In `10FLASH.prg` (decoded with XOR `0xF7` at offset `0x4A4F7`), the job is formally defined:
```text
JOBNAME:PHYSIKALISCHE_HW_NR_LESEN
JOBCOMMENT:Auslesen der physikalischen Hardwarenummer
JOBCOMMENT:KWP2000: $1A ReadECUIdentification
JOBCOMMENT:$87 physicalECUHardwareNumber (PECUHN)
JOBCOMMENT:oder alternativ
JOBCOMMENT:KWP2000: $1A ReadECUIdentification
JOBCOMMENT:$80 ECUIdentificationDataTable
RESULT:JOB_STATUS (string, "OKAY, wenn fehlerfrei")
RESULT:PHYSIKALISCHE_HW_NR (string, "Physikalische Hardware-Nummer")
RESULT:_TEL_AUFTRAG (binary, "Hex-Auftrag an SG")
RESULT:_TEL_ANTWORT (binary, "Hex-Antwort von SG")
RESULT:_TEL_AUFTRAG_2 (binary, "Hex-Auftrag an SG")
RESULT:_TEL_ANTWORT_2 (binary, "Hex-Antwort von SG")
```

### 3.2 Request Construction
The SGBD builds the diagnostic telegram at offset `0x12E40`:
```text
82 <TARGET_ADDR> F1 1A 87 <CS>
```
For target address `0x18`, this produces the exact wire request transmitted in Milestone 5.3:
```text
82 18 F1 1A 87 2C
```

### 3.3 Response Parsing & Verification
The ECU response payload is:
```text
5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80
```
Bytecode analysis between `0x13780` and `0x138A0` reveals the exact verification algorithm:
1. **Length Check**: Verifies that the payload length is exactly 20 bytes (`0x14`). If not, sets `JOB_STATUS = "ERROR_ECU_INCORRECT_LEN"`.
2. **Three-Block Verification Loop**:
   - `block1 = payload[2:8]` (`00 00 07 56 99 80`)
   - `block2 = payload[8:14]` (`00 00 07 56 99 80`)
   - `block3 = payload[14:20]` (`00 00 07 56 99 80`)
   - The bytecode executes pairwise comparisons (`block1 == block2`, `block2 == block3`, `block3 == block1`).
   - If any comparison fails, it reports `JOB_MESSAGE = "Invalid Count"` and sets `JOB_STATUS = "ERROR_CHECK_PECUHN"`.
3. **Conversion to String**:
   - The 6-byte BCD field `00 00 07 56 99 80` is converted to an ASCII string with leading zeros stripped: `"7569980"`.
4. **Field Assignment**:
   - The formatted string is published to EDIABAS as:
     ```text
     RESULT: PHYSIKALISCHE_HW_NR = "7569980"
     ```

### 3.4 Fallback via `1A 80`
If `1A 87` fails (NRC or `ERROR_CHECK_PECUHN`), `10FLASH.prg` transmits `_TEL_AUFTRAG_2` (`82 <ADDR> F1 1A 80`), reads the fallback PECUHN field at offset +31..37 (`00 00 07 56 99 80`), and assigns it to `PHYSIKALISCHE_HW_NR`.

---

## 4. Bytecode Analysis of `1A 80` (`IDENT`)

### 4.1 Job Definition and Metadata
In `10FLASH.prg` at offset `0x47D00`:
```text
JOBNAME:IDENT
JOBCOMMENT:Identdaten
JOBCOMMENT:KWP2000: $1A ReadECUIdentification
JOBCOMMENT:Modus  : Default
RESULT:JOB_STATUS
RESULT:ID_BMW_NR (string, "BMW-Teilenummer")
RESULT:ID_HW_NR (string, "BMW-Hardware-Versionsindex")
RESULT:ID_COD_INDEX (int, "Codier-Index")
RESULT:ID_DIAG_INDEX (int, "Diagnose-Index")
RESULT:ID_VAR_INDEX (int, "Varianten-Index")
RESULT:ID_DATUM_JAHR (int, "Herstelldatum (Jahr)")
RESULT:ID_DATUM_MONAT (int, "Herstelldatum (Monat)")
RESULT:ID_DATUM_TAG (int, "Herstelldatum (Tag)")
RESULT:ID_DATUM (string, "Herstelldatum (TT.MM.JJJJ)")
RESULT:ID_LIEF_NR (int, "Lieferanten-Nummer")
RESULT:ID_LIEF_TEXT (string, "Lieferanten-Text")
RESULT:ID_SW_NR_MCV (string, "Softwarenummer (message catalogue version)")
RESULT:ID_SW_NR_FSV (string, "Softwarenummer (functional software version)")
RESULT:ID_SW_NR_OSV (string, "Softwarenummer (operating system version)")
RESULT:ID_SW_NR_RES (string, "Softwarenummer (reserved - currently unused)")
```

### 4.2 Exact Field Extractions from Physical Trace
Applying `10FLASH.prg` bytecode parsing to `traces/hardware/20260926_174811_egs_ident.json`:

| Offset in Payload | Raw Bytes | Field Name | SGBD Type | Extracted / Formatted Value | Semantic Meaning |
|---|---|---|---|---|---|
| `[2:8]` | `00 00 07 59 19 72` | `ID_BMW_NR` | string | `"7591972"` | Base assembly hardware part number (`HW-NR` in `GKE195.DAT`). |
| `[8]` | `0x10` | `ID_HW_NR` | string | `"10"` | Hardware version index (2 BCD nibbles). |
| `[9]` | `0x05` | `ID_COD_INDEX` | int | `5` | Coding index. |
| `[10:12]` | `0x02 0x04` | `ID_DIAG_INDEX` | int | `516` (`0x0204`) | Diagnostic index. |
| `[12:15]` | `53 4c 20` | `ID_LIEF_TEXT` | string | `"SL "` | Supplier code ("SL" = Siemens VDO / ZF). |
| `[15]` | `0x08` | `ID_DATUM_JAHR` | int | `2008` | Production year. |
| `[16]` | `0x10` | `ID_DATUM_MONAT` | int | `10` | Production month. |
| `[17]` | `0x30` | `ID_DATUM_TAG` | int | `30` | Production day. |
| `formatted` | — | `ID_DATUM` | string | `"30.10.2008"` | Formatted manufacture date (`TT.MM.JJJJ`). |
| `[18]` | `0x08` | `ID_LIEF_NR` | int | `8` | Supplier number index in table `Lieferanten`. |
| `[19:22]` | `0x00 0x1d 0x45` | `ID_SW_NR_MCV` | string | `"0.29.69"` | Message Catalogue Version. |
| `[22:25]` | `0xc3 0x40 0x01` | `ID_SW_NR_FSV` | string | `"195.64.1"` | Functional Software Version. |
| `[25:28]` | `0x02 0x03 0x0a` | `ID_SW_NR_OSV` | string | `"2.3.10"` | Operating System Version. |
| `[28:31]` | `0x00 0x00 0x00` | `ID_SW_NR_RES` | string | `"0.0.0"` | Reserved software version. |
| `[31:37]` | `00 00 07 56 99 80` | `_PECUHN_FALLBACK` | string | `"7569980"` | Embedded Physical ECU Hardware Number (fallback source for `PHYSIKALISCHE_HW_NR`). |

---

## 5. Semantic Relationship: `7569980` vs `7591972`

The mystery of why the ECU reports two distinct numbers is completely resolved:

```text
+-----------------------------------------------------------------------------------+
| ZF 6HP EGS Mechatronic Module (E60, Address 0x18, SG-TYP GKE195)                  |
+-----------------------------------------------------------------------------------+
| 1. Physical Electronic Controller Board (Unprogrammed Hardware):                  |
|    - SGBD Result Field : PHYSIKALISCHE_HW_NR                                      |
|    - Diagnostic Source : 1A 87 (PECUHN) / 1A 80 offset +31                         |
|    - Physical Value    : 7569980                                                  |
|    - SP-Daten Registry : HWNR.DA2:7076 (registered under GKE195)                  |
|                                                                                   |
| 2. Programmed Assembly Base Hardware (ECU Assembly Variant):                     |
|    - SGBD Result Field : ID_BMW_NR                                                |
|    - Diagnostic Source : 1A 80 offset +2                                          |
|    - Physical Value    : 7591972                                                  |
|    - SP-Daten Registry : GKE195.DAT (column HW-NR for ZB 7592132)                 |
|                        : HWNR.DA2:7085 (registered under GKE195)                  |
+-----------------------------------------------------------------------------------+
```

During flash programming, WinKFP (via `03GKE195.ipo`):
1. Reads `PhysHwNrLesen -> PHYSIKALISCHE_HW_NR_LESEN` $\rightarrow$ returns `"7569980"`.
2. Validates that `"7569980"` is present in `HWNR.DA2` for family `GKE195`.
3. Consults `GKE195.DAT` to find allowable ZB numbers that can run on this hardware family.
4. Reads `IDENT` $\rightarrow$ verifies `ID_BMW_NR = "7591972"`.

Both numbers are valid, official BMW hardware identifiers representing different levels of the ECU hardware hierarchy.

---

## 6. Distinction from Factory 10FLASH Evidence

In earlier documentation, the factory trace:
```text
PHYSIKALISCHE_HW_NR_LESEN -> 1A 87 on target 0x78 / 10FLASH
```
was classified strictly as `OBSERVED_JOB_MAPPING[target=10FLASH]`.

The current milestone establishes that:
1. `10FLASH.prg` is **not** a foreign or unrelated SGBD. It is the **exact, official SGBD** designated by BMW's `KFCONF10.DA2` for EGS `GKE195` at `0x18`.
2. The job definitions and parsing rules inside `10FLASH.prg` are identical across all targets that utilize `10FLASH.prg`.
3. Consequently, the correlation is no longer an external inference; it is a **direct SGBD architectural identity**.

---

## 7. What Remains UNKNOWN

While the identification primitives are now fully resolved, the following remain `UNKNOWN` and fail-closed:
1. **Flash Session Transitions (`0x10`)**: The exact sequence of session transitions (`0x10 0x85`, `0x10 0x86`) for `GKE195` remains unobserved on the physical bus.
2. **Security Access (`0x27` vs `0x31 0x07` / `0x31 0x08`)**: SGBD `10FLASH.prg` contains RoutineControl jobs for seed/key (`31 07` / `31 08`). Whether EGS `0x18` accepts standard RoutineControl authentication on live bus without prerequisites has not been physically validated.
3. **Flash Write Primitives (`0x34`, `0x36`, `0x37`)**: The live transmission timing and block limits for flash downloading on `0x18` have not been tested on hardware.

---

## 8. Verification and Deterministic Offline Tests

A clean-room implementation of the `10FLASH.prg` decoder and offline execution engine was developed:
- Implementation: `reconstruction/ediabas/sgbd.py`
- Exported via: `reconstruction/ediabas/__init__.py`
- Test Suite: `tests/golden/ediabas/test_golden_sgbd_10flash.py`

### Test Coverage:
1. `test_phys_hw_nr_synthetic_valid`: Verifies 3-block 1A 87 decoding $\rightarrow$ `PHYSIKALISCHE_HW_NR = "7569980"`.
2. `test_phys_hw_nr_synthetic_block_mismatch`: Verifies block mismatch triggers `ERROR_CHECK_PECUHN`.
3. `test_phys_hw_nr_synthetic_invalid_length`: Verifies truncated frame triggers `ERROR_ECU_INCORRECT_LEN`.
4. `test_phys_hw_nr_synthetic_nrc`: Verifies NRC `0x7F` handling.
5. `test_phys_hw_nr_captured_physical_trace`: Executes offline against immutable trace `20260926_175924_egs_physical_hw_nr.json` $\rightarrow$ matches `"7569980"`.
6. `test_ident_synthetic_valid`: Verifies extraction of all 14 named result fields from `1A 80`.
7. `test_ident_captured_physical_trace`: Executes offline against immutable trace `20260926_174811_egs_ident.json` $\rightarrow$ matches `"7591972"`, `"30.10.2008"`, `"7569980"`.
8. `test_sgbd_offline_interpreter`: Simulates EDIABAS `execute_job` / `read_result` API contract without serial port opening.

### Verification Run Results:
```text
TOTAL: 95 tests in 4.881s | 95 passed | 0 skipped | 0 failed
Tier breakdown:
  KAT          : 63 run, 63 passed, 0 skipped, 0 failed  [PASSED]
  GOLDEN       : 24 run, 24 passed, 0 skipped, 0 failed  [PASSED]
  DIFFERENTIAL :  8 run,  8 passed, 0 skipped, 0 failed  [PASSED]
```

---

## 9. Conclusion

Milestone 5.5 conclusively resolves the semantic identity of the physical EGS identification fields:
- `7569980` is **DIRECTLY RESOLVED** as `PHYSIKALISCHE_HW_NR` (Physical ECU Hardware Number).
- `7591972` is **DIRECTLY RESOLVED** as `ID_BMW_NR` / `HW-NR` (Programmed Assembly Hardware Number).
- Both mappings are backed by direct SGBD bytecode (`10FLASH.prg`), PABD bytecode (`03GKE195.ipo`), and official SP-Daten tables (`KFCONF10.DA2`, `GKE195.DAT`, `HWNR.DA2`).
