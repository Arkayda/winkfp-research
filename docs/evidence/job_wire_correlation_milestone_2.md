# Milestone 2: Forensic EDIABAS / SGBD Job-to-Wire Correlation Report

## 1. Executive Summary & Objective

* **Milestone**: Milestone 2 — Forensic EDIABAS / SGBD Job-to-Wire Correlation.
* **Operational Mode**: **STRICTLY OFF-HARDWARE**.
  * Zero communication with physical vehicle or bench hardware.
  * `tools/kdcan_probe.py` was not executed.
  * No serial / K+DCAN ports opened; no diagnostic requests transmitted.
* **Objective**: Forensically cross-reference original EDIABAS/WinKFP traces, decompiled C sources, and SGBD metadata against the physically observed wire transactions from Milestone 1/1.1 (`0x1A 0x86` and `0x3E 0x00`).
* **Core Finding**:
  1. The original factory flash trace (`traces/sanitized/sanitized_flash_session.trc`) contains **zero** instances of `TESTER_PRESENT`, `IDENT_LESEN`, `SG_PHYS_HWNR_LESEN`, or `SG_STATUS_LESEN`.
  2. The factory keep-alive job is **`DIAGNOSE_AUFRECHT`** (argument `"NEIN;JA"`), which transmits telegram `C2 EF F1 3E 02` (`0x3E 0x02`), not `0x3E 0x00`.
  3. In the factory trace (`10FLASH`), `AIF_LESEN` executes KWP2000 service `0x23` (`ReadMemoryByAddress`), **not** `0x1A 0x86`.
  4. The job name `IDENT` executes service `0x1A 0x80`, and `PHYSIKALISCHE_HW_NR_LESEN` executes service `0x1A 0x87`.
  5. SGBD bytecode for the physical transmission controller (`0479S90T641Z`) is not redistributed in this clean-room repository.
  6. **Zero job mappings are promoted to `OBSERVED_JOB_MAPPING`** for the transmission controller. All high-level mappings remain `INFERRED_JOB_MAPPING` or `UNKNOWN` and continue to fail closed.

---

## 2. Inventory of Forensic Artifacts

The repository was systematically inventoried for material concerning diagnostic job definitions, wire requests, and session orchestration:

| Artifact Path | Artifact Type | Relevant Contents & Forensic Findings |
|---|---|---|
| `traces/sanitized/sanitized_flash_session.trc` | Factory EDIABAS / WinKFP API trace | 1,293 distinct job executions covering `10FLASH`, `13_ASK`, and `22EK92`. Contains raw `_TEL_AUFTRAG` and `_TEL_ANTWORT` hex dumps. |
| `analysis/vdle/winkfpt_004a5960.c` | Ghidra C decompilation of `winkfpt.exe` | Exact implementation of session maintenance function `FUN_004a5960`: dispatches `DIAGNOSE_AUFRECHT "NEIN;JA"` and `NORMALER_DATENVERKEHR`. |
| `analysis/vdle/winkfpt_004a5850.c` | Ghidra C decompilation of `winkfpt.exe` | Session initialization function `FUN_004a5850`: executes `NORMALER_DATENVERKEHR "NEIN;NEIN;JA"` and `"JA;NEIN;NEIN"`. |
| `reconstruction/tester_present.py` | Clean-room reconstruction | Dual-deadline keep-alive scheduler: light slot (8000 ms) and heavy slot (10000 ms). |
| `tools/analysis/spdaten_scan.py` | Static analysis utility | Analyzes SP-Daten IPO context for flash parameter setup and authentication. |
| `traces/expected/bench_contact_mock.jsonl` | Synthetic mock trace | Synthetic test fixture using reconstructed job names (`SG_PHYS_HWNR_LESEN`, `AUTHENTISIERUNG`). |
| `traces/expected/bench_full_mock.jsonl` | Synthetic mock trace | Synthetic test fixture referencing `SG_STATUS_LESEN` as a hypothetical keep-alive tick. |

---

## 3. Trace Forensic Analysis (`sanitized_flash_session.trc`)

A complete forensic scan of `traces/sanitized/sanitized_flash_session.trc` recovered every relevant job invocation, argument set, transport payload, and response:

### 3.1 Forensic Trace Evidence Table

| Job Name in Trace | Target Device | Arguments Passed | Transport Telegram (`_TEL_AUFTRAG`) | Observable Service / Subfunction | Result Telegram (`_TEL_ANTWORT`) / Fields | Trace Line Ref |
|---|---|---|---|---|---|---|
| `DIAGNOSE_AUFRECHT` | `13_ASK`, `10FLASH` | `"NEIN;JA"` | `C2 EF F1 3E 02` | KWP `0x3E` (TesterPresent), subfunction `0x02`, functional dst `0xEF` | No payload reply (`JOB_STATUS = "OKAY"`) | L198, L3962, L7761, L14387 |
| `NORMALER_DATENVERKEHR` | `10FLASH` | `"NEIN;NEIN;JA"` | `C2 EF F1 28 02` | KWP `0x28` (CommunicationControl: DisableNormalComm) | No payload reply (`JOB_STATUS = "OKAY"`) | L12818, L14033 |
| `NORMALER_DATENVERKEHR` | `10FLASH` | `"JA;NEIN;NEIN"` | `82 78 F1 29 02` | KWP `0x29` (CommunicationControl: EnableNormalComm) | No payload reply (`JOB_STATUS = "OKAY"`) | L12837, L14052 |
| `NORMALER_DATENVERKEHR` | `13_ASK`, `10FLASH` | `"JA;NEIN;JA"` | `C2 EF F1 29 02` | KWP `0x29` (CommunicationControl: EnableNormalComm Broadcast) | No payload reply (`JOB_STATUS = "OKAY"`) | L10002, L12927, L73240 |
| `IDENT` | `10FLASH` | `""` | `82 78 F1 1A 80` | KWP `0x1A` (ReadECUIdentification), subfunction `0x80` | `9F F1 78 5A 80 FF FF FF...` (35 B): `ID_BMW_NR`, `ID_HW_NR` | L11777, L12127, L13195 |
| `PHYSIKALISCHE_HW_NR_LESEN` | `10FLASH` | `""` | `82 78 F1 1A 87` | KWP `0x1A` (ReadECUIdentification), subfunction `0x87` | `94 F1 78 5A 87 00 00 09 16 56 72...` (24 B): `PHYSIKALISCHE_HW_NR = "9165672"` | L11819, L13237 |
| `ZIF_LESEN` | `10FLASH` | `""` | `82 78 F1 1A 91` | KWP `0x1A` (ReadECUIdentification), subfunction `0x91` | `8F F1 78 5A 91...` (19 B): ZIF programming record | L11666, L12391, L13082 |
| `SERIENNUMMER_LESEN` | `10FLASH` | `""` | `82 78 F1 1A 89` | KWP `0x1A` (ReadECUIdentification), subfunction `0x89` | `90 F1 78 5A 89...` (20 B): Serial number record | L12579 |
| `AIF_LESEN` | `10FLASH` | `"0"`, `"1"`, `"2"` | `86 78 F1 23 00 00 00 07 12` | KWP `0x23` (ReadMemoryByAddress), addr `0x00000007`, len `0x12` (18 B) | `93 F1 78 63 12...`: `AIF_ZB_NR`, `AIF_DATUM`, `AIF_FG_NR`, `AIF_GROESSE=18` | L11933, L11989, L12045 |
| `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` | `10FLASH` | `""` | `87 78 F1 31 07 03 34 66 36 32` | KWP `0x31` (RoutineControl: startRoutine `0x07` seed request) | `8A F1 78 71 07 15 E4 85 FE 00 03 FD 55 3C` (8-byte random seed) | L12615 |
| `NG_AUTHENTISIERUNG_START` | `10FLASH` | 38 bytes binary | `92 78 F1 31 08 EA 9C 6D F4 F5 BC 93 1D 07 14 2B 5D 25 75 5E 45` | KWP `0x31` (RoutineControl: startRoutine `0x08` key response) | `83 F1 78 71 08 01 66` (Authentication successful: `0x01`) | L12635 |
| `DIAGNOSE_MODE` | `10FLASH` | `"ECUPM"` | `82 78 F1 10 85` | KWP `0x10` (StartDiagnosticSession: session `0x85` Programming Mode) | First attempt failed `7F 10 22`; second succeeded `82 F1 78 50 85 C0` | L12656, L13871 |
| `STEUERGERAETE_RESET` | `13_ASK`, `10FLASH` | `""` | `82 78 F1 11 01` | KWP `0x11` (ECUReset: resetType `0x01` hardReset) | `81 F1 78 51 3B` (Positive response `0x51`) | L10080, L13832, L73594 |

---

## 4. SGBD / IPO Correlation & Limits of Evidence

### 4.1 Transmission Controller Target vs Trace Artifact
* **Bench Target ECU**: Physical ZF 6HP EGS mechatronic at address `0x18`.
  * Physical AIF response decoded SGBD descriptor: **`0479S90T641Z`**.
* **Trace Artifact Target**: `traces/sanitized/sanitized_flash_session.trc`.
  * Targets modules: `10FLASH` (flash loader for `13_ASK`), `13_ASK` (Audio System Controller at `0x78`), and `22EK92` (DME at `0x12`).
  * Does **NOT** record transactions for `GS19` or `0479S90T641Z`.

### 4.2 SGBD Bytecode Absence in Clean-Room Repository
* Under the project's intellectual property policy ([`docs/PROPRIETARY_MATERIAL.md`](../PROPRIETARY_MATERIAL.md)), OEM proprietary compiled bytecode files (`.prg`, `.ipo`) are excluded from redistribution.
* Consequently, the chain:
  $$\text{EDIABAS Job Name} \longrightarrow \text{SGBD Bytecode} \longrightarrow \text{BEST/1 Dispatcher} \longrightarrow \text{Wire Telegram}$$
  cannot be verified by executing original SGBD files within this repository for `0479S90T641Z`.
* **Methodological Rule**: In the absence of direct execution evidence tying a specific job name to a wire telegram for this ECU, the mapping **MUST NOT** be classified as `OBSERVED_JOB_MAPPING`.

---

## 5. Detailed Analysis: TesterPresent & Keep-Alive

### 5.1 `DIAGNOSE_AUFRECHT` vs Physical `3E 00`
A critical distinction exists between original factory keep-alive and the bench probe:

```mermaid
flowchart TD
    subgraph Original EDIABAS Flash Trace
        J1["Job: DIAGNOSE_AUFRECHT (args: NEIN;JA)"] --> T1["Wire Telegram: C2 EF F1 3E 02"]
        T1 --> D1["Service: 0x3E | Subfunction: 0x02 | Target: 0xEF (Functional)"]
        D1 --> R1["Result: No wire reply expected / suppressed (JOB_STATUS: OKAY)"]
    end
    subgraph Physical Probe (Bench Contact)
        P1["Direct Probe: tools/kdcan_probe.py"] --> T2["Wire Telegram: 82 18 F1 3E 00 C9"]
        T2 --> D2["Service: 0x3E | Subfunction: 0x00 | Target: 0x18 (Physical)"]
        D2 --> R2["Response: 83 F1 18 7F 3E 12 5B (NRC 0x12: SubFunctionNotSupported)"]
    end
```

#### Key Differences:
1. **Subfunction Parameter**:
   * Factory WinKFP sends `0x3E 0x02`. Subfunction `0x02` indicates a suppressed response or vendor-specific keep-alive sub-parameter.
   * Bench probe sent `0x3E 0x00`. Subfunction `0x00` was rejected by the physical ZF 6HP ECU with `NRC 0x12` (`subFunctionNotSupportedInvalidFormat`).
   * **Conclusion**: `0x3E 0x00` and `0x3E 0x02` are **distinct wire payloads**. They must not be collapsed or treated as equivalent.
2. **Addressing Mode**:
   * Factory trace targets functional broadcast address `0xEF` (`C2 EF F1 ...`).
   * Bench probe targeted physical ECU diagnostic address `0x18` (`82 18 F1 ...`).

### 5.2 Periodicity & Keep-Alive Scheduling
* Decompiled WinKFP code (`winkfpt_004a5960.c`) proves that session maintenance is **time-driven**, not block-driven:
  * Slot 2 (Light keep-alive): 8,000 ms (`TP_LIGHT_INTERVAL_S = 8.0`). Dispatches `DIAGNOSE_AUFRECHT "NEIN;JA"`.
  * Slot 1 (Heavy keep-alive): 10,000 ms (`TP_HEAVY_INTERVAL_S = 10.0`). Dispatches `NORMALER_DATENVERKEHR "NEIN;NEIN;JA"` followed by `"JA;NEIN;NEIN"`.
* Forensic trace block-count confirmation:
  * During 54-byte transfers: 9–10 blocks elapse between `DIAGNOSE_AUFRECHT` calls.
  * During 214-byte transfers: 86–87 blocks elapse between `DIAGNOSE_AUFRECHT` calls.
  * This variation directly confirms that transmission is gated by elapsed wall-clock time (~8 seconds), matching the reverse-engineered `GetTickCount()` interval comparison.
* **Failure Handling**: If `DIAGNOSE_AUFRECHT` returns failure (`cVar1 == 0`), `FUN_004a5960` returns 0 immediately, and the caller aborts with `ERROR_DLL_TESTERPRESENTHANDLING`. There is no retry or fallback.

---

## 6. Detailed Analysis: AIF & Identification Mappings

### 6.1 `AIF_LESEN -> 1A 86`
* **Trace Evidence**: In `sanitized_flash_session.trc`, `AIF_LESEN` against `10FLASH` executes service `0x23` (`ReadMemoryByAddress`), transferring 18-byte blocks starting at address `0x00000007`. It does **not** transmit `0x1A 0x86`.
* **Physical Bench Evidence**: The physical ZF 6HP EGS mechatronic accepted `0x1A 0x86` and returned a 66-byte structured AIF record containing Short VIN, Assembly Number, Software Number, SGBD descriptor, and date.
* **Correlation**: While KWP2000 service `0x1A 0x86` is standardized in BMW documentation as Read AIF, the connection between the high-level EDIABAS job name `AIF_LESEN` and wire telegram `0x1A 0x86` on this specific ECU is **INFERRED**, not observed in the factory trace.
* **Classification**: **`INFERRED_JOB_MAPPING[target=0479S90T641Z]`** (and `OBSERVED_JOB_MAPPING[target=10FLASH]` for the `0x23` memory-read variant).

### 6.2 `IDENT_LESEN -> 1A 86` vs `IDENT -> 1A 80`
* **Trace Evidence**: The job name `IDENT_LESEN` does not appear anywhere in `sanitized_flash_session.trc`. The actual factory job name is **`IDENT`**.
* In `sanitized_flash_session.trc`, `IDENT` consistently transmits `82 78 F1 1A 80` (Service `0x1A 0x80`, returning standard identification fields `ID_BMW_NR`, `ID_HW_NR`).
* **Correlation**:
  * `IDENT -> 1A 80`: **`OBSERVED_JOB_MAPPING[target=10FLASH]`** (confirmed in `sanitized_flash_session.trc` for `10FLASH`).
  * `IDENT_LESEN`: **`RECONSTRUCTION_ALIAS` / `UNKNOWN[target=0479S90T641Z]`**. There is no trace evidence supporting an `IDENT_LESEN` job or linking it to `1A 86`.
* **Classification for `IDENT_LESEN`**: **`RECONSTRUCTION_ALIAS` / `UNKNOWN[target=0479S90T641Z]`** (fails closed).

### 6.3 `SG_PHYS_HWNR_LESEN` vs `PHYSIKALISCHE_HW_NR_LESEN`
* **Trace Evidence**: The job name `SG_PHYS_HWNR_LESEN` does not appear in original factory traces. The factory job is named **`PHYSIKALISCHE_HW_NR_LESEN`**.
* In `sanitized_flash_session.trc`, `PHYSIKALISCHE_HW_NR_LESEN` transmits `82 78 F1 1A 87` (Service `0x1A 0x87`), which returns `94 F1 78 5A 87 00 00 09 16 56 72 ...` directly yielding `PHYSIKALISCHE_HW_NR = "9165672"`. It does **not** extract hardware numbers from an AIF payload (`1A 86`).
* **Synthetic Origin of `SG_PHYS_HWNR_LESEN`**: The job name `SG_PHYS_HWNR_LESEN` and its extraction from AIF (`1A 86`) were introduced in earlier modern mock test runners (`runner.py`, `bench_contact_mock.jsonl`).
* **Correlation**:
  * `PHYSIKALISCHE_HW_NR_LESEN -> 1A 87`: **`OBSERVED_JOB_MAPPING[target=10FLASH]`** (in `sanitized_flash_session.trc` for `10FLASH`).
  * `SG_PHYS_HWNR_LESEN -> extraction from 1A 86`: **`RECONSTRUCTION_ALIAS` / `INFERRED_JOB_MAPPING[target=0479S90T641Z]`** (synthetic reconstruction convention only; not an original EDIABAS wire mapping).
* **Classification for `SG_PHYS_HWNR_LESEN`**: **`RECONSTRUCTION_ALIAS` / `INFERRED_JOB_MAPPING[target=0479S90T641Z]`** (fails closed by default).

---

## 7. Audit of `SG_STATUS_LESEN`

A comprehensive search across the repository produced the following findings for `SG_STATUS_LESEN`:
1. **Trace Search**: Zero occurrences in `sanitized_flash_session.trc` and `sanitized_api_snippet.trc`.
2. **Decompiled C Search**: Zero references in `winkfpt.exe` decompilation (`analysis/vdle/`). WinKFP session keep-alive uses `DIAGNOSE_AUFRECHT` and `NORMALER_DATENVERKEHR`.
3. **SGBD Search**: No SGBD definition exists in the repository for `SG_STATUS_LESEN`.
4. **Origin in Repository**: The string appears only in synthetic mock trace `bench_full_mock.jsonl` where it was speculatively inserted as a mock keep-alive placeholder.
5. **Conclusion**: The mapping `SG_STATUS_LESEN -> 0x3E 0x00` is **completely unevidenced**.
6. **Final Classification**: **`UNKNOWN[target=0479S90T641Z]`** (fails closed unconditionally in `DirectKdcanBus`).

---

## 8. Forensic Job-to-Wire Evidence Matrix

The table below integrates all evidence dimensions:
* **`OBSERVED_WIRE`**: Physically verified on bench hardware (Milestone 1/1.1).
* **`Trace Evidence`**: Direct observation in `sanitized_flash_session.trc`.
* **`SGBD / C Evidence`**: Decompiled `winkfpt.exe` machine code or SP-Daten scripts.
* **`Final Classification`**: Strict, target-scoped evidence categorization.

| Job Name / Diagnostic Action | Candidate Wire Service | Physical Evidence (`OBSERVED_WIRE`) | Trace Evidence (`sanitized_flash_session.trc`) | Decompiled C / SGBD Evidence | Final Classification | DirectKdcanBus Policy |
|---|---|---|---|---|---|---|
| **Wire: AIF Query** | `0x1A 0x86` | **YES** (3 runs, 66 B response) | None (only in encrypted flash data) | Standard KWP2000 service definition | **OBSERVED_WIRE** | Executed via `wire_read_aif()` or `transport.send_job()`. |
| **Wire: TesterPresent** | `0x3E 0x00` | **YES** (3 runs, `7F 3E 12` response) | None (trace uses `3E 02`) | Generic KWP2000 service definition | **OBSERVED_WIRE** | Executed via `wire_tester_present()` or `transport.send_job()`. |
| `DIAGNOSE_AUFRECHT` | `0x3E 0x02` (functional `0xEF`) | Untested on bench | **YES** (20+ runs: `C2 EF F1 3E 02`) | `winkfpt_004a5960.c` calls `"DIAGNOSE_AUFRECHT","NEIN;JA"` | **OBSERVED_JOB_MAPPING[target=10FLASH]** / **[target=13_ASK]** | Not implemented for `0x18`; fails closed. |
| `NORMALER_DATENVERKEHR` | `0x28 0x02` / `0x29 0x02` | Untested on bench | **YES** (`C2 EF F1 28 02`, `82 78 F1 29 02`) | `winkfpt_004a5960.c` calls `"NORMALER_DATENVERKEHR"` | **OBSERVED_JOB_MAPPING[target=10FLASH]** | Not implemented; fails closed. |
| `IDENT` | `0x1A 0x80` | Untested on bench | **YES** (6 runs: `82 78 F1 1A 80`) | Standard EDIABAS job in `10FLASH` | **OBSERVED_JOB_MAPPING[target=10FLASH]** | Not implemented for `0x18`; fails closed. |
| `PHYSIKALISCHE_HW_NR_LESEN` | `0x1A 0x87` | Untested on bench | **YES** (2 runs: `82 78 F1 1A 87`) | Standard EDIABAS job in `10FLASH` | **OBSERVED_JOB_MAPPING[target=10FLASH]** | Not implemented for `0x18`; fails closed. |
| `DIAGNOSE_MODE` | `0x10 0x85` | Untested on bench | **YES** (3 runs: `82 78 F1 10 85`) | Standard EDIABAS session switch | **OBSERVED_JOB_MAPPING[target=10FLASH]** | Prohibited / fail closed. |
| `STEUERGERAETE_RESET` | `0x11 0x01` | Untested on bench | **YES** (3 runs: `82 78 F1 11 01`) | Standard ECU reset | **OBSERVED_JOB_MAPPING[target=10FLASH]** / **[target=13_ASK]** | Prohibited / fail closed. |
| `AIF_LESEN` | `0x1A 0x86` (EGS) / `0x23` (`10FLASH`) | `1A 86` accepted on wire | Trace uses `0x23`, NOT `1A 86` | Standard KWP2000 AIF definition | **UNKNOWN[target=0479S90T641Z]** / **OBSERVED_JOB_MAPPING[target=10FLASH]** | **FAIL-CLOSED** by default (`allow_inferred=False`). |
| `IDENT_LESEN` | Inferred `0x1A 0x86` / `0x1A 0x80` | None | None (job is `IDENT`, sends `1A 80`) | Reconstruction alias | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default. |
| `SG_PHYS_HWNR_LESEN` | Extraction from `1A 86` | ZB in AIF payload | None (job is `PHYSIKALISCHE_HW_NR_LESEN`) | Reconstruction convention | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default (`allow_inferred=False`). |
| `TESTER_PRESENT` | `0x3E 0x00` | `3E 00` accepted on wire | None (trace uses `DIAGNOSE_AUFRECHT -> 3E 02`) | Generic diagnostic name | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default (`allow_inferred=False`). |
| `SG_STATUS_LESEN` | Speculatively assumed `0x3E 0x00` | None | None | None | **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED ALWAYS** (`NotImplementedError`). |
| `AUTHENTISIERUNG` | ReadAuthCapabilities | None | None | `winkfpt_004b95a0.c` | **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** (`NotImplementedError`). |
| `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` | RoutineControl `0x31 0x07` (Seed) | None | **YES** (`87 78 F1 31 07 03 34 66 36 32`) | `winkfpt_0041c920.c` | **OBSERVED_JOB_MAPPING[target=10FLASH]** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** (`NotImplementedError`). |
| `NG_AUTHENTISIERUNG_START` | RoutineControl `0x31 0x08` (Key) | None | **YES** (`92 78 F1 31 08 EA 9C 6D...`) | `winkfpt_0041c920.c` | **OBSERVED_JOB_MAPPING[target=10FLASH]** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** (`NotImplementedError`). |
| `FLASH_SCHREIBEN` | Flash Block Write Transfer (`0x36`) | Prohibited | `FLASH_SCHREIBEN` (283x) | `winkfpt_004665d0.c` | **FORBIDDEN** | Hard safety block (`KdcanError`). |

---

## 9. Code Implementation Assessment

* In [`reconstruction/transport/kdcan/bus.py`](../../reconstruction/transport/kdcan/bus.py):
  1. No mappings are promoted from `INFERRED_JOB_MAPPING` to `OBSERVED_JOB_MAPPING` for the transmission controller (`GS19` / address `0x18`), because no SGBD trace for `0479S90T641Z` exists in the repository.
  2. `DirectKdcanBus` maintains its strict fail-closed contract:
     * `allow_inferred=False` (default) rejects `AIF_LESEN`, `TESTER_PRESENT`, `IDENT_LESEN`, `SG_PHYS_HWNR_LESEN` with `NotImplementedError`.
     * `SG_STATUS_LESEN` raises `NotImplementedError` unconditionally (classified as `UNKNOWN`).
     * `wire_read_aif()` and `wire_tester_present()` remain available for direct wire execution without making unevidenced EDIABAS job claims.
     * Flash writing operations (`FLASH_SCHREIBEN`, `SEND_SEGMENT`, `FLASH_SCHREIBEN_XXL`, `NG_SIGNATUR_PRUEFEN`) are hard-blocked with `KdcanError`.
* **Conclusion**: The existing codebase already precisely embodies the forensic reality. No broadening of permissions or premature promotion of job mappings was performed.

---

## 10. Automated Off-Hardware Verification

The complete verification test suite was executed in the clean-room virtual environment without hardware communication:

* **KAT Tier (`tests/kat/`)**: 33 run, 33 passed, 0 skipped, 0 failed.
  * Includes all 18 native K+DCAN transport tests in `tests/kat/transport/test_kdcan_transport.py`.
* **GOLDEN Tier (`tests/golden/`)**: 10 run, 10 passed, 0 skipped, 0 failed.
* **DIFFERENTIAL Tier (`tests/differential/`)**: 8 run, 8 passed, 0 skipped, 0 failed.
* **TOTAL**: **51 tests passed, 0 skipped, 0 failed** (Total execution time: ~4.6 s).
* **Hardware Confirmation**: Zero serial port opens, zero probe executions, zero packets sent over physical wire.
