# Milestone 5.10.2: Offline Address Terminology & API Semantics Audit

**Status**: VERIFIED & ACCEPTED (Strictly Off-Hardware)  
**Date**: 2026-09-27  
**Scope**: Target/Source Addressing Semantics, API Alignment, and Framing Terminology

---

## 1. Executive Summary

Milestone 5.10.2 executes a comprehensive, strictly OFF-HARDWARE audit of addressing terminology and API semantics across the EDIABAS job replay and canonical diagnostic pipeline layer.

The audit resolves potential terminology ambiguity regarding the DS2 wire header bytes:
1. In canonical DS2 **request frames** (TX: Tester $\to$ ECU):
   - `byte[1]` is unambiguously **destination / target ECU address** (`0x18` for EGS, `0x78` for factory trace).
   - `byte[2]` is unambiguously **source / tester address** (`0xF1`).
2. In canonical DS2 **response frames** (RX: ECU $\to$ Tester):
   - `byte[1]` is unambiguously **destination / tester address** (`0xF1`).
   - `byte[2]` is unambiguously **source / target ECU address** (`0x18` for EGS, `0x78` for factory trace).

All legacy ambiguous phrasing such as `src=0x78 -> 0x78` has been eliminated from code, comments, test suites, and documentation. No variable named `src` stores a destination address.

---

## 2. Canonical DS2 Addressing Architecture

```
========================================================================================
                               CANONICAL DS2 ADDRESSING
========================================================================================

1. REQUEST TELEGRAM (Tester -> ECU):
   +---------------+-----------------------------+-----------------------+-------------+
   | byte[0]       | byte[1]                     | byte[2]               | byte[3..N]  |
   | Format Byte   | Destination / Target ECU    | Source / Tester       | Payload     |
   | (0x80 | len)  | 0x18 (EGS) / 0x78 (Factory) | 0xF1 (Tester)         | ...         |
   +---------------+-----------------------------+-----------------------+-------------+
   * Trailing Checksum (Wire frame only): byte[N+1] = sum(byte[0..N]) & 0xFF

2. RESPONSE TELEGRAM (ECU -> Tester):
   +---------------+-----------------------------+-----------------------+-------------+
   | byte[0]       | byte[1]                     | byte[2]               | byte[3..N]  |
   | Format Byte   | Destination / Tester        | Source / Target ECU   | Payload     |
   | (0x80 | len)  | 0xF1 (Tester)               | 0x18 (EGS) / 0x78 (F) | ...         |
   +---------------+-----------------------------+-----------------------+-------------+
   * Trailing Checksum (Wire frame only): byte[N+1] = sum(byte[0..N]) & 0xFF
========================================================================================
```

---

## 3. Audited & Harmonized Components

### 3.1 Model & API Harmonization (`reconstruction/ediabas/replay.py`)
- **`EdiabasTelegram`**:
  - Exposes explicit properties `destination`, `destination_address`, `source`, `source_address` alongside `target` and `tester`.
  - `from_payload` supports `destination` and `source` keyword parameters.
- **`EdiabasJobResult`**:
  - Exposes explicit properties `destination_address` (byte 1 in request) and `source_address` (byte 2 in request) alongside `target_address` and `tester_address`.
- **`EdiabasJobReplayEngine`**:
  - `build_logical_telegram` and `execute_job` accept `destination_address` and `source_address` kwargs.
- **Auto-Detection Logic**:
  - Strict extraction using `frame_dst = raw_frame[1]` and `frame_src = raw_frame[2]`.
  - Differentiates requests (`frame_dst != 0xF1`) vs responses (`frame_dst == 0xF1`).
  - No variable named `src` stores destination.

### 3.2 Pipeline & Job Definition Alignment (`reconstruction/ediabas/job_model.py` & `pipeline.py`)
- **`SgbdJobDefinition.build_request`**:
  - Supports `destination_address` and `source_address` kwargs.
  - Enforces canonical DS2 wire order `build_ds2_frame(dst=dst, src=src, payload=payload)`.
- **`CanonicalPipeline.build_request` & `CanonicalPipeline.execute`**:
  - Accepts `destination_address` and `source_address` kwargs.

---

## 4. Deterministic Regression Testing

Test `test_17_canonical_ds2_request_addressing_semantics` in `tests/golden/ediabas/test_ediabas_job_replay.py` deterministically verifies:
1. `FACTORY_TRACE`:
   - `logical_request[1] == 0x78` (destination / target)
   - `logical_request[2] == 0xF1` (source / tester)
   - `canonical_ds2_request[1] == 0x78`
   - `canonical_ds2_request[2] == 0xF1`
   - `telegram.destination == 0x78`, `telegram.source == 0xF1`
   - `result.destination_address == 0x78`, `result.source_address == 0xF1`
2. `PHYSICAL_EGS_FIXTURE`:
   - `logical_request[1] == 0x18` (destination / target)
   - `logical_request[2] == 0xF1` (source / tester)
   - `canonical_ds2_request[1] == 0x18`
   - `canonical_ds2_request[2] == 0xF1`
   - `telegram.destination == 0x18`, `telegram.source == 0xF1`
   - `result.destination_address == 0x18`, `result.source_address == 0xF1`
3. API argument aliases:
   - Verifies execution with `destination_address=0x18` and `source_address=0xF1`.

### Test Suite Execution Output
```
Ran 17 tests in 0.009s
OK

Full Suite (tests/run_tests.py):
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  62 run,  62 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 141 tests in 4.185s | 141 passed | 0 skipped | 0 failed
```

---

## 5. Hardware Safety & Immutability Verification

- **Serial Port Access**: ZERO (`/dev/cu.usbserial-A50285BI` untouched).
- **Physical Bus Transmission**: ZERO bytes transmitted.
- **Physical Trace Fixture SHA-256 Verification**:
  ```
  f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d  traces/hardware/20260926_173201_egs_aif.json
  cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791  traces/hardware/20260926_174033_egs_tester_present.json
  4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462  traces/hardware/20260926_174811_egs_ident.json
  6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15  traces/hardware/20260926_175924_egs_physical_hw_nr.json
  ```
All fixtures match canonical reference digests exactly.
