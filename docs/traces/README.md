# Diagnostic & Flashing Traces

This directory documents the diagnostic and programming communication traces captured, analyzed, and synthesized during research on the WinKFP and EDIABAS toolchain.

---

## 1. Trace Categories & Provenance

### 1.1 Sanitized Production Trace (`traces/sanitized/sanitized_flash_session.trc`)
* **Origin**: Captured from a genuine WinKFP diagnostic and flashing session running under EDIABAS 6.4.7 (`api.trc`).
* **Nature**: Real physical diagnostic session capture (1,293 sequential EDIABAS diagnostic jobs).
* **Target ECU Identity & Scope Notice**:
  * The target ECU recorded in this trace is `13_ASK` (Audio System Controller / ASK module), not a transmission controller (such as GS19 or EGS).
  * While the WinKFP VDLE download engine, 21-byte `FLASH_SCHREIBEN` header framing, block sequence management, keep-alive pacing, and `JOB_STATUS` polling behavior are identical across WinKFP flash orchestrations, researchers should be aware of this specific ECU target when comparing payload parameters or SGBD-specific job names.
* **Sanitization Status**:
  * 100% scrubbed of private and proprietary data.
  * All 17-character Vehicle Identification Numbers (VINs matching `WBA...`) replaced with `WBAXXXXXXXXXXXXXXXX`.
  * Real timestamps, calibration numbers, dealer codes, and customer references have been scrubbed or normalized.
  * Secret key material and proprietary payloads are replaced or hash-digested.

### 1.2 Expected Benchmark Traces (`traces/expected/`)
* **Nature**: Synthetic / simulated event logs generated via the clean-room mock harness (`tools/bench_diff/bench_scenario.py`).
* **Purpose**: Golden reference models for automated L4 differential verification (`tools/bench_diff/bench_diff.py`).
* **Files**:
  * `bench_contact_mock.jsonl`: 17-event normalized log capturing the write-free controlled contact scenario (`IDENT_LESEN` -> authentication negotiation -> seed/key exchange -> segment info check -> clean session termination).
  * `bench_full_mock.jsonl`: 73-event normalized log simulating a full flash write cycle including block transfers (`FLASH_SCHREIBEN`), keep-alive ticks (`SG_STATUS_LESEN`), and final signature check (`NG_SIGNATUR_PRUEFEN`).

---

## 2. Trace Format Specification

Expected traces are stored as line-delimited JSON (`.jsonl`). Each event record adheres to the following schema:

```json
{
  "t_rel_s": 0.0125,
  "op": "job_bin",
  "dev": "DLE08",
  "name": "FLASH_SCHREIBEN",
  "args": "",
  "bytes": 54,
  "sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "status": "OKAY"
}
```

* `t_rel_s`: Relative timestamp in seconds.
* `op`: Operation type (`job`, `job_bin`, `read_text`, `read_binary`, `error`).
* `dev`: Target device / SGBD handle (e.g., `DLE08`, `13_ASK`, `VDLE`).
* `name`: Diagnostic job or result name.
* `args`: Semicolon-delimited text parameters.
* `bytes`: Length in bytes of the binary payload (if applicable).
* `sha`: SHA-256 hash of the payload (allows byte-exact verification without disclosing confidential data).
* `status`: EDIABAS `JOB_STATUS` returned by the adapter.
