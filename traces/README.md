# Traces: Sanitized Production & Expected Execution Logs

This directory contains diagnostic trace artifacts used for verification, differential validation, and protocol specification.

---

## 1. Directory Contents

* **`sanitized/sanitized_flash_session.trc`**:
  * Real communication trace captured during a factory WinKFP flashing session via EDIABAS `api.trc` (1,293 diagnostic jobs).
  * **Sanitization**: All 17-character VINs matching `WBA...` have been replaced with `WBAXXXXXXXXXXXXXXXX`. Real timestamps, calibration numbers, and customer references have been scrubbed.
* **`expected/bench_contact_mock.jsonl`**:
  * Normalized 17-event log of the write-free controlled contact scenario (`identity -> auth negotiation -> auth handshake -> segment info -> exit`).
* **`expected/bench_full_mock.jsonl`**:
  * Normalized 73-event log of a full simulated flash cycle with block transfers, keep-alive calls, and signature check.

---

## 2. Using Traces with Differential Tooling

To run the differential validator against the sanitized trace:
```bash
python3 tools/bench_diff/bench_diff.py traces/expected/bench_contact_mock.jsonl traces/sanitized/sanitized_flash_session.trc --before FLASH_SCHREIBEN
```
