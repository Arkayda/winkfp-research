# Contributing to `winkfp-research`

Thank you for your interest in contributing to the `winkfp-research` project.

This repository is dedicated to the technical reverse-engineering, documentation, and clean-room reconstruction of legacy BMW flashing protocols (WinKFP, EDIABAS, VDLE, KrApi).

---

## 1. Core Principles & Epistemological Model

Every contribution, whether documentation, test case, or reconstruction code, must adhere to the project's evidence hierarchy. When submitting issues, pull requests, or research notes, you **must explicitly tag** statements and findings:

* **`OBSERVED`**: Fact directly read from binary code, disassembly, memory state, or an execution trace. Must cite exact address, instruction, or trace snippet.
* **`INFERRED`**: Logical deduction or hypothesis derived from observed data.
* **`RECONSTRUCTED`**: Independent clean-room implementation of behavior modeled on observations.
* **`VALIDATED`**: Empirically confirmed against a specific test boundary (KAT, differential execution against original binary, or simulated bus).
* **`NOT YET VALIDATED`**: Any hypothesis, edge-case, or hardware scenario not yet backed by concrete proof.

Never claim hardware validation or successful ECU flashing unless supported by verifiable physical trace evidence.

---

## 2. Hard Exclusion of Proprietary Material

We maintain a strict clean-room policy. **Do NOT submit**:
* Original BMW executable binaries (`.exe`, `.dll`, `.drv`).
* BMW SP-Daten archives or files (`.0da`, `.ipo`, `.prg`, `.grp`, `.met`, `.c01`–`.c99`).
* Original BMW key container files (`SGIDC.as2`, `SGIDD.as2`).
* OEM cryptographic private keys.
* Unredacted diagnostic traces containing VINs, chassis numbers, or customer identifiers.
* Memory dumps from production vehicles.

Pull requests containing proprietary or unredacted material will be closed immediately and scrubbed from history.

---

## 3. Desired Contributions

We welcome:
1. **Independent Reproduction**: Reproducing existing differential tests or KATs on diverse environments.
2. **Sanitized Traces**: Anonymized diagnostic logs (EDIABAS `.trc`, CAN `.pcap`, K-Line hex dumps) with all VINs replaced by `WBAXXXXXXXXXXXXXXXX` and keys redacted.
3. **ECU Family Mapping**: Documentation of additional ECU families, authentication algorithms, and block size behaviors.
4. **Synthetic Test Fixtures**: Deterministic mock containers, test vectors, and simulation scenarios.
5. **Corrections & Errata**: Clarifications where earlier research revisions made incorrect assumptions.

---

## 4. Code Standards & Testing

* Reconstructed code in `reconstruction/` must be pure Python or standard portable languages without proprietary runtime dependencies.
* All new algorithms or parser additions must be accompanied by deterministic unit tests or Known-Answer Tests (KAT) under `tests/`.
* Code must pass all existing checks:
  ```bash
  python3 tests/run_tests.py
  ```
