# Research Source Map & Traceability Matrix

This document provides a comprehensive traceability mapping linking every published file in `winkfp-research` back to its origin in the immutable research archive `bmw_flash_re/`.

A complete, machine-readable manifest of all evaluated source files, their SHA-256 digests, provenance classification, public destinations, and disposition actions is available in:
- [`research-source-map.csv`](research-source-map.csv) (395 inventoried entries with cryptographic SHA-256 hashes)

---

## 1. Documentation & Research Guides

| Published Document | Source File(s) in `bmw_flash_re/` | Original Purpose | Transformation Performed |
|---|---|---|---|
| `docs/EVIDENCE.md` | `REPORT.md` (lines 1–320), audit notes | Evaluation of research rigor across revisions 1–18 | Synthesized into formal L0–L7 evidence model; explicit marking of hardware status (L6/L7 unvalidated). |
| `docs/METHODOLOGY.md` | `REPORT.md`, `kat_emulate.py`, `vdle_diff.py` | Implementation notes on Ghidra, Unicorn, and test runners | Formalized into pipeline documentation detailing decompiler, CPU emulator, and differential methodology. |
| `docs/ARCHITECTURE.md` | `REPORT.md`, `WAS_ORCHESTRATION.md`, `bench_scenario.py` | Technical layers from GUI to transceivers | Diagrammed and structured into clear component distinctions (OEM vs reconstructed vs open6hp). |
| `docs/PROPRIETARY_MATERIAL.md` | `SPDATEN.md`, `KEYS_AS2.md`, file inventory | Catalog of OEM data sets and containers | Clean-room disclosure detailing excluded BMW proprietary assets and reproduction instructions. |
| `docs/QUARANTINE.md` | Whole archive file census | Provenance evaluation of 3,359 source files | Complete provenance audit report confirming zero unclassified/quarantined files. |
| `docs/reverse-engineering/overview.md` | `REPORT.md` (sections 1–5) | High-level reverse-engineering summary | Restructured into dedicated modular overview of WinKFP/EDIABAS components. |
| `docs/reverse-engineering/kr-api.md` | `REPORT.md` (section 1), decompiled sources | Documentation of `KrApiLib.cpp` and crypto dispatch | Detailed documentation of Symmetric MD5, Simple cipher, and Asymmetric RSA-512 algorithms. |
| `docs/reverse-engineering/get-auth-key.md` | `KEYS_AS2.md`, `kat_e2e_getauthkey.py` | Discovery and analysis of `SGIDC.as2` and `SGIDD.as2` | Detailed guide on `GetAuthKey` (`FUN_004b8fe0`), container line grammar, and 3DES-EDE-ECB decryption. |
| `docs/reverse-engineering/security-access.md` | `REPORT.md` (lines 14–64), `flash_runner.py` | Orchestrator `FUN_0041c920` analysis | Flowchart and step-by-step description of seed acquisition, retry chains, and status codes. |
| `docs/reverse-engineering/vdle.md` | `REPORT.md` (section 2), `VDLE_TRACE.md` | VDLE download engine dispatching | Exhaustive documentation of `INIT_VDLE`, OPPS configuration, and segment table loading. |
| `docs/reverse-engineering/flash-schreiben.md` | `VDLE_TRACE.md`, `ALL_FOR_REVIEW.md` | Binary analysis of `FUN_004668b0` | Precise byte layout breakdown of 21-byte header, XXL block sizing, and chunk iteration. |
| `docs/reverse-engineering/signature-check.md` | `REPORT.md` (lines 230–270), `flash_runner.py` | Verification of `NG_SIGNATUR_PRUEFEN` | State machine documentation for status polling (0x50 pending vs 0x01 OKAY). |
| `docs/reverse-engineering/ediabas.md` | `REPORT.md` (section 4), `SECUR_DECODED.md` | EDIABAS API internals & master passwords | API boundary documentation (`apiJob`, `apiResult`), error codes, and password decoding. |
| `docs/reverse-engineering/obd32-ifh.md` | `IFH_OBD.md`, `obd_emulate.py` | Analysis of `OBD32.dll` K-Line transport | Serial framing, XOR checksumming, and baud rate negotiation documentation. |
| `docs/reverse-engineering/history/` | `REPORT.md` (audits rev 2 through rev 18.1) | Chronological development logs and external reviews | Historical preservation of all 18 revision cycles, false leads, and subsequent corrections. |

---

## 2. Reconstructions (`reconstruction/`)

| Published Module | Source File(s) in `bmw_flash_re/` | Purpose | Transformation Performed |
|---|---|---|---|
| `reconstruction/crypto/symmetric.py` | `reconstruction/security.py` | Clean-room Symmetric MD5 | Modularized into `reconstruction.crypto.symmetric` with clean typing and docstrings. |
| `reconstruction/crypto/simple.py` | `reconstruction/security.py` | Clean-room Simple 8-byte cipher | Modularized into `reconstruction.crypto.simple`. |
| `reconstruction/crypto/asymmetric.py` | `reconstruction/security.py`, `reconstruction/rsa_keys.py` | Clean-room RSA modexp & key store | Modularized into `reconstruction.crypto.asymmetric` with Little-Endian bignum handling. |
| `reconstruction/auth/key_containers.py` | `reconstruction/as2_keys.py` | Parser for `.as2` files & 3DES decryptor | Modularized into `reconstruction.auth.key_containers`. |
| `reconstruction/auth/get_auth_key.py` | `kat_e2e_getauthkey.py`, `flash_runner.py` | `GetAuthKey` simulation and key resolution | Reconstructed clean interface resolving ECU names to keys. |
| `reconstruction/auth/retry_chain.py` | `flash_runner.py` (lines 300–450) | State machine for 3x auth retries | Extracted into standalone auth retry state handler. |
| `reconstruction/vdle/protocol.py` | `reconstruction/vdle.py` | VDLE commands, states, and OPPS | Modularized into protocol definitions and constants. |
| `reconstruction/vdle/segments.py` | `reconstruction/vdle.py` | Segment table loader and chunk iterator | Reconstructed chunking and table parsing logic. |
| `reconstruction/vdle/flash_schreiben.py` | `reconstruction/vdle.py` | 21-byte block builder and XXL logic | Block packaging and validation routines. |
| `reconstruction/ediabas/api.py` | `transport/ediabas_api.py` | EDIABAS API binding and mock bus | Modularized into `reconstruction.ediabas.api`. |
| `reconstruction/ediabas/ifh.py` | `reconstruction/obd_ifh.py` | Pure-Python OBD32 IFH emulation | Modularized into `reconstruction.ediabas.ifh`. |
| `reconstruction/transport/isotp.py` | `transport/isotp.py` | ISO 15765-2 transport layer | Clean import structure for standalone framing. |
| `reconstruction/safety/id_check.py` | `safety/id_check.py` | Interlock conditions and Limits parser | Modularized into `reconstruction.safety.id_check`. |
| `reconstruction/safety/hypotheses.py` | `safety/hypotheses.py` | Hypothetical voltage/state limits | Modularized with explicit disclaimer banners. |
| `reconstruction/runner.py` | `flash_runner.py` | End-to-end flash orchestration engine | Updated imports to reference new modular packages. |

---

## 3. Analysis Artifacts (`analysis/`)

| Target Directory in `analysis/` | Source Files in `bmw_flash_re/` | Contents & Purpose |
|---|---|---|
| `analysis/kr_api/` | `decompiled/winkfpt_004617c0.c`, `00461800.c`, `004b95a0.c` | Decompiled C code for `KrApiAuthenticate`, MSVC rand nonce generation, and buffer validation. |
| `analysis/get_auth_key/` | `decompiled/winkfpt_004b8fe0.c`, `0046f350.c`, `0046f630.c`, `0046f6d0.c`, `KEYS_AS2.md` | Decompiled C code for `GetAuthKey`, ATBALGO format string tables, container naming logic. |
| `analysis/crypto/symmetric/` | `decompiled/winkfpt_004bbdb0.c`, `004bbf90.c`, `004bbdf0.c`, `004bbff0.c`, `004b8cc0.c`, `004b9f50.c` | Decompiled MD5 compression functions, IV tables (`0x605160`), and symmetric key tables. |
| `analysis/crypto/simple/` | `decompiled/winkfpt_004ba1b0.c`, `004ba080.c` | Decompiled proprietary 8-byte Simple cipher round loops. |
| `analysis/crypto/asymmetric/` & `rsa/` | `decompiled/winkfpt_004b9e30.c`, `004b8ac0.c`, `004bb720.c`, `004bb780.c`, `004bb8c0.c`, `004bb910.c`, `004bb930.c` | Decompiled RSA modular exponentiation, Montgomery reduction, and LE bignum parsing. |
| `analysis/vdle/` | `decompiled/winkfpt_004a1f80.c`, `004a5850.c`, `004a5960.c`, `004a5a40.c`, `004a5ac0.c`, `004a5b60.c`, `004a5eb0.c`, `004a6150.c`, `004665d0.c`, `004668b0.c`, `VDLE_DIFF.md`, `VDLE_TRACE.md` | Decompiled VDLE dispatcher, OPPS configuration, keep-alive routines, and block dispatch. |
| `analysis/ediabas/` | `decompiled/winkfpt_00490250.c`, `ebas32_100217e4.c`, `ebas32_10021c38.c`, `SECUR_DECODED.md` | Decompiled EDIABAS dispatch pointers, master password tables, and SGBD XOR decoders. |
| `analysis/obd32/` | `IFH_OBD.md`, `obd_emulate.py` | Export contracts and disassembly analysis of `OBD32.dll`. |

---

## 4. Tests, Tools, & Traces

| Published File | Source File(s) in `bmw_flash_re/` | Purpose | Transformation Performed |
|---|---|---|---|
| `tests/run_tests.py` | `run_selftest.py` | Master standalone test suite | Refactored to test against new modular `reconstruction/` packages. |
| `tests/kat/crypto/` | `run_selftest.py`, `kat_emulate.py` | Cryptographic KATs | Isolated into standalone unit tests for MD5, Simple, 3DES, and RSA. |
| `tests/kat/auth/` | `kat_realkeys.py`, `run_selftest.py` | Key resolution KATs | Packaged with synthetic test vectors. |
| `tests/golden/vdle/` | `VDLE_TRACE.md`, `vdle_trace.py` | Golden VDLE sequence validation | Formatted as golden assertions for test harnesses. |
| `tests/differential/` | `vdle_diff.py`, `asym_full_kat.py`, `obd_emulate.py` | Unicorn differential runners | Preserved with clear instructions for optional local binary execution. |
| `tools/bench_diff/` | `bench_diff.py`, `bench_scenario.py` | Trace differ & bench scenario runner | Cleaned and packaged as standalone command-line tools. |
| `tools/analysis/` | `secur_decode.py`, `spdaten_scan.py`, `probe_e2e.py` | Reverse engineering utilities | Formatted as standalone analysis scripts. |
| `traces/sanitized/` | `EDIABAS_6.4.7/TRACE/api.trc` | Real EDIABAS flash trace | Scrubbed of real vehicle identification numbers (`WBA...`) and secrets. |
| `traces/expected/` | `vdle_diff.py` event dumps | Golden event logs for DF1–DF11 | Saved as clean reference `.jsonl` files. |
| `examples/` | `bench_scenario.py`, `flash_runner.py` snippets | Reproducible demonstrations | Created runnable example scripts for authentication, VDLE, and trace comparison. |
