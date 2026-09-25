# Reverse-Engineering Overview: BMW WinKFP Flashing Stack

This document provides a technical summary of the legacy BMW WinKFP (Windows KFP / KMM Flashing Tool) and EDIABAS programming architecture reconstructed in this repository.

---

## 1. High-Level Subsystem Map

The legacy programming toolchain consists of six major functional layers:

```text
+--------------------------------------------------------------------------+
| 1. High-Level Orchestrator (winkfpt.exe)                                 |
|    - Central state machine FUN_0041c920                                  |
|    - Interlocks & precondition verification (FUN_0041ae40)               |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| 2. Security Access & Cryptography (KrApiLib)                             |
|    - Seed acquisition (job NG_AUTHENTISIERUNG_START)                     |
|    - Key computation: Symmetric (MD5), Simple, Asymmetric (RSA-512)     |
|    - Runtime key retrieval via GetAuthKey (FUN_004b8fe0)                 |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| 3. Download Engine (VDLE Dispatcher FUN_004a1f80)                        |
|    - Session initialization & OPPS configuration (INIT_VDLE)             |
|    - Segment table loading (LOADTABLE / REQUEST_SEGMENTINFO)             |
|    - Block chunking & 21-byte framing (SEND_SEGMENT / FLASH_SCHREIBEN)   |
|    - Resend & recovery handling (WAS / RESEND_SEGMENT)                   |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| 4. Session Maintenance & Timing                                          |
|    - Single-threaded synchronous TesterPresent keep-alive (FUN_004a5960) |
|    - DIAGNOSE_AUFRECHT and NORMALER_DATENVERKEHR scheduling              |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| 5. Diagnostic Transport Boundary (EDIABAS API)                           |
|    - apiJob, apiJobData, apiResult, apiState                             |
|    - SGBD bytecode execution (.prg / .ipo)                               |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| 6. Hardware Interface Driver (IFH / OBD32.dll)                           |
|    - K-Line UART communication (9600 8E1 wake, 8N1 high-speed transfer)  |
|    - Hardware command framing & XOR byte checksums                       |
+--------------------------------------------------------------------------+
```

---

## 2. Navigating the Reverse-Engineering Documentation

Each functional layer is analyzed in detail in its dedicated specification document:

* [kr-api.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/kr-api.md): Analysis of the internal `KrApiLib` cryptographic engine (Symmetric MD5, proprietary Simple cipher, Asymmetric RSA-512, and the MSVC LCG RNG).
* [get-auth-key.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/get-auth-key.md): Reverse engineering of `GetAuthKey` (`FUN_004b8fe0`), `SGIDC.as2` / `SGIDD.as2` container parsing, and 3DES-EDE-ECB decryption.
* [security-access.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/security-access.md): Step-by-step trace of `FUN_0041c920`, seed/key negotiation, status polling, and 3x retry chain.
* [vdle.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/vdle.md): Deep dive into the VDLE download dispatcher (`FUN_004a1f80`), OPPS configuration commands, and session lifecycle.
* [flash-schreiben.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/flash-schreiben.md): Exact byte-level structure of the 21-byte `FLASH_SCHREIBEN` block header, XXL threshold, and chunk iteration.
* [signature-check.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/signature-check.md): Post-flash verification via `NG_SIGNATUR_PRUEFEN`, status polling semantics (0x50 pending vs 1 OKAY), and bounded poll limits.
* [ediabas.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/ediabas.md): EDIABAS API architecture, error status handling, master password decoding (`63477BC6`), and SGBD script interaction.
* [obd32-ifh.md](file:///Users/blogman/winkfp-research/docs/reverse-engineering/obd32-ifh.md): Low-level serial transport, `OBD32.dll` export contracts, and K-Line telegram framing.
* [history/](file:///Users/blogman/winkfp-research/docs/reverse-engineering/history/README.md): Complete chronological record of the 18 research audit cycles, showing how hypotheses evolved into verified facts.
