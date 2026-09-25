# Detailed Chronology of Research Audits: Rev 1 to Rev 18.1

This document chronicles the step-by-step technical progression, external peer review findings, disproven hypotheses, and architectural breakthroughs across 18 major research iterations.

---

## Revision 1: Initial Static Decompilation & Hypotheses

* **Initial Discovery**: Decompiled `winkfpt.exe` using Ghidra 12.1.4. Discovered central authentication orchestrator `FUN_0041c920`, `KrApiAuthenticate` (`FUN_004b95a0`), and the VDLE command dispatcher (`FUN_004a1f80`).
* **Hypothesis 1 (Big-Endian RSA)**: RSA bignum words were initially assumed to be Big-Endian due to Ghidra's CONCAT byte-ordering display.
* **Hypothesis 2 (Null Byte Erase)**: Assumed that WinKFP sent a block of null bytes via `FLASH_SCHREIBEN` to erase flash sectors.
* **Hypothesis 3 (Multi-threaded TesterPresent)**: Assumed that session keep-alive executed concurrently on a background worker thread.

---

## Revision 2: Peer Review & Endianness Breakthrough

* **RSA Byte Order Corrected (`L1/L2`)**: Decompilation of `FUN_004bb780` confirmed words are assembled as `in[4k] | (in[4k+1] << 8)...` — strictly **Little-Endian**. Crucial validation: RSA modulus $N$ and public exponent $E$ across all keys are strictly odd only in Little-Endian interpretation (an even RSA modulus is mathematically impossible).
* **Erase Routine Removed**: Transmitting null bytes via `FLASH_SCHREIBEN` does not erase sectors; flash kernel erases internally upon entry to programming mode. Standalone erase function removed.
* **TesterPresent Single-Threaded Architecture**: Verified that WinKFP invokes keep-alive synchronously between diagnostic jobs (`FUN_004a5960` called from `REQUEST_SEGMENTINFO` and `SEND_SEGMENT`). Reconstructed as single-threaded `JobScheduler`.
* **Limits Reclassified**: Battery and ignition limits reclassified from "BMW factory values" to `HYPOTHETICAL_LIMITS`.

---

## Revision 3: Algorithmic Hardening & Automation

* **P0 Key Transcription Defect**: Extracted RSA key blobs 3 and 4 were damaged during manual copy-pasting (257 hex characters). Fixed by writing automated Ghidra export scripts (`reconstruction/rsa_keys.py`).
* **ISO-TP Framing**: Rejected payloads $> 4095$ bytes with explicit `ISOTPError` (no CAN-FD escape support). Reserved STmin values (`0x80`–`0xF0`, `0xFA`–`0xFF`) rejected as errors.
* **Session Loss Enforcement**: If keep-alive fails and cannot recover, session drops immediately; flash jobs are blocked.

---

## Revision 4: Signature Polling & MSVC RNG

* **Signature Poll Bug**: Fixed dual `poll_status()` call per loop iteration that led to missed `0x50 -> 1` transitions.
* **MSVC `rand()` Proven (`L1/L4`)**: Discovered canonical MSVC Linear Congruential Generator at `FUN_005cafa9` / `005cafbb`:
  $$\text{holdrand} = \text{holdrand} \times 0x343FD + 0x269EC3 \pmod{2^{32}}, \quad \text{output} = (\text{holdrand} \gg 16) \ \& \ 0x7FFF$$
  Canonical test vector `srand(1) -> 41` verified.

---

## Revision 5: CPU Emulation via Unicorn

* **Breakthrough**: To bypass the need for a physical 32-bit Windows XP/7 machine to run WinKFP, built an x86 CPU emulation harness using `unicorn` and `pefile` (`kat_emulate.py`).
* **Result**: Executed raw x86 machine instructions of `winkfpt.exe` directly on host OS. All 16 Known-Answer Tests (KAT) for Symmetric MD5, Simple cipher, and raw RSA modexp passed byte-for-byte against the Python reconstruction.

---

## Revision 6: Golden Trace & VDLE Framing

* **Mock EDIABAS Boundary**: Hooked global API function pointers at `DAT_00735398` in emulated memory.
* **21-Byte Header Discovered**: Reverse-engineered exact binary structure of `FLASH_SCHREIBEN` (`01 01 00 00 00 00 00 00 00 FF 00 00 00 [len_le16 x2] [addr_le32] [data] 03`).
* **XXL Threshold Proven**: Confirmed `FLASH_SCHREIBEN_XXL` is chosen strictly by `INIT_VDLE` blocksize $> 254$ (`0xFE`), even for short-tail chunks.
* **TesterPresent Throttling**: Confirmed keep-alive is deadline-throttled via `GetTickCount()` (10,000 ms heavy / 8,000 ms light).

---

## Revision 7: Event-by-Event Differential (DF1–DF7)

* **Independent Differential Engine (`vdle_diff.py`)**: Ran original machine code and clean-room Python reconstruction against an identical mock EDIABAS simulator (`EdiabasSim`).
* **Proved Scenarios DF1–DF7**: Verified OPPS mode, block sizes 8/16/256, multi-segment images, and error aborts.
* **TesterPresent Failure Path**: Verified that upon failure of `NORMALER_DATENVERKEHR`, WinKFP does NOT fall back to `DIAGNOSE_AUFRECHT`; it immediately returns 0.

---

## Revision 8: WAS Recovery & SGBD Decryption

* **WAS Recovery Reconstructed**: Dispatched `SEND_SEGMENT("-1")` to resume interrupted transfers from block `blocks_done - bias`.
* **SECUR1/SECUR2 Decoded**: Reverse-engineered master password table in `ebas32.dll` (`63477BC6`) and decoded XOR-0xF7 obfuscation. Confirmed that SGBDs execute UDS services `$07`, `$08`, `$09`.

---

## Revision 9: Low-Level IFH Driver (`OBD32.dll`)

* **OBD32 Disassembly**: Reversed `OBD32.dll` export contracts (`INITIALIZE`, `WRITEDATA`, `READDATA`).
* **K-Line Telegram Framing**: Verified driver-appended XOR byte checksums and serial port configuration (9600 8E1 wake, 8N1 high speed).
* **Differential 11/11**: Original `OBD32.dll` machine code running in Unicorn verified byte-for-byte against `reconstruction/obd_ifh.py`.

---

## Revision 10: Real Key Containers (`SGIDC.as2`)

* **"ATBALGO.C" Disproven**: Demonstrated that `"ATBALGO.C"` at `0x0065d488` had zero code references.
* **`GetAuthKey` (`FUN_004b8fe0`)**: Discovered dynamic construction of `sgidc.as2` / `sgidd.as2` container names.
* **3DES Decryption**: Extracted static 24-byte 3DES key from `.data` dwords.
* **Placeholder Revelation**: Proved that static arrays at `0x00663390` are dynamically overwritten at runtime with decrypted container keys via `SetSiproKey` (`FUN_004b8e10`).

---

## Revision 11: End-to-End Container Loading in Unicorn

* **`kat_e2e_getauthkey.py`**: Executed original `GetAuthKey` in Unicorn with full CRT/IAT hooks, parsing real `SGIDC.as2` containers from disk.
* **Automated Negotiation**: Implemented auto-negotiation in `FlashRunner` to query ECU identification and select matching authentication algorithms dynamically.

---

## Revision 12: Dual Container Record Pairing

* **Multi-Container ECUs**: Handled ECUs present in both `SGIDC.as2` and `SGIDD.as2` with differing cryptographic modes (e.g., Simple vs Asymmetric).
* **Nonce Validation**: Banned `0000` placeholder fallbacks; asymmetric authentication without a fresh nonce strictly rejected.

---

## Revision 13: EDIABAS API Integration & Real Trace Differ

* **`EdiabasApiBus`**: Built ctypes adapter for official `api32.dll` based on official `Api.h` headers.
* **Production Trace Differ (`bench_diff.py`)**: Parsed real 2.4 MB flash trace (`api.trc`) containing 1,293 diagnostic jobs across `10FLASH` and `13_ASK`.

---

## Revision 14: Strict Semantic Verification (L1 / L2)

* **Two Verdict Tiers**:
  * **L1 Choreography**: Longest common prefix of `(device, job)` sequence.
  * **L2 Semantics**: Per-event matching of text arguments, payload length, payload SHA-256, and `JOB_STATUS`.
* **Controlled Contact Terminology**: Re-termed read-only mode to "write-free / no-flash" (diagnostic session state changes).

---

## Revision 15: Strict Tri-State Diff & Provenance Limits

* **Strict Tri-State Matching**: One-sided fields (e.g., `JOB_STATUS` present on one side but missing on the other) strictly flagged as a mismatch.
* **Dynamic Payload Exemption**: `NG_AUTHENTISIERUNG_START` exempt from SHA-256 check (since seed and nonce vary per attempt); verified semantically via `verify_auth()`.
* **Limits Provenance**: Enforced that `Limits` must be parsed from a digest-bound operator policy file.

---

## Revision 16: Pre-Bench Hardening & Secret Redaction

* **P0 Stale Status Elimination**: Enforced `apiState()` inspection after every API call; non-`APIREADY` states immediately trigger `EdiabasError` rather than reusing stale `JOB_STATUS`.
* **P0 State Gate Arming**: `state = 2` armed only after successful `INIT_VDLE` response.
* **Secret Redaction**: Redacted raw key bytes in JSONL logs; logs record `key_sha256` and `key_len` by default for safe public sharing.

---

## Revision 17: Per-Attempt Auth Audit & Error Handling

* **Full Chain Audit**: Updated `FlashRunner` and `LoggingBus` to log every retry attempt (`auth_attempts_log`). `verify_auth()` verifies that every attempt in the chain recomputes to the transmitted payload.
* **API Error Boundary**: Captured `apiInit()` and `apiTrace()` return codes to prevent silent diagnostic failures.

---

## Revision 18 & 18.1: Final Preflight Guards & Lifecycle Cleanup

* **Failed Contact Audit**: Ensured that aborted sessions (e.g., 3x `ERROR_AUTHENTICATION`) still write complete audit records so logs prove cryptographic correctness forensicly.
* **Unified Preflight Guard**: Consolidated image loading, limits parsing, and adapter connection under a single error boundary with clean exit codes.
* **Rev 18.1 Lifecycle Fix**: Added idempotent `LoggingBus.close()` in `finally` blocks to prevent handle leakage across repeated in-process runs.
