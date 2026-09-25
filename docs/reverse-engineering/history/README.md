# Historical Research Evolution: Revisions 1 through 18.1

This directory preserves the historical record of the investigation into the BMW WinKFP / EDIABAS flashing toolchain.

---

## 1. Epistemological Principle: Preserving the Path of Discovery

In reverse-engineering research, documenting false leads, disproven hypotheses, and successive refinements is as vital as documenting the final conclusion:
* Early hypotheses must **NOT** be silently edited to make it appear as if the final conclusions were obvious from the outset.
* Where an earlier audit concluded $X$, but subsequent evidence proved $Y$, both the original hypothesis and the corrective discovery are preserved and labeled accordingly.

---

## 2. Chronological Milestones Overview

| Milestone | Key Focus Area | Initial Hypothesis / Finding | Subsequent Verification / Correction | Current Status |
|:---:|---|---|---|:---:|
| **Rev 1** | Initial decompiler pass on `winkfpt.exe` | RSA bignum words were assumed to be Big-Endian. | Disproven in Rev 2: $N$ and $E$ are strictly odd in Little-Endian format. | `SUPERSEDED` |
| **Rev 1** | Flash sector erasure | Assumed WinKFP transmitted null bytes to erase memory. | Disproven in Rev 2: WinKFP sends no erase command; ECU flash kernel erases internally. | `DISPROVEN` |
| **Rev 2** | Multi-threaded TesterPresent | Assumed keep-alive ran on a separate background thread. | Refined in Rev 2: Synchronous, single-threaded scheduler invoked before each segment. | `CORRECTED` |
| **Rev 3** | RSA key parameters extraction | Key arrays suffered transcription corruption (257 hex chars). | Fixed in Rev 3: Extracted via automated script directly from Ghidra database. | `CORRECTED` |
| **Rev 4** | Signature polling race conditions | Dual `poll_status()` calls caused missed `0x50 -> 1` transitions. | Fixed in Rev 4: Strict single-poll contract with bounded retry limit. | `CORRECTED` |
| **Rev 5** | Ground-truth validation via CPU emulation | Needed Windows environment to prove cryptographic KATs. | Breakthrough in Rev 5: Unicorn x86 emulator runs original code natively on macOS/Linux. | `VALIDATED` |
| **Rev 6** | SP-Daten constant verification | Flash parameters assumed uniform across all ECUs. | Validated in Rev 6: Parsed actual E60 SP-Daten sets (`CI62F1`, `CI63F1`). | `VALIDATED` |
| **Rev 8** | SGBD encryption | Password verification in `ebas32.dll` was treated as a black box. | Reversed in Rev 8: Extracted master password table (`63477BC6`) and XOR-0xF7 masks. | `VALIDATED` |
| **Rev 9** | IFH serial transport | Low-level OBD transport was unverified. | Verified in Rev 9: Emulated `OBD32.dll` in Unicorn with virtual COM port. | `VALIDATED` |
| **Rev 10** | Key container discovery (`SGIDC.as2`) | Hypothesized external definition file `ATBALGO.C`. | Disproven in Rev 10: `ATBALGO.C` is an unreferenced string; `GetAuthKey` loads `SGIDC.as2`. | `REFINED` |
| **Rev 11** | End-to-end `GetAuthKey` execution | Container loader verified through mocked provider. | Verified in Rev 11: Original `FUN_004b8fe0` executed in Unicorn reading real container. | `VALIDATED` |
| **Rev 12** | Key negotiation & record pairing | Auto-negotiation failed on dual-container ECUs. | Refined in Rev 12: Implemented art-to-record pairing across both container indices. | `CORRECTED` |
| **Rev 13** | Bench differential tooling | Trace comparison lacked semantic field checking. | Introduced `bench_diff.py` with L1 (choreography) and L2 (semantics) tiers. | `VALIDATED` |
| **Rev 14** | Write-free terminology | First contact was loosely called "read-only". | Corrected in Rev 14: Re-termed "write-free / no-flash" (diagnostic state alters). | `REFINED` |
| **Rev 15** | Strict tri-state diffing | Missing status on one side passed silently. | Fixed in Rev 15: Strict tri-state diff where one-sided values trigger failure. | `CORRECTED` |
| **Rev 16** | Secret redaction in logs | Bench logs wrote raw key bytes into JSONL. | Fixed in Rev 16: Default logs redact keys to SHA-256 + length for safe sharing. | `VALIDATED` |
| **Rev 17** | Per-attempt auth audit | Logs only audited final auth attempt. | Extended in Rev 17: Full audit trail across all retry attempts. | `VALIDATED` |
| **Rev 18** | Preflight guards & lifecycle cleanup | Handlers leaked on repeated in-process runs. | Resolved in Rev 18.1: Idempotent adapter close in `finally` blocks. | `VALIDATED` |

---

## 3. Detailed Chronology

For the exhaustive technical narrative of each audit revision and the corresponding peer review feedback, see:
* [rev1-rev18-chronology.md](rev1-rev18-chronology.md)
