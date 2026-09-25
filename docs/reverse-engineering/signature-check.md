# Post-Flash Signature Check & Status Polling

This document details the reverse engineering of the firmware signature verification process executed via diagnostic job `NG_SIGNATUR_PRUEFEN`.

---

## 1. Diagnostic Job Invocation

Following the transmission of all firmware blocks, the flashing script executes signature verification:
* **Job Name**: `NG_SIGNATUR_PRUEFEN`
* **Pre-read Timing**: The expected signature test duration is retrieved beforehand from `FLASH_ZEITEN_LESEN` via parameter `FLASH_SIGNATURTESTZEIT`.

---

## 2. Polling Loop State Machine

Because modern automotive microcontrollers perform public-key RSA signature verification over the complete downloaded image in flash, the check is asynchronous.

WinKFP polls the diagnostic result variable using a strict polling loop:

```text
                        +----------------------------+
                        |  job NG_SIGNATUR_PRUEFEN   |
                        +----------------------------+
                                      │
                                      ▼
                        +----------------------------+
                        |   Read status result       |
                        +----------------------------+
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │ status == 0x50          │ status == 0x01          │ other / error
            ▼                         ▼                         ▼
   +------------------+      +------------------+      +------------------+
   | Pending Token    |      | Signature OK     |      | Signature Failed |
   | Sleep & Continue |      | Proceed to Reset |      | Abort Flash Run  |
   +------------------+      +------------------+      +------------------+
```

### 2.1 Status Tokens
* **`0x01` (`OKAY`)**: Digital signature verified successfully. The ECU marks the application partition as valid and bootable.
* **`0x50` (`ROUTINE_NOT_COMPLETE` / Pending)**: Verification in progress. The host must wait and poll again.
* **Error Tokens (`0x00`, `0x02`, `0xFF`)**: Signature mismatch, corrupted image, or memory CRC error.

### 2.2 Polling Loop Implementation Contract
* **Single Poll per Iteration**: In early research (Rev 3), an implementation bug performed two consecutive `poll_status()` calls per loop iteration, causing race conditions where a fast status transition `0x50 -> 1` was missed. Corrected in **Revision 4** to execute exactly one poll per cycle.
* **Bounded Retries**: The loop is bound by a maximum timeout budget derived from `FLASH_SIGNATURTESTZEIT`. If the ECU remains in state `0x50` indefinitely, the runner aborts with a timeout fault.
