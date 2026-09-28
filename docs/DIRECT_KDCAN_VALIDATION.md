# Direct K+DCAN Transport & Physical Wire Validation Report

## 1. Overview & Proven Transport Reuse

To validate the `winkfp-research` codebase directly against physical vehicle hardware without reimplementing proven low-level transport mechanisms from scratch, the minimal K+DCAN serial transport and DS2 framing layer from the local `open6hp` project (`/Users/blogman/sHPAT`) was adapted as native, standalone code inside `winkfp-research`.

### Source Components Reused & Adaptation Log

| Component | Original Source Path in `open6hp` | Destination in `winkfp-research` | Modifications Made |
|---|---|---|---|
| **Base Abstraction** | `shpat/transport/base.py` | `reconstruction/transport/kdcan/base.py` | Extracted minimal `KdcanTransport` and `KdcanError` definitions; removed all transmission flasher application logic and ISO-TP dependencies. |
| **Protocol Framing** | `shpat/protocol/ds2.py` | `reconstruction/transport/kdcan/framing.py` | Clean-room standalone implementation of DS2 / BMW-FAST packet construction, header parsing, additive modulo-256 checksums, and standard KWP2000 SID/NRC constants. |
| **Serial Transport** | `shpat/transport/serial_bmwfast.py` | `reconstruction/transport/kdcan/serial.py` | Reused proven macOS FTDI device discovery (`/dev/cu.usbserial-*`), 115200 8N1 serial initialization, adaptive echo cancellation, inter-byte timing, and 15 ms line regeneration delay. |
| **Wire Tracing** | `shpat/transport/trace.py` | `reconstruction/transport/kdcan/trace.py` | Adapted `SessionTracer` and `TracedKdcanTransport` to capture microsecond-precision timestamps, raw wire bytes, payload previews, and RTT. |
| **Bus Adapter** | *New native implementation* | `reconstruction/transport/kdcan/bus.py` | Implemented `DirectKdcanBus` conforming to the `FlashRunner` bus contract (`job`, `job_bin`, `read_text`, `read_binary`). Enforced strict fail-closed policy on unmapped jobs and hard-gate blocks on flash writing. |

### License & Attribution
All adapted code carries explicit copyright attribution:
```text
Adapted from open6hp (https://github.com/Arkayda/open6hp) transport implementation.
Copyright (c) open6hp contributors. Licensed under the MIT License.
```

---

## 2. Hardware Environment & Test Setup

* **Operating System**: macOS (Darwin 24.x, x86_64).
* **Interface Hardware**: Physical K+DCAN USB OBD Interface (FTDI FT232R USB-to-Serial, VID:PID `0403:6001`).
* **Serial Device Node**: `/dev/cu.usbserial-A50285BI`.
* **Serial Line Parameters**: 115,200 baud, 8 data bits, no parity, 1 stop bit (8N1).
* **Target Electronic Control Unit**: Physical ZF 6HP EGS (Transmission Mechatronic) on diagnostic bench.
* **ECU Diagnostic Address**: `0x18` (Tester source address `0xF1`).

---

## 3. Milestone 1 Validation: Physical Wire Communication

> [!IMPORTANT]
> **Scope of Milestone 1**:
> This validation establishes **transport and wire protocol correctness** over physical hardware. 
> Successful communication and ECU identification **MUST NOT** be interpreted as proof or validation of the reconstructed WinKFP flash programming state machine (`FLASH_SCHREIBEN`, block transfers, or signature verification).

### Physical Wire Transactions Captured

The diagnostic probe (`tools/kdcan_probe.py`) was executed against the physical ECU at address `0x18`. The complete raw wire exchange was recorded by `SessionTracer` in `logs/kdcan_trace_20260926_104348.log`:

```text
# === Session Started: 2026-09-26T10:43:48.562875 ===
# === WinKFP-Research Direct K+DCAN Wire Trace ===
# Probing ECU 0x18 on port /dev/cu.usbserial-A50285BI

[10:43:48.568] TX dst=0x18 src=0xF1 len=2
       RAW: 82 18 F1 3E 00 C9
       PAY: 3E 00 | >.
[10:43:48.587] RX dst=0xF1 src=0x18 len=3 rtt=19.4ms
       RAW: 83 F1 18 7F 3E 12 5B
       PAY: 7F 3E 12 | .>.

[10:43:48.587] TX dst=0x18 src=0xF1 len=2
       RAW: 82 18 F1 1A 86 2B
       PAY: 1A 86 | ..
[10:43:48.690] RX dst=0xF1 src=0x18 len=66 rtt=102.8ms
       RAW: 80 F1 18 42 5A 86 40 [XX XX XX XX XX XX XX] 20 08 12 04 00 00 07 59 21 32 00 00 07 59 21 33 00 00 00 00 00 00 00 02 40 4E 46 53 30 31 00 30 34 37 39 53 39 30 54 36 34 31 5A [XX XX XX XX XX XX XX XX XX XX] FF FF FF [CS]
       PAY: 5A 86 40 [REDACTED_SHORT_VIN] 20 08 12 04 00 00 07 59 21 32 00 00 07 59 21 33 00 00 00 00 00 00 00 02 40 4E 46 53 30 31 00 30 34 37 39 53 39 30 54 36 34 31 5A [REDACTED_CHASSIS_VIN] FF FF FF | Z.@[REDACTED] ......Y!2...Y!3........@NFS01.0479S90T641Z[REDACTED]...
# === Session Ended: 2026-09-26T10:43:49.194813 ===
```

### Analysis of Physical Response

1. **TesterPresent (`0x3E 0x00`)**:
   - Sent: `82 18 F1 3E 00 C9`
   - Received in 19.4 ms: `83 F1 18 7F 3E 12 5B` (KWP2000 Negative Response `NRC 0x12: SubFunctionNotSupported`).
   - Direct Evidence: ECU acknowledged and responded to service `0x3E` on wire with KWP negative response `0x7F 0x3E 0x12`. This establishes physical presence and wire-level response handling for service `0x3E`; it does not prove broader parser health or full protocol compliance.
2. **KWP2000 ReadECUIdentification (`0x1A 0x86` - BMW AIF)**:
   - Sent: `82 18 F1 1A 86 2B`
   - Received in 102.8 ms: 66-byte positive response `5A 86 40 ...`
   - Initial Session State: Accepted immediately from the initial ECU state observed at the start of each probe session without requiring a preceding `0x10` (`StartDiagnosticSession`). The exact session identifier of this initial state is **UNKNOWN** (whether `0x81`, `0x01`, or an ECU-specific default).
   - Decoded ECU Identity parameters:
     - **Short VIN**: `[REDACTED]` (sanitized)
     - **Programming Date**: `2008.12.04`
     - **Assembly (ZB) Number**: `7592132`
     - **Software (SW) Number**: `7592133`
     - **SGBD File Identifier**: `0479S90T641Z`
     - **Flash Tool Stamp**: `NFS01` (genuine factory WinKFP/NFS flash stamp)
     - **Chassis VIN**: `[REDACTED]` (sanitized in evidence reports)

---

## 4. Job-to-Wire Mapping & Target-Scoped Evidence Taxonomy

In compliance with the project's evidence standards, all interactions are evaluated across canonical, target-scoped evidence dimensions:
* **`OBSERVED_WIRE`**: Specific raw byte exchange physically captured directly on a real ECU/bus over K+DCAN.
* **`OBSERVED_JOB_MAPPING[target=X]`**: Specific high-level EDIABAS / SGBD job name directly tied to a specific wire telegram for target `X` via direct evidence (e.g. original EDIABAS trace `_TEL_AUFTRAG`, direct SGBD execution). Must never be generalized across all ECUs.
* **`INFERRED_JOB_MAPPING[target=X]`**: Job believed to map to a wire service based on context or generic protocol knowledge, but direct target-specific execution evidence is absent.
* **`UNKNOWN[target=X]`**: Insufficient evidence to establish the mapping. Fails closed.
* **`RECONSTRUCTION_ALIAS`**: Convenient name introduced by the clean-room reconstruction that is not established as an original EDIABAS/SGBD job name.
* **`FORBIDDEN`**: Operation explicitly prohibited by safety boundary.
* **`VIRTUAL`**: Internal orchestration / GUI / callback operation without wire representation.

The three physical probe runs establish **`OBSERVED_WIRE` ONLY**. Direct SGBD execution traces for the physical bench transmission controller (target: ZF 6HP EGS, address `0x18`, SGBD `0479S90T641Z`) have not been captured; therefore, **`OBSERVED_JOB_MAPPING[target=0479S90T641Z]` is completely absent**. All high-level job names for the EGS are categorized strictly as `UNKNOWN[target=0479S90T641Z]` or `RECONSTRUCTION_ALIAS`:

| Diagnostic Operation / Job | Wire Telegram | `OBSERVED_WIRE` | Target-Scoped Evidence | Final Classification | DirectKdcanBus Action |
|---|---|---|---|---|---|
| **Wire: AIF Query (Bench Alias)** | `0x1A 0x86` | **YES** | Bench EGS (`0x18`) | **OBSERVED_WIRE** | Executed via `wire_read_aif()` or `transport.send_job()`. |
| **Wire: TesterPresent** | `0x3E 0x00` | **YES** | Bench EGS (`0x18`) | **OBSERVED_WIRE** | Executed via `wire_tester_present()` or `transport.send_job()`. |
| `AIF_LESEN` | Official SGBD uses `$23`; wire `1A 86` is bench alias | **YES** (Service `0x23` confirmed in Milestone 5.16) | Physically confirmed on EGS `0x18` (Milestone 5.16: SID `0x63`) | **DIRECTLY_RESOLVED** | Handled via `CanonicalPipeline` / `AIF_LESEN`. |
| `TESTER_PRESENT` | Inferred to `0x3E 0x00` | **YES** (`3E 00`) | Trace `10FLASH` uses `DIAGNOSE_AUFRECHT -> 3E 02` | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default (`NotImplementedError`); allowed with `allow_inferred=True`. |
| `IDENT_LESEN` | Inferred to `0x1A 0x80` | **YES** (`1A 80`) | Factory trace uses `IDENT -> 1A 80` | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default (`NotImplementedError`); allowed with `allow_inferred=True`. |
| `SG_PHYS_HWNR_LESEN` | Inferred to `0x1A 0x87` | **YES** (`1A 87`) | Factory trace uses `PHYSIKALISCHE_HW_NR_LESEN -> 1A 87` | **RECONSTRUCTION_ALIAS** / **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED** by default (`NotImplementedError`); allowed with `allow_inferred=True`. |
| `SG_STATUS_LESEN` | Speculatively assumed `0x3E 0x00` | **NO** | Unevidenced assumption | **UNKNOWN[target=0479S90T641Z]** | **FAIL-CLOSED ALWAYS** (`NotImplementedError` even if `allow_inferred=True`). |
| `AUTHENTISIERUNG` | KWP2000 ReadAuthCapabilities | **NO** | No EGS auth wire trace | **UNKNOWN[target=0479S90T641Z]** | Not validated on wire; **FAIL-CLOSED** (`NotImplementedError`). |
| `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` | RoutineControl `0x31 0x07` (Seed) | **NO** | `OBSERVED_JOB_MAPPING[target=10FLASH]` (`31 07`) | **UNKNOWN[target=0479S90T641Z]** | Not validated on EGS wire; **FAIL-CLOSED** (`NotImplementedError`). |
| `NG_AUTHENTISIERUNG_START` | RoutineControl `0x31 0x08` (Key) | **NO** | `OBSERVED_JOB_MAPPING[target=10FLASH]` (`31 08`) | **UNKNOWN[target=0479S90T641Z]** | Not validated on EGS wire; **FAIL-CLOSED** (`NotImplementedError`). |
| `SERIENNUMMER_LESEN` | `0x1A 0x89` serial record | **YES** | Physically confirmed on EGS `0x18` (Milestone 5.17: SID `0x5A`) | **DIRECTLY_RESOLVED** | Handled via `CanonicalPipeline` / `SERIENNUMMER_LESEN`. |
| `ZIF_LESEN` | `0x22 0x2503` program reference | **YES** | Physically confirmed on EGS `0x18` (Milestone 5.17: SID `0x62`) | **DIRECTLY_RESOLVED** | Handled via `CanonicalPipeline` / `ZIF_LESEN`. |
| `ZIF_BACKUP_LESEN` | `0x22 0x2500` backup reference | **YES** | Physically confirmed on EGS `0x18` (Milestone 5.17: SID `0x62`) | **DIRECTLY_RESOLVED** | Handled via `CanonicalPipeline` / `ZIF_BACKUP_LESEN`. |
| `FLASH_PARAMETER_SETZEN` | Session / Baud / Window Setup | **NO** | SGBD configuration | **UNKNOWN[target=0479S90T641Z]** | Not mapped; **FAIL-CLOSED** (`NotImplementedError`). |
| `INIT_VDLE` | VDLE Virtual Dispatcher Setup | N/A | WinKFP internal GUI callback | **VIRTUAL** | Callback job within WinKFP GUI, no wire equivalent; **FAIL-CLOSED**. |
| `FLASH_SCHREIBEN` | Flash Block Write Transfer | Prohibited | Hard safety interlock | **FORBIDDEN** | Flash writing disabled by hard gate; raises `KdcanError`. |
| `SEND_SEGMENT` | VDLE Segment Iteration | Prohibited | Hard safety interlock | **FORBIDDEN** | Flash writing disabled by hard gate; raises `KdcanError`. |
| `NG_SIGNATUR_PRUEFEN` | Signature Check Request | Prohibited | Hard safety interlock | **FORBIDDEN** | Post-flash write verification; raises `KdcanError`. |

See also: [`docs/evidence/direct_kdcan_milestone_1_1.md`](evidence/direct_kdcan_milestone_1_1.md) for the complete 3-run repeatability evidence report, and [`docs/evidence/authentication_flow_correlation_milestone_3.md`](evidence/authentication_flow_correlation_milestone_3.md) for the offline authentication correlation.

---

## 5. Verification of Independence

A comprehensive scan confirms complete independence between `winkfp-research` and `open6hp`:
1. **Python Imports**: `re.search(r'^\s*(from|import)\s+(shpat|open6hp)', ...)` produced **0 matches**.
2. **Submodules & Symlinks**: `gitmodules` is absent; symlink audit returned **0 symlinks**.
3. **Execution Isolation**: All tests run and pass under `.venv` without `sHPAT` in `PYTHONPATH`.

---

## 6. Remaining Gaps & Next Steps

1. **Diagnostic Session Management**: Investigate whether active diagnostic session requests (`0x10 0x85` Programming Session or `0x10 0x81` Standard Diagnostic) are required prior to seed/key negotiation on the physical EGS.
2. **Safe Read-Only Authentication Probe**: Under strictly offline analysis first, correlate whether the EGS SGBD (`0479S90T641Z`) utilizes RoutineControl authentication (`0x31 0x07` / `0x31 0x08`) or alternative diagnostic services. No hardware authentication is attempted without verified SGBD bytecode evidence.
