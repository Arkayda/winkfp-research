# Milestone 5.13 — K+DCAN DiagnosticTransport Adapter: Offline-Validated, Hardware-Quarantined

- **Document Status**: Official Architecture & Evidence Delivery
- **Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)
- **Target Address**: `0x18` (Physical EGS) / `0x78` (Factory Trace)
- **Safety Gate**: **STRICTLY OFF-HARDWARE** (Zero serial port opens, zero live ECU communication, zero diagnostic transmissions)
- **Execution Environment**: Pure Python / Virtual Environment (`.venv`)

---

## 1. Executive Summary & Safety Guarantees

Milestone 5.13 establishes the formal bridge between the low-level native K+DCAN transport implementation (`reconstruction.transport.kdcan`) and the canonical byte-level diagnostic transport contract (`reconstruction.ediabas.transport.DiagnosticTransport`).

The architecture implemented and validated in this milestone guarantees:
1. **Strict Hardware Quarantine**:
   - Zero physical serial port opening: port `/dev/cu.usbserial-A50285BI` was **never opened**.
   - Zero live ECU access: no bench or vehicle diagnostic frames were transmitted.
   - `auto_open: bool = False` by default: the adapter does NOT automatically call `backend.open()` during transceive operations unless explicitly requested.
   - `SerialKdcanTransport` was **never instantiated** during test execution or validation.
2. **Pure Byte-Level Protocol Boundary**:
   - The adapter (`KdcanDiagnosticAdapter`) implements:
     ```python
     transceive_ds2(wire_frame: bytes, timeout: float = 1.0) -> bytes
     ```
   - It is strictly job-agnostic and SGBD-agnostic: it has no knowledge of WinKFP jobs (`IDENT`, `AIF_LESEN`, `ZIF_LESEN`), SGBD bytecode routines, evidence domains, or dangerous service IDs.
   - It transmits raw DS2 wire frame bytes directly to the backend primitive and returns the raw response wire frame bytes without re-encoding.
3. **Upstream Safety Rejection**:
   - Dangerous or unsupported jobs (e.g. `FLASH_PROGRAMMIEREN`) are rejected strictly upstream by the canonical job layer (`CanonicalPipeline` and `EdiabasJobReplayEngine`).
   - Verified by automated tests: when an unsupported job is requested, `adapter.transceive_ds2()` is **never reached** (`history` length remains 0).
4. **Offline Deterministic Verification**:
   - A dedicated offline backend (`ScriptedKdcanBackend`) provides deterministic in-memory wire simulation without hardware dependencies.
   - All 15 adapter golden test scenarios pass.
   - Master verification suite: 168 tests pass, 0 fail, 0 skipped.
5. **Cryptographic Trace Integrity**:
   - All canonical physical hardware traces (`traces/hardware/*.json`) remain unmodified with verified SHA-256 checksums matching the frozen baseline.

---

## 2. Architecture & Protocol Layering

### 2.1 Layered Architecture Overview

```
+-------------------------------------------------------------------------+
|                        EDIABAS Job API Layer                            |
|             (execute_job / EdiabasJobReplayEngine)                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 1 & 2: Canonical GKE195 Pipeline                 |
|             (Catalog resolution & Canonical DS2 Request Builder)        |
+-------------------------------------------------------------------------+
                                    |
                                    | canonical DS2 wire request (bytes)
                                    v
+=========================================================================+
|             DiagnosticTransport Protocol Boundary                       |
|   KdcanDiagnosticAdapter.transceive_ds2(wire_frame, timeout) -> bytes   |
+=========================================================================+
                                    |
                                    | raw wire_frame (bytes, unchanged)
                                    v
+-------------------------------------------------------------------------+
|                    K+DCAN Transport Primitive                           |
|             KdcanTransport.transceive_raw(wire_frame, timeout)          |
|  - ScriptedKdcanBackend (Offline Deterministic Simulation)              |
|  - TracedKdcanTransport (Wire Logging Wrapper)                          |
|  - SerialKdcanTransport (Hardware-Quarantined Physical Driver)          |
+-------------------------------------------------------------------------+
                                    |
                                    | raw wire_response (bytes, unchanged)
                                    v
+=========================================================================+
|             DiagnosticTransport Protocol Boundary                       |
|                 (Returns raw wire response bytes)                       |
+=========================================================================+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 4: Fail-Closed Response Validator                |
|      (Format Byte, Length, Addressing, Checksum, Expected SID/SubID)    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 5: SGBD Semantic Field Parser                    |
|           (Decodes typed telemetry into EdiabasJobResult)               |
+-------------------------------------------------------------------------+
```

### 2.2 Component Specifications

#### 1. `KdcanDiagnosticAdapter` (`reconstruction/transport/kdcan/adapter.py`)
- Conforms to `@runtime_checkable` `DiagnosticTransport` protocol.
- Signature:
  ```python
  class KdcanDiagnosticAdapter:
      def __init__(self, backend: KdcanTransport, auto_open: bool = False) -> None: ...
      def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes: ...
  ```
- **Guarantees**:
  - Receives `wire_frame: bytes` and sends it unmodified to `backend.transceive_raw(wire_frame, timeout=timeout)`.
  - Records exact wire history in `self.history: List[Tuple[bytes, float]]`.
  - Translates timeout exceptions to `TransportTimeoutError`.
  - Translates transport/communication exceptions to `TransportError`.
  - Does NOT inspect, modify, or validate DS2 framing or SGBD job logic (strict separation of concerns).

#### 2. `ScriptedKdcanBackend` (`reconstruction/transport/kdcan/adapter.py`)
- Concrete offline subclass of `KdcanTransport`.
- Implements `open()`, `close()`, `transceive_raw()`, and `send_job()`.
- Supports deterministic request-to-response wire mappings (`responses: Dict[bytes, bytes]`), synthetic timeout errors (`timeout_error: bool`), and bus error simulation (`bus_error: Exception`).
- Operates completely in memory with zero OS hardware driver calls.

#### 3. Direct Wire Primitive `transceive_raw` (`base.py`, `serial.py`, `trace.py`)
- `KdcanTransport.transceive_raw(wire_frame: bytes, timeout: Optional[float] = None) -> bytes`:
  - Abstract base primitive ensuring exact wire bytes reach the physical or mock backend without implicit re-encoding or re-framing.
- `TracedKdcanTransport.transceive_raw`:
  - Logs TX and RX telegrams in human-readable and raw hexdump formats, forwarding the exact frame to the inner backend.
- `SerialKdcanTransport.transceive_raw`:
  - Implements direct UART transmit/receive of raw wire bytes, handling cable echo detection without re-framing payload data (quarantined in offline mode).

---

## 3. Exception Translation Specification

| Low-Level Origin Exception | Adapter Translation | Upstream Pipeline Status |
| :--- | :--- | :--- |
| `TimeoutError` | `TransportTimeoutError` | `ERROR_TIMEOUT` |
| `KdcanError` (containing `"timeout"`) | `TransportTimeoutError` | `ERROR_TIMEOUT` |
| `KdcanError` (bus / frame / device error) | `TransportError` | `ERROR_TRANSPORT` |
| `IOError` / `OSError` (device disconnected) | `TransportError` | `ERROR_TRANSPORT` |
| `TransportTimeoutError` (existing) | Re-raised as-is | `ERROR_TIMEOUT` |
| `TransportError` (existing) | Re-raised as-is | `ERROR_TRANSPORT` |

---

## 4. Verification Evidence & Test Execution

### 4.1 Golden Test Suite: `tests/golden/transport/test_kdcan_diagnostic_adapter.py`

| Test ID | Test Scenario | Verified Behavior | Status |
| :--- | :--- | :--- | :--- |
| `test_01` | Protocol Compliance | Conforms to `DiagnosticTransport` Protocol (`isinstance == True`). | **PASS** |
| `test_02` | Byte-for-Byte TX Pass-Through | Exact wire frame bytes (`82 18 F1 1A 80 25`) delivered to backend. | **PASS** |
| `test_03` | Byte-for-Byte RX Pass-Through | Exact wire response bytes returned from adapter without alteration. | **PASS** |
| `test_04` | Timeout Translation | Backend timeout converted to `TransportTimeoutError`. | **PASS** |
| `test_05` | Bus Error Translation | `KdcanError("Corrupted frame")` converted to `TransportError`. | **PASS** |
| `test_06` | Generic Exception Translation | `IOError("USB device disconnected")` converted to `TransportError`. | **PASS** |
| `test_07` | Timeout Parameter Preservation | Timeout float (`3.5s`) correctly forwarded to backend. | **PASS** |
| `test_08` | Arbitrary DS2 Frame Support | Adapter transmits arbitrary DS2 frames without job inspection. | **PASS** |
| `test_09` | Zero SGBD / Job Semantics | Module does NOT import SGBD/job models; adapter has no job fields. | **PASS** |
| `test_10` | Upstream Job Rejection | `FLASH_PROGRAMMIEREN` rejected upstream; adapter history length = 0. | **PASS** |
| `test_11` | CanonicalPipeline Integration | `IDENT` (1A 80) executed through adapter; fields decoded correctly. | **PASS** |
| `test_12` | EdiabasJobReplayEngine Integration | `PHYSIKALISCHE_HW_NR_LESEN` executed through adapter; HW NR matches. | **PASS** |
| `test_13` | Negative ECU Response (NRC 0x12) | Negative response passed through adapter; rejected by validator. | **PASS** |
| `test_14` | auto_open Quarantine | Default `auto_open=False` leaves backend closed; explicit `True` opens it. | **PASS** |
| `test_15` | Zero Physical Serial Access | `SerialKdcanTransport` is never instantiated. | **PASS** |

### 4.2 Full Repository Test Summary

```
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  89 run,  89 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 168 tests in 4.264s | 168 passed | 0 skipped | 0 failed
======================================================================
```

---

## 5. Hardware Trace Integrity (SHA-256 Digests)

All immutable hardware trace files maintain 100% cryptographic integrity:

| Trace File | Verified SHA-256 Digest | Status |
| :--- | :--- | :--- |
| `traces/hardware/20260926_173201_egs_aif.json` | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **UNMODIFIED** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **UNMODIFIED** |
| `traces/hardware/20260926_174811_egs_ident.json` | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **UNMODIFIED** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **UNMODIFIED** |

---

## 6. Known Limitations & Prerequisites for Future Physical Validation

1. **Strict Offline Status**:
   - This milestone is 100% offline. No live serial port was opened or tested against physical hardware.
2. **Serial Hardware Testing Prerequisites**:
   - Before any future physical validation:
     1. Physical K+DCAN USB adapter must be securely connected to the designated test bench.
     2. Explicit port path (e.g. `/dev/cu.usbserial-A50285BI`) must be provided by the operator.
     3. Strict safety confirmation flag (`--confirm-readonly-hardware`) must be supplied.
     4. Transmissions must remain confined strictly to read-only queries (`TESTER_PRESENT`, `IDENT`, `AIF_READ_BENCH_ALIAS`, `PHYSIKALISCHE_HW_NR_LESEN`).
     5. All write/flash/reset operations remain strictly blocked.
