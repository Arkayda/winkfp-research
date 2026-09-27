# Milestone 5.12 — Read-Only Diagnostic Transport Integration: Offline-First Runtime Boundary

**Document Status**: Official Architecture & Evidence Delivery  
**Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)  
**Target Address**: `0x18` (Physical EGS) / `0x78` (Factory Trace)  
**Safety Gate**: **STRICTLY OFF-HARDWARE** (Zero serial port opens, zero live ECU communication, zero diagnostic transmissions)  
**Execution Environment**: Pure Python / Virtual Environment (`.venv`)  

---

## 1. Executive Summary & Safety Guarantees

Milestone 5.12 introduces a formal, clean, and decoupled transport abstraction (`DiagnosticTransport`) between the canonical GKE195/10FLASH job pipeline and communication backends.

The architecture established in this milestone guarantees:
1. **Strict Offline Decoupling**: The runtime job layer (`CanonicalPipeline` and `EdiabasJobReplayEngine`) depends exclusively on a pure byte-level contract (`DiagnosticTransport.transceive_ds2`), without importing, initializing, or calling any serial drivers or live hardware mechanisms.
2. **Zero Serial / ECU Hardware Access**: Port `/dev/cu.usbserial-A50285BI` was **never opened**. No serial connections were initialized. Zero frames were transmitted over vehicle or bench buses.
3. **Physical Serial Isolation**: `SerialKdcanTransport` remains strictly isolated in `reconstruction.transport.kdcan.serial`. It was neither imported nor instantiated by the replay or pipeline layers.
4. **Immutable Physical Fixtures**: All canonical hardware traces under `traces/hardware/*.json` remain untouched, with verified SHA-256 cryptographic digests.
5. **Read-Only Whitelist**: All diagnostic routines are restricted strictly to read-only identification queries. Write/flash/reset services (`0x10`, `0x27`, `0x31`, `0x11`, `0x34`, `0x36`) are blocked fail-closed before any dispatch.

---

## 2. Architectural Boundary & Execution Flow

### 2.1 The Unified 6-Stage Execution Architecture

```
+-------------------------------------------------------------------------+
|                        EDIABAS Job API Layer                            |
|             (execute_job / EdiabasJobReplayEngine)                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 1: SGBD Job Definition & Catalog                 |
|                (SgbdJobDefinition, 10FLASH.prg Semantics)               |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 2: Canonical Request Builder                     |
|           (build_request -> Canonical DS2 Wire Request Frame)           |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|              Stage 3: Diagnostic Transport Boundary                     |
|        transceive_ds2(wire_frame: bytes, timeout: float) -> bytes       |
|    [FixtureTransport (Immutable Traces) | MockTransport (Synthetic)]    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 4: Fail-Closed Response Validator                |
|      (Format Byte, Length, Addressing, Checksum, Expected SID/SubID)    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 5: SGBD Semantic Parser                          |
|         (decode_10flash_* -> Typed Fields, Structured Dict)             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Stage 6: Provenanced EdiabasJobResult                  |
|    (Fields, Status, EvidenceDomain, Target/Tester Provenance, Axes)     |
+-------------------------------------------------------------------------+
```

### 2.2 Transport Protocol Contract

The `DiagnosticTransport` contract in `reconstruction/ediabas/transport.py` is defined as a pure byte-level Python Protocol:

```python
class DiagnosticTransport(Protocol):
    """Pure byte-level transport protocol for DS2 diagnostic communication."""

    def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes:
        """Transmit a canonical DS2 wire frame and receive the raw DS2 response frame.

        Args:
            wire_frame: Complete physical DS2 request frame (including trailing checksum).
            timeout: Response timeout in seconds.

        Returns:
            Complete physical DS2 wire response frame (including trailing checksum).

        Raises:
            TransportTimeoutError: If no response is received within timeout.
            TransportError: On lower-level transport communication failure.
        """
        ...
```

### 2.3 Strict Separation of Concerns

Under this protocol boundary:
- **`DiagnosticTransport` knows NOTHING about**:
  - WinKFP or EDIABAS job concepts (`IDENT`, `AIF_LESEN`, `ZIF_LESEN`, etc.).
  - SGBD result fields or parsing dictionaries.
  - Evidence classifications (`DIRECTLY_RESOLVED`, `OBSERVED_WIRE`, etc.) or evidence domains (`FACTORY_TRACE`, `PHYSICAL_EGS_FIXTURE`).
- **`DiagnosticTransport` ONLY handles**:
  - Ingress: Valid canonical physical DS2 wire request frames (`bytes`).
  - Egress: Raw physical DS2 wire response frames (`bytes`), or transport-level exceptions (`TransportTimeoutError`, `TransportError`).

---

## 3. Offline Transport Implementations

Two authoritative offline transport implementations have been built and verified:

### 3.1 `FixtureTransport`
Replays canonical stored responses from immutable files or fixtures.
- Accepts `TraceFixture` objects, file paths to `.json` traces, raw hex strings, byte buffers, or trace dictionaries.
- Supports `strict_tx_match=True` to enforce that the outgoing request generated by the pipeline bit-for-bit matches the recorded request in the trace.
- Records an audit trail of all transmitted requests in `transport.history`.
- Retains fixture provenance metadata in `transport.source_name`.

### 3.2 `MockTransport`
Provides deterministic, synthetic behavior for rigorous unit testing and fail-closed validation:
- Request-to-response mapping table (`responses: Dict[bytes, bytes]`).
- Default fallback response (`default_response: Optional[bytes]`).
- Dynamic request handler callback (`handler: Optional[Callable[[bytes], bytes]]`).
- Configurable timeout injection (`always_timeout: bool` or `timeout_requests: Set[bytes]`).
- Configurable lower-level transport error injection (`error: Optional[Exception]`).
- Complete transmission history audit recording `(wire_frame, timeout)`.

---

## 4. Pipeline Integration & Fail-Closed Behavior

`CanonicalPipeline` in `reconstruction/ediabas/pipeline.py` provides `execute_transport()`:

```python
def execute_transport(
    self,
    job_name: str,
    transport: DiagnosticTransport,
    target_address: int = 0x18,
    tester_address: int = 0xF1,
    destination_address: Optional[int] = None,
    source_address: Optional[int] = None,
    timeout: float = 1.0,
    custom_params: Optional[bytes] = None,
    use_fallback: bool = False,
) -> SgbdJobResult:
```

### Fail-Closed Path Handling:

| Error Condition | Pipeline Stage | Result Status | Result Fields | Safety Action |
|:---|:---|:---|:---|:---|
| **Transport Timeout** | Stage 3 (Transport) | `ERROR_TIMEOUT` | `{}` | No crash, fail-closed, error message recorded |
| **Transport Bus Error** | Stage 3 (Transport) | `ERROR_TRANSPORT` | `{}` | Clean capture of `TransportError` |
| **Invalid Format Byte** | Stage 4 (Validator) | `ERROR_DS2_FRAMING` | `{}` | Rejects invalid format byte (`!(0x80 \| len)`) |
| **Frame Length Mismatch** | Stage 4 (Validator) | `ERROR_DS2_FRAMING` | `{}` | Rejects truncated or padded frame |
| **Checksum Error** | Stage 4 (Validator) | `ERROR_DS2_CHECKSUM` | `{}` | Rejects frame with invalid XOR sum |
| **Addressing Mismatch** | Stage 4 (Validator) | `ERROR_DS2_ADDRESSING` | `{}` | Rejects wrong `dst` (tester) or `src` (ECU) |
| **Unexpected SID** | Stage 4 (Validator) | `ERROR_ECU_INCORRECT_RESPONSE_ID` | `{}` | Rejects mismatch against `expected_response_sid` |
| **Wrong Subfunction** | Stage 4 (Validator) | `ERROR_ECU_INCORRECT_SUBID` | `{}` | Rejects mismatch against `expected_response_subfunction` |
| **Negative Response** | Stage 4 (Validator) | `ERROR_ECU_NEGATIVE_RESPONSE_0x<NRC>` | `{}` | Decodes NRC without parsing data fields |
| **Unsupported Job** | Stage 1 (Job Definition) | `ERROR_JOB_UNSUPPORTED` / `NotImplementedError` | `{}` | **Blocked before dispatch**: 0 bytes sent |

---

## 5. Provenance & Evidence Domain Independence

Milestone 5.12 preserves the strict separation of evidence domains established across Milestones 5.10.1 and 5.10.2:

1. **`PHYSICAL_EGS_FIXTURE`**:
   - Canonical target address: `0x18`.
   - Tester address: `0xF1`.
   - Verified against physical hardware trace fixtures.
2. **`FACTORY_TRACE`**:
   - Canonical target address: `0x78`.
   - Tester address: `0xF1`.
   - Verified against `traces/sanitized/sanitized_flash_session.trc`.
   - Replay engine strictly forbids rewriting target to `0x18` or confusing factory traces with EGS execution.
3. **`SYNTHETIC_OFFLINE`**:
   - Used for mock transports and synthetic test vectors.
   - Target address defaults to `0x18` or explicitly specified.

The four canonical evidence axes remain strictly governed by the job definition catalog and evidence domain, untouched by the transport layer:
- `sgbd_supported`: Supported in `10FLASH.prg`.
- `factory_trace_observed`: Present in historical factory session trace.
- `physical_trace_exists`: Validated on physical bench trace.
- `directly_resolved`: Verified direct identification routine.

---

## 6. Verification & Test Evidence

### 6.1 Dedicated Test Suite (`tests/golden/ediabas/test_diagnostic_transport.py`)

A 12-test comprehensive suite was created and validated:

| Test ID | Test Name | Execution Path | Validation Focus | Status |
|:---|:---|:---|:---|:---:|
| `test_01` | `test_01_ident_via_fixture_transport` | `FixtureTransport` (`egs_ident.json`) | Physical `1A 80`, fields match, history records TX `82 18 F1 1A 80 25` | **PASSED** |
| `test_02` | `test_02_phys_hwnr_via_fixture_transport` | `FixtureTransport` (`egs_physical_hw_nr.json`) | Physical `1A 87`, HW NR `7569980`, TX `82 18 F1 1A 87 2C` | **PASSED** |
| `test_03` | `test_03_synthetic_mock_transport` | `MockTransport` (`ZIF_LESEN`) | PRGREF `0479S90T641Z`, status `OKAY`, timeout recorded | **PASSED** |
| `test_04` | `test_04_transport_timeout_handling` | `MockTransport(always_timeout=True)` | Catches timeout fail-closed, status `ERROR_TIMEOUT`, no crash | **PASSED** |
| `test_05` | `test_05_malformed_ds2_framing` | `MockTransport` (corrupted format) | Rejects format byte 0x42 with `ERROR_DS2_FRAMING` | **PASSED** |
| `test_06` | `test_06_checksum_failure` | `MockTransport` (corrupted checksum) | Rejects bad checksum with `ERROR_DS2_CHECKSUM` | **PASSED** |
| `test_07` | `test_07_addressing_mismatch` | `MockTransport` (dst=0x12) | Rejects incorrect destination with `ERROR_DS2_ADDRESSING` | **PASSED** |
| `test_08` | `test_08_wrong_response_sid` | `MockTransport` (SID=0x50) | Rejects unexpected SID with `ERROR_ECU_INCORRECT_RESPONSE_ID` | **PASSED** |
| `test_09` | `test_09_negative_ecu_response` | `MockTransport` (`7F 1A 12`) | Decodes NRC 0x12 with `ERROR_ECU_NEGATIVE_RESPONSE_0x12` | **PASSED** |
| `test_10` | `test_10_unsupported_job_rejection` | `MockTransport` (`FLASH_PROGRAMMIEREN`) | Blocked before transport; zero frames transmitted (`len(history) == 0`) | **PASSED** |
| `test_11` | `test_11_evidence_axis_preservation` | `FixtureTransport` & `MockTransport` | Evidence axes preserved; mock does not claim physical evidence | **PASSED** |
| `test_12` | `test_12_proof_of_zero_physical_transport` | Architecture check | `SerialKdcanTransport` not imported/used; zero serial leaks | **PASSED** |

### 6.2 Full Project Regression Test Run

Executed: `.venv/bin/python3 tests/run_tests.py`

```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  74 run,  74 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 153 tests in 4.303s | 153 passed | 0 skipped | 0 failed
======================================================================
```

### 6.3 Cryptographic Integrity of Physical Trace Fixtures

All hardware trace files retain their exact baseline SHA-256 hashes:

```text
f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d  traces/hardware/20260926_173201_egs_aif.json
cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791  traces/hardware/20260926_174033_egs_tester_present.json
4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462  traces/hardware/20260926_174811_egs_ident.json
6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15  traces/hardware/20260926_175924_egs_physical_hw_nr.json
```

---

## 7. Architectural Status & Next Steps

Milestone 5.12 completes the off-hardware diagnostic transport boundary. The system now features a clean, decoupled execution architecture ready for future runtime integration, while maintaining full safety guarantees and fail-closed integrity.
