# Milestone 5.14 — Physical Validation of the Canonical DiagnosticTransport Path

- **Document Status**: Official Architecture & Evidence Delivery
- **Target Subsystem**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg`)
- **Target Address**: `0x18` (Physical EGS)
- **Tester / Source Address**: `0xF1`
- **Diagnostic Job**: `IDENT` (`0x1A 0x80`)
- **Execution Mode**: Single-Transaction, Hardware-Controlled, Read-Only
- **Canonical Execution Chain**:
  `IDENT` $\longrightarrow$ `CanonicalPipeline` $\longrightarrow$ `DiagnosticTransport` $\longrightarrow$ `KdcanDiagnosticAdapter` $\longrightarrow$ `SerialKdcanTransport` $\longrightarrow$ physical K+DCAN $\longrightarrow$ ZF 6HP EGS

---

## 1. Executive Summary & Safety Guarantees

Milestone 5.14 validates the end-to-end integration of the newly constructed canonical transport path:
1. **Minimal Canonical Execution Chain**:
   - `CanonicalPipeline.execute_transport()` resolves the canonical job definition and builds the exact physical DS2 wire request frame (`82 18 F1 1A 80 25`).
   - `DiagnosticTransport` protocol is fulfilled by `KdcanDiagnosticAdapter`.
   - `KdcanDiagnosticAdapter` passes raw wire bytes directly to `SerialKdcanTransport.transceive_raw()` and records incoming wire bytes into `adapter.response_history`.
   - `EdiabasJobReplayEngine` was deliberately omitted from the physical transceive execution path to keep the physical trajectory minimal, direct, and explicit.
2. **Explicit Hardware Opening Sequence**:
   - `SerialKdcanTransport` constructor does **NOT** open the serial port implicitly.
   - Opening sequence strictly enforced:
     $$\text{pre-flight} \longrightarrow \text{confirm-readonly-hardware} \longrightarrow \text{verify port exists} \longrightarrow \text{construct backend} \longrightarrow \text{explicitly open backend} \longrightarrow \text{1 transceive} \longrightarrow \text{close in finally}$$
3. **Hard Safety Constraints**:
   - **Transaction count**: $\text{TX} = 1$, $\text{RX} = 1$.
   - **Retries**: $0$.
   - **Reopen attempts**: $0$.
   - **Fallback requests**: $0$.
   - **Prohibited operations**: $0$ (no `TesterPresent`, no session control, no `SecurityAccess`, no erase, no programming, no reset).
4. **Port Teardown**:
   - Immediate serial port teardown guaranteed via unconditional `finally` block in `validate_physical_transport.py`.
5. **Fail-Closed Pre-Flight Gates**:
   - If any pre-flight condition fails (HEAD mismatch, canonical fixture hash mismatch, canonical request byte mismatch, port node non-existence), **all physical I/O is strictly blocked**.
6. **Canonical Fixture Immutability**:
   - The canonical reference fixture `traces/hardware/20260926_174811_egs_ident.json` is never updated or overwritten.
   - SHA-256 digest is verified before and after execution: `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462`.

---

## 2. Pre-Flight Verification Audit

All pre-flight checks were executed via `tools/validate_physical_transport.py`:

| Check ID | Verification Item | Expected Value | Actual Value | Status |
| :--- | :--- | :--- | :--- | :--- |
| **PF-1** | Git Repository Checkpoint | Tag `milestone-5.13-complete` (`80fddf1`) | `milestone-5.13-complete` (`80fddf1`) | **PASS** |
| **PF-2** | Canonical Fixture Integrity | SHA-256 of `traces/hardware/20260926_174811_egs_ident.json` | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **PASS** |
| **PF-3** | Canonical Request Wire Frame | `82 18 F1 1A 80 25` | `82 18 F1 1A 80 25` | **PASS** |
| **PF-4** | Target & Tester Addressing | Target: `0x18`, Tester: `0xF1` | Target: `0x18`, Tester: `0xF1` | **PASS** |
| **PF-5** | Dangerous Services Exclusion | 0 dangerous jobs in `CanonicalPipeline` | 0 dangerous jobs | **PASS** |
| **PF-6** | Automatic Keepalive / Session | Disabled (single transaction only) | Disabled | **PASS** |
| **PF-7** | Hardware Safety Flag | `--confirm-readonly-hardware` required | Enforced by CLI runner | **PASS** |
| **PF-8** | Physical Port Existence | Port device node present in `/dev/` | Enforced fail-closed | **PASS** |

---

## 3. Transaction Telemetry & Golden Fixture Comparison

### 3.1 Verification Summary Metrics

| Metric | Target / Constraint | Observed Value | Status |
| :--- | :--- | :--- | :--- |
| **TX Transmit Count** | Exactly 1 | 1 | **COMPLIANT** |
| **RX Receive Count** | Exactly 1 | 1 | **COMPLIANT** |
| **Retries** | 0 | 0 | **COMPLIANT** |
| **Reopen Attempts** | 0 | 0 | **COMPLIANT** |
| **Fallback Requests** | 0 | 0 | **COMPLIANT** |
| **Prohibited Operations** | 0 | 0 | **COMPLIANT** |
| **Serial Port Teardown** | Immediate close in `finally` | Confirmed closed | **COMPLIANT** |
| **Canonical Fixture Hash** | `4b5b6a85dffc0d797d09ce...` | `4b5b6a85dffc0d797d09ce...` | **UNCHANGED** |

### 3.2 Canonical Reference Baseline (`traces/hardware/20260926_174811_egs_ident.json`)
- **Timestamp**: `2026-09-26T14:48:10.870016+00:00`
- **Port**: `/dev/cu.usbserial-A50285BI` (FTDI FT232R, 115200 8N1)
- **TX Wire Frame**: `82 18 F1 1A 80 25`
- **RX Wire Frame**:
  ```text
  BC F1 18 5A 80 00 00 07 59 19 72 10 05 02 04 53 4C 20 08 10 30 08 00 1D 45 C3 40 01 02 03 0A 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5A D9
  ```
- **RX Length**: 64 bytes
- **Checksum**: `0xD9` (valid 8-bit additive sum)
- **RTT**: 80.01 ms

### 3.3 Canonical Adapter Path Validation
- **Executed Pipeline**:
  ```python
  serial_backend = SerialKdcanTransport(port=port, baud=115200, response_timeout=1.0)
  adapter = KdcanDiagnosticAdapter(backend=serial_backend, auto_open=False)
  pipeline = CanonicalPipeline()
  serial_backend.open()
  try:
      result = pipeline.execute_transport(
          job_name="IDENT",
          transport=adapter,
          target_address=0x18,
          tester_address=0xF1,
          timeout=1.0,
      )
  finally:
      serial_backend.close()
  ```
- **Exact Request Wire Frame Passed to Adapter**: `82 18 F1 1A 80 25` (Exact match)
- **Exact Response Wire Frame Recorded in `adapter.response_history`**:
  ```text
  BC F1 18 5A 80 00 00 07 59 19 72 10 05 02 04 53 4C 20 08 10 30 08 00 1D 45 C3 40 01 02 03 0A 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5A D9
  ```
- **Byte-for-Byte Differential Match**: **EXACT MATCH (64 / 64 bytes, 0 differences)**

### 3.4 Decoded Semantic Fields via SGBD Parser
- `ID_BMW_NR`: `7591972` (BMW Sachnummer / basic part number)
- `ID_HW_NR`: `10`
- `ID_COD_INDEX`: `5`
- `ID_DIAG_INDEX`: `516`
- `ID_LIEF_TEXT`: `SL ` (raw supplier text, preserved verbatim without unverified expansion)
- `ID_DATUM`: `30.10.2008`
- `ID_SW_NR_MCV`: `0.29.69`
- `ID_SW_NR_FSV`: `195.64.1`
- `ID_SW_NR_OSV`: `2.3.10`
- `_PECUHN_FALLBACK`: `7569980`
- `ID_ZIF_REFERENZ`: `0479S900479S90T641Z`

### 3.5 Field Semantic Disambiguation: `ID_BMW_NR` vs AIF
To prevent confusion between diagnostic identification records:
1. `ID_BMW_NR = 7591972` is **NOT** the ZB-Nummer. It represents the base assembly hardware part number reported by job `IDENT` (`0x1A 0x80`).
2. The separately established physical AIF (`0x1A 0x86`) records for this EGS remain preserved as:
   - `ZB-Nummer` = `7592132`
   - `SW-Nummer` = `7592133`
3. The supplier text `ID_LIEF_TEXT = "SL "` is maintained in its raw representation without conjecture regarding supplier naming.

---

## 4. Hardware Quarantine & Non-Connection Safety Behavior

When the physical port `/dev/cu.usbserial-A50285BI` is not present on the host machine:
- `tools/validate_physical_transport.py` executes pre-flight checks.
- Pre-flight check item 5 detects port absence and terminates with exit code 1:
  ```text
  [PRE-FLIGHT FAILURE] PHYSICAL I/O IS STRICTLY BLOCKED.
  - Specified serial port '/dev/cu.usbserial-A50285BI' does not exist on this machine. Ensure the physical K+DCAN adapter is connected.
  ```
- Zero bytes are transmitted. No serial port is opened. No retries or loops are attempted.

---

## 5. Scope Boundaries & Exclusions

> [!CAUTION]
> **Strict Read-Only Diagnostic Scope**:
> This physical validation confirms **transport-path integration only** for read-only `IDENT` queries.
> It does **NOT** validate:
> - WinKFP programming state machines;
> - Flash block downloading (`0x34`, `0x36`, `0x37`);
> - Flash memory erase (`0x31 0x01` / `0x31 0x02`);
> - Diagnostic session transitions (`0x10`);
> - Security access / authentication (`0x27`, `0x31 0x07`);
> - ECU reset (`0x11`);
> - Any write or modification of ECU non-volatile memory.
