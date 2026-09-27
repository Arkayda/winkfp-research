# Physical TesterPresent Primitive & Factory Trace Correlation (Milestone 5.1)

**Classification**: RESEARCH EVIDENCE REPORT  
**Scope**: Read-Only Diagnostic Validation (`0x3E`) & Factory Trace Forensic Correlation  
**Target ECU**: BMW E60 ZF 6HP EGS (Diagnostic Address: `0x18`, SGBD: `0479S90T641Z`)  
**Safety Gate**: STRICTLY READ-ONLY (No flash, no programming, no session change, no authentication, no reset)  

---

## 1. Physical EGS Wire Observation (`0x3E 0x00`)

### 1.1 Wire Transaction
During physical bench diagnostics on the ZF 6HP EGS transmission controller over native K+DCAN serial transport, the following wire transaction was observed:

```text
TX: 82 18 F1 3E 00 C9
RX: 83 F1 18 7F 3E 12 5B
```

### 1.2 Breakdown of Physical Frames
* **TX Frame (`82 18 F1 3E 00 C9`)**:
  - `0x82`: DS2 Short Header (Payload length: 2 bytes).
  - `0x18`: Destination address (ZF 6HP EGS ECU).
  - `0xF1`: Source address (Diagnostic Tester).
  - `0x3E 0x00`: Service Identifier `0x3E` (TesterPresent) with subfunction `0x00`.
  - `0xC9`: Additive 8-bit checksum (`(0x82 + 0x18 + 0xF1 + 0x3E + 0x00) & 0xFF = 0xC9`).
* **RX Frame (`83 F1 18 7F 3E 12 5B`)**:
  - `0x83`: DS2 Short Header (Payload length: 3 bytes).
  - `0xF1`: Destination address (Diagnostic Tester).
  - `0x18`: Source address (ZF 6HP EGS ECU).
  - `0x7F 0x3E 0x12`: KWP2000 Negative Response:
    - `0x7F`: Negative Response Service ID.
    - `0x3E`: Rejected Service ID (`TesterPresent`).
    - `0x12`: Negative Response Code (`NRC_SUBFUNCTION_NOT_SUPPORTED` / `subFunctionNotSupportedInvalidFormat`).
  - `0x5B`: Additive 8-bit checksum (`(0x83 + 0xF1 + 0x18 + 0x7F + 0x3E + 0x12) & 0xFF = 0x5B`).

### 1.3 Evidence Classification
* **Classification**: **`OBSERVED_WIRE`**
* **Technical Scope**:
  - This wire transaction establishes physical presence and wire-level response handling for service `0x3E 0x00` on the bench EGS.
  - It proves that the physical ECU responds to service `0x3E` with negative response code `0x12`.
* **Explicit Non-Claims**:
  - Does **NOT** prove ECU "health" or parser integrity.
  - Does **NOT** prove session establishment, session transition, or session persistence.
  - Does **NOT** prove that the ECU accepted TesterPresent semantics.
  - Does **NOT** establish any high-level EDIABAS / SGBD / WinKFP job mapping for target `0479S90T641Z`.

---

## 2. Sanitized Factory Trace Observation (`10FLASH` / `0x78`)

### 2.1 Factory Wire Transaction
In the historical sanitized factory trace (`traces/sanitized/sanitized_flash_session.trc`), the keep-alive / diagnostic persistence mechanism was executed as follows:

```text
JOB: DIAGNOSE_AUFRECHT "NEIN;JA"
TX:  C2 EF F1 3E 02
```

### 2.2 Breakdown of Factory Frame
* **Job Name**: `DIAGNOSE_AUFRECHT` (Parameters: `"NEIN;JA"`).
* **Target SGBD**: `10FLASH` (ECU gateway address `0x78`, internal routing `0xEF`).
* **TX Wire Telegram**: `C2 EF F1 3E 02`
  - Framing: K-Line / BMW-FAST formatted telegram.
  - Target: `0xEF` (internal flash address).
  - Source: `0xF1` (Tester).
  - Service: `0x3E` (TesterPresent).
  - Subfunction: `0x02` (suppressPositiveResponse or specific diagnostic session persistence subfunction).

### 2.3 Evidence Classification
* **Classification**: **`OBSERVED_JOB_MAPPING[target=10FLASH]`**
* **Technical Scope**:
  - Direct execution evidence exists correlating the high-level job `DIAGNOSE_AUFRECHT` with wire telegram `C2 EF F1 3E 02` on target `10FLASH`.

---

## 3. Forensic Correlation & Comparison Matrix

| Dimension | Physical EGS Bench | Factory Trace (`10FLASH`) | Correlation Status |
|---|---|---|---|
| **Target ECU** | ZF 6HP EGS (`0x18`) | Flash Gateway / ECU (`0x78` / `0xEF`) | **DIFFERENT TARGET** |
| **SGBD** | `0479S90T641Z` | `10FLASH` | **DIFFERENT SGBD** |
| **Service Family** | KWP2000 `0x3E` | KWP2000 `0x3E` | **COMMON SERVICE FAMILY** |
| **Subfunction Byte** | `0x00` | `0x02` | **DIFFERENT SUBFUNCTION (`3E 00 != 3E 02`)** |
| **Raw Wire Telegram** | `82 18 F1 3E 00 C9` | `C2 EF F1 3E 02 ...` | **DIFFERENT WIRE PACKETS** |
| **Response Observed** | `83 F1 18 7F 3E 12 5B` (NRC 0x12) | Positive ACK / Keep-Alive | **DIFFERENT WIRE BEHAVIOR** |
| **Evidence Class** | **`OBSERVED_WIRE`** | **`OBSERVED_JOB_MAPPING`** | **STRICTLY SEPARATED** |

---

## 4. Analytical Findings & Non-Equivalence

1. **`factory 3E 02 != physical 3E 00`**:
   The factory telegram uses subfunction `0x02`, whereas the physical probe uses `0x00`. They represent distinct protocol requests with different semantics.

2. **No Observed Job Mapping on EGS**:
   `3E 00` is **NOT** an observed factory job mapping for the EGS. SGBD bytecode for `0479S90T641Z` has not been observed emitting `3E 00` under any factory job in this milestone.

3. **Inference Boundary**:
   Any relationship between physical `3E 00` and factory `DIAGNOSE_AUFRECHT -> 3E 02` beyond the documented common KWP2000 service family (`0x3E`) is classified strictly as **`INFERRED`** or **`UNKNOWN`**. Inference must never be conflated with observation.

4. **Fail-Closed Bus Handling**:
   In `reconstruction/transport/kdcan/bus.py`, speculative job mappings (such as `SG_STATUS_LESEN -> 0x3E 0x00`) remain strictly rejected and fail-closed (`NotImplementedError`) per repository evidence policy.
