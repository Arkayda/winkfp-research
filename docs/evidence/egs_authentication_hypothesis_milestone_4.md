# Milestone 4: EGS-Specific Authentication Hypothesis and Physical Probe Pre-Flight
## Forensic Analysis of ZF 6HP EGS (0479S90T641Z / GS19 / 0x18) Authentication Mechanisms and Bench Experiment Design

- **Milestone**: Milestone 4 (EGS-Specific Authentication Hypothesis and Physical Probe Pre-Flight — Corrective Pass)
- **Status**: Complete & Verified (Strictly Off-Hardware)
- **Operational Mode**: **STRICTLY OFF-HARDWARE**
  - Zero communication with physical vehicle or bench hardware.
  - Zero serial ports opened; `tools/kdcan_probe.py` was **NOT** executed.
  - No diagnostic requests transmitted (`0x10`, `0x27`, `0x31`, reset, erase, download, transfer, or flash write).
  - The minimal physical probe specification designed herein is marked **`UNEXECUTED — OPERATOR REVIEW REQUIRED`** and has **NOT** been executed.
- **Target ECU Context**:
  - Reconstructed / Bench Target: ZF 6HP19/26 Mechatronic (E60 EGS)
  - Diagnostic Address: `0x18`
  - SGBD File Identifier: `0479S90T641Z`
  - Diagnostic Protocol: KWP2000 over BMW-FAST / DS2 / K+DCAN (500 kbaud)
  - Physical Identifiers (from verified bench AIF): ZB `7592132`, ZB change `7592133`, VIN `WBANX71040...`
  - SGBD Family: `GS19`
  - SP-Daten Key Container: `SGIDC.as2` (index 3), entry `GKE192` (record `2L18`)
- **Factory Reference Target (Separate Scope)**:
  - Flash Loader: `10FLASH.PRG` targeting `13_ASK` / `IHKA81` at diagnostic address `0x78`

---

## 1. Objective and Evidence Boundary Law

### 1.1 Purpose of Milestone 4
The objective of Milestone 4 is to determine, through rigorous forensic and cryptographic cross-examination of existing repository evidence, whether the E60 SP-Daten files, decompiled WinKFP algorithms, and observed physical traces support a concrete, target-specific hypothesis for the authentication flow of:
- **ECU**: ZF 6HP EGS mechatronic
- **Address**: `0x18`
- **SGBD**: `0479S90T641Z`

The immediate goal is **NOT** to authenticate the ECU or attempt any privileged operation. The goal is to establish:
1. What is rigorously known;
2. What is only inferred by analogy;
3. What remains completely unknown;
4. What exact, minimal physical experiment would discriminate between competing hypotheses.

### 1.2 Canonical Evidence Taxonomy
To avoid conflating disparate evidence domains, all findings in this milestone are classified according to the canonical taxonomy:
* **`OBSERVED_WIRE`**: Specific raw byte exchange physically captured and verified directly on bench hardware over K+DCAN (e.g. `0x1A 0x86` returning 66 bytes on address `0x18`). Proves wire behavior only, not SGBD job provenance.
* **`OBSERVED_JOB_MAPPING[target=X]`**: Specific high-level EDIABAS / SGBD job name directly tied to a specific wire telegram for target `X` via direct evidence (e.g. original EDIABAS trace `_TEL_AUFTRAG` or direct SGBD execution). Must never be generalized across other ECUs.
* **`INFERRED_JOB_MAPPING[target=X]`**: Job believed to map to a wire service based on context or generic protocol knowledge, but direct target-specific execution evidence is absent. Fails closed.
* **`UNKNOWN[target=X]`**: Insufficient evidence to establish the mapping. Fails closed unconditionally.
* **`RECONSTRUCTION_ALIAS`**: Convenient name introduced by clean-room reconstruction that is not established as an original EDIABAS/SGBD job name (e.g. `IDENT_LESEN`, `TESTER_PRESENT`, `SG_PHYS_HWNR_LESEN`). Must not be represented as an original factory job.
* **`FORBIDDEN`**: Operation explicitly prohibited by safety boundary.
* **`VIRTUAL`**: Internal orchestration / GUI / callback operation without wire representation.

---

## 2. Phase 1 — Offline EGS Evidence Inventory

All existing evidence relevant to the ZF 6HP EGS mechatronic in the repository was audited and bifurcated into four strictly isolated categories. Generic observations from `10FLASH` are never treated as proof of EGS wire behavior.

### 2.1 Evidence Categorization Table

| Artifact / Observation | Scope / Identifier | Description & Repository Location | Canonical Classification |
|---|---|---|---|
| **Bench AIF Telegram** | `0x18` / `0479S90T641Z` | Request `0x1A 0x86` produced positive response `5A 86...` (66 bytes) across 3 runs. Yielded ZB `7592132`, ZB change `7592133`, SGBD `0479S90T641Z`, VIN. Recorded in `docs/DIRECT_KDCAN_VALIDATION.md` and `logs/kdcan_m1_1_run{1,2,3}.log`. | **`EGS_SPECIFIC_EVIDENCE`** / **`OBSERVED_WIRE`** |
| **Bench TesterPresent Telegram** | `0x18` / `0479S90T641Z` | Request `0x3E 0x00` produced negative response `7F 3E 12` (NRC `0x12`: SubFunctionNotSupported-InvalidFormat) across 3 runs. Recorded in `docs/DIRECT_KDCAN_VALIDATION.md`. | **`EGS_SPECIFIC_EVIDENCE`** / **`OBSERVED_WIRE`** |
| **SP-Daten E60 Flash Files** | `GKE195` / `E60` | Calibration and program binaries `A7592131.0da` ... `A7592155.0da`, `GKE195.DAT`. Cataloged in `docs/research-source-map.csv`. | **`EGS_SPECIFIC_EVIDENCE`** |
| **Key Container Entry `GKE192`** | `SGIDC.as2` (index 3) | Record `$K GKE192 2L18000034[REDACTED_16B_CIPHERTEXT]` (16 bytes encrypted payload). Referenced in `reconstruction/as2_keys.py`; synthetic test counterpart in `tests/fixtures/synthetic/synthetic_sgidc.as2`. | **`EGS_SPECIFIC_EVIDENCE`** |
| **Additional EGS Key Entries** | `SGIDC.as2` (index 3) | Records `GKE191` (`MG18`), `GKE193` (`3L18`), `GKE194` (`4L18`), `GKE195` (`5L18`), `GKE211`–`GKE233`. All end in suffix `18`. Cataloged in `reconstruction/as2_keys.py`. | **`EGS_SPECIFIC_EVIDENCE`** |
| **EGS Preconditions / Limits** | `GKE19` / Part `7592144` | Battery 12.0–14.5V, Ignition ON, ProgVoltage ON, ZB ON. Parsed in `reconstruction/flash_runner.py` from `tests/fixtures/synthetic/synthetic_limits.txt`. | **`EGS_SPECIFIC_EVIDENCE`** |
| **Factory Trace Auth Sequence** | `10FLASH` (`0x78`) | Contiguous sequence: `10 85` (NRC `0x22`) -> `1A 89` (Serial `"080072856"`) -> `31 07 03 <nonce>` (Seed) -> `31 08 <key16>` (Key) -> `10 85` (Success `50 85 C0`). `traces/sanitized/sanitized_flash_session.trc` (lines 12530–12660). | **`FACTORY_TRACE_OTHER_TARGET`** |
| **Factory Trace Keep-Alive** | `10FLASH` / `13_ASK` | Job `DIAGNOSE_AUFRECHT` emits `0x3E 0x02`. `traces/sanitized/sanitized_flash_session.trc`. | **`FACTORY_TRACE_OTHER_TARGET`** |
| **Factory Trace AIF Query** | `10FLASH` (`0x78`) | Job `AIF_LESEN` emits KWP service `0x23` (ReadMemoryByAddress). `traces/sanitized/sanitized_flash_session.trc`. | **`FACTORY_TRACE_OTHER_TARGET`** |
| **Factory Trace Identification** | `10FLASH` (`0x78`) | Job `IDENT` emits `0x1A 0x80`; `PHYSIKALISCHE_HW_NR_LESEN` emits `0x1A 0x87`. `traces/sanitized/sanitized_flash_session.trc`. | **`FACTORY_TRACE_OTHER_TARGET`** |
| **Clean-Room Crypto Module** | Clean-Room Python | `compute_security_key`, `generate_msvc_nonce`, `msvc_rand_after_srand` in `reconstruction/security.py`. Fully reproduces factory MD5 construction. | **`CLEAN_ROOM_RECONSTRUCTION`** |
| **Clean-Room AS2 Parser** | Clean-Room Python | `As2KeyStore`, `parse_as2`, AES key container decryption in `reconstruction/as2_keys.py`. | **`CLEAN_ROOM_RECONSTRUCTION`** |
| **Direct K+DCAN Transport** | Clean-Room Python | `DirectKdcanBus`, serial framing, fail-closed policy in `reconstruction/transport/kdcan/bus.py`. | **`CLEAN_ROOM_RECONSTRUCTION`** |
| **Clean-Room VDLE Engine** | Clean-Room Python | Flash orchestration state machine, segment streaming in `reconstruction/flash_runner.py` and `reconstruction/vdle/core.py`. | **`CLEAN_ROOM_RECONSTRUCTION`** |
| **KWP2000 Protocol Standards** | ISO 14230-3 | Standard service definitions: `0x10` (Session), `0x1A` (ReadById), `0x23` (ReadMem), `0x27` (SecAccess), `0x31` (RoutineCtrl), `0x3E` (TesterPresent). Standard NRCs: `0x11`, `0x12`, `0x22`, `0x31`, `0x33`, `0x35`. | **`GENERIC_PROTOCOL_KNOWLEDGE`** |
| **BMW-FAST Serial Framing** | Physical / Data Link | Format byte (bit 7/6 address mode, bit 5..0 length), Target Addr, Source Addr, Payload, Checksum (sum modulo 256). Handled by `reconstruction/transport/kdcan/framing.py`. | **`GENERIC_PROTOCOL_KNOWLEDGE`** |

---

## 3. Phase 3 — Key-Class Correlation for EGS

An audit of the cryptographic key container assets in `reconstruction/as2_keys.py` and `tests/fixtures/synthetic/` was conducted to establish the exact key class and supported authentication mechanisms for the ZF 6HP EGS.

### 3.1 Container Identity & Record Architecture
* **Container Files**: `SGIDC.as2` (container index 3) and `SGIDD.as2` (container index 4).
* **Target Family**: `GS19` (ZF 6HP transmission family).
* **Container Entries**: `GKE191`, `GKE192`, `GKE193`, `GKE194`, `GKE195`, `GKE211`, `GKE213`, `GKE214`, `GKE215`, `GKE233`.
* **Specific Benchmark Entry**: `GKE192` at container index 3 (`SGIDC.as2`):
  - Record line: `$K GKE192              2L18000034[REDACTED_16B_CIPHERTEXT]`
  - Record Tag: `$K` (Symmetric key record).
  - Logistics Identifier: `2L18` (suffix `18` corresponds to the data set generation for EGS mechatronics).
  - Ciphertext Payload: 16 bytes encrypted (redacted from public repository artifacts).
* **Decrypted Key Material Properties**:
  - Key Length: Exactly 16 bytes.
  - Key SHA-256 Digest: `B58F3D47331250FFF5C770FBAFDABF654B338DB278A0258BD9331FB7AB2E8B51`.
  - Secret Key Hygiene: Raw key material and ciphertext are intentionally excluded from public documentation and source files.

### 3.2 Evaluation of Competing Key Classes
Decompiled WinKFP code in `KrApiAuthenticate` (`FUN_004b95a0`), `FUN_004b89a0`, and `FUN_004b9e30` switches between three distinct authentication modes. We evaluate the presence of each key class for `GKE192`:

1. **Simple Authentication (`T_SMC` / `Simple`)**:
   - **Protocol Requirement**: Requires an 8-byte proprietary cipher key record (stored under tag `$U` or 8-byte payload).
   - **WinKFP Code Gate**: `FUN_004b89a0` explicitly inspects the key length; if length != 8, Simple authentication is rejected with an error.
   - **Container Audit for `GKE192`**: Record length is 16 bytes. Calling `store.simple_key8("GKE192", 3)` raises `ValueError("GKE192 idx3: Simple auth needs an 8-byte key record (FUN_004b89a0), got 16")`.

2. **Asymmetric Authentication (`T_SMA` / `Asymetrisch` / RSA-512)**:
   - **Protocol Requirement**: Requires a 136-byte (`0x88`) record comprising two 32-bit big-endian word counters (`0x00000010` = 16 dwords = 64 bytes) bounding a 64-byte RSA modulus $N$ and a 64-byte RSA public exponent $E$.
   - **WinKFP Code Gate**: `FUN_004b9e30` rejects any buffer whose length != 136 bytes.
   - **Container Audit for `GKE192`**: Record length is 16 bytes. Calling `store.asym_ne("GKE192", 3)` raises `ValueError("GKE192 idx3: Asymetrisch auth needs the 0x88-byte record, got 16")`.

3. **Symmetric Authentication (`T_SMB` / `Symetrisch` / MD5)**:
   - **Protocol Requirement**: Requires exactly a 16-byte symmetric key.
   - **WinKFP Code Gate**: `FUN_004b8cc0` and `FUN_004b9f50` accept exactly 16 bytes and compute a 16-byte MD5 digest over `key16 || nonce4 || serial4 || seed8 || key16`.
   - **Container Audit for `GKE192`**: Record length is exactly 16 bytes. Calling `store.sym_key16("GKE192", 3)` returns the 16-byte key successfully.

> [!NOTE]
> **Target-Scoped Key-Class Conclusion**:
> The audited `GKE192` container record contains a 16-byte symmetric key record and does not contain a compatible 8-byte Simple or 0x88-byte asymmetric key record. The key-container evidence therefore supports the symmetric key class. The actual EGS on-wire authentication method remains unvalidated.

---

## 4. Phase 4 — Session Preconditions & State Transition Hypothesis

Using strictly offline evidence, we investigate whether EGS authentication requires an initial diagnostic state, standard diagnostic session, programming session, or another explicit session transition.

### 4.1 Comparative Analysis: Factory Trace vs EGS Physical Behavior
* **Factory Trace (`10FLASH` at address `0x78`)**:
  - In trace line 12547, the tester attempted an unauthenticated session transition to Programming Mode: `10 85` (`DIAGNOSE_MODE "ECUPM"`).
  - The ECU rejected the request with `7F 10 22` (NRC `0x22`: `ConditionsNotCorrectOrRequestSequenceError`).
  - The tester was forced to execute `SERIENNUMMER_LESEN` (`1A 89`), `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` (`31 07`), and `NG_AUTHENTISIERUNG_START` (`31 08`) **prior** to entering session `0x85`.
  - Once authenticated, `10 85` succeeded (`50 85 C0`).
  - **Conclusion for `10FLASH`**: Authentication is executed from the default/initial diagnostic session; session `0x85` cannot be entered without prior authentication.
* **Physical EGS Bench Observations (Address `0x18`)**:
  - The bench EGS accepted `0x1A 0x86` (AIF query) immediately upon adapter connection without any preceding `0x10` request.
  - The bench EGS responded to `0x3E 0x00` with `7F 3E 12` (NRC `0x12`: `SubFunctionNotSupported-InvalidFormat`).
  - The exact session identifier of the initial state remains **UNKNOWN** (no `0x10` session read has been performed).
  - Whether `0x31 RoutineControl` is accessible in this initial state or requires an explicit diagnostic session switch (e.g. `10 86` Extended Session or `10 81` Standard Session) is unproven.

### 4.2 Target-Scoped State Transition Hypothesis Diagram

```text
               +-------------------------------------------------------+
               |                   Initial EGS State                   |
               |        (Observed at probe startup on address 0x18)    |
               +-------------------------------------------------------+
                                           │
                                           │  OBSERVED_WIRE:
                                           │  0x1A 0x86 accepted (66B AIF)
                                           │  0x3E 0x00 rejected (NRC 0x12)
                                           ▼
               +-------------------------------------------------------+
               |               Candidate Identification                |
               |         (AIF: 0x1A 0x86  /  Serial: 0x1A 0x89)        |
               +-------------------------------------------------------+
                                           │
                                           │  UNKNOWN[target=0479S90T641Z]:
                                           │  0x1A 0x89 wire support unverified
                                           ▼
               +-------------------------------------------------------+
               |          Candidate Authentication Prerequisite        |
               |       (Initial State vs Session Switch 0x10 0x86)     |
               +-------------------------------------------------------+
                                           │
                                           │  UNKNOWN[target=0479S90T641Z]:
                                           │  Whether 0x31/0x27 is accepted
                                           │  in initial state or requires 0x10
                                           ▼
               +-------------------------------------------------------+
               |                Candidate Seed Request                 |
               |       (RoutineControl 0x31 0x07 vs SecurityAccess 0x27)
               +-------------------------------------------------------+
                                           │
                                           │  UNKNOWN[target=0479S90T641Z]:
                                           │  Wire service & routine ID unverified
                                           ▼
               +-------------------------------------------------------+
               |                Candidate Key Submission               |
               |       (RoutineControl 0x31 0x08 vs SecurityAccess 0x27)
               +-------------------------------------------------------+
                                           │
                                           │  EGS Key-Class Evidence: GKE192 16B key / T_SMB
                                           │  Algorithm Hypothesis: INFERRED
                                           │  Actual EGS Wire Job Mapping: UNKNOWN
                                           │  Actual EGS Wire Transaction: UNKNOWN
                                           ▼
               +-------------------------------------------------------+
               |                Candidate Unlocked State               |
               |          (ECU accepts privileged diagnostic jobs)     |
               +-------------------------------------------------------+
                                           │
                                           │  UNKNOWN[target=0479S90T641Z]:
                                           │  Post-auth unlocked capabilities unverified
                                           ▼
               +-------------------------------------------------------+
               |             Programming Session Transition            |
               |          (Candidate: 0x10 0x85 "ECUPM" / 0x10 0x86)   |
               +-------------------------------------------------------+
                                           │
                                           │  FORBIDDEN:
                                           │  Entering programming mode is
                                           │  strictly prohibited by safety policy
                                           ▼
               +-------------------------------------------------------+
               |              Flash / Erase / Transfer Ops             |
               |       (Services 0x31 0x01, 0x34, 0x36, 0x37, 0x11)    |
               +-------------------------------------------------------+
```

---

## 5. Phase 2 — Authentication Hypothesis Matrix

We formulate and evaluate three competing hypotheses regarding the wire-level authentication mechanism of the ZF 6HP EGS.

### 5.1 Hypothesis Matrix

| Dimension | Target | Observation | Hypothesis | Confidence | What Would Prove / Disprove It |
|---|---|---|---|---|---|
| **Hypothesis A** | `0479S90T641Z` / EGS `0x18` | SP-Daten IPO bytecode declares jobs `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` and `NG_AUTHENTISIERUNG_START`. SGBD translates these to wire commands. | **High-Level Job Equivalence with SGBD-Specific Wire Mapping**: EGS uses the same high-level job names as `10FLASH`, but wire-level service IDs and argument structures are determined by SGBD `0479S90T641Z`. | **Medium** (Job names match; wire equivalence unknown) | **Prove**: SGBD execution trace showing the job names mapping to wire requests. <br>**Disprove**: An EDIABAS trace showing different job names for this target. |
| **Hypothesis B** | `0479S90T641Z` / EGS `0x18` | `GKE192` has a 16-byte symmetric key in container index 3; `10FLASH` uses container index 3 with `0x31 0x07` / `0x31 0x08`. WinKFP's `FUN_0041c920` orchestrates flash auth identically across modules. | **RoutineControl 0x31 Structural Similarity**: The EGS may use RoutineControl `0x31` with a seed/key flow structurally similar to the observed factory `10FLASH` authentication flow. | **Low-Medium** (Plausible analogy, but zero wire proof on `0x18`) | **Prove**: Discriminated by physical wire response to candidate `0x31` query. <br>**Disprove**: Negative response `7F 31 11` (ServiceNotSupported) or alternative service acceptance. |
| **Hypothesis C** | `0479S90T641Z` / EGS `0x18` | ZF 6HP transmission electronics are engineered by ZF/Bosch rather than BMW; many powertrain ECUs employ ISO 14230 `0x27 SecurityAccess` (`27 01` / `27 02`) or alternative routine IDs (e.g. routine `0x01` or no container index byte). | **Alternative Routine ID / SecurityAccess 0x27 / Session Dependency**: EGS does not use `31 07`/`31 08`, or uses another RoutineControl routine identifier, or SecurityAccess `0x27`, or requires an explicit diagnostic session transition (`0x10`). | **Medium** (Consistent with third-party Tier-1 supplier ECU architecture) | **Prove**: EGS rejecting `0x31` with `7F 31 11` and accepting `0x27 01`, or accepting `0x31` only after `0x10 0x86`. <br>**Disprove**: EGS accepting `31 07 03 <nonce4>` from initial state. |

---

## 6. Phase 5 — Existing Physical Evidence Correlation

### 6.1 Summary of Physically Observed Wire Transactions
During Milestone 1.1 validation, three independent bench runs were executed against the physical ZF 6HP EGS mechatronic at address `0x18`:

1. **Transaction 1: `0x3E 0x00` (TesterPresent)**:
   - Request: `82 18 F1 3E 00 CD`
   - Response: `83 F1 18 7F 3E 12 57`
   - Result: Negative Response `7F 3E 12` (NRC `0x12`: SubFunctionNotSupported-InvalidFormat).
   - Behavior: 100% reproducible across 3 runs.
2. **Transaction 2: `0x1A 0x86` (ReadDataByIdentifier: AIF)**:
   - Request: `82 18 F1 1A 86 4B`
   - Response: `B8 F1 18 5A 86 40 43 53 36 38 32 39 34 20 ...` (66 bytes payload)
   - Extracted Identifiers:
     - SGBD: `0479S90T641Z`
     - ZB-Number: `7592132` (Current), `7592133` (Target/Change)
     - Software Date: `12.04.2008`
     - VIN: `WBANX71040...`
   - Behavior: 100% reproducible across 3 runs.

---

## 7. Phase 6 — Minimal Future Physical Probe Specification

### UNEXECUTED — OPERATOR REVIEW REQUIRED

> [!CAUTION]
> **PROPOSED BENCH EXPERIMENT SPECIFICATION ONLY**
> The physical probe specified below is a theoretical bench design. **IT MUST NOT BE EXECUTED WITHOUT EXPLICIT OPERATOR REVIEW AND APPROVAL.**
> No code path in the repository executes this probe automatically.

### 7.1 Probe Objectives & Minimality Principle
The future probe is strictly architected to answer the smallest possible unresolved diagnostic question:
> *"Does the physical ZF 6HP EGS mechatronic (address 0x18) expose a candidate serial or seed acquisition routine from its initial diagnostic state, and under what service identifier?"*

### 7.2 Strict Exclusions & Safety Invariants
The probe specification **STRICTLY EXCLUDES**:
- **NO key submission** (`0x31 0x08` or `0x27 0x02` key payloads).
- **NO session transitions to programming mode** (`0x10 0x85` "ECUPM").
- **NO flash writes or erase operations** (`0x31 0x01`, `0x34`, `0x36`, `0x37`).
- **NO signature verification routines** (`NG_SIGNATUR_PRUEFEN`).
- **NO ECU resets** (`0x11 0x01`).

### 7.3 Detailed Probe Step Specification & Frame Builder Verification

#### Step 1: Query ECU Serial Number via Service `0x1A 0x89`
- **Objective**: Determine if ECU serial number is exposed via identifier `0x89`.
- **Exact Builder Function Used**:
  [`reconstruction.transport.kdcan.framing.build`](../../reconstruction/transport/kdcan/framing.py):
  ```python
  from reconstruction.transport.kdcan.framing import build
  frame = build(dst=0x18, src=0xF1, payload=bytes([0x1A, 0x89]))
  ```
- **Payload**: `1A 89` (2 bytes).
- **Full Built Frame**: `82 18 F1 1A 89 2E` (6 bytes).
- **Checksum Calculation**:
  - Additive sum modulo 256: `0x82 + 0x18 + 0xF1 + 0x1A + 0x89 = 0x22E`.
  - Checksum byte: `0x22E & 0xFF = 0x2E`.
- **Timeout**: 2000 ms.
- **Possible Discriminator Responses**:
  - Positive Response: `5A 89 <ASCII Serial Number>`.
  - Negative Response: NRC `0x12` / `0x31` / `0x11`.
  - Timeout / no response.
  - Other valid response.
- **Safety Evaluation**:
  `OPERATOR REVIEW REQUIRED` — The repository currently has no EGS-specific physical evidence establishing that the request is side-effect-free.

#### Step 2: Probe Candidate RoutineControl Seed Acquisition (`0x31 0x07`)
- **Objective**: Determine whether Service `0x31` Routine `0x07` is recognized from initial diagnostic state.
- **Exact Builder Function Used**:
  [`reconstruction.transport.kdcan.framing.build`](../../reconstruction/transport/kdcan/framing.py):
  ```python
  from reconstruction.transport.kdcan.framing import build
  frame = build(dst=0x18, src=0xF1, payload=bytes([0x31, 0x07, 0x03, 0x00, 0x00, 0x00, 0x00]))
  ```
- **Payload**: `31 07 03 00 00 00 00` (7 bytes).
- **Full Built Frame**: `87 18 F1 31 07 03 00 00 00 00 CB` (11 bytes).
- **Checksum Calculation**:
  - Additive sum modulo 256: `0x87 + 0x18 + 0xF1 + 0x31 + 0x07 + 0x03 + 0x00 + 0x00 + 0x00 + 0x00 = 0x1CB`.
  - Checksum byte: `0x1CB & 0xFF = 0xCB`.
- **Timeout**: 2000 ms.
- **Possible Discriminator Responses**:
  - Positive Response: `71 07 ...` (suggests RoutineControl seed acquisition is active).
  - Negative Response:
    - NRC `0x11` (`ServiceNotSupported`) -> suggests `0x31` is not supported in active state.
    - NRC `0x22` (`ConditionsNotCorrect`) -> suggests `0x31` requires diagnostic session change.
    - NRC `0x31` (`RequestOutOfRange`) -> suggests routine `0x07` or parameter `0x03` is invalid.
  - Timeout / no response.
  - Other valid response.
- **Safety & Side-Effect Evaluation**:
  `OPERATOR REVIEW REQUIRED` — The repository currently has no EGS-specific physical evidence establishing that the request is side-effect-free. It cannot be assumed that a seed request does not affect attempt counters, timers, or internal security states on this specific ECU revision.
- **Abort Conditions**:
  - Any bus silence exceeding 2000 ms.
  - Any framing or parity error on serial transport.
  - Any negative response indicating access lockout: NRC `0x33` (`SecurityAccessDenied`) or NRC `0x37` (`RequiredTimeDelayNotExpired`).
  - If any abort condition occurs, all probing must terminate immediately.

---

## 8. What This Milestone Does NOT Prove

To maintain strict scientific and forensic precision, the boundaries of current evidence are explicitly stated:
1. **Key Class Does Not Prove Wire Service**: The presence of a 16-byte symmetric key in `GKE192` (`SGIDC.as2`) does not prove that the physical EGS implements any specific KWP2000 wire service (`0x31` vs `0x27` vs proprietary).
2. **Matching Job Names Do Not Prove Identical SGBD Implementation**: The declaration of `AUTHENTISIERUNG_ZUFALLSZAHL_LESEN` in SP-Daten IPO bytecode does not prove that SGBD `0479S90T641Z` transmits the same byte layout as `10FLASH.PRG`.
3. **Factory `10FLASH` Flow Does Not Prove EGS Wire Bytes**: The observed factory wire sequence (`31 07 03 ...` / `31 08 ...`) on target `0x78` does not prove that address `0x18` uses the same service identifiers, routine numbers, or container parameters.
4. **Physical `1A 86` Success Does Not Establish Authentication Session**: The fact that the EGS accepts `0x1A 0x86` from its initial state does not prove that authentication services are accepted in that same state.
5. **No Counter or Lockout Behavior Has Been Physically Established**: No physical tests have evaluated whether the EGS maintains attempt counters, enforces lockout delays, or modifies internal state upon receiving candidate diagnostic requests.

---

## 9. Phase 7 — Runtime Safety & Fail-Closed Policy

The research codebase maintains strict structural isolation between offline forensic analysis and physical bus operations:
1. **No Permissions Broadening**: [`reconstruction/transport/kdcan/bus.py`](../../reconstruction/transport/kdcan/bus.py) has **NOT** been modified.
2. **No Hardware Authentication Allowlist**: No authentication services (`0x31`, `0x27`, `0x10 0x85`) have been added to the physical K+DCAN allowlist.
3. **Fail-Closed Policy Unchanged**:
   - `allow_inferred=False` (default) strictly rejects all unverified jobs and aliases (`AIF_LESEN`, `TESTER_PRESENT`, `IDENT_LESEN`, `SG_PHYS_HWNR_LESEN`) with `NotImplementedError`.
   - `SG_STATUS_LESEN` raises `NotImplementedError` unconditionally.
   - Flash write operations, segment transfers, erase commands, and signature checks raise `KdcanError` (`FORBIDDEN`).

---

## 10. Phase 8 — Unresolved Questions Matrix

The following matrix formally specifies all remaining open questions concerning EGS authentication, the current evidence status, and the exact evidence required for resolution:

| Question | EGS-Specific Evidence | Current Classification | Needed Evidence |
|---|---|---|---|
| **1. What is the high-level EDIABAS job name that reads AIF on EGS?** | Physical `0x1A 0x86` accepted on wire; `10FLASH` uses `0x23` for `AIF_LESEN`. | **`UNKNOWN[target=0479S90T641Z]`** | Execution trace of SGBD `0479S90T641Z` invoking `AIF_LESEN` or `IDENT`. |
| **2. Is the ECU serial number exposed via `0x1A 0x89`?** | No serial query has been transmitted on address `0x18`. | **`UNKNOWN[target=0479S90T641Z]`** | Physical wire test of Step 1 probe (`1A 89`) or SGBD bytecode disassembly. |
| **3. Does EGS use RoutineControl (`0x31`) or SecurityAccess (`0x27`)?** | SP-Daten IPO declares jobs `AUTHENTISIERUNG_*`; `GKE192` carries 16B key. Zero wire observations. | **`UNKNOWN[target=0479S90T641Z]`** | Physical wire test of Step 2 probe or SGBD bytecode disassembly. |
| **4. Does candidate authentication require a prior diagnostic session switch?** | `0x1A 0x86` accepted from initial state; session state ID is unread. `10FLASH` requires auth before `10 85`. | **`UNKNOWN[target=0479S90T641Z]`** | Wire response to candidate query or `0x10` session status query. |
| **5. What routine identifier is used for seed acquisition?** | `10FLASH` uses Routine `0x07`; EGS unobserved. | **`UNKNOWN[target=0479S90T641Z]`** | Wire response to Step 2 probe on address `0x18`. |
| **6. Does EGS require a 4-byte tester nonce in seed request?** | `10FLASH` requires 4-byte nonce; EGS unobserved. | **`UNKNOWN[target=0479S90T641Z]`** | SGBD decompilation or wire response to Step 2 probe. |
| **7. What unlocked diagnostic privileges are granted post-authentication?** | Unobserved on physical EGS. | **`UNKNOWN[target=0479S90T641Z]`** | Controlled post-auth capability probe (future milestone). |

---

## 11. Phase 9 & 10 — Verification & Safety Audit

### 11.1 Automated Verification Suite Execution
The complete off-hardware test suite was executed in the clean virtual environment (`.venv/bin/python3 tests/run_tests.py`):
```text
======================================================================
  WinKFP Research — Automated Verification Suite
======================================================================
Python interpreter: .venv/bin/python3
Repository root:    .

--- Running Tier: KAT (tests/kat) ---
...............................
[Hardware Scan] Detected K+DCAN serial port: None
[Hardware Scan] Pure off-hardware mode; skipping hardware port open.
..
----------------------------------------------------------------------
Ran 33 tests in 0.092s

OK

--- Running Tier: GOLDEN (tests/golden) ---
...............
----------------------------------------------------------------------
Ran 15 tests in 0.011s

OK

--- Running Tier: DIFFERENTIAL (tests/differential) ---
........
----------------------------------------------------------------------
Ran 8 tests in 3.781s

OK

======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  33 run,  33 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  15 run,  15 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :   8 run,   8 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 56 tests in 4.137s | 56 passed | 0 skipped | 0 failed
======================================================================
```

### 11.2 Independent Safety Invariant Confirmation
1. **Serial Port Invariant**: Zero K+DCAN serial ports were opened during Milestone 4 analysis.
2. **Diagnostic Probe Invariant**: `tools/kdcan_probe.py` was **NOT** executed.
3. **Telegram Invariant**: Zero diagnostic frames (`0x10`, `0x27`, `0x31`, reset, erase, download, transfer, flash write) were transmitted.
4. **Clean-Room & Isolation Invariant**: `open6hp` remains completely untouched. Zero runtime dependencies exist between `winkfp-research` and `open6hp`.
5. **Secret Key Hygiene Invariant**: No raw secret key material, proprietary OEM binaries, or unsanitized VINs were committed or introduced into public fixtures or documentation.
6. **Git Discipline Invariant**: No automatic commit or push was performed.
