# Milestone 5.10 — Offline EDIABAS-Compatible Read-Only Job Replay Architecture

**Status**: VALIDATED & PASSED (136/136 tests: 63 KAT, 57 GOLDEN, 16 DIFFERENTIAL)  
**Execution Environment**: Pure Offline Simulation (Zero Serial Port Access, Zero Diagnostic Transmission)  
**Authoritative SGBD Target**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg` / `03GKE195.ipo` / Target Address `0x18`)  
**Evidence Domains**: `FACTORY_TRACE` (Historical WinKFP session), `PHYSICAL_EGS_FIXTURE` (Immutable bench traces), `SYNTHETIC_OFFLINE` (Unit test vectors)

---

## 1. Executive Summary & Objective

Milestone 5.10 establishes a unified, deterministic, offline execution and replay layer directly above the canonical GKE195 read-only pipeline developed in Milestone 5.9.

The replay layer accurately simulates the runtime execution flow of the EDIABAS runtime kernel and SGBD interpreter:

$$\text{EDIABAS Job Invocation} \longrightarrow \text{GKE195 Job Definition} \longrightarrow \text{Canonical Request Builder} \longrightarrow \text{Offline Response Fixture} \longrightarrow \text{Response Validator} \longrightarrow \text{SGBD Semantic Parser} \longrightarrow \text{EDIABAS-like Result}$$

### Core Invariants Maintained
1. **Strict Protocol Distinction**: The application-level logical telegram buffer (`_TEL_AUFTRAG`, as managed in EDIABAS memory) and the physical DS2 transport frame (including trailing additive checksum) are modeled as distinct, un-collapsed data structures.
2. **Evidence Domain Isolation**: Replay against `FACTORY_TRACE` (WinKFP flash session observations on gateway address `0x78`) is strictly quarantined from `PHYSICAL_EGS_FIXTURE` (direct wire traces on target address `0x18`). Factory trace observations **never** synthesize physical execution evidence.
3. **Explicit Argument Modeling**: SGBD arguments (specifically `AIF_NUMMER: int = 0` for `AIF_LESEN`) are modeled explicitly, parameterizing the logical telegram and wire frame construction without creating false physical evidence.
4. **Fail-Closed Verification**: All response validations (DS2 framing, 8-bit additive checksum, target/tester addressing, response service IDs, subfunctions, common identifiers, minimum and exact lengths, negative responses) fail closed before any semantic decoding occurs.
5. **Trace Immutability**: All hardware fixtures under `traces/hardware/*.json` remain strictly immutable with identical SHA-256 digests.

---

## 2. Protocol Distinction: Logical Buffer vs Physical Wire Frame

In the EDIABAS architecture, the runtime kernel communicates with SGBD scripts through memory telegram buffers (`_TEL_AUFTRAG` and `_TEL_ANTWORT`). These buffers represent the application-layer telegram and **do not** contain the physical bus checksum. The trailing 8-bit additive checksum byte is appended exclusively by the physical transport layer (IFH-OBD / K+DCAN bus driver).

The offline replay engine explicitly models this distinction via two separate properties on `EdiabasJobResult` and `EdiabasTelegram`:
- `logical_request`: The exact `_TEL_AUFTRAG` buffer bytes (header + payload, no checksum).
- `canonical_ds2_request`: The complete DS2 wire frame transmitted on the physical bus ($N + 1$ bytes, ending in `checksum(body) & 0xFF`).

### Protocol Telegram Comparison Table (Target: 0x18, Tester: 0xF1)

| EDIABAS Job Name | SGBD Routine | Logical Telegram (`_TEL_AUFTRAG`) | Length | Canonical DS2 Wire Frame | Wire Len | Checksum | CS Formula |
|:---|:---|:---|:---:|:---|:---:|:---:|:---|
| `IDENT` | `IDENT` | `82 18 F1 1A 80` | 5 B | `82 18 F1 1A 80 25` | 6 B | `0x25` | $\sum \pmod{256}$ |
| `PHYSIKALISCHE_HW_NR_LESEN` | `PHYSIKALISCHE_HW_NR_LESEN` | `82 18 F1 1A 87` | 5 B | `82 18 F1 1A 87 2C` | 6 B | `0x2C` | $\sum \pmod{256}$ |
| `SERIENNUMMER_LESEN` | `SERIENNUMMER_LESEN` | `82 18 F1 1A 89` | 5 B | `82 18 F1 1A 89 2E` | 6 B | `0x2E` | $\sum \pmod{256}$ |
| `AIF_LESEN` (`AIF_NUMMER=0`) | `AIF_LESEN` | `86 18 F1 23 00 00 00 07 12` | 9 B | `86 18 F1 23 00 00 00 07 12 CB` | 10 B | `0xCB` | $\sum \pmod{256}$ |
| `ZIF_LESEN` | `ZIF_LESEN` | `83 18 F1 22 25 03` | 6 B | `83 18 F1 22 25 03 D6` | 7 B | `0xD6` | $\sum \pmod{256}$ |
| `ZIF_BACKUP_LESEN` | `ZIF_BACKUP_LESEN` | `83 18 F1 22 25 00` | 6 B | `83 18 F1 22 25 00 D3` | 7 B | `0xD3` | $\sum \pmod{256}$ |
| `HARDWARE_REFERENZ_LESEN` | `HARDWARE_REFERENZ_LESEN` | `83 18 F1 22 25 02` | 6 B | `83 18 F1 22 25 02 D5` | 7 B | `0xD5` | $\sum \pmod{256}$ |
| `DATEN_REFERENZ_LESEN` | `DATEN_REFERENZ_LESEN` | `83 18 F1 22 25 04` | 6 B | `83 18 F1 22 25 04 D7` | 7 B | `0xD7` | $\sum \pmod{256}$ |
| `AIF_READ_BENCH_ALIAS` | `[BENCH_ALIAS]` | `82 18 F1 1A 86` | 5 B | `82 18 F1 1A 86 2B` | 6 B | `0x2B` | $\sum \pmod{256}$ |

> [!IMPORTANT]
> The replay engine guarantees that `canonical_ds2_request[:-1] == logical_request` and `canonical_ds2_request[-1] == ds2_checksum(logical_request)`. The logical buffer is never conflated with the wire frame.

---

## 3. Evidence Domain Separation & Orthogonal Classification Axes

To prevent forensic cross-contamination, the replay layer introduces the `EvidenceDomain` enumeration and evaluates four orthogonal truth axes for every replayed job:

```
                      ┌─────────────────────────────────────────┐
                      │          EvidenceDomain Taxonomy        │
                      └────────────────────┬────────────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         │                                 │                                 │
         ▼                                 ▼                                 ▼
┌──────────────────┐             ┌──────────────────┐             ┌──────────────────┐
│  PHYSICAL_EGS    │             │  FACTORY_TRACE   │             │    SYNTHETIC     │
│  _FIXTURE        │             │                  │             │    _OFFLINE      │
│  (Target: 0x18)  │             │  (Target: 0x78)  │             │  (Negative Tests │
│  Bench Traces    │             │  WinKFP Session  │             │   & Synthetics)  │
└──────────────────┘             └──────────────────┘             └──────────────────┘
```

### Orthogonal Evidence Axes
1. `sgbd_supported`: SGBD bytecode contains a matching procedure/routine in `10FLASH.prg`.
2. `factory_trace_observed`: Observed during historical WinKFP flash execution (`traces/sanitized/sanitized_flash_session.trc`).
3. `physical_trace_exists`: Observed on physical EGS wire bench fixture (`traces/hardware/*.json`).
4. `directly_resolved`: The semantic field decoding was directly resolved and verified against immutable bench hardware.

### Replay Evidence Classification Matrix

| Replay Scenario | Domain | Target | `sgbd_supported` | `factory_trace_observed` | `physical_trace_exists` | `directly_resolved` | Final Evidence Classification |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---|
| `IDENT` on physical trace | `PHYSICAL_EGS_FIXTURE` | `0x18` | **True** | **True** | **True** | **True** | `DIRECTLY_RESOLVED` |
| `PHYSIKALISCHE_HW_NR_LESEN` on trace | `PHYSICAL_EGS_FIXTURE` | `0x18` | **True** | **True** | **True** | **True** | `DIRECTLY_RESOLVED` |
| `SERIENNUMMER_LESEN` on factory line 12577 | `FACTORY_TRACE` | `0x78` | **True** | **True** | **False** | **False** | `DIRECT_SGBD_MAPPING[10FLASH] + OBSERVED_JOB_MAPPING[10FLASH] + UNKNOWN[target=0479S90T641Z]` |
| `AIF_LESEN` ($23) on factory line 11956 | `FACTORY_TRACE` | `0x78` | **True** | **True** | **False** | **False** | `DIRECT_SGBD_MAPPING[10FLASH]` |
| `ZIF_LESEN` ($22 $2503) on factory line 11654 | `FACTORY_TRACE` | `0x78` | **True** | **True** | **False** | **False** | `DIRECT_SGBD_MAPPING[10FLASH]` |
| `AIF_READ_BENCH_ALIAS` on physical trace | `PHYSICAL_EGS_FIXTURE` | `0x18` | **False** | **False** | **True** | **False** | `OBSERVED_WIRE / RECONSTRUCTION_ALIAS` |
| Negative Vector (NRC 0x12) | `SYNTHETIC_OFFLINE` | `0x18` | **True** | **False** | **False** | **False** | `DIRECTLY_RESOLVED` (Error status) |
| Non-catalogued Job | `SYNTHETIC_OFFLINE` | `0x18` | **False** | **False** | **False** | **False** | `UNSUPPORTED` |

> [!CAUTION]
> Replaying against `EvidenceDomain.FACTORY_TRACE` explicitly resets `physical_trace_exists = False` and `directly_resolved = False`. Under no circumstances will factory observations on target `0x78` be interpreted as direct physical evidence on target `0x18`.

---

## 4. SGBD Argument Modeling: `AIF_LESEN`

In `10FLASH.prg` (routine offset `0x4F1C2`), the job `AIF_LESEN` accepts an argument `AIF_NUMMER: int`:
- Default `AIF_NUMMER = 0`: Accesses the current active AIF block starting at base address `0x00000007` with length `0x12` (18 bytes).
  - Logical Telegram: `86 <ADDR> F1 23 00 00 00 07 12`
  - Canonical DS2 Wire Frame (for target `0x18`): `86 18 F1 23 00 00 00 07 12 CB`
  - Canonical DS2 Wire Frame (for target `0x78`): `86 78 F1 23 00 00 00 07 12 2B`
- Non-zero `AIF_NUMMER = N`: Accesses the indexed historical AIF block at `addr = 0x07 + (N * 0x12)`.
  - Address parameter: `addr.to_bytes(4, "big")`
  - Length: `0x12`

### Separation from Bench Alias
`AIF_READ_BENCH_ALIAS` ($1A $86) remains a distinct diagnostic primitive. Passing a physical `1A 86` frame to official `AIF_LESEN` immediately triggers a fail-closed status:
```
status: ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86
error:  Official SGBD AIF_LESEN requires KWP Service 0x23 (ReadMemoryByAddress).
        The 1A 86 response is classified as AIF_READ_BENCH_ALIAS.
```

---

## 5. Replay Results on Canonical Jobs

### A. IDENT Replay (`traces/hardware/20260926_174811_egs_ident.json`)
- **Status**: `OKAY`
- **Domain**: `PHYSICAL_EGS_FIXTURE`
- **Logical Request**: `82 18 F1 1A 80` (5 bytes)
- **DS2 Wire Frame**: `82 18 F1 1A 80 25` (6 bytes, Checksum `0x25`)
- **Decoded Fields**:
  - `ID_BMW_NR`: `"7591972"`
  - `ID_HW_NR`: `"10"`
  - `ID_COD_INDEX`: `5`
  - `ID_DIAG_INDEX`: `516`
  - `ID_LIEF_TEXT`: `"SL "`
  - `ID_DATUM`: `"30.10.2008"`
  - `ID_SW_NR_MCV`: `"0.29.69"`
  - `ID_SW_NR_FSV`: `"195.64.1"`
  - `ID_SW_NR_OSV`: `"2.3.10"`
  - `_PECUHN_FALLBACK`: `"7569980"`

### B. PHYSIKALISCHE_HW_NR_LESEN Replay (`traces/hardware/20260926_175924_egs_physical_hw_nr.json`)
- **Status**: `OKAY`
- **Domain**: `PHYSICAL_EGS_FIXTURE`
- **Logical Request**: `82 18 F1 1A 87` (5 bytes)
- **DS2 Wire Frame**: `82 18 F1 1A 87 2C` (6 bytes, Checksum `0x2C`)
- **Decoded Fields**:
  - `PHYSIKALISCHE_HW_NR`: `"7569980"`

### C. SERIENNUMMER_LESEN Replay (Factory Trace Line 12577)
- **Status**: `OKAY`
- **Domain**: `FACTORY_TRACE`
- **Logical Request**: `82 78 F1 1A 89` (5 bytes)
- **DS2 Wire Frame**: `82 78 F1 1A 89 8E` (6 bytes, Checksum `0x8E`)
- **Decoded Fields**:
  - `SERIENNUMMER`: `"080072856"`

### D. AIF_LESEN Replay (Factory Trace Line 11956)
- **Status**: `OKAY`
- **Domain**: `FACTORY_TRACE`
- **Arguments**: `{"AIF_NUMMER": 0}`
- **Logical Request**: `86 78 F1 23 00 00 00 07 12` (9 bytes)
- **DS2 Wire Frame**: `86 78 F1 23 00 00 00 07 12 2B` (10 bytes, Checksum `0x2B`)
- **Decoded Fields**:
  - `AIF_DATUM`: `"07.10.2008"`
  - `AIF_ZB_NR`: `"9165672"`
  - `AIF_GROESSE`: `18`
  - `AIF_FG_NR`: `""`

### E. ZIF_LESEN Replay (Factory Trace Line 11654)
- **Status**: `OKAY`
- **Domain**: `FACTORY_TRACE`
- **Logical Request**: `83 78 F1 22 25 03` (6 bytes)
- **DS2 Wire Frame**: `83 78 F1 22 25 03 36` (7 bytes, Checksum `0x36`)
- **Decoded Fields**:
  - `ZIF_PROGRAMM_REFERENZ`: `"0561BF1F181A"`
  - `ZIF_SG_KENNUNG`: `"056"`
  - `ZIF_PROJEKT`: `"1BF"`
  - `ZIF_PROGRAMM_STAND`: `"1F18"`

### F. UNKNOWN Physical Execution Status Preserved
The following canonical SGBD jobs remain strictly classified as `physical_trace_exists = False` pending future bench trace acquisition:
1. `SERIENNUMMER_LESEN` ($1A $89)
2. `AIF_LESEN` ($23 ReadMemoryByAddress)
3. `ZIF_LESEN` ($22 $25 03)
4. `ZIF_BACKUP_LESEN` ($22 $25 00)
5. `HARDWARE_REFERENZ_LESEN` ($22 $25 02)
6. `DATEN_REFERENZ_LESEN` ($22 $25 04)

---

## 6. Verification Suite & Test Results

The new deterministic test module `tests/golden/ediabas/test_ediabas_job_replay.py` provides complete test coverage across 12 distinct scenarios:

```
test_01_ident_replay_physical_fixture                   PASSED [OK]
test_02_phys_hwnr_replay_physical_fixture               PASSED [OK]
test_03_factory_serial_replay                           PASSED [OK]
test_04_aif_s23_replay                                  PASSED [OK]
test_05_zif_s22_replay                                  PASSED [OK]
test_06_malformed_response_rejection                    PASSED [OK]
test_07_checksum_failure_rejection                      PASSED [OK]
test_08_negative_ecu_response                           PASSED [OK]
test_09_unsupported_job_rejection                       PASSED [OK]
test_10_aif_s23_vs_bench_alias_separation               PASSED [OK]
test_11_ediabas_buffer_vs_wire_frame_distinction        PASSED [OK]
test_12_evidence_axis_independence                      PASSED [OK]
```

### Full Repository Test Suite (`tests/run_tests.py`)
```
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  57 run,  57 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 136 tests in 4.235s | 136 passed | 0 skipped | 0 failed
======================================================================
```

---

## 7. Trace Immutability Audit

All physical trace fixtures in `traces/hardware/` were re-audited and confirmed completely unmodified:

| Trace Fixture File | Byte Size | SHA-256 Digest | Status |
|:---|:---:|:---|:---:|
| `traces/hardware/20260926_173201_egs_aif.json` | 1,784 B | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **UNMODIFIED** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | 1,460 B | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **UNMODIFIED** |
| `traces/hardware/20260926_174811_egs_ident.json` | 1,772 B | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **UNMODIFIED** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | 1,607 B | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **UNMODIFIED** |

---

## 8. Safety & Off-Hardware Invariant Affirmation

1. **Pure Off-Hardware Execution**: Neither `/dev/cu.usbserial-A50285BI` nor any other serial interface was opened or polled.
2. **Zero Bus Traffic**: No diagnostic request or physical frame was emitted to any vehicle or bench bus.
3. **Fail-Closed Guarantees**: All malformed or corrupted inputs trigger immediate deterministic rejections before semantic decoding.
