# Milestone 5.9.1 — Offline Canonical Request Checksum Consistency Audit

**Status**: COMPLETED (STRICTLY OFF-HARDWARE)  
**Safety Gate**: ZERO HARDWARE ACCESS — ZERO SERIAL PORT OPENINGS — NO BYTES TRANSMITTED  
**Target Family**: BMW E60 ZF 6HP EGS (`GKE195` / `10FLASH.prg` / `03GKE195.ipo` / Target `0x18`)  
**Date**: 2026-09-26  

---

## 1. Executive Summary & Audit Objective

A checksum consistency audit was initiated for Milestone 5.9 to investigate differences between the TX request frames documented in the markdown summary tables and the canonical DS2 additive checksum rule:

$$\text{CS} = \left(\sum_{i=0}^{N-1} \text{byte}_i\right) \pmod{256}$$

The suspect documented values in the Milestone 5.9 presentation table were:
- `SERIENNUMMER_LESEN`: documented as `82 18 F1 1A 89 22` (calculated: `2E`)
- `ZIF_LESEN`: documented as `83 18 F1 22 25 03 D1` (calculated: `D6`)
- `ZIF_BACKUP_LESEN`: documented as `83 18 F1 22 25 00 D4` (calculated: `D3`)
- `HARDWARE_REFERENZ_LESEN`: documented as `83 18 F1 22 25 02 D2` (calculated: `D5`)
- `DATEN_REFERENZ_LESEN`: documented as `83 18 F1 22 25 04 D4` (calculated: `D7`)

### Audit Finding
1. **Framing & Pipeline Code Implementation**: **100% CORRECT**.
   - `reconstruction/transport/kdcan/framing.py:build()` computes `checksum(body) = sum(body) & 0xFF`.
   - `reconstruction/ediabas/job_model.py:build_request()` and `reconstruction/ediabas/pipeline.py:build_request()` strictly delegate to `framing.py:build()`.
   - The implementation code always generated the mathematically exact checksums: `2E`, `D6`, `D3`, `D5`, `D7`.
2. **Root Cause of Discrepancies**: **Documentation Transcription Error**.
   - In earlier milestones (Milestone 5.6 and Milestone 5.8.1), these requests were represented symbolically with placeholder `<CS>`.
   - In Milestone 4 (`docs/evidence/egs_authentication_hypothesis_milestone_4.md`), `SERIENNUMMER_LESEN` was already calculated as `82 18 F1 1A 89 2E`.
   - When populating concrete hex values in the Milestone 5.9 summary table, drafting transcription errors occurred (e.g., mistaking the high byte `0x22` of sum `0x22E` for the checksum `0x2E`, and arithmetic misadditions for the `$22 25 xx` commands).
3. **Unit Tests**:
   - `tests/golden/ediabas/test_canonical_pipeline.py` previously verified prefixes `[:6]` or `[:5]` for `$22 25 xx`.
   - `test_08_fallback_metadata_preservation` has been strengthened to verify the complete frame byte-for-byte including exact checksums for all jobs (primary and fallback modes).
   - Documentation in `docs/evidence/gke195_canonical_readonly_pipeline_milestone_5_9.md` and `walkthrough.md` has been corrected to match authoritative reality.

---

## 2. Forensic Code & Implementation Audit

### 2.1 `reconstruction/transport/kdcan/framing.py`
The authoritative framing code defines:
```python
def checksum(data: bytes) -> int:
    """Additive checksum: sum of bytes modulo 256."""
    return sum(data) & 0xFF

def build(dst: int, src: int, payload: bytes) -> bytes:
    if len(payload) <= 0x3F:
        head = bytes([0x80 | len(payload), dst, src])
    else:
        head = bytes([0x80, dst, src, len(payload)])
    body = head + payload
    return body + bytes([checksum(body)])
```
For all single-frame read requests to target `0x18` from tester `0xF1`:
- Format byte: `0x80 | len(payload)`. For 2-byte payloads (`1A xx`), format byte = `0x82`. For 3-byte payloads (`22 25 xx`), format byte = `0x83`.
- Destination = `0x18`, Source = `0xF1`.
- Base header sum:
  - 2-byte payload: $0x82 + 0x18 + 0xF1 = 0x18B$.
  - 3-byte payload: $0x83 + 0x18 + 0xF1 = 0x18C$.

### 2.2 `reconstruction/ediabas/job_model.py` and `reconstruction/ediabas/pipeline.py`
`SgbdJobDefinition.build_request(...)` passes the payload directly to `build_ds2_frame`:
```python
return build_ds2_frame(dst=target_address, src=tester_address, payload=payload)
```
Execution through `pipeline.build_request(...)` was run against the Python interpreter for all catalog jobs, confirming that the code produces the exact values calculated below.

---

## 3. Canonical Checksum Verification Table

| Job Name | Payload | Format Byte | Target / Source | Documented CS (M5.9) | Implemented CS (Code) | Calculated CS (Canonical) | Audit Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`IDENT`** | `1A 80` | `0x82` | `18 F1` | `25` | `25` | `25` | **MATCH (CORRECT)** |
| **`PHYSIKALISCHE_HW_NR_LESEN`** | `1A 87` | `0x82` | `18 F1` | `2C` | `2C` | `2C` | **MATCH (CORRECT)** |
| **`PHYSIKALISCHE_HW_NR_LESEN`** *(Fallback)* | `1A 80` | `0x82` | `18 F1` | `25` | `25` | `25` | **MATCH (CORRECT)** |
| **`SERIENNUMMER_LESEN`** | `1A 89` | `0x82` | `18 F1` | `22` | `2E` | `2E` | **DISCREPANCY (DOC ERROR)** |
| **`SERIENNUMMER_LESEN`** *(Fallback)* | `1A 80` | `0x82` | `18 F1` | `25` | `25` | `25` | **MATCH (CORRECT)** |
| **`AIF_READ_BENCH_ALIAS`** | `1A 86` | `0x82` | `18 F1` | `2B` | `2B` | `2B` | **MATCH (CORRECT)** |
| **`AIF_LESEN`** | `23 00 00 00 07 12` | `0x86` | `18 F1` | `CB` | `CB` | `CB` | **MATCH (CORRECT)** |
| **`ZIF_LESEN`** | `22 25 03` | `0x83` | `18 F1` | `D1` | `D6` | `D6` | **DISCREPANCY (DOC ERROR)** |
| **`ZIF_LESEN`** *(Fallback)* | `1A 91` | `0x82` | `18 F1` | `36` | `36` | `36` | **MATCH (CORRECT)** |
| **`ZIF_BACKUP_LESEN`** | `22 25 00` | `0x83` | `18 F1` | `D4` | `D3` | `D3` | **DISCREPANCY (DOC ERROR)** |
| **`ZIF_BACKUP_LESEN`** *(Fallback)* | `1A 80` | `0x82` | `18 F1` | `25` | `25` | `25` | **MATCH (CORRECT)** |
| **`HARDWARE_REFERENZ_LESEN`** | `22 25 02` | `0x83` | `18 F1` | `D2` | `D5` | `D5` | **DISCREPANCY (DOC ERROR)** |
| **`HARDWARE_REFERENZ_LESEN`** *(Fallback)* | `1A 80` | `0x82` | `18 F1` | `25` | `25` | `25` | **MATCH (CORRECT)** |
| **`DATEN_REFERENZ_LESEN`** | `22 25 04` | `0x83` | `18 F1` | `D4` | `D7` | `D7` | **DISCREPANCY (DOC ERROR)** |

---

## 4. Discrepancy Breakdown & Root Cause Analysis

### 4.1 `SERIENNUMMER_LESEN` (`1A 89`)
- **Previous Documented Frame**: `82 18 F1 1A 89 22`
- **Corrected Canonical Frame**: `82 18 F1 1A 89 2E`
- **Arithmetic Derivation**:
  $$\text{Sum} = 0x82 + 0x18 + 0xF1 + 0x1A + 0x89 = 0x22E$$
  $$\text{CS} = 0x22E \pmod{0x100} = 0x2E$$
- **Authoritative Source**: `reconstruction/transport/kdcan/framing.py`, `docs/evidence/egs_authentication_hypothesis_milestone_4.md` (line 276).
- **Root Cause**: Transcription error during drafting of the Milestone 5.9 summary table: the high byte `0x22` from total sum `0x22E` was inadvertently recorded instead of the lower byte `0x2E`.

### 4.2 `ZIF_LESEN` (`22 25 03`)
- **Previous Documented Frame**: `83 18 F1 22 25 03 D1`
- **Corrected Canonical Frame**: `83 18 F1 22 25 03 D6`
- **Arithmetic Derivation**:
  $$\text{Sum} = 0x83 + 0x18 + 0xF1 + 0x22 + 0x25 + 0x03 = 0x1D6$$
  $$\text{CS} = 0x1D6 \pmod{0x100} = 0xD6$$
- **Authoritative Source**: `reconstruction/transport/kdcan/framing.py`.
- **Root Cause**: Manual calculation arithmetic mistake (off-by-5) during drafting table assembly.

### 4.3 `ZIF_BACKUP_LESEN` (`22 25 00`)
- **Previous Documented Frame**: `83 18 F1 22 25 00 D4`
- **Corrected Canonical Frame**: `83 18 F1 22 25 00 D3`
- **Arithmetic Derivation**:
  $$\text{Sum} = 0x83 + 0x18 + 0xF1 + 0x22 + 0x25 + 0x00 = 0x1D3$$
  $$\text{CS} = 0x1D3 \pmod{0x100} = 0xD3$$
- **Authoritative Source**: `reconstruction/transport/kdcan/framing.py`.
- **Root Cause**: Manual drafting misaddition.

### 4.4 `HARDWARE_REFERENZ_LESEN` (`22 25 02`)
- **Previous Documented Frame**: `83 18 F1 22 25 02 D2`
- **Corrected Canonical Frame**: `83 18 F1 22 25 02 D5`
- **Arithmetic Derivation**:
  $$\text{Sum} = 0x83 + 0x18 + 0xF1 + 0x22 + 0x25 + 0x02 = 0x1D5$$
  $$\text{CS} = 0x1D5 \pmod{0x100} = 0xD5$$
- **Authoritative Source**: `reconstruction/transport/kdcan/framing.py`.
- **Root Cause**: Manual drafting misaddition.

### 4.5 `DATEN_REFERENZ_LESEN` (`22 25 04`)
- **Previous Documented Frame**: `83 18 F1 22 25 04 D4`
- **Corrected Canonical Frame**: `83 18 F1 22 25 04 D7`
- **Arithmetic Derivation**:
  $$\text{Sum} = 0x83 + 0x18 + 0xF1 + 0x22 + 0x25 + 0x04 = 0x1D7$$
  $$\text{CS} = 0x1D7 \pmod{0x100} = 0xD7$$
- **Authoritative Source**: `reconstruction/transport/kdcan/framing.py`.
- **Root Cause**: Manual drafting misaddition.

---

## 5. Automated Unit Test Verification

`tests/golden/ediabas/test_canonical_pipeline.py` was updated in `test_08_fallback_metadata_preservation` to explicitly assert the complete wire frames (including the trailing checksum byte) for all jobs:
```python
# 1. IDENT: 82 18 F1 1A 80 25 (CS: 0x25)
self.assertEqual(self.pipeline.build_request("IDENT"), bytes.fromhex("82 18 F1 1A 80 25"))

# 2. PHYSIKALISCHE_HW_NR_LESEN: Primary 1A 87 2C, Fallback 1A 80 25
self.assertEqual(self.pipeline.build_request("PHYSIKALISCHE_HW_NR_LESEN"), bytes.fromhex("82 18 F1 1A 87 2C"))
self.assertEqual(self.pipeline.build_request("PHYSIKALISCHE_HW_NR_LESEN", use_fallback=True), bytes.fromhex("82 18 F1 1A 80 25"))

# 3. SERIENNUMMER_LESEN: Primary 1A 89 2E (CS: 0x2E), Fallback 1A 80 25
self.assertEqual(self.pipeline.build_request("SERIENNUMMER_LESEN"), bytes.fromhex("82 18 F1 1A 89 2E"))
self.assertEqual(self.pipeline.build_request("SERIENNUMMER_LESEN", use_fallback=True), bytes.fromhex("82 18 F1 1A 80 25"))

# 4. ZIF_LESEN: Primary 22 25 03 D6 (CS: 0xD6), Fallback 1A 91 36 (CS: 0x36)
self.assertEqual(self.pipeline.build_request("ZIF_LESEN"), bytes.fromhex("83 18 F1 22 25 03 D6"))
self.assertEqual(self.pipeline.build_request("ZIF_LESEN", use_fallback=True), bytes.fromhex("82 18 F1 1A 91 36"))

# 5. ZIF_BACKUP_LESEN: Primary 22 25 00 D3 (CS: 0xD3), Fallback 1A 80 25
self.assertEqual(self.pipeline.build_request("ZIF_BACKUP_LESEN"), bytes.fromhex("83 18 F1 22 25 00 D3"))
self.assertEqual(self.pipeline.build_request("ZIF_BACKUP_LESEN", use_fallback=True), bytes.fromhex("82 18 F1 1A 80 25"))

# 6. HARDWARE_REFERENZ_LESEN: Primary 22 25 02 D5 (CS: 0xD5), Fallback 1A 80 25
self.assertEqual(self.pipeline.build_request("HARDWARE_REFERENZ_LESEN"), bytes.fromhex("83 18 F1 22 25 02 D5"))
self.assertEqual(self.pipeline.build_request("HARDWARE_REFERENZ_LESEN", use_fallback=True), bytes.fromhex("82 18 F1 1A 80 25"))

# 7. DATEN_REFERENZ_LESEN: Primary 22 25 04 D7 (CS: 0xD7)
self.assertEqual(self.pipeline.build_request("DATEN_REFERENZ_LESEN"), bytes.fromhex("83 18 F1 22 25 04 D7"))

# 8. AIF_READ_BENCH_ALIAS: Primary 1A 86 2B (CS: 0x2B)
self.assertEqual(self.pipeline.build_request("AIF_READ_BENCH_ALIAS"), bytes.fromhex("82 18 F1 1A 86 2B"))
```

### Full Master Test Suite Run
Execution of `.venv/bin/python3 tests/run_tests.py`:
```text
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  45 run,  45 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 124 tests in 4.12s | 124 passed | 0 skipped | 0 failed
======================================================================
```

---

## 6. Immutable Physical Trace Integrity

The four physical trace fixtures on disk remain untouched and cryptographically verified:

| Trace File | Expected SHA-256 Digest | Status |
|---|---|:---:|
| `traces/hardware/20260926_173201_egs_aif.json` | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **UNMODIFIED** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **UNMODIFIED** |
| `traces/hardware/20260926_174811_egs_ident.json` | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **UNMODIFIED** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **UNMODIFIED** |

---

## 7. Safety Gate Affirmation

During Milestone 5.9.1:
- Zero serial ports were opened (`/dev/cu.usbserial-A50285BI` was never accessed).
- Zero bytes were transmitted across any physical diagnostic bus.
- Physical EGS hardware was never touched or queried.
- All audits, calculations, and tests were conducted strictly offline.
