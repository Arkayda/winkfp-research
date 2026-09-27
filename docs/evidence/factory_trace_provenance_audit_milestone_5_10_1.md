# Milestone 5.10.1 — Factory Trace Target-Address Provenance Audit

**Status**: VALIDATED & PASSED (140/140 tests: 63 KAT, 61 GOLDEN, 16 DIFFERENTIAL)  
**Execution Environment**: Pure Offline Simulation (Zero Serial Port Access, Zero Hardware Transmission)  
**Audited Components**:  
- `reconstruction/ediabas/replay.py`  
- `reconstruction/ediabas/job_model.py`  
- `reconstruction/ediabas/pipeline.py`  
- `reconstruction/ediabas/execution_model.py`  
- `tests/golden/ediabas/test_ediabas_job_replay.py`  

---

## 1. Audit Objective & Problem Statement

In BMW diagnostic networks, different functional nodes occupy distinct ECU bus addresses:
- **`PHYSICAL_EGS_FIXTURE`**: Physical ZF 6HP EGS mechatronics unit at target address `0x18` (tester address `0xF1`).
- **`FACTORY_TRACE`**: Historical WinKFP flash session traces (`traces/sanitized/sanitized_flash_session.trc`) operating against gateway / flash target address `0x78` (tester address `0xF1`).

The objective of Milestone 5.10.1 is to verify and enforce that:
1. `FACTORY_TRACE` replay **strictly preserves** its actual target address `0x78` across both the logical request buffer (`_TEL_AUFTRAG`) and the physical DS2 wire frame.
2. The default target address `0x18` (used for EGS physical fixtures) **never silently rewrites** or substitutes the target address of a factory trace.
3. Explicit provenance validation prevents accidental conflation of factory observations on gateway `0x78` with physical bench execution on `0x18`.

---

## 2. Provenance Architecture & Target Enforcement

In `reconstruction/ediabas/replay.py`, target address resolution was upgraded from passive defaults to strict provenance enforcement:

```python
# 1. Evidence Domain and Source Determination
domain = evidence_domain
# (Inferred from fixture path, fixture object, or raw frame addressing bytes)
if domain is None and raw_frame is not None and len(raw_frame) >= 4:
    src = raw_frame[2]
    if src == 0x78:
        domain = EvidenceDomain.FACTORY_TRACE
    elif src == 0x18:
        domain = EvidenceDomain.PHYSICAL_EGS_FIXTURE

# 2. Strict Target Provenance Resolution
if domain == EvidenceDomain.FACTORY_TRACE:
    effective_target = 0x78
    if target_address is not None and target_address != 0x78:
        raise ValueError(
            f"FACTORY_TRACE provenance violation: target address must be 0x78, "
            f"got 0x{target_address:02X}. Factory trace replay cannot be silently rewritten "
            f"to target 0x18 or mistaken for EGS execution."
        )
elif domain == EvidenceDomain.PHYSICAL_EGS_FIXTURE:
    effective_target = 0x18
    if target_address is not None and target_address != 0x18:
        raise ValueError(
            f"PHYSICAL_EGS_FIXTURE provenance violation: target address must be 0x18, "
            f"got 0x{target_address:02X}."
        )
else:
    effective_target = target_address if target_address is not None else 0x18
```

### Invariants Guaranteed
1. **No Silent Rewriting**: If `execute_job` is called for `FACTORY_TRACE` without specifying `target_address`, `effective_target` automatically defaults to `0x78` (not `0x18`).
2. **Hard Provenance Gate**: If a caller attempts to force `target_address=0x18` on a `FACTORY_TRACE`, a `ValueError` is raised immediately before request construction or pipeline dispatch.
3. **Physical Isolation Gate**: If a caller attempts to force `target_address=0x78` on a `PHYSICAL_EGS_FIXTURE`, a `ValueError` is raised immediately.
4. **Auto-Detection**: Raw DS2 frames targeting ECU `0x78` (whether via request `dst=0x78` or response `src=0x78`) are automatically classified as `FACTORY_TRACE` with target `0x78`.

---

## 3. Provenance Verification Matrix

| Replay Context | Input Target Arg | Effective Target | `logical_request` Byte 1 | `canonical_ds2_request` Byte 1 | `physical_trace_exists` | `directly_resolved` | Provenance Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `FACTORY_TRACE` (`SERIENNUMMER_LESEN`) | *None* | `0x78` | `0x78` (`82 78 F1...`) | `0x78` (`... 8E`) | **False** | **False** | **PASSED (Provenanced)** |
| `FACTORY_TRACE` (`AIF_LESEN`) | *None* | `0x78` | `0x78` (`86 78 F1...`) | `0x78` (`... 2B`) | **False** | **False** | **PASSED (Provenanced)** |
| `FACTORY_TRACE` (`ZIF_LESEN`) | *None* | `0x78` | `0x78` (`83 78 F1...`) | `0x78` (`... 36`) | **False** | **False** | **PASSED (Provenanced)** |
| `FACTORY_TRACE` (Forced `0x18`) | `0x18` | *Rejected* | *N/A* | *N/A* | *N/A* | *N/A* | **REJECTED (`ValueError`)** |
| `PHYSICAL_EGS_FIXTURE` (`IDENT`) | *None* | `0x18` | `0x18` (`82 18 F1...`) | `0x18` (`... 25`) | **True** | **True** | **PASSED (Provenanced)** |
| `PHYSICAL_EGS_FIXTURE` (`PHYS_HWNR`) | *None* | `0x18` | `0x18` (`82 18 F1...`) | `0x18` (`... 2C`) | **True** | **True** | **PASSED (Provenanced)** |
| `PHYSICAL_EGS_FIXTURE` (Forced `0x78`) | `0x78` | *Rejected* | *N/A* | *N/A* | *N/A* | *N/A* | **REJECTED (`ValueError`)** |

---

## 4. Test Suite Verification

Four new dedicated tests were added to `tests/golden/ediabas/test_ediabas_job_replay.py`:
- `test_13_target_provenance_factory_trace_preservation`: Confirms that `FACTORY_TRACE` defaults to and preserves target `0x78`, `physical_trace_exists = False`, and `directly_resolved = False`.
- `test_14_target_provenance_physical_egs_preservation`: Confirms that `PHYSICAL_EGS_FIXTURE` preserves target `0x18`, `physical_trace_exists = True`, and `directly_resolved = True`.
- `test_15_factory_target_rewriting_rejection`: Confirms fail-closed `ValueError` rejection when attempting to cross-contaminate target addresses.
- `test_16_raw_frame_target_auto_detection`: Confirms auto-detection of domain and target from raw DS2 framing.

### Full Test Suite Results
```
======================================================================
  VERIFICATION SUMMARY
======================================================================
  KAT             :  63 run,  63 passed,   0 skipped,   0 failed  [PASSED]
  GOLDEN          :  61 run,  61 passed,   0 skipped,   0 failed  [PASSED]
  DIFFERENTIAL    :  16 run,  16 passed,   0 skipped,   0 failed  [PASSED]
----------------------------------------------------------------------
TOTAL: 140 tests in 4.280s | 140 passed | 0 skipped | 0 failed
======================================================================
```

---

## 5. Trace Immutability Audit

All 4 physical trace fixtures in `traces/hardware/` remain bit-for-bit unchanged:

| Trace Fixture File | Byte Size | SHA-256 Digest | Status |
|:---|:---:|:---|:---:|
| `traces/hardware/20260926_173201_egs_aif.json` | 1,784 B | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` | **UNMODIFIED** |
| `traces/hardware/20260926_174033_egs_tester_present.json` | 1,460 B | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` | **UNMODIFIED** |
| `traces/hardware/20260926_174811_egs_ident.json` | 1,772 B | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` | **UNMODIFIED** |
| `traces/hardware/20260926_175924_egs_physical_hw_nr.json` | 1,607 B | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` | **UNMODIFIED** |

---

## 6. Safety Affirmation

- **Pure Offline Execution**: No physical serial ports opened; `/dev/cu.usbserial-A50285BI` untouched.
- **Zero Bus Transmission**: No physical CAN/K-Line diagnostic frames emitted.
- **Strict Evidence Boundaries**: Gateway `0x78` factory observations and physical EGS `0x18` bench traces are mutually exclusive and cryptographically verified.
