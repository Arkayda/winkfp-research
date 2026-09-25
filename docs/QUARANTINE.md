# Provenance Audit & Quarantine Report

This document records the provenance classification audit conducted on all artifacts in the source archive `bmw_flash_re/`, explains the quarantine policy, and details why no files are currently held in quarantine.

---

## 1. Quarantine Policy & Ingestion Criteria

Any artifact submitted to `winkfp-research` whose provenance cannot be definitively identified as one of the approved categories is placed into quarantine under `docs/QUARANTINE.md`.

An artifact must be quarantined if:
1. It contains binary machine code of unverified origin (potential malware or unlicensed third-party code).
2. It contains strings suggesting production customer data, personal names, or non-redacted vehicle identification numbers (VINs).
3. Its license or copyright ownership is ambiguous.
4. It claims to be an independent reconstruction but contains substantial blocks of decompiled proprietary source code.

Quarantined files are **never committed to the repository** until their status is resolved.

---

## 2. Source Archive Inventory & Classification Summary

A comprehensive recursive audit of `/Users/blogman/bmw_flash_re/` inspected all **3,359 filesystem entries**:

| Category Code | Provenance Category | Count | Disposition in `winkfp-research` |
|:---:|---|:---:|---|
| **A** | Original / OEM proprietary material | 1,700 | **EXCLUDED** (Documented in [PROPRIETARY_MATERIAL.md](file:///Users/blogman/winkfp-research/docs/PROPRIETARY_MATERIAL.md)) |
| **A/E** | Traces containing real sessions & VINs | 5 | **SANITIZED** (Redacted extracts in `traces/sanitized/`) |
| **B** | Project-authored research notes & reports | 12 | **PUBLISHED** (`docs/`, `analysis/`) |
| **B (decomp)** | Ghidra decompiler pseudocode | 45 | **PUBLISHED** (`analysis/`) |
| **B/C** | Verification test scripts & differential runners | 10 | **PUBLISHED** (`tests/`, `tools/`) |
| **C** | Clean-room Python reconstructions | 14 | **PUBLISHED** (`reconstruction/`) |
| **G** | Build artifacts, `.venv`, `.pyc`, `.DS_Store` | 1,573 | **EXCLUDED** (Filtered via `.gitignore`) |
| **H** | Unknown provenance / Unclassified | 0 | **NONE** (All files definitively classified) |
| **Total** | **All cataloged entries** | **3,359** | **Complete coverage** |

---

## 3. Current Quarantine Log

```text
Status: ZERO QUARANTINED ARTIFACTS
```

Because every item in the historical archive was definitively traced either to original BMW distributions (Category A), temporary environment files (Category G), or project-authored research and clean-room reconstructions (Categories B, C), **no files remain in quarantine**.
