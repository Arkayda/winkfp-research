# Proprietary Material & Clean-Room Exclusion Policy

This document provides a factual record of the proprietary material, commercial software distributions, and diagnostic databases that were analyzed during the reverse-engineering research, and details why they are strictly excluded from redistribution in this repository.

---

## 1. Clean-Room Principles

To comply with intellectual property standards and copyright protections:

* **No proprietary binaries, databases, or container files from Bayerische Motoren Werke AG (BMW AG) or its suppliers are distributed within this repository.**
* The source archive `bmw_flash_re/` is treated as a local, immutable, private reference library.
* All published code in `reconstruction/`, `tools/`, and `tests/` consists of original, independently authored clean-room implementations.
* Where research findings depend on data structures or tables from proprietary files, the **derived behavioral specifications, mathematical algorithms, and synthetic fixtures** are published, rather than the original files.

---

## 2. Inventory of Analyzed External Material

The following categories of proprietary artifacts were examined in private sandboxes during this research:

| Category | Typical Paths / File Types | Description & Role in Research | Exclusion Rationale |
|---|---|---|---|
| **WinKFP Executables & DLLs** | `winkfpt.exe`, `winkfp.exe` (Win32 PE) | Target of static reverse engineering and Unicorn CPU emulation to determine authentication logic, VDLE dispatcher, and segment layout. | Copyrighted binary software; redistribution prohibited. |
| **EDIABAS Runtime Binaries** | `EDIABAS_6.4.7/Bin/*.dll`, `*.exe` (`ebas32.dll`, `api32.dll`, `OBD32.dll`) | Analyzed to understand the diagnostic API, error codes, master password tables (`63477BC6`), and serial K-Line framing. | Commercial diagnostic runtime software; redistribution prohibited. |
| **BMW SP-Daten Sets** | `E60_daten/`, `spdaten_gke/` (`.0da`, `.prg`, `.ipo`, `.grp`, `.met`, `.c01`–`.c99`) | Inspected for flash parameters (address boundaries, block sizes, checksum routines) for transmission controllers (GS19 / GKE19x). | Factory programming datasets and firmware blobs; redistribution prohibited. |
| **SGBD Diagnostic Bytecode** | `sgbd/*.PRG`, `*.IPO` (`SECUR1.PRG`, `SECUR2.PRG`, `GS19*.PRG`) | Analyzed to determine ECU-side diagnostic scripts and password verification tables. | Proprietary compiled diagnostic bytecode; redistribution prohibited. |
| **Key Containers** | `SGIDC.as2`, `SGIDD.as2` | Examined to understand key store format, line grammar, logistics IDs, and 3DES key decryption for `GetAuthKey`. | Proprietary OEM security containers; redistribution prohibited. |
| **OEM Configuration Files** | `EDIABAS 2.INI`, `EDIABAS 3.INI`, `EDIABAS 4.INI`, `Ediabas.ini`, `obd.ini` | Inspected for default interface settings, timeouts, and buffer sizes. | Proprietary configuration files; replaced with documented defaults in Python. |
| **Raw Diagnostic Traces** | `api.trc`, `ifh.trc` | Real communication traces recorded during factory tool sessions, containing vehicle identifiers. | Contain real VINs and customer data; sanitized extracts are published under `traces/sanitized/`. |

---

## 3. How Users Can Reproduce Results Legally

Users seeking to verify the differential tests against original machine code or real key containers must supply their own legally acquired copies:

1. **For Unicorn KATs (`tests/differential/`)**:
   - Place a legally obtained copy of `winkfpt.exe` or `OBD32.dll` in an external directory.
   - Point the test runner to the binary via environment variable (e.g., `WINKFP_EXE_PATH=/path/to/winkfpt.exe`).
2. **For AS2 Key Containers (`reconstruction/auth/key_containers/`)**:
   - The parser reads user-supplied `SGIDC.as2` / `SGIDD.as2` files at runtime.
   - Deterministic self-tests run out-of-the-box using the synthetic container fixtures in `tests/fixtures/synthetic/`.
3. **For EDIABAS API Integration (`reconstruction/ediabas/api/`)**:
   - On Windows, point `bench_scenario.py` to your local `api32.dll`.
   - On non-Windows platforms, tests default to the included `MockBus` simulator.
