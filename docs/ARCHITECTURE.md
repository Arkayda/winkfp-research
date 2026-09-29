# System Architecture & Layer Boundaries

This document defines the architectural relationship between original BMW factory tools, reverse-engineered protocol observations, clean-room reconstructions in `winkfp-research`, and downstream implementations such as `open6hp`.

---

## 1. High-Level Architectural Flow

```text
+-----------------------------------------------------------------------+
| ORIGINAL FACTORY TOOLCHAIN (Proprietary Reference)                     |
|                                                                       |
|   WinKFP (winkfpt.exe)             NFS / KMM SGBDs                    |
|   - Authentication orchestrator    - Sequence scripts (.ipo)          |
|   - VDLE download engine           - Precondition checks (ID_CHECK)   |
|         │                                │                            |
|         └───────────────┬────────────────┘                            |
|                         ▼                                             |
|              EDIABAS Runtime (ebas32.dll)                             |
|              - apiJob / apiResult boundary                            |
|              - Master password chains (63477BC6)                      |
|                         │                                             |
|                         ▼                                             |
|              IFH Driver Layer (OBD32.dll, etc.)                       |
|              - Standard serial COM port (9600 8E1 / 8N1)              |
+─────────────────────────┼─────────────────────────────────────────────+
                          │
            REVERSE ENGINEERING & SPECIFICATION
                          │
                          ▼
+───────────────────────────────────────────────────────────────────────+
| winkfp-research (This Repository: Research & Reconstruction)          |
|                                                                       |
|  Reconstruction Layer (`reconstruction/`):                            |
|  ├── calibration/ (Hex parser, index, axis validation, runtime code-path tracer) |
|  ├── crypto/    (Symmetric MD5, Simple cipher, RSA modexp, MSVC RNG) |
|  ├── auth/      (AS2 3DES parser, GetAuthKey, retry chain)            |
|  ├── vdle/      (INIT_VDLE, segment table, 21-byte block framing)     |
|  ├── ediabas/   (api32 interface wrapper, OBD32 IFH emulation)       |
|  └── safety/    (Interlock structure, Limits parser, safety gate)     |
|                                                                       |
|  Validation & Research Tooling (`tools/`, `tests/`):                  |
|  ├── tests/kat/         (Known-Answer Tests, byte-exact vectors)      |
|  ├── tests/golden/      (Golden state machine, calibration validation)|
|  ├── tests/differential/(Unicorn emulator vs reconstruction)          |
|  ├── tools/             (Calibration CLIs, hardware probe, diff)       |
|  ├── tools/bench_diff/  (EDIABAS api.trc parser & semantic diff)      |
|  └── tools/analysis/    (SP-Daten scanner, SECUR decoder)             |
+─────────────────────────┬─────────────────────────────────────────────+
                          │ Behavioral models, protocol specs,
                          │ reference algorithms, test vectors
                          ▼
+───────────────────────────────────────────────────────────────────────+
| DOWNSTREAM RECONSTRUCTION: open6hp (Independent Project)              |
|                                                                       |
|  Custom transmission control / flasher implementation                 |
|  - Standalone transmission management for ZF 6HP                      |
|  - Consumes clean-room protocol specs derived from this research     |
+─────────────────────────┬─────────────────────────────────────────────+
                          │
                          ▼
+───────────────────────────────────────────────────────────────────────+
| PHYSICAL HARDWARE BOUNDARY (Future Roadmap / Bench Test)              |
|                                                                       |
|  Physical Interface: K+DCAN USB Cable / Edic / ICOM                   |
|  Automotive Bus:     CAN (ISO 11898) or K-Line (ISO 9141 / ISO 14230) |
|  Physical Target:    Electronic Control Unit (e.g., ZF 6HP Mechatronic|
|                      EGS GS19 / GKE192)                               |
+-----------------------------------------------------------------------+
```

---

## 2. Distinction of Artifact Types

To preserve technical rigor, components are strictly separated into four categories:

1. **Original Software (OEM)**:
   - Compiled x86 PE binaries (`winkfpt.exe`, `ebas32.dll`, `OBD32.dll`), SGBD bytecode (`.prg`, `.ipo`), and SP-Daten files.
   - Used exclusively as reverse-engineering targets for disassembly, decompilation, and CPU emulation in sandboxes.
   - **NOT redistributed in this repository.**

2. **Reconstructed Software (`reconstruction/`)**:
   - Clean-room implementations written from scratch in pure Python 3.
   - Faithfully implement the mathematical transformations, packet framing, and state machines observed in the original binaries.
   - Designed for readability, verification, and integration into open research tools.

3. **Research Tooling & Test Harnesses (`tools/`, `tests/`)**:
   - `bench_diff.py`: L1 (choreography) and L2 (semantics) event-log differ with strict tri-state matching.
   - `bench_scenario.py`: Controlled contact harness that executes identity, authentication, session keep-alive, and segment query in a write-free mode against mock or real EDIABAS adapters.
   - Emulation harnesses using Unicorn to execute isolated original machine-code functions against simulated memory spaces for byte-exact differential comparison.

4. **Physical Hardware Boundary**:
   - Serial transceivers, OBD cables, microcontrollers, and actual electronic control units.
   - As documented in [EVIDENCE.md](EVIDENCE.md), the repository establishes validation up to **L4** (differential trace), **L5** (EDIABAS API trace integration), and **L6** (read-only diagnostic identification on physical bench hardware). Physical ECU reprogramming (**L7**) is strictly not validated.

---

## 3. Relationship to `open6hp`

* `winkfp-research` and `open6hp` are **separate, independent repositories**:
  - `winkfp-research` (https://github.com/Arkayda/winkfp-research) is the **research and evidence repository**. It documents how legacy BMW toolchains function, provides Ghidra analysis notes, maintains historical revision logs, and proves reconstruction equivalence via KATs and differentials.
  - `open6hp` (https://github.com/Arkayda/open6hp) is the **independent transmission flasher project** focused on ZF 6HP gearboxes.
* They are related projects with independent Git histories. Neither repository is a submodule, subdirectory, or package of the other.
