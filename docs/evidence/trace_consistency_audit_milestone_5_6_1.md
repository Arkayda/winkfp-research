# Physical Trace Source-Of-Truth Audit (Milestone 5.6.1)

**Classification**: RESEARCH AUDIT & DATA INTEGRITY REPORT  
**Scope**: Strictly Off-Hardware Discrepancy Analysis & Trace Canonicalization  
**Target ECU**: BMW E60 ZF 6HP EGS (Address: `0x18`, SGBD: `0479S90T641Z`)  
**Safety Gate**: STRICTLY OFF-HARDWARE (Zero serial port access, zero transmission, zero ECU communication)  

---

## 1. Executive Summary & Audit Mandate

During the forensic synthesis of Milestone 5.6 (*Offline GKE195 Job/Wire Semantic Matrix*), a critical data inconsistency was detected between the prose summary in Section 4.1 and the authoritative physical hardware trace on disk:
- **Milestone 5.6 text**: Recorded physical `1A 86` response as `BC F1 18 5A 86 40 ... 5A A0` with $RTT = 49.32\text{ ms}$.
- **Milestone 5.0 hardware trace / ground truth**: Recorded physical `1A 86` response as `80 F1 18 42 5A 86 40 ... FF FF FF 0F` (71 bytes total, 66 bytes payload) with $RTT = 85.01\text{ ms}$.

This audit resolves the inconsistency, investigates the root cause, verifies the file integrity and immutability of the physical JSON traces, inspects all repository documentation referencing physical wire captures, and establishes a single canonical source-of-truth standard.

---

## 2. Root Cause Analysis of the Discrepancy

### 2.1 KWP2000 Protocol Header Mechanics
In KWP2000 (DS2 / BMW-FAST over K+DCAN serial transport), telegram framing adheres to ISO 14230-2:
1. **Short Header (Inline Length, $\le 63$ bytes payload)**:
   $$\text{Format Byte} = 0x80 \mid \text{Length}$$
   - When payload length is 60 bytes (as in `1A 80` Ident response), Format Byte is $0x80 \mid 60 = 0xBC$.
   - Telegram structure: `BC <Target> <Source> <Payload(60B)> <Checksum>`. Total size = 64 bytes.
   - When payload length is 20 bytes (as in `1A 87` Physical HW response), Format Byte is $0x80 \mid 20 = 0x94$.
   - Telegram structure: `94 <Target> <Source> <Payload(20B)> <Checksum>`. Total size = 24 bytes.
2. **Extended Header (Length Byte, $> 63$ bytes payload)**:
   $$\text{Format Byte} = 0x80, \quad \text{Length Byte} = \text{Payload Length}$$
   - When payload length is 66 bytes (as in `1A 86` AIF response), $66 > 63$ cannot fit in the 6-bit inline length field ($0x00..0x3F$).
   - The protocol strictly mandates a 4-byte header: `80 <Target> <Source> <LengthByte>`.
   - For EGS target `0x18` responding to tester `0xF1`:
     $$\text{Header} = 80\text{ }F1\text{ }18\text{ }42 \quad (0x42 = 66_{10})$$
   - Total telegram size: $4\text{ (Header)} + 66\text{ (Payload)} + 1\text{ (Checksum)} = 71\text{ bytes}$.
   - The terminating 8-bit additive checksum is $0x0F$.

### 2.2 Mechanism of the Error in Milestone 5.6
1. **Header Prefix Substitution**: The author inadvertently applied the $0xBC$ header prefix (correct for the 60-byte `1A 80` response) to the 66-byte `1A 86` record.
2. **Payload Truncation Artifact**: The trailing characters `5A A0` were an erroneous manual drafting fragment, rather than the true trailing bytes `... FF FF FF 0F`.
3. **RTT Contamination**: The recorded RTT of $49.32\text{ ms}$ was an inadvertent drafting approximation (likely confused with the $48.29\text{ ms}$ RTT of `1A 87`).
4. **TesterPresent RTT Contamination**: In Milestone 5.6 Section 4.2, TesterPresent RTT was written as $25.50\text{ ms}$ (the synthetic timing produced by the unit test mock harness) rather than the physical hardware wire timing of $31.96\text{ ms}$.

---

## 3. Physical Trace Immutability & Forensic Verification

The physical trace files residing in `traces/hardware/` represent the sole authoritative ground truth of physical ECU behavior. They were verified via filesystem inode inspection and SHA-256 cryptographic hashing.

### 3.1 Cryptographic Integrity & Timestamps
All 4 physical trace files have remained untouched since their original creation during physical test execution:

| Trace File Name | Probe Target | File Size | Birth / Modify Timestamp (UTC) | SHA-256 Checksum |
|---|---|---|---|---|
| `20260926_173201_egs_aif.json` | `aif` (`1A 86`) | 1,552 B | 2026-09-26 14:32:01 | `f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d` |
| `20260926_174033_egs_tester_present.json` | `tester_present` (`3E 00`) | 955 B | 2026-09-26 14:40:33 | `cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791` |
| `20260926_174811_egs_ident.json` | `ident` (`1A 80`) | 1,772 B | 2026-09-26 14:48:11 | `4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462` |
| `20260926_175924_egs_physical_hw_nr.json` | `physical_hw_nr` (`1A 87`) | 1,279 B | 2026-09-26 14:59:24 | `6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15` |

Zero bytes of these raw hardware trace files were modified during this audit or at any point subsequent to physical capture.

---

## 4. Master 4-Trace Canonical Physical Reference Table

The canonical physical wire observations on BMW E60 ZF 6HP EGS (address `0x18`) are defined exclusively as follows:

| Milestone / Primitive | Probe Name | Exact Physical TX Wire (Hex) | Exact Physical RX Wire (Hex) | Total Frame (Bytes) | Payload (Bytes) | Checksum (Hex) & Status | RTT (ms) | Golden Status | Evidence Classification |
|---|---|---|---|---|---|---|---|---|---|
| **M5.0 (AIF)** | `aif` | `82 18 f1 1a 86 2b` | `80 f1 18 42 5a 86 40 [XX XX XX XX XX XX XX] 20 08 12 04 00 00 07 59 21 32 00 00 07 59 21 33 00 00 00 00 00 00 00 02 40 4e 46 53 30 31 00 30 34 37 39 53 39 30 54 36 34 31 5a [XX XX XX XX XX XX XX XX XX XX] ff ff ff 0f` | 71 | 66 | `0x0F` (VALID) | 85.01 | `EXACT_BYTE_MATCH` | **`OBSERVED_WIRE`** |
| **M5.1 (TesterPresent)** | `tester_present` | `82 18 f1 3e 00 c9` | `83 f1 18 7f 3e 12 5b` | 7 | 3 | `0x5B` (VALID) | 31.96 | `EXACT_BYTE_MATCH` | **`OBSERVED_WIRE`** |
| **M5.2 (Ident)** | `ident` | `82 18 f1 1a 80 25` | `bc f1 18 5a 80 00 00 07 59 19 72 10 05 02 04 53 4c 20 08 10 30 08 00 1d 45 c3 40 01 02 03 0a 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5a d9` | 64 | 60 | `0xD9` (VALID) | 80.01 | `UNKNOWN` | **`OBSERVED_WIRE`** |
| **M5.3 (Physical HW)** | `physical_hw_nr` | `82 18 f1 1a 87 2c` | `94 f1 18 5a 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 e0` | 24 | 20 | `0xE0` (VALID) | 48.29 | `UNKNOWN` | **`OBSERVED_WIRE`** |

---

## 5. Repository Documentation Audit & Reconciliation

A comprehensive audit was performed across all documentation in `docs/` and `docs/evidence/`:

1. **`docs/evidence/gke195_job_wire_semantic_matrix_milestone_5_6.md`**:
   - **Corrected**: Replaced erroneous line 71 string `bc f1 18 5a 86 40 ... 5a a0` ($RTT = 49.32\text{ ms}$) with full exact byte-match wire sequence `80 f1 18 42 5a 86 40 ... ff ff ff 0f` ($RTT = 85.01\text{ ms}$).
   - **Corrected**: Replaced line 84 TesterPresent $RTT = 25.50\text{ ms}$ with exact wire timing $31.96\text{ ms}$.
   - **Clarified**: Updated Table row 30 response description from `5A 86 40 <71B Record>` to `80 F1 18 42 5A 86 40... (66B payload / 71B frame)`.
2. **`docs/evidence/egs_authentication_hypothesis_milestone_4.md`**:
   - **Corrected**: Fixed legacy manual transcription typographical checksum errors in lines 228-234 (`82 18 F1 3E 00 CD` $\to$ `C9`, `83 F1 18 7F 3E 12 57` $\to$ `5B`, `82 18 F1 1A 86 4B` $\to$ `2B`, and `B8 F1 18 ...` $\to$ `80 F1 18 42 ... 0F`).
3. **`docs/evidence/direct_kdcan_milestone_1_1.md`**:
   - Fully consistent. Records exact 71-byte RX wire frames across all 3 benchmark runs.
4. **`docs/DIRECT_KDCAN_VALIDATION.md`**:
   - Fully consistent. Serves as the golden benchmark fixture for Milestone 5.0 and Milestone 5.1.
5. **`docs/evidence/physical_ident_correlation_milestone_5_2.md`**:
   - Fully consistent. Records exact 64-byte `1A 80` wire frame and $80.01\text{ ms}$ RTT.
6. **`docs/evidence/physical_hw_nr_correlation_milestone_5_3.md`**:
   - Fully consistent. Records exact 24-byte `1A 87` wire frame and $48.29\text{ ms}$ RTT.

---

## 6. Verification & Automated Test Status

The complete automated test suite (`tests/run_tests.py`) was executed in off-hardware mode:
- **KAT Suite (`tests/kat`)**: 63 / 63 passed
- **Golden Suite (`tests/golden`)**: 25 / 25 passed
- **Differential Suite (`tests/differential`)**: 8 / 8 passed
- **Total**: **96 passed / 0 skipped / 0 failed** in 4.12 seconds.

---

## 7. Policy Mandate: Canonical Trace Representation

To prevent future discrepancies between prose documentation and physical captures:
1. **Trace Primacy Rule**: Any claim regarding physical wire bytes or timing must cite the corresponding `traces/hardware/<timestamp>_<probe>.json` file.
2. **No Manual Re-Typing of Hex Frames**: Multi-byte wire frames must be copied directly from the verified JSON record or generated via programmatic assertions.
3. **Strict Disambiguation of Length**: Documentation must clearly distinguish between **Payload Length** (data bytes passed to KWP2000 service) and **Wire Frame Length** (including format byte, address bytes, optional length byte, and checksum).
