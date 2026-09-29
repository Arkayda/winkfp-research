# Milestone 5.25 — Indirect Address / Pointer-Chain Forensic Reconstruction
## Architectural Specification & Technical Design (Soundness-Corrected)

**Milestone:** 5.25
**Document Status:** FORENSIC RECONSTRUCTION REPORT (SEALED)
**Sealed Baseline:** `milestone-5.24-complete` (commit `2032e5390b8dc3f861e5ad61f1aa5d6ad8e4c108`)
**Operating Mode:** 100% Offline Static Reverse-Engineering — Zero Hardware I/O
**Target Vehicle & ECU:** BMW E60 / M57D30TU2 / ZF 6HP28 / GS19.11 / GKE195 (ECU Address `0x18`)
**Target Calibration:** `spdaten_gke/E60/data/GKE195/A7592133.0da` (SHA-256: `45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112`)
**Reference Program:** `spdaten_gke/E60/data/GKE215/7591971A.0pa` (SHA-256: `63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3`)

---

## 1. Executive Summary & Design Scope

Milestone 5.24 established under exhaustive direct-reference scanning:
```text
CASE_C_NO_EXECUTABLE_CONSUMER
EXECUTABLE_CONSUMER_NOT_FOUND
PROVEN_WITHIN_DECLARED_COVERAGE
```

Milestone 5.25 addresses the principal remaining blind spot:
```text
INDIRECT_ADDRESS_RESOLUTION
MULTI_STEP_POINTER_CHAIN
DYNAMIC / REGISTER-BASED ADDRESS CONSTRUCTION
```

This document specifies the complete architecture of **Approach 2 (Modular Forensic Pipeline)** to prove or disprove whether an executable path indirectly references canonical calibration objects, incorporating four mandatory soundness corrections:
1. **Instruction Boundary / Format Validation:** Elimination of address parity heuristics; instruction validity is derived exclusively from decoder recognition, complete format identification (`OP16` | `OP32`), and decoder-determined size.
2. **Explicit Memory Endianness Architecture:** Separation of raw byte sequences from decoded scalar/pointer values with explicit `endianness` parameters (`BE`, `LE`, `UNKNOWN`) and provenance evidence. No automatic `LD.A => BE` assumptions.
3. **Preservation of Concrete PTR Values Through Arithmetic:** Guarantee that `PTR(source, concrete_value) + offset` yields `CONST(concrete_value + offset)` without silent degradation into unresolved expressions.
4. **Target Read vs Target Write Discrimination:** Formal separation of `TARGET_READ` / `TARGET_POINTER_READ` from `TARGET_WRITE`. Proves that write operations (`ST.W`, `ST.H`, `ST.B`) do not constitute consumer proof (`CASE_A` strictly requires memory read evidence).

### 1.1 Core Logical Premise
$$\text{NO\_RAW\_DATA\_POINTER\_EVIDENCE} \quad \not\equiv \quad \text{NO\_OTHER\_ADDRESS\_CONSTRUCTION\_PATH}$$
The absence of a static 32-bit raw pointer in code does not preclude indirect address generation. The engine must systematically analyze:
1. Immediate address construction (`MOVH.A` + `LEA` / `ADDIH.A`);
2. Base pointer + displacement (`[%aX + off16]`);
3. Multi-step address-register arithmetic (`ADD.A`, `SUB.A`);
4. Pointer table dereferences (`LD.A [%aX + off16]`);
5. Indexed table lookups (`[base + index * scale]`).

---

## 2. Ground Truth Anchors & Invariant Constraints

### 2.1 Canonical Calibration Targets (`A7592133.0da`, Segment 2)
Range semantics are strictly half-open $[start, end)$:
* `TARGET_1_AXIS_X`: `0x00063AD6`..`0x00063AEF` (26 B, 12 pts, `int16`, `AXIS_X`)
* `TARGET_2_AXIS_Y`: `0x00063AF0`..`0x00063B01` (18 B, 8 pts, `uint16`, `AXIS_Y`)
* `TARGET_3_KL_CURVE_1`: `0x0006418A`..`0x000641A3` (26 B, 12 pts, `int16`, `1D_CHARACTERISTIC_CURVE`)
* `TARGET_4_KL_CURVE_2`: `0x000641A4`..`0x000641BD` (26 B, 12 pts, `int16`, `1D_CHARACTERISTIC_CURVE`)
* `TARGET_5_KL_CURVE_3`: `0x000641BE`..`0x000641CF` (18 B, 8 pts, `uint16`, `1D_CHARACTERISTIC_CURVE`)

### 2.2 Calibration Descriptor & Fields (`7591971A.0pa`, Segment 3)
* `MAP_DESC_0001` at `0x000454A0` (48 B record).
* Fields: `0x000454A8`, `0x000454AC`, `0x000454B0`, `0x000454B4`, `0x000454B8`, `0x000454BC`, `0x000454C0`, `0x000454C4`, `0x000454C8`, `0x000454CC`.

### 2.3 Secondary Pointer Structures
* `0x0004BD00` (PA Seg 4): `00 06 3A F0` $\rightarrow$ `TARGET_2_AXIS_Y`
* `0x0004BD04` (PA Seg 4): `00 06 3A D6` $\rightarrow$ `TARGET_1_AXIS_X`
* `0x0004BD80` (PA Seg 4): `00 06 41 BE` $\rightarrow$ `TARGET_5_KL_CURVE_3`
* `0x0004BD84` (PA Seg 4): `00 06 41 8A` $\rightarrow$ `TARGET_3_KL_CURVE_1`
* `0x0004BD88` (PA Seg 4): `00 06 41 A4` $\rightarrow$ `TARGET_4_KL_CURVE_2`
* `0x0007CA50` (DA Seg 4): `00 06 3A F0` $\rightarrow$ `TARGET_2_AXIS_Y`
* `0x0007CA54` (DA Seg 4): `00 06 3A D6` $\rightarrow$ `TARGET_1_AXIS_X`
* `0x0007CAC8` (DA Seg 4): `00 06 41 BE` $\rightarrow$ `TARGET_5_KL_CURVE_3`
* `0x0007CACC` (DA Seg 4): `00 06 41 8A` $\rightarrow$ `TARGET_3_KL_CURVE_1`
* `0x0007CAD0` (DA Seg 4): `00 06 41 A4` $\rightarrow$ `TARGET_4_KL_CURVE_2`
* Epistemic status: `pointer_relationship = PROVEN`, `semantic_role = UNCONFIRMED`.

### 2.4 Epistemic Ceilings & Negative Constraints
1. `0x00086000`: `BASIC_BLOCK_ENTRY`, `procedure_identity = UNCONFIRMED`, `function_entry = UNCONFIRMED`, `verified_callers = []`. No prior assumption of consumer status.
2. `0x000455xx`: `REJECTED_SYNTHETIC_ADDRESS`.
3. `0x000C1A04`: `CONSTANT_COLLISION` (`ST.B %d4, [%a15 + 0x54c8]` storing into dynamic RAM).
4. `750` / `500`: Calibration scalars; clamp semantics `UNCONFIRMED`.
5. `6800`: Calibration integer; semantics `UNKNOWN / UNCONFIRMED`.
6. Non-goals: No interpolation proof, no torque/RPM curve interpretation, no full ECU simulation.

---

## 3. Pipeline Architecture (Approach 2)

The forensic pipeline is partitioned into three dedicated components:

```text
+---------------------------------------------------------------+
|                      SP-Daten Binaries                        |
|       7591971A.0pa (Base PA)    /   A7592133.0da (Cal DA)     |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|         Tier A: Inverted Pointer & Fragment Enumerator        |
|  - A1: Canonical target 32-bit BE/LE pointer scan             |
|  - A2: Descriptor field 32-bit BE/LE pointer scan             |
|  - A3: Secondary structure 32-bit BE/LE pointer scan          |
|  - A4: 16-bit address fragments (upper/lower/segment)         |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|     Module A: TriCore Abstract Address Engine                 |
|            reconstruction/calibration/address_expr_v525.py    |
|  - Instruction Boundary & Format Validation (Decoder-Based)   |
|  - Explicit Memory Endianness Model (decode(bytes, w, endian))|
|  - AbstractValue domain & Lattice merge                       |
|  - TriCore instruction transfer functions                     |
|  - Concrete PTR arithmetic preservation                       |
|  - Soundness guarantee: UNKNOWN propagation                   |
|  - Provenance tracking per register                           |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|     Module B: Indirect Pointer Chain & Slice Engine           |
|            reconstruction/calibration/indirect_address_v525.py|
|  - Tier B: Executable pointer producer discovery              |
|  - Tier C: Multi-step chain assembly (NODE_0..NODE_5)         |
|  - Bounded backward slices (origin of EA)                     |
|  - Bounded forward slices (consumption proof)                 |
|  - Target Read vs Write Proof Gate (CASE A vs CASE B)         |
|  - Stop Condition Evaluation (CASE A / B / C / D)             |
|  - 10 Deterministic Artifact Emitters                         |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|     CLI Driver: tools/run_indirect_address_v525.py            |
|  - Diagnostic output, coverage reporting, artifact persistence|
+---------------------------------------------------------------+
```

---

## 4. Module A Specification: `address_expr_v525.py`

### 4.1 Instruction Boundary & Format Validation (Correction #1)
Instruction validity is derived **strictly from the TriCore instruction decoder**, not from address parity or length parity heuristics.

A candidate instruction at address `addr` is valid if and only if:
1. Its start address is a decoder-recognized instruction boundary within a valid executable segment;
2. The decoder successfully recognizes the complete instruction format (`instruction_format = OP16 | OP32`);
3. The decoder determines its actual instruction size (`instruction_size = decoder_result`);
4. All subsequent address/dataflow interpretations use that exact decoded instruction size.

#### Decoder Rejection Statuses:
* `INVALID_INSTRUCTION_BOUNDARY`: Address falls inside a multi-byte instruction (e.g., `0x0009C580` inside `0x0009C57E`).
* `INVALID_DECODE`: Bit pattern does not correspond to any valid TriCore opcode.
* `TRUNCATED_INSTRUCTION`: Segment boundary reached before required instruction bytes are read.

### 4.2 Explicit Memory Model & Endianness Parameterization (Correction #2)
The memory model strictly separates raw memory byte retrieval from scalar/pointer interpretation:
$$\text{MEM}[address, width] \longrightarrow \text{byte sequence } b_0..b_{width-1}$$
$$\text{decode}(raw\_bytes, width, endianness) \longrightarrow \text{decoded\_value}$$

* Supported Endianness: `BE`, `LE`, `UNKNOWN`.
* **Critical Rule:** `LD.A` does **not** automatically imply Big-Endian. The analysis pipeline must evaluate:
  $$\text{instruction} \longrightarrow \text{effective address } EA \longrightarrow raw\_bytes \longrightarrow \text{explicitly justified endian interpretation} \longrightarrow \text{abstract value}$$
* If endianness cannot be justified by static data table conventions or architectural requirements:
  $$\text{decoded\_value} = \text{UNKNOWN}, \quad \text{reason} = \text{"UNKNOWN\_ENDIANNESS"}$$
* **Forensic Fact Preservation:** Static calibration pointers in `MAP_DESC_0001` (PA Segment 3), secondary tables (PA Segment 4), and calibration directories (DA Segment 4) are formally recorded as `endianness = "BE"`, with `endianness_evidence = "STATIC_DATA_ENCODING"`. Little-endian PC-relative code literals (if any) are recorded with `endianness = "LE"`, with `endianness_evidence = "CODE_STREAM_ENCODING"`.

### 4.3 Abstract Value Domain
The abstract value domain represents the state of address registers ($\%a0..\%a15$) and data registers ($\%d0..\%d15$):

$$\mathcal{V} ::= \text{CONST}(c) \mid \text{PTR}(a, v) \mid \text{BASE\_OFFSET}(r, o) \mid \text{PTR\_OFFSET}(a, o) \mid \text{INDEXED}(b, i, s, o) \mid \text{UNKNOWN}(reason)$$

| Abstract Form | Parameters | Description |
|---|---|---|
| `CONST` | `address: int` | Proven concrete 32-bit integer or memory address. |
| `PTR` | `source_addr: int, loaded_value: Optional[int], target_tag: Optional[str]` | 32-bit pointer value dereferenced from concrete memory address `source_addr`. |
| `BASE_OFFSET` | `base_reg: str, offset: int` | Register-relative expression $[\%aX + off]$. |
| `PTR_OFFSET` | `source_addr: int, offset: int` | Offset applied to a pointer whose provenance is known but whose loaded value is unknown $[*\text{source} + off]$. |
| `INDEXED` | `base: AbstractValue, index_reg: str, scale: int, offset: int` | Indexed address expression $[base + \%dY \times scale + offset]$. |
| `UNKNOWN` | `reason: str` | Indeterminate or untracked state (sound top $\top$). |

### 4.4 Concrete Pointer Arithmetic Preservation (Correction #3)
Arithmetic operations on `PTR` values must **preserve concrete address values**:
$$\text{PTR}(source\_addr, concrete\_val) + \text{IMM}(k) \longrightarrow \text{CONST}((concrete\_val + k) \pmod{2^{32}})$$
Provenance must explicitly retain the pointer origin:
```json
{
  "register": "a4",
  "value_kind": "CONST",
  "concrete_int": 408282,
  "value_repr": "0x00063ADA",
  "provenance": [
    "0x00085100: LD.A %a4, [%a12 + 0x08] -> PTR(0x000454A8, 0x00063AD6)",
    "0x00085104: LEA %a4, [%a4 + 0x04] -> CONST(0x00063ADA)"
  ],
  "derived_from": {
    "source_address": "0x000454A8",
    "base_pointer": "0x00063AD6",
    "operation": "LEA",
    "offset": 4
  },
  "confidence": "PROVEN"
}
```
* **`PTR_OFFSET` Semantics:** `PTR_OFFSET` is reserved strictly for cases where pointer provenance is known, but the loaded value is unknown:
  $$\text{PTR}(source\_addr, \text{UNKNOWN}) + \text{IMM}(k) \longrightarrow \text{PTR\_OFFSET}(source\_addr, k)$$
  $$\text{UNKNOWN} + \text{IMM}(k) \longrightarrow \text{UNKNOWN}$$

### 4.5 Register State Machine
* **Address Registers:** $\%a0..\%a15$ (initialized to $\top = \text{UNKNOWN("UNINITIALIZED")}$).
* **Data Registers:** $\%d0..\%d15$ (initialized to $\top = \text{UNKNOWN("UNINITIALIZED")}$).
* **Provenance Structure:** Every register state holds:
  ```json
  {
    "register": "a12",
    "value_kind": "CONST",
    "value_repr": "0x000454A0",
    "concrete_int": 283808,
    "provenance": [
      "0x00084120: MOVH.A %a12, 0x0004",
      "0x00084124: LEA %a12, [%a12 + 0x54A0]"
    ],
    "confidence": "PROVEN"
  }
  ```

### 4.6 Lattice Join Operator ($\sqcup$)
To guarantee termination and soundness over control flow merges:
1. $v \sqcup v = v$
2. $\text{CONST}(c_1) \sqcup \text{CONST}(c_2) = \text{CONST}(c_1)$ if $c_1 == c_2$, else $\text{UNKNOWN("BRANCH_VALUE_DIVERGENCE")}$
3. $\text{PTR}(a_1, v_1) \sqcup \text{PTR}(a_2, v_2) = \text{PTR}(a_1, v_1)$ if $a_1 == a_2 \land v_1 == v_2$, else $\text{UNKNOWN("DIVERGENT_POINTER_SOURCE")}$
4. $\text{BASE\_OFFSET}(r_1, o_1) \sqcup \text{BASE\_OFFSET}(r_2, o_2) = \text{BASE\_OFFSET}(r_1, o_1)$ if $r_1 == r_2 \land o_1 == o_2$, else $\text{UNKNOWN("DIVERGENT_BASE_OFFSET")}$
5. $\text{UNKNOWN} \sqcup v = \text{UNKNOWN}$

### 4.7 Instruction Transfer Functions
Formal transfer function specifications: $\tau : \text{Instruction} \times \mathcal{S} \rightarrow \mathcal{S}$

#### 1. `MOVH.A %a[c], const16` (Opcode `0x91`, RLC format)
* **Immediate:** $imm32 = (const16 \ll 16) \pmod{2^{32}}$
* **Transfer:** $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}(imm32)]$
* **Provenance:** Append `addr: MOVH.A %a[c], const16 -> 0x{imm32:08X}`.

#### 2. `LEA %a[c], [%a[b] + off16]` (Opcode `0xD9`, BOL format)
* **Immediate:** $off32 = \text{sign\_extend}_{16\rightarrow 32}(off16)$
* **Transfer:**
  - If $\mathcal{S}[a_b] == \text{CONST}(base)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((base + off32) \pmod{2^{32}})]$
  - If $\mathcal{S}[a_b] == \text{PTR}(source, concrete\_val)$ and $concrete\_val \neq \text{None}$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((concrete\_val + off32) \pmod{2^{32}})]$
  - If $\mathcal{S}[a_b] == \text{PTR}(source, \text{None})$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{PTR\_OFFSET}(source, off32)]$
  - If $\mathcal{S}[a_b] == \text{BASE\_OFFSET}(r, o)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{BASE\_OFFSET}(r, o + off32)]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{UNKNOWN("LEA_ON_UNKNOWN_BASE")}]$

#### 3. `ADDIH.A %a[c], %a[b], const16` (Opcode `0x11`, RLC format)
* **Immediate:** $imm32 = (const16 \ll 16) \pmod{2^{32}}$
* **Transfer:**
  - If $\mathcal{S}[a_b] == \text{CONST}(base)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((base + imm32) \pmod{2^{32}})]$
  - If $\mathcal{S}[a_b] == \text{PTR}(source, concrete\_val)$ and $concrete\_val \neq \text{None}$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((concrete\_val + imm32) \pmod{2^{32}})]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{UNKNOWN("ADDIH.A_ON_UNKNOWN_BASE")}]$

#### 4. `ADDI %d[c], %d[b], const16` (Opcode `0x1B`, RLC format)
* **Immediate:** $imm32 = \text{sign\_extend}_{16\rightarrow 32}(const16)$
* **Transfer:**
  - If $\mathcal{S}[d_b] == \text{CONST}(val)$:
    $\mathcal{S}' = \mathcal{S}[d_c \mapsto \text{CONST}((val + imm32) \pmod{2^{32}})]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[d_c \mapsto \text{UNKNOWN("ADDI_ON_UNKNOWN_DATA")}]$

#### 5. `ADD.A %a[c], %a[b], %a[a]` (Opcode `0x01` / `0x48`, RR format)
* **Transfer:**
  - If $\mathcal{S}[a_b] == \text{CONST}(c_b) \land \mathcal{S}[a_a] == \text{CONST}(c_a)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((c_b + c_a) \pmod{2^{32}})]$
  - If $\mathcal{S}[a_b] == \text{BASE\_OFFSET}(r, o) \land \mathcal{S}[a_a] == \text{CONST}(c_a)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{BASE\_OFFSET}(r, o + c_a)]$
  - If $\mathcal{S}[a_b] == \text{PTR}(source, concrete\_val) \land \mathcal{S}[a_a] == \text{CONST}(c_a)$:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{CONST}((concrete\_val + c_a) \pmod{2^{32}})]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{UNKNOWN("ADD.A_NON_CONCRETE")}]$

#### 6. `SUB.A %a[c], %a[b], %a[a]` (Format RR)
* **Transfer:** Direct subtraction analog of `ADD.A`.

#### 7. `LD.A %a[c], [%a[b] + off16]` (Opcode `0x99`, BOL format)
* **Effective Address:** $EA = \text{eval}(\mathcal{S}[a_b], off16)$
* **Transfer:**
  - If $EA$ is concrete and maps into read-only flash:
    * Read 4 raw bytes at $EA$.
    * If $EA$ is in a verified Big-Endian static pointer table:
      `decoded_val = unpack(">I", raw_bytes)` with `endianness = "BE"`, `evidence = "STATIC_DATA_ENCODING"`.
      If `decoded_val` matches canonical target $T$:
        $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{PTR}(EA, T, \text{name}(T))]$
      Else:
        $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{PTR}(EA, decoded\_val, \text{"RAW_POINTER"})]$
    * Else if endianness is not proven:
      $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{UNKNOWN("UNKNOWN_ENDIANNESS")}]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[a_c \mapsto \text{UNKNOWN("LD.A_NON_FLASH_OR_DYNAMIC")}]$

#### 8. Target Read Operations: `LD.W` (0x19), `LD.HU` (0xB9), `LD.B` (0x79), `LD.BU` (0x39)
* **Effective Address:** $EA = \text{eval}(\mathcal{S}[a_b], off16)$
* **Access Classification:**
  - If $EA \in [start(T), end(T))$ of canonical target $T$:
    Triggers `TARGET_READ` or `TARGET_POINTER_READ`.
    `access_direction = "TARGET_READ"`, `access_class = "VALUE_LOAD"`.
    $\mathcal{S}' = \mathcal{S}[d_c \mapsto \text{UNKNOWN("CALIBRATION_VALUE_LOADED")}]$
  - Else:
    $\mathcal{S}' = \mathcal{S}[d_c \mapsto \text{UNKNOWN("GENERIC_LOAD")}]$

#### 9. Target Write Operations: `ST.W` (0x59), `ST.H` (0xF9), `ST.B` (0xE9)
* **Effective Address:** $EA = \text{eval}(\mathcal{S}[a_b], off16)$
* **Access Classification:**
  - If $EA \in [start(T), end(T))$:
    Triggers `TARGET_WRITE` (`access_direction = "TARGET_WRITE"`, `access_class = "VALUE_STORE"`).
    Does **not** satisfy consumer proof (`actual_target_consumer = "UNCONFIRMED"`).

---

## 5. Module B Specification: `indirect_address_v525.py`

### 5.1 Tier A: Inverted Pointer & Fragment Enumeration
1. **Pass A1 (Canonical Target Pointers):**
   Exhaustively search all PA segments (0..17) and DA segments (0..5) for 32-bit BE and LE values equal to start/end addresses of Targets 1..5.
2. **Pass A2 (Descriptor Field Pointers):**
   Search for pointers to descriptor addresses `0x000454A8..0x000454CC`.
3. **Pass A3 (Secondary Structure Pointers):**
   Search for pointers to `0x0004BD00`, `0x0004BD80`, `0x0007CA50`, `0x0007CAC8`.
4. **Pass A4 (16-bit Address Fragments):**
   Search for upper halfwords (`0x0006`, `0x0004`, `0x0007`) and lower halfwords (`0x3AD6`, `0x3AF0`, `0x6418`, `0x418A`, `0x41A4`, `0x41BE`, `0x54A0`, `0xBD00`, `0xBD80`, `0xCA50`, `0xCAC8`).
   *Classification:* Must be tagged strictly as `ADDRESS_FRAGMENT`, `BASE_FRAGMENT`, or `OFFSET_FRAGMENT`. Fragments are never treated as proven target references without instruction assembly.

### 5.2 Tier B: Pointer Producer Identification
An instruction is classified as an **Executable Pointer Producer** if and only if:
1. It is decoded at a validated TriCore instruction boundary (`decoder_status == "VALIDATED_BY_DECODER"`);
2. Its transfer function assigns a concrete `CONST(target)` or `PTR(target)` to an address register;
3. The address matches a canonical target, descriptor field, or secondary structure.

### 5.3 Tier C: Multi-Step Pointer Chain Architecture
A verified chain consists of 6 formal nodes and 5 directed edges:

```text
[NODE_0: Code Instruction]
       |
       | Edge 0->1: REFS_STATIC_SOURCE
       v
[NODE_1: Pointer/Table Source]
       |
       | Edge 1->2: LOADS_POINTER
       v
[NODE_2: Loaded Pointer]
       |
       | Edge 2->3: APPLIES_ARITHMETIC
       v
[NODE_3: Address Arithmetic / EA]
       |
       | Edge 3->4: RESOLVES_TARGET
       v
[NODE_4: Resolved Calibration Target]
       |
       | Edge 4->5: EXECUTES_ACCESS
       v
[NODE_5: Actual Memory Access]
```

#### Node Schema:
```json
{
  "node_id": "NODE_0",
  "node_type": "CODE_INSTRUCTION",
  "address": "0x00084120",
  "raw_bytes": "91400040",
  "instruction": "MOVH.A %a12, 0x0004",
  "instruction_format": "OP32",
  "instruction_size": 4,
  "decoder_status": "VALIDATED_BY_DECODER",
  "expression": "CONST(0x00040000)",
  "provenance": ["PA Segment 8: validated 32-bit opcode 0x91"],
  "confidence": "PROVEN"
}
```

### 5.4 Slicing Engine
* **Backward Slice:**
  - Maximum depth: 32 instructions.
  - Direction: Reverse control flow from target access or candidate load.
  - Termination: `EXTERNAL_REGISTER_INPUT`, `UNSUPPORTED_INSTRUCTION`, `UNKNOWN_REGISTER_STATE`, or `BASIC_BLOCK_ENTRY_UNRESOLVED`.
* **Forward Slice:**
  - Maximum depth: 16 instructions.
  - Direction: Forward control flow from target memory load.
  - Purpose: Prove actual register utilization without extrapolating full algorithm semantics.

---

## 6. Target Access Proof Gate & Stop Conditions (Correction #4)

### 6.1 Formal Proof Gate
`actual_target_consumer = PROVEN` if and only if all of the following conditions are simultaneously met:
1. Instruction start address is a decoder-recognized instruction boundary (`decoder_status == "VALIDATED_BY_DECODER"`).
2. Decoder recognizes complete format (`OP16` or `OP32`) and actual size.
3. Abstract address register state evaluates to a concrete address $EA$.
4. $EA \in [start, end)$ of a canonical calibration target object.
5. Access direction is strictly **`TARGET_READ`** or **`TARGET_POINTER_READ`** (`access_class` is `VALUE_LOAD`, `POINTER_LOAD`, or `TABLE_LOOKUP`).

If the instruction executes `ST.W`, `ST.H`, or `ST.B`:
$$\text{TARGET\_WRITE} = \text{PROVEN}, \quad \text{actual\_target\_consumer} = \text{UNCONFIRMED}$$

### 6.2 Stop Condition Definitions

| Condition | Forensic Status | Definition |
|---|---|---|
| **CASE A** | `CASE_A_PROVEN_CONSUMER` | Validated path from code through address expression to canonical target, culminating in an actual target **READ** (`TARGET_READ` or `TARGET_POINTER_READ`). |
| **CASE B** | `CASE_B_PARTIAL_CHAIN` | Executable code constructs pointer/address expression matching target or secondary structure, or performs target write only (`TARGET_WRITE_ONLY`), but no target consumption (read) is proven. |
| **CASE C** | `CASE_C_NO_INDIRECT_CONSUMER` | Exhaustive analysis within declared coverage proves no indirect consumer exists. |
| **CASE D** | `CASE_D_UNSUPPORTED_BOUNDARY` | Pointer chain is proven up to a boundary that requires unsupported instruction encoding or analysis pattern. |

*Requirement for Case D:* Must report `last_proven_state`, `unsupported_location`, `unsupported_construct`, and exact justification for boundary termination.

---

## 7. Deterministic Artifact Specification (10 Artifacts)

All artifacts are persisted to `artifacts/calibration/` with deterministic sorting, 2-space indentation, no timestamps, and non-circular hashing (`self_hash_policy: "EXCLUDED"` in manifest).

1. `pointer_producers_v525.json`: Executable instructions producing pointers/bases to calibration objects.
2. `address_expressions_v525.json`: Abstract states and provenance per scanned basic block.
3. `pointer_chains_v525.json`: Full 6-node chains and edges.
4. `target_access_v525.json`: Memory access records to canonical calibration targets, with explicit `access_direction` (`TARGET_READ`, `TARGET_WRITE`) and `consumer_proof_status`.
5. `backward_slices_v525.json`: Bounded backward slices leading to candidate target access.
6. `forward_slices_v525.json`: Bounded forward slices from loaded calibration data.
7. `coverage_v525.json`: Declarations of scanned segments, instruction classes, and 3 unsupported categories.
8. `epistemic_status_v525.json`: Explicit categorization (`PROVEN`, `SUPPORTED`, `UNCONFIRMED`, `UNKNOWN`, `REJECTED`).
9. `change_log_v525.json`: Structured deltas relative to sealed baseline 5.24.
10. `artifact_manifest_v525.json`: Manifest listing filenames, sizes, SHA-256 sums of the other 9 artifacts, and `self_hash_policy: "EXCLUDED"`.

---

## 8. Test Architecture & Regression Matrix

### 8.1 Unit Tests (`address_expr_v525.py`)
* **Instruction Boundary:**
  - `test_valid_op16_boundary`: Decodes 2-byte instruction at valid boundary.
  - `test_valid_op32_boundary`: Decodes 4-byte instruction at valid boundary.
  - `test_intra_instruction_boundary_rejection`: Rejects address inside multi-byte instruction with `INVALID_INSTRUCTION_BOUNDARY`.
  - `test_truncated_instruction_rejection`: Rejects truncated bytes with `TRUNCATED_INSTRUCTION`.
* **Memory Endianness:**
  - `test_explicit_be_pointer_decode`: Decodes BE bytes `00 06 3A D6` to `0x00063AD6` when `endianness == "BE"`.
  - `test_explicit_le_pointer_decode`: Decodes LE bytes `D6 3A 06 00` to `0x00063AD6` when `endianness == "LE"`.
  - `test_unknown_endianness_rejection`: Returns `UNKNOWN("UNKNOWN_ENDIANNESS")` when endianness is not statically justified.
* **PTR Arithmetic Preservation:**
  - `test_ptr_concrete_plus_offset`: Proves `PTR(0x000454A8, 0x00063AD6) + 4 -> CONST(0x00063ADA)`.
  - `test_ptr_unknown_plus_offset`: Proves `PTR(0x000454A8, None) + 4 -> PTR_OFFSET(0x000454A8, 4)`.
  - `test_unknown_plus_offset`: Proves `UNKNOWN + 4 -> UNKNOWN`.
* **Transfer Functions:**
  - Unit tests for all 9 instructions (`MOVH.A`, `LEA`, `ADDIH.A`, `ADDI`, `ADD.A`, `SUB.A`, `LD.A`, `LD.W`, `LD.HU`).
  - Lattice merge convergence and `UNKNOWN` propagation.

### 8.2 Integration Tests (`indirect_address_v525.py`)
* **Target Access Discrimination:**
  - `test_target_read_satisfies_case_a`: `LD.W` to target range qualifies as `TARGET_READ` and candidate consumer.
  - `test_target_write_rejected_from_case_a`: `ST.W` to target range qualifies as `TARGET_WRITE` and `actual_target_consumer = UNCONFIRMED`.
  - `test_target_address_only_rejected`: `LEA` computing target without memory access qualifies as `TARGET_ADDRESS_ONLY`.
* **Inverted Tracing & Chains:**
  - Exact detection of 32-bit BE pointers in PA Segment 3/4 and DA Segment 4.
  - Schema compliance of `NODE_0..NODE_5`.
  - Bounded backward and forward slice limits.
  - Deterministic artifact generation and manifest verification.

### 8.3 Regression Baseline
* Full regression pass of all existing tests:
  - KAT: 63 passed
  - GOLDEN: 212 passed
  - DIFFERENTIAL: 16 passed
  - TOTAL: 291 passed, 0 failed.
* Preserve `0x00086000` status: `BASIC_BLOCK_ENTRY`, `procedure_identity = UNCONFIRMED`.
* Preserve `0x000455xx` rejection: `REJECTED_SYNTHETIC_ADDRESS`.
* Preserve `0x000C1A04` rejection: `CONSTANT_COLLISION`.
* Preserve `750/500/6800` ceilings.

---

## 9. Performance Target & Soundness Review

### 9.1 Standalone Runtime Measurement & Performance Accounting
* **Measured Standalone Runtime:** `standalone_pipeline_runtime = 17.4883 seconds`
* **Performance Target:** `performance_target = <2.0 seconds`
* **Performance Target Status:** `performance_target_status = NOT_MET`
* **Correctness Impact:** `correctness_impact = NONE` (Operational benchmark only; does not compromise soundness or forensic correctness gates; zero optimization applied during audit pass).
* **Git Working Tree State:** `working_tree_status = DIRTY_EXPECTED` (19 expected Milestone 5.25 files present in working tree prior to manual seal; zero unexpected files).

### 9.2 Architecture Self-Review Checklist
* [x] **Boundary Proof:** No instruction validity inferred from address parity; validation is strictly based on decoder recognition, complete format identification (`OP16` | `OP32`), and decoder-determined size.
* [x] **Endianness Discipline:** No automatic Big-Endian assumption for `LD.A`; raw memory byte retrieval is decoupled from decoding, requiring explicit endianness justification (`STATIC_DATA_ENCODING`).
* [x] **PTR Arithmetic:** No proven concrete pointer value is degraded to an unresolved expression upon offset addition (`PTR(src, val) + imm -> CONST(val + imm)`).
* [x] **Target Consumption Gate:** No target write (`ST.W`, `ST.H`, `ST.B`) misclassified as target consumption; `CASE_A` strictly requires `TARGET_READ` or `TARGET_POINTER_READ`.
* [x] **Unsound Concrete Inference:** Prevented by strict lattice rule ($\text{UNKNOWN} + c = \text{UNKNOWN}$).
* [x] **Epistemic Cleanliness:** Zero semantic speculation (no torque, no RPM, no curve fitting).

---

## 10. Status & Implementation Verification Outcomes

```text
Milestone: 5.25
Phase: AUDIT & VERIFICATION COMPLETE (READY FOR MANUAL APPROVAL / PRE-SEAL GATE)
Baseline: 2032e5390b8dc3f861e5ad61f1aa5d6ad8e4c108 (milestone-5.24-complete)
Architecture: Modular Forensic Pipeline (Approach 2, Soundness-Corrected)
Status: READY_FOR_MANUAL_APPROVAL
working_tree_status = DIRTY_EXPECTED
standalone_pipeline_runtime = 17.4883 seconds
performance_target = <2.0 seconds
performance_target_status = NOT_MET
correctness_impact = NONE
```

### 10.1 Implementation & Forensic Verification Summary
* **Phase A (`address_expr_v525.py`):** Fully implemented abstract interpretation machine for TriCore TC1796/TC1766 with typed `AbstractValue` lattice, `RegisterState` file (A0..A15, D0..D15), `MemoryModel` with decoupled raw byte retrieval and explicit endian parameterization, and 17 transfer functions.
* **Phase B (`test_address_expr_v525.py`):** 28 unit tests implemented covering instruction formats, format boundaries, transfer functions, endianness decoding, concrete arithmetic propagation, and sound unknown joins. (All 28 passed).
* **Phase C (`indirect_address_v525.py`):** Multi-tier forensic reconstruction engine implemented with Tier A candidate enumeration (26 candidates), Tier B pointer producer tracking, Tier C multi-step chain resolution, bounded slice generators, and 10 deterministic JSON artifact emitters.
* **Phase D (`test_indirect_address_v525.py`):** 11 integration tests implemented verifying coverage declarations, target mapping in Segment 2, secondary pointer structures, Tier A enumeration, all 4 soundness corrections, epistemic ceilings, stop condition resolution, and artifact manifest integrity. (All 11 passed).
* **Phase E (`tools/run_indirect_address_v525.py`):** CLI orchestrator implemented and validated.
* **Phase F (Full Offline Forensic Run & Dual-Run Determinism):**
  - Standalone scan executed on real `7591971A.0pa` and `A7592133.0da` binaries.
  - Dual independent execution (`RUN_A` vs `RUN_B`) confirmed **100% bit-for-bit identity** across all 10 emitted JSON artifacts.
  - Stop condition resolved:
    ```text
    case_result:      CASE_C_NO_INDIRECT_CONSUMER
    forensic_status:  INDIRECT_CONSUMER_NOT_FOUND
    confidence:       PROVEN_WITHIN_DECLARED_COVERAGE
    ```
* **Test Suite Regression Baseline:**
  - KAT: 63 passed
  - GOLDEN: 251 passed (+39 tests across Phase B and Phase D)
  - DIFFERENTIAL: 16 passed
  - TOTAL: 330 passed | 0 skipped | 0 failed (50.88s runtime).

### 10.2 Emitted Deterministic Artifacts (`artifacts/calibration/*v525*.json`)
1. `pointer_producers_v525.json` (SHA-256: `a6f1495739bd72c5adef64f2542ae74ff5839e459d0704d4e4cb378d949a721a`)
2. `address_expressions_v525.json` (SHA-256: `aa786b7ae598a375469fe53d2f4b81cc088da50a1b128e6c0fc5767ac1bf99a5`)
3. `pointer_chains_v525.json` (SHA-256: `b11fca60130a731c3a7a86a636355dff0165a7725e6b86ad4a5e63eb5669c253`)
4. `target_access_v525.json` (SHA-256: `6abd71c6135bfbd1f839e619fa7ca585a6c310fe1ded47f3df104e4e012502f5`)
5. `backward_slices_v525.json` (SHA-256: `b6b2c5e11f6eb93364c735cca9f58b5402679760ca337b390c5243d4aca9bf43`)
6. `forward_slices_v525.json` (SHA-256: `2875041b89d229b50909a3bccd8698ca922e774cf8bcbea0453f91cb75d9ecfa`)
7. `coverage_v525.json` (SHA-256: `67d06ec693453f7588c052be723604a26982a14c781ed0f13e4e8415f3fb3212`)
8. `epistemic_status_v525.json` (SHA-256: `1bd65c11c9b767ce49e884feae5a294030e06a1e411f3f109195eb7252544569`)
9. `change_log_v525.json` (SHA-256: `a143702a92427fd7b2dd5e67e8855552f7d06a048dc29f4e16c05c06b3730319`)
10. `artifact_manifest_v525.json` (`self_hash_policy: "EXCLUDED"`)

*Epistemic Invariant:* Zero modifications to `bmw_flash_re/` or SP-Daten source files; zero hardware I/O. Ready for final audit and pre-seal gate.
