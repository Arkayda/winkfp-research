"""TriCore Abstract Address Expression and Dataflow Machine for Milestone 5.25.

Provides isolated abstract interpretation of Infineon TriCore TC1796 / TC1766 instructions:
- Strict decoder-based instruction boundary and format validation (no parity heuristics).
- Abstract value domain tracking concrete addresses, pointer origins, register bases, and sound UNKNOWNs.
- Preservation of concrete pointer values through known immediate arithmetic:
    PTR(source, concrete_val) + offset -> CONST(concrete_val + offset)
- Decoupled memory byte sequence retrieval and explicit endian-aware decoding (BE, LE, UNKNOWN).
- Strict separation of TARGET_READ / TARGET_POINTER_READ from TARGET_WRITE.
- Strictly offline, deterministic, zero hardware I/O.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# -----------------------------------------------------------------------------
# 1. Target Range & Canonical Anchors Model
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class TargetRange:
    """Half-open interval [start_address, end_address) with size = end - start."""

    target_id: str
    start_address: int
    end_address: int
    span_bytes: int
    element_count: int
    data_type: str
    structural_role: str

    def contains(self, address: int) -> bool:
        """Evaluate deterministic membership in half-open interval [start, end)."""
        return self.start_address <= address < self.end_address

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "address_range_semantics": "[START, END)",
            "start_address": f"0x{self.start_address:08X}",
            "end_address": f"0x{self.end_address:08X}",
            "span_bytes": self.span_bytes,
            "element_count": self.element_count,
            "data_type": self.data_type,
            "structural_role": self.structural_role,
        }


# Canonical Target Objects in A7592133.0da (Segment 2)
CANONICAL_TARGETS: Dict[str, TargetRange] = {
    "TARGET_1_AXIS_X": TargetRange(
        target_id="TARGET_1_AXIS_X",
        start_address=0x00063AD6,
        end_address=0x00063AEF,
        span_bytes=26,
        element_count=12,
        data_type="int16",
        structural_role="AXIS_X",
    ),
    "TARGET_2_AXIS_Y": TargetRange(
        target_id="TARGET_2_AXIS_Y",
        start_address=0x00063AF0,
        end_address=0x00063B01,
        span_bytes=18,
        element_count=8,
        data_type="uint16",
        structural_role="AXIS_Y",
    ),
    "TARGET_3_KL_CURVE_1": TargetRange(
        target_id="TARGET_3_KL_CURVE_1",
        start_address=0x0006418A,
        end_address=0x000641A3,
        span_bytes=26,
        element_count=12,
        data_type="int16",
        structural_role="1D_CHARACTERISTIC_CURVE",
    ),
    "TARGET_4_KL_CURVE_2": TargetRange(
        target_id="TARGET_4_KL_CURVE_2",
        start_address=0x000641A4,
        end_address=0x000641BD,
        span_bytes=26,
        element_count=12,
        data_type="int16",
        structural_role="1D_CHARACTERISTIC_CURVE",
    ),
    "TARGET_5_KL_CURVE_3": TargetRange(
        target_id="TARGET_5_KL_CURVE_3",
        start_address=0x000641BE,
        end_address=0x000641CF,
        span_bytes=18,
        element_count=8,
        data_type="uint16",
        structural_role="1D_CHARACTERISTIC_CURVE",
    ),
}

# Secondary Table and Descriptor Anchors
SECONDARY_STRUCTURES: Dict[int, str] = {
    0x0004BD00: "PARALLEL_CALIBRATION_POINTER_ARRAY_AXIS_Y",
    0x0004BD80: "PARALLEL_CALIBRATION_POINTER_ARRAY_CURVE_3",
    0x0007CA50: "CALIBRATION_DIRECTORY_POINTER_AXIS_Y",
    0x0007CAC8: "CALIBRATION_DIRECTORY_POINTER_CURVE_3",
    0x000454A0: "MAP_DESC_0001_HEADER",
}

# Descriptor Field Anchors (0x000454A8..0x000454CC)
DESCRIPTOR_FIELDS: Dict[int, str] = {
    0x000454A8: "MAP_DESC_0001_FIELD_TARGET_1_AXIS_X_START",
    0x000454AC: "MAP_DESC_0001_FIELD_TARGET_1_AXIS_X_END",
    0x000454B0: "MAP_DESC_0001_FIELD_TARGET_2_AXIS_Y_START",
    0x000454B4: "MAP_DESC_0001_FIELD_TARGET_2_AXIS_Y_END",
    0x000454B8: "MAP_DESC_0001_FIELD_TARGET_3_KL_CURVE_1_START",
    0x000454BC: "MAP_DESC_0001_FIELD_TARGET_3_KL_CURVE_1_END",
    0x000454C0: "MAP_DESC_0001_FIELD_TARGET_4_KL_CURVE_2_START",
    0x000454C4: "MAP_DESC_0001_FIELD_TARGET_4_KL_CURVE_2_END",
    0x000454C8: "MAP_DESC_0001_FIELD_TARGET_5_KL_CURVE_3_START",
    0x000454CC: "MAP_DESC_0001_FIELD_TARGET_5_KL_CURVE_3_END",
}


def find_containing_target(address: int) -> Optional[Tuple[str, TargetRange]]:
    """Determine if address falls within any canonical calibration target [start, end)."""
    for tid, trange in CANONICAL_TARGETS.items():
        if trange.contains(address):
            return tid, trange
    return None


# -----------------------------------------------------------------------------
# 2. Abstract Value Domain & Lattice Model
# -----------------------------------------------------------------------------

class AbstractValueKind(str, Enum):
    CONST = "CONST"
    PTR = "PTR"
    BASE_OFFSET = "BASE_OFFSET"
    PTR_OFFSET = "PTR_OFFSET"
    INDEXED = "INDEXED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AbstractValue:
    """Immutable abstract value representation with explicit provenance."""

    kind: AbstractValueKind
    concrete_value: Optional[int] = None
    source_address: Optional[int] = None
    target_tag: Optional[str] = None
    base_reg: Optional[str] = None
    offset: int = 0
    index_reg: Optional[str] = None
    scale: int = 1
    unknown_reason: Optional[str] = None

    @classmethod
    def make_const(cls, val: int) -> AbstractValue:
        return cls(kind=AbstractValueKind.CONST, concrete_value=val & 0xFFFFFFFF)

    @classmethod
    def make_ptr(cls, source_addr: int, concrete_val: Optional[int], target_tag: Optional[str] = None) -> AbstractValue:
        cval = (concrete_val & 0xFFFFFFFF) if concrete_val is not None else None
        return cls(
            kind=AbstractValueKind.PTR,
            source_address=source_addr,
            concrete_value=cval,
            target_tag=target_tag,
        )

    @classmethod
    def make_base_offset(cls, reg: str, offset: int) -> AbstractValue:
        return cls(kind=AbstractValueKind.BASE_OFFSET, base_reg=reg.lower(), offset=offset)

    @classmethod
    def make_ptr_offset(cls, source_addr: int, offset: int) -> AbstractValue:
        return cls(kind=AbstractValueKind.PTR_OFFSET, source_address=source_addr, offset=offset)

    @classmethod
    def make_indexed(cls, base: AbstractValue, index_reg: str, scale: int, offset: int) -> AbstractValue:
        return cls(
            kind=AbstractValueKind.INDEXED,
            concrete_value=base.concrete_value,
            source_address=base.source_address,
            base_reg=base.base_reg,
            index_reg=index_reg.lower(),
            scale=scale,
            offset=offset,
        )

    @classmethod
    def make_unknown(cls, reason: str) -> AbstractValue:
        return cls(kind=AbstractValueKind.UNKNOWN, unknown_reason=reason)

    def is_concrete(self) -> bool:
        return self.kind == AbstractValueKind.CONST and self.concrete_value is not None

    def get_concrete_address(self) -> Optional[int]:
        if self.kind == AbstractValueKind.CONST:
            return self.concrete_value
        elif self.kind == AbstractValueKind.PTR and self.concrete_value is not None:
            return self.concrete_value
        return None

    def format_repr(self) -> str:
        if self.kind == AbstractValueKind.CONST:
            return f"CONST(0x{self.concrete_value:08X})"
        elif self.kind == AbstractValueKind.PTR:
            val_str = f"0x{self.concrete_value:08X}" if self.concrete_value is not None else "None"
            tag_str = f" [{self.target_tag}]" if self.target_tag else ""
            return f"PTR(src=0x{self.source_address:08X}, val={val_str}{tag_str})"
        elif self.kind == AbstractValueKind.BASE_OFFSET:
            sign = "+" if self.offset >= 0 else "-"
            return f"BASE({self.base_reg} {sign} 0x{abs(self.offset):X})"
        elif self.kind == AbstractValueKind.PTR_OFFSET:
            sign = "+" if self.offset >= 0 else "-"
            return f"PTR_OFFSET(src=0x{self.source_address:08X} {sign} 0x{abs(self.offset):X})"
        elif self.kind == AbstractValueKind.INDEXED:
            return f"INDEXED(base={self.base_reg}, idx={self.index_reg}*{self.scale} + 0x{self.offset:X})"
        else:
            return f"UNKNOWN({self.unknown_reason})"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "kind": self.kind.value,
            "repr": self.format_repr(),
        }
        if self.concrete_value is not None:
            d["concrete_value"] = f"0x{self.concrete_value:08X}"
        if self.source_address is not None:
            d["source_address"] = f"0x{self.source_address:08X}"
        if self.target_tag:
            d["target_tag"] = self.target_tag
        if self.base_reg:
            d["base_reg"] = self.base_reg
        if self.offset != 0:
            d["offset"] = self.offset
        if self.unknown_reason:
            d["unknown_reason"] = self.unknown_reason
        return d


# -----------------------------------------------------------------------------
# 3. Register State Machine
# -----------------------------------------------------------------------------

@dataclass
class RegisterState:
    """Abstract register file tracking A0..A15 and D0..D15 with full provenance."""

    a_regs: Dict[str, AbstractValue] = field(default_factory=dict)
    d_regs: Dict[str, AbstractValue] = field(default_factory=dict)
    provenance: Dict[str, List[str]] = field(default_factory=dict)
    confidence: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for i in range(16):
            a_key = f"a{i}"
            d_key = f"d{i}"
            if a_key not in self.a_regs:
                self.a_regs[a_key] = AbstractValue.make_unknown("UNINITIALIZED")
                self.provenance[a_key] = []
                self.confidence[a_key] = "UNCONFIRMED"
            if d_key not in self.d_regs:
                self.d_regs[d_key] = AbstractValue.make_unknown("UNINITIALIZED")
                self.provenance[d_key] = []
                self.confidence[d_key] = "UNCONFIRMED"

    def get_a(self, reg: int | str) -> AbstractValue:
        key = f"a{reg}" if isinstance(reg, int) else reg.lower()
        return self.a_regs.get(key, AbstractValue.make_unknown(f"INVALID_REG_{reg}"))

    def get_d(self, reg: int | str) -> AbstractValue:
        key = f"d{reg}" if isinstance(reg, int) else reg.lower()
        return self.d_regs.get(key, AbstractValue.make_unknown(f"INVALID_REG_{reg}"))

    def set_a(self, reg: int | str, val: AbstractValue, prov_step: str, conf: str = "PROVEN") -> None:
        key = f"a{reg}" if isinstance(reg, int) else reg.lower()
        self.a_regs[key] = val
        prior = list(self.provenance.get(key, []))
        prior.append(prov_step)
        self.provenance[key] = prior
        self.confidence[key] = conf

    def set_d(self, reg: int | str, val: AbstractValue, prov_step: str, conf: str = "PROVEN") -> None:
        key = f"d{reg}" if isinstance(reg, int) else reg.lower()
        self.d_regs[key] = val
        prior = list(self.provenance.get(key, []))
        prior.append(prov_step)
        self.provenance[key] = prior
        self.confidence[key] = conf

    def copy(self) -> RegisterState:
        new_state = RegisterState()
        new_state.a_regs = dict(self.a_regs)
        new_state.d_regs = dict(self.d_regs)
        new_state.provenance = {k: list(v) for k, v in self.provenance.items()}
        new_state.confidence = dict(self.confidence)
        return new_state

    def join(self, other: RegisterState) -> RegisterState:
        """Lattice join operation (⊔) prioritizing soundness over completeness."""
        joined = RegisterState()
        # Join address registers
        for i in range(16):
            k = f"a{i}"
            v1 = self.get_a(i)
            v2 = other.get_a(i)
            jval, prov, conf = _lattice_join_value(v1, v2, self.provenance.get(k, []), other.provenance.get(k, []))
            joined.a_regs[k] = jval
            joined.provenance[k] = prov
            joined.confidence[k] = conf

        # Join data registers
        for i in range(16):
            k = f"d{i}"
            v1 = self.get_d(i)
            v2 = other.get_d(i)
            jval, prov, conf = _lattice_join_value(v1, v2, self.provenance.get(k, []), other.provenance.get(k, []))
            joined.d_regs[k] = jval
            joined.provenance[k] = prov
            joined.confidence[k] = conf

        return joined

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address_registers": {k: self.a_regs[k].to_dict() for k in sorted(self.a_regs)},
            "data_registers": {k: self.d_regs[k].to_dict() for k in sorted(self.d_regs)},
        }


def _lattice_join_value(
    v1: AbstractValue,
    v2: AbstractValue,
    p1: List[str],
    p2: List[str],
) -> Tuple[AbstractValue, List[str], str]:
    """Compute least upper bound v1 ⊔ v2."""
    if v1 == v2:
        return v1, p1, "PROVEN"

    # If either is uninitialized, take the other
    if v1.unknown_reason == "UNINITIALIZED":
        return v2, p2, "PROVEN"
    if v2.unknown_reason == "UNINITIALIZED":
        return v1, p1, "PROVEN"

    # Divergent constants
    if v1.kind == AbstractValueKind.CONST and v2.kind == AbstractValueKind.CONST:
        if v1.concrete_value == v2.concrete_value:
            return v1, p1, "PROVEN"
        return AbstractValue.make_unknown("BRANCH_VALUE_DIVERGENCE"), p1 + p2, "UNCONFIRMED"

    # Divergent pointers
    if v1.kind == AbstractValueKind.PTR and v2.kind == AbstractValueKind.PTR:
        if v1.source_address == v2.source_address and v1.concrete_value == v2.concrete_value:
            return v1, p1, "PROVEN"
        return AbstractValue.make_unknown("DIVERGENT_POINTER_SOURCE"), p1 + p2, "UNCONFIRMED"

    # Divergent base offsets
    if v1.kind == AbstractValueKind.BASE_OFFSET and v2.kind == AbstractValueKind.BASE_OFFSET:
        if v1.base_reg == v2.base_reg and v1.offset == v2.offset:
            return v1, p1, "PROVEN"
        return AbstractValue.make_unknown("DIVERGENT_BASE_OFFSET"), p1 + p2, "UNCONFIRMED"

    # Fallback to sound UNKNOWN
    reason = f"INCOMPATIBLE_TYPES({v1.kind.value}_VS_{v2.kind.value})"
    return AbstractValue.make_unknown(reason), p1 + p2, "UNCONFIRMED"


# -----------------------------------------------------------------------------
# 4. Explicit Memory Model (Decoupled Retrieval & Endian Decoding)
# -----------------------------------------------------------------------------

@dataclass
class DecodedMemoryValue:
    """Formal record of memory byte retrieval and explicit endian decoding."""

    address: int
    raw_bytes_hex: str
    width_bytes: int
    endianness: str  # BE, LE, UNKNOWN
    decoded_value: Optional[int]
    endianness_evidence: str
    status: str  # PROVEN, UNKNOWN_ENDIANNESS, UNMAPPED_MEMORY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": f"0x{self.address:08X}",
            "raw_bytes_hex": self.raw_bytes_hex,
            "width_bytes": self.width_bytes,
            "endianness": self.endianness,
            "decoded_value": f"0x{self.decoded_value:08X}" if self.decoded_value is not None else None,
            "endianness_evidence": self.endianness_evidence,
            "status": self.status,
        }


class MemoryModel:
    """Encapsulates mapped binary images with explicit endianness discrimination."""

    def __init__(
        self,
        pa_reader: Optional[Callable[[int, int], Optional[bytes]]] = None,
        da_reader: Optional[Callable[[int, int], Optional[bytes]]] = None,
    ) -> None:
        self.pa_reader = pa_reader
        self.da_reader = da_reader

    def read_bytes(self, address: int, width: int) -> Optional[bytes]:
        """Retrieve raw byte sequence without endian assumption."""
        # Try PA first
        if self.pa_reader:
            b = self.pa_reader(address, width)
            if b is not None and len(b) == width:
                return b
        # Try DA second
        if self.da_reader:
            b = self.da_reader(address, width)
            if b is not None and len(b) == width:
                return b
        return None

    def decode_pointer(self, address: int, default_endianness: str = "UNKNOWN") -> DecodedMemoryValue:
        """Decode a 32-bit pointer at address with explicit endian justification."""
        raw = self.read_bytes(address, 4)
        if raw is None:
            return DecodedMemoryValue(
                address=address,
                raw_bytes_hex="",
                width_bytes=4,
                endianness="UNKNOWN",
                decoded_value=None,
                endianness_evidence="UNMAPPED_ADDRESS",
                status="UNMAPPED_MEMORY",
            )

        # Check static Big-Endian data table proof
        # 1. MAP_DESC_0001 descriptor in PA Segment 3 (0x000454A0..0x000454CF)
        # 2. Secondary pointer arrays in PA Segment 4 (0x0004BD00..0x0004BD9F)
        # 3. DA Directory Segment 4 (0x0007CA00..0x0007CAFF)
        if (
            (0x000454A0 <= address <= 0x000454D0)
            or (0x0004BD00 <= address <= 0x0004BD9F)
            or (0x0007CA00 <= address <= 0x0007CB00)
        ):
            endianness = "BE"
            evidence = "STATIC_DATA_ENCODING"
            val = struct.unpack(">I", raw)[0]
            status = "PROVEN"
        elif default_endianness in ("BE", "LE"):
            endianness = default_endianness
            evidence = "CALLER_EXPLICIT_ENDIAN"
            fmt = ">I" if endianness == "BE" else "<I"
            val = struct.unpack(fmt, raw)[0]
            status = "PROVEN"
        else:
            endianness = "UNKNOWN"
            evidence = "UNRESOLVED_DATA_ENDIANNESS"
            val = None
            status = "UNKNOWN_ENDIANNESS"

        return DecodedMemoryValue(
            address=address,
            raw_bytes_hex=raw.hex().upper(),
            width_bytes=4,
            endianness=endianness,
            decoded_value=val,
            endianness_evidence=evidence,
            status=status,
        )


# -----------------------------------------------------------------------------
# 5. Decoder-Based Instruction Boundary & Format Engine
# -----------------------------------------------------------------------------

@dataclass
class DecodedInstruction:
    """Validated TriCore instruction representation.

    Instruction boundary and validity are strictly determined by decoder recognition,
    NOT by address parity or length parity heuristics.
    """

    address: int
    raw_bytes: bytes
    length: int
    mnemonic: str
    operands: str
    format_class: str  # OP16, OP32
    decoder_status: str  # VALID, INVALID_INSTRUCTION_BOUNDARY, INVALID_DECODE, TRUNCATED_INSTRUCTION
    dest_reg: Optional[str] = None
    base_reg: Optional[str] = None
    source_reg: Optional[str] = None
    immediate: Optional[int] = None
    is_signed_immediate: bool = False
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": f"0x{self.address:08X}",
            "raw_hex": self.raw_bytes.hex().upper(),
            "length": self.length,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "format_class": self.format_class,
            "decoder_status": self.decoder_status,
            "dest_reg": self.dest_reg,
            "base_reg": self.base_reg,
            "immediate": f"0x{self.immediate:X}" if self.immediate is not None else None,
            "rejection_reason": self.rejection_reason,
        }


def decode_bol_off16(w32: int) -> int:
    """Decode TriCore BOL format 16-bit offset from little-endian 32-bit word.
    Formula from TriCore Architecture Reference:
    bits [5:0]   from w32[21:16]
    bits [9:6]   from w32[31:28]
    bits [15:10] from w32[27:22]
    """
    b0_5 = (w32 >> 16) & 0x3F
    b6_9 = (w32 >> 28) & 0x0F
    b10_15 = (w32 >> 22) & 0x3F
    return b0_5 | (b6_9 << 6) | (b10_15 << 10)


def sign_extend_16(val: int) -> int:
    """Sign-extend 16-bit signed integer to Python int."""
    val &= 0xFFFF
    return val - 0x10000 if (val & 0x8000) else val


def decode_instruction(data: bytes, address: int) -> DecodedInstruction:
    """Decode a single TriCore instruction at `address` strictly adhering to decoder validity rules.

    A candidate instruction is valid only if:
    1. Its start address is a decoder-recognized instruction boundary;
    2. The decoder recognizes the complete instruction format (OP16 | OP32);
    3. The decoder determines its actual instruction size (2 or 4 bytes).
    """
    if not data:
        return DecodedInstruction(
            address=address,
            raw_bytes=b"",
            length=0,
            mnemonic="INVALID",
            operands="",
            format_class="UNKNOWN",
            decoder_status="TRUNCATED_INSTRUCTION",
            rejection_reason="No bytes available at address",
        )

    b0 = data[0]
    is_32bit = (b0 & 1) == 1
    req_len = 4 if is_32bit else 2

    if len(data) < req_len:
        return DecodedInstruction(
            address=address,
            raw_bytes=data,
            length=len(data),
            mnemonic="TRUNCATED",
            operands="",
            format_class="UNKNOWN",
            decoder_status="TRUNCATED_INSTRUCTION",
            rejection_reason=f"Insufficient bytes ({len(data)} < {req_len})",
        )

    raw = data[:req_len]

    # -------------------------------------------------------------------------
    # 16-bit Instructions (OP16)
    # -------------------------------------------------------------------------
    if not is_32bit:
        w16 = struct.unpack("<H", raw)[0]
        # RET (0x0090)
        if raw == b"\x00\x90":
            return DecodedInstruction(address, raw, 2, "RET", "", "OP16", "VALID")
        # NOP (0x0000)
        if raw == b"\x00\x00":
            return DecodedInstruction(address, raw, 2, "NOP", "", "OP16", "VALID")
        # BISR: format SR, b0=0x04, b1=0x88 -> bisr const9
        if (b0 & 0x0F) == 0x04 and (raw[1] & 0xF0) == 0x80:
            const9 = ((raw[1] & 0x0F) << 4) | (b0 >> 4)
            return DecodedInstruction(address, raw, 2, "BISR", str(const9), "OP16", "VALID", immediate=const9)
        # General OP16
        return DecodedInstruction(address, raw, 2, "OP16", f"0x{w16:04X}", "OP16", "VALID")

    # -------------------------------------------------------------------------
    # 32-bit Instructions (OP32)
    # -------------------------------------------------------------------------
    w32 = struct.unpack("<I", raw)[0]
    op = b0

    # 1. MOVH.A %a[c], const16 (Opcode 0x91, RLC format)
    # w32: [7:0]=0x91, [11:8]=const[3:0], [15:12]=op2, [27:16]=const[15:4], [31:28]=reg_c
    if op == 0x91:
        reg_c = (w32 >> 28) & 0x0F
        c_low = (w32 >> 8) & 0x0F
        c_high = (w32 >> 16) & 0xFFF
        const16 = c_low | (c_high << 4)
        return DecodedInstruction(
            address=address,
            raw_bytes=raw,
            length=4,
            mnemonic="MOVH.A",
            operands=f"%a{reg_c}, 0x{const16:04X}",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg=f"a{reg_c}",
            immediate=const16,
            is_signed_immediate=False,
        )

    # 2. ADDIH.A %a[c], %a[b], const16 (Opcode 0x11, RLC format)
    # w32: [7:0]=0x11, [11:8]=const[3:0], [15:12]=reg_b, [27:16]=const[15:4], [31:28]=reg_c
    if op == 0x11:
        reg_c = (w32 >> 28) & 0x0F
        reg_b = (w32 >> 12) & 0x0F
        c_low = (w32 >> 8) & 0x0F
        c_high = (w32 >> 16) & 0xFFF
        const16 = c_low | (c_high << 4)
        return DecodedInstruction(
            address=address,
            raw_bytes=raw,
            length=4,
            mnemonic="ADDIH.A",
            operands=f"%a{reg_c}, %a{reg_b}, 0x{const16:04X}",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg=f"a{reg_c}",
            base_reg=f"a{reg_b}",
            immediate=const16,
            is_signed_immediate=False,
        )

    # 3. ADDI %d[c], %d[b], const16 (Opcode 0x1B, RLC format)
    if op == 0x1B:
        reg_c = (w32 >> 28) & 0x0F
        reg_b = (w32 >> 12) & 0x0F
        c_low = (w32 >> 8) & 0x0F
        c_high = (w32 >> 16) & 0xFFF
        const16 = c_low | (c_high << 4)
        s_const16 = sign_extend_16(const16)
        return DecodedInstruction(
            address=address,
            raw_bytes=raw,
            length=4,
            mnemonic="ADDI",
            operands=f"%d{reg_c}, %d{reg_b}, {s_const16}",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg=f"d{reg_c}",
            base_reg=f"d{reg_b}",
            immediate=s_const16,
            is_signed_immediate=True,
        )

    # 4. BOL format instructions:
    # w32: [7:0]=opcode, [11:8]=base_reg, [15:12]=dest/src_reg, offset decoded via decode_bol_off16
    # LEA (0xD9), LD.A (0x99), LD.W (0x19), LD.HU (0xB9), LD.B (0x79), LD.BU (0x39), ST.W (0x59), ST.H (0xF9), ST.B (0xE9)
    bol_opcodes = {
        0xD9: ("LEA", True, True),     # (mnemonic, is_a_base, is_a_dest)
        0x99: ("LD.A", True, True),
        0x19: ("LD.W", True, False),   # dest is d-reg
        0xB9: ("LD.HU", True, False),
        0x79: ("LD.B", True, False),
        0x39: ("LD.BU", True, False),
        0x59: ("ST.W", True, False),   # src is d-reg
        0xF9: ("ST.H", True, False),
        0xE9: ("ST.B", True, False),
    }
    if op in bol_opcodes:
        mnemonic, is_a_base, is_a_dest = bol_opcodes[op]
        base_num = (w32 >> 8) & 0x0F
        target_num = (w32 >> 12) & 0x0F
        off16 = decode_bol_off16(w32)
        s_off16 = sign_extend_16(off16)

        base_str = f"a{base_num}"
        dest_prefix = "a" if is_a_dest else "d"
        dest_str = f"{dest_prefix}{target_num}"

        sign = "+" if s_off16 >= 0 else "-"
        operands = f"%{dest_str}, [%{base_str} {sign} 0x{abs(s_off16):X}]"

        return DecodedInstruction(
            address=address,
            raw_bytes=raw,
            length=4,
            mnemonic=mnemonic,
            operands=operands,
            format_class="OP32",
            decoder_status="VALID",
            dest_reg=dest_str,
            base_reg=base_str,
            immediate=s_off16,
            is_signed_immediate=True,
        )

    # 5. Format RR: ADD.A (0x01 / 0x48), SUB.A (0x21 / 0x48)
    if op in (0x01, 0x21) and ((w32 >> 16) & 0xFF) == 0x48:
        mnemonic = "ADD.A" if op == 0x01 else "SUB.A"
        reg_c = (w32 >> 28) & 0x0F
        reg_b = (w32 >> 12) & 0x0F
        reg_a = (w32 >> 8) & 0x0F
        return DecodedInstruction(
            address=address,
            raw_bytes=raw,
            length=4,
            mnemonic=mnemonic,
            operands=f"%a{reg_c}, %a{reg_b}, %a{reg_a}",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg=f"a{reg_c}",
            base_reg=f"a{reg_b}",
            source_reg=f"a{reg_a}",
        )

    # Other 32-bit instruction
    return DecodedInstruction(
        address=address,
        raw_bytes=raw,
        length=4,
        mnemonic="OP32",
        operands=f"0x{w32:08X}",
        format_class="OP32",
        decoder_status="VALID",
    )


# -----------------------------------------------------------------------------
# 6. Transfer Function Engine & Target Access Gate
# -----------------------------------------------------------------------------

@dataclass
class TransferResult:
    """Outcome of applying a single TriCore instruction transfer function."""

    new_state: RegisterState
    instruction: DecodedInstruction
    effective_address: Optional[int] = None
    access_direction: Optional[str] = None  # TARGET_READ, TARGET_POINTER_READ, TARGET_WRITE, TARGET_ADDRESS_ONLY, None
    access_class: Optional[str] = None      # VALUE_LOAD, POINTER_LOAD, TABLE_LOOKUP, VALUE_STORE, POINTER_STORE, ADDRESS_ONLY, None
    target_match: Optional[str] = None      # Target ID if effective address hits canonical target
    consumer_proof_status: str = "UNCONFIRMED"  # PROVEN (only for TARGET_READ), UNCONFIRMED (for WRITE/ADDRESS_ONLY)
    audit_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instruction": self.instruction.to_dict(),
            "effective_address": f"0x{self.effective_address:08X}" if self.effective_address is not None else None,
            "access_direction": self.access_direction,
            "access_class": self.access_class,
            "target_match": self.target_match,
            "consumer_proof_status": self.consumer_proof_status,
            "audit_notes": self.audit_notes,
        }


def apply_transfer_function(
    inst: DecodedInstruction,
    state: RegisterState,
    memory: MemoryModel,
) -> TransferResult:
    """Apply transfer function tau(inst, state) -> TransferResult adhering to all 4 soundness rules."""
    new_state = state.copy()
    notes: List[str] = []

    if inst.decoder_status != "VALID":
        notes.append(f"REJECTED: Instruction boundary status is {inst.decoder_status}")
        return TransferResult(
            new_state=new_state,
            instruction=inst,
            consumer_proof_status="UNCONFIRMED",
            audit_notes=notes,
        )

    # -------------------------------------------------------------------------
    # 1. MOVH.A %a[c], const16 (Opcode 0x91)
    # -------------------------------------------------------------------------
    if inst.mnemonic == "MOVH.A" and inst.dest_reg and inst.immediate is not None:
        imm32 = ((inst.immediate & 0xFFFF) << 16) & 0xFFFFFFFF
        val = AbstractValue.make_const(imm32)
        prov = f"0x{inst.address:08X}: MOVH.A %{inst.dest_reg}, 0x{inst.immediate:04X} -> 0x{imm32:08X}"
        new_state.set_a(inst.dest_reg, val, prov, "PROVEN")
        notes.append(f"Assigned CONST(0x{imm32:08X}) to %{inst.dest_reg}")
        return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 2. LEA %a[c], [%a[b] + off16] (Opcode 0xD9)
    # -------------------------------------------------------------------------
    if inst.mnemonic == "LEA" and inst.dest_reg and inst.base_reg and inst.immediate is not None:
        base_val = state.get_a(inst.base_reg)
        s_off = inst.immediate

        # Correction #3: Concrete Pointer Preservation
        # PTR(source, concrete_val) + offset -> CONST(concrete_val + offset)
        if base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is not None:
            resolved_ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF
            val = AbstractValue.make_const(resolved_ea)
            prov = (
                f"0x{inst.address:08X}: LEA %{inst.dest_reg}, [%{inst.base_reg} + {s_off}] "
                f"derived from PTR(0x{base_val.source_address:08X}, 0x{base_val.concrete_value:08X}) -> CONST(0x{resolved_ea:08X})"
            )
            new_state.set_a(inst.dest_reg, val, prov, "PROVEN")
            notes.append(f"Preserved concrete PTR arithmetic: 0x{base_val.concrete_value:08X} + {s_off} = 0x{resolved_ea:08X}")

            # Evaluate target address only
            t_hit = find_containing_target(resolved_ea)
            target_tag = t_hit[0] if t_hit else None
            return TransferResult(
                new_state=new_state,
                instruction=inst,
                effective_address=resolved_ea,
                access_direction="TARGET_ADDRESS_ONLY" if target_tag else None,
                access_class="ADDRESS_ONLY" if target_tag else None,
                target_match=target_tag,
                consumer_proof_status="UNCONFIRMED",  # Address-only is NOT consumer proof!
                audit_notes=notes,
            )

        elif base_val.kind == AbstractValueKind.CONST and base_val.concrete_value is not None:
            resolved_ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF
            val = AbstractValue.make_const(resolved_ea)
            prov = f"0x{inst.address:08X}: LEA %{inst.dest_reg}, [%{inst.base_reg} + {s_off}] -> CONST(0x{resolved_ea:08X})"
            new_state.set_a(inst.dest_reg, val, prov, "PROVEN")

            t_hit = find_containing_target(resolved_ea)
            target_tag = t_hit[0] if t_hit else None
            return TransferResult(
                new_state=new_state,
                instruction=inst,
                effective_address=resolved_ea,
                access_direction="TARGET_ADDRESS_ONLY" if target_tag else None,
                access_class="ADDRESS_ONLY" if target_tag else None,
                target_match=target_tag,
                consumer_proof_status="UNCONFIRMED",
                audit_notes=notes,
            )

        elif base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is None and base_val.source_address is not None:
            # Loaded pointer value unknown -> PTR_OFFSET
            val = AbstractValue.make_ptr_offset(base_val.source_address, s_off)
            prov = f"0x{inst.address:08X}: LEA on unresolved PTR -> PTR_OFFSET(0x{base_val.source_address:08X}, {s_off})"
            new_state.set_a(inst.dest_reg, val, prov, "PARTIAL")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

        elif base_val.kind == AbstractValueKind.BASE_OFFSET and base_val.base_reg:
            val = AbstractValue.make_base_offset(base_val.base_reg, base_val.offset + s_off)
            prov = f"0x{inst.address:08X}: LEA on BASE_OFFSET -> BASE({base_val.base_reg} + {base_val.offset + s_off})"
            new_state.set_a(inst.dest_reg, val, prov, "PARTIAL")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

        else:
            # Sound UNKNOWN propagation
            val = AbstractValue.make_unknown("LEA_ON_UNKNOWN_BASE")
            prov = f"0x{inst.address:08X}: LEA on UNKNOWN base %{inst.base_reg}"
            new_state.set_a(inst.dest_reg, val, prov, "UNCONFIRMED")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 3. ADDIH.A %a[c], %a[b], const16 (Opcode 0x11)
    # -------------------------------------------------------------------------
    if inst.mnemonic == "ADDIH.A" and inst.dest_reg and inst.base_reg and inst.immediate is not None:
        base_val = state.get_a(inst.base_reg)
        shift_imm = ((inst.immediate & 0xFFFF) << 16) & 0xFFFFFFFF

        if base_val.kind == AbstractValueKind.CONST and base_val.concrete_value is not None:
            res = (base_val.concrete_value + shift_imm) & 0xFFFFFFFF
            val = AbstractValue.make_const(res)
            prov = f"0x{inst.address:08X}: ADDIH.A %{inst.dest_reg}, %{inst.base_reg}, 0x{inst.immediate:04X} -> CONST(0x{res:08X})"
            new_state.set_a(inst.dest_reg, val, prov, "PROVEN")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

        elif base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is not None:
            res = (base_val.concrete_value + shift_imm) & 0xFFFFFFFF
            val = AbstractValue.make_const(res)
            prov = f"0x{inst.address:08X}: ADDIH.A on concrete PTR -> CONST(0x{res:08X})"
            new_state.set_a(inst.dest_reg, val, prov, "PROVEN")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

        else:
            val = AbstractValue.make_unknown("ADDIH.A_ON_UNKNOWN_BASE")
            new_state.set_a(inst.dest_reg, val, f"0x{inst.address:08X}: ADDIH.A on UNKNOWN", "UNCONFIRMED")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 4. ADDI %d[c], %d[b], const16 (Opcode 0x1B)
    # -------------------------------------------------------------------------
    if inst.mnemonic == "ADDI" and inst.dest_reg and inst.base_reg and inst.immediate is not None:
        d_val = state.get_d(inst.base_reg)
        if d_val.kind == AbstractValueKind.CONST and d_val.concrete_value is not None:
            res = (d_val.concrete_value + inst.immediate) & 0xFFFFFFFF
            val = AbstractValue.make_const(res)
            prov = f"0x{inst.address:08X}: ADDI %{inst.dest_reg}, %{inst.base_reg}, {inst.immediate} -> CONST(0x{res:08X})"
            new_state.set_d(inst.dest_reg, val, prov, "PROVEN")
        else:
            val = AbstractValue.make_unknown("ADDI_ON_UNKNOWN_DATA")
            new_state.set_d(inst.dest_reg, val, f"0x{inst.address:08X}: ADDI on UNKNOWN", "UNCONFIRMED")
        return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 5. ADD.A %a[c], %a[b], %a[a] / SUB.A %a[c], %a[b], %a[a] (Format RR)
    # -------------------------------------------------------------------------
    if inst.mnemonic in ("ADD.A", "SUB.A") and inst.dest_reg and inst.base_reg and inst.source_reg:
        b_val = state.get_a(inst.base_reg)
        a_val = state.get_a(inst.source_reg)

        if b_val.is_concrete() and a_val.is_concrete() and b_val.concrete_value is not None and a_val.concrete_value is not None:
            res = (b_val.concrete_value + a_val.concrete_value) if inst.mnemonic == "ADD.A" else (b_val.concrete_value - a_val.concrete_value)
            res &= 0xFFFFFFFF
            val = AbstractValue.make_const(res)
            prov = f"0x{inst.address:08X}: {inst.mnemonic} -> CONST(0x{res:08X})"
            new_state.set_a(inst.dest_reg, val, prov, "PROVEN")
        else:
            val = AbstractValue.make_unknown(f"{inst.mnemonic}_NON_CONCRETE")
            new_state.set_a(inst.dest_reg, val, f"0x{inst.address:08X}: {inst.mnemonic} non-concrete", "UNCONFIRMED")
        return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 6. LD.A %a[c], [%a[b] + off16] (Opcode 0x99)
    # -------------------------------------------------------------------------
    if inst.mnemonic == "LD.A" and inst.dest_reg and inst.base_reg and inst.immediate is not None:
        base_val = state.get_a(inst.base_reg)
        s_off = inst.immediate

        # Calculate effective address
        ea = None
        if base_val.kind == AbstractValueKind.CONST and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF
        elif base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF

        if ea is not None:
            # Correction #2: Explicit Memory Endianness Decoding
            mem_decode = memory.decode_pointer(ea)
            if mem_decode.status == "PROVEN" and mem_decode.decoded_value is not None:
                loaded_ptr = mem_decode.decoded_value
                # Check if loaded pointer matches target or descriptor field
                tag = None
                t_hit = find_containing_target(loaded_ptr)
                if t_hit:
                    tag = t_hit[0]
                elif loaded_ptr in SECONDARY_STRUCTURES:
                    tag = SECONDARY_STRUCTURES[loaded_ptr]
                elif loaded_ptr in DESCRIPTOR_FIELDS:
                    tag = DESCRIPTOR_FIELDS[loaded_ptr]

                val = AbstractValue.make_ptr(ea, loaded_ptr, tag)
                prov = f"0x{inst.address:08X}: LD.A [%{inst.base_reg} + {s_off}] reads MEM[0x{ea:08X}] -> PTR(0x{loaded_ptr:08X}, endian={mem_decode.endianness})"
                new_state.set_a(inst.dest_reg, val, prov, "PROVEN")

                # Check if EA itself is in a target table (TARGET_POINTER_READ)
                ea_hit = find_containing_target(ea)
                access_dir = "TARGET_POINTER_READ" if ea_hit else None
                proof_stat = "PROVEN" if ea_hit else "UNCONFIRMED"

                return TransferResult(
                    new_state=new_state,
                    instruction=inst,
                    effective_address=ea,
                    access_direction=access_dir,
                    access_class="POINTER_LOAD",
                    target_match=ea_hit[0] if ea_hit else None,
                    consumer_proof_status=proof_stat,
                    audit_notes=notes,
                )
            else:
                val = AbstractValue.make_unknown(f"LD.A_DECODE_FAILED_{mem_decode.status}")
                new_state.set_a(inst.dest_reg, val, f"0x{inst.address:08X}: LD.A failed at 0x{ea:08X}", "UNCONFIRMED")
                return TransferResult(new_state=new_state, instruction=inst, effective_address=ea, audit_notes=notes)
        else:
            val = AbstractValue.make_unknown("LD.A_ON_NON_CONCRETE_EA")
            new_state.set_a(inst.dest_reg, val, f"0x{inst.address:08X}: LD.A on non-concrete EA", "UNCONFIRMED")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 7. Target Reads: LD.W (0x19), LD.HU (0xB9), LD.B (0x79), LD.BU (0x39)
    # -------------------------------------------------------------------------
    if inst.mnemonic in ("LD.W", "LD.HU", "LD.B", "LD.BU") and inst.base_reg and inst.dest_reg and inst.immediate is not None:
        base_val = state.get_a(inst.base_reg)
        s_off = inst.immediate

        ea = None
        if base_val.kind == AbstractValueKind.CONST and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF
        elif base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF

        if ea is not None:
            t_hit = find_containing_target(ea)
            if t_hit:
                # Correction #4: Valid TARGET_READ satisfies consumer proof!
                tid, trange = t_hit
                val = AbstractValue.make_unknown(f"CALIBRATION_VALUE_LOADED_FROM_{tid}")
                prov = f"0x{inst.address:08X}: {inst.mnemonic} reads MEM[0x{ea:08X}] in {tid}"
                new_state.set_d(inst.dest_reg, val, prov, "PROVEN")
                notes.append(f"PROVEN TARGET_READ: {inst.mnemonic} reads canonical target {tid} at 0x{ea:08X}")

                return TransferResult(
                    new_state=new_state,
                    instruction=inst,
                    effective_address=ea,
                    access_direction="TARGET_READ",
                    access_class="VALUE_LOAD",
                    target_match=tid,
                    consumer_proof_status="PROVEN",
                    audit_notes=notes,
                )
            else:
                val = AbstractValue.make_unknown("GENERIC_LOAD")
                new_state.set_d(inst.dest_reg, val, f"0x{inst.address:08X}: {inst.mnemonic} generic load", "UNCONFIRMED")
                return TransferResult(new_state=new_state, instruction=inst, effective_address=ea, audit_notes=notes)
        else:
            val = AbstractValue.make_unknown("LOAD_ON_NON_CONCRETE_EA")
            new_state.set_d(inst.dest_reg, val, f"0x{inst.address:08X}: Load on non-concrete EA", "UNCONFIRMED")
            return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)

    # -------------------------------------------------------------------------
    # 8. Target Writes: ST.W (0x59), ST.H (0xF9), ST.B (0xE9)
    # -------------------------------------------------------------------------
    if inst.mnemonic in ("ST.W", "ST.H", "ST.B") and inst.base_reg and inst.immediate is not None:
        base_val = state.get_a(inst.base_reg)
        s_off = inst.immediate

        ea = None
        if base_val.kind == AbstractValueKind.CONST and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF
        elif base_val.kind == AbstractValueKind.PTR and base_val.concrete_value is not None:
            ea = (base_val.concrete_value + s_off) & 0xFFFFFFFF

        if ea is not None:
            t_hit = find_containing_target(ea)
            if t_hit:
                # Correction #4: Store is TARGET_WRITE; does NOT prove consumer!
                tid, _ = t_hit
                notes.append(f"TARGET_WRITE: {inst.mnemonic} writes to {tid} at 0x{ea:08X}; consumer status UNCONFIRMED")
                return TransferResult(
                    new_state=new_state,
                    instruction=inst,
                    effective_address=ea,
                    access_direction="TARGET_WRITE",
                    access_class="VALUE_STORE",
                    target_match=tid,
                    consumer_proof_status="UNCONFIRMED",
                    audit_notes=notes,
                )

    # Default pass-through
    return TransferResult(new_state=new_state, instruction=inst, audit_notes=notes)
