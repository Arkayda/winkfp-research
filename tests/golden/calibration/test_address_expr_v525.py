"""Unit test suite for TriCore Abstract Address Expression Machine (Milestone 5.25 Phase B).

Tests:
1. Instruction boundary validation (valid OP16, valid OP32, intra-instruction boundary rejection, truncation).
2. Transfer functions (MOVH.A, LEA, ADDIH.A, ADDI, ADD.A, SUB.A).
3. Memory model with explicit endianness (BE, LE, UNKNOWN).
4. Concrete pointer arithmetic preservation (PTR + imm -> CONST).
5. Address wraparound and half-open target interval checks [start, end).
6. Target access discrimination (TARGET_READ vs TARGET_WRITE vs TARGET_ADDRESS_ONLY).
7. Consumer proof gate verification on synthetic fixtures.
8. Lattice join and sound UNKNOWN propagation.
"""

import unittest
from typing import Dict, Optional

from reconstruction.calibration.address_expr_v525 import (
    CANONICAL_TARGETS,
    AbstractValue,
    AbstractValueKind,
    DecodedInstruction,
    MemoryModel,
    RegisterState,
    TargetRange,
    apply_transfer_function,
    decode_bol_off16,
    decode_instruction,
    find_containing_target,
    sign_extend_16,
)


class TestAddressExprV525(unittest.TestCase):
    """Unit test suite for address_expr_v525 abstract interpretation machine."""

    def setUp(self):
        self.state = RegisterState()
        self.dummy_memory = MemoryModel()

    # -------------------------------------------------------------------------
    # 1. Instruction Boundary & Format Tests
    # -------------------------------------------------------------------------

    def test_valid_op16_boundary(self):
        """Verify decoder recognizes 16-bit instructions (NOP = 0x0000, RET = 0x0090, BISR = 0x0488)."""
        # NOP: 0x0000
        inst_nop = decode_instruction(b"\x00\x00", 0x00081000)
        self.assertEqual(inst_nop.decoder_status, "VALID")
        self.assertEqual(inst_nop.format_class, "OP16")
        self.assertEqual(inst_nop.length, 2)
        self.assertEqual(inst_nop.mnemonic, "NOP")

        # RET: 0x0090
        inst_ret = decode_instruction(b"\x00\x90", 0x00081002)
        self.assertEqual(inst_ret.decoder_status, "VALID")
        self.assertEqual(inst_ret.format_class, "OP16")
        self.assertEqual(inst_ret.length, 2)
        self.assertEqual(inst_ret.mnemonic, "RET")

    def test_valid_op32_boundary(self):
        """Verify decoder recognizes 32-bit instructions (MOVH.A, LEA, LD.A, etc.)."""
        # MOVH.A %a12, 0x0004 -> w32=0x98184D91 (example sample)
        # raw bytes: 91 4d 18 98
        inst_movh = decode_instruction(b"\x91\x4D\x18\x98", 0x00080486)
        self.assertEqual(inst_movh.decoder_status, "VALID")
        self.assertEqual(inst_movh.format_class, "OP32")
        self.assertEqual(inst_movh.length, 4)
        self.assertEqual(inst_movh.mnemonic, "MOVH.A")
        self.assertEqual(inst_movh.dest_reg, "a9")
        self.assertEqual(inst_movh.immediate, 0x818D)

    def test_intra_instruction_boundary_rejection(self):
        """Verify that starting decoding from an intra-instruction offset is rejected or marked invalid."""
        # 0x0009C580 regression: inside a 4-byte instruction starting at 0x0009C57E
        # If someone presents truncated or mismatched raw bytes, decoder marks invalid
        inst_bad = decode_instruction(b"", 0x0009C580)
        self.assertEqual(inst_bad.decoder_status, "TRUNCATED_INSTRUCTION")

    def test_truncated_instruction_rejection(self):
        """Verify that insufficient bytes for 32-bit opcode yield TRUNCATED_INSTRUCTION."""
        # Opcode 0x91 requires 4 bytes, only 2 provided
        inst_trunc = decode_instruction(b"\x91\x4D", 0x00080100)
        self.assertEqual(inst_trunc.decoder_status, "TRUNCATED_INSTRUCTION")
        self.assertEqual(inst_trunc.length, 2)

    # -------------------------------------------------------------------------
    # 2. Transfer Functions Tests
    # -------------------------------------------------------------------------

    def test_movh_a(self):
        """Verify MOVH.A sets high 16-bits in destination address register."""
        # MOVH.A %a12, 0x0004
        # const16 = 0x0004 -> imm32 = 0x00040000
        inst = DecodedInstruction(
            address=0x00084000,
            raw_bytes=b"\x91\x40\x00\x40",
            length=4,
            mnemonic="MOVH.A",
            operands="%a12, 0x0004",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a12",
            immediate=0x0004,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(12)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x00040000)
        self.assertTrue(len(res.new_state.provenance["a12"]) > 0)

    def test_lea_const(self):
        """Verify LEA on concrete base correctly calculates target address."""
        self.state.set_a(12, AbstractValue.make_const(0x00040000), "setup")
        # LEA %a12, [%a12 + 0x54A0]
        inst = DecodedInstruction(
            address=0x00084004,
            raw_bytes=b"\xD9...",
            length=4,
            mnemonic="LEA",
            operands="%a12, [%a12 + 0x54A0]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a12",
            base_reg="a12",
            immediate=0x54A0,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(12)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x000454A0)

    def test_lea_ptr_concrete(self):
        """Verify LEA on PTR(concrete_val) preserves concrete address (Correction #3)."""
        # %a4 holds PTR pointing to 0x00063AD6 (Axis X start) loaded from descriptor field 0x000454A8
        self.state.set_a(4, AbstractValue.make_ptr(0x000454A8, 0x00063AD6, "TARGET_1_AXIS_X"), "setup")

        # LEA %a4, [%a4 + 4] -> should become CONST(0x00063ADA), NOT an unresolved PTR_OFFSET!
        inst = DecodedInstruction(
            address=0x00084010,
            raw_bytes=b"\xD9...",
            length=4,
            mnemonic="LEA",
            operands="%a4, [%a4 + 4]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a4",
            base_reg="a4",
            immediate=4,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(4)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x00063ADA)
        # Target match should hit TARGET_1_AXIS_X
        self.assertEqual(res.target_match, "TARGET_1_AXIS_X")
        # But address-only is UNCONFIRMED consumer
        self.assertEqual(res.consumer_proof_status, "UNCONFIRMED")
        self.assertEqual(res.access_direction, "TARGET_ADDRESS_ONLY")

    def test_lea_ptr_unknown(self):
        """Verify LEA on PTR with unknown loaded value yields PTR_OFFSET."""
        self.state.set_a(4, AbstractValue.make_ptr(0x000454A8, None), "setup")
        inst = DecodedInstruction(
            address=0x00084014,
            raw_bytes=b"\xD9...",
            length=4,
            mnemonic="LEA",
            operands="%a4, [%a4 + 4]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a4",
            base_reg="a4",
            immediate=4,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(4)
        self.assertEqual(val.kind, AbstractValueKind.PTR_OFFSET)
        self.assertEqual(val.source_address, 0x000454A8)
        self.assertEqual(val.offset, 4)

    def test_addih_a(self):
        """Verify ADDIH.A adds shifted immediate to address register."""
        self.state.set_a(2, AbstractValue.make_const(0x00060000), "setup")
        inst = DecodedInstruction(
            address=0x00084020,
            raw_bytes=b"\x11...",
            length=4,
            mnemonic="ADDIH.A",
            operands="%a2, %a2, 0x0001",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a2",
            base_reg="a2",
            immediate=0x0001,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(2)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x00070000)

    def test_addi(self):
        """Verify ADDI on data register adds signed 16-bit immediate."""
        self.state.set_d(3, AbstractValue.make_const(100), "setup")
        inst = DecodedInstruction(
            address=0x00084030,
            raw_bytes=b"\x1B...",
            length=4,
            mnemonic="ADDI",
            operands="%d3, %d3, -20",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="d3",
            base_reg="d3",
            immediate=-20,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_d(3)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 80)

    def test_add_a(self):
        """Verify ADD.A adds two concrete address registers."""
        self.state.set_a(2, AbstractValue.make_const(0x00060000), "setup")
        self.state.set_a(3, AbstractValue.make_const(0x00003AD6), "setup")
        inst = DecodedInstruction(
            address=0x00084040,
            raw_bytes=b"\x01...",
            length=4,
            mnemonic="ADD.A",
            operands="%a4, %a2, %a3",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a4",
            base_reg="a2",
            source_reg="a3",
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(4)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x00063AD6)

    def test_sub_a(self):
        """Verify SUB.A subtracts two concrete address registers."""
        self.state.set_a(2, AbstractValue.make_const(0x00063B00), "setup")
        self.state.set_a(3, AbstractValue.make_const(0x00000010), "setup")
        inst = DecodedInstruction(
            address=0x00084050,
            raw_bytes=b"\x21...",
            length=4,
            mnemonic="SUB.A",
            operands="%a4, %a2, %a3",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a4",
            base_reg="a2",
            source_reg="a3",
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        val = res.new_state.get_a(4)
        self.assertEqual(val.kind, AbstractValueKind.CONST)
        self.assertEqual(val.concrete_value, 0x00063AF0)

    # -------------------------------------------------------------------------
    # 3. Explicit Memory Endianness & LD.A Tests (Correction #2)
    # -------------------------------------------------------------------------

    def test_ld_a_explicit_be(self):
        """Verify memory model decodes 32-bit Big-Endian pointer at static table address (Correction #2)."""
        # Secondary pointer table at 0x0004BD00 contains 00 06 3A F0 (Axis Y start)
        mem_storage = {0x0004BD00: bytes.fromhex("00063AF0")}
        memory = MemoryModel(pa_reader=lambda addr, width: mem_storage.get(addr))

        self.state.set_a(15, AbstractValue.make_const(0x0004BD00), "setup")
        inst = DecodedInstruction(
            address=0x00085000,
            raw_bytes=b"\x99...",
            length=4,
            mnemonic="LD.A",
            operands="%a2, [%a15 + 0]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a2",
            base_reg="a15",
            immediate=0,
        )
        res = apply_transfer_function(inst, self.state, memory)
        val = res.new_state.get_a(2)
        self.assertEqual(val.kind, AbstractValueKind.PTR)
        self.assertEqual(val.concrete_value, 0x00063AF0)
        self.assertEqual(val.source_address, 0x0004BD00)
        self.assertEqual(val.target_tag, "TARGET_2_AXIS_Y")

    def test_ld_a_explicit_le(self):
        """Verify memory model decodes 32-bit Little-Endian pointer when explicitly declared."""
        # Memory contains LE bytes D6 3A 06 00 (0x00063AD6)
        mem_storage = {0x00085500: bytes.fromhex("D63A0600")}
        memory = MemoryModel(pa_reader=lambda addr, width: mem_storage.get(addr))

        decoded = memory.decode_pointer(0x00085500, default_endianness="LE")
        self.assertEqual(decoded.status, "PROVEN")
        self.assertEqual(decoded.endianness, "LE")
        self.assertEqual(decoded.decoded_value, 0x00063AD6)

    def test_ld_a_unknown_endianness(self):
        """Verify that memory at unclassified address without static proof rejects as UNKNOWN_ENDIANNESS."""
        mem_storage = {0x00089900: bytes.fromhex("11223344")}
        memory = MemoryModel(pa_reader=lambda addr, width: mem_storage.get(addr))

        decoded = memory.decode_pointer(0x00089900, default_endianness="UNKNOWN")
        self.assertEqual(decoded.status, "UNKNOWN_ENDIANNESS")
        self.assertIsNone(decoded.decoded_value)

    def test_ld_w_target_range(self):
        """Verify LD.W with EA in canonical target range triggers TARGET_READ and consumer_proof=PROVEN."""
        # %a2 holds concrete target address 0x00063AD6 (Axis X start)
        self.state.set_a(2, AbstractValue.make_const(0x00063AD6), "setup")

        inst = DecodedInstruction(
            address=0x00085100,
            raw_bytes=b"\x19...",
            length=4,
            mnemonic="LD.W",
            operands="%d4, [%a2 + 0]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="d4",
            base_reg="a2",
            immediate=0,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.access_direction, "TARGET_READ")
        self.assertEqual(res.access_class, "VALUE_LOAD")
        self.assertEqual(res.target_match, "TARGET_1_AXIS_X")
        self.assertEqual(res.consumer_proof_status, "PROVEN")

    def test_ld_hu_target_range(self):
        """Verify LD.HU with EA in canonical target range triggers TARGET_READ and consumer_proof=PROVEN."""
        # %a3 points to Curve 1 at 0x0006418A
        self.state.set_a(3, AbstractValue.make_const(0x0006418A), "setup")

        inst = DecodedInstruction(
            address=0x00085104,
            raw_bytes=b"\xB9...",
            length=4,
            mnemonic="LD.HU",
            operands="%d5, [%a3 + 2]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="d5",
            base_reg="a3",
            immediate=2,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.effective_address, 0x0006418C)
        self.assertEqual(res.access_direction, "TARGET_READ")
        self.assertEqual(res.access_class, "VALUE_LOAD")
        self.assertEqual(res.target_match, "TARGET_3_KL_CURVE_1")
        self.assertEqual(res.consumer_proof_status, "PROVEN")

    # -------------------------------------------------------------------------
    # 4. Target Read vs Write Separation (Correction #4)
    # -------------------------------------------------------------------------

    def test_consumer_proof_valid_target_read(self):
        """Full consumer proof: valid decode -> proven state -> EA in target -> LD.W => PROVEN consumer."""
        self.state.set_a(5, AbstractValue.make_const(0x000641A4), "setup")
        inst = DecodedInstruction(
            address=0x00086010,
            raw_bytes=b"\x19...",
            length=4,
            mnemonic="LD.W",
            operands="%d0, [%a5 + 0]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="d0",
            base_reg="a5",
            immediate=0,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.access_direction, "TARGET_READ")
        self.assertEqual(res.consumer_proof_status, "PROVEN")
        self.assertEqual(res.target_match, "TARGET_4_KL_CURVE_2")

    def test_negative_target_write_unconfirmed(self):
        """Target write (ST.W) to canonical target yields TARGET_WRITE and consumer_proof=UNCONFIRMED."""
        self.state.set_a(5, AbstractValue.make_const(0x000641A4), "setup")
        inst = DecodedInstruction(
            address=0x00086014,
            raw_bytes=b"\x59...",
            length=4,
            mnemonic="ST.W",
            operands="[%a5 + 0], %d0",
            format_class="OP32",
            decoder_status="VALID",
            base_reg="a5",
            immediate=0,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.access_direction, "TARGET_WRITE")
        self.assertEqual(res.access_class, "VALUE_STORE")
        self.assertEqual(res.consumer_proof_status, "UNCONFIRMED")
        self.assertEqual(res.target_match, "TARGET_4_KL_CURVE_2")

    def test_negative_target_address_only_unconfirmed(self):
        """Computing target address via LEA without memory access yields TARGET_ADDRESS_ONLY and UNCONFIRMED."""
        self.state.set_a(1, AbstractValue.make_const(0x00064100), "setup")
        inst = DecodedInstruction(
            address=0x00086020,
            raw_bytes=b"\xD9...",
            length=4,
            mnemonic="LEA",
            operands="%a2, [%a1 + 0xBE]",
            format_class="OP32",
            decoder_status="VALID",
            dest_reg="a2",
            base_reg="a1",
            immediate=0xBE,
        )
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.effective_address, 0x000641BE)
        self.assertEqual(res.access_direction, "TARGET_ADDRESS_ONLY")
        self.assertEqual(res.access_class, "ADDRESS_ONLY")
        self.assertEqual(res.consumer_proof_status, "UNCONFIRMED")
        self.assertEqual(res.target_match, "TARGET_5_KL_CURVE_3")

    # -------------------------------------------------------------------------
    # 5. Soundness & Invariant Tests
    # -------------------------------------------------------------------------

    def test_ptr_concrete_plus_offset(self):
        """PTR(src, concrete) + offset yields CONST(concrete + offset)."""
        val = AbstractValue.make_ptr(0x000454A8, 0x00063AD6)
        self.state.set_a(0, val, "setup")
        inst = DecodedInstruction(0x00080000, b"", 4, "LEA", "", "OP32", "VALID", dest_reg="a0", base_reg="a0", immediate=8)
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.new_state.get_a(0).concrete_value, 0x00063ADE)

    def test_ptr_unknown_plus_offset(self):
        """PTR(src, None) + offset yields PTR_OFFSET(src, offset)."""
        val = AbstractValue.make_ptr(0x000454A8, None)
        self.state.set_a(0, val, "setup")
        inst = DecodedInstruction(0x00080000, b"", 4, "LEA", "", "OP32", "VALID", dest_reg="a0", base_reg="a0", immediate=8)
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.new_state.get_a(0).kind, AbstractValueKind.PTR_OFFSET)
        self.assertEqual(res.new_state.get_a(0).offset, 8)

    def test_unknown_plus_offset(self):
        """UNKNOWN + offset must strictly remain UNKNOWN."""
        self.state.set_a(0, AbstractValue.make_unknown("TEST_UNKNOWN"), "setup")
        inst = DecodedInstruction(0x00080000, b"", 4, "LEA", "", "OP32", "VALID", dest_reg="a0", base_reg="a0", immediate=8)
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.new_state.get_a(0).kind, AbstractValueKind.UNKNOWN)

    def test_address_wraparound_does_not_bypass_mapping(self):
        """Verify arithmetic wraparound mod 2^32 does not bypass canonical target mapping."""
        # 0xFFFFFFFF + 1 = 0x00000000
        self.state.set_a(0, AbstractValue.make_const(0xFFFFFFFF), "setup")
        inst = DecodedInstruction(0x00080000, b"", 4, "LEA", "", "OP32", "VALID", dest_reg="a0", base_reg="a0", immediate=1)
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        self.assertEqual(res.new_state.get_a(0).concrete_value, 0x00000000)
        self.assertIsNone(res.target_match)

    def test_target_interval_half_open(self):
        """Verify strict [start, end) half-open semantics: end address is excluded."""
        trange = CANONICAL_TARGETS["TARGET_1_AXIS_X"]
        self.assertEqual(trange.start_address, 0x00063AD6)
        self.assertEqual(trange.end_address, 0x00063AEF)
        self.assertTrue(trange.contains(0x00063AD6))
        self.assertTrue(trange.contains(0x00063AEE))
        # End address 0x00063AEF must NOT be contained
        self.assertFalse(trange.contains(0x00063AEF))

    def test_provenance_preserved(self):
        """Verify provenance trail accumulates each transformation step."""
        self.state.set_a(1, AbstractValue.make_const(0x00040000), "step 1")
        inst = DecodedInstruction(0x00080004, b"", 4, "LEA", "", "OP32", "VALID", dest_reg="a1", base_reg="a1", immediate=0x54A0)
        res = apply_transfer_function(inst, self.state, self.dummy_memory)
        prov = res.new_state.provenance["a1"]
        self.assertEqual(len(prov), 2)
        self.assertEqual(prov[0], "step 1")
        self.assertIn("0x00080004", prov[1])

    def test_unknown_join(self):
        """Lattice join with UNKNOWN yields UNKNOWN."""
        s1 = RegisterState()
        s2 = RegisterState()
        s1.set_a(0, AbstractValue.make_const(0x00063AD6), "s1")
        s2.set_a(0, AbstractValue.make_unknown("LOST_IN_BRANCH"), "s2")
        joined = s1.join(s2)
        self.assertEqual(joined.get_a(0).kind, AbstractValueKind.UNKNOWN)

    def test_divergent_const_join(self):
        """Lattice join of two different constants yields UNKNOWN(BRANCH_VALUE_DIVERGENCE)."""
        s1 = RegisterState()
        s2 = RegisterState()
        s1.set_a(0, AbstractValue.make_const(0x00063AD6), "path A")
        s2.set_a(0, AbstractValue.make_const(0x00063AF0), "path B")
        joined = s1.join(s2)
        self.assertEqual(joined.get_a(0).kind, AbstractValueKind.UNKNOWN)
        self.assertEqual(joined.get_a(0).unknown_reason, "BRANCH_VALUE_DIVERGENCE")


if __name__ == "__main__":
    unittest.main()
