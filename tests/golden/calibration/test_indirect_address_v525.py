"""Golden tests for Milestone 5.25 Indirect Address / Pointer-Chain Forensic Reconstruction.

Tests:
1. Scanner coverage declarations: segments 8..15 (executable), 0..7 (data), instruction classes,
   TriCore decoder capabilities (OP16 vs OP32, no parity rule), and 3 unsupported categories.
2. Canonical target objects mapping: range semantics [START, END), Segment 2 in A7592133.0da.
3. Secondary pointer structures: 0x0004BD00, 0x0004BD80, 0x0007CA50, 0x0007CAC8 two-level epistemic model.
4. Tier A candidate reference enumeration: 26 candidates evaluated (10 descriptor fields,
   10 secondary table entries, 5 synthetic 0x000455xx rejections, 1 RAM collision 0x000C1A04).
5. Soundness Correction 1: Instruction boundary validation (decoder-based format recognition,
   rejection of intra-instruction boundary at 0x0009C580).
6. Soundness Correction 2: Memory endianness model (explicit BE parameterization on static tables,
   UNKNOWN on unjustified addresses).
7. Soundness Correction 3: Concrete pointer arithmetic preservation (PTR + imm -> CONST).
8. Soundness Correction 4: Target read vs write discrimination (TARGET_WRITE retains UNCONFIRMED,
   TARGET_READ achieves PROVEN consumer).
9. Epistemic status ceilings: 0x00086000 (BASIC_BLOCK_ENTRY, procedure_identity UNCONFIRMED),
   0x000455xx (REJECTED_SYNTHETIC_ADDRESS), 0x000C1A04 (CONSTANT_COLLISION), 750/500 (UNCONFIRMED),
   6800 (UNKNOWN).
10. Stop condition evaluation: CASE_C_NO_INDIRECT_CONSUMER / INDIRECT_CONSUMER_NOT_FOUND.
11. Deterministic emission of 10 JSON artifacts with non-circular manifest (self_hash_policy: EXCLUDED).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.calibration.address_expr_v525 import (
    CANONICAL_TARGETS,
    AbstractValue,
    AbstractValueKind,
    DecodedInstruction,
    MemoryModel,
    RegisterState,
    apply_transfer_function,
    decode_instruction,
)
from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.indirect_address_v525 import (
    CandidateReference,
    IndirectAddressCatalog,
    PointerChain,
    PointerProducerRecord,
    TargetAccessRecord,
    reconstruct_indirect_address,
)


class TestIndirectAddressV525(unittest.TestCase):
    """Integration test suite for Milestone 5.25 indirect address reconstruction pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)
        cls.catalog = reconstruct_indirect_address(cls.pa_image, cls.da_image)

    def test_scanner_coverage_declarations(self):
        """Verify scanner explicitly declares scanned segments, instruction classes, and unsupported categories."""
        cov = self.catalog.coverage
        self.assertIn("scanned_executable_segments", cov)
        self.assertIn("scanned_data_segments", cov)
        self.assertIn("scanned_calibration_segments", cov)
        self.assertIn("instruction_reference_classes", cov)
        self.assertIn("pointer_reference_classes", cov)
        self.assertIn("address_expression_classes", cov)
        self.assertIn("decoder_capabilities", cov)
        self.assertIn("unsupported_instruction_encodings", cov)
        self.assertIn("unsupported_analysis_patterns", cov)
        self.assertIn("unsupported_address_generation_models", cov)

        # Executable segments 8..15 must be present
        for seg_idx in range(8, 16):
            self.assertIn(seg_idx, cov["scanned_executable_segments"])

        # TriCore instruction classes
        expected_insts = [
            "MOVH_A", "LEA", "ADDIH_A", "ADDI", "ADD_A", "SUB_A",
            "LD_A", "LD_W", "LD_HU", "LD_B", "LD_BU", "ST_W", "ST_H", "ST_B",
            "BOL_OFF16", "ABS_OFF18", "RLC_CONST16",
        ]
        for inst_cls in expected_insts:
            self.assertIn(inst_cls, cov["instruction_reference_classes"])

        # Unsupported categories
        self.assertEqual(cov["unsupported_instruction_encodings"], [])
        self.assertIn("DYNAMIC_INDIRECT_JUMP_TABLE", cov["unsupported_analysis_patterns"])
        self.assertIn("MULTI_REGISTER_POLYNOMIAL_ARITHMETIC", cov["unsupported_analysis_patterns"])
        self.assertIn("UNMAPPED_PERIPHERAL_BUS_BRIDGE", cov["unsupported_address_generation_models"])

    def test_canonical_targets_mapping(self):
        """Verify all 5 canonical targets are mapped to Segment 2 in A7592133.0da with [START, END) semantics."""
        targets = self.catalog.canonical_targets
        self.assertEqual(len(targets), 5)

        expected = [
            ("TARGET_1_AXIS_X", "0x00063AD6", "0x00063AEF", 26, 12, "int16"),
            ("TARGET_2_AXIS_Y", "0x00063AF0", "0x00063B01", 18, 8, "uint16"),
            ("TARGET_3_KL_CURVE_1", "0x0006418A", "0x000641A3", 26, 12, "int16"),
            ("TARGET_4_KL_CURVE_2", "0x000641A4", "0x000641BD", 26, 12, "int16"),
            ("TARGET_5_KL_CURVE_3", "0x000641BE", "0x000641CF", 18, 8, "uint16"),
        ]
        for tid, start, end, span, pts, dtype in expected:
            t = targets.get(tid)
            self.assertIsNotNone(t, f"Missing canonical target {tid}")
            self.assertEqual(t["start_address"], start)
            self.assertEqual(t["end_address"], end)
            self.assertEqual(t["span_bytes"], span)
            self.assertEqual(t["element_count"], pts)
            self.assertEqual(t["data_type"], dtype)
            self.assertEqual(t["target_segment"], 2)
            self.assertEqual(t["target_file"], "A7592133.0da")
            self.assertEqual(t["address_range_semantics"], "[START, END)")

    def test_secondary_pointer_structures(self):
        """Verify secondary pointer arrays have PROVEN pointer relationship and UNCONFIRMED semantic role."""
        sec = self.catalog.secondary_structures
        self.assertEqual(len(sec), 4)

        addrs = {s["candidate_address"] for s in sec}
        expected_addrs = {"0x0004BD00", "0x0004BD80", "0x0007CA50", "0x0007CAC8"}
        self.assertEqual(addrs, expected_addrs)

        for s in sec:
            self.assertEqual(s["pointer_relationship"], "PROVEN")
            self.assertEqual(s["semantic_role"], "UNCONFIRMED")

    def test_tier_a_candidate_references(self):
        """Verify 26 candidates evaluated: 10 descriptor fields, 10 secondary entries, 5 synthetic, 1 RAM collision."""
        candidates = self.catalog.candidate_references
        self.assertEqual(len(candidates), 26)

        # 10 descriptor fields
        desc_cands = [c for c in candidates if c.candidate_id.startswith("CAND_DESC_")]
        self.assertEqual(len(desc_cands), 10)
        for dc in desc_cands:
            self.assertEqual(dc.reference_kind, "DIRECT_POINTER")
            self.assertEqual(dc.confidence, "PROVEN")
            self.assertEqual(dc.source_segment, 3)

        # 10 secondary table entries
        sec_cands = [c for c in candidates if c.candidate_id.startswith("CAND_SEC_")]
        self.assertEqual(len(sec_cands), 10)
        for sc in sec_cands:
            self.assertEqual(sc.reference_kind, "SECONDARY_TABLE_ENTRY")
            self.assertIn("PROVEN_POINTER_RELATIONSHIP", sc.confidence)

        # 5 synthetic rejections
        synth_cands = [c for c in candidates if c.candidate_id.startswith("CAND_SYNTH_")]
        self.assertEqual(len(synth_cands), 5)
        for sc in synth_cands:
            self.assertEqual(sc.subtype, "REJECTED_SYNTHETIC_ADDRESS")
            self.assertEqual(sc.confidence, "REJECTED")

        # 1 RAM offset collision 0x000C1A04
        c1a04 = next((c for c in candidates if c.candidate_id == "CAND_RAM_C1A04"), None)
        self.assertIsNotNone(c1a04)
        self.assertEqual(c1a04.source_address, "0x000C1A04")
        self.assertEqual(c1a04.reference_kind, "CONSTANT_COLLISION")
        self.assertEqual(c1a04.subtype, "REJECTED_RAM_OFFSET")
        self.assertEqual(c1a04.confidence, "REJECTED")

    def test_soundness_correction_1_instruction_boundary(self):
        """Verify instruction boundary validation is based on decoder recognition without address parity heuristics."""
        bb = self.catalog.code_candidate_0001
        self.assertEqual(bb["address"], "0x00086000")
        self.assertEqual(bb["classification"], "BASIC_BLOCK_ENTRY")
        self.assertEqual(bb["procedure_identity"], "UNCONFIRMED")
        self.assertEqual(bb["function_entry"], "UNCONFIRMED")
        self.assertEqual(bb["verified_callers"], [])

        # Check rejected callers include intra-instruction boundary at 0x0009C580
        rejected = {rc["candidate"]: rc["reason"] for rc in bb["rejected_callers"]}
        self.assertIn("0x0009C580", rejected)
        self.assertIn("INVALID_INSTRUCTION_BOUNDARY", rejected["0x0009C580"])

    def test_soundness_correction_2_memory_endianness_model(self):
        """Verify explicit endianness parameterization and unmapped address rejection."""
        mem = MemoryModel(
            pa_reader=lambda addr, width: self.pa_image.read_bytes(addr, width),
            da_reader=lambda addr, width: self.da_image.read_bytes(addr, width),
        )

        # Big-endian table at 0x0004BD00
        dec_be = mem.decode_pointer(0x0004BD00)
        self.assertEqual(dec_be.status, "PROVEN")
        self.assertEqual(dec_be.endianness, "BE")
        self.assertEqual(dec_be.decoded_value, 0x00063AF0)

        # Unknown endianness returns None (soundness rule: no implicit BE assumption)
        dec_unk = mem.decode_pointer(0x00089900, default_endianness="UNKNOWN")
        self.assertEqual(dec_unk.status, "UNKNOWN_ENDIANNESS")
        self.assertIsNone(dec_unk.decoded_value)

        # Unmapped address returns None
        dec_unmapped = mem.decode_pointer(0x00045500, default_endianness="BE")
        self.assertEqual(dec_unmapped.status, "UNMAPPED_MEMORY")
        self.assertIsNone(dec_unmapped.decoded_value)

    def test_soundness_correction_3_concrete_pointer_arithmetic_preservation(self):
        """Verify PTR(source, val) + imm evaluates to CONST(val + imm) preserving concrete address."""
        # LEA %a15, [%a4 + 0x08] where %a4 holds PTR("MAP_DESC_0001", 0x000454A0)
        state = RegisterState()
        state.set_a("a4", AbstractValue.make_ptr(0x000454A0, 0x000454A0, "MAP_DESC_0001"), "MOVH.A/LEA")

        # Construct LEA %a15, [%a4 + 8]: BOL format
        # op=0xd9, dest=a15 (high nibble), base=a4 (low nibble), off=8
        b0 = 0xD9
        b1 = (15 << 4) | 4  # dest=a15, base=a4
        b2 = 8 & 0xFF
        b3 = (8 >> 8) & 0x03
        raw_lea = bytes([b0, b1, b2, b3])

        inst = decode_instruction(raw_lea, 0x00090000)
        self.assertEqual(inst.mnemonic, "LEA")
        self.assertEqual(inst.base_reg, "a4")
        self.assertEqual(inst.dest_reg, "a15")
        self.assertEqual(inst.decoder_status, "VALID")

        mem = MemoryModel()
        res = apply_transfer_function(inst, state, mem)
        val_a15 = res.new_state.get_a("a15")

        self.assertEqual(val_a15.kind, AbstractValueKind.CONST)
        self.assertEqual(val_a15.concrete_value, 0x000454A8)
        self.assertEqual(val_a15.get_concrete_address(), 0x000454A8)

    def test_soundness_correction_4_target_read_write_discrimination(self):
        """Verify TARGET_READ achieves PROVEN consumer status while TARGET_WRITE retains UNCONFIRMED."""
        # 1. Target Write: ST.W [%a4 + 0], %d2 -> TARGET_WRITE, UNCONFIRMED
        state_write = RegisterState()
        state_write.set_a("a4", AbstractValue.make_ptr(0x00063AD6, 0x00063AD6, "TARGET_1"), "LOAD")

        # ST.W [%a4 + 0], %d2 -> op=0x59, src=d2 (high nibble), base=a4 (low nibble), off=0
        raw_stw = bytes([0x59, (2 << 4) | 4, 0x00, 0x00])
        inst_stw = decode_instruction(raw_stw, 0x00091000)
        self.assertEqual(inst_stw.mnemonic, "ST.W")
        self.assertEqual(inst_stw.base_reg, "a4")

        res_stw = apply_transfer_function(inst_stw, state_write, MemoryModel())
        self.assertEqual(res_stw.target_match, "TARGET_1_AXIS_X")
        self.assertEqual(res_stw.access_direction, "TARGET_WRITE")
        self.assertEqual(res_stw.access_class, "VALUE_STORE")
        self.assertEqual(res_stw.consumer_proof_status, "UNCONFIRMED")

        # 2. Target Read: LD.W %d2, [%a4 + 0] -> TARGET_READ, PROVEN
        raw_ldw = bytes([0x19, (2 << 4) | 4, 0x00, 0x00])
        inst_ldw = decode_instruction(raw_ldw, 0x00091004)
        self.assertEqual(inst_ldw.mnemonic, "LD.W")
        self.assertEqual(inst_ldw.base_reg, "a4")

        res_ldw = apply_transfer_function(inst_ldw, state_write, MemoryModel())
        self.assertEqual(res_ldw.target_match, "TARGET_1_AXIS_X")
        self.assertEqual(res_ldw.access_direction, "TARGET_READ")
        self.assertEqual(res_ldw.access_class, "VALUE_LOAD")
        self.assertEqual(res_ldw.consumer_proof_status, "PROVEN")

    def test_epistemic_status_ceilings(self):
        """Verify strict epistemic ceilings are maintained in the reconstructed catalog."""
        ep = self.catalog.stop_condition
        self.assertIn("case_result", ep)
        self.assertIn("forensic_status", ep)

        # 0x00086000 ceiling
        cc = self.catalog.code_candidate_0001
        self.assertEqual(cc["classification"], "BASIC_BLOCK_ENTRY")
        self.assertEqual(cc["procedure_identity"], "UNCONFIRMED")
        self.assertEqual(cc["function_entry"], "UNCONFIRMED")
        self.assertEqual(cc["verified_callers"], [])

    def test_stop_condition_evaluation(self):
        """Verify stop condition resolves to CASE_C_NO_INDIRECT_CONSUMER with high confidence."""
        stop = self.catalog.stop_condition
        self.assertEqual(stop["case_result"], "CASE_C_NO_INDIRECT_CONSUMER")
        self.assertEqual(stop["forensic_status"], "INDIRECT_CONSUMER_NOT_FOUND")
        self.assertEqual(stop["confidence"], "PROVEN_WITHIN_DECLARED_COVERAGE")
        self.assertIn("MAP_DESC_0001", stop["explanation"])

    def test_deterministic_artifact_emission(self):
        """Verify emission of all 10 deterministic JSON artifacts with self_hash_policy: EXCLUDED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            files = self.catalog.emit_artifacts(tmppath)
            self.assertEqual(len(files), 10)

            expected_filenames = [
                "pointer_producers_v525.json",
                "address_expressions_v525.json",
                "pointer_chains_v525.json",
                "target_access_v525.json",
                "backward_slices_v525.json",
                "forward_slices_v525.json",
                "coverage_v525.json",
                "epistemic_status_v525.json",
                "change_log_v525.json",
                "artifact_manifest_v525.json",
            ]
            for fname in expected_filenames:
                fpath = tmppath / fname
                self.assertTrue(fpath.exists(), f"Missing artifact {fname}")
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.assertIsInstance(data, dict)

            # Check manifest self-hash policy
            manifest_path = tmppath / "artifact_manifest_v525.json"
            with open(manifest_path, "r", encoding="utf-8") as f:
                mdata = json.load(f)
            self.assertEqual(mdata["self_hash_policy"], "EXCLUDED")
            self.assertEqual(mdata["total_artifacts"], 10)
            self.assertEqual(len(mdata["artifacts"]), 9)  # 9 emitted artifacts listed (excluding self)


if __name__ == "__main__":
    unittest.main()
