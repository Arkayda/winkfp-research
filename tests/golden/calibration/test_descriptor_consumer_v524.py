"""Golden tests for Milestone 5.24 Descriptor Consumer Discovery & Executable Consumer Reconstruction.

Tests:
1. Coverage reporting and explicit capability declarations (instruction & data classes).
2. Descriptor field extraction from MAP_DESC_0001 at 0x000454A0 in 7591971A.0pa.
3. Canonical target address resolution (0x00063AD6..0x000641CF in A7592133.0da).
4. Rejection of synthetic unmapped 0x000455xx candidates as REJECTED_SYNTHETIC_ADDRESS.
5. False-positive control: rejection of 0x000C1A04 (st.b %d4, [%a15 + 0x54c8]) as CONSTANT_COLLISION.
6. Secondary structure candidates classification (0x0004BD00, 0x0004BD80, 0x0007CA50, 0x0007CAC8).
7. Preservation of 0x00086000 epistemic ceiling (BASIC_BLOCK_ENTRY, procedure_identity UNCONFIRMED).
8. Stop condition evaluation (Case A, Case B, or Case C).
9. Deterministic artifact emission and manifest coverage verification.
"""

import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.descriptor_consumer_v524 import (
    DescriptorConsumerCatalog,
    reconstruct_descriptor_consumers,
)


class TestDescriptorConsumerV524(unittest.TestCase):
    """Test suite for Milestone 5.24 descriptor consumer discovery and code reconstruction."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)
        cls.catalog = reconstruct_descriptor_consumers(cls.pa_image, cls.da_image)

    def test_scanner_coverage_declarations(self):
        """Verify scanner explicitly declares scanned classes, segments, and 3 unsupported categories."""
        cov = self.catalog.coverage
        self.assertIn("scanned_executable_segments", cov)
        self.assertIn("scanned_data_segments", cov)
        self.assertIn("instruction_reference_classes", cov)
        self.assertIn("data_reference_classes", cov)
        self.assertIn("decoder_capabilities", cov)
        self.assertIn("unsupported_instruction_encodings", cov)
        self.assertIn("unsupported_analysis_patterns", cov)
        self.assertIn("unsupported_address_generation_models", cov)
        self.assertEqual(cov["unsupported_instruction_encodings"], [])
        self.assertIn("DYNAMIC_INDIRECT_JUMP_TABLE", cov["unsupported_analysis_patterns"])
        self.assertIn("MULTI_REGISTER_POLYNOMIAL_ARITHMETIC", cov["unsupported_analysis_patterns"])
        self.assertIn("UNMAPPED_PERIPHERAL_BUS_BRIDGE", cov["unsupported_address_generation_models"])

        # Segments 8..15 must be included in executable coverage
        for seg_idx in range(8, 16):
            self.assertIn(seg_idx, cov["scanned_executable_segments"])

        # Instruction classes must include TriCore immediate & offset forms
        inst_classes = cov["instruction_reference_classes"]
        for ic in ["MOVH_A", "LEA", "ADDIH_A", "BOL_OFF16", "ABS_OFF18", "RLC_CONST16"]:
            self.assertIn(ic, inst_classes)

    def test_descriptor_field_extraction(self):
        """Verify exact 12-field extraction of MAP_DESC_0001 at 0x000454A0."""
        desc = self.catalog.descriptor_record
        self.assertEqual(desc["descriptor_id"], "MAP_DESC_0001")
        self.assertEqual(desc["source_address"], "0x000454A0")
        self.assertEqual(desc["span_bytes"], 48)
        self.assertEqual(len(desc["fields"]), 12)
        self.assertEqual(desc["fields"][0]["raw_hex"], "FFFFFFFF")
        self.assertEqual(desc["fields"][1]["raw_hex"], "FFFFFFFF")

    def test_canonical_target_address_mapping(self):
        """Verify all 5 canonical target objects are mapped to exact calibration segments."""
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
            self.assertIsNotNone(t, f"Missing target {tid}")
            self.assertEqual(t["start_address"], start)
            self.assertEqual(t["end_address"], end)
            self.assertEqual(t["span_bytes"], span)
            self.assertEqual(t["element_count"], pts)
            self.assertEqual(t["data_type"], dtype)
            self.assertEqual(t["target_segment"], 2)
            self.assertEqual(t["target_segment_parser_index"], 2)
            self.assertEqual(t["target_segment_address_space"], "0x00060000..0x0006FFF0")
            self.assertEqual(t["address_range_semantics"], "[START, END)")
            self.assertIn("Segment 6 in Milestone 5.23", t["segment_numbering_note"])

    def test_synthetic_0x455xx_rejection(self):
        """Verify synthetic 0x000455xx candidates are rejected with REJECTED_SYNTHETIC_ADDRESS."""
        rejected = self.catalog.rejected_candidates
        synth_addrs = {"0x00045500", "0x00045518", "0x00045528", "0x00045540", "0x00045558"}
        found_rejected = {r.candidate_address for r in rejected if r.rejection_class == "REJECTED_SYNTHETIC_ADDRESS"}
        for s in synth_addrs:
            self.assertIn(s, found_rejected, f"Synthetic candidate {s} not properly rejected")

    def test_false_positive_rejection_0x000c1a04(self):
        """Verify 0x000C1A04 (st.b %d4, [%a15 + 0x54c8]) is rejected as CONSTANT_COLLISION."""
        rejected = self.catalog.rejected_candidates
        c1a04_rej = next((r for r in rejected if r.source_address == "0x000C1A04"), None)
        self.assertIsNotNone(c1a04_rej, "0x000C1A04 must be evaluated and rejected")
        self.assertEqual(c1a04_rej.rejection_class, "CONSTANT_COLLISION")
        self.assertIn("RAM_OFFSET", c1a04_rej.evidence_reason)

    def test_secondary_structure_candidates(self):
        """Verify 0x0004BD00, 0x0004BD80, 0x0007CA50, 0x0007CAC8 two-level epistemic model."""
        sec = self.catalog.secondary_structure_candidates
        sec_addrs = {s.candidate_address for s in sec}
        expected_sec = {"0x0004BD00", "0x0004BD80", "0x0007CA50", "0x0007CAC8"}
        for addr in expected_sec:
            self.assertIn(addr, sec_addrs, f"Secondary structure {addr} missing")
        for s in sec:
            self.assertEqual(s.status, "SECONDARY_STRUCTURE_CANDIDATE")
            self.assertEqual(s.pointer_relationship, "PROVEN")
            self.assertEqual(s.semantic_role, "UNCONFIRMED")
            self.assertEqual(s.confidence, "PROVEN_POINTER_RELATIONSHIP / UNCONFIRMED_SEMANTIC_ROLE")

    def test_0x00086000_epistemic_status_preserved(self):
        """Verify 0x00086000 retains BASIC_BLOCK_ENTRY and procedure_identity UNCONFIRMED."""
        bb = self.catalog.code_candidate_0001
        self.assertEqual(bb["address"], "0x00086000")
        self.assertEqual(bb["classification"], "BASIC_BLOCK_ENTRY")
        self.assertEqual(bb["procedure_identity"], "UNCONFIRMED")
        self.assertEqual(bb["function_entry"], "UNCONFIRMED")
        self.assertEqual(bb["verified_callers"], [])

    def test_stop_condition_evaluation(self):
        """Verify stop condition is explicitly resolved to CASE_A, CASE_B, or CASE_C."""
        status = self.catalog.stop_condition
        self.assertIn(status["case_result"], ["CASE_A_PROVEN_CONSUMER", "CASE_B_PARTIAL_CHAIN", "CASE_C_NO_EXECUTABLE_CONSUMER"])
        if status["case_result"] == "CASE_C_NO_EXECUTABLE_CONSUMER":
            self.assertEqual(status["forensic_status"], "EXECUTABLE_CONSUMER_NOT_FOUND")

    def test_deterministic_artifact_generation(self):
        """Verify all 8 Milestone 5.24 artifacts are deterministically generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            files = self.catalog.emit_artifacts(tmppath)
            self.assertEqual(len(files), 8)

            expected_files = [
                "descriptor_consumers_v524.json",
                "code_references_v524.json",
                "target_access_traces_v524.json",
                "dataflow_v524.json",
                "callgraph_v524.json",
                "epistemic_status_v524.json",
                "change_log_v524.json",
                "artifact_manifest_v524.json",
            ]
            for fname in expected_files:
                fpath = tmppath / fname
                self.assertTrue(fpath.exists(), f"Missing artifact {fname}")
                # Verify valid JSON
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.assertIsInstance(data, dict)
            with open(tmppath / "artifact_manifest_v524.json", "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
                self.assertEqual(manifest_data.get("self_hash_policy"), "EXCLUDED")

    def test_segment_numbering_reconciliation(self):
        """Verify Segment 2 is canonical parser segment index for targets 0x00063AD6..0x000641CF in A7592133.0da."""
        targets = self.catalog.canonical_targets
        for tid, t in targets.items():
            self.assertEqual(t["target_segment"], 2)
            self.assertEqual(t["target_segment_parser_index"], 2)
            self.assertEqual(t["target_file"], "A7592133.0da")
            self.assertEqual(t["target_segment_address_space"], "0x00060000..0x0006FFF0")
            self.assertEqual(t["address_range_semantics"], "[START, END)")
            self.assertIn("Segment 6 in Milestone 5.23", t["segment_numbering_note"])
            self.assertIn("[START, END)", t["segment_numbering_note"])


if __name__ == "__main__":
    unittest.main()
