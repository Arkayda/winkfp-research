"""Golden Test Suite for Milestone 5.20 Calibration Map Reconstruction.

Verifies all 10 analysis stages:
1. Forensic binary inventory of A7592133.0da
2. Relationship and pointer linkage with 7591971A.0pa
3. Multi-detector table discovery
4. Axis reconstruction and monotonicity
5. Table <-> axis dimensional linkage
6. Code/data reverse-reference graph
7. Checksum, CVN, and RSA signature integrity regions
8. Map classification
9. Bounded semantic hypotheses
10. Deterministic output across repeated runs and source immutability
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from reconstruction.calibration.recon_v520 import (
    DEFAULT_DA_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PA_PATH,
    CalibrationReconstructionV520,
)

FROZEN_DA_SHA256 = "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"


class TestCalibrationReconstructionV520(unittest.TestCase):
    """Golden regression test suite for Milestone 5.20."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.orchestrator = CalibrationReconstructionV520(
            da_path=DEFAULT_DA_PATH,
            pa_path=DEFAULT_PA_PATH,
            output_dir=DEFAULT_OUTPUT_DIR,
        )
        cls.artifacts = cls.orchestrator.run_all()

    # -------------------------------------------------------------------------
    # Stage 1: Forensic Binary Inventory
    # -------------------------------------------------------------------------
    def test_01_flash_inventory_structure_and_hashes(self) -> None:
        """Verify binary inventory, SHA-256 digest, 6 segments, and ASCII strings."""
        inv_path = self.artifacts["flash_inventory"]
        self.assertTrue(inv_path.exists())
        data = json.loads(inv_path.read_text(encoding="utf-8"))

        self.assertEqual(data["file_name"], "A7592133.0da")
        self.assertEqual(data["file_sha256"], FROZEN_DA_SHA256)
        self.assertEqual(data["file_size_bytes"], 489258)
        self.assertEqual(data["segment_count"], 6)
        self.assertEqual(data["total_payload_bytes"], 173088)
        self.assertEqual(len(data["gaps"]), 5)

        # Check identified ASCII regions
        ascii_strings = {r["string"] for r in data["ascii_regions"]}
        self.assertIn("0479S90T641Z1ZY02", ascii_strings)
        self.assertIn("DAV54764", ascii_strings)
        self.assertIn("T641ZY02", ascii_strings)

        # Verify evidence classes
        self.assertEqual(data["evidence_classes"]["file_hash_and_size"], "FACT")
        self.assertEqual(data["evidence_classes"]["intel_hex_segment_boundaries"], "FACT")

    # -------------------------------------------------------------------------
    # Stage 2: Segment Layout
    # -------------------------------------------------------------------------
    def test_02_segment_layout_exact_boundaries(self) -> None:
        """Verify exact segment addresses, roles, and calibration object distribution."""
        layout_path = self.artifacts["segment_layout"]
        data = json.loads(layout_path.read_text(encoding="utf-8"))

        self.assertEqual(data["calibration_address_range"]["start"], "0x00050000")
        self.assertEqual(len(data["segments"]), 6)

        seg0 = data["segments"][0]
        self.assertEqual(seg0["start_address"], "0x00050000")
        self.assertEqual(seg0["end_address"], "0x00050080")
        self.assertEqual(seg0["byte_length"], 128)

        seg4 = data["segments"][4]
        self.assertEqual(seg4["start_address"], "0x00076000")
        self.assertEqual(seg4["end_address"], "0x0007EF60")
        self.assertEqual(seg4["byte_length"], 36704)
        self.assertTrue(seg4["contains_pointers"])

        seg5 = data["segments"][5]
        self.assertEqual(seg5["start_address"], "0x0007FF60")
        self.assertEqual(seg5["end_address"], "0x0007FF70")
        self.assertEqual(seg5["byte_length"], 16)

    # -------------------------------------------------------------------------
    # Stage 3: Base Program Cross-References (Reference Graph)
    # -------------------------------------------------------------------------
    def test_03_base_program_linkage_and_directory_references(self) -> None:
        """Verify bit-for-bit pointers at 0x000301D0 in 7591971A.0pa into A7592133.0da."""
        ref_path = self.artifacts["reference_graph"]
        data = json.loads(ref_path.read_text(encoding="utf-8"))

        base_links = {link["target_address"]: link for link in data["base_program_linkages"]}
        self.assertIn("0x00050000", base_links)  # RSA signature block
        self.assertIn("0x000500A0", base_links)  # Logistics / ZIF header
        self.assertIn("0x000500E4", base_links)  # CARB CVN
        self.assertIn("0x0007FF60", base_links)  # Trailer integrity block

        for link in data["base_program_linkages"]:
            self.assertEqual(link["source_file"], "7591971A.0pa")
            self.assertEqual(link["target_file"], "A7592133.0da")
            self.assertEqual(link["reference_type"], "DIRECT_REFERENCE")

        self.assertEqual(data["directory_pointer_references_count"], 9176)

    # -------------------------------------------------------------------------
    # Stage 4: Axis Reconstruction
    # -------------------------------------------------------------------------
    def test_04_axis_reconstruction_and_monotonicity(self) -> None:
        """Verify reconstructed breakpoint axes are monotonic and labeled UNKNOWN."""
        axis_path = self.artifacts["axis_candidates"]
        data = json.loads(axis_path.read_text(encoding="utf-8"))

        self.assertTrue(data["axis_count"] > 100)
        self.assertTrue(data["confirmed_structural_count"] >= 30)

        for ax in data["candidates"]:
            self.assertTrue(ax["id"].startswith("AXIS_CANDIDATE_"))
            self.assertEqual(ax["semantic_hypothesis"], "UNKNOWN")
            self.assertIn(ax["monotonicity"], ("strictly_increasing", "weakly_increasing"))
            self.assertTrue(ax["element_count"] >= 3)
            self.assertEqual(len(ax["raw_values"]), ax["element_count"])

    # -------------------------------------------------------------------------
    # Stage 5: Table Candidates Discovery
    # -------------------------------------------------------------------------
    def test_05_table_candidates_format_and_grids(self) -> None:
        """Verify table candidates match prompt format and include multi-detector evidence."""
        tbl_path = self.artifacts["table_candidates"]
        data = json.loads(tbl_path.read_text(encoding="utf-8"))

        self.assertTrue(data["table_count"] > 500)
        sample = data["tables"][0]

        # Verify exact prompt schema keys
        required_keys = {
            "id", "file", "file_offset", "address", "width_bits", "endianness",
            "signed", "dimensions", "axis_x", "axis_y", "references",
            "structural_evidence", "semantic_hypothesis", "confidence",
        }
        self.assertTrue(required_keys.issubset(sample.keys()))
        self.assertEqual(sample["file"], "A7592133.0da")
        self.assertTrue(len(sample["structural_evidence"]) >= 2)

    # -------------------------------------------------------------------------
    # Stage 6: Axis-Table Linkages
    # -------------------------------------------------------------------------
    def test_06_axis_table_linkages(self) -> None:
        """Verify dimensional matching between 2D tables and axis candidates."""
        link_path = self.artifacts["axis_table_links"]
        data = json.loads(link_path.read_text(encoding="utf-8"))

        self.assertTrue(data["total_links_count"] > 50)
        for link in data["links"]:
            self.assertEqual(link["link_type"], "DIMENSIONAL_MATCH")
            self.assertEqual(link["table_dimensions"][0], link["axis_x_count"])
            if link["axis_y_count"]:
                self.assertEqual(link["table_dimensions"][1], link["axis_y_count"])

    # -------------------------------------------------------------------------
    # Stage 7: Checksum & Integrity Regions
    # -------------------------------------------------------------------------
    def test_07_checksum_and_cvn_integrity_regions(self) -> None:
        """Verify RSA-1024, CARB Mode $09 CVN (0000F41E), and trailer integrity blocks."""
        chk_path = self.artifacts["checksum_regions"]
        data = json.loads(chk_path.read_text(encoding="utf-8"))

        region_types = {r["region_type"] for r in data["regions"]}
        self.assertIn("RSA_SIGNATURE", region_types)
        self.assertIn("CARB_CVN", region_types)
        self.assertIn("TRAILER_BLOCK", region_types)

        cvn = next(r for r in data["regions"] if r["region_type"] == "CARB_CVN")
        self.assertEqual(cvn["start_address"], "0x000500E4")
        self.assertEqual(cvn["stored_value"], "0000F41E")
        self.assertEqual(cvn["evidence_class"], "FACT")

    # -------------------------------------------------------------------------
    # Stage 8 & 9: Map Classes and Semantic Hypotheses
    # -------------------------------------------------------------------------
    def test_08_map_classes_and_bounded_semantics(self) -> None:
        """Verify map classes distribution and strictly bounded semantic confidence ratings."""
        sem_path = self.artifacts["map_semantics"]
        data = json.loads(sem_path.read_text(encoding="utf-8"))

        dist = data["map_class_distribution"]
        self.assertIn("1D_CURVE", dist)
        self.assertIn("2D_MAP", dist)
        self.assertIn("BREAKPOINT_AXIS", dist)
        self.assertIn("SCALAR_CONSTANT", dist)

        # Check hypotheses confidence ratings
        for hyp in data["semantic_hypotheses"]:
            self.assertIn(hyp["confidence"], ("LOW", "UNCONFIRMED"))
            self.assertTrue(len(hyp["unresolved_questions"]) > 0)
            self.assertTrue(len(hyp["reasoning"]) > 0)

    # -------------------------------------------------------------------------
    # Stage 10: Determinism and Source Immutability
    # -------------------------------------------------------------------------
    def test_09_determinism_across_executions(self) -> None:
        """Verify bit-for-bit identity across repeated pipeline runs."""
        hashes_pass1 = {
            name: hashlib.sha256(p.read_bytes()).hexdigest()
            for name, p in self.artifacts.items()
        }

        # Run pass 2
        orchestrator_pass2 = CalibrationReconstructionV520(
            da_path=DEFAULT_DA_PATH,
            pa_path=DEFAULT_PA_PATH,
            output_dir=DEFAULT_OUTPUT_DIR,
        )
        artifacts_pass2 = orchestrator_pass2.run_all()
        hashes_pass2 = {
            name: hashlib.sha256(p.read_bytes()).hexdigest()
            for name, p in artifacts_pass2.items()
        }

        for name in hashes_pass1:
            self.assertEqual(
                hashes_pass1[name],
                hashes_pass2[name],
                f"Non-deterministic serialization detected in {name}!",
            )

    def test_10_source_immutability(self) -> None:
        """Verify source calibration file was not modified."""
        digest = hashlib.sha256(DEFAULT_DA_PATH.read_bytes()).hexdigest()
        self.assertEqual(digest, FROZEN_DA_SHA256)


if __name__ == "__main__":
    unittest.main()
