"""Golden tests for Milestone 5.22: Reference Graph Deepening & Alignment Validation.

Tests Gate 2 (Instruction-Boundary Discipline), Gate 3 (Data Table vs Code Discrimination),
and Gate 5 (Code Reference Recovery).
Verifies rejection of unaligned instruction overlaps (false positives) and proper classification
of static address arrays vs executed instructions.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
    detect_executable_regions,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.code_references_v522 import (
    ReferenceDeepeningCatalog,
    deepen_references,
)


class TestCodeReferencesV522(unittest.TestCase):
    """Test suite for reference graph deepening and instruction boundary validation."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found in workspace.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)
        cls.code_catalog = detect_executable_regions(cls.pa_image, cls.da_image)

    def test_reference_deepening_and_classification(self):
        """Verify deep reference classification and data table discrimination (Gates 3 & 5)."""
        catalog = deepen_references(self.pa_image, self.da_image, self.code_catalog)
        self.assertIsInstance(catalog, ReferenceDeepeningCatalog)
        self.assertGreater(len(catalog.references), 10)

        # 1. Gate 3: Check that static address table at 0x0004381C is NOT classified as executed code
        data_table_ref = next(
            (r for r in catalog.references if r.source_address == "0x0004381C"),
            None,
        )
        self.assertIsNotNone(data_table_ref)
        self.assertEqual(data_table_ref.reference_class, "STATIC_ADDRESS_TABLE")
        self.assertIn("data_record_not_executed_instruction", data_table_ref.evidence)

        # 2. Gate 4 / Descriptor linkage: MAP_DESC_0001 at 0x000454A0
        desc_refs = [r for r in catalog.references if r.reference_class == "DESCRIPTOR_REFERENCE"]
        self.assertGreaterEqual(len(desc_refs), 5)
        self.assertTrue(any(r.target_address == "0x00063AD6" for r in desc_refs))
        self.assertTrue(any(r.target_address == "0x00063AF0" for r in desc_refs))
        self.assertTrue(any(r.target_address == "0x0006418A" for r in desc_refs))

        # 3. Vector table anchors at 0x000301D0
        vector_refs = [r for r in catalog.references if r.reference_class == "BASE_PROGRAM_REFERENCE"]
        self.assertGreaterEqual(len(vector_refs), 4)

    def test_instruction_boundary_rejection_gate2(self):
        """Gate 2: Verify unaligned overlapping byte scans are caught and rejected."""
        catalog = deepen_references(self.pa_image, self.da_image, self.code_catalog)
        # Check rejected_references
        self.assertGreater(len(catalog.rejected_references), 0)
        # Verify alignment artifact rejection
        overlap_ref = next(
            (r for r in catalog.rejected_references if r.rejection_reason == "ALIGNMENT_ARTIFACT"),
            None,
        )
        self.assertIsNotNone(overlap_ref)
        self.assertIn("unaligned_instruction_slice", overlap_ref.evidence)


if __name__ == "__main__":
    unittest.main()
