"""TDD Test Suite for Milestone 5.21 Gate 2 & 3: Reference Recovery and Validation."""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.calibration.code_references_v521 import (
    CodeReferenceEngine,
    ReferenceValidationCatalog,
)
from reconstruction.calibration.hex_parser import IntelHexParser

DA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
PA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")


class TestCodeReferencesV521(unittest.TestCase):
    """Test suite for reference recovery, classification, and validation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.da_image = IntelHexParser.parse_file(DA_FILE)
        cls.pa_image = IntelHexParser.parse_file(PA_FILE)
        cls.engine = CodeReferenceEngine(cls.da_image, cls.pa_image)
        cls.catalog: ReferenceValidationCatalog = cls.engine.recover_references()

    def test_01_reference_taxonomy_coverage(self) -> None:
        """Verify references are strictly partitioned across the required taxonomy classes."""
        valid_classes = {
            "DIRECT_CODE_REFERENCE",
            "INDIRECT_CODE_REFERENCE",
            "DESCRIPTOR_REFERENCE",
            "DATA_POINTER",
            "BASE_PROGRAM_REFERENCE",
            "CALIBRATION_INTERNAL_REFERENCE",
            "STRUCTURAL_REFERENCE",
            "HEURISTIC_POINTER",
            "FALSE_POSITIVE",
        }
        counts = self.catalog.summary_by_class
        self.assertTrue(set(counts.keys()).issubset(valid_classes))
        self.assertTrue(counts.get("BASE_PROGRAM_REFERENCE", 0) > 0)
        self.assertTrue(counts.get("DESCRIPTOR_REFERENCE", 0) > 0)
        self.assertTrue(counts.get("CALIBRATION_INTERNAL_REFERENCE", 0) > 0)

    def test_02_descriptor_table_recovery(self) -> None:
        """Verify recovery of the map descriptor block at 0x000454A0 in 7591971A.0pa."""
        desc_refs = [r for r in self.catalog.references if r.reference_class == "DESCRIPTOR_REFERENCE"]
        self.assertTrue(len(desc_refs) >= 3)
        targets = {r.target_address for r in desc_refs}
        self.assertIn("0x00063AD6", targets)  # Axis X (12 elements)
        self.assertIn("0x00063AF0", targets)  # Axis Y (8 elements)
        self.assertIn("0x0006418A", targets)  # Table candidate

    def test_03_base_program_vector_references(self) -> None:
        """Verify the 4 foundational base-program references at 0x000301D0."""
        base_refs = [
            r for r in self.catalog.references
            if r.source_file == "7591971A.0pa" and 0x000301D0 <= int(r.source_address, 16) <= 0x000301E0
        ]
        self.assertEqual(len(base_refs), 4)
        targets = {r.target_address for r in base_refs}
        self.assertEqual(
            targets,
            {"0x000500E4", "0x0007FF60", "0x000500A0", "0x00050000"},
        )
        for r in base_refs:
            self.assertEqual(r.reference_class, "BASE_PROGRAM_REFERENCE")
            self.assertEqual(r.validation_status, "PROVEN")

    def test_04_internal_calibration_references(self) -> None:
        """Verify internal calibration references in Seg 0/1 and indirect directory pointers."""
        internal_refs = [
            r for r in self.catalog.references if r.reference_class == "CALIBRATION_INTERNAL_REFERENCE"
        ]
        self.assertTrue(len(internal_refs) >= 720)  # at least the 720 indirect directory pointers


if __name__ == "__main__":
    unittest.main()
