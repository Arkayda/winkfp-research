"""TDD Test Suite for Milestone 5.21 Gate 5 & 6: Axis Validation and Ownership Graph."""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.calibration.axis_validation_v521 import (
    AxisOwnershipCatalog,
    AxisValidationEngine,
)
from reconstruction.calibration.code_references_v521 import CodeReferenceEngine
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.object_index_v521 import CanonicalObjectIndexBuilder

DA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
PA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")


class TestAxisValidationV521(unittest.TestCase):
    """Test suite for axis validation and axis-to-table ownership."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.da_image = IntelHexParser.parse_file(DA_FILE)
        cls.pa_image = IntelHexParser.parse_file(PA_FILE)
        cls.index_catalog = CanonicalObjectIndexBuilder(cls.da_image).build_catalog()
        cls.ref_catalog = CodeReferenceEngine(cls.da_image, cls.pa_image).recover_references()
        cls.engine = AxisValidationEngine(cls.index_catalog, cls.ref_catalog)
        cls.catalog: AxisOwnershipCatalog = cls.engine.build_catalog()

    def test_01_descriptor_referenced_axes_elevated(self) -> None:
        """Verify descriptor-referenced axes (0x00063AD6, 0x00063AF0) reach STRONGLY_SUPPORTED."""
        axes_by_addr = {a.address: a for a in self.catalog.axes}
        self.assertIn("0x00063AD6", axes_by_addr)
        self.assertIn("0x00063AF0", axes_by_addr)

        ax_x = axes_by_addr["0x00063AD6"]
        self.assertEqual(ax_x.validation_status, "STRONGLY_SUPPORTED")
        self.assertEqual(ax_x.element_count, 12)
        self.assertEqual(ax_x.semantic_hypothesis, "UNKNOWN")

        ax_y = axes_by_addr["0x00063AF0"]
        self.assertEqual(ax_y.validation_status, "STRONGLY_SUPPORTED")
        self.assertEqual(ax_y.element_count, 8)
        self.assertEqual(ax_y.semantic_hypothesis, "UNKNOWN")

    def test_02_dimension_only_axes_remain_unconfirmed(self) -> None:
        """Verify axes supported only by cardinality/dimension matching are NOT labeled PROVEN."""
        dim_only_axes = [
            a for a in self.catalog.axes
            if not any(r.startswith("DESCRIPTOR") or r.startswith("DIRECT_CODE") for r in a.references)
        ]
        self.assertTrue(len(dim_only_axes) > 0)
        for a in dim_only_axes:
            self.assertIn(a.validation_status, ("SUPPORTED", "UNCONFIRMED", "HEURISTIC", "REJECTED"))
            self.assertNotEqual(a.validation_status, "PROVEN")

    def test_03_descriptor_table_linkage_in_ownership_graph(self) -> None:
        """Verify the ownership graph contains descriptor-backed link for 0x0006418A."""
        links = self.catalog.ownership_links
        desc_links = [l for l in links if l.linkage_type == "DESCRIPTOR_BINDING"]
        self.assertTrue(len(desc_links) > 0)
        target_link = next(l for l in desc_links if l.table_address == "0x0006418A")
        self.assertEqual(target_link.axis_x_address, "0x00063AD6")
        self.assertEqual(target_link.axis_y_address, "0x00063AF0")
        self.assertEqual(target_link.confidence, "STRONGLY_SUPPORTED")

    def test_04_all_axes_maintain_unknown_semantics(self) -> None:
        """Verify all axis candidates have semantic_hypothesis = UNKNOWN."""
        for a in self.catalog.axes:
            self.assertEqual(a.semantic_hypothesis, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
