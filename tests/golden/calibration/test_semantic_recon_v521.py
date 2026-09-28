"""TDD Test Suite for Milestone 5.21 Gates 7, 8, 9, 10, 11: Topology, Roles, Scaling, Semantics, Rejections."""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.calibration.axis_validation_v521 import AxisValidationEngine
from reconstruction.calibration.code_references_v521 import CodeReferenceEngine
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.object_index_v521 import CanonicalObjectIndexBuilder
from reconstruction.calibration.semantic_recon_v521 import (
    SemanticReconstructionCatalog,
    SemanticReconstructionEngine,
)

DA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
PA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")


class TestSemanticReconV521(unittest.TestCase):
    """Test suite for table topology, execution roles, scaling, and negative evidence."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.da_image = IntelHexParser.parse_file(DA_FILE)
        cls.pa_image = IntelHexParser.parse_file(PA_FILE)
        cls.index_catalog = CanonicalObjectIndexBuilder(cls.da_image).build_catalog()
        cls.ref_catalog = CodeReferenceEngine(cls.da_image, cls.pa_image).recover_references()
        cls.axis_catalog = AxisValidationEngine(cls.index_catalog, cls.ref_catalog).build_catalog()
        cls.engine = SemanticReconstructionEngine(
            cls.index_catalog, cls.ref_catalog, cls.axis_catalog
        )
        cls.catalog: SemanticReconstructionCatalog = cls.engine.build_catalog()

    def test_01_execution_role_chain_reconstructed(self) -> None:
        """Verify the 6-stage execution chain is reconstructed for descriptor table."""
        roles = self.catalog.execution_roles
        self.assertTrue(len(roles) > 0)
        target_role = next((r for r in roles if r.table_address == "0x0006418A"), None)
        self.assertIsNotNone(target_role)
        self.assertEqual(target_role.axis_x_lookup, "0x00063AD6")
        self.assertEqual(target_role.axis_y_lookup, "0x00063AF0")
        self.assertIn("BILINEAR", target_role.interpolation_type)
        self.assertIsNotNone(target_role.execution_pipeline)
        self.assertEqual(
            target_role.execution_pipeline["stages"],
            ["INPUT", "INDEX", "AXIS LOOKUP", "TABLE ACCESS", "INTERPOLATION", "SCALE/OFFSET", "OUTPUT"],
        )

    def test_02_scaling_candidates_bounded(self) -> None:
        """Verify constants (750, 500, 6800) have explicit evidence-bounded hypotheses."""
        scaling = {s.raw_value_decimal: s for s in self.catalog.scaling_candidates}
        self.assertIn(750, scaling)
        self.assertIn(500, scaling)
        self.assertIn(6800, scaling)

        for val, cand in scaling.items():
            self.assertIn(cand.confidence, ("SUPPORTED", "UNCONFIRMED", "HEURISTIC"))
            self.assertNotEqual(cand.confidence, "PROVEN")
            self.assertTrue(len(cand.contradicting_evidence) > 0 or len(cand.unresolved_questions) > 0)

    def test_03_rejected_candidates_preserved(self) -> None:
        """Verify negative evidence and false positive rejections are explicitly preserved."""
        rejected = self.catalog.rejected_candidates
        self.assertTrue(len(rejected) > 0)
        reasons = {r.rejection_reason for r in rejected}
        self.assertTrue(any("gap" in r.lower() for r in reasons))

        # Gap pointers must be in rejected candidates
        gap_addrs = {r.candidate_id for r in rejected if "gap" in r.rejection_reason.lower()}
        self.assertTrue(any("0x0005FFF4" in ga or "0x0005FFFE" in ga for ga in gap_addrs))

    def test_04_evidence_tiers_distribution(self) -> None:
        """Verify candidates are categorized into evidence tiers A, B, C, D, E."""
        tiers = self.catalog.evidence_tiers
        for tier in ("TIER_A_HIGH_EVIDENCE", "TIER_B_STRONG_STRUCTURAL", "TIER_C_STRUCTURAL_ONLY", "TIER_D_HEURISTIC", "TIER_E_REJECTED"):
            self.assertIn(tier, tiers)
            self.assertTrue(isinstance(tiers[tier], list))


if __name__ == "__main__":
    unittest.main()
