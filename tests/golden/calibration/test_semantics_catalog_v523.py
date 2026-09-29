"""Golden tests for Milestone 5.23 Semantics Catalog & Evidence Hierarchy Engine.

Tests Task 4: Multi-path cross-validation, alternative interpretation tracking,
negative evidence preservation, and strict evidence ceiling clamping.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.function_tracer_v523 import trace_calibration_functions
from reconstruction.calibration.arithmetic_engine_v523 import analyze_function_arithmetic
from reconstruction.calibration.semantics_catalog_v523 import (
    CrossValidationReport,
    RejectedSemanticCatalog,
    SemanticCandidateRecord,
    SemanticCatalogBundle,
    build_semantics_catalog,
)


class TestSemanticsCatalogV523(unittest.TestCase):
    """Test suite for semantic hypothesis evaluation and negative evidence."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)
        cls.fn_catalog = trace_calibration_functions(cls.pa_image, cls.da_image)
        cls.arith_catalog = analyze_function_arithmetic(cls.fn_catalog, cls.pa_image, cls.da_image)

    def test_semantics_catalog_construction(self):
        """Verify semantic bundle construction and candidate generation."""
        bundle = build_semantics_catalog(self.fn_catalog, self.arith_catalog)
        self.assertIsInstance(bundle, SemanticCatalogBundle)
        self.assertGreaterEqual(len(bundle.candidates), 1)

        c1 = bundle.candidates[0]
        self.assertEqual(c1.function_id, "CALCODE_CANDIDATE_0001")
        self.assertEqual(c1.confidence, "UNCONFIRMED")
        self.assertEqual(c1.engineering_unit, "UNKNOWN")
        self.assertGreaterEqual(len(c1.alternatives), 1)

    def test_cross_validation_paths(self):
        """Verify cross-validation across independent evidence paths."""
        bundle = build_semantics_catalog(self.fn_catalog, self.arith_catalog)
        cv = bundle.cross_validation
        self.assertIsInstance(cv, CrossValidationReport)
        self.assertEqual(cv.function_id, "CALCODE_CANDIDATE_0001")
        self.assertTrue(cv.path_a_code_reference)
        self.assertTrue(cv.path_c_topology)
        self.assertFalse(cv.path_d_consumer_confirmed)

    def test_rejected_hypotheses_preservation(self):
        """Verify preservation of rejected semantic hypotheses."""
        bundle = build_semantics_catalog(self.fn_catalog, self.arith_catalog)
        rej = bundle.rejected_hypotheses
        self.assertIsInstance(rej, RejectedSemanticCatalog)
        self.assertGreaterEqual(len(rej.rejected_items), 4)

        rej_ids = [item.hypothesis_id for item in rej.rejected_items]
        self.assertIn("REJ_2D_KF_TABLE_MAP_DESC_0001", rej_ids)
        self.assertIn("REJ_UNSUPPORTED_RPM_AXIS_LABEL", rej_ids)
        self.assertIn("REJ_UNSUPPORTED_TORQUE_MAP_LABEL", rej_ids)
        self.assertIn("REJ_CONSTANT_6800_PROVEN_TURBINE_CEILING", rej_ids)
        self.assertIn("REJ_0x00086000_PROVEN_FUNCTION_ENTRY", rej_ids)
        self.assertIn("REJ_0x00086002_CALLER_EDGE", rej_ids)
        self.assertIn("REJ_0x0009C580_CALLER_EDGE", rej_ids)


if __name__ == "__main__":
    unittest.main()
