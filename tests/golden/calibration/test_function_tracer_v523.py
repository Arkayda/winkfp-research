"""Golden tests for Milestone 5.23 Function Boundary & Register Flow Tracer.

Tests Task 2: CALFUNC identification, caller/callee reconstruction,
register argument flow, descriptor consumption, and curve selection logic.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.function_tracer_v523 import (
    CalfuncRecord,
    FunctionTraceCatalog,
    trace_calibration_functions,
)


class TestFunctionTracerV523(unittest.TestCase):
    """Test suite for calibration function reconstruction and register flow tracing."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)

    def test_calfunc_0001_reconstruction(self):
        """Verify CALCODE_CANDIDATE_0001_AXIS_CURVE_LOOKUP reconstruction and object linkage."""
        catalog = trace_calibration_functions(self.pa_image, self.da_image)
        self.assertIsInstance(catalog, FunctionTraceCatalog)
        self.assertGreaterEqual(len(catalog.functions), 1)

        f1 = catalog.functions[0]
        self.assertEqual(f1.id, "CALCODE_CANDIDATE_0001")
        self.assertEqual(f1.name, "CALCODE_CANDIDATE_0001_AXIS_CURVE_LOOKUP")
        self.assertEqual(f1.code_location, "0x00086000")
        self.assertEqual(f1.classification, "BASIC_BLOCK_ENTRY")
        self.assertEqual(f1.procedure_identity, "UNCONFIRMED")
        self.assertEqual(f1.function_entry, "UNCONFIRMED")
        self.assertEqual(f1.verified_callers, [])
        self.assertEqual(f1.descriptor, "MAP_DESC_0001")
        self.assertEqual(f1.descriptor_address, "0x000454A0")
        self.assertEqual(len(f1.axes), 2)
        self.assertEqual(len(f1.curves), 3)

        # Check axes linkage
        ax_x = f1.axes[0]
        self.assertEqual(ax_x["id"], "TARGET_1_AXIS_X")
        self.assertEqual(ax_x["address"], "0x00063AD6")
        self.assertEqual(ax_x["element_count"], 12)

        ax_y = f1.axes[1]
        self.assertEqual(ax_y["id"], "TARGET_2_AXIS_Y")
        self.assertEqual(ax_y["address"], "0x00063AF0")
        self.assertEqual(ax_y["element_count"], 8)

        # Check curves linkage
        c1 = f1.curves[0]
        self.assertEqual(c1["id"], "TARGET_3_KL_CURVE_1")
        self.assertEqual(c1["address"], "0x0006418A")
        self.assertEqual(c1["element_count"], 12)
        self.assertEqual(c1["associated_axis"], "TARGET_1_AXIS_X")

        c2 = f1.curves[1]
        self.assertEqual(c2["id"], "TARGET_4_KL_CURVE_2")
        self.assertEqual(c2["address"], "0x000641A4")
        self.assertEqual(c2["element_count"], 12)
        self.assertEqual(c2["associated_axis"], "TARGET_1_AXIS_X")

        c3 = f1.curves[2]
        self.assertEqual(c3["id"], "TARGET_5_KL_CURVE_3")
        self.assertEqual(c3["address"], "0x000641BE")
        self.assertEqual(c3["element_count"], 8)
        self.assertEqual(c3["associated_axis"], "TARGET_2_AXIS_Y")

    def test_calfunc_dispatch_candidates(self):
        """Verify secondary dispatch candidates at 0x0004BD00 and 0x0004BD80."""
        catalog = trace_calibration_functions(self.pa_image, self.da_image)
        f1 = catalog.functions[0]
        self.assertIn("0x0004BD00", f1.dispatch_candidates)
        self.assertIn("0x0004BD80", f1.dispatch_candidates)
        self.assertEqual(f1.dispatch_status, "DISPATCH_CANDIDATE")

    def test_epistemic_evidence_ceiling(self):
        """Verify downstream semantic meaning does not exceed evidence ceiling."""
        catalog = trace_calibration_functions(self.pa_image, self.da_image)
        f1 = catalog.functions[0]
        self.assertEqual(f1.confidence, "UNCONFIRMED")
        self.assertEqual(f1.semantic_hypothesis, "UNKNOWN")
        self.assertEqual(f1.engineering_unit, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
