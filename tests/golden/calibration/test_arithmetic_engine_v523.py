"""Golden tests for Milestone 5.23 Machine Arithmetic & Transformation Engine.

Tests Task 3: Arithmetic chain extraction, interpolation classification,
scaling/bounds evaluation (750, 500, 6800), and evidence discipline.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.function_tracer_v523 import trace_calibration_functions
from reconstruction.calibration.arithmetic_engine_v523 import (
    ArithmeticAnalysisCatalog,
    ArithmeticOperation,
    InterpolationEvaluation,
    ScalingFunctionRecord,
    analyze_function_arithmetic,
)


class TestArithmeticEngineV523(unittest.TestCase):
    """Test suite for machine arithmetic modeling and scaling analysis."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)
        cls.fn_catalog = trace_calibration_functions(cls.pa_image, cls.da_image)

    def test_arithmetic_analysis_catalog(self):
        """Verify extraction of arithmetic chains and operations."""
        catalog = analyze_function_arithmetic(self.fn_catalog, self.pa_image, self.da_image)
        self.assertIsInstance(catalog, ArithmeticAnalysisCatalog)
        self.assertGreaterEqual(len(catalog.operations), 3)

        op_types = {op.operation_type for op in catalog.operations}
        self.assertTrue({"SUB", "MUL", "CLAMP"}.issubset(op_types) or len(op_types) >= 2)

    def test_interpolation_classification(self):
        """Verify interpolation analysis retains opcode unconfirmed status."""
        catalog = analyze_function_arithmetic(self.fn_catalog, self.pa_image, self.da_image)
        interp = catalog.interpolation
        self.assertIsInstance(interp, InterpolationEvaluation)
        self.assertEqual(interp.classification, "PIECEWISE_LINEAR")
        self.assertEqual(interp.structural_compatibility, "PROVEN")
        self.assertEqual(interp.runtime_opcode_execution, "UNCONFIRMED")

    def test_scaling_constants_epistemic_bounds(self):
        """Verify scaling constants 750, 500, and 6800 retain strict epistemic levels."""
        catalog = analyze_function_arithmetic(self.fn_catalog, self.pa_image, self.da_image)
        constants = {c.raw_value: c for c in catalog.scaling_constants}
        self.assertIn(750, constants)
        self.assertIn(500, constants)
        self.assertIn(6800, constants)

        c6800 = constants[6800]
        self.assertEqual(c6800.layer_a_binary, "PROVEN")
        self.assertIn("UNKNOWN", c6800.layer_c_semantics)
        self.assertIn("UNCONFIRMED", c6800.layer_c_semantics)


if __name__ == "__main__":
    unittest.main()
