"""Golden tests for Milestone 5.22: MAP_DESC_0001 Deep Trace, Axis Lookup & 1D Curve Refinement.

Tests Gate 4 (Descriptor Reconstruction), Gate 6 (Axis Lookup), Gate 7 (Curve Access),
Gate 8 (Interpolation Analysis), Gate 9 (Scaling Runtime), Gate 10 (Output Consumer),
and Gate 11 (Static Control-Flow Execution Graph).
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.runtime_tracer_v522 import (
    TraceResultsBundle,
    trace_map_desc_0001,
)


class TestRuntimeTracerV522(unittest.TestCase):
    """Test suite for runtime code path tracing and 1D curve refinement."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found in workspace.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)

    def test_map_desc_0001_trace_and_refinement(self):
        """Verify MAP_DESC_0001 5 [START, END] bounding pairs and 1D curve refinement (Gate 4)."""
        bundle = trace_map_desc_0001(self.pa_image, self.da_image)
        self.assertIsInstance(bundle, TraceResultsBundle)

        desc = bundle.descriptor_trace
        self.assertEqual(desc.descriptor_id, "MAP_DESC_0001")
        self.assertEqual(desc.source_address, "0x000454A0")
        self.assertEqual(len(desc.targets), 5)

        # Target 1: Axis X (12 points signed int16)
        t1 = desc.targets[0]
        self.assertEqual(t1.target_id, "TARGET_1_AXIS_X")
        self.assertEqual(t1.start_address, "0x00063AD6")
        self.assertEqual(t1.end_address, "0x00063AEF")
        self.assertEqual(t1.length_bytes, 26)
        self.assertEqual(t1.span_bytes, 26)
        self.assertEqual(t1.metadata_bytes, 2)
        self.assertEqual(t1.payload_bytes, 24)
        self.assertEqual(t1.element_count, 12)
        self.assertEqual(t1.structural_format, "COUNT_HEADER_UINT16 + N_ELEMENTS")
        self.assertIn("span_bytes (26) = metadata_bytes (2) + element_count (12) * element_width (2)", t1.mathematical_identity)
        self.assertEqual(t1.structural_class, "AXIS_X")
        self.assertEqual(t1.endianness, "BIG_ENDIAN")
        self.assertEqual(t1.semantic_status, "UNCONFIRMED")
        self.assertEqual(t1.semantic_hypothesis, "UNKNOWN")
        self.assertEqual(t1.raw_values[0], -10)
        self.assertEqual(t1.raw_values[-1], 700)

        # Target 2: Axis Y (8 points unsigned uint16)
        t2 = desc.targets[1]
        self.assertEqual(t2.target_id, "TARGET_2_AXIS_Y")
        self.assertEqual(t2.start_address, "0x00063AF0")
        self.assertEqual(t2.end_address, "0x00063B01")
        self.assertEqual(t2.length_bytes, 18)
        self.assertEqual(t2.span_bytes, 18)
        self.assertEqual(t2.metadata_bytes, 2)
        self.assertEqual(t2.payload_bytes, 16)
        self.assertEqual(t2.element_count, 8)
        self.assertEqual(t2.structural_format, "COUNT_HEADER_UINT16 + N_ELEMENTS")
        self.assertIn("span_bytes (18) = metadata_bytes (2) + element_count (8) * element_width (2)", t2.mathematical_identity)
        self.assertEqual(t2.structural_class, "AXIS_Y")
        self.assertEqual(t2.endianness, "BIG_ENDIAN")
        self.assertEqual(t2.semantic_status, "UNCONFIRMED")
        self.assertEqual(t2.semantic_hypothesis, "UNKNOWN")
        self.assertEqual(t2.raw_values[0], 100)
        self.assertEqual(t2.raw_values[-1], 5500)

        # Target 3: KL Curve 1 (12 points signed int16) — Refined from 2D KF to 1D KL!
        t3 = desc.targets[2]
        self.assertEqual(t3.target_id, "TARGET_3_KL_CURVE_1")
        self.assertEqual(t3.start_address, "0x0006418A")
        self.assertEqual(t3.end_address, "0x000641A3")
        self.assertEqual(t3.length_bytes, 26)
        self.assertEqual(t3.span_bytes, 26)
        self.assertEqual(t3.metadata_bytes, 2)
        self.assertEqual(t3.payload_bytes, 24)
        self.assertEqual(t3.element_count, 12)
        self.assertEqual(t3.structural_format, "COUNT_HEADER_UINT16 + N_ELEMENTS")
        self.assertIn("span_bytes (26) = metadata_bytes (2) + element_count (12) * element_width (2)", t3.mathematical_identity)
        self.assertEqual(t3.structural_class, "1D_CHARACTERISTIC_CURVE")
        self.assertEqual(t3.raw_values[0], -15)
        self.assertEqual(t3.raw_values[-1], 700)

        # Target 4: KL Curve 2 (12 points signed int16)
        t4 = desc.targets[3]
        self.assertEqual(t4.target_id, "TARGET_4_KL_CURVE_2")
        self.assertEqual(t4.start_address, "0x000641A4")
        self.assertEqual(t4.end_address, "0x000641BD")
        self.assertEqual(t4.length_bytes, 26)
        self.assertEqual(t4.span_bytes, 26)
        self.assertEqual(t4.metadata_bytes, 2)
        self.assertEqual(t4.payload_bytes, 24)
        self.assertEqual(t4.element_count, 12)
        self.assertEqual(t4.structural_format, "COUNT_HEADER_UINT16 + N_ELEMENTS")
        self.assertIn("span_bytes (26) = metadata_bytes (2) + element_count (12) * element_width (2)", t4.mathematical_identity)
        self.assertEqual(t4.structural_class, "1D_CHARACTERISTIC_CURVE")

        # Target 5: KL Curve 3 (8 points unsigned uint16)
        t5 = desc.targets[4]
        self.assertEqual(t5.target_id, "TARGET_5_KL_CURVE_3")
        self.assertEqual(t5.start_address, "0x000641BE")
        self.assertEqual(t5.end_address, "0x000641CF")
        self.assertEqual(t5.length_bytes, 18)
        self.assertEqual(t5.span_bytes, 18)
        self.assertEqual(t5.metadata_bytes, 2)
        self.assertEqual(t5.payload_bytes, 16)
        self.assertEqual(t5.element_count, 8)
        self.assertEqual(t5.structural_format, "COUNT_HEADER_UINT16 + N_ELEMENTS")
        self.assertIn("span_bytes (18) = metadata_bytes (2) + element_count (8) * element_width (2)", t5.mathematical_identity)
        self.assertEqual(t5.structural_class, "1D_CHARACTERISTIC_CURVE")

    def test_axis_lookup_and_curve_access(self):
        """Verify axis lookup and curve access models (Gates 6 & 7)."""
        bundle = trace_map_desc_0001(self.pa_image, self.da_image)
        axis_lookup = bundle.axis_lookup
        self.assertEqual(len(axis_lookup.lookups), 2)
        lookup_x = next(l for l in axis_lookup.lookups if l.target_axis == "0x00063AD6")
        self.assertEqual(lookup_x.search_algorithm, "CLAMPED_INTERVAL_SEARCH")
        self.assertEqual(lookup_x.element_count, 12)
        self.assertEqual(lookup_x.monotonicity, "STRICTLY_INCREASING")
        self.assertEqual(lookup_x.endianness, "BIG_ENDIAN")
        self.assertEqual(lookup_x.semantic_status, "UNCONFIRMED")
        self.assertEqual(lookup_x.semantic_hypothesis, "UNKNOWN")

        lookup_y = next(l for l in axis_lookup.lookups if l.target_axis == "0x00063AF0")
        self.assertEqual(lookup_y.search_algorithm, "CLAMPED_INTERVAL_SEARCH")
        self.assertEqual(lookup_y.element_count, 8)
        self.assertEqual(lookup_y.monotonicity, "STRICTLY_INCREASING")
        self.assertEqual(lookup_y.endianness, "BIG_ENDIAN")
        self.assertEqual(lookup_y.semantic_status, "UNCONFIRMED")
        self.assertEqual(lookup_y.semantic_hypothesis, "UNKNOWN")

        curve_access = bundle.curve_access
        self.assertEqual(len(curve_access.accesses), 3)
        c1 = next(c for c in curve_access.accesses if c.target_address == "0x0006418A")
        self.assertEqual(c1.element_width_bits, 16)
        self.assertEqual(c1.stride_bytes, 2)
        self.assertEqual(c1.header_offset_bytes, 2)
        self.assertTrue(c1.signed)

    def test_interpolation_and_scaling(self):
        """Verify interpolation analysis and scaling constants evaluation (Gates 8 & 9)."""
        bundle = trace_map_desc_0001(self.pa_image, self.da_image)
        interp = bundle.interpolation_analysis
        self.assertEqual(interp.structural_model, "1D_LINEAR_PIECEWISE")
        self.assertEqual(interp.runtime_interpolation_status, "UNCONFIRMED")
        self.assertEqual(interp.confidence, "SUPPORTED")

        scaling = bundle.scaling_runtime
        self.assertEqual(len(scaling.constants), 3)
        c750 = next(c for c in scaling.constants if c.address == "0x000505BA")
        self.assertEqual(c750.decimal_value, 750)
        c500 = next(c for c in scaling.constants if c.address == "0x000505BC")
        self.assertEqual(c500.decimal_value, 500)
        c6800 = next(c for c in scaling.constants if c.address == "0x000505BE")
        self.assertEqual(c6800.decimal_value, 6800)
        self.assertEqual(c6800.layer_c_status, "UNKNOWN")

    def test_execution_graph_and_consumer(self):
        """Verify 10-node execution graph and consumer status (Gates 10 & 11)."""
        bundle = trace_map_desc_0001(self.pa_image, self.da_image)
        consumer = bundle.output_consumer
        self.assertEqual(consumer.consumer_status, "UNCONFIRMED")

        graph = bundle.execution_graph
        self.assertEqual(len(graph.nodes), 10)
        node_roles = [n["role"] for n in graph.nodes]
        self.assertEqual(node_roles, [
            "ENTRY",
            "DESCRIPTOR",
            "INPUT",
            "AXIS_LOOKUP",
            "INDEX_CALCULATION",
            "CURVE_ADDRESS",
            "CELL_READ",
            "INTERPOLATION",
            "SCALE_OFFSET",
            "OUTPUT_CONSUMER",
        ])
        self.assertEqual(len(graph.edges), 9)


if __name__ == "__main__":
    unittest.main()
