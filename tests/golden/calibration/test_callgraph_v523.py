"""Golden tests for Milestone 5.23 Control-Flow & Callgraph Support Engine.

Tests TriCore instruction decode, branch/call discrimination, basic block
splitting, and callgraph edge extraction on 7591971A.0pa.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.callgraph_v523 import (
    BasicBlock,
    CallEdge,
    CallGraph,
    ControlFlowGraph,
    InstructionRecord,
    build_control_flow_graph,
    decode_tricore_instruction,
)


class TestCallgraphV523(unittest.TestCase):
    """Test suite for TriCore control-flow and callgraph construction."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists():
            raise unittest.SkipTest("Target reference binary 7591971A.0pa not found.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)

    def test_instruction_decoding_primitives(self):
        """Verify TriCore opcode discrimination and length calculation."""
        # 16-bit instruction (even byte 0) e.g. 0x00, 0x04
        inst16 = decode_tricore_instruction(b"\x04\x88", 0x00030000)
        self.assertEqual(inst16.length_bytes, 2)
        self.assertEqual(inst16.address, 0x00030000)
        self.assertFalse(inst16.is_call)

        # 32-bit instruction (odd byte 0) e.g. 0xD9, 0x5D
        inst32 = decode_tricore_instruction(b"\xd9\xf6\xac\xe0", 0x00030002)
        self.assertEqual(inst32.length_bytes, 4)
        self.assertEqual(inst32.address, 0x00030002)
        self.assertTrue(inst32.is_call or inst32.is_branch or inst32.mnemonic != "UNKNOWN")

    def test_vector_table_control_flow(self):
        """Verify basic block recovery across vector table at 0x00030000."""
        cfg = build_control_flow_graph(self.pa_image, start_address=0x00030000, length_bytes=64)
        self.assertIsInstance(cfg, ControlFlowGraph)
        self.assertGreater(len(cfg.blocks), 0)
        for block in cfg.blocks:
            self.assertGreater(len(block.instructions), 0)
            self.assertLessEqual(block.start_address, block.end_address)

    def test_call_edge_extraction(self):
        """Verify call edge discrimination without creating synthetic edges."""
        cfg = build_control_flow_graph(self.pa_image, start_address=0x00080000, length_bytes=512)
        cg = cfg.extract_callgraph()
        self.assertIsInstance(cg, CallGraph)
        for edge in cg.edges:
            self.assertIn(edge.edge_type, ["CALL_DIRECT", "CALL_INDIRECT", "TAIL_CALL"])
            self.assertTrue(edge.caller_address.startswith("0x"))
            self.assertTrue(edge.target_address.startswith("0x"))


if __name__ == "__main__":
    unittest.main()
