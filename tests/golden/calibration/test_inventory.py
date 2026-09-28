"""Golden unit tests for Flash Inventory and Layout scanner."""

import tempfile
import unittest
from pathlib import Path
from reconstruction.calibration.hex_parser import IntelHexParser, MemorySegment, ParsedHexImage
from reconstruction.calibration.inventory import (
    FlashArtifact,
    MemorySegmentLayout,
    build_flash_inventory,
    build_flash_layout,
)


class TestFlashInventoryAndLayout(unittest.TestCase):
    """Test suite for deterministic flash inventory and memory layout builder."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        # Create mock calibration hex file
        self.mock_da_path = self.base_path / "A7592133.0da"
        self.mock_da_content = (
            ";$REFERENZ 0479S90T641Z1ZY02 V\n"
            ";$CARB_MODE_9_CVN 0000F41E Y\n"
            ":020000040005F5\n"      # 0x00050000
            ":0400000000000020DC\n"  # 4 bytes signature prefix
            ":0400A0003034373988\n"  # 0x000500A0: '0479'
            ":00000001FF\n"
        )
        self.mock_da_path.write_text(self.mock_da_content, encoding="latin-1")

        # Create mock program hex file
        self.mock_pa_path = self.base_path / "7591971A.0pa"
        self.mock_pa_content = (
            ";;ZL_System: GS19.11.0\n"
            ":020000040000FA\n"      # 0x00000000
            ":04000000A1A2A3A472\n"  # Vector table
            ":00000001FF\n"
        )
        self.mock_pa_path.write_text(self.mock_pa_content, encoding="latin-1")

        # Create mock DAT file
        self.mock_dat_path = self.base_path / "GKE195.DAT"
        self.mock_dat_content = "7592132,0000000,7591972,A,7592133DA,0FFFFFFFFFD,000,1 7\n"
        self.mock_dat_path.write_text(self.mock_dat_content, encoding="latin-1")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_build_flash_inventory_metadata(self) -> None:
        """Verify building flash inventory returns expected schema and fields."""
        files = {
            "primary_calibration": self.mock_da_path,
            "base_program": self.mock_pa_path,
            "assembly_table": self.mock_dat_path,
        }
        inventory = build_flash_inventory(files)
        self.assertIn("artifacts", inventory)
        self.assertIn("total_analyzed", inventory)
        self.assertEqual(inventory["total_analyzed"], 3)

        artifacts = inventory["artifacts"]
        by_name = {a["filename"]: a for a in artifacts}

        # Check primary calibration entry
        da_entry = by_name["A7592133.0da"]
        self.assertEqual(da_entry["artifact_type"], "calibration")
        self.assertEqual(da_entry["format"], "intel_hex_bmw")
        self.assertEqual(da_entry["provenance"], "[C]")
        self.assertIn("0479S90T641Z1ZY02", da_entry["references"])
        self.assertTrue(len(da_entry["sha256"]) == 64)

        # Check DAT entry
        dat_entry = by_name["GKE195.DAT"]
        self.assertEqual(dat_entry["artifact_type"], "assembly_table")
        self.assertEqual(dat_entry["format"], "text_dat")

    def test_build_flash_layout_classification(self) -> None:
        """Verify memory segment layout assigns classifications and address boundaries."""
        da_parsed = IntelHexParser.parse(self.mock_da_content)
        pa_parsed = IntelHexParser.parse(self.mock_pa_content)

        images = {
            "A7592133.0da": da_parsed,
            "7591971A.0pa": pa_parsed,
        }
        layout = build_flash_layout(images)
        self.assertIn("images", layout)
        self.assertIn("A7592133.0da", layout["images"])

        da_layout = layout["images"]["A7592133.0da"]
        self.assertIn("segments", da_layout)
        segments = da_layout["segments"]
        self.assertTrue(len(segments) >= 1)

        # First segment at 0x00050000 should be rsa_signature or header
        first_seg = segments[0]
        self.assertEqual(first_seg["start_address"], "0x00050000")
        self.assertIn(first_seg["classification"], ["rsa_signature", "metadata_header", "calibration_data"])
        self.assertIn(first_seg["evidence_class"], ["[C]", "[O]", "[R]"])

    def test_deterministic_layout_output(self) -> None:
        """Verify that running layout generation multiple times produces identical dicts."""
        da_parsed = IntelHexParser.parse(self.mock_da_content)
        layout1 = build_flash_layout({"A7592133.0da": da_parsed})
        layout2 = build_flash_layout({"A7592133.0da": da_parsed})
        self.assertEqual(layout1, layout2)


if __name__ == "__main__":
    unittest.main()
