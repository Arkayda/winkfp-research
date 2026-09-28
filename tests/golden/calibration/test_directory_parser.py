"""Test suite for Calibration Directory Parser and Structural Models (Milestone 5.20)."""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.calibration.directory_parser import (
    CalibrationDirectoryParser,
    ExtractedCalibrationObject,
)
from reconstruction.calibration.hex_parser import IntelHexParser

DA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
PA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")


class TestDirectoryParser(unittest.TestCase):
    """Test suite for Segment 4 calibration directory parsing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = IntelHexParser.parse_file(DA_FILE)
        cls.parser = CalibrationDirectoryParser(cls.image)
        cls.objects = cls.parser.parse_objects()

    def test_01_pointer_table_dimensions(self) -> None:
        """Verify Segment 4 directory table contains exactly 9,176 32-bit pointers."""
        seg4 = self.image.segments[4]
        self.assertEqual(seg4.start_address, 0x00076000)
        self.assertEqual(seg4.end_address, 0x0007EF60)
        self.assertEqual(len(seg4.data), 36704)
        self.assertEqual(len(self.parser.raw_pointers), 9176)

    def test_02_first_and_last_pointer_targets(self) -> None:
        """Verify first and last pointers point to expected calibration addresses."""
        ptrs = self.parser.raw_pointers
        self.assertEqual(ptrs[0], 0x0005069E)
        self.assertTrue(ptrs[-1] <= 0x000714F0)

    def test_03_extracted_object_count(self) -> None:
        """Verify parser extracts distinct non-empty calibration objects."""
        self.assertTrue(len(self.objects) > 8000)

    def test_04_scalar_constants_extraction(self) -> None:
        """Verify 1-byte, 2-byte, and 4-byte scalar constants are classified correctly."""
        scalars = [obj for obj in self.objects if obj.object_type == "SCALAR"]
        self.assertTrue(len(scalars) > 1000)
        widths = {len(obj.data) for obj in scalars}
        self.assertTrue(widths.issubset({1, 2, 4}))

    def test_05_monotonic_axis_extraction(self) -> None:
        """Verify 1D monotonic breakpoint axes are extracted with verified ordering."""
        axes = [obj for obj in self.objects if obj.object_type == "AXIS"]
        self.assertTrue(len(axes) > 50)
        for ax in axes:
            self.assertTrue(ax.is_monotonic)
            self.assertTrue(ax.element_count >= 4)

    def test_06_2d_table_extraction(self) -> None:
        """Verify 2D calibration tables with valid grid factors are extracted."""
        tables = [obj for obj in self.objects if obj.object_type == "TABLE_2D"]
        self.assertTrue(len(tables) > 50)
        for tbl in tables:
            self.assertEqual(len(tbl.dimensions), 2)
            nx, ny = tbl.dimensions
            elem_size = 2 if tbl.width_bits == 16 else 1
            self.assertEqual(len(tbl.data), nx * ny * elem_size)


if __name__ == "__main__":
    unittest.main()
