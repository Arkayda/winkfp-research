"""Golden tests for Milestone 5.22: Architecture Validation and Executable Region Inventory.

Tests Gate 0 (Architecture Validation) and Gate 1 (Executable Region Inventory).
Validates Infineon TriCore TC1796/TC1766 processor model, 16-bit/32-bit instruction boundaries,
endianness, and memory block segmentation.
"""

import unittest
from pathlib import Path

from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
    ArchitectureValidator,
    CodeRegionCatalog,
    detect_executable_regions,
)


class TestCodeRegionsV522(unittest.TestCase):
    """Test suite for TriCore architecture validation and executable region modeling."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found in workspace.")
        cls.pa_image = IntelHexParser.parse_file(cls.pa_path)
        cls.da_image = IntelHexParser.parse_file(cls.da_path)

    def test_architecture_validation_gate0(self):
        """Gate 0: Validate TriCore instruction discrimination and vector table decoding."""
        validator = ArchitectureValidator(self.pa_image)
        record = validator.validate_architecture()
        self.assertEqual(record.architecture, "Infineon TriCore TC1796 / TC1766")
        self.assertEqual(record.status, "PROVEN")
        self.assertEqual(record.instruction_endianness, "LITTLE_ENDIAN")
        self.assertEqual(record.data_endianness, "BIG_ENDIAN")
        # Ensure 16-bit / 32-bit boundary discrimination is verified
        self.assertTrue(record.instruction_boundary_check_passed)
        self.assertGreater(len(record.decoded_samples), 5)
        # Vector table entries in Segment 0 must be 8-byte aligned with 2b + 4b + 2b structure
        sample0 = record.decoded_samples[0]
        self.assertEqual(sample0["address"], "0x00030000")
        self.assertEqual(sample0["entry_length_bytes"], 8)
        self.assertEqual(sample0["instruction_count"], 3)

    def test_executable_region_inventory_gate1(self):
        """Gate 1: Verify canonical inventory of code and data segments in 7591971A.0pa."""
        catalog = detect_executable_regions(self.pa_image, self.da_image)
        self.assertIsInstance(catalog, CodeRegionCatalog)
        self.assertEqual(catalog.architecture, "Infineon TriCore TC1796 / TC1766")

        # Verify flash segment table bounds at 0x00044240
        self.assertEqual(catalog.flash_segment_table["bootloader"]["start"], "0x00030000")
        self.assertEqual(catalog.flash_segment_table["bootloader"]["end"], "0x0004FFFB")
        self.assertEqual(catalog.flash_segment_table["calibration"]["start"], "0x000500E8")
        self.assertEqual(catalog.flash_segment_table["calibration"]["end"], "0x00075FFF")
        self.assertEqual(catalog.flash_segment_table["application"]["start"], "0x00080000")
        self.assertEqual(catalog.flash_segment_table["application"]["end"], "0x000FFEA7")

        # Verify application code regions (Segments 8-15)
        app_regions = [r for r in catalog.regions if r.region_type == "APPLICATION_CODE"]
        self.assertGreaterEqual(len(app_regions), 8)
        self.assertTrue(any(r.start_address == "0x00080000" for r in app_regions))

        # Verify descriptor block (Segment 3)
        desc_region = next(r for r in catalog.regions if r.region_type == "DESCRIPTOR_BLOCK")
        self.assertEqual(desc_region.start_address, "0x000454A0")
        self.assertEqual(desc_region.size, 48)

        # Verify calibration directory (DA Segment 4)
        cal_dir = next(r for r in catalog.regions if r.region_type == "CALIBRATION_DIRECTORY")
        self.assertEqual(cal_dir.start_address, "0x00076000")
        self.assertEqual(cal_dir.size, 36704)


if __name__ == "__main__":
    unittest.main()
