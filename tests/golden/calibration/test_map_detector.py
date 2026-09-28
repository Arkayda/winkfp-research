"""Golden unit tests for candidate map, axis, and checksum region detectors."""

import unittest
from reconstruction.calibration.hex_parser import MemorySegment, ParsedHexImage
from reconstruction.calibration.map_detector import (
    AxisCandidate,
    ChecksumRegion,
    MapCandidate,
    detect_axes,
    detect_checksum_regions,
    detect_map_candidates,
)


class TestMapDetector(unittest.TestCase):
    """Test suite for deterministic detection of axes, maps, and checksum regions."""

    def test_detect_monotonic_16bit_little_endian_axis(self) -> None:
        """Verify detection of 16-bit little-endian monotonic sequence."""
        # 8 points: 100, 200, 300, 400, 500, 600, 700, 800 (0x0064, 0x00C8, 0x012C, ...)
        raw_vals = [100, 200, 300, 400, 500, 600, 700, 800]
        data = bytearray(0x100)
        offset = 0x20
        for i, val in enumerate(raw_vals):
            data[offset + i * 2 : offset + (i + 1) * 2] = val.to_bytes(2, byteorder="little")

        seg = MemorySegment(start_address=0x00050000, end_address=0x00050100, data=bytes(data))
        axes = detect_axes(seg, min_points=6, max_points=32)

        self.assertTrue(len(axes) >= 1)
        found = next((a for a in axes if a.start_address == 0x00050020), None)
        self.assertIsNotNone(found)
        self.assertEqual(found.width, 16)
        self.assertEqual(found.endianness, "little_endian")
        self.assertEqual(found.element_count, 8)
        self.assertEqual(found.decoded_values, raw_vals)
        self.assertEqual(found.monotonicity, "strictly_increasing")
        self.assertEqual(found.units, "UNKNOWN")
        self.assertEqual(found.evidence_class, "[O]")

    def test_detect_candidate_2d_map(self) -> None:
        """Verify map candidate detector links 2D table to adjacent axis candidates."""
        # Axis 1 (X): 4 points (0x10, 0x20, 0x30, 0x40)
        # Axis 2 (Y): 4 points (0x05, 0x0A, 0x0F, 0x14)
        # Table data: 16 points (4x4)
        data = bytearray(0x200)
        # Put X-axis at 0x10 (4 uint16 LE)
        for i, v in enumerate([10, 20, 30, 40]):
            data[0x10 + i * 2 : 0x10 + (i + 1) * 2] = v.to_bytes(2, "little")
        # Put Y-axis at 0x18 (4 uint16 LE)
        for i, v in enumerate([100, 200, 300, 400]):
            data[0x18 + i * 2 : 0x18 + (i + 1) * 2] = v.to_bytes(2, "little")
        # Put 16 bytes of values at 0x20
        for i in range(16):
            data[0x20 + i] = (i * 5) & 0xFF

        seg = MemorySegment(start_address=0x00050000, end_address=0x00050200, data=bytes(data))
        axes = detect_axes(seg, min_points=4, max_points=8)
        maps = detect_map_candidates(seg, axes)

        self.assertTrue(len(maps) >= 1)
        # Ensure candidate dimensions are labeled as 'candidate' and have provenance [R]
        for m in maps:
            self.assertIn("candidate", m.dimensions.lower())
            self.assertEqual(m.evidence_class, "[R]")
            self.assertEqual(m.units, "UNKNOWN")

    def test_detect_checksum_and_cvn_regions(self) -> None:
        """Verify detection of CARB CVN and file checksum locations."""
        data = bytearray(0x200)
        # At 0x000500EE: F4 1E (CARB CVN 0000F41E)
        data[0x00EE : 0x00F0] = bytes([0xF4, 0x1E])
        seg = MemorySegment(start_address=0x00050000, end_address=0x00050200, data=bytes(data))

        image = ParsedHexImage(
            segments=[seg],
            headers={
                "CARB_MODE_9_CVN": "0000F41E Y",
                "CHECKSUMME": "2352 H",
            },
            trailers=[
                {
                    "type": 0x10,
                    "address_int": 0x00050080,
                    "address": "0x00050080",
                    "data": bytes([0x74, 0x4D, 0x69, 0x07]),
                }
            ],
        )

        regions = detect_checksum_regions(image)
        self.assertTrue(len(regions) >= 2)

        # Check CVN region
        cvn = next((r for r in regions if "CARB_CVN" in r.checksum_algorithm), None)
        self.assertIsNotNone(cvn)
        self.assertEqual(cvn.checksum_location["address"], "0x000500EE")
        self.assertEqual(cvn.checksum_location["expected_value"], "0x0000F41E")
        self.assertIn("[C]", cvn.confidence)


if __name__ == "__main__":
    unittest.main()
