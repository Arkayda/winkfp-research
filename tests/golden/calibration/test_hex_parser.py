"""Golden unit tests for BMW Intel Hex Parser with custom record type support."""

import unittest
from reconstruction.calibration.hex_parser import IntelHexParser, MemorySegment, ParsedHexImage


class TestIntelHexParser(unittest.TestCase):
    """Test suite for Intel Hex parser supporting standard and BMW-specific records."""

    def test_standard_data_and_eof(self) -> None:
        """Verify parsing of standard Type 00 data and Type 01 EOF."""
        hex_text = (
            ":0400000001020304F2\n"
            ":0400040005060708DE\n"
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 1)
        seg = parsed.segments[0]
        self.assertEqual(seg.start_address, 0x0000)
        self.assertEqual(seg.end_address, 0x0008)
        self.assertEqual(seg.size, 8)
        self.assertEqual(seg.data, bytes([1, 2, 3, 4, 5, 6, 7, 8]))

    def test_extended_linear_addressing_type_04(self) -> None:
        """Verify Type 04 extended linear address sets upper 16 bits."""
        hex_text = (
            ":020000040005F5\n"      # Linear base = 0x00050000
            ":04001000AABBCCDDDE\n"  # Address 0x00050010
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 1)
        seg = parsed.segments[0]
        self.assertEqual(seg.start_address, 0x00050010)
        self.assertEqual(seg.end_address, 0x00050014)
        self.assertEqual(seg.data, bytes([0xAA, 0xBB, 0xCC, 0xDD]))

    def test_extended_segment_addressing_type_02(self) -> None:
        """Verify Type 02 extended segment address shifts by 4 bits."""
        hex_text = (
            ":020000025000AC\n"      # Segment base = 0x5000 << 4 = 0x00050000
            ":040020001122334432\n"  # Address 0x00050020
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 1)
        seg = parsed.segments[0]
        self.assertEqual(seg.start_address, 0x00050020)
        self.assertEqual(seg.end_address, 0x00050024)
        self.assertEqual(seg.data, bytes([0x11, 0x22, 0x33, 0x44]))

    def test_dual_linear_and_segment_addressing(self) -> None:
        """Verify linear and segment base combine: linear + segment + offset."""
        hex_text = (
            ":020000040002F8\n"  # Linear base = 0x00020000
            ":020000021000EC\n"  # Segment base = 0x00010000
            ":02005000A1B25B\n"  # Address = 0x00020000 + 0x00010000 + 0x0050 = 0x00030050
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 1)
        self.assertEqual(parsed.segments[0].start_address, 0x00030050)
        self.assertEqual(parsed.segments[0].data, bytes([0xA1, 0xB2]))

    def test_custom_bmw_type_10_trailer(self) -> None:
        """Verify BMW custom record Type 0x10 is recorded as trailer metadata."""
        hex_text = (
            ":020000040005F5\n"
            ":0400000001020304F2\n"
            ":0400001012345678D8\n"  # Type 0x10 trailer record
            ":00000010F0\n"          # Type 0x10 zero-length trailer end
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 1)
        self.assertEqual(len(parsed.trailers), 2)
        self.assertEqual(parsed.trailers[0]["type"], 0x10)
        self.assertEqual(parsed.trailers[0]["data"], bytes([0x12, 0x34, 0x56, 0x78]))

    def test_record_checksum_validation(self) -> None:
        """Verify invalid checksum raises ValueError."""
        bad_hex = ":040000000102030400\n:00000001FF\n"  # 00 is wrong checksum
        with self.assertRaises(ValueError):
            IntelHexParser.parse(bad_hex)

    def test_header_directives_extraction(self) -> None:
        """Verify header comments starting with ;$ are extracted as directives."""
        hex_text = (
            ";==========================================================\n"
            ";$REFERENZ 0479S90T641Z1ZY02\n"
            ";$CHECKSUMME 2352 H\n"
            ";$CARB_MODE_9_CVN 0000F41E Y\n"
            ":020000040005F5\n"
            ":020000001234B8\n"
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(parsed.headers.get("REFERENZ"), "0479S90T641Z1ZY02")
        self.assertEqual(parsed.headers.get("CHECKSUMME"), "2352 H")
        self.assertEqual(parsed.headers.get("CARB_MODE_9_CVN"), "0000F41E Y")

    def test_disjoint_segment_merging(self) -> None:
        """Verify non-contiguous data blocks become separate segments."""
        hex_text = (
            ":0400000001020304F2\n"  # 0x0000..0x0004
            ":0400100005060708D2\n"  # 0x0010..0x0014 (gap 0x0004..0x0010)
            ":00000001FF\n"
        )
        parsed = IntelHexParser.parse(hex_text)
        self.assertEqual(len(parsed.segments), 2)
        self.assertEqual(parsed.segments[0].start_address, 0x0000)
        self.assertEqual(parsed.segments[0].end_address, 0x0004)
        self.assertEqual(parsed.segments[1].start_address, 0x0010)
        self.assertEqual(parsed.segments[1].end_address, 0x0014)


if __name__ == "__main__":
    unittest.main()
