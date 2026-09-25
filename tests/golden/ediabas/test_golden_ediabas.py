"""Golden tests for EDIABAS API mock and IFH K-Line framing."""

import unittest
from reconstruction.ediabas import MockBus, build_frame, parse_frame, xor_checksum


class TestGoldenEDIABAS(unittest.TestCase):
    def test_kline_xor_checksum(self):
        """K-Line frame with appended checksum XORs to zero."""
        payload = bytes.fromhex("8012F10103")
        chk = xor_checksum(payload)
        frame = payload + bytes([chk])
        self.assertEqual(xor_checksum(frame), 0)

    def test_kline_build_parse_roundtrip(self):
        """K-Line frame round-trip serialization with checksum."""
        payload = b"\x12\x34\x56"
        frame = build_frame(payload, hdr=0x80, with_checksum=True)
        self.assertEqual(xor_checksum(frame), 0)
        hdr, parsed_payload = parse_frame(frame)
        self.assertEqual(hdr, 0x80)
        self.assertEqual(parsed_payload, payload)

    def test_mock_bus_diagnostics(self):
        """MockBus provides deterministic responses."""
        bus = MockBus(ident="GKE192")
        self.assertTrue(bus.job("DLE08", "IDENT"))
        self.assertEqual(bus.read_text("SG_PHYS_HWNR"), "GKE192")
        self.assertEqual(bus.read_text("AUTHENTISIERUNG"), "T_SMB")


if __name__ == "__main__":
    unittest.main()
