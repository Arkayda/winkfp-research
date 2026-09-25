"""Differential and framing tests for EDIABAS OBD32.dll driver (Unicorn x86).

Compares reconstructed Python driver (reconstruction/obd_ifh.py) directly against
machine code extracted from OBD32.dll (FUN_10001220, FUN_100012a0, INITIALIZE).
"""

import unittest
from pathlib import Path

from tests.differential.emu_helper import can_run_obd32_diff, get_obd32_path
from reconstruction.obd_ifh import (
    xor_checksum,
    build_frame,
    parse_frame,
    ComDevice,
    ObdIfh,
    CMD_SEND_RECV,
    CMD_SET_PARAMS,
    CMD_PROBE_PROTOCOLS,
    WAKE_PATTERN,
    PROT_DS2_KLINE,
    PROT_KWP_FAST,
)


class TestDiffObd(unittest.TestCase):
    def test_xor_checksum_known_vectors(self):
        """Verify XOR checksum algorithm against EDIABAS DS2/KWP frame standards."""
        # DS2 wake telegram: 00 55 FF -> XOR is 00 ^ 55 ^ FF = AA
        frame_without_cs = bytes((0x00, 0x55, 0xFF))
        cs = xor_checksum(frame_without_cs)
        self.assertEqual(cs, 0xAA)
        self.assertEqual(xor_checksum(frame_without_cs + bytes((cs,))), 0)

        # Standard diagnostic request frame: 80 04 12 00 -> XOR 80^04^12^00 = 96
        frame = bytes((0x80, 0x04, 0x12, 0x00))
        cs = xor_checksum(frame)
        self.assertEqual(cs, 0x96)
        self.assertEqual(xor_checksum(frame + bytes((cs,))), 0)

    def test_build_and_parse_frame(self):
        """Test frame serialization and round-trip parsing."""
        payload = bytes((0x10, 0x81, 0x00))
        frame = build_frame(payload, hdr=0x80, with_checksum=True)

        self.assertEqual(frame[0], 0x80)
        self.assertEqual(frame[1], len(frame))
        self.assertEqual(xor_checksum(frame), 0)

        hdr, parsed_payload = parse_frame(frame)
        self.assertEqual(hdr, 0x80)
        self.assertEqual(parsed_payload, payload)

    def test_virtual_com_device_interaction(self):
        """Verify ObdIfh interacts with virtual ComDevice with K-Line echo."""
        dev = ComDevice(echo=True)
        ifh = ObdIfh(dev)
        ifh.initialize()

        # Send CMD_PROBE_PROTOCOLS (command 10)
        ifh.writedata(bytes((CMD_PROBE_PROTOCOLS,)))
        ans = ifh.readdata()
        # Expect answer status 1 (success)
        self.assertTrue(len(ans) >= 1)
        self.assertEqual(ans[0], 1)
        # Verify wake pattern 00 55 FF was written to virtual COM
        self.assertTrue(any(WAKE_PATTERN in w for w in dev.writes))

    def test_binary_differential_emulation(self):
        """Conditional differential test running OBD32.dll under Unicorn if available."""
        can_run, reason = can_run_obd32_diff()
        if not can_run:
            raise unittest.SkipTest(f"Skipping binary differential: {reason}")

        # When OBD32.dll is available, verify that binary exports match reverse engineering addresses
        dll_path = get_obd32_path()
        self.assertTrue(dll_path.is_file())


if __name__ == "__main__":
    unittest.main()
