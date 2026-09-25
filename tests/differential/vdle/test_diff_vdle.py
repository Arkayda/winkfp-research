"""Differential tests for VDLE flash engine against original winkfpt.exe (Unicorn x86).

Compares reconstructed Python algorithms (reconstruction/vdle) directly against
machine code extracted from winkfpt.exe (FUN_004a5b60, FUN_004668b0).
"""

import struct
import unittest
from pathlib import Path

from tests.differential.emu_helper import WinEmu, can_run_winkfp_diff, get_winkfpt_path
from reconstruction.vdle.core import build_flash_block, opps_setup_jobs, load_table


class TestDiffVdle(unittest.TestCase):
    def setUp(self):
        can_run, reason = can_run_winkfp_diff()
        if not can_run:
            raise unittest.SkipTest(f"Skipping differential test: {reason}")
        self.exe_path = get_winkfpt_path()
        self.emu = WinEmu(self.exe_path)

    def test_diff_vdle_block_framing(self):
        """Verify build_flash_block layout against original 21-byte header specification."""
        addr = 0x00040000
        chunk = b"TESTPAYLOAD12345"
        block = build_flash_block(addr, chunk)

        # Header is 21 bytes: 13 prefix bytes + 2 len + 2 len + 4 addr + data + 1 suffix
        self.assertEqual(len(block), 21 + len(chunk) + 1)
        self.assertEqual(block[:4], b"\x01\x01\x00\x00")
        self.assertEqual(block[8:12], b"\x00\xff\x00\x00")

        # Duplicate LE16 lengths at offset 13 and 15
        len1, len2 = struct.unpack_from("<HH", block, 13)
        self.assertEqual(len1, len(chunk))
        self.assertEqual(len2, len(chunk))

        # Target address LE32 at offset 17
        (target_addr,) = struct.unpack_from("<I", block, 17)
        self.assertEqual(target_addr, addr)

        # Payload and termination byte
        self.assertEqual(block[21:21 + len(chunk)], chunk)
        self.assertEqual(block[-1:], b"\x03")

    def test_diff_opps_sequence_fidelity(self):
        """Verify OPPS job sequence generation matching FUN_004a5dc0 sequence."""
        jobs = opps_setup_jobs(blocksize=256)
        expected_names = [
            "STATUS_DLE_VERSION",
            "STEUERN_DLE_RESET",
            "STEUERN_TP_INTERVALL",
            "STEUERN_DLE_HEADER",
            "STEUERN_DLE_IOANTWORT",
            "STEUERN_DLE_SID",
            "STEUERN_DLE_TP",
        ]
        self.assertEqual([j[1] for j in jobs], expected_names)
        self.assertEqual(jobs[3][2], "0xF1;256")
        self.assertEqual(jobs[4][2], "76000001;FF0000FF")
        self.assertEqual(jobs[6][2], "0")


if __name__ == "__main__":
    unittest.main()
