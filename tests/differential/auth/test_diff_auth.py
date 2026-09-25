"""Differential tests for authentication and crypto against original winkfpt.exe (Unicorn x86).

Compares reconstructed Python algorithms (reconstruction/crypto, reconstruction/auth)
directly against machine code extracted from winkfpt.exe.
"""

import struct
import unittest
from pathlib import Path

from tests.differential.emu_helper import WinEmu, can_run_winkfp_diff, get_winkfpt_path
from reconstruction.crypto.symmetric import compute_security_key, use_static_placeholder
from reconstruction.crypto.simple import compute_security_key_simple
from reconstruction.crypto.asymmetric import compute_security_key_asymmetric
from reconstruction.auth import As2KeyStore


class TestDiffAuth(unittest.TestCase):
    def setUp(self):
        can_run, reason = can_run_winkfp_diff()
        if not can_run:
            raise unittest.SkipTest(f"Skipping differential test: {reason}")
        self.exe_path = get_winkfpt_path()
        self.emu = WinEmu(self.exe_path)

    def test_diff_symmetric_md5(self):
        """Verify reconstruction of FUN_004b9f50 against binary machine code."""
        F_SYM = 0x4B9F50
        vectors = [
            (bytes.fromhex("0102030405060708"), b"WK93", b"ab3f", 3),
            (bytes.fromhex("deadbeefcafebabe"), b"SG#1", b"00ff", 4),
            (bytes.fromhex("ffffffffffffffff"), b"ZZZZ", b"f00d", 5),
            (bytes.fromhex("0000000000000000"), b"ABCD", b"1234", 3),
        ]

        for seed, serial, nonce, idx in vectors:
            p_seed = self.emu.alloc(seed)
            p_rnd = self.emu.alloc(nonce)
            p_ser = self.emu.alloc(serial[:4].ljust(4, b"\x00"))
            p_out = self.emu.alloc(b"\x00" * 16)

            self.emu.call(F_SYM, [p_seed, p_rnd, p_ser, idx, p_out])
            got = self.emu.read(p_out, 16)

            expected = compute_security_key(
                seed, serial, key16=use_static_placeholder(idx), nonce=nonce
            )
            self.assertEqual(got, expected, f"Mismatch on idx={idx}, seed={seed.hex()}")

    def test_diff_simple_mode(self):
        """Verify reconstruction of FUN_004ba080 against binary machine code."""
        F_SIMPLE = 0x4BA080
        vectors = [
            (bytes.fromhex("01020304"), bytes([3]) * 8),
            (bytes.fromhex("a1b2c3d4"), bytes(range(8))),
            (bytes.fromhex("ffffffff"), b"\x11\x22\x33\x44\x55\x66\x77\x88"),
        ]

        for seed, key8 in vectors:
            p_in = self.emu.alloc(seed + b"\x00" * 28)
            p_key = self.emu.alloc(key8)
            p_out = self.emu.alloc(b"\x00" * 8)

            self.emu.call(F_SIMPLE, [p_in, 8, p_key, p_out])
            got = self.emu.read(p_out, 8)

            expected = compute_security_key_simple(seed, key8)
            self.assertEqual(got, expected, f"Mismatch on seed={seed.hex()}")


if __name__ == "__main__":
    unittest.main()
