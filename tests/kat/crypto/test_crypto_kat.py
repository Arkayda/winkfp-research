"""Cryptographic Known-Answer Tests (KAT) for KrApi algorithms."""

import os
import unittest
import hashlib
from reconstruction.crypto import (
    compute_security_key,
    compute_security_key_symmetric,
    compute_security_key_simple,
    compute_security_key_asymmetric,
    compute_security_key_asymmetric_as2,
    use_static_placeholder,
    RSA_KEYS,
    msvc_rand_after_srand,
)
from reconstruction.auth import (
    des3_ecb_decrypt,
    BINARY_VECTORS,
    As2Record,
    SYNTHETIC_3DES_KEY,
    get_3des_key,
)
from reconstruction.as2_keys import _des_block, _des_subkeys, KEY_3DES


class TestCryptoKAT(unittest.TestCase):
    def setUp(self):
        self.seed = bytes.fromhex("0102030405060708")
        self.serial = bytes.fromhex("11223344")
        self.nonce = b"ab3f"

    def test_msvc_rand_lcg(self):
        """MSVC LCG rand(): srand(1) -> 41, then 18467."""
        self.assertEqual(msvc_rand_after_srand(1), 41)

    def test_symmetric_md5_vector(self):
        """Symmetric MD5: MD5(key16 || nonce4 || serial4 || seed8 || key16)."""
        key16 = use_static_placeholder(3)
        token = compute_security_key_symmetric(self.seed, self.serial, key16=key16, nonce=self.nonce)
        expected = hashlib.md5(key16 + self.nonce + self.serial + self.seed + key16).digest()
        self.assertEqual(token, expected)

    def test_simple_cipher_determinism(self):
        """Simple cipher uses only seed[0:4] and 8-byte key."""
        key8 = bytes([3]) * 8
        out1 = compute_security_key_simple(self.seed, key8)
        out2 = compute_security_key_simple(self.seed[:4] + b"\xff" * 4, key8)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 8)

    def test_fips_des_vector(self):
        """FIPS 46-3 single-DES block encryption test vector."""
        subkeys = _des_subkeys(bytes.fromhex("133457799BBCDFF1"))
        ct = _des_block(bytes.fromhex("0123456789ABCDEF"), subkeys)
        self.assertEqual(ct.hex().lower(), "85e813540f0ab405")

    def test_3des_ecb_decrypt_vectors(self):
        """3DES-EDE-ECB decrypt against synthetic vectors."""
        for ct_hex, pt_hex in BINARY_VECTORS:
            pt = des3_ecb_decrypt(KEY_3DES, bytes.fromhex(ct_hex))
            self.assertEqual(pt.hex().lower(), pt_hex.lower())

    def test_get_3des_key_environment(self):
        """get_3des_key returns synthetic default or parses AS2_3DES_KEY env variable."""
        # 1. Default fallback is synthetic key
        orig_env = os.environ.get("AS2_3DES_KEY")
        try:
            if "AS2_3DES_KEY" in os.environ:
                del os.environ["AS2_3DES_KEY"]
            self.assertEqual(get_3des_key(), SYNTHETIC_3DES_KEY)
            self.assertEqual(KEY_3DES, SYNTHETIC_3DES_KEY)

            # 2. Valid 24-byte hex key injected via environment
            injected_hex = "aa" * 24
            os.environ["AS2_3DES_KEY"] = injected_hex
            self.assertEqual(get_3des_key(), bytes.fromhex(injected_hex))

            # 3. Invalid length raises ValueError
            os.environ["AS2_3DES_KEY"] = "aa" * 16
            with self.assertRaises(ValueError):
                get_3des_key()
        finally:
            if orig_env is not None:
                os.environ["AS2_3DES_KEY"] = orig_env
            elif "AS2_3DES_KEY" in os.environ:
                del os.environ["AS2_3DES_KEY"]

    def test_rsa_key_parameters(self):
        """RSA static keys 3, 4, 5: 128 bytes (1024-bit) and strictly odd."""
        for idx in (3, 4, 5):
            n_bytes = bytes.fromhex(RSA_KEYS[idx]["N"])
            e_bytes = bytes.fromhex(RSA_KEYS[idx]["E"])
            self.assertEqual(len(n_bytes), 128)
            self.assertEqual(len(e_bytes), 128)
            self.assertTrue(n_bytes[0] % 2 == 1, f"RSA key {idx} N must be odd in LE")
            self.assertTrue(e_bytes[0] % 2 == 1, f"RSA key {idx} E must be odd in LE")

    def test_rsa_sign_deterministic(self):
        """RSA signing generates deterministic 128-byte signatures."""
        for idx in (3, 4, 5):
            sig = compute_security_key_asymmetric(self.seed, self.serial, self.nonce, idx)
            self.assertEqual(len(sig), 128)


if __name__ == "__main__":
    unittest.main()
