"""Authentication Known-Answer Tests (KAT) using synthetic fixtures."""

import unittest
from pathlib import Path
from reconstruction.auth import As2KeyStore, As2Record
from reconstruction.crypto import compute_security_key_symmetric, compute_security_key_simple


class TestAuthKAT(unittest.TestCase):
    def setUp(self):
        fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "synthetic"
        self.c_path = fixtures_dir / "synthetic_sgidc.as2"
        self.d_path = fixtures_dir / "synthetic_sgidd.as2"
        self.store = As2KeyStore.from_paths({3: self.c_path, 4: self.d_path})

    def test_store_parsing(self):
        """Synthetic containers parse correctly by index."""
        self.assertIn("GKE192", self.store._by_index[3])
        self.assertIn("HKL65", self.store._by_index[3])
        self.assertIn("ACC65", self.store._by_index[4])

    def test_symmetric_key_extraction(self):
        """GKE192 16-byte key extracts and matches decrypted binary vector."""
        key = self.store.sym_key16("GKE192", 3)
        self.assertEqual(len(key), 16)
        self.assertEqual(key.hex().lower(), "0102030405060708090a0b0c0d0e0f10")

    def test_simple_key_extraction(self):
        """HKL65 8-byte key extracts cleanly from plaintext $U record."""
        key = self.store.simple_key8("HKL65", 3)
        self.assertEqual(len(key), 8)
        self.assertEqual(key.hex().lower(), "0102030405060708")

    def test_missing_ecu_raises(self):
        """Unknown ECU lookup raises KeyError."""
        with self.assertRaises(KeyError):
            self.store.auth_blob("NONEXISTENT", 3)


if __name__ == "__main__":
    unittest.main()
