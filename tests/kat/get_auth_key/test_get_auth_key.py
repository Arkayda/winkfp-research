"""GetAuthKey resolution unit tests using synthetic key store."""

import unittest
from pathlib import Path
from reconstruction.auth import As2KeyStore, resolve_auth_key


class TestGetAuthKey(unittest.TestCase):
    def setUp(self):
        fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "synthetic"
        self.c_path = fixtures_dir / "synthetic_sgidc.as2"
        self.d_path = fixtures_dir / "synthetic_sgidd.as2"
        self.store = As2KeyStore.from_paths({3: self.c_path, 4: self.d_path})

    def test_resolve_symmetric_gke192(self):
        """Resolving GKE192 in container 3 returns 16-byte decrypted symmetric key."""
        blob = resolve_auth_key(self.store, "GKE192", 3)
        self.assertEqual(len(blob), 16)
        self.assertEqual(blob.hex().lower(), "0102030405060708090a0b0c0d0e0f10")

    def test_resolve_simple_hkl65(self):
        """Resolving HKL65 in container 3 returns 8-byte Simple key."""
        blob = resolve_auth_key(self.store, "HKL65", 3)
        self.assertEqual(len(blob), 8)
        self.assertEqual(blob.hex().lower(), "0102030405060708")

    def test_resolve_acc65_container_4(self):
        """Resolving ACC65 in container 4 returns 16-byte key."""
        blob = resolve_auth_key(self.store, "ACC65", 4)
        self.assertEqual(len(blob), 16)
        self.assertEqual(blob.hex().lower(), "2122232425262728292a2b2c2d2e2f30")

    def test_unregistered_ecu_raises(self):
        """Unregistered ECU raises KeyError."""
        with self.assertRaises(KeyError):
            resolve_auth_key(self.store, "UNKNOWN_ECU", 3)


if __name__ == "__main__":
    unittest.main()
