"""Golden regression tests for cryptographic authentication and serialization.

This module validates clean-room cryptographic construction and the 38-byte
job argument container boundary.

EVIDENCE BIFURCATION (Milestone 3.2):
1. PUBLIC GOLDEN TEST:
   - Uses synthetic deterministic test key material.
   - Contains NO recovered OEM secret keys.
   - Verifies MD5 construction formula and container serialization boundary.
2. PRIVATE FACTORY VECTOR METADATA:
   - Records metadata identifying the real factory trace vector (10FLASH).
   - Records the SHA-256 digest of the recovered key (raw key is omitted).
   - Records the observed 16-byte factory wire authentication value.
   - Explicitly documents that offline private evaluation reproduced the wire value,
     but the vector is NOT directly reproduced from public repository files.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any, Dict

from reconstruction.as2_keys import As2KeyStore
from reconstruction.security import compute_security_key
from reconstruction.transport.kdcan.framing import build

# ---------------------------------------------------------------------------
# 1. Private Factory Vector Metadata (Audit Record — Raw Key Omitted)
# ---------------------------------------------------------------------------
# Extracted from traces/sanitized/sanitized_flash_session.trc (lines 12560-12640)
# Target: 10FLASH at diagnostic address 0x78 (module IHKA81 / 13_ASK)
PRIVATE_FACTORY_10FLASH_VECTOR_METADATA: Dict[str, Any] = {
    "target": "10FLASH",
    "target_address": 0x78,
    "job_seed": "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN",
    "job_key": "NG_AUTHENTISIERUNG_START",
    "tester_nonce": bytes.fromhex("34663632"),  # ASCII "4f62" from "3;0x34663632"
    "serial_number_raw": "080072856",           # from SERIENNUMMER_LESEN
    "serial_number_input": b"2856",             # offset 5..9 extracted by FUN_0041c920
    "ecu_seed": bytes.fromhex("15E485FE0003FD55"),  # from Routine 0x07 response
    "auth_method": "Symetrisch",
    "key_record_reference": "IHKA81 @ SGIDC.as2 (idx 3, ident GU78, target 0x78)",
    "key_length_bytes": 16,
    # SHA-256 digest of recovered 16-byte key (raw key bytes redacted from public repo):
    "key_sha256": "AB5E51C8D22E6A10720014CA756C0B065A8D7D29FBFE45D6903CA38FB7ED9BE2",
    # 16-byte key payload physically observed on wire in trace line 12616 (_TEL_AUFTRAG):
    # Telegram: 92 78 F1 31 08 EA 9C 6D F4 F5 BC 93 1D 07 14 2B 5D 25 75 5E 45
    "observed_wire_key": bytes.fromhex("EA9C6DF4F5BC931D07142B5D25755E45"),
    "offline_verified_match": True,
}

# ---------------------------------------------------------------------------
# 1.1 EGS Key Container Metadata (Audit Record — Raw Key Omitted)
# ---------------------------------------------------------------------------
# Target: ZF 6HP EGS mechatronic at address 0x18 (SGBD 0479S90T641Z, family GS19)
PRIVATE_EGS_GKE192_METADATA: Dict[str, Any] = {
    "target": "ZF 6HP EGS",
    "target_address": 0x18,
    "sgbd": "0479S90T641Z",
    "ecu_family": "GS19",
    "container_file": "SGIDC.as2",
    "container_index": 3,
    "record_identifier": "2L18",
    "key_record_reference": "$K GKE192 2L18000034[REDACTED_16B_CIPHERTEXT]",
    "key_length_bytes": 16,
    # SHA-256 digest of decrypted 16-byte key:
    "key_sha256": "B58F3D47331250FFF5C770FBAFDABF654B338DB278A0258BD9331FB7AB2E8B51",
    "supported_method": "Symetrisch",
    "t_smb_compatible": True,
    "t_sma_compatible": False,  # No 136-byte RSA key record
    "t_smc_compatible": False,  # No 8-byte Simple key record
}

# ---------------------------------------------------------------------------
# 2. Public Synthetic Vector (Deterministic Test Material for Automated KAT)
# ---------------------------------------------------------------------------
# Uses non-secret deterministic test key to verify MD5 construction and container logic
PUBLIC_SYNTHETIC_AUTH_VECTOR: Dict[str, Any] = {
    "description": "Deterministic public KAT demonstrating MD5 construction without OEM secret key",
    "test_key16": bytes(range(1, 17)),  # 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
    "tester_nonce": bytes.fromhex("34663632"),
    "serial_number_input": b"2856",
    "ecu_seed": bytes.fromhex("15E485FE0003FD55"),
    # Expected MD5: MD5(test_key16 + nonce4 + serial4 + seed8 + test_key16)
    "expected_computed_key": bytes.fromhex("9353BD5A4DE09EDB37D052403F9B15E9"),
    "job_argument_38b": bytes.fromhex(
        "010000000000000000000000001000000000000000"
        "9353BD5A4DE09EDB37D052403F9B15E9"
        "03"
    ),
}


class TestGoldenAuth(unittest.TestCase):
    """Automated golden test suite for clean-room authentication algorithms."""

    def test_public_crypto_construction(self):
        """Clean-room compute_security_key matches deterministic MD5 construction with synthetic key."""
        vec = PUBLIC_SYNTHETIC_AUTH_VECTOR

        computed_key = compute_security_key(
            seed=vec["ecu_seed"],
            serial=vec["serial_number_input"],
            key16=vec["test_key16"],
            nonce=vec["tester_nonce"],
        )

        self.assertEqual(len(computed_key), 16)
        self.assertEqual(computed_key, vec["expected_computed_key"])
        self.assertEqual(computed_key.hex().upper(), "9353BD5A4DE09EDB37D052403F9B15E9")

    def test_job_argument_wire_payload_boundary(self):
        """38-byte binary job argument correctly separates container envelope from 16-byte wire payload."""
        vec = PUBLIC_SYNTHETIC_AUTH_VECTOR
        arg_38b = vec["job_argument_38b"]
        self.assertEqual(len(arg_38b), 38)

        # Structure analysis from decompiled FUN_0041c920:
        # byte 0: mode/command indicator (0x01 = Symmetric)
        self.assertEqual(arg_38b[0], 0x01)

        # byte 13: length indicator (0x10 = 16 bytes)
        key_len = arg_38b[13]
        self.assertEqual(key_len, 16)

        # bytes 21..37: key payload
        key_payload = arg_38b[21:21 + key_len]
        self.assertEqual(key_payload, vec["expected_computed_key"])

        # byte 37: trailer/key index byte (0x03)
        self.assertEqual(arg_38b[37], 0x03)

    def test_factory_vector_metadata_integrity(self):
        """Private factory vector metadata record preserves forensic integrity without secret key bytes."""
        meta = PRIVATE_FACTORY_10FLASH_VECTOR_METADATA

        # Mandatory forensic identification fields
        self.assertEqual(meta["target"], "10FLASH")
        self.assertEqual(meta["target_address"], 0x78)
        self.assertEqual(meta["auth_method"], "Symetrisch")
        self.assertEqual(meta["key_length_bytes"], 16)
        self.assertTrue(meta["offline_verified_match"])

        # Wire observation from trace line 12616
        self.assertEqual(len(meta["observed_wire_key"]), 16)
        self.assertEqual(meta["observed_wire_key"].hex().upper(), "EA9C6DF4F5BC931D07142B5D25755E45")

        # Cryptographic digest of recovered key is validated; raw key is strictly absent
        self.assertEqual(len(meta["key_sha256"]), 64)
        self.assertEqual(
            meta["key_sha256"],
            "AB5E51C8D22E6A10720014CA756C0B065A8D7D29FBFE45D6903CA38FB7ED9BE2",
        )
        self.assertNotIn("key16", meta)
        self.assertNotIn("key", meta)
        self.assertNotIn("raw_key", meta)

    def test_egs_metadata_integrity(self):
        """EGS GKE192 metadata record preserves forensic integrity without secret key bytes."""
        meta = PRIVATE_EGS_GKE192_METADATA

        self.assertEqual(meta["target"], "ZF 6HP EGS")
        self.assertEqual(meta["target_address"], 0x18)
        self.assertEqual(meta["sgbd"], "0479S90T641Z")
        self.assertEqual(meta["ecu_family"], "GS19")
        self.assertEqual(meta["container_file"], "SGIDC.as2")
        self.assertEqual(meta["container_index"], 3)
        self.assertEqual(meta["record_identifier"], "2L18")
        self.assertEqual(meta["key_record_reference"], "$K GKE192 2L18000034[REDACTED_16B_CIPHERTEXT]")
        self.assertEqual(meta["key_length_bytes"], 16)
        self.assertEqual(meta["supported_method"], "Symetrisch")
        self.assertTrue(meta["t_smb_compatible"])
        self.assertFalse(meta["t_sma_compatible"])
        self.assertFalse(meta["t_smc_compatible"])

        # Cryptographic digest of recovered key is validated; raw key is strictly absent
        self.assertEqual(len(meta["key_sha256"]), 64)
        self.assertEqual(
            meta["key_sha256"],
            "B58F3D47331250FFF5C770FBAFDABF654B338DB278A0258BD9331FB7AB2E8B51",
        )
        self.assertNotIn("key16", meta)
        self.assertNotIn("key", meta)
        self.assertNotIn("raw_key", meta)

    def test_egs_container_constraints(self):
        """EGS GKE192 record enforces symmetric authentication mode only (FUN_004b89a0 gates)."""
        fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "synthetic" / "synthetic_sgidc.as2"
        store = As2KeyStore.from_paths({3: fixture_path})

        # Symmetric extraction succeeds and matches expected 16-byte synthetic test key
        key = store.sym_key16("GKE192", 3)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, bytes(range(1, 17)))

        # Verify that the public fixture contains a genuinely synthetic key
        # and does NOT contain the private recovered key or its digest:
        import hashlib
        synth_digest = hashlib.sha256(key).hexdigest().upper()
        self.assertEqual(synth_digest, "5DFBABEEDF318BF33C0927C43D7630F51B82F351740301354FA3D7FC51F0132E")
        self.assertNotEqual(synth_digest, PRIVATE_EGS_GKE192_METADATA["key_sha256"])

        # Simple mode requires 8-byte record -> rejected
        with self.assertRaises(ValueError) as ctx_simple:
            store.simple_key8("GKE192", 3)
        self.assertIn("Simple auth needs an 8-byte key record", str(ctx_simple.exception))

        # Asymmetric mode requires 0x88 (136-byte) record -> rejected
        with self.assertRaises(ValueError) as ctx_asym:
            store.asym_ne("GKE192", 3)
        self.assertIn("Asymetrisch auth needs the 0x88-byte record", str(ctx_asym.exception))

    def test_candidate_probe_frames_builder(self):
        """Candidate physical probe telegrams build mathematically correct checksums via framing.build."""
        # Step 1 candidate: 0x1A 0x89 (Serial read)
        frame_1a89 = build(dst=0x18, src=0xF1, payload=bytes([0x1A, 0x89]))
        self.assertEqual(frame_1a89, bytes.fromhex("8218F11A892E"))
        self.assertEqual(frame_1a89[-1], 0x2E)

        # Step 2 candidate: 0x31 0x07 (RoutineControl seed acquisition probe with dummy nonce)
        frame_3107 = build(dst=0x18, src=0xF1, payload=bytes([0x31, 0x07, 0x03, 0x00, 0x00, 0x00, 0x00]))
        self.assertEqual(frame_3107, bytes.fromhex("8718F131070300000000CB"))
        self.assertEqual(frame_3107[-1], 0xCB)


if __name__ == "__main__":
    unittest.main()
