#!/usr/bin/env python3
"""Demonstration of BMW WinKFP authentication calculation using synthetic vectors.

This script executes:
1. Symmetric MD5 key derivation (T_SMA, T_SMB, T_SMC).
2. Asymmetric RSA-1024 modular exponentiation with per-dword byte swapping.
3. AS2 container loading and decryption using 3DES ECB.
"""

import sys
from pathlib import Path

# Add repository root to path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reconstruction.crypto.symmetric import compute_security_key, use_static_placeholder
from reconstruction.crypto.asymmetric import compute_security_key_asymmetric
from reconstruction.auth.key_containers import As2KeyStore


def main():
    print("=== WinKFP Research: Authentication Demo ===\n")

    # 1. Symmetric Authentication Demo
    seed = bytes.fromhex("0102030405060708")
    serial = b"GKE1"
    nonce = b"ab3f"
    key_idx = 3

    sym_key = compute_security_key(seed, serial, key16=use_static_placeholder(key_idx), nonce=nonce)
    print(f"[1] Symmetric Key Derivation (Index {key_idx}):")
    print(f"    ECU Seed:   {seed.hex()}")
    print(f"    Serial:     {serial.decode('ascii')}")
    print(f"    Tester Rnd: {nonce.decode('ascii')}")
    print(f"    Derived SG-Schluessel (16 bytes): {sym_key.hex()}\n")

    # 2. Asymmetric RSA Authentication Demo
    asym_key = compute_security_key_asymmetric(seed, serial, nonce=nonce, key_index=key_idx)
    print(f"[2] Asymmetric Key Derivation (RSA Modexp, Index {key_idx}):")
    print(f"    Derived Response Signature (128 bytes): {asym_key[:32].hex()}...")
    print(f"    Full Signature Length: {len(asym_key)} bytes\n")

    # 3. AS2 Key Store Demo (using synthetic fixtures)
    fixtures_dir = ROOT / "tests" / "fixtures" / "synthetic"
    c_path = fixtures_dir / "synthetic_sgidc.as2"
    d_path = fixtures_dir / "synthetic_sgidd.as2"

    store = As2KeyStore.from_paths({3: c_path, 4: d_path})
    blob = store.auth_blob("GKE192", 3)
    print("[3] Synthetic AS2 Key Store Lookup:")
    print(f"    Found key record for GKE192 index 3")
    print(f"    Decrypted payload length: {len(blob)} bytes\n")

    print("Demo completed successfully.")


if __name__ == "__main__":
    main()
