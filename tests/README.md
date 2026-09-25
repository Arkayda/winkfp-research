# Verification & Test Suites

The `winkfp-research` test suite establishes evidence tiers (L1–L5) for cryptographic algorithms, communication adapters, flash state machines, and hardware safety interlocks.

## Test Tiers

### 1. Known-Answer Tests (KAT) — `tests/kat/`
Validates core cryptographic and key-resolution algorithms against fixed reference vectors derived from reverse-engineering Ghidra decompiler output.
- `tests/kat/crypto/test_crypto_kat.py`: Symmetric MD5 authentication (`FUN_004b9f50`), Simple XOR/table encryption (`FUN_004ba080`), and Asymmetric RSA modular exponentiation (`FUN_004b9e30`).
- `tests/kat/auth/test_auth_kat.py`: AS2 container 3DES-ECB decryption (`sgidc.as2`, `sgidd.as2`).
- `tests/kat/get_auth_key/test_get_auth_key.py`: Key derivation and resolution for various ECU identifiers and modes.

### 2. Golden Protocol Tests — `tests/golden/`
Validates state machine transitions, telegram sequencing, and safety gates against synthetic mock buses.
- `tests/golden/vdle/test_golden_vdle.py`: VDLE state machine, OPPS hardware initialization, table loading, and 21-byte block formatting.
- `tests/golden/ediabas/test_golden_ediabas.py`: EDIABAS mock bus job handling, result set indexing, and error status simulation.
- `tests/golden/flash/test_golden_flash.py`: End-to-end `FlashRunner` flashing cycle on `MockBus` with `SafetyContext` battery voltage interlock.

### 3. Differential Tests — `tests/differential/`
Validates Python reconstructions against original WinKFP machine code running under Unicorn x86 emulation.
- `tests/differential/auth/test_diff_auth.py`: Direct instruction-level execution of `FUN_004b9f50`, `FUN_004ba080`, and `FUN_004b9e30` in `winkfpt.exe`.
- `tests/differential/vdle/test_diff_vdle.py`: Block framing and OPPS job sequences against `winkfpt.exe`.
- `tests/differential/ediabas/test_diff_obd.py`: OBD32.dll framing, XOR checksums, and K-Line virtual COM device interaction.

*Note: Differential tests automatically and gracefully skip if `unicorn`, `pefile`, or the original OEM binaries are not present in the environment.*

## Running Tests

### Master Test Runner
```bash
# Run all available test suites
python3 tests/run_tests.py

# Run only Known-Answer Tests (KAT)
python3 tests/run_tests.py --tier kat

# Run only Golden Protocol Tests
python3 tests/run_tests.py --tier golden

# Run only Differential Tests
python3 tests/run_tests.py --tier differential
```

### Standard Unittest Discovery
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
