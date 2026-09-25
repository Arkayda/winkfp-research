# Reconstructed Clean-Room Implementation (`reconstruction/`)

This directory contains the independent, clean-room Python 3 reconstruction of the legacy BMW WinKFP and EDIABAS flashing toolchain.

---

## 1. Clean-Room Architecture & Packages

```text
reconstruction/
├── __init__.py
├── runner.py                    # High-level flash orchestration engine (FlashRunner)
├── crypto/                      # Reconstructed cryptographic routines (KrApi)
│   ├── symmetric/               # MD5 HMAC authentication (compute_security_key_symmetric)
│   ├── simple/                  # Proprietary 8-byte cipher (compute_security_key_simple)
│   └── asymmetric/              # RSA-512 / RSA-1024 modular exponentiation (LE bignum)
├── auth/                        # Security access & container key management
│   ├── key_containers/          # SGIDC.as2 / SGIDD.as2 parser & 3DES-EDE-ECB decryptor
│   ├── get_auth_key/            # Runtime GetAuthKey simulation & key lookup
│   └── retry_chain/             # 3x attempt retry state machine & auto-negotiation
├── vdle/                        # Vehicle Download Engine (VDLE)
│   ├── protocol/                # Command tokens (INIT_VDLE, TP switches) & OPPS setup
│   ├── segments/                # Segment table parser & chunk iteration
│   └── flash_schreiben/         # 21-byte block header builder & XXL threshold logic
├── ediabas/                     # Diagnostic communication runtime
│   ├── api/                     # EDIABAS api32.dll ctypes adapter & MockBus simulator
│   └── ifh/                     # OBD32 serial K-Line driver emulation & XOR frame checksums
├── transport/                   # Low-level network transport
│   └── isotp.py                 # Standalone ISO 15765-2 framing implementation
└── safety/                      # Flashing interlocks & precondition checks
    ├── id_check.py              # ID_CHECK.DAT rule parser
    └── hypotheses.py            # Strict Limits parser and battery/voltage verification
```

---

## 2. Compatibility & Imports

All modules can be imported either via their modular subpackage paths:
```python
from reconstruction.crypto import compute_security_key_symmetric
from reconstruction.auth import As2KeyStore
from reconstruction.vdle import build_flash_block
from reconstruction.ediabas import MockBus
from reconstruction.safety import Limits
```
or via the top-level backwards-compatible facades (`reconstruction.security`, `reconstruction.as2_keys`, `reconstruction.vdle`, etc.).
