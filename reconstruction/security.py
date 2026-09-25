"""Security Access reconstruction — KrApiLib, winkfpt.exe.

Everything in this module is reconstructed from decompiled code:
[C] = logic read from binary, [O] = exact string/constant found,
[R] = reconstruction with stated assumptions. No engineering
inventions here beyond explicitly marked parameters.

Rev 3 changes (external audit):
  * RSA keys re-extracted programmatically from Ghidra memory dump
    (hand transcription had corrupted E of keys 3/4 — 257 hex chars).
    All six blobs verified: 128 bytes, odd (parity is mandatory for
    RSA moduli/exponents — also the decisive check that byte order
    is little-endian).
  * nonce generation no longer pollutes the global RNG.
  * placeholder symmetric key requires explicit opt-in.
"""

import hashlib
import time
from typing import Optional

from .rsa_keys import RSA_KEYS as _RSA_KEYS

for _idx, _pair in _RSA_KEYS.items():
    for _part in ("N", "E"):
        _blob = bytes.fromhex(_pair[_part])          # ValueError if malformed
        assert len(_blob) == 128, f"key {_idx}{_part}: not 128 bytes"
        assert int.from_bytes(_blob, "little") & 1, f"key {_idx}{_part}: even (invalid RSA)"


def msvc_rand_after_srand(seed: int) -> int:
    """First rand() after srand(seed) — read directly from winkfpt's
    statically linked CRT [C]:
      FUN_005cafa9 srand:  holdrand = seed
      FUN_005cafbb rand:   holdrand = holdrand*0x343FD + 0x269EC3 (mod 2^32)
                           return (holdrand >> 16) & 0x7FFF
    Known control vector: srand(1) → rand() == 41."""
    holdrand = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return (holdrand >> 16) & 0x7FFF


# --- Symmetric: MD5(key16 ‖ nonce4 ‖ serial4 ‖ seed8 ‖ key16) — [C] --------


def generate_msvc_nonce(now: Optional[float] = None) -> bytes:
    """FUN_00461800 [C]: nonce = sprintf("%4.4lx", rand()) after
    srand(time(NULL)). The same original mints the nonce for ALL THREE
    auth arts (Symmetric MD5 and both RSA paths); rev 12 lets the
    orchestrator call this once per auth attempt so no mode needs a
    placeholder."""
    t = int(time.time() if now is None else now)
    return ("%4.4x" % msvc_rand_after_srand(t)).encode()


def compute_security_key(seed: bytes, serial: bytes, key16: bytes,
                         nonce: Optional[bytes] = None) -> bytes:
    """FUN_004bb930/bbdb0/bbf90/bbdf0 [C].

    seed   — 8 bytes, ECU result "ZUFALLSZAHL" of NG_AUTHENTISIERUNG_START
    serial — ECU "SERIENNUMMER", first 4 bytes used
    key16  — the real 16-byte symmetric key: sgidX.as2 container record
             (rev 10: reconstruction/as2_keys.py — As2KeyStore.sym_key16),
             NOT a static table; the .data bytes 03/04/05×16 are runtime
             SetSiproKey slots shipped as filler.
    nonce  — 4 bytes; original = last 4 ASCII-hex chars of "%4.4lx" % rand()
    """
    if len(seed) != 8:
        raise ValueError("seed must be 8 bytes")
    if len(key16) != 16:
        raise ValueError("key16 must be 16 bytes")
    if nonce is None:
        # FUN_00461800 [C] — see generate_msvc_nonce(); rand() ≤ 0x7FFF
        # → always 4 hex chars.
        nonce = generate_msvc_nonce()
    if len(nonce) != 4:
        raise ValueError("nonce must be 4 bytes")
    return hashlib.md5(key16 + nonce + serial[:4].ljust(4, b"\x00")
                       + seed + key16).digest()


def use_static_placeholder(key_index: int) -> bytes:
    """The static .data tables for indexes 3/4/5 hold the index byte x16
    [C].  Rev 10 finding: these are the SetSiproKey slots
    (FUN_004b8e10) which KrApiAuthenticate OVERWRITES at runtime with
    the first 8 bytes of the GetAuthKey blob before the cipher runs —
    proven by execution in kat_realkeys.py.  The pristine .data bytes
    are filler, never the shipped keys; use As2KeyStore for the real
    material.  Kept for lab tests only."""
    if key_index not in (3, 4, 5):
        raise ValueError("static placeholders exist for indexes 3/4/5 only")
    return bytes([key_index]) * 16


# --- Simple mode: proprietary 8-byte cipher FUN_004ba080 — [C] -------------


def _simple_cipher(buf_in: bytes, length: int, key8: bytes) -> bytes:
    out = bytearray(8)
    for i in range(8):                                    # phase 1 [C]
        out[i] = key8[i] ^ buf_in[length - 1 - i]
    for i in range(4):                                    # phase 2 [C]
        out[i] ^= (length >> (8 * i)) & 0xFF
    stream = buf_in + b"\x00" * 32                        # original reads
    off = 0                                               # past 8 bytes [R]
    while off < length:                                   # phase 3 [C]
        state = bytearray(out)
        for _round in range(4):
            for i in (7, 0, 1, 2, 3, 4, 5, 6):            # order [C]
                b = state[i]
                a = state[(i - 2) % 8]
                c = state[(i - 1) % 8]
                byte = stream[off + ((i + 1) % 8)]
                v = (((a & (0xFF ^ b)) | (c & b)) + byte) & 0xFF
                state[(i + 1) % 8] = (v * 3 + state[(i + 1) % 8] * 4) & 0xFF
        for i in range(8):
            out[i] = (out[i] + state[i]) & 0xFF
        off += 8
    return bytes(out)


def compute_security_key_simple(seed: bytes, key8: bytes) -> bytes:
    """FUN_004ba1b0 [C]: input = seed[0:4] + 4 zero bytes, 8-byte key
    (tables at 0x663390/98/a0 for indexes 3/4/5 [O])."""
    if len(seed) < 4:
        raise ValueError("seed must be at least 4 bytes")
    if len(key8) != 8:
        raise ValueError("key8 must be 8 bytes")
    return _simple_cipher(seed[:4] + b"\x00" * 4, 8, key8)


# --- Asymmetric: RSA-1024 over MD5(nonce‖serial‖seed) ----------------------
# Byte order [C]: FUN_004bb780 builds LITTLE-ENDIAN words; N/E blobs
# ([u32 word count][LE bytes]) are odd only under LE. Modexp is Montgomery
# m-ary FUN_004bd0e0 [C]. Output transform [C]: FUN_004b95a0 reverses the
# bytes INSIDE each 4-byte word (FUN_004b8a70 semantics) over keylen/2
# bytes of the result struct {count|key} — for the returned key itself
# (at +4) that is a per-dword byte reversal over 128 bytes.
#
# KAT (kat_emulate.py — Unicorn emulation of the original binary):
# 18/18 byte-exact, including raw modexp for keys 3/4/5 and FULL
# KrApiAuthenticate end-to-end for ALL THREE modes — the asymmetric run
# executes the real SetAsymmKey/SetAsymmKeyExp gates, RSA and result
# swap (GetAuthKey buffer format derived empirically in
# asym_full_kat.py: two 132-byte per-dword-byteswapped halves,
# length 0x108 — the only length FUN_004b8a00 accepts besides 0x88).


def compute_security_key_asymmetric(seed: bytes, serial: bytes, nonce: bytes,
                                    key_index: int) -> bytes:
    if key_index not in _RSA_KEYS:
        raise ValueError("key index must be one of "
                         f"{sorted(_RSA_KEYS)}")
    if len(seed) != 8 or len(nonce) != 4:
        raise ValueError("seed=8B, nonce=4B required")
    digest = hashlib.md5(nonce + serial[:4].ljust(4, b"\x00") + seed).digest()
    n = int.from_bytes(bytes.fromhex(_RSA_KEYS[key_index]["N"]), "little")
    e = int.from_bytes(bytes.fromhex(_RSA_KEYS[key_index]["E"]), "little")
    m = int.from_bytes(digest, "little")               # FUN_004bb780 [C]
    sig = pow(m, e, n)                                 # FUN_004bd0e0 [C]
    raw = sig.to_bytes(128, "little")
    return b"".join(raw[i:i + 4][::-1] for i in range(0, 128, 4))


# --- Asymmetric RSA-512 from the sgidX.as2 containers (rev 10) -------------


def _wordswap(buf: bytes) -> bytes:
    return b"".join(buf[i:i + 4][::-1] for i in range(0, len(buf), 4))


def compute_security_key_asymmetric_as2(seed: bytes, serial: bytes,
                                        nonce: bytes, blob88: bytes) -> bytes:
    """RSA-512 path with REAL per-ECU key material from the sgid
    containers (the 0x88 GetAuthKey form, [u32 BE 0x10][64B N MSB-first]
    [u32 BE 0x10][64B E MSB-first] after 3DES decryption — see
    reconstruction/as2_keys.py).

    Byte order [C by execution, kat_realkeys.py Part 3]: the two
    FUN_004b8a70 calls dword-swap the halves into the internal
    little-endian word representation; the modexp input is the MD5
    digest read little-endian (FUN_004bb780); the returned 64-byte
    result is the little-endian signature with per-dword byte
    reversal (the KrApiAuthenticate output loop)."""
    if len(seed) != 8 or len(nonce) != 4:
        raise ValueError("seed=8B, nonce=4B required")
    if len(blob88) != 0x88:
        raise ValueError("as2 asym blob must be 0x88 bytes")
    import struct as _struct
    if (_struct.unpack(">I", blob88[:4])[0] != 0x10
            or _struct.unpack(">I", blob88[68:72])[0] != 0x10):
        raise ValueError("unexpected KrApi count words")
    n_b, e_b = blob88[4:68], blob88[72:136]
    digest = hashlib.md5(nonce + serial[:4].ljust(4, b"\x00") + seed).digest()
    n = int.from_bytes(_wordswap(n_b), "little")
    e = int.from_bytes(_wordswap(e_b), "little")
    m = int.from_bytes(digest, "little")
    sig = pow(m, e, n)
    return _wordswap(sig.to_bytes(64, "little"))
