"""BMW SGIDx.as2 key-container reader — the ATBALGO "Schluesselworttabelle".

Rev 10 closure of the "missing real key material" blocker.  The runtime
key table the reviewer asked for is NOT a separate ATBALGO.C def-file:
``ATBALGO.C`` in winkfpt.exe is only a FORMAT-table name string (the
cluster at 0x65d488 with BinToAscii/atbGetActFormat/atbGetKeyWord —
zero code references).  The actual key material ships as the
``sgid<c>.as2`` containers that GetAuthKey (FUN_004b8fe0) reads:

  * container FILE NAME is built by GetAuthKey itself:
    sprintf(name, "%s%c%s", "SgId", '@' + key_index, ".as2") →
    index 3 → "sgidc.as2", index 4 → "sgidd.as2"   [C disasm]
  * both files live in <NFS>/DATA/GDATEN and in the SP-Daten
    (data/gdaten); the "$L n" header record carries the same index.
  * line grammar of "$K" records (parser FUN_004bad40, FIXED offsets):
        pos 0     '$'
        pos 1     tag:  'K' = 3DES-encrypted, 'U' = plaintext
        pos 3..22 ECU name, 20 chars, space padded
        pos 23..26 four-char logistics id (e.g. "2L18", "MG18")
        pos 27..32 six-char field ("000034", "AB0042", ...)
        pos 33..   hex payload (the ciphertext)
    (hex decoder FUN_004ba520 uppercases; non-hex chars decode as 0)
  * payload lengths observed: 8 B (Simple), 16 B (Symetrisch),
    136 B (Asymetrisch, the 0x88 form FUN_004b8a00 accepts).
    Lengths are validated by FUN_004b89a0 per mode: Simple=8,
    Symetrisch=0x10, Asymetrisch=0x108 (0x88 allowed).
    * '$K' payloads are decrypted in place by FUN_004ba410 →
    FUN_004ba250: 3DES-EDE-ECB, no padding finalisation, key
    assembled by FUN_004bbd80/4be470/480/bd60/4be4a0 from .data
    dwords (0x6633b8/c0/c8/d0/d8 chain — placeholder-looking
    0707/0505 patterns are KDF inputs; the effective 24-byte key was
    captured from a live emulated run).
    REDACTED FOR PUBLIC REPOSITORY:
    The 24-byte proprietary 3DES key encryption key is classified as
    SENSITIVE_RECOVERED_KEY_MATERIAL. In this public repository,
    SYNTHETIC_3DES_KEY is used by default. Users wishing to decode
    OEM containers can inject the key via the AS2_3DES_KEY environment variable.
    Key digest (SHA-256): 4C013D0CA1170E848807C20E997E9222CAE6590E689B58ED1AA39003238DDF4C
  * decrypted 136 B asym blobs have the KrApi {count|key} structure
    with big-endian count words ("00 00 00 10" = 16 dwords = 64 B)
    and MSB-first key halves:
        [u32 BE 0x10][64 B modulus][u32 BE 0x10][64 B exponent]
    (0x10 = 16 dwords = 64 bytes → RSA-512 material, the 0x88 form).

Runtime flow (all [C] by decompile + execution):
  KrApiAuthenticate FUN_004b95a0 → GetAuthKey FUN_004b8fe0(ecu, idx)
  → sgid file → 3DES → blob; mode dispatch "Symetrisch"/"Simple"/
  "Asymetrisch"; for Simple, SetSiproKey FUN_004b8e10 OVERWRITES the
  .data slots 0x663390/98/a0 (which ship as 03/03/04 filler) with the
  first 8 blob bytes before FUN_004ba1b0 reads them back — the
  "placeholder" tables only ever hold real keys at runtime.

The EGS mechatronic of the E60 flash set (CI62F1/CI63F1 IPOs,
SG_ADRESSE 0x62) maps to the GKE19x container names; SGIDC.as2
(index 3) carries GKE191…GKE233, SGIDD.as2 (index 4) additionally
GKE192/GDE192.
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --- 3DES-EDE key configuration -------------------------------------------
# The proprietary 24-byte 3DES master key assembled by winkfpt.exe (.data chain
# 0x6633b8..0x6633d8 via FUN_004bbd80/FUN_004ba250) is classified as
# SENSITIVE_RECOVERED_KEY_MATERIAL and redacted from this public repository.
#
# SHA-256 of OEM key: 4C013D0CA1170E848807C20E997E9222CAE6590E689B58ED1AA39003238DDF4C
#
# By default, a deterministic synthetic 24-byte key is used for testing and
# offline public execution. For private research against real OEM containers,
# the key can be supplied via the AS2_3DES_KEY environment variable.

SYNTHETIC_3DES_KEY = bytes(range(1, 25))


def get_3des_key() -> bytes:
    """Return the active 24-byte 3DES key.

    Uses the hex-encoded key from the AS2_3DES_KEY environment variable
    if set; otherwise defaults to SYNTHETIC_3DES_KEY.
    """
    env_val = os.environ.get("AS2_3DES_KEY")
    if env_val:
        k = bytes.fromhex(env_val.strip())
        if len(k) != 24:
            raise ValueError(f"AS2_3DES_KEY must be exactly 24 bytes, got {len(k)}")
        return k
    return SYNTHETIC_3DES_KEY


# Backward-compatibility alias pointing to the default synthetic key
KEY_3DES = SYNTHETIC_3DES_KEY

# name suffix GetAuthKey builds:  '@' + index → 'C'/'D'  [C]
CONTAINER_INDEX = {3: "SGIDC.as2", 4: "SGIDD.as2"}


# --------------------------------------------------------------------------
# pure-python 3DES (FIPS 46-3 tables; the binary uses the OpenSSL-style
# SP representation at 0x605300 — equivalent cipher, proven by vectors)
# --------------------------------------------------------------------------
_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
       62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
      12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
      22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
_SBOX = (
    ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
     (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
     (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
     (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)),
    ((15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
     (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
     (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
     (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)),
    ((10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
     (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
     (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
     (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)),
    ((7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
     (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
     (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
     (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)),
    ((2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
     (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
     (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
     (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)),
    ((12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
     (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
     (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
     (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)),
    ((4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
     (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
     (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
     (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)),
    ((13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
     (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
     (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
     (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)),
)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
      2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)


def _bits(data: bytes) -> List[int]:
    out = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def _from_bits(bits: List[int]) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v


def _des_subkeys(key8: bytes) -> List[int]:
    k = _bits(key8)
    cd = [k[PC - 1] for PC in _PC1]
    c, d = cd[:28], cd[28:]
    subs = []
    for rot in _SHIFTS:
        c = c[rot:] + c[:rot]
        d = d[rot:] + d[:rot]
        cd = c + d
        subs.append(_from_bits([cd[PC - 1] for PC in _PC2]))
    return subs


def _f(r: int, k: int) -> int:
    e = 0
    for i in range(48):
        e = (e << 1) | ((r >> (32 - _E[i])) & 1)
    x = e ^ k
    out = 0
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F
        row = ((six >> 4) & 2) | (six & 1)
        col = (six >> 1) & 0xF
        out = (out << 4) | _SBOX[i][row][col]
    p = 0
    for i in range(32):
        p = (p << 1) | ((out >> (32 - _P[i])) & 1)
    return p


def _des_block(block8: bytes, subkeys: List[int]) -> bytes:
    m = _bits(block8)
    ip = [_m[_i - 1] for _i, _m in zip(_IP, [m] * 64)] if False else \
        [m[i - 1] for i in _IP]
    l, r = _from_bits(ip[:32]), _from_bits(ip[32:])
    for k in subkeys:
        l, r = r, l ^ _f(r, k)
    rl = _bits(r.to_bytes(4, "big") + l.to_bytes(4, "big"))
    fp = [_from_bits([rl[i - 1] for i in _FP])]
    return fp[0].to_bytes(8, "big")


def des3_ecb_decrypt(key24: bytes, data: bytes) -> bytes:
    """3DES-EDE decrypt (the FUN_004ba410 direction, param_3 = 1)."""
    if len(data) % 8:
        raise ValueError("3DES input must be a multiple of 8 bytes")
    k1, k2, k3 = key24[:8], key24[8:16], key24[16:]
    sk_enc = [_des_subkeys(k) for k in (k1, k2, k3)]
    sk_dec = [s[::-1] for s in sk_enc]
    # EDE: encrypt C = E3(D2(E1(P))); decrypt P = D1(E2(D3(C)))
    order = (sk_dec[2], sk_enc[1], sk_dec[0])
    out = b""
    for off in range(0, len(data), 8):
        blk = data[off:off + 8]
        for subs in order:
            blk = _des_block(blk, subs)
        out += blk
    return out


def des3_ecb_encrypt(key24: bytes, data: bytes) -> bytes:
    if len(data) % 8:
        raise ValueError("3DES input must be a multiple of 8 bytes")
    k1, k2, k3 = key24[:8], key24[8:16], key24[16:]
    sk_enc = [_des_subkeys(k) for k in (k1, k2, k3)]
    sk_dec = [s[::-1] for s in sk_enc]
    order = (sk_enc[0], sk_dec[1], sk_enc[2])
    out = b""
    for off in range(0, len(data), 8):
        blk = data[off:off + 8]
        for subs in order:
            blk = _des_block(blk, subs)
        out += blk
    return out


# --------------------------------------------------------------------------
# container parsing
# --------------------------------------------------------------------------
class As2Record:
    __slots__ = ("tag", "ecu", "ident", "field6", "payload_hex")

    def __init__(self, tag: str, ecu: str, ident: str, field6: str,
                 payload_hex: str):
        self.tag = tag
        self.ecu = ecu
        self.ident = ident
        self.field6 = field6
        self.payload_hex = payload_hex

    @property
    def ciphertext(self) -> bytes:
        return bytes.fromhex(self.payload_hex)

    def decrypt(self, key: Optional[bytes] = None) -> bytes:
        """'$K' records: 3DES-decrypt; '$U' would be plaintext."""
        blob = self.ciphertext
        if self.tag.upper() == "K":
            k = key if key is not None else get_3des_key()
            return des3_ecb_decrypt(k, blob)
        return blob


def parse_as2(text: str) -> List[As2Record]:
    """Parse the '$'-record grammar (loader FUN_004bb380 → line parser
    FUN_004bad40: fixed character positions)."""
    records: List[As2Record] = []
    for ln in text.splitlines():
        ln = ln.rstrip("\r")
        if len(ln) < 2 or ln[0] != "$":
            continue
        tag = ln[1]
        if tag.upper() not in ("K", "U"):
            continue                       # $L/$V/$G — header records
        if len(ln) <= 0x21:
            continue
        records.append(As2Record(
            tag=tag,
            ecu=ln[3:23].strip(),
            ident=ln[23:27],
            field6=ln[27:33],
            payload_hex=ln[33:].strip(),
        ))
    return records


class As2KeyStore:
    """Lookup layer mirroring GetAuthKey(ecu_name, key_index)."""

    def __init__(self, containers: Dict[int, List[As2Record]]):
        # index → {ecu: [records in file order]}
        self._by_index: Dict[int, Dict[str, List[As2Record]]] = {}
        for idx, records in containers.items():
            table: Dict[str, List[As2Record]] = {}
            for rec in records:
                table.setdefault(rec.ecu.upper(), []).append(rec)
            self._by_index[idx] = table

    @classmethod
    def from_paths(cls, paths: Dict[int, Path]) -> "As2KeyStore":
        return cls({i: parse_as2(Path(p).read_text("latin-1"))
                    for i, p in paths.items()})

    # -- GetAuthKey equivalents -------------------------------------------
    def auth_blob(self, ecu: str, key_index: int, key: Optional[bytes] = None) -> bytes:
        """Decrypted GetAuthKey buffer for (ecu, index).
        Mirrors the file-order lookup: first record wins."""
        if key_index not in self._by_index:
            raise KeyError(
                f"no container loaded for key index {key_index} "
                f"(GetAuthKey would open sgid"
                f"{chr(0x40 + key_index)}.as2)")
        recs = self._by_index[key_index].get(ecu.upper())
        if not recs:
            raise KeyError(f"ECU {ecu!r} not in container index "
                           f"{key_index}")
        return recs[0].decrypt(key=key)

    def simple_key8(self, ecu: str, key_index: int, key: Optional[bytes] = None) -> bytes:
        blob = self.auth_blob(ecu, key_index, key=key)
        if len(blob) != 8:
            raise ValueError(
                f"{ecu} idx{key_index}: Simple auth needs an 8-byte "
                f"key record (FUN_004b89a0), got {len(blob)}")
        return blob

    def sym_key16(self, ecu: str, key_index: int, key: Optional[bytes] = None) -> bytes:
        blob = self.auth_blob(ecu, key_index, key=key)
        if len(blob) != 16:
            raise ValueError(
                f"{ecu} idx{key_index}: Symetrisch auth needs a "
                f"16-byte record (FUN_004b89a0), got {len(blob)}")
        return blob

    def asym_ne(self, ecu: str, key_index: int, key: Optional[bytes] = None
                ) -> Tuple[bytes, bytes]:
        """(modulus, exponent) from the 136-byte 0x88 blob.  The KrApi
        count words are big-endian ("00 00 00 10" = 16 dwords = 64 B)
        and the 64-byte halves follow MSB-first (natural RSA bigint
        byte order):  [u32 BE 0x10][64 B N][u32 BE 0x10][64 B E]."""
        blob = self.auth_blob(ecu, key_index, key=key)
        if len(blob) != 0x88:
            raise ValueError(
                f"{ecu} idx{key_index}: Asymetrisch auth needs the "
                f"0x88-byte record, got {len(blob)}")
        cnt1 = struct.unpack(">I", blob[:4])[0]
        cnt2 = struct.unpack(">I", blob[68:72])[0]
        if cnt1 != 0x10 or cnt2 != 0x10:
            raise ValueError("unexpected KrApi key count words")
        return blob[4:68], blob[72:136]


# ECU names of the E60 EGS mechatronic present in the containers [O]
EGS_MECHATRONIC = ["GKE191", "GKE192", "GKE193", "GKE194", "GKE195",
                   "GKE211", "GKE213", "GKE214", "GKE215", "GKE233"]

# Deterministic synthetic decrypt vectors for pure-Python 3DES verification:
BINARY_VECTORS = [
    ("948b35b581e58150ec1e9b339919a96c",       # synthetic 16B key: 01020304...
     "0102030405060708090a0b0c0d0e0f10"),
    ("dc724e8af0e58b102e5fc2f7e8cbff56",       # synthetic 16B key: 21222324...
     "2122232425262728292a2b2c2d2e2f30"),
]
