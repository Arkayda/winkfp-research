# GetAuthKey & AS2 Key Container Specification

This document details the reverse engineering of the runtime key retrieval engine in `winkfpt.exe`, specifically `GetAuthKey` (`FUN_004b8fe0`) and the `sgid<x>.as2` cryptographic container format.

---

## 1. Background & Container Discovery

Earlier research revisions hypothesized that key material was loaded from an external definition file named `ATBALGO.C`.
In **Revision 10**, inspection of strings in `winkfpt.exe` revealed that `"ATBALGO.C"` at virtual address `0x0065d488` had zero code references and was merely an internal compiler identifier for a FORMAT parser table.

The true key retrieval routine is `GetAuthKey` (`FUN_004b8fe0`). It dynamically constructs the container filename using the requested key index:

```c
/* Disassembly of FUN_004b8fe0 */
sprintf(filename, "%s%c%s", "SgId", '@' + key_index, ".as2");
__strlwr(filename);
/* key_index = 3 -> "sgidc.as2" */
/* key_index = 4 -> "sgidd.as2" */
```

These files reside in the BMW SP-Daten directory (`<NFS>/DATA/GDATEN/SGIDC.as2`).

---

## 2. AS2 Container File Grammar

The `.as2` container files are ASCII line-based records with fixed-column field offsets (parsed by `FUN_004bad40`):

### 2.1 Header Record (`$L`)
Defines the container index level:
```text
$L 3
```

### 2.2 Key Record (`$K` / `$U`)
Each record describes an ECU security profile:

```text
Position    Length    Field Name         Description
0           1         Prefix             Literal '$'
1           1         Record Tag         'K' = 3DES-encrypted, 'U' = plaintext
2           1         Separator          Space
3..22       20        ECU Identifier     Space-padded ASCII string (e.g., "GKE192              ")
23..26      4         Logistics ID       4-character code (e.g., "2L18", "MG18")
27..32      6         Sub-type ID        6-character code (e.g., "000034", "AB0042")
33..end     var       Payload            Hex-encoded ASCII string
```

---

## 3. Decryption Routine (3DES-EDE-ECB)

When the record tag is `'K'`, the hex payload is decoded into raw bytes and decrypted in-place by `FUN_004ba410` -> `FUN_004ba250`:

* **Cipher**: Triple-DES (3DES / TDEA) in Electronic Codebook (ECB) mode (`DES-EDE3-ECB`).
* **Padding**: Raw block decryption without PKCS#7 finalization.
* **Effective 24-Byte Key**:
  Reconstructed at runtime from `.data` dwords at `0x006633b8` / `0x006633c0` / `0x006633c8` / `0x006633d0` / `0x006633d8` via `FUN_004bbd80` -> `FUN_004ba250`.
  *(Note: The proprietary 24-byte 3DES master key encryption key is classified as `SENSITIVE_RECOVERED_KEY_MATERIAL` and redacted from this public repository. SHA-256 digest: `4C013D0CA1170E848807C20E997E9222CAE6590E689B58ED1AA39003238DDF4C`).*

---

## 4. Decrypted Payload Classes & Structure

The decrypted plaintext payload falls into one of three structural classes depending on length:

| Mode | Raw Length | Decrypted Length | Internal Structure | Example Target ECU |
|---|:---:|:---:|---|---|
| **Simple** | 8 bytes | 8 bytes | 8-byte symmetric key for `FUN_004ba080` | `HKL65` |
| **Symmetric** | 16 bytes | 16 bytes | 16-byte symmetric key for MD5 HMAC | `GKE192` (GS19 Mechatronic) |
| **Asymmetric** | 136 bytes (`0x88`) | 136 bytes | KrApi count/key structure (RSA-512) | `GKE191` |

### 4.1 Asymmetric 136-byte (`0x88`) RSA-512 Structure
Decrypted 136-byte asymmetric records adhere to the KrApi key layout:

```text
Offset    Size    Field
0..3      4 B     Modulus dword count (Big-Endian u32: 0x00000010 = 16 dwords = 64 bytes)
4..67     64 B    RSA Modulus N (512 bits, MSB first)
68..71    4 B     Exponent dword count (Big-Endian u32: 0x00000010 = 16 dwords = 64 bytes)
72..135   64 B    RSA Public Exponent E (512 bits, MSB first)
```

---

## 5. Runtime Key Overwrite in Memory

For **Simple** mode authentication:
* Static `.data` slots at `0x00663390`, `0x00663398`, `0x006633a0` in `winkfpt.exe` contain filler bytes (`0x03, 0x03, 0x04...`).
* `SetSiproKey` (`FUN_004b8e10`) **dynamically overwrites** these static slots in memory with the decrypted 8-byte key extracted from the container before cipher execution.
* The static bytes in the binary image are merely uninitialized placeholders; valid authentication keys exist strictly in memory after container decryption.
