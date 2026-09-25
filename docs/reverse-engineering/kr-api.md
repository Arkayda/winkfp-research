# KrApi Cryptographic Library Specification

This document details the reverse-engineering analysis of the internal cryptographic library embedded within `winkfpt.exe`, referred to in internal debugging strings as `KrApiLib` (`KrApiAuthenticate`, `KrApiLib.cpp`).

---

## 1. Entry Point & Wrapper (`FUN_004617c0` -> `FUN_004b95a0`)

`KrApiAuthenticate` is invoked via wrapper `FUN_004617c0`. It takes:
* Key index: `0..5` (validated at entry).
* Mode selector: string `"Symetrisch"`, `"Simple"`, or `"Asymetrisch"`.
* Output buffer: allocated to hold at least `0x108` (264) bytes.

```c
/* Decompiled signature (winkfpt.exe @ 0x004b95a0) */
int __cdecl KrApiAuthenticate(
    int key_index,
    char *mode,
    byte *seed,
    int seed_len,
    byte *serial,
    int serial_len,
    byte *nonce,
    byte *out_buf,
    int *out_len
);
```

---

## 2. Symmetric Authentication (`"Symetrisch"`)

`FUN_004b9f50` implements the symmetric mode:

### 2.1 Formula & Hash Construction
The authentication token is computed using MD5 over a concatenated 48-byte buffer:
```text
Token = MD5( key16 || nonce4 || serial4 || seed8 || key16 )
```
* **`key16`**: 16-byte symmetric key corresponding to the target ECU.
* **`nonce4`**: 4 ASCII-hex characters generated from MSVC `rand()` formatted via `sprintf("%4.4lx", rand())`.
* **`serial4`**: 4-byte ECU serial number obtained via diagnostic job `SERIENNUMMER_LESEN`.
* **`seed8`**: 8-byte random seed returned by the ECU in response to `NG_AUTHENTISIERUNG_START`.

### 2.2 MD5 Implementation Identification
The MD5 hashing engine is statically compiled into `winkfpt.exe`:
* Standard RFC 1321 initialization vectors (`FUN_004bbdb0`):
  `A = 0x67452301`, `B = 0xEFCDAB89`, `C = 0x98BADCFE`, `D = 0x10325476`.
* Compression function (`FUN_004bbdf0`) utilizing round constants table $K$ at virtual address `0x00605160`:
  `0xd76aa478`, `0xe8c7b756`, `0x242070db`, `0xc1bdceee`...

---

## 3. Proprietary Simple Cipher (`"Simple"`)

`FUN_004ba1b0` dispatches to core cipher transformation `FUN_004ba080`:

### 3.1 Input Layout & Constraints
* **Seed**: Only the first 4 bytes of the seed (`seed[0:4]`) are used; the remaining 4 bytes are zero-padded:
  `input = seed[0:4] || 00 00 00 00`.
* **Key**: 8-byte symmetric key retrieved from container `$K` records (e.g., `HKL65`).

### 3.2 Cipher Rounds (`FUN_004ba080`)
1. **Phase 1 (Key Whitening & Inversion)**:
   $$\text{out}[i] = \text{key}[i] \oplus \text{input}[7 - i] \quad (i = 0 \dots 7)$$
2. **Phase 2 (Length Mixing)**:
   $$\text{out}[0 \dots 3] \mathrel{\oplus}= \text{len\_le}$$
3. **Phase 3 (Nonlinear Feistel-like Rounds)**:
   Four rounds of 8 permutation steps over an 8-byte state array.
   Step index order: $i = 7, 0, 1, 2, 3, 4, 5, 6$.
   $$\text{state}[i+1] = \left( (\text{mux}(\text{state}[i-2], \text{state}[i-1], \text{state}[i]) + \text{input}[i+1]) \times 3 + \text{state}[i+1] \times 4 \right) \pmod{256}$$
   After 4 rounds, the state is added into the output buffer:
   $$\text{out}[i] = (\text{out}[i] + \text{state}[i]) \pmod{256}$$

---

## 4. Asymmetric Authentication (`"Asymetrisch"`)

`FUN_004b9e30` dispatches to RSA modular exponentiation:

### 4.1 Message Digest Construction
The data to be signed is an MD5 digest over nonce, serial, and seed:
```text
Digest = MD5( nonce4 || serial4 || seed8 )
```

### 4.2 RSA Modular Exponentiation (`FUN_004bb780` / `FUN_004bb910`)
* **Key Length**: 1024-bit (128 bytes) or 512-bit (64 bytes) modulus $N$ and public exponent $E$.
* **Representation**: Numbers are stored in **Little-Endian 32-bit dwords**:
  $$\text{word}_k = \text{buf}[4k] \mid (\text{buf}[4k+1] \ll 8) \mid (\text{buf}[4k+2] \ll 16) \mid (\text{buf}[4k+3] \ll 24)$$
  *(Early research revision 1 mistakenly assumed Big-Endian; resolved in rev 2 by verifying that both $N$ and $E$ are strictly odd in LE).*
* **Operation**:
  $$S = \text{Digest}^E \pmod N$$
* **Word Swapping**: The resulting ciphertext words are inverted via a 4-byte endianness swap loop (`FUN_004b95a0`) before transmission.

---

## 5. Nonce Generation & MSVC `rand()`

The 4-character ASCII nonce is generated using the classic Microsoft Visual C++ Linear Congruential Generator (LCG):

```c
/* Decompiled MSVC rand() @ 0x005cafbb */
int __cdecl msvc_rand(void)
{
    holdrand = holdrand * 0x343FD + 0x269EC3;
    return (holdrand >> 16) & 0x7FFF;
}
```

* **Canonical Vector**: With `srand(1)`, the first call to `rand()` returns exactly `41` (`0x0029`), and the second returns `18467`.
* The random integer is formatted into a 4-character ASCII hex string (`sprintf(nonce, "%4.4lx", rand())`).
