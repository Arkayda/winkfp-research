# FLASH_SCHREIBEN Framing & Block Transmission

This document details the exact byte-level framing of the `FLASH_SCHREIBEN` diagnostic jobs produced by `FUN_004668b0` in `winkfpt.exe`.

---

## 1. 21-Byte Block Header Structure

Every data block transferred to the ECU by `SEND_SEGMENT` begins with a 21-byte framing header and terminates with an `0x03` (ETX) byte:

```text
Offset    Length    Value / Type    Description
0..3      4 B       01 01 00 00     Magic constant (0x0101 Little-Endian)
4..7      4 B       00 00 00 00     Reserved / Zero padding
8..11     4 B       00 FF 00 00     Constant (0x00FF0000)
12        1 B       00              Padding byte
13..14    2 B       u16 LE          Payload chunk length (Little-Endian)
15..16    2 B       u16 LE          Duplicate payload chunk length (Little-Endian)
17..20    4 B       u32 LE          Target flash memory address (Little-Endian)
21..N     var       bytes           Firmware data payload
N+1       1 B       03              ETX terminator
```

### Key Structural Findings
1. **Little-Endian Addressing**: The absolute flash target address is encoded in **Little-Endian 32-bit format**, incremented by `blocksize` for each successive chunk.
2. **Duplicate Length Field**: The 16-bit payload length is repeated twice consecutively at offsets `13` and `15`.
3. **ETX Byte**: A single trailing byte `0x03` is appended immediately following the payload bytes.

---

## 2. Standard vs XXL Job Selection (`FLASH_SCHREIBEN_XXL`)

WinKFP dispatches one of two EDIABAS jobs to transmit the framed block:
* `FLASH_SCHREIBEN`
* `FLASH_SCHREIBEN_XXL`

### The Selection Threshold
> [!IMPORTANT]
> The job variant is determined **strictly by the configured session block size**, NOT by the individual chunk length:
> $$\text{Job} = \begin{cases} \text{FLASH\_SCHREIBEN\_XXL}, & \text{if } \text{blocksize} > 254 \ (0\text{xFE}) \\ \text{FLASH\_SCHREIBEN}, & \text{otherwise} \end{cases}$$
>
> In differential scenario **E** (`blocksize = 256`), even a final short-tail chunk of only 16 bytes is dispatched via `FLASH_SCHREIBEN_XXL`.

---

## 3. Status Polling & Recovery Handling

After transmitting each block, WinKFP polls the EDIABAS result variable:
```text
FLASH_SCHREIBEN_STATUS == 1
```

* **Success (`1`)**: The engine increments the block counter and proceeds to the next chunk.
* **Failure / State Drop**: If the status poll fails or returns an error token:
  1. The VDLE latch drops the state gate to prevent further transmission.
  2. The failure is reported back through `FUN_00466740(0, 1)`.
  3. WinKFP initiates the WAS (Wiederanlaufspeicher) recovery orchestration to query interrupted block positions and resume transmission without restarting from byte zero.
