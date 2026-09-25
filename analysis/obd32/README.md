# OBD32.dll Reverse-Engineering & Disassembly Notes

This directory records the disassembly and memory layout analysis of `OBD32.dll` (shipping EDIABAS 6.4.7 distribution, ImageBase `0x10000000`).

---

## 1. Export Address Table & Core Functions

| Export Name | Ordinal | Virtual Address (VA) | Functional Purpose |
|---|:---:|:---:|---|
| `INITIALIZE` | 1 | `0x100040C0` | Parses `obd.ini`, initializes port context, calls `CreateFileA` on COM port. |
| `WRITEDATA` | 2 | `0x100041B0` | Dispatches command opcode; handles parameter configuration or telegram transmission. |
| `READDATA` | 3 | `0x100041F0` | Copies received ECU response buffer to caller. |

---

## 2. Command Telegram Functions

* **`FUN_10001220` (Calculate & Append XOR Checksum)**:
  Loops through bytes `0..len-1`, computes bitwise XOR accumulation, and writes result to `data[len]`.
* **`FUN_100012a0` (Verify XOR Checksum)**:
  Loops through received frame; returns 1 if $\bigoplus_{i=0}^{\text{len}-1} \text{byte}[i] == 0$, 0 otherwise.
* **`FUN_10001350` (Echo Collision Detection)**:
  Transmits one byte via `WriteFile`, immediately calls `ReadFile` to read back local bus echo. If echo does not match transmitted byte, increments collision counter.
* **`FUN_100021b0` (Wakeup Sequence)**:
  Toggles baud rate and sends standard 5-baud or fast wake-up pulses (`0x00, 0x55, 0xFF`).
