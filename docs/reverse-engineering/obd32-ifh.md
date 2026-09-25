# IFH Transport & OBD32 K-Line Driver Specification

This document details the reverse engineering of the low-level hardware interface driver `OBD32.dll` and the IFH (Interface Handler) serial communication protocol.

---

## 1. Position in the Diagnostic Stack

```text
winkfpt.exe / SGBD Scripts
       │
       ▼
api32.dll (EDIABAS API)
       │
       ▼
XStd32.dll ("STD:" Transport Dispatcher)
       │
       ▼
OBD32.dll (Interface = STD:OBD)  <--- Analyzed in this document
       │
       ▼
Windows Win32 Serial COM Port (RS-232 / FTDI FT232R K+DCAN)
```

---

## 2. Export Contract (`OBD32.dll`)

`OBD32.dll` exposes three primary stdcall export functions called by `XStd32.dll`:

| Export | Virtual Address | Parameters | Semantics |
|---|---|---|---|
| `INITIALIZE` | `0x100040C0` | `int *status` | Reads `obd.ini` parameters and opens the target COM port (e.g., `COM1`). |
| `WRITEDATA` | `0x100041B0` | `int *status, byte *data, int len` | Parses command telegram, configures DCB, and transmits packet over UART. |
| `READDATA` | `0x100041F0` | `int *status, byte **buf, int *len` | Returns pointer and length of received ECU response telegram. |

---

## 3. Command Dispatch & Framing Protocols

The internal dispatcher in `OBD32.dll` processes telegrams according to a 1-byte command opcode:

### Command 1: Open & Initialize Port
* Configures Windows `DCB` (Device Control Block) settings to default: **9600 Baud, 8 Data Bits, Even Parity, 1 Stop Bit (8E1)**.
* Configures 20,000-byte serial I/O buffers.

### Command 5: Set Communication Parameters
* Updates baud rate and parity according to protocol context:
  * Diagnostic wake-up: `9600 8E1`
  * High-speed communication: `115200 8N1` or `57600 8N1`

### Command 6: Send Telegram & Calculate XOR Checksum
* The caller provides the raw diagnostic payload.
* `OBD32.dll` automatically calculates and appends the longitudinal XOR redundancy byte across all message bytes:
  $$\text{Checksum} = \bigoplus_{i=0}^{N-1} \text{data}[i]$$
* Transmits the frame and waits for the ECU response.

### Command 10: Bus Wake-Up Probe
* Sends slow wake-up pattern at both supported bauds (8E1, then 8N1).

---

## 4. Echo Collision & Retry Behavior

On standard ISO 9141 / K-Line interfaces, the TX and RX lines are tied together at the transceiver, resulting in a local echo of every transmitted byte:
* `OBD32.dll` monitors incoming bytes during transmission to confirm bus echo.
* If an echo collision occurs (mismatched byte detected due to bus contention or line short):
  * Default configuration: `RETRY = OFF`.
  * The driver immediately terminates the write operation and returns error status `IFH_0006` (Command Execution Failed).
