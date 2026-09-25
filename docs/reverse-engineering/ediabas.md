# EDIABAS Runtime & API Architecture

This document details the reverse engineering of the EDIABAS (Electronic Diagnostic Base System) runtime interface, the API boundary in `winkfpt.exe`, and the internal security password architecture of `ebas32.dll`.

---

## 1. WinKFP EDIABAS Boundary (`DAT_00735398`)

WinKFP does not implement vehicle bus protocols (ISO-TP, UDS, KWP2000) directly. All communication is routed through a global dispatch table initialized at `DAT_00735398`:
* All diagnostic requests pass through `FUN_00490250`, which invokes the standard `apiJob` export of `api32.dll`.
* EDIABAS acts as a middle-tier interpreter that executes compiled SGBD scripts (`.prg`) and sequence scripts (`.ipo`).

---

## 2. Standard `api32.dll` Export Contract

The EDIABAS API provides a C stdcall interface used by BMW diagnostic applications:

| Function | Signature | Semantics |
|---|---|---|
| `apiInit` | `apiInit(void)` | Initializes runtime engine and loads `EDIABAS.INI`. |
| `apiJob` | `apiJob(ecu, job, args, result_fmt)` | Dispatches diagnostic job to the specified SGBD. |
| `apiJobData` | `apiJobData(ecu, job, data, len, result_fmt)` | Dispatches diagnostic job with raw binary payload (e.g., `FLASH_SCHREIBEN`). |
| `apiState` | `apiState(void)` | Returns current execution state (`APIBUSY`, `APIREADY`, `APIBREAK`). |
| `apiResultText` | `apiResultText(buf, var, set)` | Reads string result variable from result set `set`. |
| `apiResultBinary` | `apiResultBinary(buf, len, var, set)` | Reads binary blob result variable from result set `set`. |
| `apiEnd` | `apiEnd(void)` | Closes communication handles and shuts down server. |

---

## 3. SGBD Protection & `ebas32.dll` Master Password Chain

SGBD files (`.prg`) contain compiled bytecode that executes inside the EDIABAS virtual machine. To prevent unauthorized inspection, SGBD files are protected by a master password verification mechanism in `ebas32.dll`:

### 3.1 Obfuscated Descriptor & Master File (`63477BC6`)
* In `ebas32.dll` at virtual address `0x1002e12e`, an obfuscated descriptor decodes to the master password filename: **`63477BC6`**.
* This file resides in `<EDIABAS>/Bin/` and holds the master password table.

### 3.2 Master Password Entries
Decoded from `63477BC6`, the accepted password table contains three 10-byte keys:
```text
pwd[0] = ba79d059838e7de9c678
pwd[1] = 953d8a45c9bd50c2ee4d
pwd[2] = 9305b8698d9b4a9ff10c
```

### 3.3 SGBD Verification (`SECUR1.PRG` / `SECUR2.PRG`)
* Files such as `SECUR1.PRG` and `SECUR2.PRG` contain password records matching the master table entries.
* SGBD plaintext sections are obfuscated using a simple `XOR 0xF7` mask. Applying `XOR 0xF7` reveals the internal author headers:
  ```text
  Security1
  BMW EE-32 Bernd Schikora
  Remes GmbH Wolfgang Rapp
  ```
