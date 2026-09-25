# VDLE Flash Engine & Command Dispatcher

This document details the reverse engineering of the VDLE (Vehicle Download Engine) dispatcher and session lifecycle in `winkfpt.exe`.

---

## 1. Command Dispatcher (`FUN_004a1f80`)

The VDLE engine is controlled via a centralized command dispatcher (`FUN_004a1f80`), which parses commands passed by the high-level flashing script:

| Dispatch Token | Virtual Address | Parameters | Functional Description |
|---|---|---|---|
| `INIT_VDLE` | `0x004a5b60` | `name`, `blocksize`, `opps_mode` | Initializes VDLE context, configures OPPS hardware, and loads segment tables. |
| `START_TESTERPRESENT` | `0x004a5a40` | `None` | Starts periodic diagnostic session keep-alive. |
| `STOP_TESTERPRESENT` | `0x004a5850` | `None` | Stops periodic keep-alive requests. |
| `REQUEST_SEGMENTINFO` | `0x004665d0` | `segment_index` | Queries start address and length of specified segment. |
| `SEND_SEGMENT` | `0x004668b0` | `segment_index` | Executes transmission loop for blocks within specified segment. |

---

## 2. `INIT_VDLE` & OPPS Initialization Sequence (`FUN_004a5b60`)

`INIT_VDLE` takes three arguments:
1. Target interface name string (e.g., `"DLE08"`).
2. Block transfer size: integer `1` to `0xFFE9` (converted via `atol`).
3. OPPS mode flag: string `"yes"` or `"no"`.

### 2.1 The OPPS Sequence (`opps_mode == "yes"`)
When OPPS mode is active, WinKFP configures the hardware diagnostic head with a strict command sequence:

1. **OPPS Reset**: Dispatches `STEUERN_DLE_RESET` via `FUN_004a5e70` (raises `ERROR_DLL_OPPSRESET` upon failure).
2. **Configure TP Interval**: Dispatches `STEUERN_TP_INTERVALL` with parameter `"8000"` (8,000 ms).
3. **Configure Header**: Dispatches `STEUERN_DLE_HEADER` with parameter `"0xF1;16"`.
4. **Configure I/O Answer Mask**: Dispatches `STEUERN_DLE_IOANTWORT` with parameters `"76000001"`, `"FF0000FF"`.
5. **Configure Service ID**: Dispatches `STEUERN_DLE_SID` with parameter `"36"` (`0x36` = UDS / KWP `TransferData`).
6. **TesterPresent OFF**: Dispatches `STEUERN_DLE_TP` with parameter `"0"`.

### 2.2 Segment Table Loading (`LOADTABLE`)
`FUN_00490570` parses the binary image headers into two internal global arrays:
* Start addresses array: allocated at `0x00881498`.
* Segment sizes array: allocated at `0x00881630`.
* Total blocks calculation:
  $$\text{Total Blocks} = \sum_{k} \left\lceil \frac{\text{size}_k}{\text{blocksize}} \right\rceil$$

### 2.3 Response Format
Upon successful initialization, `INIT_VDLE` returns:
```text
OKAY;<number_of_segments>
```

---

## 3. Flash Memory Erase Architecture

A major discovery from decompiling `winkfpt.exe` is that **WinKFP does NOT issue a standalone sector-erase diagnostic command**:
* Sector erasure is executed internally by the target ECU's RAM flash kernel upon entering the programming session.
* The legacy token `SERASE` (used in older K-Line BEST protocols) was identified in `ebas32.dll` at `0x10089b5c` as static table data without executable references in the modern UDS/KWP flashing path.
* Early research revisions that attempted to simulate an erase step by transmitting null bytes were proven incorrect and superseded in **Revision 2**.
