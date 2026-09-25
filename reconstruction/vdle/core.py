"""VDLE flash-engine reconstruction (winkfpt.exe) — [C] unless marked.

Sequence [C]: INIT_VDLE → LOADTABLE → REQUEST_SEGMENTINFO → SEND_SEGMENT
(→ FLASH_SCHREIBEN_STATUS) — reconstructed from FUN_004a5b60/00490570/
004665d0/004668b0/004a6150 control flow.

Rev 6 — DIFFERENTIAL-PROVEN against the original machine code
(vdle_trace.py, Unicorn + mock EDIABAS, 32/32 checks; see VDLE_TRACE.md):
  * build_flash_block: REAL header is 21 bytes with the address stored
    LITTLE-ENDIAN and the chunk length stored LE16 TWICE — not the
    previously assumed 14-byte BE header.
  * XXL job selection is keyed on the INIT_VDLE blocksize
    (blocksize > 0xFE), NOT on the chunk length: a 16-byte tail chunk of
    a bs=256 transfer still goes out as FLASH_SCHREIBEN_XXL.
  * OPPS setup order + arguments exact (STEUERN_DLE_HEADER gets
    "0xF1;<blocksize>"; STEUERN_DLE_TP "0" ends the setup).
  * INIT_VDLE replies "OKAY;<segment count>" (NOT the block count).

Rev 3 fixes (external audit):
  * start_kernel_programming() no longer hardcodes address 0 — the
    address MUST come from the segment table (REQUEST_SEGMENTINFO).
  * poll timeout is an explicit [R] parameter, not a silent constant.
  * erase: no separate erase job exists [C]; writing zeros does NOT
    erase — no erase-looking API is provided at all.
  * added signature-check orchestration entry (job name found in
    binary [O]) — sequence shape is [R] until differential-tested.
"""

import struct
import time
from typing import Callable

JOB_FLASH_WRITE = "FLASH_SCHREIBEN"            # [O]
JOB_FLASH_WRITE_XXL = "FLASH_SCHREIBEN_XXL"    # [O], used when bs > 254
JOB_SIGNATURE_CHECK = "NG_SIGNATUR_PRUEFEN"    # [O]
XXL_THRESHOLD = 0xFE                            # [C] applies to BLOCKSIZE

# SEND_SEGMENT report strings [C — FUN_00466740 + live DF5–DF7 diff]:
# success is the CONSTANT "OKAY;1;" (never a block count); abort reports
# append a detail token naming the failing stage.
REPLY_SEND_OK = "OKAY;1;"
REPLY_SEND_TP_FAIL = ("ERROR_DLL_SEND_SEGMENT;0;"
                      "ERROR_DLL_STD_TESTERPRESENTHANDLING")
REPLY_SEND_JOB_FAIL = ("ERROR_DLL_SEND_SEGMENT;1;"
                       "ERROR_DLL_STD_NOOKAY")
REPLY_SEND_STATUS_FAIL = ("ERROR_DLL_SEND_SEGMENT;0;"
                          "ERROR_DLL_STD_FLASH_SCHREIBEN_STATUS")
REPLY_SEND_GENERIC_FAIL = "ERROR_DLL_SEND_SEGMENT;0;"
REPLY_SEND_WRONGSTATE = ("ERROR_DLL_SEND_SEGMENT;0;"
                         "ERROR_DLL_WRONGSTATE")     # [C live, state gate
REPLY_SEND_ILLEGAL_WAS = ("ERROR_DLL_SEND_SEGMENT;0;"
                          "ERROR_DLL_ILEGALL_WAS")   # [C live, DF9: "-1"
                                                   # resume with no attempt

# REQUEST_SEGMENTINFO replies [C — FUN_004665d0]:
REPLY_SEG_INIT_ERROR = "ERROR_DLL_INIT_ERROR"        # not initialized
REPLY_SEG_WRONGSTATE = "ERROR_DLL_WRONGSTATE"        # state != downloading
REPLY_SEG_PARAM = "ERROR_DLL_JOBAPIPARAM"
REPLY_SEG_ILLEGAL_WAS = "ERROR_DLL_ILEGALL_WAS"      # "-1" with no attempt

OPPS_SETUP_SEQUENCE = [                        # [C] diff-proven order
    ("DLE", "STATUS_DLE_VERSION", ""),
    ("DLE", "STEUERN_DLE_RESET", ""),
    ("DLE", "STEUERN_TP_INTERVALL", "8000"),
    # header argument is "0xF1;<blocksize string>" — proven live
    ("DLE", "STEUERN_DLE_HEADER", "0xF1;{blocksize}"),
    ("DLE", "STEUERN_DLE_IOANTWORT", "76000001;FF0000FF"),
    ("DLE", "STEUERN_DLE_SID", "36"),
    ("DLE", "STEUERN_DLE_TP", "0"),
]


def opps_setup_jobs(blocksize: int) -> list:
    """[C] The OPPS job sequence INIT_VDLE issues when argv[2]=="yes"
    (FUN_004a5dc0/5e70/5e90/5ee0/5f90/6040/5eb0). Byte-order and arguments
    proven by the differential trace (scenario B)."""
    return [(d, j, a.format(blocksize=blocksize))
            for d, j, a in OPPS_SETUP_SEQUENCE]


def build_flash_block(address: int, data: bytes) -> bytes:
    """[C] DIFFERENTIAL-PROVEN FLASH_SCHREIBEN parameter block (live
    execution of FUN_004668b0; every scenario in VDLE_TRACE.md):

        01 01 00 00 | 00 00 00 00 | 00 FF 00 00 | 00 |
        len_le16 | len_le16 (duplicate) | addr_le32 | data… | 03

    The address is LITTLE-endian and increments by the INIT_VDLE
    blocksize per chunk; the chunk length appears twice as LE16."""
    n = len(data)
    return (b"\x01\x01\x00\x00" + b"\x00" * 4 + b"\x00\xff\x00\x00"
            + b"\x00" + struct.pack("<H", n) + struct.pack("<H", n)
            + struct.pack("<I", address) + data + b"\x03")


def init_vdle_reply(segment_count: int) -> str:
    """[C] INIT_VDLE result string: "OKAY;<segment count>" — the block
    count (DAT_00881628) is computed but NOT reported (scenario D:
    seg_count=1, block_count=2 → reply "OKAY;1")."""
    return f"OKAY;{segment_count}"


def load_table(file_bytes: bytes) -> list:
    """[C] LOADTABLE (FUN_00490570) segment-table file format,
    diff-proven live (vdle_trace.py): [u32 table_offset][segment data
    @4, contiguous][@table_offset: u32 count][u32 starts[count]]
    [u32 sizes[count]]. Raises ValueError on a malformed table."""
    if len(file_bytes) < 4:
        raise ValueError("table file too short")
    (table_off,) = struct.unpack_from("<I", file_bytes, 0)
    if not 4 <= table_off <= len(file_bytes) - 4:
        raise ValueError(f"table offset out of range: {table_off}")
    (count,) = struct.unpack_from("<I", file_bytes, table_off)
    if count > 0x400 or table_off + 4 + 8 * count > len(file_bytes):
        raise ValueError(f"implausible segment count: {count}")
    starts = struct.unpack_from(f"<{count}I", file_bytes, table_off + 4)
    sizes = struct.unpack_from(f"<{count}I", file_bytes,
                               table_off + 4 + 4 * count)
    if any(s == 0 for s in sizes):
        raise ValueError("zero-size segment in table")
    return list(zip(starts, sizes))


def segment_info_reply(address: int, size: int) -> str:
    """[C] REQUEST_SEGMENTINFO argument string the original composes
    from its loaded table: sprintf("OKAY;0x%08X;0x%08X", addr, size)
    (inverse of parse_segment_info; golden trace, VDLE_TRACE.md)."""
    return f"OKAY;0x{address:08X};0x{size:08X}"


class SendState:
    """[C] SEND_SEGMENT resume state (FUN_00467010/FUN_004668b0):

    - segment (DAT_008817d4): segment of the interrupted attempt, -1 if
      none; saved when a FLASH_SCHREIBEN job comes back not-OKAY.
    - blocks_done (DAT_0088162c): block index of the attempt; starts at
      the entry block, incremented only AFTER a block's status poll
      succeeds — so on failure it still points at the FAILED block.
    - bias (DAT_008817c0): atoi of the segment argument of a two-arg
      call (fresh with explicit block context), -1 for a one-arg fresh
      call; the resume entry computes  resume_block = blocks_done - bias.
    """

    def __init__(self):
        self.segment = -1
        self.blocks_done = 0
        self.bias = 0

    def resume_block(self) -> int:
        """[C] FUN_00467010 resume path: block = max(0, blocks_done-bias)."""
        return max(0, self.blocks_done - self.bias)

    def was_info(self, start: int, size: int, blocksize: int) -> str:
        """[C] FUN_004665d0 WAS variant (arg "-1"): segment info of the
        INTERRUPTED position — address advanced and size reduced by the
        blocks already written:  OKAY;0x<start+bs*blk>;0x<size-bs*blk>."""
        blk = self.resume_block()
        return segment_info_reply(start + blocksize * blk,
                                  size - blocksize * blk)


def iter_flash_chunks(start: int, size: int, blocksize: int,
                      start_block: int = 0):
    """[C] FUN_004668b0 chunk loop: yields (address, chunk_length) for
    each FLASH_SCHREIBEN block, starting at start_block (resume support).
    The XXL job variant is selected by blocksize, not chunk length."""
    if not 0 < blocksize <= 0xFFE9:
        raise ValueError("blocksize out of INIT_VDLE range 1..0xFFE9")
    addr = start + blocksize * start_block
    pos = blocksize * start_block
    while pos < size:
        n = min(blocksize, size - pos)
        yield addr, n
        addr += n
        pos += n


def send_flash_segment(address: int, data: bytes, blocksize: int,
                       send_job: Callable[[str, bytes], bool],
                       poll_status: Callable[[], int],
                       poll_timeout_s: float = 10.0) -> bool:
    """[C] flow, [R] timeout value (not proven from binary).
    blocksize is the INIT_VDLE value: it — not len(data) — selects the
    XXL job variant (diff-proven, scenario E)."""
    if address < 0 or address > 0xFFFFFFFF:
        raise ValueError("address must be u32 (from segment table)")
    if not 0 < blocksize <= 0xFFE9:
        raise ValueError("blocksize out of INIT_VDLE range 1..0xFFE9")
    job = (JOB_FLASH_WRITE if blocksize <= XXL_THRESHOLD
           else JOB_FLASH_WRITE_XXL)
    if not send_job(job, build_flash_block(address, data)):
        return False
    deadline = time.monotonic() + poll_timeout_s
    while time.monotonic() < deadline:
        if poll_status() == 1:                 # FLASH_SCHREIBEN_STATUS [C]
            return True
        time.sleep(0.05)
    return False


def send_first_programming_segment(address: int, data: bytes,
                                   blocksize: int,
                                   send_job: Callable[[str, bytes], bool],
                                   poll_status: Callable[[], int],
                                   poll_timeout_s: float = 10.0) -> bool:
    """[R] Send the FIRST real segment for the region: the ECU flash kernel
    performs sector erase internally when programming starts [C]. There is
    no separate START command — this is an ordinary first segment. The
    address must be the real segment address from parse_segment_info()."""
    return send_flash_segment(address, data, blocksize, send_job,
                              poll_status, poll_timeout_s)


def parse_segment_info(reply: str) -> tuple:
    """[C] Parse the REQUEST_SEGMENTINFO reply, whose format is read
    directly from FUN_004665d0: sprintf("OKAY;0x%08X;0x%08X", addr, size).
    Returns (address, size). Raises on error replies — error tokens like
    ERROR_DLL_WRONGSTATE are passed through verbatim."""
    parts = reply.split(";")
    if len(parts) == 3 and parts[0] == "OKAY":
        address = int(parts[1], 16)
        size = int(parts[2], 16)
        if 0 <= address <= 0xFFFFFFFF and size > 0:
            return address, size
        raise ValueError(f"segment info out of range: {reply!r}")
    raise ValueError(f"segment info error reply: {reply!r}")


SIG_RESULT_NAME = "Daten"                        # [C] FUN_0045cab0 call
SIG_TOKEN_OK = "OKAY"                           # [C] strcmp @0x630194
SIG_TOKEN_PENDING = "ROUTINE_NOT_COMPLETE"      # [C] keep polling
SIG_TOKEN_CHECK_FAILED = "ERROR_FLASH_SIGNATURE_CHECK"   # [C] hard fail
SIG_TOKEN_SG_RESPONSE = "ERROR_SG_RESPONSE"     # [C] fail
SIG_TOKEN_NO_RESPONSE = "NO_RESPONSE"           # [C] abort


def verify_image_signature(send_job: Callable[[str, str], bool],
                           read_result: Callable[[], str],
                           poll_timeout_s: float = 30.0,
                           poll_interval_s: float = 0.1) -> bool:
    """[C] Post-programming integrity check — FUN_0041b4a0 "CheckSignatur"
    (rev 8; the earlier numeric 1/0x50 guess was WRONG-shaped: the
    original polls the TEXT result "Daten" of NG_SIGNATUR_PRUEFEN):

        "OKAY"                    → signature verified
        "ROUTINE_NOT_COMPLETE"    → ECU still computing, keep polling
        "ERROR_FLASH_SIGNATURE_CHECK" / "ERROR_SG_RESPONSE" → fail
        "NO_RESPONSE"             → abort

    The original arms three timers (10000 ms, 0x1e46 ms, (retries+1)*1000
    ms via FUN_00461c80) and stops when the outer deadline passes —
    mirrored here by poll_timeout_s ([R] value)."""
    if not send_job(JOB_SIGNATURE_CHECK, ""):
        return False
    deadline = time.monotonic() + poll_timeout_s
    while time.monotonic() < deadline:
        token = read_result()                    # result "Daten"
        if token == SIG_TOKEN_OK:
            return True
        if token == SIG_TOKEN_PENDING:
            time.sleep(poll_interval_s)
            continue
        return False                             # any error token
    return False
