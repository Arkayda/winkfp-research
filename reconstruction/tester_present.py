"""TesterPresent / session keep-alive reconstruction (winkfpt.exe).

Original behaviour [C]: session maintenance (FUN_004a5960) runs INLINE
before segment operations — not as a free-running thread. On keep-alive
failure the caller ABORTS the operation (FUN_004665d0 replies
ERROR_DLL_TESTERPRESENTHANDLING [O]); it never proceeds with the next
flash job.

Rev 7 — execution-proven dual-deadline model (FUN_004a5960 disassembly
0x4a5960..0x4a5a44 + live emulation, vdle_diff.py):
  * TWO deadline slots in DAT_00881470[0..9]; TP uses slots 1 and 2.
  * slot 1 "heavy": 10000 ms (ESI=0x2710), slot 2 "light": 8000 ms
    (ESI=0x1f40 — matches the OPPS STEUERN_TP_INTERVALL "8000" value).
  * expired(slot 1)?  → send the FULL NORMALER_DATENVERKEHR pair
    ("NEIN;NEIN;JA" then "JA;NEIN;NEIN"). If EITHER fails the function
    returns 0 IMMEDIATELY — there is NO DIAGNOSE_AUFRECHT fallback after
    a NORMALER failure (JZ 0x004a59e8 → XOR AL,AL → RET). Both slots are
    re-armed BEFORE the pair is sent.
  * else expired(slot 2)? → send the single LIGHT keep-alive
    DIAGNOSE_AUFRECHT "NEIN;JA" (re-arms both slots, returns its result).
  * else → nothing to do (return ok). Skipped entirely while the session
    flag DAT_0088146c is 0 or in OPPS mode (fast path 0x4a5960..0x4a5974).

Rev 6 finding kept: keep-alive is deadline-THROTTLED (FUN_004a57e0
stores GetTickCount()+interval, FUN_004a5820 reports expiry and
auto-clears the slot) — not once per block.
"""

import threading
import time
from typing import Callable

JOB_NORMAL_TRAFFIC = "NORMALER_DATENVERKEHR"   # [O]
JOB_TP_SWITCH = "STEUERN_DLE_TP"               # [O]
JOB_KEEP_ALIVE = "DIAGNOSE_AUFRECHT"           # [O]

TP_HEAVY_INTERVAL_S = 10.0        # slot 1, 0x2710 ms [C asm 0x4a598a]
TP_LIGHT_INTERVAL_S = 8.0         # slot 2, 0x1f40 ms [C asm 0x4a5999]


class SessionLost(RuntimeError):
    """Keep-alive failed — the original returns 0 from FUN_004a5960 and
    the caller aborts the flash job (no recovery attempt exists)."""


class JobScheduler:
    """Single owner of the transport (matches original job serialization).
    All job calls first perform inline session maintenance; any failure
    aborts instead of silently continuing."""

    def __init__(self, send_job: Callable[[str, str], bool]):
        self._send = send_job
        self._lock = threading.Lock()
        self._tp_on = False
        # deadline slots, 0.0 = unset/expired — mirrors DAT_00881470 == 0
        self._dl_heavy = 0.0
        self._dl_light = 0.0

    def start_session(self) -> bool:                 # FUN_004a5850 [C]
        with self._lock:
            return (self._send(JOB_NORMAL_TRAFFIC, "NEIN;NEIN;JA")
                    and self._send(JOB_NORMAL_TRAFFIC, "JA;NEIN;NEIN"))

    def tp_enable(self, on: bool) -> bool:           # FUN_004a5eb0 [C]
        with self._lock:
            self._tp_on = self._send(JOB_TP_SWITCH, "1" if on else "0")
            return self._tp_on

    def job(self, name: str, arg: str) -> bool:
        with self._lock:
            self._keepalive_locked()                 # FUN_004a5960 [C]
            return self._send(name, arg)

    def _rearm_deadlines_locked(self, now: float) -> None:
        """[C] FUN_004a57e0 x2 at 0x4a5994/0x4a59a3 (and 0x4a5a0a/0x4a5a19
        in the light branch): both slots are re-armed BEFORE any keep-alive
        job is sent — even if the subsequent job fails."""
        self._dl_heavy = now + TP_HEAVY_INTERVAL_S
        self._dl_light = now + TP_LIGHT_INTERVAL_S

    def _keepalive_locked(self) -> None:             # FUN_004a5960 [C]
        if not self._tp_on:
            return
        now = time.monotonic()
        if now < self._dl_heavy:                     # slot 1 still armed
            if now < self._dl_light:
                return                               # nothing due
            # LIGHT branch: single DIAGNOSE_AUFRECHT (slot 2 expired)
            self._rearm_deadlines_locked(now)
            if not self._send(JOB_KEEP_ALIVE, "NEIN;JA"):
                raise SessionLost("DIAGNOSE_AUFRECHT keep-alive failed")
            return
        # HEAVY branch: full NORMALER_DATENVERKEHR pair, NO fallback
        self._rearm_deadlines_locked(now)
        ok = (self._send(JOB_NORMAL_TRAFFIC, "NEIN;NEIN;JA")
              and self._send(JOB_NORMAL_TRAFFIC, "JA;NEIN;NEIN"))
        if not ok:
            raise SessionLost("NORMALER_DATENVERKEHR pair failed — the "
                              "original returns 0 immediately with NO "
                              "DIAGNOSE_AUFRECHT fallback (caller replies "
                              "ERROR_DLL_TESTERPRESENTHANDLING)")


def tester_present_start(scheduler: JobScheduler) -> bool:
    """START_TESTERPRESENT equivalent [C]: session up + TP on."""
    if not scheduler.start_session():
        raise RuntimeError("ERROR_DLL_TESTERPRESENTHANDLING")   # [O]
    return scheduler.tp_enable(True)
