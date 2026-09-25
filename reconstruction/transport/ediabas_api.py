#!/usr/bin/env python3
"""EDIABAS api32.dll bus adapter — the LAST bridge to real hardware.

FlashRunner speaks an EDIABAS-like bus contract
(job/job_bin/read_text/read_binary — the same boundary winkfpt.exe uses,
proven by the vdle_diff differentials). This module implements that
contract on top of the REAL api32.dll via ctypes, so the reconstruction
can drive a physical ECU through a genuine EDIABAS installation.

Signatures are NOT guessed [O]: Api.h / Apicalls.c / Apidll.h ship with
the EDIABAS 6.4.7 installation (Downloads/BMW/Inpa/EDIABAS_6.4.7) whose
Bin/api32.dll is the same distribution family as the md5-verified
api32.dll we reverse-engineered. Every DLL export takes the application
HANDLE as its FIRST argument (minted by __apiInit(&handle)) — Apicalls.c
§3 "Applikations-Locking ueber Handle" — and the stdcall export
decorations of our api32.dll match the header declarations exactly
(__apiJob@20 = handle+4, __apiResultText@20 = handle+4,
__apiJobData@24 = handle+5, __apiErrorText@12 = handle+2 ...).

Bench wiring (rev 13):

    from transport.ediabas_api import EdiabasApiBus
    bus = EdiabasApiBus.open(dll_path=r"C:\\EDIABAS\\Bin\\api32.dll")
    report = FlashRunner(bus, image, safety=ctx, auth="auto").flash()
    bus.close()

The DLL loads only on Windows (PE32 x86, stdcall). Dry-run/CI uses the
FakeApi selftest below plus bench_scenario --bus mock.
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

RESULT_SET = 1              # first result set (Api.h APIWORD set)
TEXT_BUFSIZ = 512           # JOB_STATUS & friends are short [O INPA-style]
BIN_BUFSIZ = 0xFFFF         # APIWORD is 16-bit — cap the buffer there
ENCODING = "cp1252"         # EDIABAS is ANSI; results carry German text

# API states after a job [O Api.h defines]. __apiJob/__apiJobData return
# VOID (Apidll.h) — the ONLY official way to tell "the call failed at
# API/IFH level" from "the ECU answered" is __apiState afterwards.
APIBUSY, APIREADY, APIBREAK, APIERROR = 0, 1, 2, 3


class EdiabasError(RuntimeError):
    """EDIABAS-side failure: APIFALSE + apiErrorText payload."""


class EdiabasUnavailable(RuntimeError):
    """api32.dll cannot be loaded (not Windows / wrong arch / no
    installation). Bench on Windows; dry-run uses the mock bus."""


def _load_api(dll_path: str | None = None):
    """Bind the __apiXxx export set of api32.dll with ctypes.

    Arg types follow Apidll.h [O]. Returns a plain namespace; injected
    fakes in the selftest implement the same surface in Python, so the
    marshalling logic is testable on any platform.
    """
    import ctypes

    if sys.platform != "win32":
        raise EdiabasUnavailable(
            "api32.dll needs 32-bit Windows (PE32 stdcall). Run the "
            "bench on the Windows/EDIABAS machine; for dry-run use "
            "bench_scenario.py --bus mock")
    try:
        dll = ctypes.WinDLL(dll_path or "api32.dll")
    except OSError as e:
        raise EdiabasUnavailable(
            f"cannot load api32.dll from {dll_path or 'PATH'}: {e}. "
            f"Typical fix: 32-bit Python + EDIABAS Bin on PATH") from None

    c = ctypes.c_uint32
    b = ctypes.c_char_p
    i = ctypes.c_int32
    w = ctypes.c_uint16
    api = type("Api", (), {})()

    def proto(name, restype, argtypes):
        fn = getattr(dll, f"__{name}")
        fn.restype = restype
        fn.argtypes = argtypes
        setattr(api, name, fn)

    proto("apiInit", i, [ctypes.POINTER(c)])                       # @4
    proto("apiEnd", None, [c])                                     # @4
    proto("apiState", i, [c])                                      # @4
    proto("apiErrorCode", i, [c])                                  # @4
    proto("apiErrorText", None, [c, b, i])                         # @12
    proto("apiSetConfig", i, [c, b, b])                            # @12
    proto("apiSwitchDevice", i, [c, b, b])                         # @12
    proto("apiJob", None, [c, b, b, b, b])                         # @20
    proto("apiJobData", None, [c, b, b, b, i, b])                  # @24
    proto("apiResultText", i, [c, b, b, w, b])                     # @20
    proto("apiResultBinary", i, [c, b, ctypes.POINTER(w), b, w])   # @20
    # __apiTrace@8 = (handle, flag) — not in Api.h but exported by the
    # shipping api32.dll; flag > 0 enables the EDIABAS trace files
    # (TRACE/api.trc — the format bench_diff parses). Bound softly so
    # ancient DLLs without the export load, but --trace then FAILS
    # LOUDLY instead of silently producing no trace (rev 15).
    try:
        proto("apiTrace", i, [c, i])                               # @8
    except AttributeError:
        pass
    return api


class EdiabasApiBus:
    """FlashRunner bus contract on real EDIABAS (api32.dll).

    IS_REAL_HW marks this bus as REAL hardware for the safety
    boundaries above it (bench_scenario.run_full refuses auth-off).

    FAILURE CONTRACT (rev 16) — API level and ECU level are NOT the
    same thing and must never be conflated [O Apicalls.c/Apidll.h]:
      API/IFH failure   __apiJob ran but apiState() != APIREADY (no
                        device, SGBD missing, IFH error …). EDIABAS then
                        keeps the PREVIOUS job's results — a JOB_STATUS
                        read now would return a STALE "OKAY". Therefore
                        job()/job_bin() RAISE EdiabasError immediately
                        and never read results in this state.
      ECU JOB_STATUS    apiState() == APIREADY → the job really ran and
                        the result set is fresh; job() then returns
                        (JOB_STATUS == "OKAY") like every bus.
    This adapter is synchronous-only: APIBUSY after the call (async
    polling configs) is refused loudly instead of half-read."""

    IS_REAL_HW = True               # safety boundaries key off this

    def __init__(self, api, trace: bool = False):
        self._api = api
        # rev 17: the handle is assigned BEFORE the init check — a
        # failed apiInit used to raise AttributeError from
        # _error_text() (self._handle missing) instead of the real
        # EDIABAS error, masking the actual init failure
        self._handle = ctypes.c_uint32(0)
        if not api.apiInit(ctypes.byref(self._handle)):
            detail = self._error_text() or "EDIABAS initialization refused"
            raise EdiabasError(f"apiInit failed: {detail}")
        if trace:
            # rev 15: no silent no-op — if this api32.dll lacks the
            # __apiTrace export the operator asked for a trace and
            # MUST know it will not appear
            if not hasattr(api, "apiTrace"):
                self.close()
                raise EdiabasError(
                    "--trace requested but this api32.dll has no "
                    "__apiTrace export — trace would silently be "
                    "missing; refusing")
            # rev 17: the RETURN VALUE matters too — an existing export
            # whose call fails would leave the run untraced while the
            # operator believes the trace is on (trace IS part of the
            # measurement experiment)
            rc = api.apiTrace(self._handle, 1)
            if not rc:
                self.close()
                raise EdiabasError(
                    f"__apiTrace(handle, 1) failed (returned {rc!r}) — "
                    f"trace would be missing; refusing")

    # -- construction on a real Windows box ------------------------------
    @classmethod
    def open(cls, dll_path: str | None = None, trace: bool = False,
             config: dict | None = None,
             _api=None) -> "EdiabasApiBus":
        """_api injects a fake __apiXxx surface for the selftest (the
        real path loads api32.dll via _load_api)."""
        bus = cls(_api if _api is not None else _load_api(dll_path),
                  trace=trace)
        # rev 18: a failed apiSetConfig must not LEAK the open handle —
        # close it before propagating (repeated runs in one Windows
        # session would otherwise accumulate apiEnd-less handles)
        try:
            bus._apply_config(config)
        except Exception:
            bus.close()
            raise
        return bus

    def _apply_config(self, config: dict | None):
        for name, value in (config or {}).items():
            if not self._api.apiSetConfig(self._handle,
                                          name.encode(ENCODING),
                                          value.encode(ENCODING)):
                raise EdiabasError(self._error_text())

    # -- internal ---------------------------------------------------------
    def _error_text(self) -> str:
        import ctypes
        buf = ctypes.create_string_buffer(256)
        self._api.apiErrorText(self._handle, buf, 256)
        return buf.value.decode(ENCODING, "replace")

    def _check_state(self, what: str):
        """The ONLY API-level failure detection [O Apidll.h: __apiJob
        returns void — apiState() afterwards is the contract]. Anything
        but APIREADY means the job did NOT run; the previous job's
        results are still live and MUST NOT be read as JOB_STATUS
        (rev 16: this is exactly how a stale OKAY used to pass)."""
        state = self._api.apiState(self._handle)
        if state != APIREADY:
            code = self._api.apiErrorCode(self._handle)
            names = {APIBUSY: "APIBUSY (async config — this adapter is "
                              "synchronous-only)",
                     APIBREAK: "APIBREAK", APIERROR: "APIERROR"}
            raise EdiabasError(
                f"{what}: API-level failure, apiState={state} "
                f"{names.get(state, '?')}, apiErrorCode={code}: "
                f"{self._error_text()} — results of the previous job "
                f"are STALE and will not be read")

    # -- bus contract (vdle_diff.EdiabasSim semantics) --------------------
    def job(self, device: str, name: str, args: str = "") -> bool:
        """__apiJob(handle, ecu, job, para, result="") [O Apicalls.c];
        result "" requests all result fields. apiState must be APIREADY
        before JOB_STATUS is read — see the class failure contract."""
        self._api.apiJob(self._handle, device.encode(ENCODING),
                         name.encode(ENCODING), args.encode(ENCODING), b"")
        self._check_state(f"apiJob {device}/{name}")
        return self.read_text("JOB_STATUS", "") == "OKAY"

    def job_bin(self, device: str, name: str, data: bytes) -> bool:
        """__apiJobData(handle, ecu, job, parabuf, paralen, result) [O] —
        the binary path winkfpt uses for FLASH_SCHREIBEN/NG_SIGNATUR."""
        import ctypes
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data) \
            if data else ctypes.create_string_buffer(b"", 1)
        self._api.apiJobData(self._handle, device.encode(ENCODING),
                             name.encode(ENCODING),
                             ctypes.cast(buf, ctypes.c_char_p),
                             len(data), b"")
        self._check_state(f"apiJobData {device}/{name}")
        return self.read_text("JOB_STATUS", "") == "OKAY"

    def read_text(self, name: str, default: str = "") -> str:
        """__apiResultText(handle, buf, result, set=1, format="")
        [O Apidll.h]. APIFALSE (unknown name) → contract default."""
        import ctypes
        buf = ctypes.create_string_buffer(TEXT_BUFSIZ)
        if not self._api.apiResultText(self._handle, buf,
                                       name.encode(ENCODING),
                                       RESULT_SET, b""):
            return default
        return buf.value.decode(ENCODING, "replace")

    def read_binary(self, name: str) -> bytes:
        """__apiResultBinary(handle, buf, &buflen, result, set=1) [O];
        buflen is in/out — APIFALSE or empty → b"" per contract."""
        import ctypes
        buf = ctypes.create_string_buffer(BIN_BUFSIZ)
        n = ctypes.c_uint16(BIN_BUFSIZ)
        if not self._api.apiResultBinary(self._handle, buf,
                                         ctypes.byref(n),
                                         name.encode(ENCODING),
                                         RESULT_SET):
            return b""
        return buf.raw[:n.value]

    # -- lifecycle --------------------------------------------------------
    def close(self):
        if getattr(self, "_handle", None) is not None:
            self._api.apiEnd(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Self-test: FakeApi implements the __apiXxx surface in pure Python — the
# marshalling of OUR side (handle-first, cp1252, exact binary lengths,
# JOB_STATUS semantics) is verified without Windows.
# ---------------------------------------------------------------------------
def _selftest():
    import ctypes

    passed, failed = 0, []

    def check(name, cond):
        nonlocal passed
        if cond:
            passed += 1
            print(f"EDIBUS OK   {name}")
        else:
            failed.append(name)
            print(f"EDIBUS FAIL {name}")

    class FakeApi:
        """Records every call exactly as api32 would see it; serves a
        canned result table per last job (results persist until the
        next job, like EDIABAS). api_fail_jobs models an API/IFH-level
        failure: the job does NOT run, apiState goes APIERROR and the
        PREVIOUS job's results stay live (the stale-results trap)."""

        def __init__(self):
            self.calls = []            # (name, handle, args...)
            self.results = {}          # name -> bytes value
            self.init_ok = True
            self.trace_ok = True       # __apiTrace return value
            self.setconfig_ok = True   # __apiSetConfig return value
            self.state = APIREADY      # apiState answer (after a job)
            self.api_fail_jobs = set() # job names that fail at API level
            self.error_code = 0
            self.force_state = None    # test override of the post-job state

        def _rec(self, name, *args):
            self.calls.append((name, self.handle, *args))

        def apiInit(self, handle_out):
            self.handle = 0xC0DE
            handle_out._obj.value = self.handle
            self._rec("apiInit", None)
            return int(self.init_ok)

        def apiEnd(self, h):
            self._rec("apiEnd")

        def apiState(self, h):
            self._rec("apiState")
            return self.state

        def apiErrorCode(self, h):
            self._rec("apiErrorCode")
            return self.error_code

        def apiErrorText(self, h, buf, size):
            self._rec("apiErrorText", None, size)
            buf.value = b"fake error"

        def apiSetConfig(self, h, name, value):
            self._rec("apiSetConfig", name, value)
            return int(self.setconfig_ok)

        def apiJob(self, h, ecu, job, para, result):
            self._rec("apiJob", ecu, job, para, result)
            if job.decode() in self.api_fail_jobs:
                self.state, self.error_code = APIERROR, 7
                return                   # results NOT replaced: stale
            self.state, self.error_code = (
                self.force_state if self.force_state is not None
                else APIREADY), 0
            self.results = {"JOB_STATUS": b"OKAY",
                            "SG_PHYS_HWNR": b"GKE192;4 003 692"}

        def apiJobData(self, h, ecu, job, buf, paralen, result):
            data = ctypes.string_at(buf, paralen)
            self._rec("apiJobData", ecu, job, data, paralen, result)
            if job.decode() in self.api_fail_jobs:
                self.state, self.error_code = APIERROR, 7
                return
            self.state, self.error_code = (
                self.force_state if self.force_state is not None
                else APIREADY), 0
            self.results = {"JOB_STATUS": b"OKAY"}

        def apiResultText(self, h, buf, name, s, fmt):
            self._rec("apiResultText", name, s, fmt)
            val = self.results.get(name.decode())
            if val is None:
                return 0
            buf.value = val
            return 1

        def apiResultBinary(self, h, buf, n, name, s):
            self._rec("apiResultBinary", name, s)
            val = self.results.get(name.decode())
            if val is None or len(val) > n._obj.value:
                return 0
            ctypes.memmove(buf, val, len(val))
            n._obj.value = len(val)
            return 1

        def apiTrace(self, h, flag):
            self._rec("apiTrace", flag)
            return int(self.trace_ok)

    fake = FakeApi()
    bus = EdiabasApiBus(fake)
    check("apiInit minted the handle and passed it first",
          fake.calls[0] == ("apiInit", 0xC0DE, None))

    ok = bus.job("DLE08", "SG_PHYS_HWNR_LESEN", "")
    c = [c for c in fake.calls if c[0] == "apiJob"][-1]
    check("job(): handle-first + ansi strings + result-all",
          c == ("apiJob", 0xC0DE, b"DLE08", b"SG_PHYS_HWNR_LESEN", b"", b"")
          and ok)
    check("job() returns JOB_STATUS == OKAY", ok is True)
    check("read_text decodes the persisted result + default on miss",
          bus.read_text("SG_PHYS_HWNR") == "GKE192;4 003 692"
          and bus.read_text("NOSUCH", "dflt") == "dflt")

    ok = bus.job_bin("DLE08", "NG_AUTHENTISIERUNG_START", b"\x01\x02\x03\x04")
    c = [c for c in fake.calls if c[0] == "apiJobData"][-1]
    check("job_bin(): exact bytes + exact length",
          c == ("apiJobData", 0xC0DE, b"DLE08",
                b"NG_AUTHENTISIERUNG_START", b"\x01\x02\x03\x04", 4, b""))

    fake.results["ZUFALLSZAHL"] = bytes.fromhex("0102030405060708")
    check("read_binary returns exact length",
          bus.read_binary("ZUFALLSZAHL") == bytes.fromhex("0102030405060708"))

    del fake.results["ZUFALLSZAHL"]
    check("unknown binary result -> b'' per contract",
          bus.read_binary("NOSUCH") == b"")

    # rev 16 — the reviewer's exact trap: job A succeeded (JOB_STATUS
    # OKAY persists in the result set), job B fails at API/IFH level so
    # EDIABAS keeps job A's results. job() MUST raise instead of
    # reading the stale OKAY and reporting success.
    reads_before = sum(1 for c in fake.calls if c[0] == "apiResultText"
                       and c[2] == b"JOB_STATUS")
    fake.api_fail_jobs.add("INIT_VDLE")
    raised = False
    try:
        bus.job("VDLE", "INIT_VDLE", "OKAY;1")
    except EdiabasError as e:
        raised = "APIERROR" in str(e) and "STALE" in str(e)
    reads_after = sum(1 for c in fake.calls if c[0] == "apiResultText"
                      and c[2] == b"JOB_STATUS")
    check("API failure raises; stale JOB_STATUS not read (job)",
          raised and reads_after == reads_before)
    fake.api_fail_jobs.discard("INIT_VDLE")

    fake.api_fail_jobs.add("NG_AUTHENTISIERUNG_START")
    try:
        bus.job_bin("DLE08", "NG_AUTHENTISIERUNG_START", b"\x01\x02")
        check("API failure raises; stale JOB_STATUS not read (job_bin)",
              False)
    except EdiabasError as e:
        check("API failure raises; stale JOB_STATUS not read (job_bin)",
              "APIERROR" in str(e))
    fake.api_fail_jobs.discard("NG_AUTHENTISIERUNG_START")

    # APIBUSY after the call (async polling config) — refused loudly,
    # this adapter is synchronous-only
    fake.force_state = APIBUSY
    try:
        bus.job("DLE08", "IDENT", "")
        check("APIBUSY after the call refuses (sync-only adapter)",
              False)
    except EdiabasError as e:
        check("APIBUSY after the call refuses (sync-only adapter)",
              "APIBUSY" in str(e))
    fake.force_state = None

    bus.close()
    check("apiEnd received the handle",
          fake.calls[-1] == ("apiEnd", 0xC0DE))

    # rev 15: --trace actually reaches the DLL...
    fake2 = FakeApi()
    EdiabasApiBus(fake2, trace=True).close()
    check("trace=True calls __apiTrace(handle, 1)",
          ("apiTrace", 0xC0DE, 1) in fake2.calls)

    # ...and fails LOUDLY when the export is missing (no silent no-trace)
    class NoTraceApi(FakeApi):
        @property
        def apiTrace(self):        # models a DLL without the export:
            raise AttributeError   # hasattr() -> False
    try:
        EdiabasApiBus(NoTraceApi(), trace=True)
        check("missing __apiTrace export refuses loudly", False)
    except EdiabasError as e:
        check("missing __apiTrace export refuses loudly",
              "trace" in str(e))

    # rev 17: the export EXISTS but the call itself fails — refuse;
    # the trace is part of the measurement experiment
    fake3 = FakeApi()
    fake3.trace_ok = False
    try:
        EdiabasApiBus(fake3, trace=True)
        check("failing __apiTrace call refuses loudly (rc checked)",
              False)
    except EdiabasError as e:
        check("failing __apiTrace call refuses loudly (rc checked)",
              "apiTrace" in str(e))

    # rev 17: a failed apiInit surfaces the EDIABAS error text — not
    # an AttributeError from a handle that was not yet assigned
    fake4 = FakeApi()
    fake4.init_ok = False
    try:
        EdiabasApiBus(fake4)
        check("failed apiInit raises EdiabasError with error text",
              False)
    except EdiabasError as e:
        check("failed apiInit raises EdiabasError with error text",
              "apiInit" in str(e) and "fake error" in str(e))
    except AttributeError:
        check("failed apiInit raises EdiabasError with error text",
              False)

    # rev 18: a failed apiSetConfig closes the handle (no apiEnd-less
    # handle leak across repeated runs in one session) — through the
    # REAL open() cleanup path
    fake5 = FakeApi()
    fake5.setconfig_ok = False
    try:
        EdiabasApiBus.open(config={"Trace": "1"}, _api=fake5)
        check("failed apiSetConfig raises AND closes the handle",
              False)
    except EdiabasError:
        check("failed apiSetConfig raises AND closes the handle",
              any(c[0] == "apiSetConfig" for c in fake5.calls)
              and fake5.calls[-1] == ("apiEnd", 0xC0DE))

    # non-Windows load path refuses with a usable message
    if sys.platform != "win32":
        try:
            _load_api("api32.dll")
            check("_load_api refuses off-Windows with EdiabasUnavailable",
                  False)
        except EdiabasUnavailable as e:
            check("_load_api refuses off-Windows with EdiabasUnavailable",
                  "mock" in str(e))

    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_selftest())
