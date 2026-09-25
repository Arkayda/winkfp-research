#!/usr/bin/env python3
"""Integration layer: the COMPLETE flash scenario of the shipping IPO
(CI62F1/CI63F1/CIA0F1/ULF2HI — see WAS_ORCHESTRATION.md) as one Python
call, built exclusively on reconstruction/*.

    from flash_runner import FlashRunner, SafetyContext
    report = FlashRunner(bus, image_bytes, safety=safety_ctx).flash()
    assert report.ok and report.signature_ok

`bus` is any EDIABAS-like transport with the winkfpt boundary semantics:
    bus.job(device, name, args) -> bool        # apiJob + JOB_STATUS read
    bus.job_bin(device, name, data) -> bool    # apiJobJobBin
    bus.read_text(name, default) -> str
    bus.read_binary(name) -> bytes
(vdle_diff.EdiabasSim implements exactly this and is used by the
self-test; a real transport adapter maps these onto EDIABAS api32 /
a TCP remote / a custom driver.)

Choreography implemented (all [C] execution-proven against the original
winkfpt.exe machine code in vdle_diff.py DF1–DF11):
  safety     HARD GATE (rev 11): flash() refuses to run without a
             validated SafetyContext; re-validated right before the
             download phase
  setup      FLASH_PARAMETER_SETZEN + INIT_VDLE (state gate -> 2)
  auth       auto-negotiated (rev 11): SG_PHYS_HWNR_LESEN → ECU
             identity, AUTHENTISIERUNG → offered T_SMA/B/C arts,
             sgidX.as2 container record class → the actually possible
             art; SERIENNUMMER_LESEN → serial,
             AUTHENTISIERUNG_ZUFALLSZAHL_LESEN → seed, compute
             SG-Schluessel, NG_AUTHENTISIERUNG_START with the IPO
             retry semantics (ROUTINE_NOT_COMPLETE / NO_RESPONSE /
             ERROR_ERROR_AUTHENTICATION, max 3 attempts, overall
             window FLASH_AUTHENTISIERZEIT — winkfpt orchestrator
             FUN_0041c920 timers 10000 / 0x1E46 / (N+1)*1000 ms)
  totals     REQUEST_SEGMENTINFO "99"
  download   per segment: REQUEST_SEGMENTINFO <n>, SEND_SEGMENT <n>
             (TesterPresent dual-rate keep-alive before every block,
             FLASH_SCHREIBEN <block>, JOB_STATUS, poll
             FLASH_SCHREIBEN_STATUS until ENDE)
  recovery   on a failed FLASH job the resume state is saved
             (blocks_done); WAS attempt = REQUEST_SEGMENTINFO "-1" +
             SEND_SEGMENT "-1"; when the error-report latch has dropped
             the state gate (measured: ALWAYS, after any reported
             failure) the runner restarts the session with a fresh
             INIT_VDLE and resends the segment from block 0
  signature  NG_SIGNATUR_PRUEFEN string-token protocol
             (OKAY / ROUTINE_NOT_COMPLETE / ERROR_* / NO_RESPONSE)
  finish     EXIT_VDLE
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reconstruction import security
from reconstruction import tester_present
from reconstruction import vdle as rvdle

DEV_VDLE = "VDLE"          # callback SGBD (winkfpt) device name [C]
DEV_ECU = "DLE08"          # ECU flash device (argv[0] buffer) [C]

# ---- IPO CI62F1 Authentisierung block [C] ---------------------------------
AUTH_ART_OF_FLAG = {"T_SMA": "Asymetrisch", "T_SMB": "Symetrisch",
                    "T_SMC": "Simple"}
AUTH_CLASS_OF_ART = {"Simple": 8, "Symetrisch": 16, "Asymetrisch": 136}
AUTH_RETRY_MAX = 3                      # [C] orchestrator FUN_0041c920:
                                        # "повтор авторизации максимум 3 раза"
AUTH_DEFAULT_WINDOW_S = 10.0            # [C] orchestrator timer 10000 ms
AUTH_RETRYABLE = ("ERROR_ERROR_AUTHENTICATION", "ROUTINE_NOT_COMPLETE",
                  "NO_RESPONSE")


class AuthUnavailable(Exception):
    """Auto-negotiation impossible in THIS environment (e.g. the sgidX
    containers are not installed). The phase is skipped — the ECU will
    refuse programming on its own; auth is never faked."""


def discover_store():
    """Locate the sgidX.as2 containers (NFS DATA/GDATEN or SP-Daten
    data/gdaten) and build the As2KeyStore. Raises FileNotFoundError."""
    from reconstruction.as2_keys import As2KeyStore
    home = Path.home()
    for cand in (home / "Downloads/BMW/extracted/E60_daten/data/gdaten",
                 home / "Downloads/BMW/extracted/standard_tools/"
                        "code$GetNFSInstallDir/DATA/GDATEN"):
        if (cand / "SGIDC.as2").exists():
            idxs = {3: cand / "SGIDC.as2"}
            if (cand / "SGIDD.as2").exists():
                idxs[4] = cand / "SGIDD.as2"
            return As2KeyStore.from_paths(idxs)
    raise FileNotFoundError("sgidX.as2 containers not found (need NFS "
                            "DATA/GDATEN or SP-Daten data/gdaten)")


@dataclass
class AuthConfig:
    """Per-ECU key material for the Authentisierung phase (rev 10).

    ecu_name — record name inside the sgidX.as2 container
               (e.g. "GKE192" for the E60 EGS mechatronic)
    key_index — 3 → sgidC.as2, 4 → sgidD.as2  [C: GetAuthKey builds
               "sgid" + chr('@'+index) + ".as2"]
    art      — "Simple" | "Symetrisch" | "Asymetrisch" — must match the
               record class the container holds for that ECU (8 B / 16 B
               / 136 B; the length gate FUN_004b89a0 enforces it at
               runtime).  The IPO offers the art per the ECU's
               AUTHENTISIERUNG response (T_SMA/B/C flags).
    store    — reconstruction.as2_keys.As2KeyStore (or {index: path}).
    nonce    — 4 bytes, part of the auth chain for Symetrisch AND
               Asymetrisch alike; None (default) → the orchestrator
               mints a fresh FUN_00461800 nonce per attempt (rev 12:
               no placeholder nonce exists anywhere in the codebase).

    An explicit AuthConfig pins the whole phase; auth=None/auto lets the
    runner NEGOTIATE it from the live ECU (rev 11).
    """
    ecu_name: str
    key_index: int = 3
    art: str = "Symetrisch"
    store: object = None
    nonce: bytes | None = None

    def resolve_store(self):
        if self.store is None:
            return discover_store()
        if isinstance(self.store, dict):
            from reconstruction.as2_keys import As2KeyStore
            return As2KeyStore.from_paths(self.store)
        return self.store


@dataclass
class SafetyContext:
    """Hard-gate interlock context (rev 11): provenance-carrying Limits
    (safety.hypotheses — built via Limits.from_limits_file from the
    operator's digest-bound limits policy file; NOT BMW-validated
    numbers, see safety/hypotheses) plus a read_state() over the live
    vehicle measurements. flash() refuses to start without a context
    whose validate() is empty, and re-validates it before the first
    byte goes to the ECU."""

    limits: object                     # safety.hypotheses.Limits
    read_state: object                 # Callable[[str], object]

    def validate(self) -> list:
        try:
            from .safety.hypotheses import check_preconditions
        except (ImportError, ValueError):
            try:
                from reconstruction.safety.hypotheses import check_preconditions
            except (ImportError, ValueError):
                from safety.hypotheses import check_preconditions
        ok, failures = check_preconditions(self.read_state, self.limits)
        return [] if ok else failures


@dataclass
class PhaseLog:
    name: str
    events: list = field(default_factory=list)


@dataclass
class FlashReport:
    ok: bool = False
    phases: list = field(default_factory=list)
    segments_total: int = 0
    segments_done: int = 0
    blocks_written: int = 0
    bytes_written: int = 0
    was_attempted: bool = False
    restarted: bool = False
    signature_ok: bool = False
    auth_ok: bool = False
    auth_ecu: str = ""
    auth_art: str = ""
    auth_attempts: int = 0
    auth_note: str = ""
    auth_key_hex: str = ""        # rev 15 audit: last computed SG-Schluessel
    auth_nonce_hex: str = ""      # rev 15 audit: nonce of that attempt
    auth_attempts_log: list = field(default_factory=list)
    # ^ rev 17: PER-ATTEMPT audit trail — {attempt, ecu, art, idx,
    # seed_hex, nonce_hex, key_hex, status, ok} for EVERY
    # NG_AUTHENTISIERUNG_START try, so the WHOLE retry chain (not just
    # the winning attempt) is verifiable offline (bench_diff --verify)
    error: str | None = None

    def summary(self) -> str:
        lines = [f"flash {'OK' if self.ok else 'FAILED'}"
                 + (f": {self.error}" if self.error else ""),
                 f"  segments {self.segments_done}/{self.segments_total}"
                 f", blocks {self.blocks_written}"
                 f", bytes {self.bytes_written}"]
        if self.auth_ecu:
            lines.append(
                f"  authentisierung: "
                f"{'OK' if self.auth_ok else 'NOK'} "
                f"({self.auth_ecu}, {self.auth_art}, "
                f"attempts {self.auth_attempts})")
        elif self.auth_note:
            lines.append(f"  authentisierung: skipped ({self.auth_note})")
        if self.was_attempted:
            lines.append(f"  WAS attempted: {self.was_attempted}"
                         f", restart used: {self.restarted}")
        lines.append(f"  signature: {'OK' if self.signature_ok else 'NOK'}")
        return "\n".join(lines)


class FlashFailure(Exception):
    pass


class FlashRunner:
    """Drives one complete programming session over `bus`."""

    def __init__(self, bus, image: bytes, *, blocksize: int = 8,
                 tester_present_on: bool = True,
                 flash_parameter: str | None = "0x62;2;18;1;simple",
                 poll_limit: int = 8,
                 auth: AuthConfig | None | str = None,
                 auth_nonce: bytes | None = None,
                 safety: SafetyContext | None = None):
        self.bus = bus
        self.image = image
        self.segments = rvdle.load_table(image)
        self.bs = blocksize
        self.tp_on = tester_present_on
        self.flash_parameter = flash_parameter
        self.poll_limit = poll_limit
        self.auth = auth
        self.auth_nonce = auth_nonce
        self.safety = safety
        self.state = rvdle.SendState()
        self._gate = 0                       # winkfpt DAT_008818e0
        self.report = FlashReport(
            segments_total=len(self.segments))
        self.sched = tester_present.JobScheduler(
            self._tp_send)                   # dual-rate 10 s / 8 s [C]

    # -- safety hard gate (rev 11) ------------------------------------------
    def check_safety(self, where: str = "flash"):
        """API-level hard gate: no validated SafetyContext → flash() is
        not executable at all (the refusal propagates to the caller, it
        is not a warning and not a report entry)."""
        if self.safety is None:
            raise FlashFailure(
                f"{where}: REFUSED — no SafetyContext. Construct "
                f"SafetyContext(limits=Limits.from_limits_file(...), "
                f"read_state=...) so every interlock number is parsed "
                f"from the digest-bound limits file (rev 11 hard gate).")
        try:
            failures = self.safety.validate()
        except (TypeError, ValueError) as e:
            # rev 12: untraced limits (bare Limits(...)) are a refusal,
            # not a crash — same gate, same exception type
            raise FlashFailure(f"{where}: safety gate FAILED: {e}") from None
        if failures:
            raise FlashFailure(
                f"{where}: safety gate FAILED: " + "; ".join(failures))

    # -- bus wrappers (also the event log for the report) -----------------
    def _phase(self, name):
        ph = PhaseLog(name)
        self.report.phases.append(ph)
        return ph

    def _job(self, dev, name, args=""):
        ok = self.bus.job(dev, name, args)
        self._last(name, ("job", dev, name, args))
        if (dev == DEV_VDLE and not args.startswith("OKAY")
                and not args.startswith("ERROR_DLL_STD_NOOKAY;1")):
            self._gate = 1      # [C] FUN_004a2160 error-report latch
        return ok

    def _job_bin(self, dev, name, data):
        ok = self.bus.job_bin(dev, name, data)
        self._last(name, ("job_bin", dev, name, len(data)))
        return ok

    def _last(self, name, ev):
        if self.report.phases:
            self.report.phases[-1].events.append(ev)

    def _tp_send(self, job, arg):
        return self.bus.job(DEV_ECU, job, arg)

    def _keepalive(self):
        """Dual-rate TesterPresent; raises SessionLost on failure [C]."""
        if not self.tp_on:
            return
        with self.sched._lock:
            self.sched._keepalive_locked()

    # -- phases ------------------------------------------------------------
    def setup(self):
        ph = self._phase("setup")
        if self.flash_parameter:
            # [R rev 16] an ECU refusing the flash parameters is fatal —
            # proceeding to INIT_VDLE on a refused session would diverge
            # from the production tool's behaviour anyway
            if not self._job(DEV_ECU, "FLASH_PARAMETER_SETZEN",
                             self.flash_parameter):
                raise FlashFailure(
                    "FLASH_PARAMETER_SETZEN failed — not proceeding to "
                    "INIT_VDLE on a refused parameter set")
        self._init_vdle()

    def _init_vdle(self):
        """INIT_VDLE arms the state gate ONLY on success (rev 16). The
        old code set _gate = 2 unconditionally, so a failed INIT_VDLE
        left the runner in gate 2 on a dead session and REQUEST_SEGMENT-
        INFO / the download would run on an artificially armed gate
        (review 15's P0). [C] INIT_VDLE reply feeds the segment table;
        [R] refusing to arm on a non-OKAY reply is the strict form."""
        if not self._job(DEV_VDLE, "INIT_VDLE",
                         rvdle.init_vdle_reply(len(self.segments))):
            raise FlashFailure(
                "INIT_VDLE failed — state gate NOT armed; the session "
                "must not continue")
        self._gate = 2                       # [C] INIT_VDLE state arm
        self.state.segment = -1              # [C] INIT clears WAS state

    # -- authentisierung (rev 10 manual / rev 11 negotiated + IPO retry) --
    def negotiate_auth(self) -> AuthConfig:
        """Derive the WHOLE auth configuration from the live session
        (rev 11): the ECU answers identity + offered arts, the sgidX
        container record class decides which offered art is actually
        possible. All job names are the IPO CI62F1 Authentisierung
        block [C]; the mapping T_SMA/B/C → Asymetrisch/Symetrisch/
        Simple is the IPO's own print table."""
        # 1) hardware identity — right before FLASH_PARAMETER_SETZEN in
        #    the IPO prologue [C]
        self._job(DEV_ECU, "SG_PHYS_HWNR_LESEN", "OKAY")
        ident = ""
        for name in ("SG_PHYS_HWNR", "HWNR"):
            ident = self.bus.read_text(name, "")
            if ident:
                break
        ecu = ident.strip().split(";")[0].strip().upper()
        if not ecu:
            raise FlashFailure(
                "auto-negotiation: no ECU identity "
                "(SG_PHYS_HWNR_LESEN → SG_PHYS_HWNR/HWNR empty)")
        # 2) arts the ECU offers [C IPO result AUTHENTISIERUNG: the
        #    T_SMA/T_SMB/T_SMC flags next to "Authentisierungsart :")
        self._job(DEV_ECU, "AUTHENTISIERUNG", "OKAY")
        flags = [f.strip() for f in
                 self.bus.read_text("AUTHENTISIERUNG", "").split(";")]
        offered = [AUTH_ART_OF_FLAG[f] for f in flags
                   if f in AUTH_ART_OF_FLAG]
        if not offered:
            raise FlashFailure(
                f"auto-negotiation: ECU {ecu} offered no known auth art "
                f"(AUTHENTISIERUNG -> {flags!r})")
        # 3) the container records: what GetAuthKey can deliver per
        #    index (rev 12: an ECU may sit in BOTH containers with
        #    DIFFERENT record classes)
        try:
            store = discover_store()
        except FileNotFoundError as e:
            raise AuthUnavailable(str(e)) from None
        records = {}                              # idx → record class (B)
        for idx in (3, 4):
            try:
                records[idx] = len(store.auth_blob(ecu, idx))
            except KeyError:
                pass
        if not records:
            raise AuthUnavailable(
                f"ECU {ecu!r} has no record in any sgidX container")
        # 4) rev 12 pairing: for each art the ECU OFFERS (in offer
        #    order) find the container record of the matching class —
        #    art → record, NOT record → art. The old order (first
        #    container with any record, then class check) failed loudly
        #    when only the OTHER container held the matching class.
        #    Within one art idx 3 wins over 4 [R: deterministic tie
        #    break; the original takes the index from SP-Daten config].
        for art in offered:
            need = AUTH_CLASS_OF_ART[art]
            for idx in (3, 4):
                if records.get(idx) == need:
                    self.report.auth_ecu, self.report.auth_art = ecu, art
                    return AuthConfig(ecu_name=ecu, key_index=idx, art=art,
                                      store=store, nonce=self.auth_nonce)
        raise FlashFailure(
            f"auto-negotiation: ECU {ecu} offers {offered} but no "
            f"container record matches — "
            + ", ".join(f"sgid{chr(0x40 + i)}.as2 holds {c} B"
                        for i, c in sorted(records.items()))
            + " — stale SP-Daten vs ECU?")

    def _compute_auth_key(self, a: AuthConfig, seed: bytes,
                          serial: bytes) -> bytes:
        try:
            art = a.art.lower()
            if art == "simple":
                return security.compute_security_key_simple(
                    seed, a.resolve_store().simple_key8(
                        a.ecu_name, a.key_index))
            if art == "symetrisch":
                return security.compute_security_key(
                    seed, serial,
                    a.resolve_store().sym_key16(a.ecu_name, a.key_index),
                    nonce=a.nonce)
            if art == "asymetrisch":
                # rev 12: the b"0000" placeholder is GONE. A 4-byte
                # nonce is a hard requirement — the orchestrator mints
                # one per attempt (FUN_00461800, see authenticate()).
                if a.nonce is None or len(a.nonce) != 4:
                    raise FlashFailure(
                        "asymetrisch auth requires a 4-byte nonce "
                        "(FUN_00461800 srand(time)/rand) — refusing to "
                        "compute with a placeholder nonce")
                return security.compute_security_key_asymmetric_as2(
                    seed, serial, a.nonce,
                    a.resolve_store().auth_blob(a.ecu_name, a.key_index))
            raise FlashFailure(f"unknown auth art {a.art!r}")
        except ValueError as e:            # record class mismatch etc.
            raise FlashFailure(f"auth material: {e}") from None

    def _auth_window_s(self) -> float:
        """[C] IPO FLASH_ZEITEN_LESEN result "AuthentisierungZeit" (ms);
        winkfpt orchestrator default timer 10000 ms (FUN_0041c920)."""
        self._job(DEV_ECU, "FLASH_ZEITEN_LESEN", "OKAY")
        try:
            return float(self.bus.read_text("AuthentisierungZeit", "")) / 1000.0
        except ValueError:
            return AUTH_DEFAULT_WINDOW_S

    def authenticate(self):
        """IPO Authentisierung phase with REAL container key material:
        SERIENNUMMER_LESEN → (per attempt) AUTHENTISIERUNG_ZUFALLSZAHL_LESEN
        → compute SG-Schluessel → NG_AUTHENTISIERUNG_START → JOB_STATUS,
        with the orchestrator retry semantics [C FUN_0041c920]:
        ROUTINE_NOT_COMPLETE / NO_RESPONSE / ERROR_ERROR_AUTHENTICATION
        are retried with a FRESH seed, max 3 attempts, inside the
        FLASH_AUTHENTISIERZEIT window."""
        self._phase("auth")
        a = self.auth
        if a is False:
            self.report.phases.pop()         # auth explicitly disabled
            return True
        if a is None or a == "auto":
            try:
                a = self.negotiate_auth()
            except AuthUnavailable as e:
                self.report.auth_note = str(e)
                return True         # never fake auth; the ECU will refuse
        else:
            self.report.auth_ecu = a.ecu_name
            self.report.auth_art = a.art
        self._job(DEV_ECU, "SERIENNUMMER_LESEN", "OKAY")
        serial = self.bus.read_binary("SERIENNUMMER")
        window = self._auth_window_s()
        deadline = time.monotonic() + window
        # rev 12: nonce is attempt state, conceptually identical for
        # all three arts. Pinned once (runner auth_nonce wins over an
        # AuthConfig nonce) or minted FRESH for every attempt, exactly
        # like the seed — FUN_00461800 srand(time(NULL))/"%4.4lx"%rand().
        pinned = self.auth_nonce if self.auth_nonce is not None else a.nonce
        attempts = 0
        while True:
            attempts += 1
            self.report.auth_attempts = attempts
            # fresh ZUFALLSZAHL for every attempt [C orchestrator]
            self._job(DEV_ECU, "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN",
                      f"{a.key_index};")
            seed = self.bus.read_binary("ZUFALLSZAHL")
            a.nonce = pinned if pinned is not None \
                else security.generate_msvc_nonce()
            key = self._compute_auth_key(a, seed, serial)
            # rev 15: NEVER collapse a real ECU status into NO_RESPONSE.
            # The bus bool only says whether the call went out; the
            # status comes from the JOB_STATUS result either way (a real
            # EDIABAS bus returns False for non-OKAY statuses — the
            # distinction ERROR_ERROR_AUTHENTICATION vs ROUTINE_NOT_
            # COMPLETE vs a genuinely missing answer must survive).
            sent = self._job_bin(DEV_ECU, "NG_AUTHENTISIERUNG_START", key)
            status = self.bus.read_text("JOB_STATUS", "")
            if not sent and not status:
                status = "NO_RESPONSE"      # call failed, no answer at all
            # audit trail (rev 15): what the runner actually computed —
            # lets a bench log be verified offline (bench_diff --verify)
            self.report.auth_key_hex = key.hex()
            self.report.auth_nonce_hex = a.nonce.hex()
            # rev 17: PER-ATTEMPT record — every try of the retry chain
            # carries its own evidence (seed, nonce, key, status)
            self.report.auth_attempts_log.append({
                "attempt": attempts, "ecu": a.ecu_name, "art": a.art,
                "idx": a.key_index, "seed_hex": seed.hex(),
                "nonce_hex": a.nonce.hex(), "key_hex": key.hex(),
                "status": status, "ok": status == "OKAY"})
            if status == "OKAY":
                self.report.auth_ok = True
                return True
            if status not in AUTH_RETRYABLE:
                raise FlashFailure(
                    f"NG_AUTHENTISIERUNG_START: unexpected JOB_STATUS "
                    f"{status!r}")
            if attempts >= AUTH_RETRY_MAX:
                raise FlashFailure(
                    f"NG_AUTHENTISIERUNG_START {status} after "
                    f"{attempts} attempts (auth window {window:.0f}s)")
            if time.monotonic() > deadline:
                raise FlashFailure(
                    f"Ueberschreitung der AuthentisierungZeit "
                    f"({window:.0f}s), status {status}")

    def totals(self):
        self._phase("totals")
        # "99" = grand total variant [C]; not gate-relevant, keep simple
        if self._gate == 2:
            self._job(DEV_VDLE, "REQUEST_SEGMENTINFO",
                      rvdle.segment_info_reply(*self._totals()))

    def _totals(self):
        start = min(s for s, _ in self.segments)
        size = sum(z for _, z in self.segments)
        return start, size

    def download(self):
        ph = self._phase("download")
        for seg, (start, size) in enumerate(self.segments):
            info = self._seginfo(str(seg))
            if info is None:
                raise FlashFailure(f"seginfo({seg}) failed")
            self._send_segment(seg, ph)
            self.report.segments_done = seg + 1

    def _seginfo(self, idx):
        if self._gate != 2:                  # [C] state gate, DF10 cascade
            self._job(DEV_VDLE, "REQUEST_SEGMENTINFO",
                      rvdle.REPLY_SEG_WRONGSTATE)
            return None
        if idx == "-1":                      # WAS variant [C]
            if self.state.segment == -1:
                self._job(DEV_VDLE, "REQUEST_SEGMENTINFO",
                          rvdle.REPLY_SEG_ILLEGAL_WAS)
                return None
            start, size = self.segments[self.state.segment]
            reply = self.state.was_info(start, size, self.bs)
        else:
            addr, size = self.segments[int(idx)]
            reply = rvdle.segment_info_reply(addr, size)
        self._keepalive()
        self._job(DEV_VDLE, "REQUEST_SEGMENTINFO", reply)
        return rvdle.parse_segment_info(reply)

    def _send_segment(self, seg, ph):
        """SEND_SEGMENT chunk loop [C FUN_004668b0] + measured recovery."""
        start, size = self.segments[seg]
        off0 = 4 + sum(s for _, s in self.segments[:seg])
        flash_job = (rvdle.JOB_FLASH_WRITE if self.bs <= rvdle.XXL_THRESHOLD
                     else rvdle.JOB_FLASH_WRITE_XXL)
        self.state.segment = -1              # cleared on loop entry [C]
        self.state.blocks_done = 0
        self.state.bias = 0                  # 2-arg fresh form: bias 0 [C]

        addr, n = next(rvdle.iter_flash_chunks(start, size, self.bs, 0))
        blk = 0
        while n:
            self._keepalive()                # before EVERY block [C]
            pos = self.bs * blk
            chunk = self.image[off0 + pos:off0 + pos + n]
            if not self._job_bin(DEV_ECU, flash_job, chunk):
                # [C] resume state saved ONLY on a failed FLASH job; the
                # block counter increments AFTER a successful status
                # poll, so blocks_done points AT the failed block
                self.state.segment = seg
                self.state.blocks_done = blk
                # [C] FUN_00466740(0,1): the failure report goes through
                # the wrapper FIRST — its latch drops the state gate
                # before the IPO sees anything
                self._job(DEV_VDLE, "SEND_SEGMENT", rvdle.REPLY_SEND_JOB_FAIL)
                self.report.was_attempted = True
                return self._recover(seg, ph)
            if not self._poll_status_end():
                return
            self.report.blocks_written += 1
            self.report.bytes_written += n
            blk += 1
            try:
                addr, n = next(rvdle.iter_flash_chunks(
                    start, size, self.bs, blk))
            except StopIteration:
                n = 0
        self._job(DEV_VDLE, "SEND_SEGMENT", rvdle.REPLY_SEND_OK)

    def _poll_status_end(self):
        for _ in range(self.poll_limit):
            v = self.bus.read_binary("FLASH_SCHREIBEN_STATUS")
            if v == b"\x01" or self.bus.read_text(
                    "FLASH_SCHREIBEN_STATUS", "") == "1":
                return True
        self._job(DEV_VDLE, "SEND_SEGMENT",
                  rvdle.REPLY_SEND_STATUS_FAIL)
        return False

    def _recover(self, seg, ph):
        """The IPO WAS block verbatim (DF10) + the measured restart
        fallback (DF11): after ANY reported failure the state gate is
        down, so re-INIT and resend the whole segment from block 0."""
        was = self._seginfo("-1")            # WAS query (IPO step 1)
        if was is not None:
            self._send_resume(seg, ph)       # gate survived → resume
            return
        # measured cascade: the WAS query error itself keeps the gate
        # down → restart the session like an operator would [C DF11]
        self.report.restarted = True
        self._init_vdle()                    # rev 16: arms the gate only
        self._send_segment(seg, ph)          # on a successful INIT_VDLE

    def _send_resume(self, seg, ph):
        blk = self.state.resume_block()
        start, size = self.segments[seg]
        off0 = 4 + sum(s for _, s in self.segments[:seg])
        flash_job = (rvdle.JOB_FLASH_WRITE if self.bs <= rvdle.XXL_THRESHOLD
                     else rvdle.JOB_FLASH_WRITE_XXL)
        for addr, n in rvdle.iter_flash_chunks(start, size, self.bs, blk):
            self._keepalive()
            pos = self.bs * self.state.blocks_done
            chunk = self.image[off0 + pos:off0 + pos + n]
            if not self._job_bin(DEV_ECU, flash_job, chunk):
                raise FlashFailure("resume FLASH job failed again")
            if not self._poll_status_end():
                raise FlashFailure("resume status poll failed")
            self.report.blocks_written += 1
            self.report.bytes_written += n
            self.state.blocks_done += 1
        self._job(DEV_VDLE, "SEND_SEGMENT", rvdle.REPLY_SEND_OK)

    def verify_signature(self):
        self._phase("signature")

        def read_result():
            return self.bus.read_text(rvdle.SIG_RESULT_NAME, "")

        def fire(_, __):
            return self.bus.job(DEV_ECU, "NG_SIGNATUR_PRUEFEN", "")

        ok = rvdle.verify_image_signature(fire, read_result,
                                          poll_timeout_s=self.poll_limit)
        self.report.signature_ok = ok
        return ok

    def finish(self):
        self._phase("finish")
        self._job(DEV_VDLE, "EXIT_VDLE", "OKAY")

    # -- entry --------------------------------------------------------------
    def flash(self):
        self.check_safety("flash()")           # rev 11 hard gate: raises
        try:
            self.setup()
            self.authenticate()
            self.check_safety("before download()")
            self.totals()
            self.download()
            if not self.verify_signature():
                raise FlashFailure("signature check failed")
            self.finish()
            self.report.ok = True
        except FlashFailure as e:
            self.report.error = str(e)
            try:
                self.finish()
            except Exception:
                pass
        except tester_present.SessionLost:
            self.report.error = "tester-present session lost"
        except RuntimeError as e:
            # transport-level failure (e.g. EdiabasError from the
            # apiState contract, rev 16): abort, best-effort EXIT_VDLE.
            # SessionLost (also a RuntimeError) is matched above.
            self.report.error = f"transport failure: {e}"
            try:
                self.finish()
            except Exception:
                pass
        return self.report


# ---------------------------------------------------------------------------
# Self-test mock bus (same semantics as vdle_diff.EdiabasSim, standalone)
# ---------------------------------------------------------------------------
class MockBus:
    """Minimal EDIABAS-side mock: OKAY everything; optional scripted
    failures for the FLASH job, the auth JOB_STATUS sequence and the
    signature poll sequence."""

    def __init__(self, flash_fail_on_call=0, sig_seq=None,
                 serial=b"WK93", seed=bytes.fromhex("0102030405060708"),
                 auth_status="OKAY", auth_results=None,
                 ident="GKE192", auth_offer="T_SMB",
                 auth_job_ok=True, fail_job=None):
        self.flash_calls = 0
        self.flash_fail_on_call = flash_fail_on_call
        self.sig_seq = list(sig_seq or [])
        self.serial = serial
        self.seed = seed
        self.auth_status = auth_status
        self.auth_results = list(auth_results or [])
        self.auth_status_now = None  # rev 17: EDIABAS-faithful — the
        #                            # job SETS the result, reads are
        #                            # idempotent until the next job
        self.ident = ident
        self.auth_offer = auth_offer
        self.auth_job_ok = auth_job_ok   # False models the REAL bus:
        self.auth_calls = 0              # non-OKAY status -> job False
        self.fail_job = fail_job         # rev 16: this TEXT job returns
        self.jobs = []                   # False (ECU-side refusal)

    def job(self, dev, name, args=""):
        self.jobs.append((dev, name, args))
        return name != self.fail_job

    def job_bin(self, dev, name, data):
        self.jobs.append((dev, name, data))
        self.flash_calls += 1
        if name == "NG_AUTHENTISIERUNG_START":
            self.auth_calls += 1
            self.auth_status_now = (self.auth_results.pop(0)
                                    if self.auth_results
                                    else self.auth_status)
            return self.auth_job_ok   # real EDIABAS returns False for
            #                      # ERROR_* statuses (rev 15 semantics)
        return self.flash_calls != self.flash_fail_on_call

    def read_text(self, name, default=""):
        if name == rvdle.SIG_RESULT_NAME:
            # each poll sees the ECU's progress → pop the scripted token
            return self.sig_seq.pop(0) if self.sig_seq else default
        if name == "FLASH_SCHREIBEN_STATUS":
            return "1"
        if name == "SG_PHYS_HWNR":
            return self.ident
        if name == "AUTHENTISIERUNG":
            return self.auth_offer
        if name == "AuthentisierungZeit":
            return "10000"                  # IPO FLASH_ZEITEN_LESEN [ms]
        if name == "JOB_STATUS":
            # rev 17: idempotent — the result belongs to the LAST job
            # and survives any number of reads (real EDIABAS keeps it
            # until the next job; the old pop-per-read double-consumed
            # under LoggingBus, which reads the status for its event)
            if self.jobs and self.jobs[-1][1] == \
                    "NG_AUTHENTISIERUNG_START":
                return self.auth_status_now or self.auth_status
            return "OKAY"
        return default

    def read_binary(self, name):
        if name == "SERIENNUMMER":
            return self.serial
        if name == "ZUFALLSZAHL":
            return self.seed
        return b"\x01"


class _DualStore:
    """Self-test store: ECU 'DUAL1' lives in BOTH containers with
    DIFFERENT record classes — 16 B in sgidC (idx 3), a structurally
    valid 0x88 asym blob in sgidD (idx 4). Proves rev 12 negotiation
    pairs art → record instead of record → art."""

    def auth_blob(self, ecu, idx):
        if ecu == "DUAL1":
            if idx == 3:
                return b"\x11" * 16
            if idx == 4:
                return ((0x10).to_bytes(4, "big") + b"\x33" * 64
                        + (0x10).to_bytes(4, "big") + b"\x44" * 64)
        raise KeyError(f"{ecu}/{idx}")

    def sym_key16(self, ecu, idx):
        return self.auth_blob(ecu, idx)

    def simple_key8(self, ecu, idx):
        return self.auth_blob(ecu, idx)


def _selftest():
    from vdle_diff import build_vdle_file
    passed, failed = 0, []

    def check(name, cond):
        nonlocal passed
        if cond:
            passed += 1
            print(f"RUNNER OK   {name}")
        else:
            failed.append(name)
            print(f"RUNNER FAIL {name}")

    try:
        from .safety.hypotheses import Limits
    except (ImportError, ValueError):
        try:
            from reconstruction.safety.hypotheses import Limits
        except (ImportError, ValueError):
            from safety.hypotheses import Limits

    def safety(bus=None, battery=13.2):
        """Default interlock: provenance-bearing limits + live state.
        Rev 12: Limits.for_testing is the explicitly labelled test
        factory — a bare Limits(...) is gate-refused."""
        state = {"battery_v": battery, "ignition_on": True,
                 "programming_voltage_enabled": True,
                 "zb_number_matches": True}

        def flip_after_first_check(k, v):
            """State that turns bad after the first validate() — proves
            the gate re-runs before download()."""
            seen = []

            def read(name):
                if name == k and seen:
                    return v
                if name == k:
                    seen.append(1)
                    return state[name]
                return state[name]
            return read

        return SafetyContext(
            limits=Limits.for_testing(battery_v_range=(11.5, 14.5)),
            read_state=state.get), flip_after_first_check

    image = build_vdle_file([(0x00870000, 0x18)], fill_from=0x40)
    safe, flip = safety()

    # ---- rev 11: safety hard gate --------------------------------------
    bus = MockBus(sig_seq=["OKAY"])
    refused = False
    try:
        FlashRunner(bus, image, blocksize=8, safety=None,
                    auth=False).flash()
    except FlashFailure as e:
        refused = "SafetyContext" in str(e)
    check("safety hard gate: flash refused without SafetyContext",
          refused and not bus.jobs)

    bus = MockBus(sig_seq=["OKAY"])
    refused = False
    try:
        bad = SafetyContext(
            limits=safe.limits,
            read_state={"battery_v": 9.1, "ignition_on": True,
                        "programming_voltage_enabled": True,
                        "zb_number_matches": True}.get)
        FlashRunner(bus, image, blocksize=8, safety=bad,
                    auth=False).flash()
    except FlashFailure as e:
        refused = "safety gate" in str(e) and "battery" in str(e)
    check("safety hard gate: out-of-range battery refuses",
          refused and not bus.jobs)

    # rev 12: untraced limits — a bare Limits(...) with perfect fields
    # is still a refusal (provenance cannot be bypassed)
    bus = MockBus(sig_seq=["OKAY"])
    refused = False
    try:
        untraced = SafetyContext(
            limits=Limits(battery_v_range=(11.5, 14.5), ignition_on=True,
                          programming_voltage_enabled=True,
                          zb_number_must_match=True),
            read_state={"battery_v": 13.2, "ignition_on": True,
                        "programming_voltage_enabled": True,
                        "zb_number_matches": True}.get)
        FlashRunner(bus, image, blocksize=8, safety=untraced,
                    auth=False).flash()
    except FlashFailure as e:
        refused = "untraced provenance" in str(e)
    check("safety hard gate: bare Limits() refused (provenance)",
          refused and not bus.jobs)

    # happy path: 3 blocks + signature OK (auth off: download machinery)
    bus = MockBus(sig_seq=["ROUTINE_NOT_COMPLETE", "OKAY"])
    rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                      auth=False).flash()
    check("happy path completes", rep.ok and rep.signature_ok)
    check("happy path blocks", rep.blocks_written == 3
          and rep.bytes_written == 0x18)
    check("phases", [p.name for p in rep.phases] ==
          ["setup", "totals", "download", "signature", "finish"])
    check("EXIT_VDLE sent", any(j == ("VDLE", "EXIT_VDLE", "OKAY")
                                for j in bus.jobs))

    # rev 16: a failed INIT_VDLE must NOT arm the state gate — no
    # REQUEST_SEGMENTINFO / SEND_SEGMENT / FLASH job may follow on a
    # dead session (review 15's P0: gate was armed unconditionally)
    bus = MockBus(sig_seq=["OKAY"], fail_job="INIT_VDLE")
    rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                      auth=False).flash()
    check("failed INIT_VDLE aborts; state gate stays down",
          not rep.ok and "INIT_VDLE" in (rep.error or "")
          and not any(j[1] in ("REQUEST_SEGMENTINFO", "SEND_SEGMENT")
                      for j in bus.jobs if j[0] == DEV_VDLE)
          and not any(isinstance(j[2], bytes) for j in bus.jobs))

    # refused flash parameters abort BEFORE any session is opened
    bus = MockBus(sig_seq=["OKAY"], fail_job="FLASH_PARAMETER_SETZEN")
    rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                      auth=False).flash()
    check("failed FLASH_PARAMETER_SETZEN aborts before INIT_VDLE",
          not rep.ok and "FLASH_PARAMETER_SETZEN" in (rep.error or "")
          and not any(j[1] == "INIT_VDLE" for j in bus.jobs))

    # gate re-validated before download(): battery drops mid-session
    _, flip = safety()
    ctx_flip = SafetyContext(limits=safe.limits,
                             read_state=flip("battery_v", 9.0))
    bus = MockBus(sig_seq=["OKAY"])
    rep = FlashRunner(bus, image, blocksize=8, safety=ctx_flip,
                      auth=False).flash()
    check("safety re-checked before download()",
          not rep.ok and "download" in (rep.error or "")
          and not any(j[1].startswith("FLASH_SCHREIBEN")
                      for j in bus.jobs if len(j) == 3
                      and isinstance(j[2], bytes)))

    # failure at block 2 → WAS attempt (gate down) → restart → resend all
    bus = MockBus(flash_fail_on_call=2, sig_seq=["OKAY"])
    rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                      auth=False).flash()
    check("failure recovered via restart", rep.ok and rep.restarted)
    check("WAS attempted", rep.was_attempted)
    flash_calls = [j for j in bus.jobs if len(j) == 3
                   and isinstance(j[2], bytes)]
    check("resend after restart (b0,b1! + full b0,b1,b2)",
          len(flash_calls) == 5)
    check("restart summary sane", rep.segments_done == 1
          and rep.blocks_written >= 3)

    # signature failure aborts
    bus = MockBus(sig_seq=["ERROR_FLASH_SIGNATURE_CHECK"])
    rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                      auth=False).flash()
    check("signature failure aborts", not rep.ok and not rep.signature_ok)

    # ---- real-key Authentisierung phase ---------------------------------
    from reconstruction.as2_keys import As2KeyStore
    gdaten = (Path.home() /
              "Downloads/BMW/extracted/E60_daten/data/gdaten")
    if (gdaten / "SGIDC.as2").exists():
        store = As2KeyStore.from_paths({3: gdaten / "SGIDC.as2",
                                        4: gdaten / "SGIDD.as2"})

        # GKE192 (EGS mechatronic) Symmetrisch 16-byte container key
        bus = MockBus(sig_seq=["ROUTINE_NOT_COMPLETE", "OKAY"])
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        want = security.compute_security_key(
            bus.seed, bus.serial, store.sym_key16("GKE192", 3),
            nonce=b"ab3f")
        sent = [j[2] for j in bus.jobs
                if j[1] == "NG_AUTHENTISIERUNG_START"][0]
        check("auth phase runs with real GKE192 key16",
              rep.ok and rep.auth_ok and sent == want)
        check("auth phases logged",
              [p.name for p in rep.phases][:2] == ["setup", "auth"])
        check("seed read job uses container index",
              any(j == ("DLE08", "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN", "3;")
                  for j in bus.jobs))

        # HKL65 Simple 8-byte container key
        bus = MockBus(sig_seq=["OKAY"])
        cfg = AuthConfig(ecu_name="HKL65", key_index=3, art="Simple",
                         store=store)
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        want = security.compute_security_key_simple(
            bus.seed, store.simple_key8("HKL65", 3))
        sent = [j[2] for j in bus.jobs
                if j[1] == "NG_AUTHENTISIERUNG_START"][0]
        check("auth Simple with real HKL65 key8",
              rep.ok and rep.auth_ok and sent == want)

        # auth rejection retried 3x then aborts [C orchestrator]
        bus = MockBus(sig_seq=["OKAY"],
                      auth_status="ERROR_ERROR_AUTHENTICATION")
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        check("auth rejection retried 3x then aborts",
              not rep.ok and not rep.auth_ok
              and rep.auth_attempts == 3 and "AUTHENT" in (rep.error or ""))

        # rev 15: REAL-bus semantics — job_bin False + real JOB_STATUS.
        # ERROR_ERROR_AUTHENTICATION must stay a retryable auth error
        # (3 attempts), NOT collapse into NO_RESPONSE semantics.
        bus = MockBus(sig_seq=["OKAY"],
                      auth_status="ERROR_ERROR_AUTHENTICATION",
                      auth_job_ok=False)
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        check("real-bus auth: ERROR_AUTHENTICATION preserved (job False)",
              not rep.ok and not rep.auth_ok
              and rep.auth_attempts == 3
              and "ERROR_ERROR_AUTHENTICATION" in (rep.error or "")
              and bus.auth_calls == 3)
        check("per-attempt audit: full retry chain recorded (rev 17)",
              len(rep.auth_attempts_log) == 3
              and [r["attempt"] for r in rep.auth_attempts_log] == [1, 2, 3]
              and all(r["status"] == "ERROR_ERROR_AUTHENTICATION"
                      and r["ok"] is False and r["ecu"] == "GKE192"
                      and r["art"] == "Symetrisch" and r["idx"] == 3
                      and r["seed_hex"] and r["nonce_hex"] and r["key_hex"]
                      for r in rep.auth_attempts_log))

        # a NON-retryable status surfaces its TRUE value, not NO_RESPONSE
        bus = MockBus(sig_seq=["OKAY"],
                      auth_status="ERROR_SG_NOT_FLASHABLE",
                      auth_job_ok=False)
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        check("real-bus auth: non-retryable status surfaces true value",
              not rep.ok and rep.auth_attempts == 1
              and "ERROR_SG_NOT_FLASHABLE" in (rep.error or ""))

        # audit trail: report carries the computed key + nonce (hex)
        bus = MockBus(sig_seq=["OKAY"])
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        want = security.compute_security_key(
            bus.seed, bus.serial, store.sym_key16("GKE192", 3),
            nonce=b"ab3f")
        check("auth audit trail: key+nonce recorded in the report",
              rep.ok and rep.auth_key_hex == want.hex()
              and rep.auth_nonce_hex == b"ab3f".hex())

        # ---- rev 11: AUTO-NEGOTIATION ---------------------------------
        # default: identity → GKE192 record (16 B) → offered T_SMB wins
        bus = MockBus(sig_seq=["ROUTINE_NOT_COMPLETE", "OKAY"])
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=None, auth_nonce=b"ab3f").flash()
        want = security.compute_security_key(
            bus.seed, bus.serial, store.sym_key16("GKE192", 3),
            nonce=b"ab3f")
        sent = [j[2] for j in bus.jobs
                if j[1] == "NG_AUTHENTISIERUNG_START"][0]
        check("auto-negotiation derives GKE192/Symetrisch from the bus",
              rep.ok and rep.auth_ok and rep.auth_ecu == "GKE192"
              and rep.auth_art == "Symetrisch" and sent == want)
        check("negotiation queried identity and offer",
              any(j[1] == "SG_PHYS_HWNR_LESEN" for j in bus.jobs)
              and any(j[1] == "AUTHENTISIERUNG" for j in bus.jobs))

        # HKL65: ECU offers T_SMC first, record class 8 B → Simple
        bus = MockBus(sig_seq=["OKAY"], ident="HKL65",
                      auth_offer="T_SMA;T_SMC")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=None, auth_nonce=b"ab3f").flash()
        want = security.compute_security_key_simple(
            bus.seed, store.simple_key8("HKL65", 3))
        sent = [j[2] for j in bus.jobs
                if j[1] == "NG_AUTHENTISIERUNG_START"][0]
        check("auto-negotiation picks the offered+possible art (Simple)",
              rep.ok and rep.auth_ok and rep.auth_art == "Simple"
              and sent == want)

        # offer/container class mismatch → explicit failure
        bus = MockBus(sig_seq=["OKAY"], auth_offer="T_SMC")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=None).flash()
        check("auto-negotiation fails loudly on class mismatch",
              not rep.ok and not rep.auth_ok
              and "offers" in (rep.error or ""))

        # rev 12: ECU in BOTH containers, matching class only in sgidD —
        # art → record pairing must find idx 4 (the old record → art
        # order took idx 3 first and failed with "class mismatch")
        dual = _DualStore()
        orig_ds = discover_store
        try:
            globals()["discover_store"] = lambda: dual
            bus = MockBus(sig_seq=["OKAY"], ident="DUAL1",
                          auth_offer="T_SMA")
            rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                              auth=None, auth_nonce=b"ab3f").flash()
        finally:
            globals()["discover_store"] = orig_ds
        want = security.compute_security_key_asymmetric_as2(
            bus.seed, bus.serial, b"ab3f", dual.auth_blob("DUAL1", 4))
        sent = [j[2] for j in bus.jobs
                if j[1] == "NG_AUTHENTISIERUNG_START"][0]
        check("negotiation pairs art→record across containers (idx 4)",
              rep.ok and rep.auth_ok and rep.auth_art == "Asymetrisch"
              and any(j == ("DLE08", "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN",
                            "4;") for j in bus.jobs)
              and sent == want)

        # rev 12: no b"0000" fallback — asym without nonce is a hard error
        try:
            FlashRunner._compute_auth_key(
                None, AuthConfig(ecu_name="X", key_index=4,
                                 art="Asymetrisch"),
                bytes.fromhex("0102030405060708"), b"WK93")
            check("asym without nonce is a hard error (no placeholder)",
                  False)
        except FlashFailure:
            check("asym without nonce is a hard error (no placeholder)",
                  True)

        # retry semantics: ROUTINE_NOT_COMPLETE then OKAY, fresh seed
        bus = MockBus(sig_seq=["OKAY"],
                      auth_results=["ROUTINE_NOT_COMPLETE", "OKAY"])
        cfg = AuthConfig(ecu_name="GKE192", key_index=3,
                         art="Symetrisch", store=store, nonce=b"ab3f")
        rep = FlashRunner(bus, image, blocksize=8, safety=safe,
                          auth=cfg).flash()
        seeds = [j for j in bus.jobs
                 if j == ("DLE08", "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN", "3;")]
        check("auth retry: ROUTINE_NOT_COMPLETE → fresh seed → OKAY",
              rep.ok and rep.auth_ok and rep.auth_attempts == 2
              and len(seeds) == 2)
    else:
        print("RUNNER SKIP auth phase (sgid containers not found)")

    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_selftest())
