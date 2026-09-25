#!/usr/bin/env python3
"""Bench scenario — the hardware-validation experiment (rev 13–15).

The reviewer's single control experiment: run identity → auth → session
→ first segment info (→ full flash) against a REAL ECU and capture an
event log that can be diffed against the original WinKFP (bench_diff).

Two modes:
  contact (default)  WRITE-FREE / NO-FLASH first contact (review 13
                     terminology — NOT "read-only"). No flash-write
                     occurs; diagnostic/session/security state MAY
                     change (the ECU runs the auth/session handshake).
                     Flow: safety gate → ECU identity → auth
                     negotiation → auth handshake → INIT_VDLE →
                     REQUEST_SEGMENTINFO "0" → EXIT_VDLE. No
                     FLASH_PARAMETER_SETZEN, no SEND_SEGMENT, no
                     FLASH_SCHREIBEN. This is a CONTROLLED CONTACT
                     HARNESS — it re-uses the flash() phases in the
                     same order but is NOT a byte-exact replay of the
                     production orchestration (the state gate is armed
                     the same way setup() does it). A contact PASS
                     proves transport/auth/session INTEGRATION, not the
                     full flash choreography.
  full               the complete production FlashRunner.flash()
                     (FLASH_PARAMETER_SETZEN included) — requires the
                     explicit --yes-i-will-write consent flag.

Safety on the bench is NOT optional and NOT bypassable: the limits are
PARSED from a strict --limits file (BAT <lo> <hi> etc., rev 15 — the
digest provably covers the numbers). That file is the operator's
digest-bound POLICY, not BMW-validated per-ECU data — the real NFS
ID_CHECK.DAT is a different thing entirely (see safety/id_check.py) and
is NOT the source of these numbers. --battery-v is the operator's
MEASURED voltage. The --no-* flags only change the REPORTED state,
never the limits — they can make the gate fail, never pass.

Every boundary call is logged as JSONL with the REAL JOB_STATUS (rev
15), sha256 of payloads/results, and an auth_audit record. The
SG-Schluessel is a SECRET: by default the log carries only its sha256
+ length (payload event and audit alike) so bench logs stay shareable
artifacts; the raw key hex is written only with --include-secret-auth
(rev 16). API-level EDIABAS failures (apiState != APIREADY) surface as
an "error" event and abort the run — they are never misread as a stale
JOB_STATUS (rev 16, transport/ediabas_api failure contract).

--auth-off is a TEST capability: allowed on the mock bus and in the
write-free contact mode; HARD-REFUSED for --mode full on a real bus —
flashing without authentication is not an operator decision (rev 16).

Buses:
  --bus ediabas  real EDIABAS api32.dll (Windows; transport/ediabas_api)
  --bus mock     MockBus dry-run (any platform; selftest/CI)

    # Windows bench box, first contact:
    python bench_scenario.py --mode contact --bus ediabas \
        --dll C:/EDIABAS/Bin/api32.dll --image GKE192.bin \
        --limits egd limits.txt --battery-v 13.2
    # then compare with the original tool's trace:
    python bench_diff.py bench_log.jsonl api.trc --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reconstruction.runner import (
    DEV_VDLE, FlashFailure, FlashRunner, MockBus, SafetyContext
)
from reconstruction import tester_present
from reconstruction import vdle as rvdle
from reconstruction.safety import Limits
from reconstruction.transport.ediabas_api import EdiabasError, EdiabasUnavailable

_HEX_CAP = 64                 # seed 8 B, serial 4 B, SG-Schluessel 16/64 B
AUTH_JOB = "NG_AUTHENTISIERUNG_START"   # payload IS the derived secret


class LoggingBus:
    """Transparent bus wrapper recording every boundary call as one
    JSONL event — the artifact bench_diff consumes. Rev 15: job events
    carry the REAL JOB_STATUS read right after the call. Rev 16: (a)
    the SG-Schluessel payload of AUTH_JOB is REDACTED by default
    (sha256 + length only; raw hex needs include_secret) so the bench
    log is a shareable artifact; (b) an API-level failure of the inner
    bus (EdiabasError — apiState contract) is logged as an error event
    with NO status (there is none — reading results then would be a
    stale read) and re-raised; (c) real_hw propagates from the inner
    bus so run_full can enforce the auth boundary."""

    def __init__(self, inner, log_path: str, include_secret: bool = False):
        self.inner = inner
        self.log_path = Path(log_path)
        self.include_secret = include_secret
        self.real_hw = getattr(inner, "IS_REAL_HW", False)
        self.t0 = time.monotonic()
        self.events = []

    def _rec(self, ev):
        ev = {"t": round(time.monotonic() - self.t0, 4), **ev}
        self.events.append(ev)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def _status(self):
        # read via the inner bus: the status belongs to the job event,
        # not a separate read event
        return self.inner.read_text("JOB_STATUS", "")

    def job(self, dev, name, args=""):
        try:
            ok = self.inner.job(dev, name, args)
        except EdiabasError as e:
            self._rec({"op": "job", "dev": dev, "name": name,
                       "args": str(args), "ok": False, "status": None,
                       "error": str(e)})
            raise
        self._rec({"op": "job", "dev": dev, "name": name,
                   "args": str(args), "ok": ok,
                   "status": self._status()})
        return ok

    def job_bin(self, dev, name, data):
        try:
            ok = self.inner.job_bin(dev, name, data)
        except EdiabasError as e:
            self._rec({"op": "job_bin", "dev": dev, "name": name,
                       "bytes": len(data), "ok": False, "status": None,
                       "error": str(e)})
            raise
        rec = {"op": "job_bin", "dev": dev, "name": name,
               "bytes": len(data),
               "sha": hashlib.sha256(data).hexdigest()}
        if name == AUTH_JOB and not self.include_secret:
            rec["redacted"] = True       # the payload IS the key (rev 16)
        elif len(data) <= _HEX_CAP:
            rec["hex"] = data.hex()
        rec.update({"ok": ok, "status": self._status()})
        self._rec(rec)
        return ok

    def read_text(self, name, default=""):
        v = self.inner.read_text(name, default)
        self._rec({"op": "read_text", "name": name, "value": str(v)})
        return v

    def read_binary(self, name):
        v = self.inner.read_binary(name)
        self._rec({"op": "read_binary", "name": name, "bytes": len(v),
                   **({"hex": v.hex()} if 0 < len(v) <= _HEX_CAP else {})})
        return v

    def close(self):
        """rev 18.1 lifecycle passthrough: main() closes the adapter in
        a finally, so repeated in-process runs don't leak the EDIABAS
        application handle (P2 of review 18; mock buses without
        close() are simply tolerated)."""
        closer = getattr(self.inner, "close", None)
        if callable(closer):
            closer()

    def auth_audit(self, rep):
        """Persist the runner's PER-ATTEMPT auth computation (rev 17):
        one record per NG_AUTHENTISIERUNG_START try — its own seed,
        nonce, status and key witness — so bench_diff --verify proves
        the WHOLE retry chain offline, not only the winning attempt.
        The key stays sha256-only unless include_secret (rev 16).
        Runs where auth never fired (skipped/off) get one marker
        record without key evidence."""
        if not rep.auth_attempts_log:
            self._rec({"op": "auth_audit", "ecu": rep.auth_ecu,
                       "art": rep.auth_art, "attempts": 0,
                       "ok": rep.auth_ok, "note": rep.auth_note
                       or "auth disabled/skipped"})
            return
        for r in rep.auth_attempts_log:
            key = bytes.fromhex(r["key_hex"])
            rec = {"op": "auth_audit", "attempt": r["attempt"],
                   "ecu": r["ecu"], "art": r["art"], "idx": r["idx"],
                   "seed_hex": r["seed_hex"], "nonce_hex": r["nonce_hex"],
                   "status": r["status"], "ok": r["ok"],
                   "key_len": len(key),
                   "key_sha256": hashlib.sha256(key).hexdigest()}
            if self.include_secret:
                rec["key_hex"] = r["key_hex"]
            self._rec(rec)


def build_safety(battery_v: float, limits_path, ecu_family: str,
                 ecu_part: str, *, ignition_on: bool = True,
                 prog_voltage: bool = True, zb_match: bool = True
                 ) -> SafetyContext:
    """Bench interlock: limits are PARSED from the strict operator
    policy file (rev 15 — digest covers the numbers; the file is the
    operator's POLICY, not BMW-validated per-ECU data); the operator
    supplies only the measured state, and the --no-* flags alter the
    state side alone, so they can never make an unsatisfied interlock
    pass."""
    if limits_path is None:
        raise FlashFailure(
            "bench: --limits is mandatory — the safety gate needs "
            "parsed, digest-bound limits (Limits.from_limits_file), "
            "not operator-typed numbers")
    return SafetyContext(
        limits=Limits.from_limits_file(Path(limits_path), ecu_family,
                                       ecu_part),
        read_state={"battery_v": battery_v, "ignition_on": ignition_on,
                    "programming_voltage_enabled": prog_voltage,
                    "zb_number_matches": zb_match}.get)


def run_contact(bus, image: bytes, safety: SafetyContext, *,
                auth="auto", auth_nonce=None, blocksize: int = 8):
    """Controlled contact harness (review 13) — write-free/no-flash
    first contact. No flash-write occurs; diagnostic/session/security
    state may change. Deliberately NOT a byte-exact replay of flash():
    the harness drives the flash() phases in the same order but arms
    the INIT_VDLE state gate itself (exactly the value setup() sets in
    the production path) and stops before any segment write.
    rev 18: report-oriented like flash() — an in-run failure (auth
    exhausted, transport error) lands in report.error and the report
    is RETURNED, so main() always writes the per-attempt auth_audit.
    The failure case is the forensically valuable one: without this,
    a 3x ERROR_AUTHENTICATION contact produced seed/payload events but
    NO audit witnesses. check_safety refusals still propagate (a
    refusal is not a run)."""
    runner = FlashRunner(bus, image, blocksize=blocksize,
                         flash_parameter=None, auth=auth,
                         auth_nonce=auth_nonce, safety=safety)
    runner.check_safety("bench contact")     # same hard gate as flash()

    def _exit_best_effort():
        try:
            runner._phase("finish")
            runner._job(DEV_VDLE, "EXIT_VDLE", "OKAY")
        except Exception:
            pass

    try:
        runner._phase("setup")
        runner._init_vdle()                  # rev 16: arms the state
        a = runner.authenticate()            # gate ONLY on success
        runner.totals()                      # REQUEST_SEGMENTINFO "99"
        seg0 = runner._seginfo("0")          # first real segment info
        runner._phase("finish")
        runner._job(DEV_VDLE, "EXIT_VDLE", "OKAY")
        runner.report.ok = bool(a and seg0 is not None)
    except FlashFailure as e:
        runner.report.error = str(e)
        _exit_best_effort()
    except tester_present.SessionLost:
        runner.report.error = "tester-present session lost"
        _exit_best_effort()
    except RuntimeError as e:
        # transport failure (EdiabasError apiState contract, rev 16)
        runner.report.error = f"transport failure: {e}"
        _exit_best_effort()
    return runner.report


def run_full(bus, image: bytes, safety: SafetyContext, *,
             auth="auto", auth_nonce=None, flash_parameter=None):
    """The complete production flash(). flash_parameter=None means
    FlashRunner's own IPO default (FLASH_PARAMETER_SETZEN IS sent) —
    rev 15: full mode must not silently diverge from production.
    rev 16: auth=False on a REAL-hardware bus is a HARD refusal —
    flashing without authentication is not an operator decision
    (mock buses keep the test capability)."""
    if auth is False and getattr(bus, "real_hw", False):
        raise FlashFailure(
            "full flash with auth DISABLED on real hardware: refused "
            "(rev 16 safety boundary — --auth-off is a mock/contact "
            "test capability only)")
    kwargs = {} if flash_parameter is None else \
        {"flash_parameter": flash_parameter}
    return FlashRunner(bus, image, auth=auth, auth_nonce=auth_nonce,
                       safety=safety, **kwargs).flash()


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Bench scenario: reconstruction vs real ECU "
                    "(contact = write-free/no-flash default)")
    ap.add_argument("--mode", choices=["contact", "full"],
                    default="contact")
    ap.add_argument("--bus", choices=["ediabas", "mock"],
                    default="ediabas")
    ap.add_argument("--dll", default=None, help="path to api32.dll")
    ap.add_argument("--trace", action="store_true",
                    help="enable the EDIABAS api trace (fails loudly "
                         "if the DLL has no __apiTrace export)")
    ap.add_argument("--image", default=None,
                    help="flash/calibration image (.bin)")
    ap.add_argument("--limits", default=None, required=True,
                    help="strict limits file: 'BAT <lo> <hi>' + "
                         "IGNITION/PROGVOLTAGE/ZB ON|OFF lines")
    ap.add_argument("--ecu-family", default="UNKNOWN")
    ap.add_argument("--ecu-part", default="UNKNOWN")
    ap.add_argument("--battery-v", type=float, required=True,
                    help="MEASURED now, from the PSU display")
    ap.add_argument("--no-ignition", action="store_true",
                    help="reported STATE only — limits come from the "
                         "file; this can only fail the gate, not pass")
    ap.add_argument("--no-prog-voltage", action="store_true",
                    help="reported STATE only (see --no-ignition)")
    ap.add_argument("--no-zb-match", action="store_true",
                    help="reported STATE only (see --no-ignition)")
    ap.add_argument("--flash-parameter", default=None,
                    help="override the IPO default (full mode only)")
    ap.add_argument("--auth-off", action="store_true",
                    help="test capability: skip the auth handshake — "
                         "mock bus / write-free contact only; HARD "
                         "refused for --mode full on the real bus")
    ap.add_argument("--include-secret-auth", action="store_true",
                    help="log the RAW SG-Schluessel hex (auth_audit "
                         "key_hex + payload hex); default records "
                         "sha256 only — bench logs stay shareable")
    ap.add_argument("--yes-i-will-write", action="store_true")
    ap.add_argument("--log", default="bench_log.jsonl")
    args = ap.parse_args(argv)

    if args.mode == "full" and not args.yes_i_will_write:
        print("REFUSED: --mode full needs --yes-i-will-write "
              "(this writes to the ECU flash)", file=sys.stderr)
        return 2

    # rev 16: no unauthenticated FLASH WRITES on real hardware, ever —
    # consent + safety gate do not make --auth-off acceptable here
    if args.auth_off and args.mode == "full" and args.bus == "ediabas":
        print("REFUSED: --auth-off cannot be combined with --mode full "
              "on the real bus — authentication is mandatory before "
              "any flash write (rev 16)", file=sys.stderr)
        return 2
    if args.auth_off and args.bus == "ediabas":
        print("WARNING: contact without the auth handshake on REAL "
              "hardware (allowed: contact is write-free)", file=sys.stderr)

    log = Path(args.log)
    if log.exists():
        log.unlink()
    auth = False if args.auth_off else "auto"
    bus = None

    # rev 18: ONE error boundary around the whole preflight + run —
    # parse → validate → load image → build safety → open adapter →
    # run. Nothing before the adapter may abort with a traceback
    # (missing --image = OSError, bad limits = ValueError, adapter
    # failures = EdiabasError/EdiabasUnavailable); everything prints
    # BENCH FAILED with the real message and exits 1.
    try:
        if args.image:
            image = Path(args.image).read_bytes()
        elif args.bus == "mock":
            from vdle_diff import build_vdle_file
            image = build_vdle_file([(0x00870000, 0x18)], fill_from=0x40)
        else:
            # validated BEFORE the DLL is opened — no point touching
            # the adapter if the run cannot happen anyway
            print("REFUSED: --image is required on the real bus",
                  file=sys.stderr)
            return 2

        safety = build_safety(args.battery_v, args.limits,
                              args.ecu_family, args.ecu_part,
                              ignition_on=not args.no_ignition,
                              prog_voltage=not args.no_prog_voltage,
                              zb_match=not args.no_zb_match)

        if args.bus == "ediabas":
            from transport.ediabas_api import EdiabasApiBus
            inner = EdiabasApiBus.open(args.dll, trace=args.trace)
        else:
            inner = MockBus(sig_seq=["OKAY"])
            inner.IS_REAL_HW = False
        bus = LoggingBus(inner, log, include_secret=args.include_secret_auth)

        if args.mode == "contact":
            rep = run_contact(bus, image, safety, auth=auth)
            print("bench contact (write-free/no-flash, "
                  "controlled harness) "
                  + ("OK" if rep.ok else "INCOMPLETE")
                  + (f": authentisierung "
                     f"{'OK' if rep.auth_ok else 'NOK'}"
                     + (f" ({rep.auth_ecu}, {rep.auth_art}, "
                        f"attempts {rep.auth_attempts})"
                        if rep.auth_ecu else
                        f" ({rep.auth_note})" if rep.auth_note else "")))
            if not rep.ok and rep.error:
                print(f"contact error: {rep.error}", file=sys.stderr)
        else:
            rep = run_full(bus, image, safety, auth=auth,
                           flash_parameter=args.flash_parameter)
            print(rep.summary())
            if not rep.ok and rep.error:
                print(f"flash error: {rep.error}", file=sys.stderr)
        bus.auth_audit(rep)
    except (FlashFailure, EdiabasError, EdiabasUnavailable,
            OSError, ValueError) as e:
        print(f"BENCH FAILED: {e}", file=sys.stderr)
        print(f"event log: {log}", file=sys.stderr)
        return 1
    finally:
        # rev 18.1 (review 18 P2): the adapter handle is released on
        # BOTH exit paths — successful one-shot CLI processes were
        # fine, but repeated main() calls in one Python process leaked
        # the EDIABAS application handle
        if bus is not None:
            bus.close()
    print(f"event log: {log} ({len(bus.events)} events)")
    return 0 if rep.ok else 1


# ---------------------------------------------------------------------------
def _selftest():
    import tempfile

    from vdle_diff import build_vdle_file

    passed, failed = 0, []

    def check(name, cond):
        nonlocal passed
        if cond:
            passed += 1
            print(f"BENCH OK   {name}")
        else:
            failed.append(name)
            print(f"BENCH FAIL {name}")

    image = build_vdle_file([(0x00870000, 0x18)], fill_from=0x40)

    with tempfile.TemporaryDirectory() as td:
        lim = Path(td) / "limits.txt"
        lim.write_text("# bench limits v1\nBAT 11.5 14.8\n"
                       "IGNITION ON\nPROGVOLTAGE ON\nZB ON\n")
        safety = build_safety(13.2, lim, "EGS", "24 60 8 521 023")

        # ---- write-free/no-flash contact ---------------------------
        logf = Path(td) / "contact.jsonl"
        bus = LoggingBus(MockBus(sig_seq=["OKAY"]), logf)
        rep = run_contact(bus, image, safety)
        bus.auth_audit(rep)
        jobs = [e for e in bus.events if e["op"] in ("job", "job_bin")]
        names = [e["name"] for e in jobs]
        bins = [e["name"] for e in jobs if e["op"] == "job_bin"]
        check("contact completes", rep.ok)
        check("contact: identity + auth + session + seginfo + exit",
              {"SG_PHYS_HWNR_LESEN", "AUTHENTISIERUNG", "INIT_VDLE",
               "REQUEST_SEGMENTINFO", "EXIT_VDLE",
               "NG_AUTHENTISIERUNG_START"} <= set(names))
        check("contact: ONLY auth job is binary (no flash writes)",
              bins == ["NG_AUTHENTISIERUNG_START"])
        check("contact: no FLASH_PARAMETER / SEND_SEGMENT / SCHREIBEN",
              not [n for n in names if "FLASH_PARAMETER" in n
                   or "SEND_SEGMENT" in n or "FLASH_SCHREIBEN" in n])
        events = [json.loads(l) for l in logf.read_text().splitlines()]
        check("JSONL event log parses and covers every call",
              len(events) == len(bus.events) and events[0]["op"] == "job")
        check("job events carry the REAL JOB_STATUS (rev 15)",
              all(e.get("status") == "OKAY"
                  for e in events if e["op"] in ("job", "job_bin")))
        bin_ev = [e for e in events if e["op"] == "job_bin"]
        check("job_bin event: sha256 always; SG-Schluessel hex REDACTED "
              "by default (rev 16)",
              len(bin_ev) == 1 and len(bin_ev[0]["sha"]) == 64
              and "hex" not in bin_ev[0]
              and bin_ev[0].get("redacted") is True
              and bin_ev[0]["bytes"] == len(bytes.fromhex(rep.auth_key_hex)))
        seed_ev = [e for e in events if e["op"] == "read_binary"
                   and e["name"] == "ZUFALLSZAHL"]
        check("small binary results carry hex (seed auditable)",
              seed_ev and bytes.fromhex(seed_ev[0]["hex"])
              and seed_ev[0]["bytes"] == 8)
        audit = [e for e in events if e["op"] == "auth_audit"]
        check("auth_audit: PER-ATTEMPT record (rev 17), key sha256+len+"
              "nonce+seed+status, no raw key",
              len(audit) == 1
              and audit[0]["attempt"] == 1 and audit[0]["idx"] == 3
              and audit[0]["status"] == "OKAY" and audit[0]["ok"] is True
              and audit[0]["seed_hex"]
              and audit[0]["key_sha256"] == hashlib.sha256(
                  bytes.fromhex(rep.auth_key_hex)).hexdigest()
              and audit[0]["key_len"] == len(bytes.fromhex(rep.auth_key_hex))
              and audit[0]["nonce_hex"] and "key_hex" not in audit[0])

        # --include-secret-auth: raw key hex IS logged (operator asked)
        logs = Path(td) / "secret.jsonl"
        sbus = LoggingBus(MockBus(sig_seq=["OKAY"]), logs,
                          include_secret=True)
        srep = run_contact(sbus, image, safety)
        sbus.auth_audit(srep)
        sev = [json.loads(l) for l in logs.read_text().splitlines()]
        check("--include-secret-auth logs the raw key (payload + audit)",
              any(e["op"] == "job_bin" and e["name"] == AUTH_JOB
                  and e.get("hex") == srep.auth_key_hex for e in sev)
              and any(e["op"] == "auth_audit"
                      and e.get("key_hex") == srep.auth_key_hex
                      for e in sev))

        # API-level failure of the inner bus: logged with error and NO
        # status (reading one would be a stale read); rev 18: the
        # contact RETURNS a failed report (error boundary inside
        # run_contact) instead of raising past the audit
        class _ApiFailBus(MockBus):
            def job(self, dev, name, args=""):
                raise EdiabasError(
                    "apiJob VDLE/INIT_VDLE: API-level failure, "
                    "apiState=3 APIERROR, apiErrorCode=7: IFH error")

        apilog = Path(td) / "apierr.jsonl"
        arep = run_contact(LoggingBus(_ApiFailBus(), apilog), image, safety)
        aev = [json.loads(l) for l in apilog.read_text().splitlines()]
        errv = [e for e in aev if e.get("op") == "job" and e.get("error")]
        check("API-level failure: error event, no stale status, "
              "report carries the failure",
              not arep.ok and "APIERROR" in (arep.error or "")
              and errv and errv[0]["ok"] is False
              and errv[0]["status"] is None
              and "APIERROR" in errv[0]["error"])

        # rev 18 — the reviewer's asymmetry: a FAILED contact must keep
        # its per-attempt auth audit (3x ERROR_AUTHENTICATION). The
        # chain stays cryptographically verifiable: the log alone can
        # PROVE our computation was self-consistent and the refusal
        # came from the ECU side.
        failog = Path(td) / "authfail.jsonl"
        fbus = LoggingBus(MockBus(sig_seq=["OKAY"],
                                  auth_status="ERROR_ERROR_AUTHENTICATION",
                                  auth_job_ok=False), failog)
        frep = run_contact(fbus, image, safety)
        fbus.auth_audit(frep)            # exactly what main() now does
        fraw = [json.loads(l) for l in failog.read_text().splitlines()]
        faud = [e for e in fraw if e.get("op") == "auth_audit"]
        from bench_diff import verify_auth
        vok, note = verify_auth(fraw)
        check(f"FAILED contact keeps the FULL per-attempt audit ({note})",
              not frep.ok and frep.auth_attempts == 3
              and len(faud) == 3
              and all(a["status"] == "ERROR_ERROR_AUTHENTICATION"
                      and a["ok"] is False and a["attempt"] == i + 1
                      for i, a in enumerate(faud))
              and vok)

        # rev 16 boundary: auth-off + real hardware + full = HARD refuse
        class _RealMock(MockBus):
            IS_REAL_HW = True
        refused = False
        try:
            run_full(LoggingBus(_RealMock(), Path(td) / "rf.jsonl"),
                     image, safety, auth=False)
        except FlashFailure as e:
            refused = "auth" in str(e) and "real hardware" in str(e)
        check("run_full refuses auth-off on a real-hw bus", refused)

        # ---- limits provenance is parsed, not typed -----------------
        try:
            build_safety(13.2, None, "EGS", "x")
            check("bench refuses without --limits file", False)
        except FlashFailure:
            check("bench refuses without --limits file", True)
        bad = Path(td) / "bad_limits.txt"
        bad.write_text("BAT 11.5 14.8\nTYPED 42\n")
        try:
            build_safety(13.2, bad, "EGS", "x")
            check("unparsable limits line is a hard error", False)
        except ValueError:
            check("unparsable limits line is a hard error", True)
        nobat = Path(td) / "nobat.txt"
        nobat.write_text("IGNITION ON\n")
        try:
            build_safety(13.2, nobat, "EGS", "x")
            check("limits file without BAT refused", False)
        except ValueError:
            check("limits file without BAT refused", True)

        # --no-* flags can only fail the gate, never pass it
        try:
            run_contact(LoggingBus(MockBus(), Path(td) / "x.jsonl"),
                        image, build_safety(13.2, lim, "EGS", "x",
                                            ignition_on=False))
            check("state flag against file limits fails the gate", False)
        except FlashFailure as e:
            check("state flag against file limits fails the gate",
                  "ignition" in str(e))

        # ---- full mode consent gate (CLI level) --------------------
        check("CLI refuses full mode without consent",
              main(["--mode", "full", "--bus", "mock", "--limits",
                    str(lim), "--battery-v", "13.2",
                    "--log", str(Path(td) / "no.jsonl")]) == 2)
        check("CLI refuses --auth-off + real bus + full (rev 16)",
              main(["--mode", "full", "--bus", "ediabas", "--auth-off",
                    "--yes-i-will-write", "--limits", str(lim),
                    "--battery-v", "13.2",
                    "--log", str(Path(td) / "no2.jsonl")]) == 2)
        # rev 17: adapter-construction failure is a guarded BENCH
        # FAILED (exit 1) with a usable message — never a traceback
        if sys.platform != "win32":
            import io
            import contextlib
            imgf = Path(td) / "img.bin"
            imgf.write_bytes(image)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = main(["--mode", "contact", "--bus", "ediabas",
                           "--image", str(imgf),
                           "--limits", str(lim), "--battery-v", "13.2",
                           "--log", str(Path(td) / "no3.jsonl")])
            check("CLI: api32 unavailable -> BENCH FAILED, no traceback",
                  rc == 1 and "BENCH FAILED" in err.getvalue()
                  and "mock" in err.getvalue())

        # rev 18: the WHOLE preflight is inside the error boundary —
        # missing image, unparsable limits and a malformed image are
        # BENCH FAILED (exit 1), never a Python traceback
        import io
        import contextlib

        def cli_stderr(argv):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = main(argv)
            return rc, buf.getvalue()

        rc, out = cli_stderr(
            ["--mode", "contact", "--bus", "mock",
             "--image", str(Path(td) / "missing.bin"),
             "--limits", str(lim), "--battery-v", "13.2",
             "--log", str(Path(td) / "no4.jsonl")])
        check("CLI: missing --image -> BENCH FAILED, no traceback",
              rc == 1 and "BENCH FAILED" in out)

        garbage = Path(td) / "garbage.txt"
        garbage.write_text("NOT A LIMITS FILE\n")
        rc, out = cli_stderr(
            ["--mode", "contact", "--bus", "mock",
             "--limits", str(garbage), "--battery-v", "13.2",
             "--log", str(Path(td) / "no5.jsonl")])
        check("CLI: unparsable --limits -> BENCH FAILED, no traceback",
              rc == 1 and "BENCH FAILED" in out
              and "unparsable" in out)

        junk = Path(td) / "junk.bin"
        junk.write_bytes(b"\x01\x02")
        rc, out = cli_stderr(
            ["--mode", "contact", "--bus", "mock", "--image", str(junk),
             "--limits", str(lim), "--battery-v", "13.2",
             "--log", str(Path(td) / "no6.jsonl")])
        check("CLI: malformed image -> BENCH FAILED, no traceback",
              rc == 1 and "BENCH FAILED" in out)

        # rev 18.1 (review 18 P2): lifecycle — main() closes the
        # adapter in a finally, so repeated in-process runs work
        class _ClosableMock(MockBus):
            def __init__(self):
                super().__init__(sig_seq=["OKAY"])
                self.closed = 0

            def close(self):
                self.closed += 1

        cm = _ClosableMock()
        lbc = LoggingBus(cm, Path(td) / "closable.jsonl")
        lbc.close()
        lbc.close()
        check("LoggingBus.close delegates to the inner adapter "
              "(idempotent use, mock without close tolerated)",
              cm.closed == 2
              and LoggingBus(MockBus(), Path(td) / "noclose.jsonl")
              .close() is None)
        rc1 = main(["--mode", "contact", "--bus", "mock",
                    "--limits", str(lim), "--battery-v", "13.2",
                    "--log", str(Path(td) / "twice.jsonl")])
        rc2 = main(["--mode", "contact", "--bus", "mock",
                    "--limits", str(lim), "--battery-v", "13.2",
                    "--log", str(Path(td) / "twice.jsonl")])
        check("CLI: second main() in the SAME process still succeeds "
              "(no handle/lifecycle leak)",
              rc1 == 0 and rc2 == 0)

        # ---- full mode (mock, auth off): PRODUCTION choreography ----
        rc = main(["--mode", "full", "--bus", "mock", "--auth-off",
                   "--yes-i-will-write", "--limits", str(lim),
                   "--battery-v", "13.2",
                   "--log", str(Path(td) / "full.jsonl")])
        full_events = [json.loads(l)
                       for l in (Path(td) / "full.jsonl").read_text()
                       .splitlines()]
        check("full mode (mock) flashes with consent",
              rc == 0 and any(e["name"].startswith("FLASH_SCHREIBEN")
                              for e in full_events
                              if e["op"] == "job_bin"))
        check("full mode sends FLASH_PARAMETER_SETZEN (production "
              "path, rev 15 latent-bug fix)",
              any(e["name"] == "FLASH_PARAMETER_SETZEN"
                  for e in full_events if e["op"] == "job"))

    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_selftest() if len(sys.argv) == 1 else main())
