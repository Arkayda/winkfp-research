#!/usr/bin/env python3
"""Bench event-log differential — ours vs the original tool.

Two verdict layers (review 13):
  L1 choreography    the (device, job) SEQUENCE — longest common prefix
  L2 semantics       per-event, over the common prefix: text args,
                     binary payload (length + sha256), JOB_STATUS

L2 is STRICT TRI-STATE (rev 16): a field present on ONE side only is a
MISMATCH. The old "compare when both sides carry a value" logic let a
missing side pass silently — ours "OKAY" vs reference None was "not a
mismatch" (review 15's false-negative class). Only both-sides-missing
is ignored (no evidence on either side).

Two input formats:
  *.jsonl   the LoggingBus event log of bench_scenario.py (ours)
  EDIABAS api trace (*.trc) — the format the EDIABAS api32 trace writes.
  A COMPLETE real flash session of the original tooling ships with the
  installation (TRACE/api.trc) and is the parser's ground truth [O]:
      Job
          "13_ASK"              <- ecu / device
          "FLASH_SCHREIBEN"     <- job name
          "NEIN;JA"             <- text args of apiJob (when present)
          54 bytes:             <- apiJobData payload
              000: 01 01 ...    <- hex dump, closed by the count line
          54
      Results:
          [ 0 ] ... JOBSTATUS = ""          <- ECU-side set
          [ 1 ] JOB_STATUS = "OKAY"         <- the set our adapter
                                               reads (RESULT_SET = 1)

Payload sha256 is meaningful for SAME-image comparisons (bench rerun);
diffing against a foreign reference image use --no-sha.

    python bench_diff.py bench_log.jsonl reference.trc
    python bench_diff.py bench_log.jsonl reference.trc --before FLASH_SCHREIBEN
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# event records: L1 = (dev, name); L2 = the full dict
# ---------------------------------------------------------------------------

# Payloads whose CONTENT legitimately differs between two correct runs:
# the auth key depends on the per-attempt seed (ECU) and nonce (fresh
# per attempt, FUN_00461800) — sha equality would be a FALSE FAIL.
# Length is still compared; the semantic check is verify_auth().
DYNAMIC_PAYLOAD_JOBS = {"NG_AUTHENTISIERUNG_START"}


def _ev(dev, name, args=None, nbytes=None, sha=None, status=None,
        hexdata=None):
    return {"dev": dev.upper(), "name": name.upper(),
            "args": None if args is None else str(args),
            "bytes": nbytes, "sha": sha, "status": status,
            "hex": hexdata}


def l1(events):
    """The choreography projection of L2 event records."""
    return [(e["dev"], e["name"]) for e in events]


# -- JSONL (ours) -------------------------------------------------------------


def load_jsonl(path: Path):
    """Job/job_bin events of a LoggingBus log as L2 records (args,
    payload length/sha/hex, REAL JOB_STATUS — rev 15)."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        ev = json.loads(line)
        if ev["op"] not in ("job", "job_bin"):
            continue                    # reads are derivates, not the flow
        out.append(_ev(ev["dev"], ev["name"], args=ev.get("args"),
                       nbytes=ev.get("bytes"), sha=ev.get("sha"),
                       status=ev.get("status") or None,
                       hexdata=ev.get("hex")))
    return out


# -- EDIABAS api trace [O: built on the real api.trc flash session] ----------
_QUOTED = re.compile(r'^\s*"([^"]*)"\s*$')
_BYTES_HDR = re.compile(r"^(\d+) bytes:")
_HEXLINE = re.compile(r"^\s*[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2} ?)+)")
_STATUS = re.compile(r'^\s*JOB_STATUS\s*=\s*"([^"]*)"')


def _sha(data: bytes):
    return hashlib.sha256(data).hexdigest()


def load_ediabas_trc(path: Path):
    """Parse `Job` blocks of an EDIABAS api trace into L2 records:
    quoted ecu/job (+ optional third quoted line = text args), the
    apiJobData hex dump (payload length + sha256) and the JOB_STATUS
    of result set [1] — the same set EdiabasApiBus reads."""
    out = []
    pending = []                        # quoted strings of this block
    payload = None                      # bytearray while in the dump
    announced = 0
    in_dump = False
    status = None

    def flush():
        nonlocal pending, payload, status
        if len(pending) >= 2:
            args = pending[2] if len(pending) >= 3 else None
            data = bytes(payload) if payload else None
            out.append(_ev(pending[0], pending[1], args=args,
                           nbytes=len(data) if data is not None else None,
                           sha=_sha(data) if data is not None else None,
                           status=status))
        pending, payload, status = [], None, None

    for raw in path.read_text(errors="replace").splitlines():
        s = raw.strip()
        if s == "Job":
            flush()
            in_dump, announced = False, 0
            continue
        if in_dump:
            if s.isdigit():
                in_dump = False         # closing count of apiJobData
            else:
                m = _HEXLINE.match(raw)
                if m and payload is not None:
                    payload += bytes.fromhex(m.group(1).replace(" ", ""))
                continue
        m = _QUOTED.match(s)
        if m:
            pending.append(m.group(1))
            continue
        m = _BYTES_HDR.match(s)
        if m and len(pending) >= 2:
            in_dump, payload, announced = True, bytearray(), int(m.group(1))
            continue
        m = _STATUS.match(s)
        if m:
            status = m.group(1)
    flush()
    return out


def load_any(path: Path):
    if path.suffix == ".jsonl":
        return load_jsonl(path)
    return load_ediabas_trc(path)


# -- differential -------------------------------------------------------------


def common_prefix_len(a, b):
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def diff(a, b, label_a="A", label_b="B", context: int = 3):
    """L1 choreography differential. Returns (equal, report_lines)."""
    a1, b1 = l1(a), l1(b)
    n = common_prefix_len(a1, b1)
    equal = n == len(a1) == len(b1) and len(a1) > 0
    lines = [f"L1 choreography — {label_a}: {len(a1)} jobs   "
             f"{label_b}: {len(b1)} jobs   common prefix: {n}"]
    ca, cb = Counter(a1), Counter(b1)
    for name in sorted(set(ca) | set(cb)):
        if ca[name] != cb[name]:
            lines.append(f"  count differs: {name}  "
                         f"{label_a}={ca[name]} {label_b}={cb[name]}")
    if not equal:
        lo = max(0, n - context)
        lines.append(f"  first divergence at #{n}:")
        for i in range(lo, n + context + 1):
            for label, seq in ((label_a, a1), (label_b, b1)):
                if i < len(seq):
                    mark = ">>" if i == n else "  "
                    lines.append(f"    {mark} {label}[{i}] {seq[i]}")
    return equal, lines


def diff_static(a, b, with_sha: bool = True, label_a: str = "A",
                label_b: str = "B"):
    """L2-STATIC differential over the L1 common prefix: text args,
    binary payload length, payload sha256 — STRICT TRI-STATE (rev 16):
    a field present on one side only is a mismatch. Text args None
    (trc: no third quoted line) normalize to "" — that is a VALUE
    equivalence, not a missing side. Payload bytes None means "no
    binary payload" — None vs N is a real mismatch (one side sent
    bytes the other did not). DYNAMIC_PAYLOAD_JOBS stay exempt from
    sha (their content legitimately differs between two correct runs;
    see verify_auth for the semantic check).
    Returns (n_compared, mismatches)."""
    n = common_prefix_len(l1(a), l1(b))
    mism = []
    for i in range(n):
        ea, eb = a[i], b[i]
        args_a = "" if ea["args"] is None else str(ea["args"])
        args_b = "" if eb["args"] is None else str(eb["args"])
        if args_a != args_b:
            mism.append(f"#{i} {ea['dev']}/{ea['name']} args: "
                        f"{ea['args']!r} != {eb['args']!r}")
        if ea["bytes"] != eb["bytes"]:
            mism.append(f"#{i} {ea['dev']}/{ea['name']} payload bytes: "
                        f"{_miss(ea['bytes'], label_a)} != "
                        f"{_miss(eb['bytes'], label_b)}")
        if with_sha and ea["name"] not in DYNAMIC_PAYLOAD_JOBS \
                and ea["bytes"] is not None \
                and ea["bytes"] == eb["bytes"] \
                and ea["sha"] != eb["sha"]:
            mism.append(f"#{i} {ea['dev']}/{ea['name']} payload sha256: "
                        f"{ea['sha'] or f'<missing on {label_a}>'} != "
                        f"{eb['sha'] or f'<missing on {label_b}>'}")
    return n, mism


def _miss(v, label):
    return f"<missing on {label}>" if v is None else repr(v)


def diff_dynamic(a, b, label_a: str = "A", label_b: str = "B"):
    """L2-DYNAMIC differential over the L1 common prefix: the REAL
    JOB_STATUS per event — STRICT TRI-STATE (rev 16):
      both PRESENT     → values must match
      one side MISSING → MISMATCH (the rev-15 code silently passed
                         ours OKAY vs reference None)
      both MISSING     → ignored (no evidence on either side)
    Returns (n, mismatches)."""
    n = common_prefix_len(l1(a), l1(b))
    mism = []
    for i in range(n):
        ea, eb = a[i], b[i]
        sa = ea["status"] or None
        sb = eb["status"] or None
        if sa and sb:
            if sa != sb:
                mism.append(f"#{i} {ea['dev']}/{ea['name']} JOB_STATUS: "
                            f"{sa!r} != {sb!r}")
        elif sa or sb:
            mism.append(
                f"#{i} {ea['dev']}/{ea['name']} JOB_STATUS present only "
                f"on {label_a if sa else label_b} ({(sa or sb)!r}), "
                f"missing on {label_b if sa else label_a}")
    return n, mism


def verify_auth(events, store=None):
    """Semantic self-audit of OUR bench log — the WHOLE retry chain
    (rev 17; rev 15 verified only the last attempt). For EVERY
    auth_audit record (= one NG_AUTHENTISIERUNG_START try): recompute
    the SG-Schluessel from THAT attempt's own seed + nonce + the
    serial + container material, and match it against the k-th payload
    witness (sha256 by default, hex only with --include-secret-auth)
    and the audit's own key witness. The audit is cross-checked, not
    trusted: its seed must equal the k-th logged ZUFALLSZAHL read, its
    index the k-th seed-job args, its status the payload event's
    JOB_STATUS when that carries one.
    Returns (ok, note)."""
    from reconstruction import runner as flash_runner

    audits = [e for e in events
              if e.get("op") == "auth_audit" and e.get("attempt")]
    if not audits:
        return False, "no per-attempt auth_audit records in the log"
    payload = [e for e in events
               if e.get("name") == "NG_AUTHENTISIERUNG_START"
               and e.get("op") == "job_bin"]
    if not payload:
        return False, "no NG_AUTHENTISIERUNG_START job in the log"
    if len(payload) != len(audits):
        return False, (f"retry chain incomplete: {len(audits)} audit "
                       f"records vs {len(payload)} sent payloads")
    seed_ev = [e for e in events if e.get("op") == "read_binary"
               and e["name"] == "ZUFALLSZAHL" and e.get("hex")]
    ser_ev = [e for e in events if e.get("op") == "read_binary"
              and e["name"] == "SERIENNUMMER" and e.get("hex")]
    idx_ev = [e for e in events if e.get("op") == "job"
              and e["name"] == "AUTHENTISIERUNG_ZUFALLSZAHL_LESEN"]
    if len(seed_ev) < len(audits) or not ser_ev \
            or len(idx_ev) < len(audits):
        return False, "log misses seed/serial/index evidence"
    serial = bytes.fromhex(ser_ev[-1]["hex"])
    if store is None:
        try:
            store = flash_runner.discover_store()
        except FileNotFoundError as e:
            return False, f"containers unavailable, cannot verify: {e}"
    from reconstruction import security

    for k, (a, p) in enumerate(zip(audits, payload), 1):
        # the audit is EVIDENCE, not truth — cross-check vs raw log
        if a["seed_hex"] != seed_ev[k - 1]["hex"]:
            return False, (f"attempt {k}: audit seed != the logged "
                           f"ZUFALLSZAHL read")
        want_idx = int(str(idx_ev[k - 1].get("args", "3;")).split(";")[0])
        if a["idx"] != want_idx:
            return False, (f"attempt {k}: audit idx {a['idx']} != the "
                           f"seed-job args index {want_idx}")
        pstat = p.get("status") or None
        if pstat and pstat != a["status"]:
            return False, (f"attempt {k}: audit status {a['status']!r} "
                           f"!= payload event JOB_STATUS {pstat!r}")
        seed = bytes.fromhex(a["seed_hex"])
        nonce = bytes.fromhex(a["nonce_hex"])
        try:
            if a["art"] == "Simple":
                want = security.compute_security_key_simple(
                    seed, store.simple_key8(a["ecu"], a["idx"]))
            elif a["art"] == "Symetrisch":
                want = security.compute_security_key(
                    seed, serial, store.sym_key16(a["ecu"], a["idx"]),
                    nonce=nonce)
            elif a["art"] == "Asymetrisch":
                want = security.compute_security_key_asymmetric_as2(
                    seed, serial, nonce, store.auth_blob(a["ecu"], a["idx"]))
            else:
                return False, f"attempt {k}: unknown art {a['art']!r}"
        except (KeyError, ValueError) as e:
            return False, f"attempt {k}: material lookup failed: {e}"
        ok = True
        if p.get("hex"):
            ok = ok and want.hex() == p["hex"]
        else:                                   # redacted default log
            ok = ok and len(want) == p.get("bytes") \
                and _sha(want) == p.get("sha")
        if a.get("key_hex"):
            ok = ok and want.hex() == a["key_hex"]
        else:
            ok = ok and _sha(want) == a.get("key_sha256")
        if not ok:
            return False, (f"attempt {k}/{len(audits)} ({a['ecu']}/"
                           f"{a['art']}/idx{a['idx']}): recomputed "
                           f"!= sent payload")
    return True, (f"{audits[-1]['ecu']}/{audits[-1]['art']}: all "
                  f"{len(audits)} attempt(s) of the retry chain "
                  f"recomputed == sent payload")


def window_before(events, job_name: str):
    """Sub-sequence up to (excluding) the first occurrence of the job —
    the pre-flash window: --before FLASH_SCHREIBEN compares the WHOLE
    pre-flash orchestration (AIF_LESEN, DATEN_REFERENZ_LESEN,
    DIAGNOSEPROTOKOLL_*, FLASH_PARAMETER_LESEN …) against ours."""
    job_name = job_name.upper()
    for i, e in enumerate(events):
        if e["name"] == job_name:
            return events[:i]
    return events


# ---------------------------------------------------------------------------
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Bench differential: L1 choreography + L2 semantics "
                    "vs the original tool's trace")
    ap.add_argument("log_a")
    ap.add_argument("log_b")
    ap.add_argument("--label-a", default=None)
    ap.add_argument("--label-b", default=None)
    ap.add_argument("--before", metavar="JOB", default=None,
                    help="compare only the window before JOB's first "
                         "occurrence (e.g. FLASH_SCHREIBEN = pre-flash "
                         "orchestration)")
    ap.add_argument("--no-sha", action="store_true",
                    help="skip payload sha256 (foreign reference image)")
    ap.add_argument("--verify", action="store_true",
                    help="semantic auth self-audit of OUR log "
                         "(recompute the SG-Schluessel from logged "
                         "seed/serial/nonce + containers)")
    args = ap.parse_args(argv)
    a = load_any(Path(args.log_a))
    b = load_any(Path(args.log_b))
    if args.before:
        a, b = window_before(a, args.before), window_before(b, args.before)
    la = args.label_a or Path(args.log_a).name
    lb = args.label_b or Path(args.log_b).name
    ok1, lines = diff(a, b, la, lb)
    print("\n".join(lines))
    n, mism = diff_static(a, b, with_sha=not args.no_sha,
                          label_a=la, label_b=lb)
    if mism:
        print(f"L2-static — {len(mism)} mismatch(es) over the "
              f"{n}-event common prefix:")
        for m in mism[:20]:
            print(f"  {m}")
    else:
        print(f"L2-static — match over the {n}-event common prefix")
    n, dyn = diff_dynamic(a, b, label_a=la, label_b=lb)
    if dyn:
        print(f"L2-dynamic — {len(dyn)} JOB_STATUS mismatch(es):")
        for m in dyn[:20]:
            print(f"  {m}")
    else:
        print(f"L2-dynamic — JOB_STATUS match over the {n}-event "
              f"common prefix")
    ok = ok1 and not mism and not dyn
    if args.verify:
        raw = ([json.loads(l) for l
                in Path(args.log_a).read_text(encoding="utf-8")
                .splitlines()]
               if Path(args.log_a).suffix == ".jsonl" else a)
        vok, note = verify_auth(raw)
        print(f"auth semantic verify: {'PASS' if vok else 'FAIL'} — {note}")
        ok = ok and vok
    if ok:
        print(f"DIFF OK: {la} and {lb} match (L1 + L2)")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
def _selftest():
    import tempfile

    from bench_diff import window_before as bd_window

    passed, failed = 0, []

    def check(name, cond):
        nonlocal passed
        if cond:
            passed += 1
            print(f"BDIFF OK   {name}")
        else:
            failed.append(name)
            print(f"BDIFF FAIL {name}")

    # JSONL L2 round trip (LoggingBus format: sha256+hex+real status)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "a.jsonl"
        p.write_text("\n".join(json.dumps(e) for e in [
            {"op": "job", "dev": "DLE08", "name": "SG_PHYS_HWNR_LESEN",
             "args": "", "ok": True, "status": "OKAY"},
            {"op": "read_text", "name": "SG_PHYS_HWNR", "value": "x"},
            {"op": "job", "dev": "VDLE", "name": "INIT_VDLE",
             "args": "OKAY;1", "ok": True, "status": "OKAY"},
            {"op": "read_binary", "name": "ZUFALLSZAHL", "bytes": 8,
             "hex": "0102030405060708"},
            {"op": "job_bin", "dev": "DLE08",
             "name": "NG_AUTHENTISIERUNG_START", "bytes": 8,
             "sha": _sha(b"\x01" * 8), "hex": (b"\x01" * 8).hex(),
             "ok": True, "status": "OKAY"}]) + "\n")
        ev = load_jsonl(p)
        check("JSONL loader: jobs only, reads excluded",
              l1(ev) == [("DLE08", "SG_PHYS_HWNR_LESEN"),
                         ("VDLE", "INIT_VDLE"),
                         ("DLE08", "NG_AUTHENTISIERUNG_START")])
        check("JSONL loader carries L2 fields (args/bytes/sha/status)",
              ev[2]["bytes"] == 8 and ev[2]["sha"] == _sha(b"\x01" * 8)
              and ev[1]["args"] == "OKAY;1" and ev[2]["status"] == "OKAY")

        # L1: identical vs itself / divergence located / counts
        equal, _ = diff(ev, ev)
        check("identical sequences diff clean", equal)
        other = ev[:-1] + [_ev("DLE08", "FLASH_SCHREIBEN")]
        equal, lines = diff(ev, other, "ours", "ref")
        check("divergence found + located",
              not equal and any("first divergence at #2" in l
                                for l in lines))
        equal, lines = diff(ev, ev + ev[:1], "a", "b")
        check("count-only difference reported",
              not equal and any("count differs" in l for l in lines))

        # L2-STATIC: sha tampering of a STATIC payload is caught
        flash_ev = [_ev("DLE08", "FLASH_SCHREIBEN", nbytes=8,
                        sha=_sha(b"\x01" * 8))]
        tampered = [dict(flash_ev[0], sha=_sha(b"\x02" * 8))]
        n, mism = diff_static(flash_ev, tampered)
        check("L2-static catches a tampered payload (field named)",
              n == 1 and len(mism) == 1 and "payload sha256" in mism[0])
        # DYNAMIC payloads (auth key) are exempt from sha: two CORRECT
        # runs differ (fresh seed/nonce) and must NOT be a false FAIL
        run1 = [_ev("DLE08", "NG_AUTHENTISIERUNG_START", nbytes=8,
                    sha=_sha(b"\xaa" * 8))]
        run2 = [_ev("DLE08", "NG_AUTHENTISIERUNG_START", nbytes=8,
                    sha=_sha(b"\xbb" * 8))]
        n, mism = diff_static(run1, run2)
        check("dynamic auth payload: sha exempt, length still checked",
              n == 1 and not mism)
        n, mism = diff_static(
            run1, [dict(run2[0], bytes=16)])
        check("dynamic auth payload: length mismatch still caught",
              n == 1 and len(mism) == 1 and "bytes" in mism[0])
        # L2-STATIC tri-state (rev 16): one-sided args / bytes mismatch
        n, mism = diff_static(
            [_ev("DLE08", "DIAGNOSE_AUFRECHT", args="NEIN;JA")],
            [_ev("DLE08", "DIAGNOSE_AUFRECHT")])
        check("L2-static: args present on one side only = mismatch",
              n == 1 and len(mism) == 1 and "args" in mism[0])
        n, mism = diff_static(
            [_ev("DLE08", "IDENT")],
            [_ev("DLE08", "IDENT", args="")])
        check("L2-static: args None normalizes to '' (both = no args)",
              n == 1 and not mism)
        n, mism = diff_static(
            [_ev("DLE08", "FLASH_SCHREIBEN", nbytes=8,
                 sha=_sha(b"\x01" * 8))],
            [_ev("DLE08", "FLASH_SCHREIBEN")])
        check("L2-static: payload on one side only = mismatch",
              n == 1 and len(mism) == 1 and "bytes" in mism[0])
        # L2-DYNAMIC tri-state (rev 16): the REAL JOB_STATUS
        n, dyn = diff_dynamic(
            [_ev("DLE08", "X", status="OKAY")],
            [_ev("DLE08", "X", status="ERROR_ERROR_AUTHENTICATION")])
        check("L2-dynamic catches a JOB_STATUS divergence",
              n == 1 and len(dyn) == 1 and "JOB_STATUS" in dyn[0])
        n, dyn = diff_dynamic(
            [_ev("DLE08", "X", status="OKAY")],
            [_ev("DLE08", "X")], label_a="ours", label_b="ref")
        check("L2-dynamic: one-sided JOB_STATUS is a MISMATCH (rev 16)",
              n == 1 and len(dyn) == 1 and "ours" in dyn[0]
              and "ref" in dyn[0])
        n, dyn = diff_dynamic(
            [_ev("DLE08", "X")], [_ev("DLE08", "X")])
        check("L2-dynamic: both sides missing -> no evidence, ignored",
              n == 1 and not dyn)

        # --verify end-to-end on a REAL mock contact log (containers
        # present on this machine): recompute the SG-Schluessel from
        # the log and compare with the payload actually sent
        import bench_scenario as bs
        lim = Path(td) / "limits.txt"
        lim.write_text("BAT 11.5 14.8\n")
        logv = Path(td) / "verify.jsonl"
        busv = bs.LoggingBus(bs.MockBus(sig_seq=["OKAY"]), logv)
        from vdle_diff import build_vdle_file
        repv = bs.run_contact(busv, build_vdle_file(
            [(0x00870000, 0x18)], fill_from=0x40),
            bs.build_safety(13.2, lim, "EGS", "x"))
        busv.auth_audit(repv)
        raw = [json.loads(l) for l in logv.read_text().splitlines()]
        # rev 16: the default log is REDACTED — the key exists only as
        # sha256 (payload event + audit); verify must work from that
        check("redacted default log: key present only as sha256",
              all("hex" not in e for e in raw
                  if e.get("op") == "job_bin"
                  and e["name"] == "NG_AUTHENTISIERUNG_START")
              and all("key_hex" not in e for e in raw
                      if e.get("op") == "auth_audit"))
        vok, note = verify_auth(raw)
        check(f"verify_auth recomputes the key from sha witnesses "
              f"({note})", vok and repv.auth_ok)
        # tampered audit key sha -> FAIL (the audit is cross-checked
        # against the payload, not trusted blindly)
        raw_bad = [dict(e) for e in raw]
        for e in raw_bad:
            if e.get("op") == "auth_audit":
                e["key_sha256"] = "00" * 32
        vok, note = verify_auth(raw_bad)
        check("verify_auth fails on a tampered audit key", not vok)
        # tampered payload sha -> FAIL (the SENT payload is a witness)
        raw_bad2 = [dict(e) for e in raw]
        for e in raw_bad2:
            if e.get("op") == "job_bin" \
                    and e.get("name") == "NG_AUTHENTISIERUNG_START":
                e["sha"] = "00" * 32
        vok, note = verify_auth(raw_bad2)
        check("verify_auth fails on a tampered payload sha", not vok)

        # rev 17: the WHOLE retry chain is verified, not only the last
        # attempt (review 16 methodological fix) — attempt 1
        # ROUTINE_NOT_COMPLETE, attempt 2 OKAY
        logr = Path(td) / "retry.jsonl"
        busr = bs.LoggingBus(
            bs.MockBus(sig_seq=["OKAY"],
                       auth_results=["ROUTINE_NOT_COMPLETE", "OKAY"]),
            logr)
        repr_ = bs.run_contact(busr, build_vdle_file(
            [(0x00870000, 0x18)], fill_from=0x40),
            bs.build_safety(13.2, lim, "EGS", "x"))
        busr.auth_audit(repr_)
        rawr = [json.loads(l) for l in logr.read_text().splitlines()]
        vok, note = verify_auth(rawr)
        check(f"verify_auth proves the FULL retry chain ({note})",
              vok and repr_.auth_attempts == 2
              and len([e for e in rawr
                       if e.get("op") == "auth_audit"]) == 2)
        # tampering the FIRST attempt's key witness -> FAIL: the chain
        # audit covers every attempt, not just the winner
        raw_first = [dict(e) for e in rawr]
        for e in raw_first:
            if e.get("op") == "auth_audit" and e.get("attempt") == 1:
                e["key_sha256"] = "00" * 32
        vok, note = verify_auth(raw_first)
        check("verify_auth: tampered FIRST attempt fails "
              "(chain, not last-only)", not vok and "attempt 1" in note)

    # the REAL EDIABAS flash trace shipping with the installation [O]
    trc = (Path.home() / "Downloads/BMW/Inpa/EDIABAS_6.4.7/TRACE/"
           "api.trc")
    if trc.exists():
        jobs = load_ediabas_trc(trc)
        names = [e["name"] for e in jobs]
        devs = {e["dev"] for e in jobs}
        check("real api.trc parses: >1000 jobs, flash-SGBD + ECU devices",
              len(jobs) > 1000 and {"10FLASH", "13_ASK"} <= devs)
        check("real api.trc: FLASH_SCHREIBEN* dominates (flash phase)",
              sum(1 for n in names if n.startswith("FLASH_SCHREIBEN"))
              > 800)
        check("real api.trc contains DIAGNOSE_AUFRECHT keep-alives",
              "DIAGNOSE_AUFRECHT" in names)
        check("real api.trc contains the IPO signature job",
              "NG_SIGNATUR_PRUEFEN" in names)

        # L2 from the trace: payloads + text args + JOB_STATUS
        binjobs = [e for e in jobs if e["sha"]]
        check("trace L2: binary payloads parsed (length + sha256)",
              binjobs and all(e["bytes"] == len(bytes.fromhex("")) or
                              e["bytes"] > 0 for e in binjobs[:50])
              and len({e["sha"] for e in binjobs}) > 100)
        txt = [e for e in jobs if e["args"] is not None]
        check("trace L2: text args captured (apiJob 3rd quoted line)",
              txt and any(e["name"] == "DIAGNOSE_AUFRECHT"
                          and e["args"] == "NEIN;JA" for e in txt))
        st = [e for e in jobs if e["status"] is not None]
        check("trace L2: JOB_STATUS of result set [1] captured",
              st and {e["status"] for e in st} >= {"OKAY"})

        # documented ground truth: first FLASH_SCHREIBEN block = 54 B
        first_flash = next(e for e in jobs
                           if e["name"] == "FLASH_SCHREIBEN")
        check("trace L2: first FLASH_SCHREIBEN payload is the "
              "documented 54 bytes",
              first_flash["bytes"] == 54
              and first_flash["sha"] == _sha(first_flash["raw"])
              if "raw" in first_flash else first_flash["bytes"] == 54)

        equal, _ = diff(jobs, load_ediabas_trc(trc))
        n1, m1 = diff_static(jobs, load_ediabas_trc(trc))
        n2, m2 = diff_dynamic(jobs, load_ediabas_trc(trc))
        check("real api.trc diffs clean against itself (L1+L2)",
              equal and not m1 and not m2)

        # pre-flash window (review 13) — the shipped traces are ROTATED
        # (both api.trc and apiold.trc start mid-flash), so the window
        # before the first FLASH_SCHREIBEN is empty HERE; on a bench-
        # fresh trace it holds the whole pre-flash orchestration.
        synth = [_ev("VDLE", "INIT_VDLE"), _ev("DLE08", "IDENT"),
                 _ev("DLE08", "FLASH_SCHREIBEN"), _ev("DLE08", "MORE")]
        check("pre-flash window excludes the first write onward",
              [e["name"] for e in bd_window(synth, "FLASH_SCHREIBEN")]
              == ["INIT_VDLE", "IDENT"])
        check("rotated reference: file starts mid-flash "
              "(documented rotation)",
              bd_window(jobs, "FLASH_SCHREIBEN") == []
              and jobs[0]["name"] == "FLASH_SCHREIBEN")

        # the pre-flash jobs DO live in the trace as the inter-segment
        # orchestration of the flash SGBD (10FLASH) — the reference
        # checklist for the bench diff beyond IPO CI62F1
        inter = sorted({e["name"] for e in jobs
                        if e["dev"] == "10FLASH"})
        check("reference choreography: 10FLASH orchestration present",
              {"AIF_LESEN", "DATEN_REFERENZ_LESEN", "DIAGNOSE_MODE",
               "FLASH_BLOCKLAENGE_LESEN", "FLASH_PARAMETER_LESEN"}
              <= set(inter))
        print(f"    10FLASH reference orchestration ({len(inter)} jobs): "
              + " ".join(inter))
    else:
        print("BDIFF SKIP real api.trc not found")

    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_selftest() if len(sys.argv) == 1 else main())
