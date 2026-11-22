"""Scan queue and process supervision. Concurrency, cooldown, timeouts and cancellation live here (BR-V13..V19)."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import config, db, rules

_HOSTCHARS = re.compile(r"^[a-z0-9][a-z0-9.\-]*$|^[0-9a-f:.]+$")   # never starts with "-": it would be read as a flag
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MODULE = re.compile(r"MODULE (\d+)")

_procs: dict[int, subprocess.Popen] = {}
_cancel: set[int] = set()
_lock = threading.Lock()
_started = False


def clean_log(text: str) -> str:
    """The log is hostile text (banners, headers). Strip terminal escapes and control characters."""
    return _CTRL.sub("", _ANSI.sub("", text.replace("\r", "\n")))


def scan_target_arg(asset: dict) -> str:
    """What we type into the scanner's prompt: scheme://host (default port only) or the bare host."""
    host = asset["host"].lower()
    if not _HOSTCHARS.match(host):
        raise ValueError("unsafe host")
    url = asset.get("url") or ""
    sp = urlsplit(url) if url else None
    if sp and sp.scheme in ("http", "https") and (sp.hostname or "").lower() == host and not sp.port:
        return f"{sp.scheme}://{host}"
    return host


def enqueue(asset_ids: list[int], profile: str, force: bool) -> dict:
    """BR-V12..V16. Returns {queued:[scan ids], skipped:[{asset_id, host, reason}]}."""
    if profile not in config.PROFILES:
        raise ValueError("unknown profile")
    if not asset_ids:
        raise ValueError("select at least one asset")
    ids = list(dict.fromkeys(asset_ids))
    if len(ids) > config.MAX_BULK_SCAN:
        raise ValueError(f"at most {config.MAX_BULK_SCAN} assets per bulk scan")
    waiting = db.one("SELECT COUNT(*) c FROM scans WHERE status IN ('queued','running')")["c"]
    queued, skipped = [], []
    for aid in ids:
        a = db.one("SELECT a.*, t.status AS tstatus FROM assets a JOIN targets t ON t.id=a.target_id WHERE a.id=?", (aid,))
        if not a:
            skipped.append({"asset_id": aid, "host": "?", "reason": "unknown asset"})
            continue

        def skip(reason: str, a=a) -> None:
            skipped.append({"asset_id": a["id"], "host": a["host"], "reason": reason})

        if a["tstatus"] == "revoked":
            skip("authorisation revoked for this target")
        elif a["excluded"]:
            skip("excluded from scope")
        elif db.one("SELECT 1 x FROM scans WHERE asset_id=? AND status IN ('queued','running')", (aid,)):
            skip("already queued or running")
        elif waiting + len(queued) >= config.MAX_QUEUE:
            skip("queue is full")
        else:
            last = db.one("SELECT finished_at FROM scans WHERE asset_id=? AND finished_at IS NOT NULL "
                          "ORDER BY finished_at DESC LIMIT 1", (aid,))
            left = rules.cooldown_remaining(last["finished_at"] if last else None)
            if left and not force:
                skip(f"scanned {config.SCAN_COOLDOWN_S - left}s ago; wait {left}s or force")
            else:
                sid = db.run("INSERT INTO scans(asset_id, profile, queued_at) VALUES (?,?,?)",
                             (aid, profile, rules.now()))
                queued.append(sid)
    db.audit("scan_enqueued", f"{len(queued)} queued, {len(skipped)} skipped, profile={profile}, force={force}")
    return {"queued": queued, "skipped": skipped}


def cancel(scan_id: int) -> bool:
    s = db.one("SELECT status FROM scans WHERE id=?", (scan_id,))
    if not s:
        return False
    if s["status"] == "queued":
        db.run("UPDATE scans SET status='cancelled', finished_at=? WHERE id=?", (rules.now(), scan_id))
        db.audit("scan_cancelled", f"scan {scan_id} (queued)")
        return True
    if s["status"] == "running":
        with _lock:
            _cancel.add(scan_id)
            p = _procs.get(scan_id)
        if p and p.poll() is None:
            _kill(p)
        db.audit("scan_cancelled", f"scan {scan_id} (running)")
        return True
    return False


def _kill(p: subprocess.Popen) -> None:
    try:
        os.killpg(p.pid, signal.SIGTERM)
        time.sleep(1.5)
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _read_findings(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        parts = (line.split("\t") + ["", ""])[:3]
        sev = rules.normalise_severity(clean_log(parts[0]))
        title, detail = clean_log(parts[1])[:300], clean_log(parts[2])[:600]
        if title:
            out.append((sev, title, detail))
    return out


def _finish(scan_id: int, asset_id: int, status: str, error: str, d: Path) -> None:
    rows = _read_findings(d / "findings.tsv") if status in ("done", "timeout", "cancelled") else []
    prev = db.one("SELECT id FROM scans WHERE asset_id=? AND status='done' AND id<>? ORDER BY finished_at DESC LIMIT 1",
                  (asset_id, scan_id))
    prev_keys = [r["key"] for r in db.q("SELECT key FROM findings WHERE scan_id=?", (prev["id"],))] if prev else []
    seen: set[str] = set()
    counts: dict[str, int] = {}
    for sev, title, detail in rows:
        key = rules.finding_key(sev, title)
        if key in seen:                                    # BR-V19: one row per distinct finding per scan
            continue
        seen.add(key)
        state = "open" if (not prev or key in prev_keys) else "new"
        db.run("INSERT INTO findings(scan_id, asset_id, severity, title, detail, key, status) VALUES (?,?,?,?,?,?,?)",
               (scan_id, asset_id, sev, title, detail, key, state))
        counts[sev] = counts.get(sev, 0) + 1
    report = next(iter(sorted(d.glob("vapt_report_*.md"))), None)
    score = rules.risk_score(counts)
    db.run("UPDATE scans SET status=?, error=?, finished_at=?, counts=?, risk=?, report=?, module=? WHERE id=?",
           (status, error[:300], rules.now(), json.dumps(counts), score, str(report) if report else "",
            config.TOTAL_MODULES if status == "done" else db.one("SELECT module m FROM scans WHERE id=?", (scan_id,))["m"],
            scan_id))
    db.audit("scan_finished", f"scan {scan_id} {status}, risk {score}")


def _supervise(scan_id: int) -> None:
    s = db.one("SELECT s.*, a.host, a.url, a.id AS aid FROM scans s JOIN assets a ON a.id=s.asset_id WHERE s.id=?", (scan_id,))
    d = config.SCANS_DIR / str(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    log = d / "scan.log"
    (d / "findings.tsv").unlink(missing_ok=True)       # a re-used folder must never leak an older run's findings
    prof = config.PROFILES[s["profile"]]
    try:
        arg = scan_target_arg(s)
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "USER", "TMPDIR")}
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + env.get("PATH", "/usr/bin:/bin")
        env.update(TERM="xterm", VAPT_SKIP_TOOLS=",".join(prof["skip"]), VAPT_FINDINGS_FILE=str(d / "findings.tsv"))
        with open(log, "wb") as lf:
            p = subprocess.Popen(["bash", str(config.SCANNER)], cwd=d, env=env, stdin=subprocess.PIPE, stdout=lf,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            with _lock:
                _procs[scan_id] = p
            assert p.stdin is not None
            p.stdin.write(f"{arg}\ny\n".encode())          # target, then the authorisation confirmation
            p.stdin.close()
            deadline = time.monotonic() + prof["timeout_s"]
            timed_out = False
            while p.poll() is None:
                if time.monotonic() > deadline:
                    timed_out = True
                    _kill(p)
                    break
                mods = _MODULE.findall(clean_log(log.read_text(errors="replace")))
                if mods:
                    db.run("UPDATE scans SET module=? WHERE id=?", (int(mods[-1]), scan_id))
                time.sleep(2)
            p.wait()
        mods = _MODULE.findall(clean_log(log.read_text(errors="replace")))
        if mods:
            db.run("UPDATE scans SET module=? WHERE id=?", (int(mods[-1]), scan_id))
        with _lock:
            was_cancelled = scan_id in _cancel
            _cancel.discard(scan_id)
        if was_cancelled:
            _finish(scan_id, s["aid"], "cancelled", "cancelled by you", d)
        elif timed_out:
            _finish(scan_id, s["aid"], "timeout", f"stopped after {prof['timeout_s']}s; partial results kept", d)
        elif p.returncode == 0:
            _finish(scan_id, s["aid"], "done", "", d)
        elif p.returncode == 3:                            # scanner's reachability gate: no web response
            _finish(scan_id, s["aid"], "failed", "No web response, so the scan stopped at the reachability gate. Nothing was tested.", d)
        else:
            _finish(scan_id, s["aid"], "failed", f"scanner exited with code {p.returncode}", d)
    except Exception as exc:  # noqa: BLE001
        _finish(scan_id, s["aid"], "failed", str(exc), d)
    finally:
        with _lock:
            _procs.pop(scan_id, None)


def _tick() -> None:
    running = db.one("SELECT COUNT(*) c FROM scans WHERE status='running'")["c"]
    free = config.MAX_CONCURRENT_SCANS - running
    if free <= 0:
        return
    for s in db.q("SELECT id, asset_id FROM scans WHERE status='queued' ORDER BY id LIMIT 20"):
        if free <= 0:
            break
        # BR-V15: never two scans on the same asset, and the target must still be authorised
        t = db.one("SELECT t.status FROM assets a JOIN targets t ON t.id=a.target_id WHERE a.id=?", (s["asset_id"],))
        if t and t["status"] == "revoked":
            db.run("UPDATE scans SET status='cancelled', error='authorisation revoked', finished_at=? WHERE id=?",
                   (rules.now(), s["id"]))
            continue
        db.run("UPDATE scans SET status='running', started_at=?, module=0 WHERE id=?", (rules.now(), s["id"]))
        threading.Thread(target=_supervise, args=(s["id"],), daemon=True, name=f"scan-{s['id']}").start()
        free -= 1


def _loop() -> None:
    while True:
        try:
            _tick()
        except Exception:  # noqa: BLE001 - the scheduler must survive anything
            pass
        time.sleep(1.5)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, daemon=True, name="scheduler").start()


def stop_all() -> None:
    with _lock:
        procs = list(_procs.values())
    for p in procs:
        if p.poll() is None:
            _kill(p)
