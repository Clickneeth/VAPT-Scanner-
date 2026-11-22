"""FastAPI app: JSON API + static single-page UI. Loopback only (BR-V01)."""
from __future__ import annotations

import csv
import hmac
import io
import json
import secrets
import shutil
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config, db, discovery, rules, runner

STATIC = config.WEBUI / "static"
TOOLS = ["subfinder", "httpx", "nmap", "ffuf", "katana", "nuclei", "testssl.sh", "nikto", "whois", "dig", "curl"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    runner.start()
    yield
    runner.stop_all()


app = FastAPI(title="VAPT Console", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# BR-V01/V02: only reachable as 127.0.0.1 / localhost (defeats DNS rebinding), and no cross-site writes.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


COOKIE = "vapt_session"


def _authed(request: Request) -> bool:
    tok = config.AUTH_TOKEN
    return bool(tok) and hmac.compare_digest(request.cookies.get(COOKIE, ""), tok)


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    # BR-V26: a random per-launch token (printed at startup, file mode 0600) is the key to the whole console.
    # Another local user or process that can reach the port still cannot read or drive it.
    if not path.startswith("/static/"):
        tok = config.AUTH_TOKEN
        if request.method == "GET" and path == "/" and tok and hmac.compare_digest(request.query_params.get("t", ""), tok):
            r = RedirectResponse("/", status_code=303)           # swap the URL token for an HttpOnly cookie
            r.set_cookie(COOKIE, tok, httponly=True, samesite="strict", path="/")
            r.headers["Cache-Control"] = "no-store"
            return r
        if not _authed(request):
            if path.startswith("/api/"):
                return JSONResponse({"error": "not authorised: open the launch URL printed when the server started"}, status_code=401)
            return PlainTextResponse("VAPT Console: open the launch URL printed in the terminal (or in webui/data/launch_url.txt).",
                                     status_code=401)
    if request.method not in ("GET", "HEAD"):
        origin = request.headers.get("origin")
        ok_origin = origin is None or origin in (f"http://127.0.0.1:{config.PORT}", f"http://localhost:{config.PORT}")
        if request.headers.get("x-vapt-ui") != "1" or not ok_origin:
            return JSONResponse({"error": "blocked: cross-site or missing header"}, status_code=403)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


class TargetsIn(BaseModel):
    text: str = Field(max_length=20000)
    attested: bool = False
    basis: str = Field(default="", max_length=500)


class AssetIn(BaseModel):
    target_id: int
    value: str = Field(max_length=300)
    attested: bool = False
    basis: str = Field(default="", max_length=500)


class ScanIn(BaseModel):
    asset_ids: list[int] = Field(max_length=config.MAX_BULK_SCAN * 5)
    profile: str = "standard"
    force: bool = False


def _bad(msg: str, code: int = 400):
    raise HTTPException(status_code=code, detail=msg)


@app.get("/api/meta")
def meta():
    import shutil as sh
    return {
        "profiles": config.PROFILES, "tools": {t: bool(sh.which(t)) for t in TOOLS},
        "limits": {"bulk": config.MAX_BULK_SCAN, "concurrency": config.MAX_CONCURRENT_SCANS,
                   "cooldown_s": config.SCAN_COOLDOWN_S, "min_basis": config.MIN_BASIS_CHARS,
                   "targets_per_drop": config.MAX_TARGETS_PER_DROP},
        "modules": config.TOTAL_MODULES,
    }


@app.get("/api/state")
def state():
    targets = db.q("SELECT * FROM targets ORDER BY id DESC")
    assets = db.q("""
        SELECT a.*, ls.id AS last_scan_id, ls.status AS last_status, ls.risk AS last_risk,
               ls.counts AS last_counts, ls.finished_at AS last_finished, ls.profile AS last_profile
        FROM assets a LEFT JOIN scans ls ON ls.id = (
            SELECT id FROM scans WHERE asset_id=a.id AND status IN ('done','timeout') ORDER BY finished_at DESC LIMIT 1)
        ORDER BY a.target_id, CASE a.kind WHEN 'root' THEN 0 WHEN 'ip' THEN 1 ELSE 2 END, a.host""")
    for a in assets:
        a["ips"] = db.jl(a["ips"], [])
        a["tech"] = db.jl(a["tech"], [])
        a["last_counts"] = db.jl(a["last_counts"], {})
        a["cooldown"] = rules.cooldown_remaining(a["last_finished"])
        a["alive"] = bool(a["alive"])
    scans = db.q("""
        SELECT s.id, s.asset_id, s.profile, s.status, s.queued_at, s.started_at, s.finished_at, s.module,
               s.risk, s.counts, s.error, a.host FROM scans s JOIN assets a ON a.id=s.asset_id
        ORDER BY s.id DESC LIMIT 300""")
    for s in scans:
        s["counts"] = db.jl(s["counts"], {})
    return {"targets": targets, "assets": assets, "scans": scans}


class ParseIn(BaseModel):
    text: str = Field(max_length=20000)


@app.post("/api/parse")
def parse(body: ParseIn):
    """Side-effect-free preview so the page validates with exactly the server's rules."""
    return {"items": [{"raw": p.raw[:100], "kind": p.kind, "value": p.value, "warning": p.warning, "error": p.error}
                      for p in rules.parse_targets(body.text)]}


@app.post("/api/targets")
def add_targets(body: TargetsIn):
    err = rules.check_authorisation(body.attested, body.basis)
    if err:
        _bad(err)
    parsed = rules.parse_targets(body.text)
    if not parsed:
        _bad("No targets found in that text.")
    added, duplicates, rejected = [], [], []
    for p in parsed:
        if p.error:
            rejected.append({"raw": p.raw[:100], "error": p.error})
            continue
        if db.one("SELECT 1 x FROM targets WHERE value=?", (p.value,)):
            duplicates.append(p.value)
            continue
        tid = db.run("INSERT INTO targets(kind, value, basis, authorised_at, created_at, warning) VALUES (?,?,?,?,?,?)",
                     (p.kind, p.value, body.basis.strip(), rules.now(), rules.now(), p.warning))
        db.audit("target_authorised", f"{p.value} ({p.kind}); basis: {body.basis.strip()[:200]}")
        discovery.start(tid)
        added.append({"id": tid, "value": p.value, "kind": p.kind, "warning": p.warning})
    return {"added": added, "duplicates": duplicates, "rejected": rejected}


@app.post("/api/targets/{tid}/discover")
def rediscover(tid: int):
    t = db.one("SELECT * FROM targets WHERE id=?", (tid,))
    if not t:
        _bad("unknown target", 404)
    if t["status"] == "revoked":
        _bad("authorisation was revoked for this target")
    if t["status"] == "discovering":
        _bad("discovery is already running")
    discovery.start(tid)
    return {"ok": True}


@app.post("/api/targets/{tid}/revoke")
def revoke(tid: int):
    t = db.one("SELECT * FROM targets WHERE id=?", (tid,))
    if not t:
        _bad("unknown target", 404)
    db.run("UPDATE targets SET status='revoked' WHERE id=?", (tid,))
    for s in db.q("SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id "
                  "WHERE a.target_id=? AND s.status IN ('queued','running')", (tid,)):
        runner.cancel(s["id"])
    db.audit("target_revoked", t["value"])
    return {"ok": True}


@app.delete("/api/targets/{tid}")
def delete_target(tid: int):
    t = db.one("SELECT * FROM targets WHERE id=?", (tid,))
    if not t:
        _bad("unknown target", 404)
    if db.one("SELECT 1 x FROM scans s JOIN assets a ON a.id=s.asset_id "
              "WHERE a.target_id=? AND s.status IN ('queued','running')", (tid,)):
        _bad("cancel its running scans first")
    scan_ids = [r["id"] for r in db.q("SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id WHERE a.target_id=?", (tid,))]
    with db.conn() as c:
        c.execute("DELETE FROM findings WHERE scan_id IN (SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id WHERE a.target_id=?)", (tid,))
        c.execute("DELETE FROM scans WHERE asset_id IN (SELECT id FROM assets WHERE target_id=?)", (tid,))
        c.execute("DELETE FROM assets WHERE target_id=?", (tid,))
        c.execute("DELETE FROM targets WHERE id=?", (tid,))
    for sid in scan_ids:
        d = (config.SCANS_DIR / str(sid)).resolve()
        if d.parent == config.SCANS_DIR.resolve() and d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
    db.audit("target_deleted", t["value"])
    return {"ok": True}


@app.post("/api/assets")
def add_asset(body: AssetIn):
    """BR-V06: manual IP/host. Needs its own attestation because it may sit outside the target's namespace."""
    err = rules.check_authorisation(body.attested, body.basis)
    if err:
        _bad(err)
    t = db.one("SELECT * FROM targets WHERE id=?", (body.target_id,))
    if not t or t["status"] == "revoked":
        _bad("choose an active target")
    p = rules.parse_one(body.value)
    if p.error:
        _bad(f"{body.value[:60]}: {p.error}")
    if p.kind == "ip":
        kind = "ip"
    else:
        kind = "subdomain" if t["kind"] == "domain" and rules.in_scope(t["value"], p.value) else "host"
    if db.one("SELECT 1 x FROM assets WHERE target_id=? AND host=?", (body.target_id, p.value)):
        _bad("that asset already exists for this target", 409)
    db.run("INSERT INTO assets(target_id, host, kind, ips, source, note, created_at) VALUES (?,?,?,?,?,?,?)",
           (body.target_id, p.value, kind, json.dumps([p.value] if kind == "ip" else []), "manual",
            p.warning, rules.now()))
    db.audit("asset_added", f"{p.value} ({kind}) to {t['value']}; basis: {body.basis.strip()[:200]}")

    def probe_one() -> None:
        ips = [p.value] if kind == "ip" else discovery._resolve(p.value)
        if any(rules.forbidden_ip(i) for i in ips):
            # BR-V04: same rule as discovery: keep only safe addresses, exclude the asset, never probe it
            db.run("UPDATE assets SET ips=?, excluded=1, note=? WHERE target_id=? AND host=?",
                   (json.dumps([i for i in ips if not rules.forbidden_ip(i)]),
                    "Resolves to a forbidden address range (link-local, multicast or reserved); excluded.",
                    body.target_id, p.value))
            return
        db.run("UPDATE assets SET ips=? WHERE target_id=? AND host=?", (json.dumps(ips), body.target_id, p.value))
        discovery._apply_probe(body.target_id, p.value, discovery._probe([p.value]).get(p.value))

    threading.Thread(target=probe_one, daemon=True).start()
    return {"ok": True, "value": p.value, "kind": kind, "warning": p.warning}


@app.post("/api/assets/{aid}/exclude")
def exclude(aid: int, request: Request):
    a = db.one("SELECT excluded, host FROM assets WHERE id=?", (aid,))
    if not a:
        _bad("unknown asset", 404)
    new = 0 if a["excluded"] else 1
    db.run("UPDATE assets SET excluded=? WHERE id=?", (new, aid))
    if new:                                                  # BR-V11: excluding an asset stops its pending work too
        for sc in db.q("SELECT id FROM scans WHERE asset_id=? AND status IN ('queued','running')", (aid,)):
            runner.cancel(sc["id"])
    db.audit("asset_excluded" if new else "asset_included", a["host"])
    return {"excluded": bool(new)}


@app.post("/api/scans")
def create_scans(body: ScanIn):
    try:
        res = runner.enqueue(body.asset_ids, body.profile, body.force)
    except ValueError as exc:
        _bad(str(exc))
    return res


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: int):
    if not runner.cancel(sid):
        _bad("that scan is not queued or running", 409)
    return {"ok": True}


@app.get("/api/scans/{sid}")
def scan_detail(sid: int, offset: int = 0):
    s = db.one("SELECT s.*, a.host, a.url FROM scans s JOIN assets a ON a.id=s.asset_id WHERE s.id=?", (sid,))
    if not s:
        _bad("unknown scan", 404)
    log = config.SCANS_DIR / str(sid) / "scan.log"
    text, size = "", 0
    if log.exists():
        raw = log.read_bytes()
        size = len(raw)
        text = runner.clean_log(raw[max(0, offset):].decode("utf-8", "replace"))
    findings = db.q("SELECT severity, title, detail, status FROM findings WHERE scan_id=? ORDER BY "
                    "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id", (sid,))
    prev = db.one("SELECT id FROM scans WHERE asset_id=? AND status='done' AND id<? ORDER BY finished_at DESC LIMIT 1",
                  (s["asset_id"], sid))
    resolved = []
    if prev and s["status"] in ("done", "timeout"):
        cur = {f["severity"] + "::" for f in findings}  # noqa: F841 - placeholder to keep keys symmetrical
        cur_keys = {r["key"] for r in db.q("SELECT key FROM findings WHERE scan_id=?", (sid,))}
        resolved = [r for r in db.q("SELECT severity, title, detail, key FROM findings WHERE scan_id=?", (prev["id"],))
                    if r["key"] not in cur_keys]
        for r in resolved:
            r.pop("key", None)
    s["counts"] = db.jl(s["counts"], {})
    s.pop("dir", None)
    s.pop("report", None)
    return {"scan": s, "log": text, "next_offset": size, "findings": findings, "resolved": resolved}


@app.get("/api/scans/{sid}/report")
def report(sid: int):
    s = db.one("SELECT report FROM scans WHERE id=?", (sid,))
    if not s or not s["report"]:
        _bad("no report for this scan", 404)
    p = Path(s["report"]).resolve()
    if config.SCANS_DIR.resolve() not in p.parents or not p.is_file():
        _bad("report not found", 404)
    return FileResponse(p, media_type="text/markdown", filename=f"vapt-scan-{sid}.md",
                        headers={"Content-Disposition": f'attachment; filename="vapt-scan-{sid}.md"'})


def _latest_findings() -> list[dict]:
    return db.q("""
        SELECT f.severity, f.title, f.detail, f.status, a.host, a.id AS asset_id, s.id AS scan_id, s.finished_at
        FROM findings f JOIN scans s ON s.id=f.scan_id JOIN assets a ON a.id=f.asset_id
        WHERE s.id = (SELECT id FROM scans WHERE asset_id=a.id AND status IN ('done','timeout')
                      ORDER BY finished_at DESC LIMIT 1)
        ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, a.host""")


@app.get("/api/findings")
def findings():
    return {"findings": _latest_findings()}


def _csv_cell(v) -> str:
    """BR-V22: spreadsheet formula injection guard (target-controlled text ends up in this file)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/export")
def export(fmt: str = "csv"):
    rows = _latest_findings()
    if fmt == "json":
        return Response(json.dumps(rows, indent=2), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="vapt-findings.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "host", "finding", "detail", "status", "scan_id", "finished_at"])
    for r in rows:
        w.writerow([_csv_cell(r[k]) for k in ("severity", "host", "title", "detail", "status", "scan_id", "finished_at")])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="vapt-findings.csv"'})


@app.get("/api/audit")
def audit(limit: int = 200):
    return {"audit": db.q("SELECT ts, action, detail FROM audit ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),))}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


def main() -> None:
    import os
    import webbrowser

    import uvicorn
    config.AUTH_TOKEN = secrets.token_urlsafe(32)
    config.DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(config.DATA, 0o700)                                # the DB, logs and token are private to you
    url = f"http://{config.HOST}:{config.PORT}/?t={config.AUTH_TOKEN}"
    f = config.DATA / "launch_url.txt"
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(url + "\n")
    os.chmod(f, 0o600)
    print(f"\nVAPT Console is running. Open this link (it carries this launch's key):\n\n  {url}\n", flush=True)
    if os.environ.get("VAPT_UI_NO_BROWSER") != "1":
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - opening a browser is a convenience only
            pass
    uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="warning")


if __name__ == "__main__":
    main()
