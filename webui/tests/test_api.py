import json
import time
from pathlib import Path

import pytest

from vaptui import config, db, rules, runner

GOOD = {"attested": True, "basis": "Written permission from the CISO, ticket 42"}


def add_target(client, text="example.com"):
    r = client.post("/api/targets", json={"text": text, **GOOD})
    assert r.status_code == 200, r.text
    return r.json()


def add_asset_row(target_id, host="a.example.com", **kw):
    return db.run("INSERT INTO assets(target_id, host, kind, created_at, alive, url) VALUES (?,?,?,?,?,?)",
                  (target_id, host, kw.get("kind", "subdomain"), rules.now(), 1, f"https://{host}"))


def test_BRV01_unknown_host_header_blocked(client):
    r = client.get("/api/meta", headers={"Host": "evil.com"})
    assert r.status_code == 400


def test_BRV02_writes_need_custom_header_and_same_origin(client):
    from fastapi.testclient import TestClient
    from vaptui.server import app
    bare = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", cookies={"vapt_session": "test-session-token"})
    assert bare.post("/api/parse", json={"text": "a.com"}).status_code == 403
    r = client.post("/api/parse", json={"text": "a.com"}, headers={"Origin": "http://evil.com"})
    assert r.status_code == 403
    r = client.post("/api/parse", json={"text": "a.com"}, headers={"Origin": f"http://127.0.0.1:{config.PORT}"})
    assert r.status_code == 200


def test_security_headers_and_no_inline_script(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "default-src 'none'" in csp
    assert "<script>" not in r.text.replace('<script src="/static/app.js" defer></script>', "")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_BRV03_targets_refused_without_attestation(client):
    r = client.post("/api/targets", json={"text": "example.com", "attested": False, "basis": "x" * 30})
    assert r.status_code == 400
    r = client.post("/api/targets", json={"text": "example.com", "attested": True, "basis": "short"})
    assert r.status_code == 400
    assert db.q("SELECT * FROM targets") == []


def test_BRV06_target_added_audited_and_duplicates_reported(client):
    out = add_target(client, "example.com 8.8.8.8 bad_one 169.254.169.254")
    assert [a["value"] for a in out["added"]] == ["example.com", "8.8.8.8"]
    assert len(out["rejected"]) == 2
    again = add_target(client, "example.com")
    assert again["duplicates"] == ["example.com"] and not again["added"]
    log = client.get("/api/audit").json()["audit"]
    assert any(a["action"] == "target_authorised" and "Written permission" in a["detail"] for a in log)


def test_BRV06_manual_asset_needs_its_own_attestation_and_validates(client):
    tid = add_target(client)["added"][0]["id"]
    body = {"target_id": tid, "value": "203.0.113.9"}
    assert client.post("/api/assets", json={**body, "attested": False, "basis": ""}).status_code == 400
    assert client.post("/api/assets", json={**body, "value": "169.254.169.254", **GOOD}).status_code == 400
    ok = client.post("/api/assets", json={**body, **GOOD})
    assert ok.status_code == 200 and ok.json()["kind"] == "ip"
    assert client.post("/api/assets", json={**body, **GOOD}).status_code == 409
    sub = client.post("/api/assets", json={"target_id": tid, "value": "api.example.com", **GOOD}).json()
    assert sub["kind"] == "subdomain"
    foreign = client.post("/api/assets", json={"target_id": tid, "value": "partner.net", **GOOD}).json()
    assert foreign["kind"] == "host"


def test_BRV12_enqueue_rules(client):
    tid = add_target(client)["added"][0]["id"]
    a1, a2, a3 = (add_asset_row(tid, f"h{i}.example.com") for i in range(3))
    db.run("UPDATE assets SET excluded=1 WHERE id=?", (a3,))
    r = client.post("/api/scans", json={"asset_ids": [a1, a2, a3, a1], "profile": "quick"}).json()
    assert len(r["queued"]) == 2
    assert r["skipped"][0]["reason"] == "excluded from scope"
    again = client.post("/api/scans", json={"asset_ids": [a1], "profile": "quick"}).json()
    assert again["skipped"][0]["reason"] == "already queued or running"
    assert client.post("/api/scans", json={"asset_ids": [a1], "profile": "nope"}).status_code == 400
    assert client.post("/api/scans", json={"asset_ids": []}).status_code == 400


def test_BRV13_cooldown_blocks_rescan_unless_forced(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = db.run("INSERT INTO scans(asset_id, profile, status, queued_at, finished_at) VALUES (?,?,?,?,?)",
                 (a, "quick", "done", rules.now(), rules.now()))
    r = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()
    assert not r["queued"] and "wait" in r["skipped"][0]["reason"]
    forced = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick", "force": True}).json()
    assert len(forced["queued"]) == 1 and sid


def test_BRV14_bulk_cap(client):
    tid = add_target(client)["added"][0]["id"]
    ids = [add_asset_row(tid, f"b{i}.example.com") for i in range(config.MAX_BULK_SCAN + 1)]
    assert client.post("/api/scans", json={"asset_ids": ids, "profile": "quick"}).status_code == 400


def test_BRV11_revoke_stops_scanning_and_cancels_queue(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    assert client.post(f"/api/targets/{tid}/revoke").status_code == 200
    assert db.one("SELECT status FROM scans WHERE id=?", (sid,))["status"] == "cancelled"
    r = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick", "force": True}).json()
    assert r["skipped"][0]["reason"].startswith("authorisation revoked")
    assert client.post(f"/api/targets/{tid}/discover").status_code == 400


def test_delete_target_removes_everything(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = db.run("INSERT INTO scans(asset_id, profile, status, queued_at) VALUES (?,?,?,?)", (a, "quick", "done", rules.now()))
    db.run("INSERT INTO findings(scan_id, asset_id, severity, title, detail, key) VALUES (?,?,?,?,?,?)", (sid, a, "HIGH", "t", "d", "k"))
    d = config.SCANS_DIR / str(sid)
    d.mkdir(parents=True)
    (d / "scan.log").write_text("x")
    assert client.delete(f"/api/targets/{tid}").status_code == 200
    assert not db.q("SELECT * FROM assets") and not db.q("SELECT * FROM findings") and not d.exists()


def test_BRV22_csv_export_neutralises_formulas(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = db.run("INSERT INTO scans(asset_id, profile, status, queued_at, finished_at) VALUES (?,?,?,?,?)", (a, "quick", "done", rules.now(), rules.now()))
    db.run("INSERT INTO findings(scan_id, asset_id, severity, title, detail, key) VALUES (?,?,?,?,?,?)",
           (sid, a, "HIGH", '=HYPERLINK("http://evil","x")', "+cmd|calc", "k"))
    body = client.get("/api/export?fmt=csv").text
    assert "'=HYPERLINK" in body and "'+cmd" in body
    assert json.loads(client.get("/api/export?fmt=json").text)[0]["severity"] == "HIGH"


def test_clean_log_strips_terminal_escapes():
    hostile = "ok \x1b[2J\x1b[31mred\x1b]0;title\x07 end\x00\r"
    out = runner.clean_log(hostile)
    assert "\x1b" not in out and "\x00" not in out and "\x07" not in out and "ok" in out


@pytest.mark.parametrize("host", ["-n", "a b", "x;rm", "a/b", "$(id)"])
def test_scan_target_arg_rejects_unsafe_hosts(host):
    with pytest.raises(ValueError):
        runner.scan_target_arg({"host": host, "url": ""})


def test_scan_target_arg_prefers_scheme_for_default_port():
    assert runner.scan_target_arg({"host": "a.example.com", "url": "https://a.example.com"}) == "https://a.example.com"
    assert runner.scan_target_arg({"host": "a.example.com", "url": "https://a.example.com:8443"}) == "a.example.com"
    assert runner.scan_target_arg({"host": "a.example.com", "url": "https://other.com"}) == "a.example.com"


def test_report_download_cannot_escape_scans_dir(client, tmp_path):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    secret = tmp_path / "secret.md"
    secret.write_text("nope")
    sid = db.run("INSERT INTO scans(asset_id, profile, status, queued_at, report) VALUES (?,?,?,?,?)", (a, "quick", "done", rules.now(), str(secret)))
    assert client.get(f"/api/scans/{sid}/report").status_code == 404


FAKE = """#!/usr/bin/env bash
read -r target; read -r ok
echo "got $target / $ok skip=$VAPT_SKIP_TOOLS"
echo "MODULE 1 — RECON"; echo $'\\033[31mhostile\\033[0m'
echo "MODULE 4 — PORT SCAN"
printf 'HIGH\\tSensitive port open\\t22/tcp open ssh\\n' >> "$VAPT_FINDINGS_FILE"
printf 'LOW\\tServer header\\tnginx 1.2\\n' >> "$VAPT_FINDINGS_FILE"
printf 'HIGH\\tSensitive port open\\t22/tcp open ssh\\n' >> "$VAPT_FINDINGS_FILE"
echo "# report" > vapt_report_x.md
"""


def run_fake(monkeypatch, tmp_path, body=FAKE):
    s = tmp_path / "fake.sh"
    s.write_text(body)
    monkeypatch.setattr(config, "SCANNER", s)


def wait_status(sid, want, secs=20):
    end = time.time() + secs
    while time.time() < end:
        st = db.one("SELECT status FROM scans WHERE id=?", (sid,))["status"]
        if st in want:
            return st
        time.sleep(0.05)
    raise AssertionError(db.one("SELECT * FROM scans WHERE id=?", (sid,)))


def test_BRV17_end_to_end_with_fake_scanner(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path)
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid, "a.example.com")
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick()
    assert wait_status(sid, {"done", "failed"}) == "done"
    row = db.one("SELECT * FROM scans WHERE id=?", (sid,))
    assert json.loads(row["counts"]) == {"HIGH": 1, "LOW": 1}, "duplicate findings collapse (BR-V19)"
    assert row["module"] == config.TOTAL_MODULES and row["risk"] == 6 and row["report"].endswith("vapt_report_x.md")
    det = client.get(f"/api/scans/{sid}").json()
    assert "got https://a.example.com / y" in det["log"]
    assert "skip=subfinder,ffuf,katana,nikto,testssl.sh" in det["log"], "profile skip list reaches the scanner"
    assert "\x1b" not in det["log"]
    assert client.get(f"/api/scans/{sid}/report").status_code == 200


def test_BRV19_second_scan_marks_new_and_resolved(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path)
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    s1 = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick(); wait_status(s1, {"done"})
    changed = FAKE.replace("Server header", "Brand new issue")
    run_fake(monkeypatch, tmp_path, changed)
    s2 = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick", "force": True}).json()["queued"][0]
    runner._tick(); wait_status(s2, {"done"})
    d = client.get(f"/api/scans/{s2}").json()
    by = {f["title"]: f["status"] for f in d["findings"]}
    assert by["Brand new issue"] == "new" and by["Sensitive port open"] == "open"
    assert [r["title"] for r in d["resolved"]] == ["Server header"]


def test_BRV15_concurrency_limit_and_one_per_asset(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\nsleep 30\n")
    monkeypatch.setattr(config, "MAX_CONCURRENT_SCANS", 2)
    tid = add_target(client)["added"][0]["id"]
    ids = [add_asset_row(tid, f"c{i}.example.com") for i in range(4)]
    sids = client.post("/api/scans", json={"asset_ids": ids, "profile": "quick"}).json()["queued"]
    runner._tick()
    time.sleep(0.5)
    states = [db.one("SELECT status FROM scans WHERE id=?", (s,))["status"] for s in sids]
    assert states.count("running") == 2 and states.count("queued") == 2
    for s in sids:
        runner.cancel(s)
    for s in sids:
        wait_status(s, {"cancelled"})


def test_BRV18_cancel_kills_running_scan_and_keeps_partial(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\nread a; read b\nprintf 'LOW\\tpartial\\tx\\n' >> \"$VAPT_FINDINGS_FILE\"\nsleep 60\n")
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick(); wait_status(sid, {"running"}); time.sleep(0.6)
    assert client.post(f"/api/scans/{sid}/cancel").status_code == 200
    assert wait_status(sid, {"cancelled"}) == "cancelled"
    assert db.one("SELECT COUNT(*) c FROM findings WHERE scan_id=?", (sid,))["c"] == 1


def test_BRV18_timeout_stops_scan(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\nsleep 60\n")
    monkeypatch.setitem(config.PROFILES["quick"], "timeout_s", 1)
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick()
    assert wait_status(sid, {"timeout", "failed"}, 30) == "timeout"


def test_BRV17_restart_marks_orphaned_running_scans_failed(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = db.run("INSERT INTO scans(asset_id, profile, status, queued_at) VALUES (?,?,?,?)", (a, "quick", "running", rules.now()))
    db.init()
    assert db.one("SELECT status FROM scans WHERE id=?", (sid,))["status"] == "failed"


def test_BRV24_exit_code_3_is_reported_as_no_web_response(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\nread a; read b\nprintf 'INFO\\tTarget unreachable\\tx\\n' >> \"$VAPT_FINDINGS_FILE\"\nexit 3\n")
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick()
    assert wait_status(sid, {"failed"}) == "failed"
    row = db.one("SELECT error FROM scans WHERE id=?", (sid,))
    assert "No web response" in row["error"]
    assert db.one("SELECT COUNT(*) c FROM findings WHERE scan_id=?", (sid,))["c"] == 0


# ---- security review round: revoke/exclude must hold at start time, discovery revoke sticks, DNS re-check ----

def test_BRV11_excluding_an_asset_cancels_its_queued_scan(client):
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    client.post(f"/api/assets/{a}/exclude")
    assert db.one("SELECT status FROM scans WHERE id=?", (sid,))["status"] == "cancelled"


def test_BRV11_tick_never_starts_a_scan_for_an_excluded_or_revoked_asset(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\ntouch started.flag\nsleep 5\n")
    tid = add_target(client)["added"][0]["id"]
    a1, a2 = add_asset_row(tid, "x1.example.com"), add_asset_row(tid, "x2.example.com")
    s1 = client.post("/api/scans", json={"asset_ids": [a1], "profile": "quick"}).json()["queued"][0]
    s2 = client.post("/api/scans", json={"asset_ids": [a2], "profile": "quick"}).json()["queued"][0]
    db.run("UPDATE assets SET excluded=1 WHERE id=?", (a1,))                   # lands after queueing, before start
    db.run("UPDATE targets SET status='revoked' WHERE id=?", (tid,))
    runner._tick()
    time.sleep(0.4)
    for sid in (s1, s2):
        row = db.one("SELECT status, error FROM scans WHERE id=?", (sid,))
        assert row["status"] == "cancelled" and "revoked" in row["error"]
    assert not list(config.SCANS_DIR.glob("*/started.flag")), "no scanner process may have been launched"


def test_BRV11_supervisor_rechecks_authorisation_before_launch(client, monkeypatch, tmp_path):
    """The window between the conditional UPDATE and Popen: revoke lands there, the process must not start."""
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\ntouch started.flag\nsleep 5\n")
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid)
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    db.run("UPDATE scans SET status='running', started_at=? WHERE id=?", (rules.now(), sid))   # as _tick would
    db.run("UPDATE targets SET status='revoked' WHERE id=?", (tid,))                           # the race
    runner._supervise(sid)
    assert db.one("SELECT status FROM scans WHERE id=?", (sid,))["status"] == "cancelled"
    assert not list(config.SCANS_DIR.glob("*/started.flag"))


def test_BRV04_forbidden_resolution_blocks_launch(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\ntouch started.flag\n")
    monkeypatch.setattr(runner.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))])
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid, "rebind.example.com")
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick()
    assert wait_status(sid, {"failed"}) == "failed"
    assert "never scanned" in db.one("SELECT error FROM scans WHERE id=?", (sid,))["error"]
    assert not list(config.SCANS_DIR.glob("*/started.flag"))


def test_BRV24_discovery_revoked_midway_is_not_overwritten(client, monkeypatch):
    from vaptui import discovery
    monkeypatch.undo()                                                           # use the real discovery.start/discover
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at) VALUES ('domain','example.com','b',?,?)",
                 (rules.now(), rules.now()))

    def revoke_while_enumerating(domain):
        db.run("UPDATE targets SET status='revoked' WHERE id=?", (tid,))
        return ["a.example.com"]

    monkeypatch.setattr(discovery, "_subfinder", revoke_while_enumerating)
    monkeypatch.setattr(discovery, "_is_wildcard", lambda d: False)
    monkeypatch.setattr(discovery, "_resolve", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(discovery, "_probe", lambda hs: (_ for _ in ()).throw(AssertionError("probed after revoke")))
    discovery.discover(tid)
    assert db.one("SELECT status FROM targets WHERE id=?", (tid,))["status"] == "revoked"
    assert not db.q("SELECT * FROM assets WHERE target_id=?", (tid,)), "no assets written after revoke"


def test_BRV04_discovered_host_resolving_to_metadata_range_is_excluded(client, monkeypatch):
    from vaptui import discovery
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at,status) VALUES ('domain','example.com','b',?,?,'discovering')",
                 (rules.now(), rules.now()))
    discovery._upsert_asset(tid, "meta.example.com", "subdomain", "discovery", ["169.254.169.254", "93.184.216.34"], False)
    row = db.one("SELECT * FROM assets WHERE host='meta.example.com'")
    assert row["excluded"] == 1 and json.loads(row["ips"]) == ["93.184.216.34"] and "forbidden" in row["note"]


def test_BRV04_unresolvable_host_fails_closed_before_launch(client, monkeypatch, tmp_path):
    run_fake(monkeypatch, tmp_path, "#!/usr/bin/env bash\ntouch started.flag\n")
    def boom(*a, **k):
        raise OSError("dns down")
    monkeypatch.setattr(runner.socket, "getaddrinfo", boom)
    tid = add_target(client)["added"][0]["id"]
    a = add_asset_row(tid, "nxdomain.example.com")
    sid = client.post("/api/scans", json={"asset_ids": [a], "profile": "quick"}).json()["queued"][0]
    runner._tick()
    assert wait_status(sid, {"failed"}) == "failed"
    assert "does not resolve" in db.one("SELECT error FROM scans WHERE id=?", (sid,))["error"]
    assert not list(config.SCANS_DIR.glob("*/started.flag"))


def test_BRV26_everything_needs_the_launch_token(client):
    from fastapi.testclient import TestClient
    from vaptui.server import app
    anon = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", headers={"X-VAPT-UI": "1"})
    assert anon.get("/api/state").status_code == 401
    assert anon.post("/api/targets", json={"text": "a.com", **GOOD}).status_code == 401
    assert anon.get("/").status_code == 401 and "launch URL" in anon.get("/").text
    wrong = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", cookies={"vapt_session": "nope"})
    assert wrong.get("/api/meta").status_code == 401
    assert anon.get("/static/app.css").status_code == 200, "static assets carry no data"
    assert db.q("SELECT * FROM targets") == []


def test_BRV26_launch_code_is_single_use_and_cookie_is_a_different_value(client):
    from fastapi.testclient import TestClient
    from vaptui.server import app
    c = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", follow_redirects=False)
    bad = c.get("/?t=wrong")
    assert bad.status_code == 401 and "set-cookie" not in bad.headers
    ok = c.get("/?t=test-launch-code")
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    cookie = ok.headers["set-cookie"]
    assert "httponly" in cookie.lower() and "samesite=lax" in cookie.lower()
    assert "test-launch-code" not in cookie and "test-session-token" in cookie, "cookie must not be the URL code"
    assert c.get("/api/meta").status_code == 200
    again = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", follow_redirects=False)
    assert again.get("/?t=test-launch-code").status_code == 401, "the link cannot be replayed"
    assert again.get("/api/meta").status_code == 401


def test_BRV26_server_with_no_token_set_refuses_everything(monkeypatch):
    from fastapi.testclient import TestClient
    from vaptui.server import app
    monkeypatch.setattr(config, "SESSION_TOKEN", None)
    monkeypatch.setattr(config, "LAUNCH_CODE", None)
    c = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", cookies={"vapt_session": ""})
    assert c.get("/api/meta").status_code == 401 and c.get("/?t=").status_code == 401


def test_BRV26_browser_is_opened_with_a_file_path_never_the_secret(tmp_path, monkeypatch):
    """`ps` shows process arguments to every local user, so the code must not be in them."""
    import vaptui.server as srv
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda u, *a, **k: opened.append(u) or True)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(config, "DATA", tmp_path)
    monkeypatch.delenv("VAPT_UI_NO_BROWSER", raising=False)
    srv.main()
    assert len(opened) == 1 and opened[0].startswith("file://") and "t=" not in opened[0]
    assert config.LAUNCH_CODE in (tmp_path / "launch.html").read_text()
    assert oct((tmp_path / "launch.html").stat().st_mode)[-3:] == "600" and oct((tmp_path / "launch_url.txt").stat().st_mode)[-3:] == "600"
    assert config.SESSION_TOKEN != config.LAUNCH_CODE


def test_BRV04_probe_result_that_connected_to_a_forbidden_ip_is_dropped_and_excluded():
    from vaptui import discovery
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at,status) VALUES ('domain','example.com','b',?,?,'ready')", (rules.now(), rules.now()))
    discovery._upsert_asset(tid, "rebound.example.com", "subdomain", "discovery", ["93.184.216.34"], False)
    discovery._apply_probe(tid, "rebound.example.com", {"url": "https://rebound.example.com", "status_code": 200,
                                                         "title": "metadata!", "host_ip": "169.254.169.254"})
    row = db.one("SELECT alive, excluded, url, title, note FROM assets WHERE host='rebound.example.com'")
    assert row["alive"] == 0 and row["excluded"] == 1 and row["url"] == "" and row["title"] == ""
    assert "forbidden" in row["note"]
    discovery._upsert_asset(tid, "fine.example.com", "subdomain", "discovery", ["93.184.216.34"], False)
    discovery._apply_probe(tid, "fine.example.com", {"url": "https://fine.example.com", "status_code": 200, "host_ip": "93.184.216.34", "a": ["93.184.216.34"]})
    assert db.one("SELECT alive FROM assets WHERE host='fine.example.com'")["alive"] == 1


def test_BRV04_manual_host_resolving_to_forbidden_range_is_excluded_not_probed(client, monkeypatch):
    from vaptui import discovery
    probed = []
    monkeypatch.setattr(discovery, "_resolve", lambda h: ["169.254.169.254"])
    monkeypatch.setattr(discovery, "_probe", lambda hs: probed.append(hs) or {})
    tid = add_target(client)["added"][0]["id"]
    assert client.post("/api/assets", json={"target_id": tid, "value": "meta.example.com", **GOOD}).status_code == 200
    end = time.time() + 5
    while time.time() < end and not db.one("SELECT excluded FROM assets WHERE host='meta.example.com'")["excluded"]:
        time.sleep(0.05)
    row = db.one("SELECT excluded, ips, note FROM assets WHERE host='meta.example.com'")
    assert row["excluded"] == 1 and json.loads(row["ips"]) == [] and "forbidden" in row["note"]
    assert probed == [], "the probe must never run against it"


def test_BRV04_probe_never_follows_redirects():
    src = (Path(__file__).resolve().parents[1] / "vaptui" / "discovery.py").read_text()
    assert "-follow-redirects" not in src


# ---- Quick Scan: enter a target, scanning starts ----

def _quick(client, text="example.com", attested=True, profile="quick"):
    return client.post("/api/quickscan", json={"text": text, "attested": attested, "profile": profile})


def test_BRV27_quickscan_needs_the_tick_and_validates(client):
    assert _quick(client, attested=False).status_code == 400
    assert _quick(client, profile="nope").status_code == 400
    assert _quick(client, text="  ").status_code == 400
    r = _quick(client, "example.com 169.254.169.254 bad_one").json()
    assert [t["value"] for t in r["started"]] == ["example.com"] and len(r["rejected"]) == 2
    t = db.one("SELECT auto_scan, basis FROM targets WHERE value='example.com'")
    assert t["auto_scan"] == "quick" and "Self-attested" in t["basis"]
    log = client.get("/api/audit").json()["audit"]
    assert any("quick scan" in a["detail"] for a in log)
    assert _quick(client, "example.com").json()["duplicates"] == ["example.com"]


def test_BRV27_quickscan_refuses_a_revoked_target(client):
    tid = _quick(client).json()["started"][0]["id"]
    client.post(f"/api/targets/{tid}/revoke")
    r = _quick(client).json()
    assert not r["started"] and "revoked" in r["rejected"][0]["error"]


def test_BRV28_auto_scan_picks_only_live_in_scope_real_hosts():
    rows = [dict(id=1, kind="root", host="a.com", alive=1, excluded=0, wildcard=0),
            dict(id=2, kind="subdomain", host="z.a.com", alive=1, excluded=0, wildcard=0),
            dict(id=3, kind="subdomain", host="b.a.com", alive=1, excluded=0, wildcard=0),
            dict(id=4, kind="subdomain", host="dead.a.com", alive=0, excluded=0, wildcard=0),
            dict(id=5, kind="subdomain", host="ex.a.com", alive=1, excluded=1, wildcard=0),
            dict(id=6, kind="subdomain", host="wild.a.com", alive=1, excluded=0, wildcard=1)]
    assert rules.auto_scan_asset_ids(rows) == [1, 3, 2]


def test_BRV28_auto_scan_cap():
    rows = [dict(id=i, kind="subdomain", host=f"h{i:04d}.a.com", alive=1, excluded=0, wildcard=0) for i in range(config.MAX_BULK_SCAN + 30)]
    assert len(rules.auto_scan_asset_ids(rows)) == config.MAX_BULK_SCAN


def test_BRV28_discovery_finishing_queues_scans_for_live_hosts_only(client, monkeypatch):
    from vaptui import discovery
    monkeypatch.undo()                                                          # real discover(), stubbed tools
    monkeypatch.setattr(runner.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(discovery, "_subfinder", lambda d: ["www.example.com", "dead.example.com"])
    monkeypatch.setattr(discovery, "_is_wildcard", lambda d: False)
    monkeypatch.setattr(discovery, "_resolve", lambda h: ["93.184.216.34"])
    probe = lambda hs: {h: {"url": f"https://{h}", "status_code": 200, "host_ip": "93.184.216.34"} for h in hs if h != "dead.example.com"}  # noqa: E731
    monkeypatch.setattr(discovery, "_probe", probe)
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at,auto_scan) VALUES ('domain','example.com','b',?,?,'standard')", (rules.now(), rules.now()))
    discovery.discover(tid)
    hosts = [r["host"] for r in db.q("SELECT a.host FROM scans s JOIN assets a ON a.id=s.asset_id WHERE s.status='queued' ORDER BY s.id")]
    assert hosts == ["example.com", "www.example.com"], "root first, dead host skipped"
    assert {r["profile"] for r in db.q("SELECT profile FROM scans")} == {"standard"}


def test_BRV28_manual_targets_are_never_auto_scanned(client, monkeypatch):
    from vaptui import discovery
    monkeypatch.undo()
    monkeypatch.setattr(discovery, "_subfinder", lambda d: [])
    monkeypatch.setattr(discovery, "_is_wildcard", lambda d: False)
    monkeypatch.setattr(discovery, "_resolve", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(discovery, "_probe", lambda hs: {h: {"url": f"https://{h}", "status_code": 200} for h in hs})
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at) VALUES ('domain','example.com','b',?,?)", (rules.now(), rules.now()))
    discovery.discover(tid)
    assert db.q("SELECT * FROM scans") == []


def test_BRV28_revoked_before_discovery_ends_means_no_scans(client, monkeypatch):
    from vaptui import discovery
    monkeypatch.undo()
    def revoke_midway(domain):
        db.run("UPDATE targets SET status='revoked' WHERE id=1")
        return ["a.example.com"]
    monkeypatch.setattr(discovery, "_subfinder", revoke_midway)
    monkeypatch.setattr(discovery, "_is_wildcard", lambda d: False)
    monkeypatch.setattr(discovery, "_resolve", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(discovery, "_probe", lambda hs: {h: {"url": f"https://{h}", "status_code": 200} for h in hs})
    tid = db.run("INSERT INTO targets(kind,value,basis,authorised_at,created_at,auto_scan) VALUES ('domain','example.com','b',?,?,'quick')", (rules.now(), rules.now()))
    assert tid == 1
    discovery.discover(tid)
    assert db.q("SELECT * FROM scans") == []


def test_BRV26_lax_cookie_still_blocks_cross_site_writes(client):
    """Lax cookies ride along on cross-site top-level GETs, so writes must still be refused without our header/origin."""
    from fastapi.testclient import TestClient
    from vaptui.server import app
    c = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", cookies={"vapt_session": "test-session-token"})
    assert c.post("/api/quickscan", json={"text": "a.com", "attested": True}).status_code == 403
    assert c.post("/api/quickscan", json={"text": "a.com", "attested": True}, headers={"X-VAPT-UI": "1", "Origin": "http://evil.com"}).status_code == 403
    assert c.get("/api/state").status_code == 200, "reads are idempotent and carry no secrets beyond what the page shows"
    assert db.q("SELECT * FROM targets") == []
