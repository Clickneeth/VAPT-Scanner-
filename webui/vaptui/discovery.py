"""Passive subdomain discovery + liveness probe for one target (runs in a worker thread)."""
from __future__ import annotations

import json
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import config, db, rules


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


def _is_wildcard(domain: str) -> bool:
    """BR-V10: a domain that resolves a random label answers for everything; its subdomains are not evidence."""
    return bool(_resolve(f"{secrets.token_hex(8)}-vapt-probe.{domain}"))


def _subfinder(domain: str) -> list[str]:
    exe = shutil.which("subfinder")
    if not exe:
        return []
    try:
        r = subprocess.run(
            [exe, "-d", domain, "-silent", "-timeout", "15", "-max-time", "2"],
            capture_output=True, text=True, timeout=config.DISCOVERY_TIMEOUT_S, check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    return r.stdout.splitlines()


def _probe(hosts: list[str]) -> dict[str, dict]:
    """httpx (ProjectDiscovery) liveness + title/server/tech for each host. Read-only GETs."""
    exe = shutil.which("httpx")
    if not exe or not hosts:
        return {}
    with tempfile.TemporaryDirectory() as td:
        lst = Path(td) / "h.txt"
        lst.write_text("\n".join(hosts) + "\n")
        try:
            r = subprocess.run(
                [exe, "-l", str(lst), "-silent", "-json", "-timeout", "8", "-threads", "25", "-retries", "1",
                 "-status-code", "-title", "-web-server", "-tech-detect", "-follow-redirects", "-rate-limit", "50"],
                capture_output=True, text=True, timeout=config.DISCOVERY_TIMEOUT_S, check=False,
            )
        except subprocess.TimeoutExpired:
            return {}
    out: dict[str, dict] = {}
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        inp = str(j.get("input", "")).lower()
        if inp and inp not in out:
            out[inp] = j
    return out


def _upsert_asset(target_id: int, host: str, kind: str, source: str, ips: list[str], wildcard: bool) -> None:
    # BR-V04: a hostname that resolves into a never-scanned class (e.g. 169.254.169.254) keeps only its safe
    # addresses, and the asset is marked excluded so it cannot be scanned by accident.
    safe = [i for i in ips if not rules.forbidden_ip(i)]
    blocked = len(safe) != len(ips)
    note = "Resolves to a forbidden address range (link-local, multicast or reserved); excluded." if blocked else ""
    db.run(
        "INSERT INTO assets(target_id, host, kind, ips, source, wildcard, excluded, note, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id, host) DO UPDATE SET ips=excluded.ips, "
        "wildcard=excluded.wildcard, excluded=MAX(assets.excluded, excluded.excluded), note=excluded.note",
        (target_id, host, kind, json.dumps(safe), source, int(wildcard), int(blocked), note, rules.now()),
    )


def _still_discovering(target_id: int) -> bool:
    """BR-V11: a revoke during discovery must stop the work and must never be overwritten."""
    t = db.one("SELECT status FROM targets WHERE id=?", (target_id,))
    return bool(t and t["status"] == "discovering")


def _apply_probe(target_id: int, host: str, j: dict | None) -> None:
    if not j:
        return
    url = str(j.get("url", ""))[:300]
    if not url.startswith(("http://", "https://")):
        return
    db.run(
        "UPDATE assets SET alive=1, url=?, status_code=?, title=?, server=?, tech=? WHERE target_id=? AND host=?",
        (url, j.get("status_code"), str(j.get("title", ""))[:200], str(j.get("webserver", ""))[:100],
         json.dumps([str(t)[:40] for t in (j.get("tech") or [])][:12]), target_id, host),
    )


def discover(target_id: int) -> None:
    t = db.one("SELECT * FROM targets WHERE id=?", (target_id,))
    if not t or t["status"] == "revoked":
        return
    if db.execute("UPDATE targets SET status='discovering', error='' WHERE id=? AND status<>'revoked'", (target_id,)) != 1:
        return
    db.audit("discovery_started", t["value"])
    try:
        if t["kind"] == "ip":
            _upsert_asset(target_id, t["value"], "ip", "target", [t["value"]], False)
            _apply_probe(target_id, t["value"], _probe([t["value"]]).get(t["value"]))
        else:
            domain = t["value"]
            wildcard = _is_wildcard(domain)
            found = _subfinder(domain)
            if not _still_discovering(target_id):
                return
            names = rules.clean_subdomains(domain, [domain] + found)
            hosts: dict[str, list[str]] = {}
            with ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(_resolve, h): h for h in names}
                for f in as_completed(futs, timeout=config.DISCOVERY_TIMEOUT_S):
                    hosts[futs[f]] = f.result()
            for h in names:
                kind = "root" if h == domain else "subdomain"
                # BR-V10: with a wildcard zone only the root is trusted as 'real'; others are flagged
                _upsert_asset(target_id, h, kind, "target" if kind == "root" else "discovery",
                              hosts.get(h, []), wildcard and kind != "root")
            if not _still_discovering(target_id):
                return
            probed = _probe([h for h in names if hosts.get(h)])
            if not _still_discovering(target_id):
                return
            for h in names:
                _apply_probe(target_id, h, probed.get(h))
            if wildcard:
                db.run("UPDATE targets SET warning=? WHERE id=?",
                       ("Wildcard DNS: every name resolves, so discovered subdomains are flagged and may not be real.",
                        target_id))
        db.execute("UPDATE targets SET status='ready', discovered_at=? WHERE id=? AND status='discovering'",
                   (rules.now(), target_id))
        n = db.one("SELECT COUNT(*) c FROM assets WHERE target_id=?", (target_id,))["c"]
        db.audit("discovery_done", f"{t['value']}: {n} assets")
    except Exception as exc:  # noqa: BLE001 - a failed discovery must never crash the server
        db.execute("UPDATE targets SET status='failed', error=? WHERE id=? AND status='discovering'",
                   (str(exc)[:300], target_id))
        db.audit("discovery_failed", f"{t['value']}: {exc}")


def start(target_id: int) -> None:
    threading.Thread(target=discover, args=(target_id,), daemon=True, name=f"discover-{target_id}").start()
