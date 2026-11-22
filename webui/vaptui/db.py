"""SQLite store. One short-lived connection per call, guarded by a lock (the runner uses threads)."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from . import config, rules

_LOCK = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'new',          -- new | discovering | ready | failed | revoked
  basis TEXT NOT NULL, authorised_at TEXT NOT NULL, created_at TEXT NOT NULL,
  discovered_at TEXT, error TEXT DEFAULT '', warning TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id),
  host TEXT NOT NULL, kind TEXT NOT NULL,       -- root | subdomain | ip | host
  ips TEXT NOT NULL DEFAULT '[]', alive INTEGER NOT NULL DEFAULT 0, url TEXT DEFAULT '',
  status_code INTEGER, title TEXT DEFAULT '', server TEXT DEFAULT '', tech TEXT NOT NULL DEFAULT '[]',
  source TEXT NOT NULL DEFAULT 'discovery',     -- discovery | target | manual
  excluded INTEGER NOT NULL DEFAULT 0, wildcard INTEGER NOT NULL DEFAULT 0, note TEXT DEFAULT '',
  created_at TEXT NOT NULL, UNIQUE(target_id, host));
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id), profile TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',        -- queued | running | done | failed | cancelled | timeout
  queued_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, module INTEGER NOT NULL DEFAULT 0,
  risk INTEGER NOT NULL DEFAULT 0, counts TEXT NOT NULL DEFAULT '{}', error TEXT DEFAULT '',
  dir TEXT DEFAULT '', report TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id), asset_id INTEGER NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open');         -- new | open (vs the previous finished scan of the asset)
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_assets_target ON assets(target_id);
CREATE INDEX IF NOT EXISTS ix_scans_asset ON scans(asset_id);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
"""


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    with _LOCK:
        config.DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
        c = sqlite3.connect(config.DB_PATH, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()


def init() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        # a crash or restart must not leave phantom running scans (BR-V17)
        c.execute("UPDATE scans SET status='failed', error='server restarted while running', finished_at=? "
                  "WHERE status IN ('running')", (rules.now(),))
        c.execute("UPDATE targets SET status='failed', error='server restarted during discovery' "
                  "WHERE status='discovering'")


def q(sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def one(sql: str, args: tuple = ()) -> dict[str, Any] | None:
    rows = q(sql, args)
    return rows[0] if rows else None


def run(sql: str, args: tuple = ()) -> int:
    with conn() as c:
        return c.execute(sql, args).lastrowid or 0


def execute(sql: str, args: tuple = ()) -> int:
    """Like run() but returns the affected row count: lets callers make conditional, atomic state changes."""
    with conn() as c:
        return c.execute(sql, args).rowcount


def audit(action: str, detail: str) -> None:
    """BR-V21: every state-changing action leaves a trail."""
    run("INSERT INTO audit(ts, action, detail) VALUES (?,?,?)", (rules.now(), action, detail[:500]))


def jl(s: str | None, default: Any) -> Any:
    try:
        return json.loads(s) if s else default
    except ValueError:
        return default
