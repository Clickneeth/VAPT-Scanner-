import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="vaptui-test-")
os.environ["VAPT_UI_DATA"] = _tmp                     # must be set before vaptui.config is imported
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from vaptui import config, db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    if config.DB_PATH.exists():
        config.DB_PATH.unlink()
    import shutil
    shutil.rmtree(config.SCANS_DIR, ignore_errors=True)
    db.init()
    # never start real tools from tests
    from vaptui import discovery, runner
    monkeypatch.setattr(discovery, "start", lambda tid: None)
    monkeypatch.setattr(runner, "start", lambda: None)
    # tests use made-up hostnames: resolve them to a public documentation-range address (never real DNS)
    monkeypatch.setattr(runner.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    yield


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from vaptui.server import app
    c = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", headers={"X-VAPT-UI": "1"})
    return c
