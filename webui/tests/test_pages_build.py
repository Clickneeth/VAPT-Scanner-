"""docs/ (the GitHub Pages front page) is generated; it must never drift from the real console UI."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _build(tmp_path):
    spec = importlib.util.spec_from_file_location("build_pages", ROOT / "scripts" / "build_pages.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.build(tmp_path)


def test_docs_matches_a_fresh_build(tmp_path):
    _build(tmp_path)
    for f in tmp_path.iterdir():
        assert (ROOT / "docs" / f.name).read_text() == f.read_text(), f"docs/{f.name} is stale: run python3 scripts/build_pages.py"


def test_pages_demo_never_scans_or_calls_out():
    demo = (ROOT / "webui" / "demo" / "demo.js").read_text()
    assert "XMLHttpRequest" not in demo and "sendBeacon" not in demo and "WebSocket" not in demo
    assert "realFetch(input, init)" in demo, "only non-/api/ calls may pass through, and the app makes none"
    html = (ROOT / "docs" / "index.html").read_text()
    assert "/static/" not in html and 'src="demo.js"' in html and "Live demo" in (ROOT / "docs" / "demo.js").read_text()
