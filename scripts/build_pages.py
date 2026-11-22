#!/usr/bin/env python3
"""Builds docs/ (the GitHub Pages front page) from the real console's static files plus the demo backend.

    python3 scripts/build_pages.py [--out docs]

The page is the SAME app.js and app.css as the real console; demo.js swaps the backend for an in-browser simulation.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC, DEMO = ROOT / "webui" / "static", ROOT / "webui" / "demo"


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name in ("app.js", "app.css"):
        shutil.copyfile(STATIC / name, out / name)
    for name in ("demo.js", "demo.css"):
        shutil.copyfile(DEMO / name, out / name)
    html = (STATIC / "index.html").read_text()
    html = html.replace('href="/static/app.css"', 'href="app.css">\n<link rel="stylesheet" href="demo.css"')
    html = html.replace('<script src="/static/app.js" defer></script>',
                        '<script src="demo.js"></script>\n<script src="app.js" defer></script>')
    html = html.replace("<title>VAPT Console</title>", "<title>VAPT Console: scan a target</title>"
                        '\n<meta name="description" content="Enter a domain or IP. The console maps its subdomains, then scans every live host. Live demo with simulated data; the real scanner runs on your own machine.">')
    html = html.replace("local · loopback only", "live demo · simulated")
    assert "/static/" not in html, "unrewritten asset path"
    (out / "index.html").write_text(html)
    (out / ".nojekyll").write_text("")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs"))
    build(Path(ap.parse_args().out))
    print("built", ap.parse_args().out)
