"""All limits in one place (business rules reference these names)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]            # ~/vapt-scanner
WEBUI = ROOT / "webui"
SCANNER = ROOT / "vapt_scanner.sh"
DATA = Path(os.environ.get("VAPT_UI_DATA", WEBUI / "data"))
DB_PATH = DATA / "console.db"
SCANS_DIR = DATA / "scans"

LAUNCH_CODE: str | None = None                        # one-time code in the launch link; consumed by the first exchange
SESSION_TOKEN: str | None = None                      # the cookie value after that exchange; None means nothing is authorised
HOST = "127.0.0.1"                                    # BR-V01: never listen on anything but loopback
PORT = int(os.environ.get("VAPT_UI_PORT", "8770"))

MAX_TARGETS_PER_DROP = 50                             # BR-V05
MAX_SUBDOMAINS_PER_TARGET = 500                       # BR-V09
MAX_BULK_SCAN = 200                                   # BR-V14
MAX_QUEUE = 500                                       # BR-V14
MAX_CONCURRENT_SCANS = int(os.environ.get("VAPT_UI_CONCURRENCY", "2"))   # BR-V15
SCAN_COOLDOWN_S = int(os.environ.get("VAPT_UI_COOLDOWN", "300"))         # BR-V13
DISCOVERY_TIMEOUT_S = 180                             # BR-V08
MIN_BASIS_CHARS = 10                                  # BR-V03
TOTAL_MODULES = 10

# BR-V16: scan profiles. Only non-intrusive tools exist here; there is no sqlmap/dalfox profile.
PROFILES = {
    "quick": {
        "label": "Quick",
        "blurb": "Headers, ports, tech, nuclei. About 5 to 10 minutes.",
        "skip": ["subfinder", "ffuf", "katana", "nikto", "testssl.sh"],
        "timeout_s": 900,
    },
    "standard": {
        "label": "Standard",
        "blurb": "Adds directory fuzzing, crawl and TLS audit. About 10 to 25 minutes.",
        "skip": ["subfinder", "nikto"],
        "timeout_s": 1800,
    },
    "deep": {
        "label": "Deep",
        "blurb": "Everything including nikto. Slowest, noisiest, up to 40 minutes.",
        "skip": ["subfinder"],
        "timeout_s": 2700,
    },
}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
