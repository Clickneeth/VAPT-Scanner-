"""The bash scanner itself: input hardening and the reachability gate (no real traffic: tools skipped, .invalid host)."""
import os
import subprocess
from pathlib import Path

import pytest

from vaptui import config

ALL_TOOLS = "whois,dig,subfinder,curl,nmap,ffuf,httpx,katana,nuclei,testssl.sh,nikto"


def run_script(tmp_path: Path, target: str, skip: str = ALL_TOOLS, extra_env: dict | None = None):
    env = {**os.environ, "TERM": "xterm", "VAPT_SKIP_TOOLS": skip, "VAPT_FINDINGS_FILE": str(tmp_path / "f.tsv"),
           **(extra_env or {})}
    return subprocess.run(["bash", str(config.SCANNER)], input=f"{target}\ny\n", text=True, cwd=tmp_path, env=env,
                          capture_output=True, timeout=120)


@pytest.mark.parametrize("target", ["-n", "https://-x", "http://@evil", "a;b", "$(id)", "a b|c", "`id`"])
def test_BRV23_hostile_targets_refused_before_any_tool_runs(tmp_path, target):
    r = run_script(tmp_path, target)
    assert r.returncode == 1
    assert not list(tmp_path.glob("vapt_output_*")), "no output folder for a refused target"


@pytest.mark.parametrize("target", ["example.com", "10.0.0.1", "https://ex.com/p?q=1"])
def test_BRV23_normal_targets_accepted(tmp_path, target):
    r = run_script(tmp_path, target)           # all tools skipped: only the input stage runs
    assert "Target  :" in r.stdout and "not allowed" not in r.stdout


def test_BRV24_unreachable_host_stops_at_gate_with_exit_3_and_no_findings(tmp_path):
    """Regression: 'curl || echo 000' produced '000000' and the gate failed open, reporting findings for dead hosts."""
    r = run_script(tmp_path, "gate-test.invalid", skip="whois,dig,subfinder")
    assert r.returncode == 3, r.stdout[-400:]
    assert "unreachable" in r.stdout.lower()
    assert not (tmp_path / "f.tsv").exists() or (tmp_path / "f.tsv").read_text() == ""
    assert "MODULE 3" not in r.stdout, "later modules must not run"


def test_BRV25_hostile_banner_cannot_inject_terminal_or_markdown(tmp_path):
    """add_finding is the single choke point for target-controlled text."""
    sh = tmp_path / "t.sh"
    body = Path(config.SCANNER).read_text()
    helpers = body[body.index("sanitize()"):body.index("# ─── Built-in wordlist")]
    fn = body[body.index("add_finding() {"):body.index("# ─── Input")]
    sh.write_text('CYAN=;RESET=;GREEN=;YELLOW=;RED=\nFINDINGS=()\n' + helpers + fn +
                  "add_finding HIGH $'x\\033[2J|<img src=x>[a](http://e)`' $'d\\nline2'\nprintf '%s\\n' \"${FINDINGS[0]}\"\n")
    r = subprocess.run(["bash", str(sh)], capture_output=True, text=True, env={**os.environ, "VAPT_FINDINGS_FILE": str(tmp_path / "o.tsv")})
    out = r.stdout.splitlines()[-1]
    assert "\x1b" not in r.stdout and "<img" not in out and "](" not in out and "`" not in out and "|" not in out.split("|", 2)[2]
    tsv = (tmp_path / "o.tsv").read_text()
    assert "\x1b" not in tsv and tsv.count("\t") == 2 and tsv.count("\n") == 1, "one clean line per finding"
