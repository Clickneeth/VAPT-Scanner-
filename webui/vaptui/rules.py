"""Pure business logic: no I/O, so every rule is unit-tested (tests/test_rules.py)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import config

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_SPLIT = re.compile(r"[\s,;]+")


@dataclass
class Parsed:
    raw: str
    kind: str = ""          # "domain" | "ip"
    value: str = ""
    warning: str = ""
    error: str = ""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_host(raw: str) -> str:
    """Pull a bare host out of 'https://user:pw@Host.com:8080/path?x'. Credentials are dropped, never stored."""
    s = raw.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):                                  # [v6]:port
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:                                 # host:port
        s = s.split(":", 1)[0]
    return s.strip(".")


def parse_one(raw: str) -> Parsed:
    p = Parsed(raw=raw)
    host = clean_host(raw)
    if not host:
        p.error = "empty"
        return p
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        # BR-V04: addresses that are never a legitimate scan target
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            p.error = "address class is never scanned (unspecified, multicast, link-local such as cloud metadata, reserved)"
            return p
        p.kind, p.value = "ip", str(ip)
        if ip.is_private or ip.is_loopback:
            p.warning = "private/loopback address: only your own lab or an authorised internal network"
        return p
    if len(host) > 253 or not DOMAIN_RE.match(host):
        p.error = "not a valid domain or IP address"
        return p
    p.kind, p.value = "domain", host
    return p


def parse_targets(text: str) -> list[Parsed]:
    """BR-V05: one drop may hold many targets; duplicates collapse; capped at MAX_TARGETS_PER_DROP."""
    seen: set[str] = set()
    out: list[Parsed] = []
    for tok in _SPLIT.split(text or ""):
        if not tok or tok.startswith("#"):
            continue
        p = parse_one(tok)
        key = p.value or p.raw
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    if len(out) > config.MAX_TARGETS_PER_DROP:
        for p in out[config.MAX_TARGETS_PER_DROP:]:
            p.error = f"over the limit of {config.MAX_TARGETS_PER_DROP} targets per drop"
        out = out[: config.MAX_TARGETS_PER_DROP] + [p for p in out[config.MAX_TARGETS_PER_DROP:]]
    return out


def check_authorisation(attested: bool, basis: str) -> str:
    """BR-V03: nothing is added without an explicit attestation and a written basis."""
    if not attested:
        return "You must confirm you are authorised to test these targets."
    if len((basis or "").strip()) < config.MIN_BASIS_CHARS:
        return f"Describe your authorisation (at least {config.MIN_BASIS_CHARS} characters): who permitted it, or which program."
    return ""


def in_scope(target_domain: str, host: str) -> bool:
    """BR-V07: a discovered host belongs to a target only if it IS the domain or a true subdomain of it."""
    host = host.lower().strip(".")
    d = target_domain.lower().strip(".")
    return host == d or host.endswith("." + d)


def clean_subdomains(target_domain: str, names: list[str]) -> list[str]:
    """BR-V07/V09: keep only in-scope valid hostnames, no wildcards, de-duplicated, capped."""
    out: list[str] = []
    seen: set[str] = set()
    for n in names:
        h = clean_host(n)
        if h.startswith("*."):
            h = h[2:]
        if not DOMAIN_RE.match(h) or not in_scope(target_domain, h) or h in seen:
            continue
        seen.add(h)
        out.append(h)
    out.sort()
    return out[: config.MAX_SUBDOMAINS_PER_TARGET]


def parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def cooldown_remaining(last_finished: str | None, at: datetime | None = None) -> int:
    """BR-V13: seconds until this asset may be scanned again (0 = allowed)."""
    t = parse_ts(last_finished)
    if t is None:
        return 0
    at = at or datetime.now(timezone.utc)
    left = config.SCAN_COOLDOWN_S - int((at - t).total_seconds())
    return max(0, left)


def finding_key(severity: str, title: str) -> str:
    """BR-V19: stable identity of a finding across scans (numbers and timestamps are noise)."""
    t = re.sub(r"\d+", "#", title.lower())
    return f"{severity.upper()}::{t.strip()}"


def diff_findings(previous: list[str], current: list[str]) -> dict[str, list[str]]:
    """BR-V19: what is new, still open, or resolved compared with the previous completed scan."""
    prev, cur = set(previous), set(current)
    return {"new": sorted(cur - prev), "open": sorted(cur & prev), "resolved": sorted(prev - cur)}


def risk_score(counts: dict[str, int]) -> int:
    """BR-V20: 0 to 100, weighted by severity and capped."""
    raw = sum(config.SEV_WEIGHT.get(k.upper(), 0) * v for k, v in counts.items())
    return min(100, raw)


def risk_label(score: int) -> str:
    if score >= 50:
        return "critical"
    if score >= 20:
        return "high"
    if score >= 6:
        return "medium"
    return "low" if score > 0 else "clean"


def normalise_severity(sev: str) -> str:
    s = (sev or "").upper().strip()
    return s if s in config.SEVERITIES else "INFO"
