from datetime import datetime, timedelta, timezone

from vaptui import config, rules


def test_BRV04_link_local_multicast_reserved_never_scanned():
    for bad in ["169.254.169.254", "224.0.0.1", "0.0.0.0", "240.0.0.1"]:
        assert rules.parse_one(bad).error, bad


def test_BRV04_private_and_loopback_allowed_with_warning():
    for ok in ["10.1.2.3", "192.168.0.9", "127.0.0.1"]:
        p = rules.parse_one(ok)
        assert not p.error and p.kind == "ip" and p.warning


def test_BRV05_url_credentials_and_paths_are_dropped():
    p = rules.parse_one("https://admin:hunter2@Example.COM:8443/login?x=1#f")
    assert p.value == "example.com" and p.kind == "domain"
    assert "hunter2" not in p.value


def test_BRV05_duplicates_collapse_and_invalid_flagged():
    out = rules.parse_targets("a.com, A.com\nhttps://a.com/x  nope_domain  1.2.3.4")
    vals = [p.value or p.raw for p in out]
    assert vals.count("a.com") == 1
    assert any(p.error for p in out if p.raw == "nope_domain")
    assert any(p.kind == "ip" and p.value == "1.2.3.4" for p in out)


def test_BRV05_drop_is_capped():
    text = "\n".join(f"h{i}.example.com" for i in range(config.MAX_TARGETS_PER_DROP + 5))
    out = rules.parse_targets(text)
    assert sum(1 for p in out if p.error) == 5


def test_BRV05_single_label_and_flag_like_hosts_rejected():
    for bad in ["localhost", "com", "-n", "a..b.com", "exa_mple.com", "-x.example.com"]:
        parsed = rules.parse_targets(bad)
        assert not parsed or all(p.error for p in parsed), bad


def test_BRV03_authorisation_needs_attestation_and_basis():
    assert rules.check_authorisation(False, "Written permission from the CISO")
    assert rules.check_authorisation(True, "short")
    assert rules.check_authorisation(True, "   ") != ""
    assert rules.check_authorisation(True, "Written permission from the CISO") == ""


def test_BRV07_scope_is_true_subdomain_only():
    assert rules.in_scope("example.com", "example.com")
    assert rules.in_scope("example.com", "a.b.example.com")
    assert not rules.in_scope("example.com", "evilexample.com")
    assert not rules.in_scope("example.com", "example.com.evil.net")


def test_BRV07_clean_subdomains_drops_foreign_wildcards_and_dupes():
    got = rules.clean_subdomains("example.com", ["*.example.com", "a.example.com", "A.example.com",
                                                 "evil.net", "x.example.com.evil.net", "b.example.com"])
    assert got == ["a.example.com", "b.example.com", "example.com"]


def test_BRV09_subdomain_cap():
    names = [f"s{i}.example.com" for i in range(config.MAX_SUBDOMAINS_PER_TARGET + 40)]
    assert len(rules.clean_subdomains("example.com", names)) == config.MAX_SUBDOMAINS_PER_TARGET


def test_BRV13_cooldown():
    now = datetime.now(timezone.utc)
    assert rules.cooldown_remaining(None) == 0
    recent = (now - timedelta(seconds=30)).isoformat()
    assert 0 < rules.cooldown_remaining(recent, now) <= config.SCAN_COOLDOWN_S - 29
    old = (now - timedelta(seconds=config.SCAN_COOLDOWN_S + 5)).isoformat()
    assert rules.cooldown_remaining(old, now) == 0


def test_BRV19_finding_key_ignores_numbers_and_case():
    a = rules.finding_key("high", "Open port 8080 on host")
    b = rules.finding_key("HIGH", "open PORT 9090 on host")
    assert a == b
    assert rules.finding_key("LOW", "x") != rules.finding_key("HIGH", "x")


def test_BRV19_diff():
    d = rules.diff_findings(["a", "b"], ["b", "c"])
    assert d == {"new": ["c"], "open": ["b"], "resolved": ["a"]}


def test_BRV20_risk_score_weighted_and_capped():
    assert rules.risk_score({}) == 0
    assert rules.risk_score({"HIGH": 2, "LOW": 3}) == 13
    assert rules.risk_score({"CRITICAL": 99}) == 100
    assert rules.risk_label(0) == "clean" and rules.risk_label(60) == "critical"


def test_BRV16_no_intrusive_profile_exists():
    skipped = " ".join(" ".join(p["skip"]) for p in config.PROFILES.values())
    assert "sqlmap" not in config.PROFILES and "dalfox" not in config.PROFILES
    assert all("subfinder" in p["skip"] for p in config.PROFILES.values()), "discovery already ran in step 1"
    assert "ffuf" in skipped


def test_BRV04_ipv4_mapped_ipv6_forms_cannot_smuggle_metadata_address():
    for bad in ["::ffff:169.254.169.254", "[::ffff:169.254.169.254]", "::ffff:0.0.0.0", "fe80::1", "ff02::1"]:
        assert rules.parse_one(bad).error, bad
    assert rules.forbidden_ip("::ffff:169.254.169.254") and rules.forbidden_ip("not-an-ip")
    assert not rules.forbidden_ip("93.184.216.34")
    p = rules.parse_one("::ffff:10.0.0.5")
    assert p.value == "10.0.0.5" and p.warning
