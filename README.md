# VAPT Interactive Scanner

An interactive bash-based VAPT L4 scanner implementing smart sequential scanning logic.

## Author
G. Shankar Praneeth (126015102)

## Tools Used
- `whois`, `dig` — Reconnaissance
- `curl` — Header analysis
- `nmap` — Port scanning
- `ffuf` — Directory fuzzing
- `httpx` — Tech detection
- `katana`, `waybackurls` — URL crawling
- `nuclei` — Vulnerability scanning
- `testssl.sh` — TLS/SSL audit (protocols, ciphers, certificate, known TLS flaws)
- `nikto` — Web server scan (dangerous files, misconfiguration; DoS tests excluded)

## Responsible use

This is a security testing tool. Run it only against systems you own or have explicit written permission to test.
Unauthorised scanning is illegal in most countries. The console asks for an authorisation basis and keeps an audit log,
but you are responsible for how you use it. Provided as is, with no warranty.

## Usage
```bash
bash vapt_scanner.sh
```

## Modules
1. Recon — whois, dig, subfinder
2. Reachability gate
3. Headers — curl headers, CORS, HTTP methods
4. Ports — nmap port + SSL scan
5. Fuzzing — ffuf directory fuzzing
6. Tech — httpx tech detection
7. Crawl — katana + waybackurls
8. Vuln Scan — nuclei templates
9. TLS Audit — testssl.sh (only when HTTPS is present)
10. Web Server Scan — nikto (capped at 4 minutes)

## Web console (webui/)

A local, loopback-only UI around `vapt_scanner.sh`: drop targets, map every subdomain first, then choose what to scan.

```bash
webui/run.sh          # first run creates webui/venv; it prints (and opens) a launch link with a per-launch key
```

1. **Scope**: paste or drop domains and IPs, tick the authorisation box and state your basis (stored in the audit log).
   Domains are mapped passively (subfinder, DNS, httpx liveness). Nothing is scanned yet.
2. **Assets**: every discovered host with IPs, status, title and tech. Scan one, a selection, or all live hosts with a
   Quick / Standard / Deep profile. Add extra IPs or hosts (each needs its own attestation).
3. **Scans**: live progress, log, findings and what changed since the previous scan of that asset.
4. **Findings**: latest result per asset, filter by severity, export CSV or JSON.

Business rules (each has a `test_BRVxx_` test in `webui/tests/`): loopback only and no cross-site writes (V01, V02),
authorisation attestation with a written basis (V03), link-local/multicast/reserved IPs refused (V04), subdomains kept
only if truly under the target (V07), wildcard DNS flagged (V10), revoke stops scanning (V11), per-asset cooldown (V13),
bulk and queue caps (V14), concurrency limit and one scan per asset (V15), no intrusive profile (V16), crash-safe state
(V17), hard timeouts and cancel (V18), finding de-duplication and new/resolved diff (V19), risk score (V20), audit log
(V21), CSV formula-injection guard (V22), hostile target input refused (V23), unreachable hosts report nothing (V24),
hostile banners cannot inject terminal or Markdown (V25). Revoke and exclude hold even between queueing and launch,
and a hostname that resolves to a never-scanned range is excluded and re-checked right before launch (V04, V11).

Every launch generates a random key: the link carries it once, then a strict-same-site cookie keeps you signed in, so
other local users or processes cannot drive the console (V26). The key file is `webui/data/launch_url.txt` (mode 0600).

Tests: `cd webui && venv/bin/pytest -q`. Only scan systems you are authorised to test.
