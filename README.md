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
