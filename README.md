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

## Usage
```bash
bash vapt_scanner.sh
```

## Modules
1. Recon — whois, dig
2. Headers — curl headers, CORS, HTTP methods
3. Ports — nmap port + SSL scan
4. Fuzzing — ffuf directory fuzzing
5. Tech — httpx tech detection
6. Crawl — katana + waybackurls
7. Vuln Scan — nuclei templates
