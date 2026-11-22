#!/usr/bin/env bash
# VAPT Interactive Scanner — G. Shankar Praneeth
# Only run against targets you have explicit written authorization to test.

set -euo pipefail

# ─── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*"; }
banner()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}"; echo -e "${BOLD} $*${RESET}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}"; }

# ─── Built-in wordlist (embedded so ffuf always has something) ──────────────
WORDLIST_FILE="$(mktemp /tmp/vapt_wordlist.XXXXXX)"
cat >"$WORDLIST_FILE" <<'WORDS'
admin
login
dashboard
api
v1
v2
config
backup
uploads
static
assets
images
js
css
src
test
dev
staging
robots.txt
sitemap.xml
.env
.git
.htaccess
phpinfo.php
wp-admin
wp-login.php
wp-config.php
administrator
panel
manage
console
portal
register
signup
forgot-password
reset-password
profile
account
user
users
search
contact
about
help
faq
terms
privacy
news
blog
shop
store
cart
checkout
payment
invoice
export
import
download
upload
file
files
docs
documentation
api/v1
api/v2
api/v3
graphql
swagger
swagger-ui
swagger.json
openapi.json
health
status
metrics
actuator
debug
trace
logs
log
error
errors
hidden
secret
secrets
private
internal
server-status
server-info
info
phpMyAdmin
phpmyadmin
adminer
database
db
sql
WORDS

# ─── Cleanup on exit ────────────────────────────────────────────────────────
cleanup() { rm -f "$WORDLIST_FILE"; }
trap cleanup EXIT

# ─── Helper: require tool ───────────────────────────────────────────────────
require() {
  if ! command -v "$1" &>/dev/null; then
    warn "Tool '$1' not found — skipping this step."
    return 1
  fi
  return 0
}

# ─── Helper: run a command with a hard wall-clock cap (macOS has no `timeout`) ──
run_capped() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) & local watchdog=$!
  local rc=0; wait "$pid" 2>/dev/null || rc=$?
  kill "$watchdog" 2>/dev/null || true; wait "$watchdog" 2>/dev/null || true
  return "$rc"
}

# ─── Report helpers ─────────────────────────────────────────────────────────
REPORT_FILE=""
FINDINGS=()   # severity|title|detail

report_line() { echo "$1" >> "$REPORT_FILE"; }

add_finding() {
  local sev="$1" title="$2" detail="$3"
  FINDINGS+=("${sev}|${title}|${detail}")
  case "$sev" in
    CRITICAL) error  "[CRITICAL] $title — $detail" ;;
    HIGH)     error  "[HIGH]     $title — $detail" ;;
    MEDIUM)   warn   "[MEDIUM]   $title — $detail" ;;
    LOW)      warn   "[LOW]      $title — $detail" ;;
    INFO)     info   "[INFO]     $title — $detail" ;;
  esac
}

# ─── Input ──────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${RED}"
cat <<'LOGO'
 __   __ _   ____  _____
 \ \ / // | |  _ \|_   _|
  \ V / | | | |_) | | |
   \_/  |_| |____/  |_|
  Interactive VAPT Scanner
LOGO
echo -e "${RESET}"
echo -e "${YELLOW}IMPORTANT: Only scan targets you have explicit written authorization to test.${RESET}\n"

read -rp "$(echo -e "${BOLD}Enter target URL or IP (e.g. https://example.com or 192.168.1.1): ${RESET}")" RAW_TARGET

if [[ -z "$RAW_TARGET" ]]; then
  error "No target provided. Exiting."
  exit 1
fi

# Normalise: strip trailing slash
RAW_TARGET="${RAW_TARGET%/}"

# Derive host (strip scheme)
HOST="${RAW_TARGET#http://}"; HOST="${HOST#https://}"; HOST="${HOST%%/*}"

# Derive base URL with scheme
if [[ "$RAW_TARGET" =~ ^https?:// ]]; then
  BASE_URL="$RAW_TARGET"
else
  BASE_URL="http://$RAW_TARGET"
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="vapt_report_${HOST//:/_}_${TIMESTAMP}.md"
OUTPUT_DIR="vapt_output_${HOST//:/_}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo -e "\n${BOLD}Target  : ${CYAN}$BASE_URL${RESET}"
echo -e "${BOLD}Host    : ${CYAN}$HOST${RESET}"
echo -e "${BOLD}Report  : ${CYAN}$REPORT_FILE${RESET}"
echo -e "${BOLD}Outputs : ${CYAN}$OUTPUT_DIR/${RESET}\n"

read -rp "$(echo -e "${YELLOW}Confirm you are authorised to scan this target? [y/N]: ${RESET}")" CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { error "Aborted."; exit 1; }

# ─── Init report ────────────────────────────────────────────────────────────
{
  echo "# VAPT Scan Report — $HOST"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Target | \`$BASE_URL\` |"
  echo "| Scan started | $(date) |"
  echo "| Scanner | VAPT Interactive Scanner v2 |"
  echo ""
  echo "---"
} > "$REPORT_FILE"

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1 — RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 1 — RECONNAISSANCE"
report_line "## 1. Reconnaissance"
report_line ""

# WHOIS
if require whois; then
  info "Running whois..."
  WHOIS_OUT="$OUTPUT_DIR/whois.txt"
  whois "$HOST" > "$WHOIS_OUT" 2>&1 || true
  REGISTRAR=$(grep -i "registrar:" "$WHOIS_OUT" 2>/dev/null | head -1 | awk -F: '{print $2}' | xargs || echo "n/a")
  EXPIRY=$(grep -i "expir" "$WHOIS_OUT" 2>/dev/null | head -1 | awk -F: '{print $2}' | xargs || echo "n/a")
  success "Registrar: $REGISTRAR | Expiry: $EXPIRY"
  report_line "### WHOIS"
  report_line "\`\`\`"
  head -40 "$WHOIS_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# DNS
if require dig; then
  info "Running DNS enumeration..."
  DNS_OUT="$OUTPUT_DIR/dns.txt"
  {
    echo "=== A Records ==="; dig +short A "$HOST" 2>/dev/null
    echo "=== MX Records ==="; dig +short MX "$HOST" 2>/dev/null
    echo "=== NS Records ==="; dig +short NS "$HOST" 2>/dev/null
    echo "=== TXT Records ==="; dig +short TXT "$HOST" 2>/dev/null
    echo "=== AAAA Records ==="; dig +short AAAA "$HOST" 2>/dev/null
  } | tee "$DNS_OUT"
  report_line "### DNS Records"
  report_line "\`\`\`"
  cat "$DNS_OUT" >> "$REPORT_FILE"
  report_line "\`\`\`"
  report_line ""

  # Check for zone transfer
  info "Testing DNS zone transfer..."
  NS_LIST=$(dig +short NS "$HOST" 2>/dev/null)
  for ns in $NS_LIST; do
    ZONE=$(dig @"$ns" "$HOST" AXFR 2>/dev/null | head -5)
    if [[ "$ZONE" != *"Transfer failed"* && -n "$ZONE" ]]; then
      add_finding "CRITICAL" "DNS Zone Transfer Allowed" "NS $ns exposes full zone for $HOST"
    fi
  done
fi

# Subdomain enumeration
if require subfinder; then
  info "Running subdomain enumeration with subfinder..."
  SUB_OUT="$OUTPUT_DIR/subdomains.txt"
  subfinder -d "$HOST" -silent -timeout 15 -max-time 2 -o "$SUB_OUT" 2>/dev/null || true
  SUB_COUNT=$(wc -l < "$SUB_OUT" 2>/dev/null || echo 0)
  success "Found $SUB_COUNT subdomains → $SUB_OUT"
  report_line "### Subdomains (subfinder)"
  report_line "\`\`\`"
  cat "$SUB_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2 — REACHABILITY CHECK (stage gate)
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 2 — REACHABILITY CHECK"
report_line "## 2. Reachability"
report_line ""

info "Checking if target is reachable..."
HTTP_CODE=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$BASE_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "000" ]]; then
  error "Target is unreachable (no response). Stopping scan."
  add_finding "INFO" "Target unreachable" "$BASE_URL returned no response"
  report_line "**Target unreachable — scan aborted at reachability gate.**"
  report_line ""
  echo "Report saved: $REPORT_FILE"
  exit 1
fi

success "Target responded with HTTP $HTTP_CODE"
report_line "Target responded with HTTP **$HTTP_CODE**"
report_line ""

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3 — SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 3 — SECURITY HEADERS"
report_line "## 3. Security Headers"
report_line ""

if require curl; then
  info "Fetching response headers..."
  HEADERS_OUT="$OUTPUT_DIR/headers.txt"
  curl -sk --max-time 15 -I "$BASE_URL" -o "$HEADERS_OUT" 2>/dev/null || \
    curl -sk --max-time 15 -I "${BASE_URL/https/http}" -o "$HEADERS_OUT" 2>/dev/null || true

  # Parse headers into lowercase for easy grep
  HEADERS_LC=$(tr '[:upper:]' '[:lower:]' < "$HEADERS_OUT" 2>/dev/null || true)

  report_line "| Header | Status | Severity |"
  report_line "|---|---|---|"

  check_header() {
    local header="$1" sev="$2" label="$3"
    if echo "$HEADERS_LC" | grep -q "^${header}"; then
      success "$label: present"
      report_line "| $label | ✅ Present | — |"
    else
      add_finding "$sev" "Missing header: $label" "$BASE_URL does not set $label"
      report_line "| $label | ❌ Missing | $sev |"
    fi
  }

  check_header "content-security-policy"        "HIGH"   "Content-Security-Policy"
  check_header "strict-transport-security"       "HIGH"   "Strict-Transport-Security"
  check_header "x-frame-options"                "MEDIUM" "X-Frame-Options"
  check_header "x-content-type-options"         "MEDIUM" "X-Content-Type-Options"
  check_header "referrer-policy"                "LOW"    "Referrer-Policy"
  check_header "permissions-policy"             "LOW"    "Permissions-Policy"

  # Server version disclosure
  SERVER_HDR=$(grep -i "^server:" "$HEADERS_OUT" 2>/dev/null | head -1 || true)
  if [[ -n "$SERVER_HDR" ]]; then
    VERSION=$(echo "$SERVER_HDR" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
    if [[ -n "$VERSION" ]]; then
      add_finding "MEDIUM" "Server version disclosed" "$SERVER_HDR"
    fi
  fi

  # X-Powered-By disclosure
  POWERED=$(grep -i "^x-powered-by:" "$HEADERS_OUT" 2>/dev/null | head -1 || true)
  [[ -n "$POWERED" ]] && add_finding "LOW" "X-Powered-By header present" "$POWERED"

  report_line ""
  report_line "### Raw Headers"
  report_line "\`\`\`"
  cat "$HEADERS_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""

  # CORS check
  info "Checking CORS misconfiguration..."
  CORS_OUT=$(curl -sk --max-time 10 -H "Origin: https://evil.com" -I "$BASE_URL" 2>/dev/null || true)
  ACAO=$(echo "$CORS_OUT" | grep -i "access-control-allow-origin:" | head -1 || true)
  if echo "$ACAO" | grep -q "evil.com\|\*"; then
    add_finding "HIGH" "CORS misconfiguration" "Server reflects arbitrary Origin or allows wildcard: $ACAO"
  else
    success "CORS: no wildcard/reflection detected"
  fi

  # HTTP methods
  info "Checking allowed HTTP methods..."
  METHODS_OUT=$(curl -sk --max-time 10 -X OPTIONS -I "$BASE_URL" 2>/dev/null | grep -i "allow:" || true)
  if echo "$METHODS_OUT" | grep -qiE "PUT|DELETE|TRACE|CONNECT"; then
    add_finding "MEDIUM" "Dangerous HTTP methods allowed" "$METHODS_OUT"
  else
    success "HTTP methods: $METHODS_OUT"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4 — PORT SCAN
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 4 — PORT SCAN"
report_line "## 4. Port Scan"
report_line ""

if require nmap; then
  NMAP_OUT="$OUTPUT_DIR/nmap.txt"
  info "Running nmap top-1000 ports + service detection + SSL audit..."
  nmap -sV -sC --script ssl-enum-ciphers,http-title,http-methods \
       --open -T4 "$HOST" -oN "$NMAP_OUT" 2>/dev/null || true
  success "Nmap scan complete → $NMAP_OUT"

  # Flag dangerous open ports
  DANGER_PORTS="21|22|23|25|3306|5432|6379|27017|9200|5900"
  OPEN_DANGER=$(grep -E "^[0-9]+/(tcp|udp).*open" "$NMAP_OUT" 2>/dev/null | grep -E "$DANGER_PORTS" || true)
  if [[ -n "$OPEN_DANGER" ]]; then
    while IFS= read -r line; do
      add_finding "HIGH" "Sensitive port open" "$line"
    done <<< "$OPEN_DANGER"
  fi

  report_line "\`\`\`"
  cat "$NMAP_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5 — DIRECTORY FUZZING
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 5 — DIRECTORY FUZZING"
report_line "## 5. Directory Fuzzing"
report_line ""

if require ffuf; then
  FFUF_OUT="$OUTPUT_DIR/ffuf.json"
  info "Fuzzing directories with ffuf (${BOLD}$(wc -l < "$WORDLIST_FILE")${RESET} words)..."
  ffuf -u "${BASE_URL}/FUZZ" \
       -w "$WORDLIST_FILE" \
       -mc 200,201,204,301,302,307,401,403 \
       -of json -o "$FFUF_OUT" \
       -t 40 -timeout 10 \
       -s 2>/dev/null || true

  # Parse results
  if [[ -f "$FFUF_OUT" ]]; then
    FOUND_PATHS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$FFUF_OUT'))
    results = d.get('results', [])
    for r in results:
        print(f\"{r['status']}  {r['url']}\")
except:
    pass
" 2>/dev/null || true)

    if [[ -n "$FOUND_PATHS" ]]; then
      success "Discovered paths:"
      echo "$FOUND_PATHS"
      # Flag sensitive paths
      while IFS= read -r line; do
        PATH_URL=$(echo "$line" | awk '{print $2}')
        STATUS=$(echo "$line" | awk '{print $1}')
        if echo "$PATH_URL" | grep -qiE "\.env|\.git|backup|config|admin|secret|phpmy|adminer|database"; then
          add_finding "HIGH" "Sensitive path exposed ($STATUS)" "$PATH_URL"
        fi
      done <<< "$FOUND_PATHS"
    else
      success "No directories found."
    fi

    report_line "\`\`\`"
    echo "$FOUND_PATHS" >> "$REPORT_FILE" 2>/dev/null || true
    report_line "\`\`\`"
    report_line ""
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 6 — TECH DETECTION
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 6 — TECH DETECTION"
report_line "## 6. Technology Detection"
report_line ""

if require httpx; then
  HTTPX_OUT="$OUTPUT_DIR/httpx.txt"
  info "Running httpx tech detection..."
  echo "$BASE_URL" | httpx -tech-detect -status-code -title -follow-redirects \
                            -silent -o "$HTTPX_OUT" 2>/dev/null || true
  success "Tech detection:"
  cat "$HTTPX_OUT" 2>/dev/null || true
  report_line "\`\`\`"
  cat "$HTTPX_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 7 — WEB CRAWL
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 7 — WEB CRAWL"
report_line "## 7. Web Crawl"
report_line ""

if require katana; then
  KATANA_OUT="$OUTPUT_DIR/katana.txt"
  info "Crawling with katana (depth 3)..."
  katana -u "$BASE_URL" -d 3 -silent -o "$KATANA_OUT" 2>/dev/null || true
  CRAWL_COUNT=$(wc -l < "$KATANA_OUT" 2>/dev/null || echo 0)
  success "Crawled $CRAWL_COUNT URLs → $KATANA_OUT"

  # Flag interesting endpoints
  INTERESTING=$(grep -iE "\.(php|asp|aspx|jsp|cgi)|api/|admin|login|upload|export|import|sql|backup|debug" "$KATANA_OUT" 2>/dev/null || true)
  if [[ -n "$INTERESTING" ]]; then
    warn "Interesting endpoints found:"
    echo "$INTERESTING"
    add_finding "INFO" "Interesting endpoints crawled" "$(echo "$INTERESTING" | wc -l | xargs) endpoints — see katana.txt"
  fi

  report_line "\`\`\`"
  head -50 "$KATANA_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 8 — VULNERABILITY SCAN
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 8 — VULNERABILITY SCAN"
report_line "## 8. Vulnerability Scan (Nuclei)"
report_line ""

if require nuclei; then
  NUCLEI_OUT="$OUTPUT_DIR/nuclei.txt"
  info "Running nuclei (critical, high, medium templates)..."
  nuclei -u "$BASE_URL" \
         -severity critical,high,medium \
         -tags cve,misconfig,exposure,takeover \
         -silent -o "$NUCLEI_OUT" 2>/dev/null || true

  if [[ -s "$NUCLEI_OUT" ]]; then
    NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT")
    warn "Nuclei found $NUCLEI_COUNT issue(s):"
    cat "$NUCLEI_OUT"
    while IFS= read -r line; do
      SEV=$(echo "$line" | grep -oE '\[(critical|high|medium|low|info)\]' | tr -d '[]' | tr '[:lower:]' '[:upper:]' || echo "MEDIUM")
      add_finding "$SEV" "Nuclei: $line" "See nuclei.txt"
    done < "$NUCLEI_OUT"
  else
    success "No nuclei findings."
  fi

  report_line "\`\`\`"
  cat "$NUCLEI_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 9 — TLS / SSL AUDIT (testssl.sh)
# Runs only when the target is https or nmap saw 443 open. Read-only handshakes, no exploitation.
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 9 — TLS / SSL AUDIT"
report_line "## 9. TLS / SSL Audit (testssl.sh)"
report_line ""

TLS_TARGET=""
if [[ "$BASE_URL" =~ ^https:// ]]; then
  TLS_TARGET="$HOST"
elif grep -qE "^443/tcp[[:space:]]+open" "${NMAP_OUT:-/dev/null}" 2>/dev/null; then
  TLS_TARGET="${HOST}:443"
fi

if [[ -z "$TLS_TARGET" ]]; then
  info "No HTTPS service detected, skipping TLS audit."
  report_line "_Skipped: no HTTPS service detected._"
  report_line ""
elif require testssl.sh; then
  TLS_TXT="$OUTPUT_DIR/testssl.txt"
  TLS_CSV="$OUTPUT_DIR/testssl.csv"
  info "Running testssl.sh on $TLS_TARGET (protocols, ciphers, certificate, known TLS flaws; capped at 300s)..."
  run_capped 300 testssl.sh --quiet --color 0 --warnings off \
      --severity MEDIUM --overwrite --logfile "$TLS_TXT" --csvfile "$TLS_CSV" "$TLS_TARGET" >/dev/null 2>&1 || true

  if grep -q '"FATAL"' "$TLS_CSV" 2>/dev/null; then
    warn "testssl.sh aborted: $(grep '"FATAL"' "$TLS_CSV" | head -1 | cut -d'"' -f10 | cut -c1-120). See testssl.csv"
  elif [[ -s "$TLS_CSV" ]]; then
    TLS_ROWS=$(awk -F'","' 'NR>1 && ($4=="MEDIUM"||$4=="HIGH"||$4=="CRITICAL") {
        id=$1; gsub(/^"/,"",id); f=$5; gsub(/"$/,"",f); gsub(/\|/,"/",id); gsub(/\|/,"/",f);
        if (id=="security_headers") next;
        print $4 "|TLS: " id "|" f }' "$TLS_CSV" 2>/dev/null | sort -u | head -30 || true)
    if [[ -n "$TLS_ROWS" ]]; then
      while IFS='|' read -r SEV TITLE DETAIL; do
        add_finding "$SEV" "$TITLE" "$DETAIL"
      done <<< "$TLS_ROWS"
    else
      success "testssl.sh: nothing at MEDIUM or above."
    fi
  else
    warn "testssl.sh produced no results (target unreachable, or the 300s cap was hit)."
  fi

  report_line "\`\`\`"
  cat "$TLS_TXT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# MODULE 10 — WEB SERVER SCAN (nikto)
# Tuning 1,2,3,4,5,7,b,d,e: interesting files, misconfig, info disclosure, XSS/injection checks,
# file retrieval, software ID, web services, admin consoles. Excludes DoS (6) and file upload (0).
# ═══════════════════════════════════════════════════════════════════════════
banner "MODULE 10 — WEB SERVER SCAN"
report_line "## 10. Web Server Scan (Nikto)"
report_line ""

if require nikto; then
  NIKTO_OUT="$OUTPUT_DIR/nikto.txt"
  info "Running nikto (no DoS tests; capped at 240s)..."
  run_capped 270 nikto -h "$BASE_URL" -maxtime 240s -timeout 10 -nointeractive -ask no \
      -Tuning 123457bde -Format txt -output "$NIKTO_OUT" >/dev/null 2>&1 || true

  if [[ -s "$NIKTO_OUT" ]]; then
    NIKTO_ROWS=$(grep -E '^\+ ' "$NIKTO_OUT" 2>/dev/null \
      | grep -vE '^\+ (Target|Start Time|End Time|Server:|[0-9]+ host|[0-9]+ requests|No CGI|Scan terminated|Platform|SSL Info|Subject|Ciphers|Issuer|ERROR|GET Unable to connect|Unable to connect)' \
      | sed 's/^+ //; s/|/\//g' | head -25 || true)
    if [[ -n "$NIKTO_ROWS" ]]; then
      while IFS= read -r line; do
        if [[ "$line" =~ [Vv]ulnerab|CVE-|outdated|[Dd]efault|[Ee]xposed|[Dd]isclos ]]; then SEV="MEDIUM"; else SEV="LOW"; fi
        add_finding "$SEV" "Nikto: ${line:0:90}" "See nikto.txt"
      done <<< "$NIKTO_ROWS"
    else
      success "No nikto findings."
    fi
  else
    warn "nikto produced no output."
  fi

  report_line "\`\`\`"
  cat "$NIKTO_OUT" >> "$REPORT_FILE" 2>/dev/null || true
  report_line "\`\`\`"
  report_line ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# FINDINGS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
banner "FINDINGS SUMMARY"

{
  echo "## Findings Summary"
  echo ""
  echo "| # | Severity | Title | Detail |"
  echo "|---|---|---|---|"
} >> "$REPORT_FILE"

COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0; COUNT_LOW=0; COUNT_INFO=0

IDX=1
for finding in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
  IFS='|' read -r SEV TITLE DETAIL <<< "$finding"
  echo "| $IDX | **$SEV** | $TITLE | $DETAIL |" >> "$REPORT_FILE"
  case "$SEV" in
    CRITICAL) COUNT_CRIT=$((COUNT_CRIT + 1)) ;;
    HIGH)     COUNT_HIGH=$((COUNT_HIGH + 1)) ;;
    MEDIUM)   COUNT_MED=$((COUNT_MED + 1))   ;;
    LOW)      COUNT_LOW=$((COUNT_LOW + 1))   ;;
    INFO)     COUNT_INFO=$((COUNT_INFO + 1)) ;;
  esac
  IDX=$((IDX + 1))
done

{
  echo ""
  echo "### Counts"
  echo "| Severity | Count |"
  echo "|---|---|"
  echo "| 🔴 Critical | $COUNT_CRIT |"
  echo "| 🟠 High     | $COUNT_HIGH |"
  echo "| 🟡 Medium   | $COUNT_MED  |"
  echo "| 🔵 Low      | $COUNT_LOW  |"
  echo "| ⚪ Info     | $COUNT_INFO |"
  echo ""
  echo "---"
  echo "*Report generated by VAPT Interactive Scanner v2 — $(date)*"
} >> "$REPORT_FILE"

echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e " ${RED}Critical: $COUNT_CRIT${RESET}  ${YELLOW}High: $COUNT_HIGH${RESET}  Medium: $COUNT_MED  Low: $COUNT_LOW  Info: $COUNT_INFO"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "\n${GREEN}Report saved:${RESET}  $REPORT_FILE"
echo -e "${GREEN}Raw outputs: ${RESET}  $OUTPUT_DIR/"
