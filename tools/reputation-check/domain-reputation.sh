#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Package Profiler Contributors
#
# domain-reputation.sh
# Checks domain reputation via DNSBL lookups, MX IP blocklist queries,
# WHOIS domain age, SPF/DKIM/DMARC records, and nameserver health.
# Accepts a domain name, email address, file, or delimited list.
#
# Companion script to the Package Profiler suite — designed to vet domains
# extracted from package metadata: author email domains, homepage URLs, source
# repository hosts, and download mirror domains appearing in SBOM / meta.json.
#
# Usage:
#   ./domain-reputation.sh [OPTIONS] <domain|email|file|->
#   ./domain-reputation.sh example.com
#   ./domain-reputation.sh user@example.com     (domain extracted from email)
#   ./domain-reputation.sh "a.com, b.com"
#   ./domain-reputation.sh domains.txt
#   echo "example.com" | ./domain-reputation.sh -
#
# Options:
#   -a, --min-age DAYS       Flag domains younger than N days (default: 30)
#       --warn-age DAYS      Warn (not hard-flag) below N days (default: 3×min-age)
#   -j, --json               JSON output to stdout (requires jq)
#   -sj, -js                 Silent + JSON — pipe-friendly
#   -s, --silent             Suppress all output except verdicts
#   -q, --quiet              Alias for --silent
#   -v, --verbose            Show additional diagnostic detail
#       --skip-whois         Skip WHOIS domain age check (avoids rate limits)
#       --skip-ip-dnsbl      Skip MX IP blocklist check (faster)
#       --version            Print version and exit
#   -h, --help               Show this help
#
# Exit codes:
#   0  All domains passed
#   1  One or more domains flagged as FLAGGED or SUSPICIOUS
#   2  Dependency missing or argument error
#
# VERDICT MODEL:
#   CLEAN       Passed all hard checks; advisory notes may be present
#   SUSPICIOUS  Domain confirmed too young (below --min-age threshold)
#   FLAGGED     Listed on one or more domain or IP DNSBLs
#
#   Hard flags change the verdict; advisory (warn) flags are reported but
#   do not affect the exit code.  This distinction prevents noisy failures
#   on legitimate domains that simply lack DMARC or have a single nameserver.
#
# JSON OUTPUT:
#   -j / -sj emit a single JSON document with a "domain_reputation" root key.
#   When multiple domains are checked, all results appear in "results[]".
#   Requires jq; terminal output mode has no jq dependency.

IFS=$' \t\n'
set -uo pipefail

VERSION="1.0.0"

# ── Defaults ───────────────────────────────────────────────────────────────────
MIN_DOMAIN_AGE_DAYS=30
WARN_DOMAIN_AGE_DAYS=0          # 0 = auto: computed as 3×MIN_DOMAIN_AGE_DAYS
QUIET=false
VERBOSE=false
JSON_OUTPUT=false
SKIP_WHOIS=false
SKIP_IP_DNSBL=false
SKIP_RELAY_CHECK=false
SCRIPT_NAME="$(basename "$0")"
_WHOIS_CALL_COUNT=0             # tracks inter-query delay for rate limiting

# ── Colours ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# ── Terminal output helpers ────────────────────────────────────────────────────
pass()    { $QUIET || $JSON_OUTPUT || echo -e "  ${GREEN}✓${NC} $*"; }
fail()    { $QUIET || $JSON_OUTPUT || echo -e "  ${RED}✗${NC} $*"; }
warn()    { $QUIET || $JSON_OUTPUT || echo -e "  ${YELLOW}~${NC} $*"; }
info()    { $QUIET || $JSON_OUTPUT || echo -e "  ${CYAN}i${NC} $*"; }
section() { $QUIET || $JSON_OUTPUT || echo -e "\n  ${BOLD}${CYAN}── $* ──${NC}"; }

# ── Help ───────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] <domain|email|file|->

Options:
  -a, --min-age DAYS       Minimum domain age — hard flag below threshold (default: $MIN_DOMAIN_AGE_DAYS)
      --warn-age DAYS      Advisory warning below threshold (default: 3× min-age)
  -j, --json               JSON output to stdout (requires jq)
  -sj, -js                 Silent + JSON — pipe-friendly
  -s, --silent             Suppress progress output
  -q, --quiet              Alias for --silent
  -v, --verbose            Show additional diagnostic detail
      --skip-whois         Skip WHOIS domain age check (avoids rate limits)
      --skip-ip-dnsbl      Skip MX IP blocklist check
      --skip-relay-check   Skip open relay detection
      --version            Print version and exit
  -h, --help               Show this help

Input:
  Domain name:          $SCRIPT_NAME example.com
  Email address:        $SCRIPT_NAME user@example.com
  Comma/semicolon list: $SCRIPT_NAME "a.com; b.com"
  File:                 $SCRIPT_NAME domains.txt
  Stdin:                echo "example.com" | $SCRIPT_NAME -

Verdicts:
  CLEAN       Passed all hard checks (advisory notes may be present)
  SUSPICIOUS  Domain confirmed too young (below --min-age threshold)
  FLAGGED     Listed on one or more domain or IP DNSBLs
EOF
  exit 0
}

# ── Dependency check ───────────────────────────────────────────────────────────
check_deps() {
  local missing=()
  command -v dig     &>/dev/null || missing+=("dig (bind-utils / dnsutils)")
  command -v openssl &>/dev/null || missing+=("openssl (required for STARTTLS / implicit-TLS relay probes on ports 587 and 465)")
  if $JSON_OUTPUT; then
    command -v jq &>/dev/null || missing+=("jq (required for --json mode)")
  fi
  if (( ${#missing[@]} > 0 )); then
    echo -e "${RED}Error:${NC} Missing required tools:" >&2
    for dep in "${missing[@]}"; do echo "  • $dep" >&2; done
    exit 2
  fi

  # whois is optional — its absence auto-enables --skip-whois rather than
  # hard-failing.  WHOIS checks are advisory: inconclusive results (rate-limited,
  # non-standard format) never affect the verdict.
  if ! $SKIP_WHOIS; then
    command -v whois &>/dev/null || {
      warn "whois not installed — domain age check will be skipped"
      warn "install with: apt install whois  /  brew install whois"
      SKIP_WHOIS=true
    }
  fi
}

# ── DNSBL zone definitions ─────────────────────────────────────────────────────
#
# Domain-based zones (query: domain.zone → A record response)
# These list domains associated with spam, phishing, and malware campaigns.
# Zones are queried in the order listed; the first confirmed hit short-circuits
# the rest for that domain.
#
DOMAIN_DNSBL_ZONES=(
  "dbl.spamhaus.org"    # Spamhaus Domain Blocklist — spam, phish, malware, C&C
  "multi.surbl.org"     # SURBL aggregate — spam and phishing domains
  "dbl.nordspam.com"    # NordSpam domain list
  "rhsbl.abuse.ch"      # Abuse.ch — malware and botnet domains
)

# IP-based zones (query: reversed-IP.zone → A record response)
# The MX server's IP is checked against these.  A domain can be clean while its
# MX server is blocklisted (shared hosting, recently-compromised server).
# Resolving the MX IP here reuses the work already done in the MX check.
#
IP_DNSBL_ZONES=(
  "zen.spamhaus.org"    # Spamhaus composite (SBL + XBL + PBL) — comprehensive
  "bl.spamcop.net"      # SpamCop — spam sources reported by users
)

# ── DNSBL response decoders ────────────────────────────────────────────────────

decode_spamhaus_dbl() {
  # https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
  case "$1" in
    127.0.1.2)       echo "spam domain" ;;
    127.0.1.4)       echo "phishing domain" ;;
    127.0.1.5)       echo "malware domain" ;;
    127.0.1.6)       echo "botnet C&C domain" ;;
    127.0.1.102)     echo "abused legitimate spam domain" ;;
    127.0.1.103)     echo "abused legitimate phishing domain" ;;
    127.0.1.104)     echo "abused legitimate malware domain" ;;
    127.0.1.105)     echo "abused legitimate botnet C&C domain" ;;
    127.255.255.252) echo "QUERY LIMIT EXCEEDED" ;;
    127.255.255.254) echo "QUERY LIMIT EXCEEDED" ;;
    127.255.255.255) echo "DNSBL zone misconfigured" ;;
    *)               echo "listed (code: $1)" ;;
  esac
}

decode_surbl() {
  # SURBL multi uses a bitmask on the last octet of the response.
  # https://surbl.org/additional-documentation
  local code="$1"
  local last_octet="${code##*.}"
  local descriptions=()

  (( last_octet & 2   )) && descriptions+=("SC (SpamCop)")          || true
  (( last_octet & 4   )) && descriptions+=("WS (jwSpamSpy)")        || true
  (( last_octet & 8   )) && descriptions+=("PH (phishing)")         || true
  (( last_octet & 16  )) && descriptions+=("MW (malware/cracked)")  || true
  (( last_octet & 64  )) && descriptions+=("AB (AbuseButler)")      || true
  (( last_octet & 128 )) && descriptions+=("CR (cred phishing)")    || true

  if (( ${#descriptions[@]} > 0 )); then
    local IFS='+'; echo "${descriptions[*]}"
  else
    echo "listed (code: $code)"
  fi
}

decode_spamhaus_zen() {
  # https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
  case "$1" in
    127.0.0.2)  echo "SBL — Spamhaus spam source" ;;
    127.0.0.3)  echo "SBL CSS — spam-support service" ;;
    127.0.0.4)  echo "XBL CBL — exploited/botnet IP" ;;
    127.0.0.9)  echo "SBL DROP — hijacked/rogue network" ;;
    127.0.0.10) echo "PBL ISP — ISP policy block" ;;
    127.0.0.11) echo "PBL user — user-level policy block" ;;
    127.255.255.252) echo "QUERY LIMIT EXCEEDED" ;;
    127.255.255.254) echo "QUERY LIMIT EXCEEDED" ;;
    127.255.255.255) echo "DNSBL zone misconfigured" ;;
    *)          echo "listed (code: $1)" ;;
  esac
}

# ── JSON accumulation state ────────────────────────────────────────────────────
# One set of variables per domain; reset at the top of check_domain().
# Arrays collect multi-value results (NS records, DNSBL hits); scalars
# capture single values or status strings.

JSON_NS_RECORDS=()
JSON_NS_COUNT=0
JSON_MX_RECORDS=()
JSON_SPF_PRESENT=false
JSON_SPF_RECORD=""
JSON_SPF_POLICY=""
JSON_SPF_LOOKUP_COUNT=0
JSON_SPF_LOOKUP_WARN=false
JSON_DMARC_PRESENT=false
JSON_DMARC_RECORD=""
JSON_DMARC_POLICY=""
JSON_DKIM_FOUND=false
JSON_DKIM_SELECTOR=""
JSON_DNSBL_HITS=()
JSON_DNSBL_CLEAN=()
JSON_IP_DNSBL_HITS=()
JSON_IP_DNSBL_CLEAN=()
JSON_MX_IP=""
JSON_AGE_DATE=""
JSON_AGE_DAYS=-1
JSON_AGE_STATUS="not_checked"
JSON_RELAY_STATUS="not_checked"
JSON_RELAY_OPEN=false
JSON_RELAY_PORTS_TRIED=()   # per-port result objects: {port, tls, result:"relay_rejected|relay_accepted|unreachable|inconclusive"}

# Collected JSON result objects (one per domain); wrapped by main().
JSON_RESULTS=()

# ── Check functions ────────────────────────────────────────────────────────────

check_dnsbl() {
  # Queries each domain-based DNSBL zone by prepending the target domain to
  # the zone name and looking up an A record.  Any response in the 127.x.x.x
  # range indicates a listing; responses in 127.255.255.x indicate rate-limit
  # or zone errors and are skipped rather than false-positived.
  local domain="$1"
  local flagged=false

  section "DNSBL Reputation (domain)"
  JSON_DNSBL_HITS=()
  JSON_DNSBL_CLEAN=()

  for zone in "${DOMAIN_DNSBL_ZONES[@]}"; do
    local query="${domain}.${zone}"
    local result
    result=$(dig +short +time=5 +tries=2 "$query" A 2>/dev/null | head -1 || true)

    if [[ -z "$result" ]]; then
      pass "Not listed: $zone"
      JSON_DNSBL_CLEAN+=("$zone")
      continue
    fi

    if [[ "$result" == "127.255.255.252" || \
          "$result" == "127.255.255.254" || \
          "$result" == "127.255.255.255" ]]; then
      warn "$zone: query limit exceeded or zone error — result unreliable"
      continue
    fi

    local meaning
    case "$zone" in
      "dbl.spamhaus.org") meaning=$(decode_spamhaus_dbl "$result") ;;
      "multi.surbl.org")  meaning=$(decode_surbl         "$result") ;;
      *)                  meaning="listed (code: $result)" ;;
    esac

    fail "LISTED on $zone — $meaning"
    JSON_DNSBL_HITS+=("{\"zone\":\"${zone}\",\"code\":\"${result}\",\"meaning\":\"${meaning}\"}")
    flagged=true
  done

  $flagged && return 1 || return 0
}

check_ip_dnsbl() {
  # Resolves the domain's lowest-priority MX to an IP, then queries IP-based
  # DNSBL zones using the standard reverse-octet format (e.g. 1.2.3.4 →
  # 4.3.2.1.zen.spamhaus.org).
  #
  # WHY a separate IP DNSBL check matters:
  # Domain-based DNSBLs only list domains that have been explicitly reported.
  # A domain that has never sent spam (new or low-volume) may be clean on
  # all domain lists while its MX server is on a blocklist due to other
  # tenants on the same shared hosting IP.  IP-based checks catch this.
  #
  # Only IPv4 is handled here; IPv6 DNSBL support is rare and inconsistent
  # across zones, so the check is skipped for IPv6 MX hosts.
  local domain="$1"
  local flagged=false

  section "DNSBL Reputation (MX IP)"
  JSON_IP_DNSBL_HITS=()
  JSON_IP_DNSBL_CLEAN=()
  JSON_MX_IP=""

  # Resolve the primary MX host to an IP.
  local mx_host
  mx_host=$(dig +short +time=5 +tries=2 MX "$domain" 2>/dev/null \
    | sort -n | awk '{print $2}' | head -1 | sed 's/\.$//')

  if [[ -z "$mx_host" ]]; then
    warn "IP DNSBL: no MX record found — skipping IP lookup"
    return 0
  fi

  local mx_ip
  mx_ip=$(dig +short +time=5 +tries=2 A "$mx_host" 2>/dev/null | head -1)

  if [[ -z "$mx_ip" ]]; then
    warn "IP DNSBL: MX host $mx_host did not resolve to an IPv4 address — skipping"
    return 0
  fi

  # Skip IPv6 addresses — construct a basic check for IPv4 only.
  if [[ ! "$mx_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    warn "IP DNSBL: IPv6 MX address $mx_ip — IP-based DNSBL check skipped"
    return 0
  fi

  JSON_MX_IP="$mx_ip"
  info "IP DNSBL: checking MX IP $mx_ip (host: $mx_host)"

  # Build reversed-octet query prefix (e.g. 1.2.3.4 → 4.3.2.1)
  local reversed
  reversed=$(echo "$mx_ip" | awk -F. '{print $4"."$3"."$2"."$1}')

  for zone in "${IP_DNSBL_ZONES[@]}"; do
    local query="${reversed}.${zone}"
    local result
    result=$(dig +short +time=5 +tries=2 "$query" A 2>/dev/null | head -1 || true)

    if [[ -z "$result" ]]; then
      pass "IP not listed: $zone"
      JSON_IP_DNSBL_CLEAN+=("$zone")
      continue
    fi

    if [[ "$result" == "127.255.255.252" || \
          "$result" == "127.255.255.254" || \
          "$result" == "127.255.255.255" ]]; then
      warn "$zone: query limit exceeded or zone error — result unreliable"
      continue
    fi

    local meaning
    case "$zone" in
      "zen.spamhaus.org") meaning=$(decode_spamhaus_zen "$result") ;;
      *)                  meaning="listed (code: $result)" ;;
    esac

    fail "MX IP $mx_ip LISTED on $zone — $meaning"
    JSON_IP_DNSBL_HITS+=("{\"zone\":\"${zone}\",\"ip\":\"${mx_ip}\",\"code\":\"${result}\",\"meaning\":\"${meaning}\"}")
    flagged=true
  done

  $flagged && return 1 || return 0
}

check_domain_age() {
  # Queries WHOIS and attempts to parse the registration date from the raw
  # response.  Different registrars use different field names and date formats;
  # the function tries a ranked list of both and falls back progressively.
  #
  # Age classification uses two thresholds:
  #   warn_age  (default: 3×min_age)  → advisory note, no verdict change
  #   min_age   (default: 30 days)    → hard flag, SUSPICIOUS verdict
  #
  # WHY a graduated model rather than a single threshold:
  # A 5-day-old domain is unambiguously suspicious.  A 45-day-old domain might
  # simply be a developer who just published a first package.  The warn tier
  # surfaces the signal without penalising legitimate early-stage projects.
  #
  # Return codes:
  #   0  age OK (above warn threshold)
  #   1  HARD flag (below min_age)
  #   2  Inconclusive (WHOIS unavailable, rate-limited, or format unrecognised)
  #   3  Advisory warn only (between min_age and warn_age)
  local domain="$1"

  section "Domain Age (WHOIS)"
  JSON_AGE_STATUS="not_checked"
  JSON_AGE_DATE=""
  JSON_AGE_DAYS=-1

  if $SKIP_WHOIS; then
    warn "WHOIS check skipped"
    return 2
  fi

  # Rate-limit guard: WHOIS servers typically allow 5–10 queries per minute.
  # When processing a list, insert a 1-second pause between calls.
  # The first call is free; the counter is incremented after each call.
  if (( _WHOIS_CALL_COUNT > 0 )); then
    sleep 1
  fi
  (( ++_WHOIS_CALL_COUNT )) || true

  local raw_whois
  raw_whois=$(whois "$domain" 2>/dev/null) || {
    warn "WHOIS lookup failed for $domain"
    JSON_AGE_STATUS="lookup_failed"
    return 2
  }

  # Field name variants used by different registrars.
  # sed 's/^[^:]*: *//' strips everything up to the FIRST colon.
  # NOT '.*: *' (greedy) which would strip to the LAST colon and mangle
  # timestamps like 2007-01-02T22:25:08Z down to just '08Z'.
  local raw_date=""
  local fields=(
    "Creation Date"            # Verisign/ICANN, GoDaddy, most gTLD registrars
    "Registry Creation Date"   # Cloudflare Registrar, RDAP-format output
    "Created On"               # Namecheap, Enom
    "created"                  # RIPE, AFNIC, DENIC and other ccTLD registries
    "Domain Registration Date"
    "Registered on"            # Nominet (.co.uk)
    "Registration Time"
    "domain_dateregistered"
    "created_date"
    "Crdate"                   # Some LACNIC / ARIN output
  )

  for field in "${fields[@]}"; do
    raw_date=$(echo "$raw_whois" \
      | grep -iE "^[[:space:]]*${field}[[:space:]]*:" \
      | head -1 \
      | sed 's/^[^:]*: *//' \
      | tr -d '\r')
    [[ -n "$raw_date" ]] && break
  done

  if [[ -z "$raw_date" ]]; then
    warn "Could not determine registration date (registrar may redact or use non-standard WHOIS format)"
    JSON_AGE_STATUS="date_not_found"
    return 2
  fi

  $VERBOSE && info "Raw registration date: $raw_date"

  # Date normalisation strategy — cheapest reliable method tried first:
  #   1. Regex extract of YYYY-MM-DD from any ISO 8601 variant
  #      (handles: 2007-01-02, 2007-01-02T22:25:08, 2007-01-02T22:25:08.000Z)
  #   2. GNU date -d  — freeform strings on Linux
  #   3. BSD date -j  — named-month formats like "02-Jan-2007" on macOS
  #   4. BSD date -j  — dot-separated dates like "2007.01.02" on macOS
  local normalized=""
  normalized=$(echo "$raw_date" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)

  if [[ -z "$normalized" ]]; then
    normalized=$(date -d  "$raw_date"             +%Y-%m-%d 2>/dev/null) \
      || normalized=$(date -j -f "%d-%b-%Y"  "$raw_date" +%Y-%m-%d 2>/dev/null) \
      || normalized=$(date -j -f "%Y.%m.%d"  "$raw_date" +%Y-%m-%d 2>/dev/null) \
      || true
  fi

  if [[ -z "$normalized" ]]; then
    warn "Could not parse registration date format: $raw_date"
    JSON_AGE_STATUS="date_parse_failed"
    return 2
  fi

  local created_ts now_ts age_days
  created_ts=$(date -d  "$normalized" +%s 2>/dev/null \
    || date -j -f "%Y-%m-%d" "$normalized" +%s 2>/dev/null) || {
      warn "Failed to convert date to timestamp: $normalized"
      JSON_AGE_STATUS="date_parse_failed"
      return 2
    }

  now_ts=$(date +%s)
  age_days=$(( (now_ts - created_ts) / 86400 ))
  JSON_AGE_DATE="$normalized"
  JSON_AGE_DAYS="$age_days"

  # Human-readable age string
  local age_display
  if   (( age_days >= 365 )); then
    age_display="$(( age_days / 365 )) year(s), $(( (age_days % 365) / 30 )) month(s)"
  elif (( age_days >= 30 )); then
    age_display="$(( age_days / 30 )) month(s)"
  else
    age_display="${age_days} day(s)"
  fi

  # Determine the effective warn threshold.
  local effective_warn_age
  if (( WARN_DOMAIN_AGE_DAYS > 0 )); then
    effective_warn_age="$WARN_DOMAIN_AGE_DAYS"
  else
    effective_warn_age=$(( MIN_DOMAIN_AGE_DAYS * 3 ))
  fi

  if (( age_days < MIN_DOMAIN_AGE_DAYS )); then
    fail "Domain is only ${age_days} day(s) old — below hard threshold of ${MIN_DOMAIN_AGE_DAYS} days (registered: $normalized)"
    JSON_AGE_STATUS="hard_flagged"
    return 1
  elif (( age_days < effective_warn_age )); then
    warn "Domain is ${age_days} day(s) old — below advisory threshold of ${effective_warn_age} days (registered: $normalized)"
    JSON_AGE_STATUS="advisory"
    return 3
  else
    pass "Domain age: $age_display (registered: $normalized)"
    JSON_AGE_STATUS="ok"
    return 0
  fi
}

check_mx_records() {
  local domain="$1"

  section "Mail Exchange (MX) Records"
  JSON_MX_RECORDS=()

  local mx_records
  mx_records=$(dig +short +time=5 +tries=2 MX "$domain" 2>/dev/null | sort -n)

  if [[ -z "$mx_records" ]]; then
    warn "No MX records found — domain may not accept email"
    return 1
  fi

  while IFS= read -r mx; do
    [[ -z "$mx" ]] && continue
    local priority host
    priority=$(echo "$mx" | awk '{print $1}')
    host=$(echo "$mx"      | awk '{print $2}' | sed 's/\.$//')
    pass "MX $priority → $host"
    JSON_MX_RECORDS+=("{\"priority\":${priority},\"host\":\"${host}\"}")
  done <<< "$mx_records"

  return 0
}

check_spf() {
  # Checks for the presence of an SPF TXT record and evaluates its policy
  # and lookup depth.
  #
  # SPF LOOKUP DEPTH:
  # RFC 7208 §4.6.4 imposes a hard limit of 10 DNS lookups per SPF evaluation.
  # Mechanisms that trigger lookups: include:, a:, mx:, ptr:, exists:, and
  # the implicit A/MX lookup for the bare 'a' and 'mx' mechanisms.
  # A record that appears valid but exceeds 10 lookups will cause a "permerror"
  # at delivery time — the sending domain effectively has no SPF protection
  # even though the record exists.  Chains like:
  #   include:spf.sendgrid.net → include:spf.protection.outlook.com → ...
  # can easily reach 9–12 lookups after three levels of nesting.
  #
  # We count at the first level only (we don't recursively resolve includes).
  # A count ≥8 at the first level is a warning; ≥10 would already be in
  # violation before accounting for any nested includes.
  local domain="$1"

  section "SPF Record"
  JSON_SPF_PRESENT=false
  JSON_SPF_RECORD=""
  JSON_SPF_POLICY=""
  JSON_SPF_LOOKUP_COUNT=0
  JSON_SPF_LOOKUP_WARN=false

  local spf
  spf=$(dig +short +time=5 +tries=2 TXT "$domain" 2>/dev/null \
    | grep -i "v=spf1" \
    | head -1 \
    | tr -d '"')

  if [[ -z "$spf" ]]; then
    warn "No SPF record found — domain is not SPF-protected (increases spam risk)"
    return 1
  fi

  pass "SPF record present: $spf"
  JSON_SPF_PRESENT=true
  JSON_SPF_RECORD="$spf"

  # Count first-level lookup-triggering mechanisms.
  # Each token that starts with include:, a:, mx:, ptr:, exists: counts as 1.
  # Bare 'a' and 'mx' (without a colon) each also count as 1.
  local lookup_count=0
  local token
  for token in $spf; do
    case "$token" in
      include:*|a:*|mx:*|ptr:*|exists:*) (( ++lookup_count )) || true ;;
      a|+a|-a|~a|?a|mx|+mx|-mx|~mx|?mx) (( ++lookup_count )) || true ;;
    esac
  done
  JSON_SPF_LOOKUP_COUNT="$lookup_count"

  if (( lookup_count >= 10 )); then
    fail "SPF: $lookup_count first-level DNS lookups — already at or above the RFC 7208 limit of 10"
    JSON_SPF_LOOKUP_WARN=true
  elif (( lookup_count >= 8 )); then
    warn "SPF: $lookup_count first-level DNS lookups — approaching the RFC 7208 limit of 10 (nested includes may push this over)"
    JSON_SPF_LOOKUP_WARN=true
  else
    $VERBOSE && info "SPF: $lookup_count first-level DNS lookup(s) — within limit"
  fi

  # Evaluate the qualifier on the 'all' mechanism.
  if echo "$spf" | grep -q "+all"; then
    fail "SPF uses +all — accepts mail from ANY server (extremely dangerous)"
    JSON_SPF_POLICY="+all"
    return 1
  elif echo "$spf" | grep -q "~all"; then
    warn "SPF uses ~all (softfail) — some mail may not be authenticated"
    JSON_SPF_POLICY="~all"
  elif echo "$spf" | grep -q "?all"; then
    warn "SPF uses ?all (neutral) — provides no real protection"
    JSON_SPF_POLICY="?all"
  elif echo "$spf" | grep -q "\-all"; then
    pass "SPF uses -all (hardfail) — strict enforcement"
    JSON_SPF_POLICY="-all"
  else
    warn "SPF record has no 'all' qualifier — ambiguous policy"
    JSON_SPF_POLICY="none"
  fi

  return 0
}

check_dmarc() {
  local domain="$1"

  section "DMARC Record"
  JSON_DMARC_PRESENT=false
  JSON_DMARC_RECORD=""
  JSON_DMARC_POLICY=""

  local dmarc
  dmarc=$(dig +short +time=5 +tries=2 TXT "_dmarc.${domain}" 2>/dev/null \
    | grep -i "v=DMARC1" \
    | head -1 \
    | tr -d '"')

  if [[ -z "$dmarc" ]]; then
    warn "No DMARC record found — domain has no DMARC policy"
    return 1
  fi

  pass "DMARC record present: $dmarc"
  JSON_DMARC_PRESENT=true
  JSON_DMARC_RECORD="$dmarc"

  local policy
  policy=$(echo "$dmarc" | grep -oiE 'p=(none|quarantine|reject)' \
    | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
  JSON_DMARC_POLICY="${policy:-unspecified}"

  case "$policy" in
    reject)     pass "DMARC policy: reject (strongest enforcement)" ;;
    quarantine) pass "DMARC policy: quarantine (moderate enforcement)" ;;
    none)       warn "DMARC policy: none (monitoring only — no enforcement)" ;;
    "")         warn "DMARC policy not specified in record" ;;
  esac

  return 0
}

check_dkim() {
  # DKIM selectors are not standardised — each mail provider uses its own.
  # We probe a set of common selector names.  A negative result here does NOT
  # mean the domain lacks DKIM; it may simply use a non-standard selector.
  # This check is therefore informational only and never contributes to the
  # verdict or flag counts.
  local domain="$1"

  section "DKIM (common selectors — best effort)"
  JSON_DKIM_FOUND=false
  JSON_DKIM_SELECTOR=""

  local common_selectors=(
    "default" "dkim" "mail" "email" "k1" "google" "selector1" "selector2"
    "s1" "s2" "smtp" "key1" "mimecast" "mailjet" "sendgrid" "everlytickey1"
  )

  local found=false
  for selector in "${common_selectors[@]}"; do
    local result
    result=$(dig +short +time=3 +tries=1 TXT "${selector}._domainkey.${domain}" 2>/dev/null \
      | grep -i "v=DKIM1" \
      | head -1 \
      | tr -d '"')

    if [[ -n "$result" ]]; then
      pass "DKIM record found (selector: $selector)"
      JSON_DKIM_FOUND=true
      JSON_DKIM_SELECTOR="$selector"
      found=true
      break
    fi
  done

  if ! $found; then
    warn "No DKIM record found for common selectors — domain may still use DKIM with a non-standard selector"
  fi

  return 0   # Never a hard failure — absence is inconclusive, not a flag.
}

# ── Relay probe SMTP infrastructure ───────────────────────────────────────────
# A lean, self-contained SMTP layer used only by check_open_relay().
# Kept separate from any general-purpose SMTP code to make the relay check
# easy to reason about in isolation.
#
# FD 61 is used for plain TCP connections; TLS connections use a coproc so
# the same read/write FD variables work uniformly across both paths.
# FD 61 was chosen to avoid the 3–9 range (used by bash internals) and to
# not conflict with FD 63 used by email-validate.sh if the two scripts are
# ever sourced together or run in the same shell session.
RELAY_FD=61
RELAY_READ_FD=61
RELAY_WRITE_FD=61
RELAY_USE_TLS=false
RELAY_TLS_PID=""

_relay_read() {
  # Read one complete SMTP response, handling multi-line continuations.
  RELAY_CODE=""; RELAY_TEXT=""
  local line timeout="${SMTP_RELAY_TIMEOUT:-10}"
  while IFS= read -t "$timeout" -r line <&"$RELAY_READ_FD" 2>/dev/null; do
    line="${line%$'\r'}"
    RELAY_CODE="${line:0:3}"
    RELAY_TEXT="$line"
    [[ "${line:3:1}" != "-" ]] && break
  done
}

_relay_send() { printf '%s\r\n' "$1" >&"$RELAY_WRITE_FD" 2>/dev/null || true; }

_relay_close() {
  _relay_send "QUIT"
  if $RELAY_USE_TLS; then
    eval "exec ${RELAY_WRITE_FD}>&-" 2>/dev/null || true
    eval "exec ${RELAY_READ_FD}<&-"  2>/dev/null || true
    [[ -n "$RELAY_TLS_PID" ]] && wait "$RELAY_TLS_PID" 2>/dev/null || true
    RELAY_TLS_PID=""
    RELAY_USE_TLS=false
  else
    eval "exec ${RELAY_FD}>&-" 2>/dev/null || true
  fi
  RELAY_READ_FD=$RELAY_FD
  RELAY_WRITE_FD=$RELAY_FD
}

_relay_open_plain() {
  local host="$1" port="$2"
  local timeout_cmd=""
  command -v timeout  &>/dev/null && timeout_cmd="timeout"
  command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"
  local t="${SMTP_RELAY_TIMEOUT:-10}"

  if [[ -n "$timeout_cmd" ]]; then
    $timeout_cmd "$t" bash -c \
      "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null || return 1
  fi
  eval "exec ${RELAY_FD}<>/dev/tcp/${host}/${port}" 2>/dev/null || return 1
  RELAY_READ_FD=$RELAY_FD
  RELAY_WRITE_FD=$RELAY_FD
  RELAY_USE_TLS=false
  return 0
}

_relay_open_tls() {
  # Opens a TLS-protected SMTP connection via an openssl coprocess.
  # use_starttls=true  → port 587: openssl handles EHLO + STARTTLS negotiation,
  #                      we drain pre-TLS responses, then proceed post-TLS.
  # use_starttls=false → port 465: implicit TLS; 220 banner follows immediately.
  local host="$1" port="$2" use_starttls="${3:-false}"
  local timeout_cmd=""
  command -v timeout  &>/dev/null && timeout_cmd="timeout"
  command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"
  local t="${SMTP_RELAY_TIMEOUT:-10}"

  command -v openssl &>/dev/null || return 1

  if [[ -n "$timeout_cmd" ]]; then
    $timeout_cmd "$t" bash -c \
      "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null || return 1
  fi

  [[ -n "$RELAY_TLS_PID" ]] && {
    kill "$RELAY_TLS_PID" 2>/dev/null || true
    wait "$RELAY_TLS_PID" 2>/dev/null || true
    RELAY_TLS_PID=""
  }

  local starttls_flag=""
  $use_starttls && starttls_flag="-starttls smtp"

  # shellcheck disable=SC2086
  coproc RELAY_TLS_COPROC {
    exec openssl s_client \
      -connect "${host}:${port}" \
      $starttls_flag \
      -quiet -ign_eof 2>/dev/null
  }
  RELAY_TLS_PID="$RELAY_TLS_COPROC_PID"
  RELAY_READ_FD="${RELAY_TLS_COPROC[0]}"
  RELAY_WRITE_FD="${RELAY_TLS_COPROC[1]}"
  RELAY_USE_TLS=true

  if $use_starttls; then
    # Drain the three pre-TLS exchanges openssl handled internally:
    #   1. 220 banner  2. 250 EHLO response  3. 220 STARTTLS confirm
    local i
    for i in 1 2 3; do
      _relay_read
      [[ -z "$RELAY_CODE" ]] && { _relay_close; return 1; }
    done
    # Post-TLS EHLO — must be issued by us after TLS establishment.
    _relay_send "EHLO probe.example.invalid"
    _relay_read
    [[ "$RELAY_CODE" != "250" ]] && { _relay_close; return 1; }
  fi
  return 0
}

_relay_probe_dialogue() {
  # Runs the minimal SMTP sequence needed to test for open relay on an
  # already-open connection.  Does NOT send a RCPT TO for the target domain —
  # only for the external probe address.
  #
  # WHY we probe example.invalid rather than the target domain:
  # We're not checking whether the domain's own addresses are valid; we're
  # checking whether the server will forward mail *for a domain it doesn't own*
  # without requiring authentication.  example.invalid (RFC 2606) is
  # unambiguously unhosted anywhere — there is no plausible scenario in which
  # a legitimate server accepts RCPT TO for it.
  #
  # Returns: 0 = relay confirmed (open)
  #          1 = relay rejected (closed — expected behaviour)
  #          2 = dialogue failed before RCPT TO (inconclusive)
  local starttls_done="${1:-false}"    # true when _relay_open_tls completed EHLO

  # EHLO — skip if already done by _relay_open_tls STARTTLS path
  if ! $starttls_done; then
    _relay_read   # consume banner
    [[ "$RELAY_CODE" != "220" ]] && { _relay_close; return 2; }
    _relay_send "EHLO probe.example.invalid"
    _relay_read
    if [[ "$RELAY_CODE" != "250" ]]; then
      _relay_send "HELO probe.example.invalid"
      _relay_read
      [[ "$RELAY_CODE" != "250" ]] && { _relay_close; return 2; }
    fi
  fi

  _relay_send "MAIL FROM:<noreply@example.invalid>"
  _relay_read
  [[ "$RELAY_CODE" != "250" ]] && { _relay_close; return 2; }

  # Generate a randomised local-part to avoid any allow-listing of known probe
  # addresses that some servers apply when they detect security researchers.
  local rand_local
  rand_local="relay$(od -An -N6 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')probe"
  local relay_addr="${rand_local}@example.invalid"

  _relay_send "RCPT TO:<${relay_addr}>"
  _relay_read
  _relay_close

  if [[ "$RELAY_CODE" == "250" || "$RELAY_CODE" == "251" ]]; then
    return 0   # open relay — server accepted RCPT TO for external domain
  elif [[ "$RELAY_CODE" =~ ^5 ]]; then
    return 1   # correctly rejected
  else
    return 2   # inconclusive (4xx greylist, timeout, etc.)
  fi
}

check_open_relay() {
  # Probes the domain's primary MX server across ALL THREE ports to determine
  # whether it will forward mail for arbitrary external domains without
  # requiring authentication — the definition of an open relay.
  #
  # WHY all ports are checked independently rather than stopping at the first
  # result: a server can have correct relay rejection on one port while being
  # an open relay on another.  This is not hypothetical — misconfigured
  # submission stacks (port 587) that accept RCPT TO before requiring AUTH
  # are a known failure mode distinct from port 25 relay configuration.
  # Stopping at the first definitive result would silently miss these cases.
  # Every reachable port is probed and its result recorded independently.
  #
  # Port order: 587 (STARTTLS) → 25 (plain) → 465 (implicit TLS)
  # All three are attempted regardless of prior results.
  #
  # Return codes:
  #   0 = no open relay detected on any reachable port
  #   1 = open relay confirmed on one or more ports
  local domain="$1"

  section "Open Relay Detection"
  JSON_RELAY_STATUS="not_checked"
  JSON_RELAY_OPEN=false
  JSON_RELAY_PORTS_TRIED=()

  # Resolve the lowest-priority (most preferred) MX record.
  local mx_host
  mx_host=$(dig +short +time=5 +tries=2 MX "$domain" 2>/dev/null \
    | sort -n | awk '{print $2}' | head -1 | sed 's/\.$//')

  if [[ -z "$mx_host" ]]; then
    warn "Relay: no MX record found — skipping open relay check"
    JSON_RELAY_STATUS="no_mx"
    return 0
  fi

  info "Relay: probing $mx_host across all ports (587/25/465)..."

  local any_open=false
  local any_checked=false
  local rc=0

  # ── Port 587 — STARTTLS ──────────────────────────────────────────────────
  if _relay_open_tls "$mx_host" 587 true; then
    any_checked=true
    rc=0; _relay_probe_dialogue true || rc=$?
    case $rc in
      0) fail "Relay: OPEN RELAY on port 587 (STARTTLS) — server accepted RCPT TO for example.invalid"
         any_open=true
         JSON_RELAY_PORTS_TRIED+=("{\"port\":587,\"tls\":true,\"result\":\"relay_accepted\"}") ;;
      1) pass "Relay: port 587 (STARTTLS) — relay correctly rejected"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":587,\"tls\":true,\"result\":\"relay_rejected\"}") ;;
      2) warn "Relay: port 587 dialogue inconclusive"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":587,\"tls\":true,\"result\":\"inconclusive\"}") ;;
    esac
  else
    info "Relay: port 587 unreachable or STARTTLS failed"
    JSON_RELAY_PORTS_TRIED+=("{\"port\":587,\"tls\":true,\"result\":\"unreachable\"}")
  fi

  # ── Port 25 — plain ──────────────────────────────────────────────────────
  if _relay_open_plain "$mx_host" 25; then
    any_checked=true
    rc=0; _relay_probe_dialogue false || rc=$?
    case $rc in
      0) fail "Relay: OPEN RELAY on port 25 (plain) — server accepted RCPT TO for example.invalid"
         any_open=true
         JSON_RELAY_PORTS_TRIED+=("{\"port\":25,\"tls\":false,\"result\":\"relay_accepted\"}") ;;
      1) pass "Relay: port 25 (plain) — relay correctly rejected"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":25,\"tls\":false,\"result\":\"relay_rejected\"}") ;;
      2) warn "Relay: port 25 dialogue inconclusive"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":25,\"tls\":false,\"result\":\"inconclusive\"}") ;;
    esac
  else
    info "Relay: port 25 unreachable"
    JSON_RELAY_PORTS_TRIED+=("{\"port\":25,\"tls\":false,\"result\":\"unreachable\"}")
  fi

  # ── Port 465 — implicit TLS ──────────────────────────────────────────────
  if _relay_open_tls "$mx_host" 465 false; then
    any_checked=true
    rc=0; _relay_probe_dialogue false || rc=$?
    case $rc in
      0) fail "Relay: OPEN RELAY on port 465 (implicit TLS) — server accepted RCPT TO for example.invalid"
         any_open=true
         JSON_RELAY_PORTS_TRIED+=("{\"port\":465,\"tls\":true,\"result\":\"relay_accepted\"}") ;;
      1) pass "Relay: port 465 (implicit TLS) — relay correctly rejected"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":465,\"tls\":true,\"result\":\"relay_rejected\"}") ;;
      2) warn "Relay: port 465 dialogue inconclusive"
         JSON_RELAY_PORTS_TRIED+=("{\"port\":465,\"tls\":true,\"result\":\"inconclusive\"}") ;;
    esac
  else
    info "Relay: port 465 unreachable or TLS failed"
    JSON_RELAY_PORTS_TRIED+=("{\"port\":465,\"tls\":true,\"result\":\"unreachable\"}")
  fi

  # ── Overall result ───────────────────────────────────────────────────────
  if $any_open; then
    local open_list
    open_list=$(printf '%s\n' "${JSON_RELAY_PORTS_TRIED[@]}" \
      | jq -rcs '[.[] | select(.result=="relay_accepted") | .port] | join(",")')
    fail "Relay: OPEN RELAY confirmed on port(s): $open_list"
    JSON_RELAY_OPEN=true
    JSON_RELAY_STATUS="open_relay"
    return 1
  elif $any_checked; then
    JSON_RELAY_STATUS="closed"
    return 0
  else
    warn "Relay: could not connect to any port (587/25/465) — open relay status inconclusive"
    JSON_RELAY_STATUS="inconclusive"
    return 0
  fi
}

# ─────────────────────────────────────────────────────────────────────────────

check_nameservers() {
  local domain="$1"

  section "Nameservers"
  JSON_NS_RECORDS=()
  JSON_NS_COUNT=0

  local ns_records
  ns_records=$(dig +short +time=5 +tries=2 NS "$domain" 2>/dev/null | sed 's/\.$//')

  if [[ -z "$ns_records" ]]; then
    fail "No NS records found — domain may not exist or DNS is broken"
    return 1
  fi

  while IFS= read -r ns; do
    [[ -z "$ns" ]] && continue
    (( ++JSON_NS_COUNT )) || true
    pass "NS: $ns"
    JSON_NS_RECORDS+=("$ns")
  done <<< "$ns_records"

  if (( JSON_NS_COUNT < 2 )); then
    warn "Only ${JSON_NS_COUNT} nameserver(s) found — DNS resilience best practice requires at least 2"
  fi

  return 0
}

# ── JSON emission ──────────────────────────────────────────────────────────────
emit_json() {
  local domain="$1" verdict="$2" hard_flags="$3" warn_flags="$4"

  # Serialise array state into JSON arrays.
  local ns_json dnsbl_hits_json dnsbl_clean_json ip_hits_json ip_clean_json mx_json \
        relay_ports_json
  ns_json=$(printf '%s\n'   "${JSON_NS_RECORDS[@]:-}"     | grep -v '^$' | jq -R . | jq -sc .)
  mx_json=$(printf '%s\n'   "${JSON_MX_RECORDS[@]:-}"     | grep -v '^$' | jq -Rsc 'split("\n")|map(select(length>0))|map(fromjson)')
  dnsbl_hits_json=$(printf '%s\n' "${JSON_DNSBL_HITS[@]:-}"  | grep -v '^$' | jq -Rsc 'split("\n")|map(select(length>0))|map(fromjson)')
  dnsbl_clean_json=$(printf '%s\n' "${JSON_DNSBL_CLEAN[@]:-}" | grep -v '^$' | jq -R . | jq -sc .)
  ip_hits_json=$(printf '%s\n'  "${JSON_IP_DNSBL_HITS[@]:-}"  | grep -v '^$' | jq -Rsc 'split("\n")|map(select(length>0))|map(fromjson)')
  ip_clean_json=$(printf '%s\n' "${JSON_IP_DNSBL_CLEAN[@]:-}" | grep -v '^$' | jq -R . | jq -sc .)
  relay_ports_json=$(printf '%s\n' "${JSON_RELAY_PORTS_TRIED[@]:-}" | grep -v '^$' | jq -Rsc 'split("\n")|map(select(length>0))|map(fromjson)')

  jq -cn \
    --arg  domain        "$domain" \
    --arg  verdict       "$verdict" \
    --arg  timestamp     "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson hard_flags "$hard_flags" \
    --argjson warn_flags "$warn_flags" \
    --argjson ns_records "$ns_json" \
    --argjson ns_count   "$JSON_NS_COUNT" \
    --argjson mx_records "$mx_json" \
    --arg     mx_ip      "$JSON_MX_IP" \
    --argjson spf_present  "$JSON_SPF_PRESENT" \
    --arg     spf_record   "$JSON_SPF_RECORD" \
    --arg     spf_policy   "$JSON_SPF_POLICY" \
    --argjson spf_lookup_count "$JSON_SPF_LOOKUP_COUNT" \
    --argjson spf_lookup_warn  "$JSON_SPF_LOOKUP_WARN" \
    --argjson dmarc_present  "$JSON_DMARC_PRESENT" \
    --arg     dmarc_record   "$JSON_DMARC_RECORD" \
    --arg     dmarc_policy   "$JSON_DMARC_POLICY" \
    --argjson dkim_found     "$JSON_DKIM_FOUND" \
    --arg     dkim_selector  "$JSON_DKIM_SELECTOR" \
    --argjson dnsbl_hits   "$dnsbl_hits_json" \
    --argjson dnsbl_clean  "$dnsbl_clean_json" \
    --argjson ip_dnsbl_hits  "$ip_hits_json" \
    --argjson ip_dnsbl_clean "$ip_clean_json" \
    --arg     age_status "$JSON_AGE_STATUS" \
    --arg     age_date   "$JSON_AGE_DATE" \
    --argjson age_days   "$JSON_AGE_DAYS" \
    --arg     relay_status  "$JSON_RELAY_STATUS" \
    --argjson relay_open    "$JSON_RELAY_OPEN" \
    --argjson relay_ports   "$relay_ports_json" \
    '{
      domain:    $domain,
      timestamp: $timestamp,
      verdict:   $verdict,
      flags: {
        hard: $hard_flags,
        advisory: $warn_flags
      },
      checks: {
        nameservers: {
          count:   $ns_count,
          records: $ns_records
        },
        mx: {
          records: $mx_records,
          ip:      $mx_ip
        },
        spf: {
          present:       $spf_present,
          record:        $spf_record,
          policy:        $spf_policy,
          lookup_count:  $spf_lookup_count,
          lookup_warn:   $spf_lookup_warn
        },
        dmarc: {
          present: $dmarc_present,
          record:  $dmarc_record,
          policy:  $dmarc_policy
        },
        dkim: {
          found:    $dkim_found,
          selector: $dkim_selector
        },
        dnsbl: {
          hits:  $dnsbl_hits,
          clean: $dnsbl_clean
        },
        ip_dnsbl: {
          hits:  $ip_dnsbl_hits,
          clean: $ip_dnsbl_clean
        },
        domain_age: {
          status:     $age_status,
          registered: $age_date,
          age_days:   $age_days
        },
        open_relay: {
          status:      $relay_status,
          open:        $relay_open,
          ports_tried: $relay_ports
        }
      }
    }'
}

# ── Per-domain check ───────────────────────────────────────────────────────────
check_domain() {
  local input="$1"
  local domain

  # Accept either a bare domain or an email address.
  if [[ "$input" == *"@"* ]]; then
    domain="${input#*@}"
    domain="${domain,,}"
    $QUIET || $JSON_OUTPUT || info "(extracted domain from email: $domain)"
  else
    domain="${input,,}"
  fi
  domain="${domain%.}"    # strip trailing dot if present

  # Reset JSON accumulation state for this domain.
  JSON_NS_RECORDS=(); JSON_NS_COUNT=0
  JSON_MX_RECORDS=(); JSON_MX_IP=""
  JSON_SPF_PRESENT=false; JSON_SPF_RECORD=""; JSON_SPF_POLICY=""
  JSON_SPF_LOOKUP_COUNT=0; JSON_SPF_LOOKUP_WARN=false
  JSON_DMARC_PRESENT=false; JSON_DMARC_RECORD=""; JSON_DMARC_POLICY=""
  JSON_DKIM_FOUND=false; JSON_DKIM_SELECTOR=""
  JSON_DNSBL_HITS=(); JSON_DNSBL_CLEAN=()
  JSON_IP_DNSBL_HITS=(); JSON_IP_DNSBL_CLEAN=()
  JSON_AGE_DATE=""; JSON_AGE_DAYS=-1; JSON_AGE_STATUS="not_checked"
  JSON_RELAY_STATUS="not_checked"; JSON_RELAY_OPEN=false; JSON_RELAY_PORTS_TRIED=()

  # Two-tier flag tracking:
  #   hard_flags  — concrete abuse evidence; drives the verdict
  #                 (DNSBL listing, confirmed-young domain, missing NS records)
  #   warn_flags  — advisory observations; reported but do not change verdict
  #                 (missing SPF/DMARC, no MX, single NS, inconclusive WHOIS)
  local hard_flags=0
  local warn_flags=0
  local verdict="CLEAN"

  if ! $QUIET && ! $JSON_OUTPUT; then
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD} Domain: ${CYAN}${domain}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  fi

  # ── Advisory checks ────────────────────────────────────────────────────────
  # No NS records is the only hard failure in this group — a domain with no
  # NS records doesn't functionally exist and cannot be evaluated further.
  # Everything else here is advisory even when it looks alarming: many
  # legitimate domains lack DMARC, use a single nameserver, or have no MX.
  check_nameservers "$domain" || { (( ++hard_flags )) || true; }
  check_mx_records  "$domain" || { (( ++warn_flags )) || true; }
  check_spf         "$domain" || { (( ++warn_flags )) || true; }
  check_dmarc       "$domain" || { (( ++warn_flags )) || true; }
  check_dkim        "$domain"   # informational only — never increments flags

  # ── Domain DNSBL check ─────────────────────────────────────────────────────
  check_dnsbl "$domain" || {
    (( ++hard_flags )) || true
    verdict="FLAGGED"
  }

  # ── MX IP DNSBL check ──────────────────────────────────────────────────────
  if ! $SKIP_IP_DNSBL; then
    check_ip_dnsbl "$domain" || {
      (( ++hard_flags )) || true
      verdict="FLAGGED"
    }
  fi

  # ── Domain age check ───────────────────────────────────────────────────────
  # Return code 1 = hard flag (confirmed too young).
  # Return code 2 = inconclusive (WHOIS unavailable / unparseable) → advisory.
  # Return code 3 = advisory warn tier (between min-age and warn-age).
  local age_rc=0
  check_domain_age "$domain" || age_rc=$?
  case $age_rc in
    1) (( ++hard_flags )) || true
       [[ "$verdict" == "CLEAN" ]] && verdict="SUSPICIOUS" || true ;;
    2) (( ++warn_flags )) || true ;;
    3) (( ++warn_flags )) || true ;;
  esac

  # ── Open relay check ────────────────────────────────────────────────────────
  # An open relay is a hard flag — it is a more direct indicator of malicious
  # or severely misconfigured infrastructure than a DNSBL listing, which may
  # reflect past behaviour.  An open relay is observable, current, and
  # reproducible at query time.
  if ! $SKIP_RELAY_CHECK; then
    if ! check_open_relay "$domain"; then
      (( ++hard_flags )) || true
      verdict="FLAGGED"
    fi
  fi

  # ── Print verdict ──────────────────────────────────────────────────────────
  if $JSON_OUTPUT; then
    JSON_RESULTS+=( "$(emit_json "$domain" "$verdict" "$hard_flags" "$warn_flags")" )
  elif $QUIET; then
    case "$verdict" in
      CLEAN)      echo -e "${GREEN}[CLEAN]${NC}      $domain (${warn_flags} advisory note(s))" ;;
      SUSPICIOUS) echo -e "${YELLOW}[SUSPICIOUS]${NC} $domain (confirmed young domain)" ;;
      FLAGGED)
        if $JSON_RELAY_OPEN; then
          echo -e "${RED}[FLAGGED]${NC}    $domain (OPEN RELAY detected)"
        else
          echo -e "${RED}[FLAGGED]${NC}    $domain (DNSBL listed)"
        fi ;;
    esac
  else
    echo ""
    case "$verdict" in
      CLEAN)
        if (( hard_flags == 0 && warn_flags == 0 )); then
          echo -e "  ${GREEN}► VERDICT: CLEAN — no issues found${NC}"
        else
          echo -e "  ${GREEN}► VERDICT: CLEAN — passed all hard checks, ${warn_flags} advisory note(s)${NC}"
        fi ;;
      SUSPICIOUS)
        echo -e "  ${YELLOW}► VERDICT: SUSPICIOUS — domain confirmed too young (below ${MIN_DOMAIN_AGE_DAYS}-day threshold)${NC}" ;;
      FLAGGED)
        if $JSON_RELAY_OPEN; then
          local open_ports_display
          open_ports_display=$(printf '%s\n' "${JSON_RELAY_PORTS_TRIED[@]}" \
            | jq -rcs '[.[] | select(.result=="relay_accepted") | .port | tostring] | join(",")')
          echo -e "  ${RED}► VERDICT: FLAGGED — OPEN RELAY detected on port(s): ${open_ports_display} (${hard_flags} hard flag(s), ${warn_flags} advisory note(s))${NC}"
        else
          echo -e "  ${RED}► VERDICT: FLAGGED — listed on one or more DNSBLs (${hard_flags} hard flag(s), ${warn_flags} advisory note(s))${NC}"
        fi ;;
    esac
  fi

  [[ "$verdict" == "CLEAN" ]] && return 0 || return 1
}

# ── Input parsing ──────────────────────────────────────────────────────────────
parse_input() {
  local input="$1"
  if [[ "$input" == "-" ]]; then
    cat
  elif [[ -f "$input" ]]; then
    cat "$input"
  else
    echo "$input" | tr ',;' '\n'
  fi
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -a|--min-age)      MIN_DOMAIN_AGE_DAYS="$2"; shift 2 ;;
      --warn-age)        WARN_DOMAIN_AGE_DAYS="$2"; shift 2 ;;
      -j|--json)         JSON_OUTPUT=true; QUIET=true; shift ;;
      -sj|-js)           JSON_OUTPUT=true; QUIET=true; shift ;;
      -s|--silent|-q|--quiet) QUIET=true; shift ;;
      -v|--verbose)      VERBOSE=true; shift ;;
      --skip-whois)      SKIP_WHOIS=true; shift ;;
      --skip-ip-dnsbl)   SKIP_IP_DNSBL=true; shift ;;
      --skip-relay-check) SKIP_RELAY_CHECK=true; shift ;;
      --version)         echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
      -h|--help)         usage ;;
      --)                shift; break ;;
      -*)                echo "Unknown option: $1" >&2; exit 2 ;;
      *)                 break ;;
    esac
  done

  local input="${1:-}"
  [[ -z "$input" ]] && usage

  check_deps

  local overall_rc=0
  local total=0 passed=0 failed=0

  while IFS= read -r line; do
    local entry
    entry=$(echo "$line" | tr -d '[:space:]')
    [[ -z "$entry" || "$entry" == \#* ]] && continue

    (( ++total ))
    if check_domain "$entry"; then
      (( ++passed ))
    else
      (( ++failed ))
      overall_rc=1
    fi
  done < <(parse_input "$input")

  if $JSON_OUTPUT; then
    local results_array
    results_array=$(printf '%s\n' "${JSON_RESULTS[@]}" | jq -sc .)
    jq -n \
      --arg  timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg  version   "$VERSION" \
      --argjson total  "$total" \
      --argjson passed "$passed" \
      --argjson failed "$failed" \
      --argjson results "$results_array" \
      '{ domain_reputation: {
          timestamp: $timestamp,
          version:   $version,
          summary: {
            total:  $total,
            passed: $passed,
            failed: $failed
          },
          results: $results
        }}'
  elif (( total > 1 )) && ! $QUIET; then
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD} Summary: ${total} checked — ${GREEN}${passed} passed${NC}${BOLD}, ${RED}${failed} flagged${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  fi

  exit $overall_rc
}

main "$@"
