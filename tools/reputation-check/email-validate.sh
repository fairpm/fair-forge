#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Package Profiler Contributors
#
# email-validate.sh
# Validates email addresses for syntax, role-based identity, disposable domain,
# MX records, PTR records, and SMTP deliverability without sending a message.
#
# Companion script to the Package Profiler suite — designed to validate contact
# addresses extracted from package metadata (composer.json, package.json, SBOM
# author fields, etc.).  Can be run standalone or integrated into a review
# pipeline via JSON output mode.
#
# Usage:
#   ./email-validate.sh [OPTIONS] <email|file|->
#   ./email-validate.sh user@example.com
#   ./email-validate.sh "a@b.com, c@d.com"
#   ./email-validate.sh emails.txt
#   echo "user@example.com" | ./email-validate.sh -
#
# Options:
#   -t, --timeout SECS     SMTP connection timeout in seconds (default: 10)
#   -j, --json             JSON output to stdout (suppresses terminal output)
#   -sj, -js               Silent + JSON — pipe-friendly; identical to -j
#   -q, --quiet            Quiet mode: only print the verdict line per address
#   -v, --verbose          Show additional diagnostic detail
#       --skip-smtp        Skip the SMTP probe entirely (DNS checks only)
#       --fail-on-role     Exit 1 when a role-based address is detected
#       --version          Print version and exit
#   -h, --help             Show this help
#
# Exit codes:
#   0  All addresses passed
#   1  One or more addresses failed, were flagged as role, or are suspicious
#   2  Dependency missing or argument error
#
# CONFIDENCE SCORING:
#   Each check contributes positive or negative points to a running score.
#   Hard states (VERIFIED, UNDELIVERABLE, ROLE_ADDRESS) bypass the threshold
#   entirely.  Score-based verdicts:
#     >= 60   LIKELY DELIVERABLE
#     >= 20   PROBABLY DELIVERABLE
#     >= -10  INCONCLUSIVE
#     < -10   PROBABLY UNDELIVERABLE
#
# JSON OUTPUT:
#   -j / -sj emit a single JSON document with a "email_validation" root key.
#   When multiple addresses are validated, all results appear in "results[]".
#   Requires jq for JSON output; terminal output mode has no jq dependency.

IFS=$' \t\n'
set -uo pipefail

VERSION="1.0.0"

# ── Defaults ───────────────────────────────────────────────────────────────────
SMTP_TIMEOUT=10
QUIET=false
VERBOSE=false
JSON_OUTPUT=false
SKIP_SMTP=false
FAIL_ON_ROLE=false
SKIP_RELAY_CHECK=false
SCRIPT_NAME="$(basename "$0")"

# Local-parts that are known role addresses but are expected and acceptable in
# this context — detected and noted, but not penalised and not subject to
# --fail-on-role.  Populated via --exempt-role; stored normalised to lowercase.
# Example: security@, support@, privacy@ are commonly listed in package
# manifests as legitimate contact points and should not penalise a package score.
ROLE_EXEMPT_LOCAL_PARTS=()

DISPOSABLE_LIST_URL="https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
DISPOSABLE_CACHE="${TMPDIR:-/tmp}/disposable_domains.txt"
CACHE_MAX_AGE_HOURS=24

# ── Colours ────────────────────────────────────────────────────────────────────
# Colour codes are only set when stdout is a terminal.  When piping (-j mode,
# redirect, or subprocess), NC/RED/GREEN etc. remain empty strings so no escape
# sequences bleed into downstream consumers.
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# ── Terminal output helpers ────────────────────────────────────────────────────
# All four helpers suppress output when either QUIET or JSON_OUTPUT is true.
# JSON mode accumulates state in variables; emit_json() renders it at the end.
# Using `$VAR || cmd` exploits the fact that QUIET/JSON_OUTPUT hold literal
# bash commands "true" or "false", short-circuiting when true.
pass() { $QUIET || $JSON_OUTPUT || echo -e "  ${GREEN}✓${NC} $*"; }
fail() { $QUIET || $JSON_OUTPUT || echo -e "  ${RED}✗${NC} $*"; }
warn() { $QUIET || $JSON_OUTPUT || echo -e "  ${YELLOW}~${NC} $*"; }
info() { $QUIET || $JSON_OUTPUT || echo -e "  ${CYAN}i${NC} $*"; }

# ── Known catch-all providers ──────────────────────────────────────────────────
# These providers return 250 OK for any RCPT TO regardless of mailbox existence,
# making the SMTP probe meaningless for address-existence confirmation.
# The list covers providers with documented or well-observed catch-all behaviour
# at scale.  Custom-domain users of Google Workspace / Microsoft 365 are caught
# separately by is_google_mx() / is_microsoft_mx().
CATCHALL_DOMAINS=(
  gmail.com googlemail.com
  outlook.com hotmail.com hotmail.co.uk hotmail.fr hotmail.de hotmail.es
  hotmail.it hotmail.nl live.com live.co.uk live.fr live.de live.nl
  live.com.au live.ca msn.com passport.com
  icloud.com me.com mac.com
  yahoo.com yahoo.co.uk yahoo.fr yahoo.de yahoo.es yahoo.it yahoo.ca
  yahoo.com.au yahoo.co.jp yahoo.co.nz yahoo.gr ymail.com rocketmail.com
  aol.com aim.com verizon.net
  proton.me protonmail.com protonmail.ch pm.me
  fastmail.com fastmail.fm fastmail.net fastmail.org fastmail.to
  fastmail.us fastmail.cn fastmail.es fastmail.de
  zoho.com zohomail.com
  yandex.com yandex.ru yandex.ua yandex.by yandex.kz ya.ru
  mail.ru inbox.ru list.ru bk.ru internet.ru
  gmx.com gmx.net gmx.de gmx.at gmx.ch web.de
  tutanota.com tutanota.de tutamail.com tuta.io keemail.me
  runbox.com
  posteo.de posteo.net posteo.eu
  mailfence.com
)

# ── Role address map ───────────────────────────────────────────────────────────
# Role-based addresses are valid RFC addresses but represent functions, teams,
# or automated processes rather than individual people.  They appear frequently
# in package metadata (plugin author fields, composer.json contacts) and are
# a signal worth surfacing without being a hard disqualifier.
#
# Four categories with distinct scoring rationale:
#
#   system      RFC-mandated or infrastructure addresses (postmaster, abuse,
#               hostmaster).  These must exist per RFC 2142 and DO receive mail,
#               but they are not personal — score penalty: -15.
#
#   automation  Addresses specifically designed NOT to receive replies
#               (noreply, do-not-reply, mailer-daemon).  If a package lists one
#               of these as an author or contact email, it's almost certainly a
#               copy-paste error or a placeholder — score penalty: -30.
#
#   departmental  Shared team inboxes that may route to a real person but are
#               not individually owned (info@, support@, sales@).  Common,
#               legitimate, but not a personal address — score penalty: -10.
#
#   distribution  Alias lists that reach multiple recipients.  A developer
#               using all@company.com as their author email is suspicious —
#               score penalty: -20.
#
# Each local-part is stored in lower-case; check_role() normalises the input
# and strips subaddress tags (e.g., admin+filter → admin) before lookup.
declare -A ROLE_ADDRESS_MAP=(

  # ── system ──────────────────────────────────────────────────────────────────
  # RFC 2142 requires postmaster, abuse, and hostmaster to exist on every
  # domain that accepts mail.  root, mailer-daemon, and listmaster are
  # conventional infrastructure addresses present on virtually every mail server.
  [postmaster]=system
  [hostmaster]=system
  [webmaster]=system
  [abuse]=system
  [root]=system
  [mailer-daemon]=system
  [mailerdaemon]=system
  [listmaster]=system
  [listserv]=system
  [bounce]=system
  [bounces]=system
  [ndr]=system          # Non-Delivery Report — Exchange convention
  [devnull]=system      # used as a discard sink

  # ── automation ──────────────────────────────────────────────────────────────
  # These addresses by design do not accept inbound mail.  An author field
  # containing noreply@ almost always indicates a template that was never
  # personalised, or an automated system that generated the package manifest.
  [noreply]=automation
  [no-reply]=automation
  [no_reply]=automation
  [donotreply]=automation
  [do-not-reply]=automation
  [do_not_reply]=automation
  [donot-reply]=automation
  [notifications]=automation
  [notification]=automation
  [notify]=automation
  [automated]=automation
  [automailer]=automation
  [autoreply]=automation
  [auto-reply]=automation
  [auto_reply]=automation
  [daemon]=automation
  [robot]=automation
  [bot]=automation
  [system]=automation   # generic system@ sender on many platforms
  [noreply+]=automation

  # ── departmental ────────────────────────────────────────────────────────────
  # Shared functional inboxes.  Legitimate for organisations to use as a
  # published contact, but not a personal developer address.  The -10 penalty
  # is mild because info@, support@, and contact@ are common on small projects
  # where one person manages everything.
  [admin]=departmental
  [administrator]=departmental
  [info]=departmental
  [information]=departmental
  [contact]=departmental
  [contactus]=departmental
  [contact-us]=departmental
  [help]=departmental
  [support]=departmental
  [helpdesk]=departmental
  [help-desk]=departmental
  [service]=departmental
  [services]=departmental
  [billing]=departmental
  [accounts]=departmental
  [accounting]=departmental
  [finance]=departmental
  [hr]=departmental
  [humanresources]=departmental
  [human-resources]=departmental
  [legal]=departmental
  [compliance]=departmental
  [marketing]=departmental
  [sales]=departmental
  [press]=departmental
  [media]=departmental
  [pr]=departmental
  [publicrelations]=departmental
  [public-relations]=departmental
  [security]=departmental
  [spam]=departmental   # abuse/spam reporting alias
  [phishing]=departmental
  [fraud]=departmental
  [report]=departmental
  [reports]=departmental
  [newsletter]=departmental
  [news]=departmental
  [subscribe]=departmental
  [unsubscribe]=departmental
  [feedback]=departmental
  [careers]=departmental
  [jobs]=departmental
  [recruitment]=departmental
  [recruiting]=departmental
  [team]=departmental
  [devteam]=departmental
  [ops]=departmental
  [devops]=departmental
  [sre]=departmental
  [it]=departmental
  [itsupport]=departmental
  [it-support]=departmental

  # ── distribution ────────────────────────────────────────────────────────────
  # Aliases that reach multiple recipients simultaneously.  Unlike departmental
  # addresses, these are clearly list-style and should never appear as an
  # individual author or developer contact.
  [all]=distribution
  [everyone]=distribution
  [staff]=distribution
  [employees]=distribution
  [users]=distribution
  [members]=distribution
  [list]=distribution
  [lists]=distribution
  [dlist]=distribution
  [distribution]=distribution
  [general]=distribution
  [announce]=distribution
  [announcements]=distribution
  [internal]=distribution
  [company]=distribution
)

# ── Role penalty table ─────────────────────────────────────────────────────────
# Score adjustments per category.  Stored separately from the map so they
# can be tuned without touching the address list.
declare -A ROLE_SCORE=(
  [system]=-15
  [automation]=-30
  [departmental]=-10
  [distribution]=-20
)

# ── Help ───────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] <email|file|->

Options:
  -t, --timeout SECS     SMTP timeout (default: $SMTP_TIMEOUT)
  -j, --json             JSON output to stdout (requires jq)
  -sj, -js               Silent + JSON — pipe-friendly
  -q, --quiet            Quiet mode — only print verdict lines
  -v, --verbose          Show additional diagnostic detail
      --skip-smtp        Skip SMTP probe (DNS-only mode; faster)
      --fail-on-role     Exit 1 if address is role-based (default: warn only)
      --skip-relay-check Skip open relay detection (only relevant when SMTP probe runs)
      --exempt-role LOCAL  Exempt a role local-part from penalty and --fail-on-role
                         (address is still noted as role-based; no score impact)
                         Accepts comma-separated values; flag may be repeated
                         e.g. --exempt-role security,privacy --exempt-role support
      --version          Print version and exit
  -h, --help             Show this help

Input formats:
  Single address:        $SCRIPT_NAME user@example.com
  Comma/semicolon list:  $SCRIPT_NAME "a@b.com, c@d.com"
  File (one per line):   $SCRIPT_NAME addresses.txt
  Stdin:                 echo "user@example.com" | $SCRIPT_NAME -

Verdicts:
  VERIFIED              SMTP confirmed mailbox exists; catch-all ruled out
  LIKELY DELIVERABLE    Score >= 60; strong positive signals
  PROBABLY DELIVERABLE  Score >= 20; passes basic checks
  INCONCLUSIVE          Score -10 to 19; mixed signals or provider limits
  PROBABLY UNDELIVERABLE  Score < -10; multiple negative signals
  UNDELIVERABLE         Hard failure — syntax invalid or 5xx RCPT rejection
  UNVERIFIABLE          Catch-all provider or server — cannot confirm mailbox
  ROLE_ADDRESS          Role-based address detected (with --fail-on-role only)
EOF
  exit 0
}

# ── Dependency check ───────────────────────────────────────────────────────────
check_deps() {
  local missing=()
  command -v dig     &>/dev/null || missing+=("dig (bind-utils / dnsutils)")
  command -v curl    &>/dev/null || missing+=("curl")
  command -v openssl &>/dev/null || missing+=("openssl (required for STARTTLS / implicit-TLS SMTP probes on ports 587 and 465)")
  if $JSON_OUTPUT; then
    command -v jq &>/dev/null || missing+=("jq (required for --json mode)")
  fi
  if (( ${#missing[@]} > 0 )); then
    echo -e "${RED}Error:${NC} Missing required tools:" >&2
    for dep in "${missing[@]}"; do echo "  • $dep" >&2; done
    exit 2
  fi

  # 'timeout' (GNU coreutils) prevents the SMTP probe from hanging for TCP's
  # own SYN timeout (~60s) when port 25 is silently firewalled.
  # 'gtimeout' is the macOS Homebrew coreutils alias.
  # Operation continues without it, but users on residential ISPs or CI
  # environments that block port 25 may see long pauses.
  command -v timeout &>/dev/null || command -v gtimeout &>/dev/null \
    || warn "Neither 'timeout' nor 'gtimeout' found — SMTP probe may hang up to ~60s on firewalled hosts"

  # python3 is used only for IPv6 PTR query construction in check_mx_ptr().
  # If absent, IPv6 PTR lookups are skipped with a warning; all other checks
  # are unaffected.  IPv4 PTR lookups use pure bash and have no python3 dependency.
  command -v python3 &>/dev/null \
    || warn "python3 not found — IPv6 PTR record lookups will be skipped"
}

# ── Disposable domain cache ────────────────────────────────────────────────────
# The disposable domain list is fetched from GitHub and cached locally for up to
# CACHE_MAX_AGE_HOURS.  On failure, the check is skipped gracefully — missing
# the disposable check is far preferable to blocking on a network failure.
refresh_disposable_cache() {
  local age=99999
  if [[ -f "$DISPOSABLE_CACHE" ]]; then
    local modified
    modified=$(date -r "$DISPOSABLE_CACHE" +%s 2>/dev/null \
      || stat -c %Y "$DISPOSABLE_CACHE" 2>/dev/null \
      || echo 0)
    age=$(( ( $(date +%s) - modified ) / 3600 ))
  fi

  if (( age >= CACHE_MAX_AGE_HOURS )); then
    $QUIET || $JSON_OUTPUT || echo -e "${CYAN}Refreshing disposable domain list...${NC}"
    if ! curl -sSf --max-time 15 "$DISPOSABLE_LIST_URL" -o "$DISPOSABLE_CACHE" 2>/dev/null; then
      warn "Could not fetch disposable domain list — disposable check will be skipped."
      DISPOSABLE_CACHE=""
    fi
  fi
}

# ── Check functions ────────────────────────────────────────────────────────────

check_syntax() {
  # Validates against a pragmatic subset of RFC 5321/5322.
  # Supported: local-part of [a-zA-Z0-9._%+-], domain with at least one dot,
  # TLD of at least 2 characters.
  # Not supported: quoted local-parts ("first last"@example.com), IP literals
  # ([192.168.1.1]), and internationalized domain names (IDN) — these are rare
  # in package metadata and would require significantly more logic.
  local email="$1"
  [[ "$email" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]
}

check_role() {
  # Checks whether the local-part of the address matches a known role address.
  # Sets ROLE_LOCAL and ROLE_CATEGORY globals; returns 0 if role detected,
  # 1 if not.
  #
  # Normalisation: strips RFC 5233 subaddress tags (admin+filter → admin)
  # before lookup so tagged variants of role addresses are caught correctly.
  # Lowercasing is applied for case-insensitive matching.
  local local_part="$1"
  local normalised="${local_part,,}"      # to lowercase
  normalised="${normalised%%+*}"          # strip subaddress tag

  ROLE_LOCAL=""
  ROLE_CATEGORY=""

  local cat="${ROLE_ADDRESS_MAP[$normalised]:-}"
  if [[ -n "$cat" ]]; then
    ROLE_LOCAL="$normalised"
    ROLE_CATEGORY="$cat"
    return 0
  fi
  return 1
}

check_disposable() {
  local domain="$1"
  [[ -n "${DISPOSABLE_CACHE:-}" && -f "$DISPOSABLE_CACHE" ]] \
    && grep -qx "$domain" "$DISPOSABLE_CACHE"
}

is_catchall_domain() {
  local domain="$1"
  local d
  for d in "${CATCHALL_DOMAINS[@]}"; do
    [[ "$domain" == "$d" ]] && return 0
  done
  return 1
}

is_google_mx() {
  # Catches Google Workspace custom domains whose MX points to Google servers.
  local mx="$1"
  [[ "$mx" == *".google.com" || "$mx" == *".googlemail.com" ]]
}

is_microsoft_mx() {
  # Catches Exchange Online / Microsoft 365 custom domains.
  local mx="$1"
  [[ "$mx" == *".protection.outlook.com" || "$mx" == *"mail.protection.outlook.com" ]]
}

get_mx_host() {
  local domain="$1"
  local mx

  # Prefer the lowest-priority (most preferred) MX record.
  mx=$(dig +short +time=5 +tries=2 MX "$domain" 2>/dev/null \
    | sort -n \
    | awk '{print $2}' \
    | head -1 \
    | sed 's/\.$//')

  if [[ -z "$mx" ]]; then
    # Some domains accept mail via their A record with no explicit MX.
    # This is technically valid (RFC 5321 §5) and worth attempting.
    mx=$(dig +short +time=5 +tries=2 A "$domain" 2>/dev/null | head -1)
  fi

  echo "$mx"
}

# ── SMTP globals ───────────────────────────────────────────────────────────────
# FD for plain /dev/tcp connections.  63 chosen over low numbers because bash
# and its builtins (process substitution, here-strings) internally use FDs 3–9.
SMTP_FD=63

# Abstracted read/write FDs — set by smtp_open_plain() or smtp_open_tls().
# All smtp_read_resp() / smtp_send() calls use these instead of SMTP_FD
# directly, so the same dialogue code works for both plain and TLS connections.
SMTP_READ_FD=63
SMTP_WRITE_FD=63

# TLS connection state — managed by smtp_open_tls() / smtp_close().
SMTP_USE_TLS=false
SMTP_TLS_PID=""

# When true, the post-TLS EHLO exchange has already been completed by
# smtp_open_tls() during STARTTLS negotiation.  smtp_run_dialogue() skips
# its own EHLO step when this flag is set.
SMTP_TLS_EHLO_DONE=false

SMTP_CODE=""
SMTP_TEXT=""

# Probe stage flags — set by smtp_probe(), read by validate_email() for scoring.
SMTP_PROBE_CONNECTED=false    # TCP connection succeeded on at least one port
SMTP_PROBE_BANNER=false       # 220 banner received
SMTP_PROBE_MAIL_FROM=false    # MAIL FROM accepted
SMTP_PROBE_FALLBACK_ALIVE=false   # banner grab on 2525 succeeded (no full dialogue)
SMTP_PROBE_PORT=0             # port on which the full dialogue succeeded
SMTP_PROBE_PORTS_TRIED=()        # per-port outcomes: {"port":N,"result":"completed|unreachable|banner_only"}
SMTP_PROBE_TLS=false          # whether TLS was used for the successful dialogue
SMTP_PROBE_OPEN_RELAY=false   # open relay probe accepted an external domain

# ── SMTP helpers ───────────────────────────────────────────────────────────────

smtp_read_resp() {
  # Reads one complete SMTP response from SMTP_READ_FD.
  # SMTP multi-line responses continue while the 4th character is '-';
  # the final line has a space in position 4.  We discard continuation lines
  # and only expose the final code + text to callers.
  SMTP_CODE=""; SMTP_TEXT=""
  local line
  while IFS= read -t "$SMTP_TIMEOUT" -r line <&"$SMTP_READ_FD"; do
    line="${line%$'\r'}"
    SMTP_CODE="${line:0:3}"
    SMTP_TEXT="$line"
    [[ "${line:3:1}" != "-" ]] && break
  done
}

smtp_send() { printf '%s\r\n' "$1" >&"$SMTP_WRITE_FD" 2>/dev/null || true; }

smtp_close() {
  smtp_send "QUIT"
  if $SMTP_USE_TLS; then
    # Close the coprocess FDs so openssl receives EOF on stdin and exits.
    # Wait for the PID to fully reap the process before the name is reusable.
    eval "exec ${SMTP_WRITE_FD}>&-" 2>/dev/null || true
    eval "exec ${SMTP_READ_FD}<&-"  2>/dev/null || true
    [[ -n "$SMTP_TLS_PID" ]] && wait "$SMTP_TLS_PID" 2>/dev/null || true
    SMTP_TLS_PID=""
    SMTP_USE_TLS=false
    SMTP_TLS_EHLO_DONE=false
  else
    eval "exec ${SMTP_FD}>&-" 2>/dev/null || true
    eval "exec ${SMTP_FD}<&-" 2>/dev/null || true
  fi
  SMTP_READ_FD=63
  SMTP_WRITE_FD=63
}

smtp_random_local() {
  # Generates a random local-part that is astronomically unlikely to be a real
  # mailbox.  Used as the catch-all probe address.  Prefers /proc/sys uuid for
  # true randomness; falls back to /dev/urandom hex.
  local rand
  rand=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-') \
    || rand=$(od -An -N12 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  echo "zzprobe${rand:0:16}zz"
}

smtp_open_plain() {
  # Opens a plain TCP connection to host:port via bash's /dev/tcp facility.
  # Sets SMTP_READ_FD and SMTP_WRITE_FD to SMTP_FD (bidirectional).
  # Returns 0 on success, 1 if unreachable or connection refused.
  local host="$1" port="$2"
  local timeout_cmd=""
  command -v timeout  &>/dev/null && timeout_cmd="timeout"
  command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"

  # Quick reachability test before opening the persistent FD.
  # Without 'timeout', bash's /dev/tcp will block for up to TCP's SYN timeout
  # (~60 s) on a silently firewalled port.
  if [[ -n "$timeout_cmd" ]]; then
    $timeout_cmd "$SMTP_TIMEOUT" bash -c \
      "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null || return 1
  fi

  eval "exec ${SMTP_FD}<>/dev/tcp/${host}/${port}" 2>/dev/null || return 1
  SMTP_READ_FD=$SMTP_FD
  SMTP_WRITE_FD=$SMTP_FD
  SMTP_USE_TLS=false
  return 0
}

smtp_open_tls() {
  # Opens a TLS-protected SMTP connection via an openssl coprocess.
  #
  # For implicit TLS (port 465, use_starttls=false):
  #   TLS handshake happens immediately; the first thing we read is the 220
  #   banner after TLS establishment.  smtp_run_dialogue() proceeds normally.
  #
  # For STARTTLS (port 587, use_starttls=true):
  #   openssl handles the EHLO + STARTTLS exchange on our behalf before handing
  #   control to us.  This means the coprocess output contains pre-TLS SMTP
  #   traffic (220 banner, 250 EHLO, 220 STARTTLS confirm) that we must drain
  #   before starting our own dialogue.  After draining, we send our post-TLS
  #   EHLO and set SMTP_TLS_EHLO_DONE=true so smtp_run_dialogue() skips its own
  #   EHLO step.
  #
  # The coprocess pattern is used because it gives us bidirectional I/O with
  # the openssl process using numbered FDs, which the existing smtp_read_resp()
  # and smtp_send() functions can consume without modification.
  local host="$1" port="$2" use_starttls="${3:-false}"
  local timeout_cmd=""
  command -v timeout  &>/dev/null && timeout_cmd="timeout"
  command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"

  # Quick TCP reachability check before spawning openssl.
  if [[ -n "$timeout_cmd" ]]; then
    $timeout_cmd "$SMTP_TIMEOUT" bash -c \
      "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null || return 1
  fi

  # Kill any leftover TLS coprocess from a previous failed attempt.
  if [[ -n "$SMTP_TLS_PID" ]]; then
    kill "$SMTP_TLS_PID" 2>/dev/null || true
    wait "$SMTP_TLS_PID" 2>/dev/null || true
    SMTP_TLS_PID=""
  fi

  local starttls_flag=""
  $use_starttls && starttls_flag="-starttls smtp"

  # shellcheck disable=SC2086  (word-splitting intentional for $starttls_flag)
  coproc SMTP_TLS_COPROC {
    exec openssl s_client \
      -connect "${host}:${port}" \
      $starttls_flag \
      -quiet -ign_eof 2>/dev/null
  }

  SMTP_TLS_PID="$SMTP_TLS_COPROC_PID"
  SMTP_READ_FD="${SMTP_TLS_COPROC[0]}"
  SMTP_WRITE_FD="${SMTP_TLS_COPROC[1]}"
  SMTP_USE_TLS=true
  SMTP_TLS_EHLO_DONE=false

  if $use_starttls; then
    # Drain the three pre-TLS responses that openssl handled on our behalf:
    #   1. 220  initial server banner
    #   2. 250  EHLO response (possibly multi-line; smtp_read_resp loops it)
    #   3. 220  "Ready to start TLS" confirmation
    # After draining, TLS is established and the server is waiting for EHLO.
    local i
    for i in 1 2 3; do
      smtp_read_resp
      if [[ -z "$SMTP_CODE" ]]; then
        # openssl exited or timed out during STARTTLS negotiation
        smtp_close
        return 1
      fi
    done
    # Issue the post-TLS EHLO ourselves before returning.
    smtp_send "EHLO probe.example.invalid"
    smtp_read_resp
    if [[ "$SMTP_CODE" != "250" ]]; then
      smtp_close
      return 1
    fi
    SMTP_TLS_EHLO_DONE=true
  fi

  return 0
}

smtp_run_dialogue() {
  # Executes the full EHLO → MAIL FROM → RCPT TO → catch-all probe →
  # open relay probe sequence on an already-open connection (FDs are set).
  # Called by smtp_probe() after a successful smtp_open_plain/tls().
  #
  # Arguments: email  port  tls_used
  # The port and tls_used arguments are used solely to write the ports_tried
  # entry at the point where the dialogue outcome is known.  Result values:
  #   rcpt_rejected   — 5xx response to RCPT TO (mailbox does not exist)
  #   rcpt_accepted   — RCPT TO accepted (catch-all status determined separately)
  #   dialogue_failed — connected but dialogue broke before RCPT TO
  #
  # Return codes:
  #   0 = RCPT accepted, catch-all rejected, relay check passed → VERIFIED
  #   1 = 5xx RCPT rejection                                    → UNDELIVERABLE
  #   3 = connected; dialogue failed before RCPT TO             → inconclusive
  #   4 = RCPT accepted, catch-all confirmed                    → UNVERIFIABLE
  #   5 = RCPT accepted, catch-all inconclusive                 → partial score
  #  (open relay status set in SMTP_PROBE_OPEN_RELAY regardless of above)
  local email="$1" port="$2" tls_used="$3"
  local domain="${email#*@}"

  # ── EHLO / HELO ─────────────────────────────────────────────────────────────
  # Skip if smtp_open_tls() already completed EHLO during STARTTLS draining.
  if ! $SMTP_TLS_EHLO_DONE; then
    smtp_send "EHLO probe.example.invalid"
    smtp_read_resp
    if [[ "$SMTP_CODE" != "250" ]]; then
      warn "SMTP: EHLO returned $SMTP_CODE, trying HELO"
      smtp_send "HELO probe.example.invalid"
      smtp_read_resp
      if [[ "$SMTP_CODE" != "250" ]]; then
        fail "SMTP: HELO failed — $SMTP_TEXT"
        SMTP_PROBE_PORTS_TRIED+=("{\"port\":${port},\"tls\":${tls_used},\"result\":\"dialogue_failed\"}")
        smtp_close; return 3
      fi
    fi
  fi

  # ── MAIL FROM ────────────────────────────────────────────────────────────────
  smtp_send "MAIL FROM:<noreply@example.invalid>"
  smtp_read_resp
  if [[ "$SMTP_CODE" != "250" ]]; then
    warn "SMTP: MAIL FROM rejected ($SMTP_CODE) — $SMTP_TEXT"
    SMTP_PROBE_PORTS_TRIED+=("{\"port\":${port},\"tls\":${tls_used},\"result\":\"dialogue_failed\"}")
    smtp_close; return 3
  fi
  SMTP_PROBE_MAIL_FROM=true

  # ── RCPT TO (target address) ─────────────────────────────────────────────────
  smtp_send "RCPT TO:<${email}>"
  smtp_read_resp

  if [[ "$SMTP_CODE" =~ ^5 ]]; then
    fail "SMTP: mailbox rejected — $SMTP_TEXT"
    JSON_SMTP_RCPT_ACCEPTED=false
    SMTP_PROBE_PORTS_TRIED+=("{\"port\":${port},\"tls\":${tls_used},\"result\":\"rcpt_rejected\"}")
    smtp_close; return 1
  elif [[ "$SMTP_CODE" != "250" && "$SMTP_CODE" != "251" ]]; then
    warn "SMTP: unexpected response to RCPT TO: $SMTP_TEXT"
    warn "SMTP: this typically indicates greylisting or a temporary server failure"
    SMTP_PROBE_PORTS_TRIED+=("{\"port\":${port},\"tls\":${tls_used},\"result\":\"dialogue_failed\"}")
    smtp_close; return 3
  fi

  pass "SMTP: mailbox accepted — $SMTP_TEXT"
  JSON_SMTP_RCPT_ACCEPTED=true
  # ports_tried entry written after catch-all, below, once full outcome is known

  # ── Catch-all probe ──────────────────────────────────────────────────────────
  # Send a second RCPT TO with a UUID-derived local-part at the same domain.
  # A real server will reject it; a catch-all will accept it, meaning the
  # earlier acceptance of the target address is not evidence of mailbox existence.
  local probe_local
  probe_local=$(smtp_random_local)

  info "SMTP: probing for catch-all with bogus address <${probe_local}@${domain}>"
  smtp_send "RCPT TO:<${probe_local}@${domain}>"
  smtp_read_resp

  local catchall_code="$SMTP_CODE"
  local catchall_result="inconclusive"
  if   [[ "$catchall_code" =~ ^5 ]];                               then catchall_result="ruled_out"
  elif [[ "$catchall_code" == "250" || "$catchall_code" == "251" ]]; then catchall_result="confirmed"
  fi

  # ── Open relay probe ─────────────────────────────────────────────────────────
  SMTP_PROBE_OPEN_RELAY=false
  if ! $SKIP_RELAY_CHECK; then
    local relay_local relay_addr
    relay_local=$(smtp_random_local)
    relay_addr="${relay_local}@example.invalid"

    info "SMTP: probing for open relay with external address <$relay_addr>"
    smtp_send "RCPT TO:<${relay_addr}>"
    smtp_read_resp

    if [[ "$SMTP_CODE" == "250" || "$SMTP_CODE" == "251" ]]; then
      fail "SMTP: OPEN RELAY — server accepted RCPT TO for external domain example.invalid ($SMTP_CODE)"
      fail "SMTP: this server will forward mail for any destination without authentication"
      SMTP_PROBE_OPEN_RELAY=true
      JSON_SMTP_OPEN_RELAY=true
    elif [[ "$SMTP_CODE" =~ ^5 ]]; then
      pass "SMTP: relay probe rejected ($SMTP_CODE) — server does not relay for external domains"
      JSON_SMTP_OPEN_RELAY=false
    else
      warn "SMTP: relay probe returned ${SMTP_CODE:-timeout} — inconclusive"
      JSON_SMTP_OPEN_RELAY=false
    fi
  fi

  smtp_close

  # Write ports_tried entry now that the full outcome is known.
  SMTP_PROBE_PORTS_TRIED+=("{\"port\":${port},\"tls\":${tls_used},\"result\":\"rcpt_accepted\"}")

  JSON_SMTP_CATCHALL="$catchall_result"
  case "$catchall_result" in
    ruled_out)
      pass "SMTP: catch-all probe rejected ($catchall_code) — server validates addresses individually"
      return 0 ;;
    confirmed)
      warn "SMTP: catch-all probe accepted ($catchall_code) — server accepts any address at this domain"
      warn "SMTP: the earlier acceptance of <$email> cannot confirm the mailbox exists"
      return 4 ;;
    *)
      warn "SMTP: catch-all probe returned ${catchall_code:-timeout} — inconclusive"
      return 5 ;;
  esac
}
smtp_probe() {
  # Attempts a full SMTP dialogue to determine whether an address is deliverable.
  # Tries ports in the following order, stopping at the first that yields a
  # definitive RCPT TO result:
  #
  #   1. Port 587 STARTTLS  — submission port with TLS; tried first because
  #                            outbound port 25 is blocked on most cloud VMs,
  #                            CI runners, and residential ISPs.  Requires
  #                            openssl for the STARTTLS handshake.
  #   2. Port 25  plain     — MTA-to-MTA relay; the RFC-authoritative port for
  #                            delivery confirmation.  Frequently blocked outbound
  #                            but definitive when reachable.
  #   3. Port 465 TLS       — SMTPS (implicit TLS); re-standardised in RFC 8314
  #                            (2018) and widely re-enabled on modern servers.
  #                            Requires openssl.
  #   4. Port 2525 plain    — Non-standard submission port used by some hosting
  #                            providers (Mailgun, SendGrid, Rackspace) when both
  #                            25 and 587 are blocked.  Banner-only: no RCPT TO
  #                            is attempted because no standard MTA listens here
  #                            for delivery, only for relayed client submission.
  #
  # A full RCPT TO dialogue on any of ports 587/25/465 is equally definitive —
  # VERIFIED/UNDELIVERABLE/UNVERIFIABLE are scored the same regardless of which
  # port succeeded.  The port used is recorded in SMTP_PROBE_PORT and reported
  # in the score log.
  #
  # Return codes:
  #   0 = RCPT accepted, catch-all rejected, relay check passed  → VERIFIED
  #   1 = 5xx RCPT rejection                                     → UNDELIVERABLE
  #   2 = no port reachable (all blocked or server unreachable)  → scored by fallback
  #   3 = connected; dialogue failed before completing RCPT TO   → inconclusive
  #   4 = RCPT accepted, catch-all confirmed                     → UNVERIFIABLE
  #   5 = RCPT accepted, catch-all inconclusive                  → partial score
  local host="$1" email="$2"

  SMTP_PROBE_CONNECTED=false
  SMTP_PROBE_BANNER=false
  SMTP_PROBE_MAIL_FROM=false
  SMTP_PROBE_FALLBACK_ALIVE=false
  SMTP_PROBE_PORT=0
  SMTP_PROBE_PORTS_TRIED=()
  SMTP_PROBE_TLS=false
  SMTP_PROBE_OPEN_RELAY=false

  # ── Port 587 — STARTTLS ────────────────────────────────────────────────────
  info "SMTP: trying port 587 (STARTTLS)..."
  if smtp_open_tls "$host" 587 true; then
    SMTP_PROBE_CONNECTED=true
    SMTP_PROBE_BANNER=true    # openssl confirmed 220 during STARTTLS draining
    SMTP_PROBE_PORT=587
    SMTP_PROBE_TLS=true
    pass "SMTP: connected → $host:587 (STARTTLS)"
    local rc=0
    smtp_run_dialogue "$email" 587 true || rc=$?
    return $rc
  fi
  SMTP_PROBE_PORTS_TRIED+=('{"port":587,"result":"unreachable"}')

  # ── Port 25 — plain ────────────────────────────────────────────────────────
  info "SMTP: port 587 unavailable — trying port 25 (plain)..."
  if smtp_open_plain "$host" 25; then
    SMTP_PROBE_CONNECTED=true
    SMTP_PROBE_PORT=25
    SMTP_PROBE_TLS=false

    # Read 220 banner
    smtp_read_resp
    if [[ "$SMTP_CODE" != "220" ]]; then
      fail "SMTP: unexpected banner on port 25 — got '${SMTP_TEXT:-no response}'"
      SMTP_PROBE_PORTS_TRIED+=("{\"port\":25,\"result\":\"bad_banner\",\"tls\":false,\"code\":\"${SMTP_CODE}\"}")
      smtp_close; return 3
    fi
    SMTP_PROBE_BANNER=true
    pass "SMTP: connected → $host:25"
    pass "SMTP: server ready — $SMTP_TEXT"

    local rc=0
    smtp_run_dialogue "$email" 25 false || rc=$?
    return $rc
  fi
  SMTP_PROBE_PORTS_TRIED+=('{"port":25,"result":"unreachable"}')

  # ── Port 465 — implicit TLS ────────────────────────────────────────────────
  info "SMTP: port 25 unavailable — trying port 465 (implicit TLS)..."
  if smtp_open_tls "$host" 465 false; then
    SMTP_PROBE_CONNECTED=true
    SMTP_PROBE_PORT=465
    SMTP_PROBE_TLS=true

    # For implicit TLS, TLS handshake is done; read the post-TLS 220 banner.
    smtp_read_resp
    if [[ "$SMTP_CODE" != "220" ]]; then
      fail "SMTP: unexpected banner on port 465 — got '${SMTP_TEXT:-no response}'"
      SMTP_PROBE_PORTS_TRIED+=("{\"port\":465,\"result\":\"bad_banner\",\"tls\":true,\"code\":\"${SMTP_CODE}\"}")
      smtp_close; return 3
    fi
    SMTP_PROBE_BANNER=true
    pass "SMTP: connected → $host:465 (TLS)"
    pass "SMTP: server ready — $SMTP_TEXT"

    local rc=0
    smtp_run_dialogue "$email" 465 true || rc=$?
    return $rc
  fi
  SMTP_PROBE_PORTS_TRIED+=('{"port":465,"result":"unreachable"}')

  # ── Port 2525 — banner only ────────────────────────────────────────────────
  info "SMTP: ports 587/25/465 all unavailable — trying port 2525 (banner only)..."
  if smtp_open_plain "$host" 2525; then
    local banner=""
    IFS= read -t "$SMTP_TIMEOUT" -r banner <&"$SMTP_READ_FD" || true
    smtp_close
    banner="${banner%$'\r'}"
    if [[ "$banner" =~ ^220 ]]; then
      pass "SMTP: server alive on port 2525 — banner: $banner"
      SMTP_PROBE_PORTS_TRIED+=('{"port":2525,"result":"banner_only","tls":false}')
      SMTP_PROBE_FALLBACK_ALIVE=true
      info "SMTP: port 2525 is a non-standard submission port — no RCPT TO attempted"
    else
      SMTP_PROBE_PORTS_TRIED+=('{"port":2525,"result":"connected_no_banner","tls":false}')
    fi
  else
    SMTP_PROBE_PORTS_TRIED+=('{"port":2525,"result":"unreachable"}')
  fi

  # All full-dialogue ports are unreachable.
  return 2
}


JSON_SYNTAX_PASS=false
JSON_ROLE_FLAGGED=false
JSON_ROLE_LOCAL=""
JSON_ROLE_CATEGORY=""
JSON_ROLE_EXEMPT=false
JSON_DISPOSABLE_FLAGGED=false
JSON_MX_STATUS="not_checked"
JSON_MX_HOST=""
JSON_PTR_STATUS="not_checked"
JSON_PTR_IP=""
JSON_PTR_VALUE=""
JSON_CATCHALL_SKIPPED=false
JSON_CATCHALL_REASON=""
JSON_SMTP_STATUS="not_checked"
JSON_SMTP_CONNECTED=false
JSON_SMTP_BANNER=false
JSON_SMTP_MAIL_FROM=false
JSON_SMTP_RCPT_ACCEPTED=false
JSON_SMTP_CATCHALL="not_checked"
JSON_SMTP_PORT=0
JSON_SMTP_TLS=false
JSON_SMTP_OPEN_RELAY=false
JSON_SMTP_PORTS_TRIED=()

# Collected JSON result objects (one per address); wrapped by main().
JSON_RESULTS=()

# ── Scoring ────────────────────────────────────────────────────────────────────
_score() {
  local n=$1; shift
  SCORE=$(( SCORE + n ))
  SCORE_LOG+=( "$(printf '%+4d  %s' "$n" "$*")" )
}

# ── Verdict rendering ──────────────────────────────────────────────────────────
_print_verdict() {
  # Renders the confidence score breakdown and final verdict line to the
  # terminal.  In JSON mode this function is a no-op; emit_json() handles
  # output instead.
  $JSON_OUTPUT && return 0

  local email="$1" hard_verdict="${2:-}"
  local verdict

  if [[ -n "$hard_verdict" ]]; then
    verdict="$hard_verdict"
  elif (( SCORE >= 60 )); then
    verdict="LIKELY DELIVERABLE"
  elif (( SCORE >= 20 )); then
    verdict="PROBABLY DELIVERABLE"
  elif (( SCORE >= -10 )); then
    verdict="INCONCLUSIVE"
  else
    verdict="PROBABLY UNDELIVERABLE"
  fi

  if ! $QUIET && (( ${#SCORE_LOG[@]} > 0 )); then
    echo ""
    echo -e "  ${BOLD}${CYAN}── Confidence Score ─────────────────────────────────────${NC}"
    local entry
    for entry in "${SCORE_LOG[@]}"; do
      local sign="${entry:0:1}"
      if   [[ "$sign" == "+" ]]; then echo -e "    ${GREEN}${entry}${NC}"
      elif [[ "$sign" == "-" ]]; then echo -e "    ${RED}${entry}${NC}"
      else                            echo -e "    ${CYAN}${entry}${NC}"
      fi
    done
    echo -e "  ${CYAN}  ───────────────────────────────────────────────────────${NC}"
    printf "    %+4d  total\n" "$SCORE"
    echo ""
  fi

  if $QUIET; then
    case "$verdict" in
      "VERIFIED")               echo -e "${GREEN}[VERIFIED]${NC}             $email" ;;
      "LIKELY DELIVERABLE")     echo -e "${GREEN}[LIKELY DELIVERABLE]${NC}   $email" ;;
      "PROBABLY DELIVERABLE")   echo -e "${CYAN}[PROB. DELIVERABLE]${NC}    $email" ;;
      "INCONCLUSIVE")           echo -e "${YELLOW}[INCONCLUSIVE]${NC}         $email" ;;
      "PROBABLY UNDELIVERABLE") echo -e "${YELLOW}[PROB. UNDELIVERABLE]${NC}  $email" ;;
      "UNDELIVERABLE")          echo -e "${RED}[UNDELIVERABLE]${NC}        $email" ;;
      "UNVERIFIABLE")           echo -e "${YELLOW}[UNVERIFIABLE]${NC}         $email" ;;
      "ROLE_ADDRESS")           echo -e "${YELLOW}[ROLE ADDRESS]${NC}         $email" ;;
    esac
  else
    case "$verdict" in
      "VERIFIED")               echo -e "  ${GREEN}► VERDICT: VERIFIED DELIVERABLE  (score: ${SCORE})${NC}" ;;
      "LIKELY DELIVERABLE")     echo -e "  ${GREEN}► VERDICT: LIKELY DELIVERABLE  (score: ${SCORE})${NC}" ;;
      "PROBABLY DELIVERABLE")   echo -e "  ${CYAN}► VERDICT: PROBABLY DELIVERABLE  (score: ${SCORE})${NC}" ;;
      "INCONCLUSIVE")           echo -e "  ${YELLOW}► VERDICT: INCONCLUSIVE  (score: ${SCORE})${NC}" ;;
      "PROBABLY UNDELIVERABLE") echo -e "  ${YELLOW}► VERDICT: PROBABLY UNDELIVERABLE  (score: ${SCORE})${NC}" ;;
      "UNDELIVERABLE")          echo -e "  ${RED}► VERDICT: UNDELIVERABLE${NC}" ;;
      "UNVERIFIABLE")           echo -e "  ${YELLOW}► VERDICT: UNVERIFIABLE — server accepts all addresses at this domain  (score: ${SCORE})${NC}" ;;
      "ROLE_ADDRESS")           echo -e "  ${YELLOW}► VERDICT: ROLE ADDRESS — ${ROLE_CATEGORY} address detected  (local-part: ${ROLE_LOCAL})${NC}" ;;
    esac
  fi
}
check_mx_ptr() {
  # Resolves the MX hostname to its IP, then queries the PTR record.
  # A PTR whose value matches (or shares the domain of) the MX hostname is a
  # strong positive signal that the server is intentionally operated for mail —
  # dynamic IPs and freshly-spun-up servers typically lack PTR records.
  # Absence is noted but not scored as a hard failure; many legitimate servers
  # skip rDNS configuration.
  #
  # Return codes: 0=matches, 1=exists-no-match, 2=no-PTR, 3=MX-unresolvable
  local mx_host="$1"

  local mx_ip
  mx_ip=$(dig +short +time=5 +tries=2 A    "$mx_host" 2>/dev/null | head -1)
  [[ -z "$mx_ip" ]] && \
  mx_ip=$(dig +short +time=5 +tries=2 AAAA "$mx_host" 2>/dev/null | head -1)

  if [[ -z "$mx_ip" ]]; then
    warn "PTR:  MX hostname $mx_host did not resolve to an IP"
    JSON_PTR_STATUS="unresolved"
    return 3
  fi

  JSON_PTR_IP="$mx_ip"

  local ptr_query ptr_result
  if [[ "$mx_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # IPv4: reverse the octets and append .in-addr.arpa
    ptr_query=$(echo "$mx_ip" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
  else
    # IPv6: python3 handles the nibble-expansion and reversal.
    # The ipaddress module (stdlib since Python 3.3) provides reverse_pointer
    # directly, avoiding a fragile manual implementation.
    ptr_query=$(python3 -c "
import ipaddress, sys
a = ipaddress.ip_address('$mx_ip')
print(a.reverse_pointer)
" 2>/dev/null) || {
      warn "PTR:  IPv6 PTR lookup skipped (python3 unavailable)"
      JSON_PTR_STATUS="skipped_ipv6"
      return 2
    }
  fi

  ptr_result=$(dig +short +time=5 +tries=2 PTR "$ptr_query" 2>/dev/null \
    | sed 's/\.$//' | head -1)

  if [[ -z "$ptr_result" ]]; then
    warn "PTR:  $mx_ip has no PTR record — server may be misconfigured or on a dynamic IP"
    JSON_PTR_STATUS="no_ptr"
    return 2
  fi

  JSON_PTR_VALUE="$ptr_result"
  local mx_lower="${mx_host,,}" ptr_lower="${ptr_result,,}"
  if [[ "$ptr_lower" == "$mx_lower" || "$ptr_lower" == *".${mx_lower#*.}" ]]; then
    pass "PTR:  $mx_ip → $ptr_result (matches MX hostname)"
    JSON_PTR_STATUS="matches"
    return 0
  else
    warn "PTR:  $mx_ip → $ptr_result (does not match MX hostname $mx_host)"
    JSON_PTR_STATUS="mismatch"
    return 1
  fi
}

# ── JSON emission ──────────────────────────────────────────────────────────────
emit_json() {
  # Serialises all JSON state globals for one address into a compact JSON object.
  # Called by validate_email() after the verdict is known; the result is appended
  # to JSON_RESULTS[] and wrapped by main() into the root document.
  local address="$1" verdict="$2"

  # Serialise SCORE_LOG as a JSON array of strings.
  local score_log_json smtp_ports_json
  score_log_json=$(printf '%s\n' "${SCORE_LOG[@]}" \
    | jq -R . | jq -sc .)
  smtp_ports_json=$(printf '%s\n' "${JSON_SMTP_PORTS_TRIED[@]:-}" \
    | grep -v '^$' | jq -Rsc 'split("\n") | map(select(length>0)) | map(fromjson)')

  jq -cn \
    --arg  address    "$address" \
    --arg  verdict    "$verdict" \
    --arg  timestamp  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson score   "$SCORE" \
    --argjson role_flagged    "$JSON_ROLE_FLAGGED" \
    --arg    role_local       "$JSON_ROLE_LOCAL" \
    --arg    role_category    "$JSON_ROLE_CATEGORY" \
    --argjson role_exempt     "$JSON_ROLE_EXEMPT" \
    --argjson disposable      "$JSON_DISPOSABLE_FLAGGED" \
    --arg    mx_status        "$JSON_MX_STATUS" \
    --arg    mx_host          "$JSON_MX_HOST" \
    --arg    ptr_status       "$JSON_PTR_STATUS" \
    --arg    ptr_ip           "$JSON_PTR_IP" \
    --arg    ptr_value        "$JSON_PTR_VALUE" \
    --argjson catchall_skipped  "$JSON_CATCHALL_SKIPPED" \
    --arg    catchall_reason    "$JSON_CATCHALL_REASON" \
    --arg    smtp_status        "$JSON_SMTP_STATUS" \
    --argjson smtp_connected    "$JSON_SMTP_CONNECTED" \
    --argjson smtp_banner       "$JSON_SMTP_BANNER" \
    --argjson smtp_mail_from    "$JSON_SMTP_MAIL_FROM" \
    --argjson smtp_rcpt         "$JSON_SMTP_RCPT_ACCEPTED" \
    --arg    smtp_catchall      "$JSON_SMTP_CATCHALL" \
    --argjson smtp_port        "$JSON_SMTP_PORT" \
    --argjson smtp_tls         "$JSON_SMTP_TLS" \
    --argjson smtp_open_relay  "$JSON_SMTP_OPEN_RELAY" \
    --argjson smtp_ports_tried    "$smtp_ports_json" \
    --argjson score_log        "$score_log_json" \
    '{
      address:   $address,
      timestamp: $timestamp,
      verdict:   $verdict,
      score:     $score,
      role: {
        flagged:    $role_flagged,
        local_part: $role_local,
        category:   $role_category,
        exempt:     $role_exempt
      },
      checks: {
        disposable:       $disposable,
        mx: {
          status: $mx_status,
          host:   $mx_host
        },
        ptr: {
          status: $ptr_status,
          ip:     $ptr_ip,
          record: $ptr_value
        },
        catchall_provider: {
          skipped: $catchall_skipped,
          reason:  $catchall_reason
        },
        smtp: {
          status:         $smtp_status,
          port:           $smtp_port,
          ports_tried:       $smtp_ports_tried,
          tls:            $smtp_tls,
          connected:      $smtp_connected,
          banner:         $smtp_banner,
          mail_from:      $smtp_mail_from,
          rcpt_accepted:  $smtp_rcpt,
          catchall_probe: $smtp_catchall,
          open_relay:     $smtp_open_relay
        }
      },
      score_log: $score_log
    }'
}

# ── Per-address validation ─────────────────────────────────────────────────────
validate_email() {
  local email="${1,,}"   # normalise to lowercase
  local domain="${email#*@}"
  local local_part="${email%@*}"
  local hard_verdict=""
  local skip_smtp="$SKIP_SMTP"

  # Reset all per-address state.
  SCORE=0; SCORE_LOG=()
  ROLE_LOCAL=""; ROLE_CATEGORY=""
  JSON_SYNTAX_PASS=false
  JSON_ROLE_FLAGGED=false;   JSON_ROLE_LOCAL="";   JSON_ROLE_CATEGORY="";   JSON_ROLE_EXEMPT=false
  JSON_DISPOSABLE_FLAGGED=false
  JSON_MX_STATUS="not_checked";  JSON_MX_HOST=""
  JSON_PTR_STATUS="not_checked"; JSON_PTR_IP="";  JSON_PTR_VALUE=""
  JSON_CATCHALL_SKIPPED=false;   JSON_CATCHALL_REASON=""
  JSON_SMTP_STATUS="not_checked"
  JSON_SMTP_CONNECTED=false; JSON_SMTP_BANNER=false
  JSON_SMTP_MAIL_FROM=false; JSON_SMTP_RCPT_ACCEPTED=false
  JSON_SMTP_CATCHALL="not_checked"
  JSON_SMTP_PORT=0; JSON_SMTP_TLS=false; JSON_SMTP_OPEN_RELAY=false; JSON_SMTP_PORTS_TRIED=()

  if ! $QUIET && ! $JSON_OUTPUT; then
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD} Validating: ${CYAN}${email}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  fi

  # ── 1. Syntax (hard fail) ──────────────────────────────────────────────────
  if check_syntax "$email"; then
    pass "Syntax valid"
    JSON_SYNTAX_PASS=true
  else
    fail "Syntax invalid"
    JSON_SYNTAX_PASS=false
    hard_verdict="UNDELIVERABLE"
    if $JSON_OUTPUT; then
      JSON_RESULTS+=( "$(emit_json "$email" "$hard_verdict")" )
    else
      _print_verdict "$email" "$hard_verdict"
    fi
    return 1
  fi

  # ── 2. Role address ────────────────────────────────────────────────────────
  # Runs before the disposable check so that role@disposable addresses are
  # reported as role addresses first — the role signal is more actionable.
  #
  # Exempted local-parts (--exempt-role) are still identified and noted in the
  # output and in JSON, but receive no score penalty and do not trigger
  # --fail-on-role.  This is appropriate for addresses like security@, privacy@,
  # or support@ that are expected contact points in package manifests.
  if check_role "$local_part"; then
    local role_exempt=false
    local exempt_lp
    for exempt_lp in "${ROLE_EXEMPT_LOCAL_PARTS[@]:-}"; do
      [[ "$exempt_lp" == "$ROLE_LOCAL" ]] && { role_exempt=true; break; }
    done

    JSON_ROLE_FLAGGED=true
    JSON_ROLE_LOCAL="$ROLE_LOCAL"
    JSON_ROLE_CATEGORY="$ROLE_CATEGORY"

    if $role_exempt; then
      info "Role address: local-part '${ROLE_LOCAL}' is a ${ROLE_CATEGORY} address (exempted — no penalty)"
      JSON_ROLE_EXEMPT=true
    else
      local role_penalty="${ROLE_SCORE[$ROLE_CATEGORY]}"
      fail "Role address: local-part '${ROLE_LOCAL}' is a ${ROLE_CATEGORY} address"
      _score "$role_penalty" "Role address (${ROLE_CATEGORY}) — not a personal address"
      JSON_ROLE_EXEMPT=false
      if $FAIL_ON_ROLE; then
        hard_verdict="ROLE_ADDRESS"
        if $JSON_OUTPUT; then
          JSON_RESULTS+=( "$(emit_json "$email" "$hard_verdict")" )
        else
          _print_verdict "$email" "$hard_verdict"
        fi
        return 1
      fi
    fi
  else
    pass "Not a role address"
    JSON_ROLE_FLAGGED=false
    JSON_ROLE_EXEMPT=false
  fi

  # ── 3. Disposable domain ───────────────────────────────────────────────────
  if check_disposable "$domain"; then
    fail "Disposable/throwaway domain: $domain"
    _score -50 "Known disposable/throwaway domain"
    JSON_DISPOSABLE_FLAGGED=true
  else
    pass "Not a known disposable domain"
    JSON_DISPOSABLE_FLAGGED=false
  fi

  # ── 4. MX / DNS (hard fail if absent) ─────────────────────────────────────
  local mx_host
  mx_host=$(get_mx_host "$domain")

  if [[ -z "$mx_host" ]]; then
    fail "No MX or A record found for domain: $domain"
    JSON_MX_STATUS="not_found"
    hard_verdict="UNDELIVERABLE"
    if $JSON_OUTPUT; then
      JSON_RESULTS+=( "$(emit_json "$email" "$hard_verdict")" )
    else
      _print_verdict "$email" "$hard_verdict"
    fi
    return 1
  fi
  pass "MX record: $mx_host"
  _score +20 "MX record found ($mx_host)"
  JSON_MX_STATUS="found"
  JSON_MX_HOST="$mx_host"

  # ── 5. Known catch-all providers ──────────────────────────────────────────
  if is_catchall_domain "$domain"; then
    warn "Known catch-all provider ($domain) — SMTP probe skipped"
    _score -20 "Known catch-all provider — mailbox existence unverifiable via SMTP"
    JSON_CATCHALL_SKIPPED=true
    JSON_CATCHALL_REASON="known_catchall_provider"
    skip_smtp=true
  elif is_google_mx "$mx_host"; then
    warn "Google Workspace MX detected ($mx_host) — SMTP probe skipped"
    # -5 rather than -20: Google Workspace is known-legitimate mail infrastructure.
    # The penalty reflects only the inability to verify the specific mailbox via
    # SMTP, not uncertainty about whether the domain receives mail at all.
    _score -5 "Google Workspace MX — known infrastructure; mailbox existence unverifiable via SMTP"
    JSON_CATCHALL_SKIPPED=true
    JSON_CATCHALL_REASON="google_workspace_mx"
    skip_smtp=true
  elif is_microsoft_mx "$mx_host"; then
    warn "Microsoft 365 / Exchange Online MX detected ($mx_host) — SMTP probe skipped"
    # Same rationale as Google Workspace above.
    _score -5 "Microsoft 365/Exchange MX — known infrastructure; mailbox existence unverifiable via SMTP"
    JSON_CATCHALL_SKIPPED=true
    JSON_CATCHALL_REASON="microsoft365_mx"
    skip_smtp=true
  fi

  # ── 6. PTR record ──────────────────────────────────────────────────────────
  local ptr_rc=0
  check_mx_ptr "$mx_host" || ptr_rc=$?
  case $ptr_rc in
    0) _score +15 "PTR record matches MX hostname — deliberately maintained mail server" ;;
    1) _score  +5 "PTR record exists but does not match MX hostname" ;;
    2) ;;   # no PTR — neutral; many legitimate servers lack rDNS
    3) _score  -5 "MX hostname did not resolve to an IP address" ;;
  esac

  # ── 7. SMTP probe ──────────────────────────────────────────────────────────
  # Always probe the MX hostname — it is the authoritative delivery target for
  # the domain as declared in DNS.  The PTR check above is a reputation signal
  # only; a mismatch is scored but never redirects the probe target.
  #
  # The earlier rationale for switching to the PTR hostname on mismatch was
  # that it might be "the server's real identity," but this is wrong in the
  # common case: most PTR mismatches arise because the IP belongs to a hosting
  # provider whose rDNS points to shared infrastructure (e.g.
  # server42.hostingprovider.com).  Probing that host sends RCPT TO for the
  # target address to a server that has no knowledge of the target domain,
  # producing unreliable results and unexpected ports_tried outcomes.
  local smtp_target="$mx_host"

  if $skip_smtp; then
    info "SMTP probe skipped — cannot confirm mailbox existence for this provider"
    JSON_SMTP_STATUS="skipped"
    JSON_SMTP_CONNECTED=false
  else
    info "Probing SMTP on $smtp_target (trying ports 587/25/465/2525, timeout: ${SMTP_TIMEOUT}s)..."
    local smtp_rc=0
    smtp_probe "$smtp_target" "$email" || smtp_rc=$?

    JSON_SMTP_CONNECTED="$SMTP_PROBE_CONNECTED"
    JSON_SMTP_BANNER="$SMTP_PROBE_BANNER"
    JSON_SMTP_MAIL_FROM="$SMTP_PROBE_MAIL_FROM"
    JSON_SMTP_PORT="$SMTP_PROBE_PORT"
    JSON_SMTP_TLS="$SMTP_PROBE_TLS"
    JSON_SMTP_OPEN_RELAY="$SMTP_PROBE_OPEN_RELAY"
    JSON_SMTP_PORTS_TRIED=("${SMTP_PROBE_PORTS_TRIED[@]}")

    local port_label="port ${SMTP_PROBE_PORT}"
    [[ $SMTP_PROBE_PORT -eq 0 ]] && port_label="fallback port"

    case $smtp_rc in
      0)  $SMTP_PROBE_CONNECTED && _score +20 "TCP connection established ($port_label)"
          $SMTP_PROBE_BANNER    && _score +15 "220 banner received from mail server"
          $SMTP_PROBE_MAIL_FROM && _score +10 "MAIL FROM accepted"
          _score +35 "RCPT TO accepted — mailbox acknowledged by server ($port_label)"
          _score +25 "Catch-all probe rejected — server validates addresses individually"
          $SMTP_PROBE_TLS       && _score  +5 "Connection used TLS"
          JSON_SMTP_STATUS="verified"
          hard_verdict="VERIFIED"
          ;;
      1)  $SMTP_PROBE_CONNECTED && _score +20 "TCP connection established ($port_label)"
          $SMTP_PROBE_BANNER    && _score +15 "220 banner received from mail server"
          $SMTP_PROBE_MAIL_FROM && _score +10 "MAIL FROM accepted"
          _score -80 "RCPT TO rejected with 5xx — mailbox does not exist"
          JSON_SMTP_STATUS="rejected"
          hard_verdict="UNDELIVERABLE"
          ;;
      2)  if $SMTP_PROBE_FALLBACK_ALIVE; then
            _score +5 "Mail server alive on port 2525 — all standard SMTP ports blocked outbound"
            JSON_SMTP_STATUS="all_ports_blocked_server_alive"
          else
            _score -20 "All SMTP ports blocked (587/25/465/2525) — server unreachable"
            JSON_SMTP_STATUS="all_ports_blocked_server_unreachable"
          fi
          ;;
      3)  $SMTP_PROBE_CONNECTED && _score +20 "TCP connection established ($port_label)"
          $SMTP_PROBE_BANNER    && _score +15 "220 banner received from mail server"
          _score -10 "SMTP dialogue failed before completing RCPT TO stage"
          JSON_SMTP_STATUS="dialogue_failed"
          ;;
      4)  $SMTP_PROBE_CONNECTED && _score +20 "TCP connection established ($port_label)"
          $SMTP_PROBE_BANNER    && _score +15 "220 banner received from mail server"
          $SMTP_PROBE_MAIL_FROM && _score +10 "MAIL FROM accepted"
          _score +35 "RCPT TO accepted ($port_label)"
          _score -50 "Catch-all confirmed — server accepts any address at this domain"
          JSON_SMTP_STATUS="catchall_confirmed"
          hard_verdict="UNVERIFIABLE"
          ;;
      5)  $SMTP_PROBE_CONNECTED && _score +20 "TCP connection established ($port_label)"
          $SMTP_PROBE_BANNER    && _score +15 "220 banner received from mail server"
          $SMTP_PROBE_MAIL_FROM && _score +10 "MAIL FROM accepted"
          _score +35 "RCPT TO accepted — mailbox acknowledged by server ($port_label)"
          _score  -5 "Catch-all status inconclusive — could not confirm address-specific validation"
          JSON_SMTP_STATUS="rcpt_accepted_catchall_inconclusive"
          ;;
    esac

    # Open relay check is independent of catch-all outcome.
    # A server that relays for arbitrary external domains is a hard negative
    # signal regardless of whether the target mailbox itself exists.
    if $SMTP_PROBE_OPEN_RELAY; then
      _score -70 "OPEN RELAY — server accepted RCPT TO for an external domain (serious misconfiguration)"
      JSON_SMTP_STATUS="open_relay_detected"
      hard_verdict="UNVERIFIABLE"   # relay acceptance proves nothing about the target mailbox
    fi
  fi

  # ── Compute final verdict for JSON ─────────────────────────────────────────
  local final_verdict
  if [[ -n "$hard_verdict" ]]; then
    final_verdict="$hard_verdict"
  elif (( SCORE >= 60 )); then
    final_verdict="LIKELY DELIVERABLE"
  elif (( SCORE >= 20 )); then
    final_verdict="PROBABLY DELIVERABLE"
  elif (( SCORE >= -10 )); then
    final_verdict="INCONCLUSIVE"
  else
    final_verdict="PROBABLY UNDELIVERABLE"
  fi

  if $JSON_OUTPUT; then
    JSON_RESULTS+=( "$(emit_json "$email" "$final_verdict")" )
  else
    _print_verdict "$email" "$hard_verdict"
  fi

  # Exit code: hard VERIFIED or score >= 20 is a pass.
  # PROBABLY DELIVERABLE (20–59) is treated as a pass for bulk runs —
  # flagging every ambiguous address would drown actionable results.
  if [[ "$hard_verdict" == "VERIFIED" ]]; then return 0; fi
  if [[ -n "$hard_verdict" ]]; then return 1; fi
  (( SCORE >= 20 )) && return 0 || return 1
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
  # Manual option parsing supports both short (-t 5) and long (--timeout 5)
  # forms.  getopts handles short options only; the while/case loop is required
  # for long-form flags.
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--timeout)     SMTP_TIMEOUT="$2"; shift 2 ;;
      -j|--json)        JSON_OUTPUT=true; QUIET=true; shift ;;
      -sj|-js)          JSON_OUTPUT=true; QUIET=true; shift ;;
      -q|--quiet)       QUIET=true; shift ;;
      -v|--verbose)     VERBOSE=true; shift ;;
      --skip-smtp)      SKIP_SMTP=true; shift ;;
      --fail-on-role)   FAIL_ON_ROLE=true; shift ;;
      --skip-relay-check) SKIP_RELAY_CHECK=true; shift ;;
      --exempt-role)
        # Split on commas so --exempt-role "security,privacy,support" works
        # alongside repeated --exempt-role security --exempt-role privacy.
        local IFS=','
        local ep
        for ep in $2; do
          ROLE_EXEMPT_LOCAL_PARTS+=("${ep,,}")   # normalise to lowercase
        done
        unset IFS
        shift 2 ;;
      --version)        echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
      -h|--help)        usage ;;
      --)               shift; break ;;
      -*)               echo "Unknown option: $1" >&2; exit 2 ;;
      *)                break ;;
    esac
  done

  local input="${1:-}"
  [[ -z "$input" ]] && usage

  check_deps
  refresh_disposable_cache

  local overall_rc=0
  local total=0 passed=0 failed=0 unverifiable=0

  while IFS= read -r line; do
    local email
    email=$(echo "$line" | tr -d '[:space:]')
    [[ -z "$email" || "$email" == \#* ]] && continue

    (( ++total ))
    local rc=0
    validate_email "$email" || rc=$?

    if (( rc == 0 )); then
      (( ++passed ))
    else
      (( ++failed ))
      overall_rc=1
      # Track unverifiable separately for the summary line.
      [[ "${JSON_SMTP_STATUS:-}" == "catchall_confirmed" || "${JSON_CATCHALL_SKIPPED:-}" == "true" ]] \
        && (( ++unverifiable )) || true
    fi
  done < <(parse_input "$input")

  if $JSON_OUTPUT; then
    # Wrap all per-address results in the root document.
    local results_array
    results_array=$(printf '%s\n' "${JSON_RESULTS[@]}" | jq -sc .)
    jq -n \
      --arg  timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg  version   "$VERSION" \
      --argjson total  "$total" \
      --argjson passed "$passed" \
      --argjson failed "$failed" \
      --argjson results "$results_array" \
      '{ email_validation: {
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
    local fail_label="${failed} failed"
    (( unverifiable > 0 )) && fail_label="${failed} failed (${unverifiable} unverifiable)"
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD} Summary: ${total} checked — ${GREEN}${passed} passed${NC}${BOLD}, ${RED}${fail_label}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  fi

  exit $overall_rc
}

main "$@"
