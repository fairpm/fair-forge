#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# vuln-scan.sh - vulnerability scan and CVSS risk scoring
#
# Usage: vuln-scan.sh [OPTIONS] <input_sbom>
#
# Scans an SBOM (SPDX or CycloneDX JSON) for known vulnerabilities using Grype.
# Calculates a weighted CVSS risk score via vuln-scan-risk.jq (required peer file).
#
# Output file: <output-dir>/<clean-name>.vuln.json
#
# Exit codes: 0 = success (scan complete), 1 = scan failed, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

OUTPUT_FORMAT="merged"      # merged | grype-only | summary | risk
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
TIMEOUT_SECONDS=300
CALCULATE_RISK=true
INPUT_TARGET=""             # SBOM file, archive, or directory

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/vuln_scan_*.json /tmp/vuln_final_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <input_sbom>

Scan an SBOM for known vulnerabilities using Grype, with CVSS-based risk scoring.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show additional detail
    -f, --format FORMAT     Output format: merged, grype-only, summary, risk
                            (default: merged)
    -t, --timeout SECONDS   Grype scan timeout (default: 300)
    -o, --output-dir DIR    Directory for output file (default: current dir)
    --no-file               Output to stdout only; do not write file
    --no-risk               Skip risk score calculation
    --version               Print version and exit

ARGUMENTS:
    input_sbom              Path to SBOM file (SPDX or CycloneDX JSON)

OUTPUT FILE:
    <output-dir>/<clean-name>.vuln.json

OUTPUT FORMATS:
    merged      SBOM merged with vulnerability data and risk assessment (default)
    grype-only  Raw Grype vulnerability results only
    summary     Vulnerability count by severity (text or JSON)
    risk        Risk score only — suitable for CI/CD gates

RISK SCORING:
    Requires vuln-scan-risk.jq in the same directory as this script.
    Uses CVSS v3.1 base scores (falls back to v3.0); weights per severity:

      Critical  ×100    (score 9.0–10.0)
      High      × 25    (score 7.0–8.9)
      Medium    ×  5    (score 4.0–6.9)
      Low       ×  1    (score 0.1–3.9)
      Negligible×  0.1

    Total weighted_risk thresholds:
      >= 1000   CRITICAL — immediate action required
      >= 500    HIGH     — remediate soon
      >= 100    MEDIUM   — plan remediation
      <  100    LOW      — monitor for updates

EXAMPLES:
    # Full scan, merged output
    $(basename "$0") sbom-myplugin.cdx.json

    # Risk score only (CI gate)
    $(basename "$0") -f risk --no-file sbom.cdx.json

    # Custom output directory
    $(basename "$0") -o ./meta/myplugin sbom.cdx.json

    # Summary to stdout
    $(basename "$0") --no-file -f summary sbom.cdx.json

ENVIRONMENT:
    GRYPE_DB_AUTO_UPDATE    Set to "false" to disable DB auto-update
    GRYPE_ARGS              Additional arguments passed to Grype
                            (e.g. 'GRYPE_ARGS="--only-fixed" vuln-scan.sh sbom.cdx.json')

DEPENDENCIES:
    grype              https://github.com/anchore/grype
    jq
    vuln-scan-risk.jq  Required peer file — must be in same directory as this script

VERSION: $VERSION (toolkit $TOOLKIT_VERSION)
EOF
    exit 0
}

log()  { [[ "$SILENT" == "false" ]] && echo "$@" >&2 || true; }
info() { [[ "$VERBOSE" == "true" ]] && echo "   $*" >&2 || true; }
die()  { echo "Error: $*" >&2; exit 2; }

# ── Functions: Validation ────────────────────────────────────────────────────

check_dependencies() {
    local missing=()
    for cmd in grype jq; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Missing required commands: ${missing[*]}" >&2
        exit 2
    fi
}

# Locate vuln-scan-risk.jq — must be in same directory as this script.
# Fails hard: a missing .jq file produces zeroed risk scores silently,
# which is worse than an explicit error for CI gate use.
locate_jq_file() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local jq_file="$script_dir/vuln-scan-risk.jq"
    if [[ ! -f "$jq_file" ]]; then
        echo "Error: Required peer file not found: $jq_file" >&2
        echo "       vuln-scan-risk.jq must be in the same directory as vuln-scan.sh" >&2
        exit 2
    fi
    echo "$jq_file"
}

# ── Functions: Naming ─────────────────────────────────────────────────────────

sanitize_filename() {
    local input="$1"
    local base
    base=$(basename "$input")
    local clean="$base"
    clean="${clean#sbom-}"
    clean="${clean%.spdx.json}"
    clean="${clean%.cdx.json}"
    clean="${clean%.vuln.json}"
    clean="${clean%.json}"
    clean="${clean%.tar.gz}"
    clean="${clean%.tar.bz2}"
    clean="${clean%.tgz}"
    clean="${clean%.zip}"
    clean=$(echo "$clean" | sed 's/[^a-zA-Z0-9._-]/_/g')
    echo "$clean"
}

# ── Functions: Risk ──────────────────────────────────────────────────────────

calculate_risk_score() {
    local vuln_file="$1"
    local jq_file="$2"
    jq -f "$jq_file" "$vuln_file"
}

risk_level_label() {
    local score="$1"
    # bc for float comparison
    if (( $(echo "$score >= 1000" | bc -l 2>/dev/null || echo 0) )); then
        echo "CRITICAL"
    elif (( $(echo "$score >= 500" | bc -l 2>/dev/null || echo 0) )); then
        echo "HIGH"
    elif (( $(echo "$score >= 100" | bc -l 2>/dev/null || echo 0) )); then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help ;;
        -sj|-js)
            SILENT=true; JSON_OUTPUT=true; shift ;;
        -s|--silent)
            SILENT=true; shift ;;
        -j|--json)
            JSON_OUTPUT=true; shift ;;
        -v|--verbose)
            VERBOSE=true; shift ;;
        -f|--format)
            [[ -z "${2:-}" ]] && die "--format requires an argument"
            OUTPUT_FORMAT="$2"
            [[ "$OUTPUT_FORMAT" =~ ^(merged|grype-only|summary|risk)$ ]] \
                || die "Invalid format '$OUTPUT_FORMAT'. Use: merged, grype-only, summary, risk"
            shift 2 ;;
        -t|--timeout)
            [[ -z "${2:-}" ]] && die "--timeout requires an argument"
            TIMEOUT_SECONDS="$2"
            [[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
                || die "Timeout must be a positive integer"
            shift 2 ;;
        -o|--output-dir)
            [[ -z "${2:-}" ]] && die "--output-dir requires an argument"
            OUTPUT_DIR="$2"
            shift 2 ;;
        --no-file)
            WRITE_FILE=false; shift ;;
        --no-risk)
            CALCULATE_RISK=false; shift ;;
        --version)
            echo "vuln-scan.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*)
            die "Unknown option: $1 (use --help for usage)" ;;
        *)
            INPUT_TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────

[[ -z "$INPUT_TARGET" ]] && die "No input specified (use --help for usage)"
[[ ! -e "$INPUT_TARGET" ]] && die "Target not found: $INPUT_TARGET"

check_dependencies

# ── Determine input type ──────────────────────────────────────────────────────
# Grype natively accepts: SBOM file (SPDX/CycloneDX JSON), archive, directory.
# We detect which we have so we can name outputs correctly and set scan mode.

INPUT_IS_SBOM=false
INPUT_IS_ARCHIVE=false
INPUT_IS_DIR=false
GRYPE_SCHEME=""

if [[ -d "$INPUT_TARGET" ]]; then
    INPUT_IS_DIR=true
    GRYPE_SCHEME="dir:${INPUT_TARGET}"
elif [[ -f "$INPUT_TARGET" ]]; then
    case "$INPUT_TARGET" in
        *.zip|*.tar.gz|*.tgz|*.tar.bz2)
            INPUT_IS_ARCHIVE=true
            GRYPE_SCHEME="${INPUT_TARGET}"   # Grype detects archive format automatically
            ;;
        *.json)
            # Must be valid JSON and contain SPDX or CycloneDX markers
            if jq empty "$INPUT_TARGET" 2>/dev/null; then
                if jq -e '.spdxVersion or .bomFormat' "$INPUT_TARGET" &>/dev/null; then
                    INPUT_IS_SBOM=true
                    GRYPE_SCHEME="${INPUT_TARGET}"
                else
                    # Valid JSON but not an SBOM — may be a vuln-scan merged output;
                    # try sbom:// scheme so Grype can inspect it
                    GRYPE_SCHEME="sbom:${INPUT_TARGET}"
                    INPUT_IS_SBOM=true
                fi
            else
                die "File is not valid JSON and not a recognised archive: $INPUT_TARGET"
            fi
            ;;
        *)
            # Non-JSON file — pass to Grype and let it determine format
            GRYPE_SCHEME="${INPUT_TARGET}"
            ;;
    esac
fi

JQ_FILE=""
if [[ "$CALCULATE_RISK" == "true" ]]; then
    JQ_FILE=$(locate_jq_file)
fi

# ── Grype database freshness ──────────────────────────────────────────────────
# Grype auto-updates its DB once per day. We check the DB age and warn if it
# appears stale (> 26 hours), but we do not block the scan — the controller
# (sbom-toolkit.sh) is responsible for priming the update in parallel.
DB_AGE_HOURS=""
db_info=$(grype db status --output json 2>/dev/null || echo "{}")
db_built=$(echo "$db_info" | jq -r '.built // ""' 2>/dev/null || echo "")
if [[ -n "$db_built" ]]; then
    db_epoch=$(date -d "$db_built" +%s 2>/dev/null \
               || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$db_built" +%s 2>/dev/null \
               || echo "0")
    now_epoch=$(date +%s)
    DB_AGE_HOURS=$(( (now_epoch - db_epoch) / 3600 ))
    if [[ $DB_AGE_HOURS -gt 26 ]]; then
        log "  [WARN] Grype vulnerability database is ${DB_AGE_HOURS}h old (> 26h)"
        log "         Run: grype db update   — or set GRYPE_DB_AUTO_UPDATE=true"
    else
        info "Grype DB age: ${DB_AGE_HOURS}h"
    fi
fi

CLEAN_BASE=$(sanitize_filename "$INPUT_TARGET")
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_BASE}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
    [[ -w "$OUTPUT_DIR" ]] \
        || die "Output directory is not writable: $OUTPUT_DIR"
fi

OUTPUT_FILE="$OUTPUT_DIR/${CLEAN_BASE}.vuln.json"

# ── Grype scan ────────────────────────────────────────────────────────────────

log "[SCAN] Scanning '$(basename "$INPUT_TARGET")' for vulnerabilities..."
[[ -n "$DB_AGE_HOURS" ]] \
    && log "       DB age: ${DB_AGE_HOURS}h" \
    || log "       (First run may be slow while Grype initialises its database)"

TMP_VULN=$(mktemp -t vuln_scan_XXXXXX.json)

grype_status=0
declare -a grype_cmd=(grype "$GRYPE_SCHEME" -o json)
if [[ -n "${GRYPE_ARGS:-}" ]]; then
    # SC2206: intentional word-split of user-supplied extra args
    # shellcheck disable=SC2206
    grype_cmd+=($GRYPE_ARGS)
fi
timeout "${TIMEOUT_SECONDS}s" "${grype_cmd[@]}" > "$TMP_VULN" 2>/dev/null \
    || grype_status=$?

if [[ "$grype_status" -eq 124 ]]; then
    echo "Error: Grype scan timed out after ${TIMEOUT_SECONDS}s" >&2
    echo "       Try: export GRYPE_DB_AUTO_UPDATE=false  (skip DB update)" >&2
    echo "       Or increase timeout: -t <seconds>" >&2
    exit 1
elif [[ "$grype_status" -ne 0 ]]; then
    echo "Error: Grype scan failed (exit code $grype_status)" >&2
    exit 1
fi

[[ -s "$TMP_VULN" ]] || { echo "Error: Grype produced an empty output file" >&2; exit 1; }

log "[PROC] Processing results..."

# ── Risk calculation ──────────────────────────────────────────────────────────

RISK_DATA="{}"
RISK_SCORE="0"
RISK_LEVEL="LOW"

if [[ "$CALCULATE_RISK" == "true" ]]; then
    # Capture stderr separately so a jq error message is visible, not silenced
    risk_stderr=$(mktemp -t vuln_risk_err_XXXXXX.txt)
    risk_exit=0
    RISK_DATA=$(calculate_risk_score "$TMP_VULN" "$JQ_FILE" 2>"$risk_stderr") \
        || risk_exit=$?

    if [[ -z "$RISK_DATA" ]] || ! echo "$RISK_DATA" | jq -e '.weighted_risk' &>/dev/null; then
        # Log the actual jq error to help diagnose
        if [[ -s "$risk_stderr" ]]; then
            log "  [WARN] Risk calculation error: $(head -3 "$risk_stderr")"
        fi
        log "  [WARN] Risk calculation failed — recording zero risk score"
        log "         Verify vuln-scan-risk.jq is valid and Grype output has a .matches array"
        RISK_DATA=$(jq -n '{
            weighted_risk: 0,
            vuln_counts: {critical:0,high:0,medium:0,low:0,negligible:0,unknown:0,total:0},
            cvss_critical:0, cvss_high:0, cvss_medium:0, cvss_low:0, cvss_negligible:0,
            scoring_notes: {method:"failed", weights:"", unscored_vulns:0, cvss_version:""}
        }')
    fi
    rm -f "$risk_stderr" 2>/dev/null || true

    RISK_SCORE=$(echo "$RISK_DATA" | jq -r '.weighted_risk // 0')
    RISK_LEVEL=$(risk_level_label "$RISK_SCORE")
    info "Weighted risk score: $RISK_SCORE ($RISK_LEVEL)"
fi

VULN_COUNT=$(jq '.matches | length' "$TMP_VULN" 2>/dev/null || echo "0")

# ── Output ────────────────────────────────────────────────────────────────────

case "$OUTPUT_FORMAT" in

    # ── risk: score only (CI gate mode) ─────────────────────────────────────
    risk)
        echo "$RISK_SCORE"
        ;;

    # ── summary: counts by severity ─────────────────────────────────────────
    summary)
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            jq -n \
                --argjson risk  "$RISK_DATA" \
                --argjson total "$VULN_COUNT" \
                '{
                    vulnerability_summary: {
                        total:        $total,
                        by_severity:  $risk.vuln_counts,
                        weighted_risk: $risk.weighted_risk,
                        risk_level:    $risk.scoring_notes
                    }
                }'
        else
            echo "Vulnerability Summary for: $(basename "$INPUT_TARGET")"
            echo "  Total:     $VULN_COUNT"
            echo "$RISK_DATA" | jq -r '
                .vuln_counts | to_entries[]
                | "  \(.key | ascii_upcase): \(.value)"'
            echo "  Risk Score: $RISK_SCORE ($RISK_LEVEL)"
        fi
        ;;

    # ── grype-only: raw Grype JSON ───────────────────────────────────────────
    grype-only)
        if [[ "$WRITE_FILE" == "true" ]]; then
            jq . "$TMP_VULN" > "$OUTPUT_FILE"
            chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
            log "[OK]   Saved: $OUTPUT_FILE"
            log "[SCAN] Vulnerabilities: $VULN_COUNT | Risk: $RISK_SCORE ($RISK_LEVEL)"
        else
            jq . "$TMP_VULN"
        fi
        ;;

    # ── merged: SBOM + vulnerability data + risk assessment (default) ────────
    merged)
        TMP_FINAL=$(mktemp -t vuln_final_XXXXXX.json)

        # Build the risk_assessment block with a consistent schema
        RISK_BLOCK=$(jq -n \
            --argjson risk_data  "$RISK_DATA" \
            --arg     level      "$RISK_LEVEL" \
            --arg     timestamp  "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg     toolkit    "$TOOLKIT_VERSION" \
            '{
                risk_assessment: {
                    weighted_risk:   $risk_data.weighted_risk,
                    risk_level:      $level,
                    cvss_totals: {
                        critical:   $risk_data.cvss_critical,
                        high:       $risk_data.cvss_high,
                        medium:     $risk_data.cvss_medium,
                        low:        $risk_data.cvss_low,
                        negligible: $risk_data.cvss_negligible
                    },
                    vuln_counts:     $risk_data.vuln_counts,
                    scoring_notes:   $risk_data.scoring_notes,
                    timestamp:       $timestamp,
                    toolkit_version: $toolkit
                }
            }')

        merge_status=0
        # For SBOM inputs: merge vuln data into the SBOM JSON.
        # For directory/archive inputs: build a standalone result document
        # (there is no SBOM JSON to merge into).
        if [[ "$INPUT_IS_SBOM" == "true" ]]; then
            jq --slurpfile vulns "$TMP_VULN" \
               --argjson   risk  "$RISK_BLOCK" \
               '
                # Clean Grype output before embedding:
                #   - replace local cache paths with a readable label
                #   - strip matchDetails (cataloger implementation detail, not useful to consumers)
                #   - strip realPath from artifact locations (absolute scanner paths, not portable)
                ($vulns[0] | walk(
                    if type == "string"
                       and (contains(".cache/grype") or contains(".cache\\grype"))
                    then "(local cache)"
                    else .
                    end
                )
                | del(.matches[]?.matchDetails)
                | del(.matches[]?.artifact?.locations[]?.realPath)
                ) as $clean_vulns
                |
                . + {
                    vulnerability_scan: $clean_vulns,
                    risk_assessment:    $risk.risk_assessment
                }
               ' "$INPUT_TARGET" > "$TMP_FINAL" 2>/dev/null || merge_status=$?
        else
            jq -n \
               --arg  target "$(basename "$INPUT_TARGET")" \
               --slurpfile vulns "$TMP_VULN" \
               --argjson risk  "$RISK_BLOCK" \
               '
                ($vulns[0] | walk(
                    if type == "string"
                       and (contains(".cache/grype") or contains(".cache\\grype"))
                    then "(local cache)"
                    else .
                    end
                )
                | del(.matches[]?.matchDetails)
                | del(.matches[]?.artifact?.locations[]?.realPath)
                ) as $clean_vulns
                |
                {
                    target:             $target,
                    vulnerability_scan: $clean_vulns,
                    risk_assessment:    $risk.risk_assessment
                }
               ' > "$TMP_FINAL" 2>/dev/null || merge_status=$?
        fi

        if [[ "$merge_status" -ne 0 ]]; then
            echo "Error: Failed to build vulnerability output document" >&2
            rm -f "$TMP_FINAL"
            exit 1
        fi

        if [[ "$WRITE_FILE" == "true" ]]; then
            mv "$TMP_FINAL" "$OUTPUT_FILE"
            chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
            log "[OK]   Saved: $OUTPUT_FILE"
            log "[SCAN] Vulnerabilities: $VULN_COUNT | Risk: $RISK_SCORE ($RISK_LEVEL)"

            case "$RISK_LEVEL" in
                CRITICAL) log "       [CRIT]   Immediate action required" ;;
                HIGH)     log "       [HIGH]   Review and remediate soon" ;;
                MEDIUM)   log "       [MEDIUM] Plan remediation" ;;
                LOW)      log "       [LOW]    Monitor for updates" ;;
            esac
        else
            jq . "$TMP_FINAL"
            rm -f "$TMP_FINAL"
        fi
        ;;
esac

exit 0
