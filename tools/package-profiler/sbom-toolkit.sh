#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# sbom-toolkit.sh - SBOM supply chain security toolkit controller
#
# Usage: sbom-toolkit.sh [OPTIONS] <target>
#
# Orchestrates the full toolkit pipeline against an archive or directory:
#
#   Wave 1 (parallel):  checksum-verify, sbom-discover, sbom-gen
#   Wave 2 (parallel):  vuln-scan, license-check, dependency-audit,
#                       provenance-verify, sbom-compare
#   Wave 3 (sequential): slsa-attest
#
# Aggregates all scan results into a single <name>.meta.json.
# Applies CI gate thresholds after wave 3.
#
# Output directory: <output-dir>/<clean-name>/
# Meta JSON:        <output-dir>/<clean-name>/<clean-name>.meta.json
#
# Exit codes: 0 = pass, 1 = CI gate triggered or scan issues, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Locate script directory ───────────────────────────────────────────────────
# All peer scripts must be in the same directory as this controller.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Default configuration ────────────────────────────────────────────────────

TARGET=""
OUTPUT_BASE="./meta"
SILENT=false
VERBOSE=false
KEEP_INTERMEDIATE=false
NO_LOG=false
DRY_RUN=false

# Ecosystem for license-check (separate from source-type for checksum-verify)
ECOSYSTEM=""

# WordPress plugin/version (forwarded to provenance-verify)
WP_PLUGIN=""
WP_VERSION=""

# Package type context for provenance-verify risk scoring.
# public    — package is on a public registry; verification is expected
# internal  — private/proprietary build; public registry checks not applicable
# prerelease — not yet published; public verification not yet available
# custom    — modified public package; partial verification expected
# Defaults to "public" (same as provenance-verify default).
PACKAGE_TYPE="public"

# SLSA attestation options
SLSA_LEVEL=0
BUILDER_ID=""
POLICY_URI=""
DISCLAIMER_URI=""

# Source context (forwarded to provenance-verify and slsa-attest)
SOURCE_REPO=""
SOURCE_COMMIT=""
SOURCE_REF=""
BUILD_TRIGGER=""
BUILD_ID=""

# SBOM compare baseline (optional)
COMPARE_BASELINE=""

# CI gate thresholds
FAIL_ON_RISK=""           # Numeric threshold; exit 1 if total_risk >= N
FAIL_ON_SEVERITY=""       # CRITICAL | HIGH; exit 1 if any finding at this level
FAIL_ON_GPL_INCOMPAT=false
FAIL_ON_LICENSE_UNKNOWN=true
FAIL_ON_CONFUSION=false        # Exit 1 if dep-confusion or typosquat findings exist

# Skip flags
SKIP_CHECKSUM=false
SKIP_DISCOVER=false
SKIP_SBOM_GEN=false
SKIP_VULN=false
SKIP_LICENSE=false
SKIP_AUDIT=false
SKIP_PROVENANCE=false
SKIP_COMPARE=false
SKIP_SLSA=false

# license-check flags
LICENSE_REQUIRE_GPL_COMPAT=false

# ── Cleanup trap ─────────────────────────────────────────────────────────────

TMP_FILES=()
cleanup() {
    if [[ "$KEEP_INTERMEDIATE" == "false" ]]; then
        local f
        for f in "${TMP_FILES[@]+"${TMP_FILES[@]}"}"; do
            rm -f "$f" 2>/dev/null || true
        done
    fi
    # Kill any background jobs still running
    jobs -p 2>/dev/null | xargs kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Run the full SBOM supply chain security toolkit against an archive or directory.

ARGUMENTS:
    target                  Archive (.zip, .tar.gz, .tgz, .tar.bz2) or directory

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages (passed to all scripts)
    -v, --verbose           Show additional detail (passed to all scripts)
    -o, --output-dir DIR    Base output directory (default: ./meta)
                            Final outputs land in <DIR>/<clean-name>/
    --keep-intermediate     Keep individual scan JSON files after aggregation
    --no-log                Do not write run.log (progress still shown on stderr)
    --dry-run               Show what would be run without executing
    --version               Print version and exit

ECOSYSTEM AND CONTEXT:
    --ecosystem TYPE        Ecosystem for license policy:
                            wordpress | typo3 | drupal | packagist |
                            npm | pypi | github | file
    --source-type TYPE      Archive source type for checksum API lookup:
                            wordpress | packagist | npm | pypi | github | file
    --wp-plugin SLUG        WordPress plugin slug (enables WP-specific checks)
    --wp-version VERSION    WordPress plugin version

SOURCE AND BUILD CONTEXT (forwarded to provenance-verify and slsa-attest):
    --source-repo URL       Source repository URL
    --source-commit SHA     Source commit hash
    --source-ref REF        Source git ref (e.g. refs/tags/v1.2.3)
    --build-trigger TYPE    Build trigger: push | tag | manual | schedule | api
    --build-id ID           CI run ID or build reference
    --package-type TYPE     Package context for provenance risk scoring:
                            public (default) | internal | prerelease | custom
                            Forwarded to provenance-verify. Use 'internal' for
                            private packages not expected on public registries,
                            'prerelease' for not-yet-published versions.

SLSA ATTESTATION:
    --slsa-level N          SLSA level to attest (1, 2, or 3; default: 1)
    --builder-id URI        Builder identity URI (required for slsa-attest)
    --policy-uri URI        Policy URI (required for slsa-attest)
    --disclaimer-uri URI    Observer disclaimer URI (optional)

COMPARISON:
    --compare FILE          Baseline SBOM for sbom-compare (SBOM vs SBOM mode)
    --manifest FILE         Manifest file for sbom-compare (SBOM vs manifest mode)

CI GATE OPTIONS:
    --fail-on-risk N        Exit 1 if total risk score >= N
    --fail-on-severity SEV  Exit 1 if any finding at CRITICAL or HIGH severity
                            Values: CRITICAL | HIGH
    --require-gpl-compat    Exit 1 if any license is not GPL-compatible
    --allow-license-unknown Do not fail on unknown license identifiers

SKIP OPTIONS (skip individual pipeline stages):
    --skip-checksum         Skip checksum-verify
    --skip-discover         Skip sbom-discover
    --skip-sbom-gen         Skip sbom-gen (use if SBOM already exists)
    --skip-vuln             Skip vuln-scan
    --skip-license          Skip license-check
    --skip-audit            Skip dependency-audit
    --skip-provenance       Skip provenance-verify
    --skip-compare          Skip sbom-compare
    --skip-slsa             Skip slsa-attest

OUTPUT STRUCTURE:
    <output-dir>/<clean-name>/
      <name>.spdx.json           SPDX 2.3 SBOM
      <name>.cdx.json            CycloneDX 1.5 SBOM
      <name>.meta.json           Aggregated toolkit results
      <name>.slsa-L<n>.provenance.json   SLSA attestation
      run.log                    Full run log (omitted with --no-log)
      (individual scan JSONs retained if --keep-intermediate)

PIPELINE:
    Wave 1 (parallel):   checksum-verify  sbom-discover  sbom-gen
    Wave 2 (parallel):   vuln-scan  license-check  dependency-audit
                         provenance-verify  sbom-compare
    Wave 3 (sequential): slsa-attest → meta aggregation → CI gates

EXAMPLES:
    # Standard WordPress plugin scan
    $(basename "$0") \\
      --ecosystem wordpress \\
      --wp-plugin akismet --wp-version 5.3 \\
      akismet.5.3.zip

    # Full pipeline with CI gate
    $(basename "$0") \\
      --ecosystem wordpress \\
      --require-gpl-compat \\
      --fail-on-risk 500 \\
      --fail-on-severity HIGH \\
      --builder-id https://ci.example.com/builder \\
      --policy-uri  https://example.com/policy \\
      --slsa-level 2 \\
      akismet.5.3.zip

    # Skip SBOM generation (SBOM already exists)
    $(basename "$0") \\
      --skip-sbom-gen \\
      --ecosystem npm \\
      ./my-package/

    # Compare against a baseline SBOM
    $(basename "$0") \\
      --compare ./baseline/package.spdx.json \\
      package.zip

DEPENDENCIES:
    All toolkit scripts must be in the same directory as this controller.
    Required: syft, grype, jq, curl, sha256sum, awk
    See individual script --help for per-script dependencies.

VERSION: $VERSION (toolkit $TOOLKIT_VERSION)
EOF
    exit 0
}

log()     { [[ "$SILENT" == "false" ]] && echo "[$(date +%H:%M:%S)] $*" >&2 || true; }
log_raw() { [[ "$SILENT" == "false" ]] && echo "$*" >&2 || true; }
info()    { [[ "$VERBOSE" == "true"  ]] && echo "   $*" >&2 || true; }
die()     { echo "Error: $*" >&2; exit 2; }

log_file() {
    # Tee a message to both stderr and the run log
    local msg="$1"
    [[ "$SILENT" == "false" ]] && echo "[$(date +%H:%M:%S)] $msg" >&2 || true
    echo "[$(date +%H:%M:%S)] $msg" >> "$RUN_LOG" 2>/dev/null || true
}

# ── Functions: Script location ────────────────────────────────────────────────

find_script() {
    local name="$1"
    local path="$SCRIPT_DIR/$name"
    if [[ ! -f "$path" ]]; then
        echo "Error: Required script not found: $path" >&2
        return 1
    fi
    if [[ ! -x "$path" ]]; then
        chmod +x "$path" 2>/dev/null || {
            echo "Error: Cannot make $path executable" >&2
            return 1
        }
    fi
    echo "$path"
}

# ── Functions: Naming ─────────────────────────────────────────────────────────

# NOTE: sanitize_name is duplicated verbatim across all toolkit scripts.
# Any changes must be kept in sync with the same function in:
#   checksum-verify.sh, dependency-audit.sh, license-check.sh,
#   provenance-verify.sh, sbom-compare.sh, sbom-discover.sh,
#   sbom-gen.sh, sbom-toolkit.sh, slsa-attest.sh
sanitize_name() {
    local input="$1"
    local base
    base=$(basename "$input")
    local clean="$base"
    # Strip compound extensions first (order matters), then single
    clean="${clean%.checksum.json}"
    clean="${clean%.provenance.json}"
    clean="${clean%.slsa-assessment.json}"
    clean="${clean%.spdx.json}"
    clean="${clean%.cdx.json}"
    clean="${clean%.vuln.json}"
    clean="${clean%.license.json}"
    clean="${clean%.deps-audit.json}"
    clean="${clean%.compare.json}"
    clean="${clean%.discover.json}"
    clean="${clean%.json}"
    clean="${clean%.tar.gz}"
    clean="${clean%.tar.bz2}"
    clean="${clean%.tar.xz}"
    clean="${clean%.tar.zst}"
    clean="${clean%.tar}"
    clean="${clean%.tgz}"
    clean="${clean%.txz}"
    clean="${clean%.tzst}"
    clean="${clean%.zip}"
    clean=$(echo "$clean" | sed 's/[^a-zA-Z0-9._-]/_/g')
    [[ -z "$clean" ]] && clean="package_$(date +%s)"
    echo "$clean"
}

# ── Functions: Parallel wave execution ───────────────────────────────────────
#
# run_wave <label> <job_array_name>
# Each element of the job array is a string:
#   "<script_name>|<output_json_var>|<args...>"
# Jobs run in parallel; controller waits for all to complete.
# Non-zero exit from any job is noted but does not abort the wave —
# scans can fail without preventing other scans from running.
# Wave exit status is the number of failed jobs.

declare -A JOB_PIDS      # pid → script_name
declare -A JOB_OUTPUTS   # script_name → output json path
declare -A JOB_STATUS    # script_name → exit code

run_wave() {
    local label="$1"
    shift
    local -n wave_jobs="$1"   # nameref to array of job specs

    [[ ${#wave_jobs[@]} -eq 0 ]] && return 0

    log_file "── $label ──────────────────────────────────────────"

    # Launch all jobs
    local spec script_name out_var args_str
    for spec in "${wave_jobs[@]}"; do
        IFS='|' read -r script_name out_var args_str <<< "$spec"

        if [[ "$DRY_RUN" == "true" ]]; then
            log_file "  [DRY] $script_name $args_str"
            JOB_STATUS["$script_name"]=0
            continue
        fi

        local script_path
        script_path=$(find_script "$script_name") || {
            log_file "  [SKIP] $script_name — script not found"
            JOB_STATUS["$script_name"]=2
            continue
        }

        # Run in background; redirect stdout+stderr to a temp log
        local tmp_log
        tmp_log=$(mktemp -t toolkit_job_XXXXXX.log)
        TMP_FILES+=("$tmp_log")

        # shellcheck disable=SC2086
        bash "$script_path" $args_str >> "$tmp_log" 2>&1 &
        local pid=$!
        JOB_PIDS[$pid]="$script_name|$out_var|$tmp_log"
        log_file "  [RUN]  $script_name (pid $pid)"
    done

    [[ "$DRY_RUN" == "true" ]] && return 0

    # Wait for all jobs
    local pid script out_var_name tmp_log_path status
    for pid in "${!JOB_PIDS[@]}"; do
        IFS='|' read -r script out_var_name tmp_log_path <<< "${JOB_PIDS[$pid]}"
        status=0
        wait "$pid" 2>/dev/null || status=$?
        JOB_STATUS["$script"]=$status

        # Append job log to run log with a per-script header so the log is
        # navigable when multiple scripts run in parallel and their output
        # is interleaved or collected separately.
        {
            echo "── $script ──────────────────────────── $(date -u +"%H:%M:%S") ──"
            cat "$tmp_log_path"
            echo "────────────────────────────────────────────────────────────────"
            echo ""
        } >> "$RUN_LOG" 2>/dev/null || true

        if [[ $status -eq 0 ]]; then
            log_file "  [OK]   $script (pid $pid)"
        elif [[ $status -eq 1 ]]; then
            log_file "  [WARN] $script exited 1 — issues found (pid $pid)"
        else
            log_file "  [FAIL] $script exited $status (pid $pid)"
        fi

        # Record output file path if the variable name was set
        if [[ -n "$out_var_name" ]]; then
            JOB_OUTPUTS["$script"]="${out_var_name}"
        fi
    done

    # Clear PID tracking for next wave
    for pid in "${!JOB_PIDS[@]}"; do
        unset "JOB_PIDS[$pid]"
    done

    return 0
}

# ── Functions: Build CLI flags from booleans ──────────────────────────────────

silent_flag()  { [[ "$SILENT"  == "true" ]] && echo "-s"  || echo ""; }
verbose_flag() { [[ "$VERBOSE" == "true" ]] && echo "-v"  || echo ""; }
json_flag()    { echo "-j"; }  # always request JSON output from subscripts

# ── Functions: Meta JSON aggregation ─────────────────────────────────────────

aggregate_meta() {
    local output_dir="$1"
    local clean_name="$2"
    local run_id="$3"

    log_file "── Aggregating scan results ──────────────────────────"

    # Start with toolkit header
    local meta
    meta=$(jq -n \
        --arg  version    "$TOOLKIT_VERSION" \
        --arg  run_id     "$run_id" \
        --arg  timestamp  "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg  target     "$(basename "$TARGET")" \
        --arg  sbom_spdx  "${clean_name}.spdx.json" \
        --arg  sbom_cdx   "${clean_name}.cdx.json" \
        '{
            toolkit: {
                version:    $version,
                run_id:     $run_id,
                timestamp:  $timestamp,
                target:     $target,
                sbom_files: {
                    spdx:      $sbom_spdx,
                    cyclonedx: $sbom_cdx
                }
            }
        }')

    # Merge each individual scan JSON if it exists
    # The key used in the meta JSON matches the root key of each script's output
    local scan_keys=(
        "crypto_verification:${output_dir}/${clean_name}.checksum.json"
        "provenance_verification:${output_dir}/${clean_name}.provenance.json"
        "vulnerability_scan:${output_dir}/${clean_name}.vuln.json"
        "license_compliance:${output_dir}/${clean_name}.license.json"
        "dependency_audit:${output_dir}/${clean_name}.deps-audit.json"
        "sbom_discovery:${output_dir}/${clean_name}.discover.json"
        "sbom_comparison:${output_dir}/${clean_name}.compare.json"
    )

    local entry key scan_file
    for entry in "${scan_keys[@]}"; do
        key="${entry%%:*}"
        scan_file="${entry#*:}"

        if [[ -f "$scan_file" ]] && jq empty "$scan_file" 2>/dev/null; then
            # Each script outputs { <root_key>: { ... } } — extract the inner object.
            # Write to a temp file rather than passing as --argjson to avoid
            # ARG_MAX ("Argument list too long") on large vuln/license outputs.
            local tmp_inner
            tmp_inner=$(mktemp -t sbom_meta_inner_XXXXXX.json)
            TMP_FILES+=("$tmp_inner")
            jq --arg k "$key" '.[$k] // .' "$scan_file" > "$tmp_inner" 2>/dev/null \
                || echo '{}' > "$tmp_inner"
            local tmp_meta
            tmp_meta=$(mktemp -t sbom_meta_XXXXXX.json)
            TMP_FILES+=("$tmp_meta")
            echo "$meta" > "$tmp_meta"
            meta=$(jq -n \
                --arg        k   "$key" \
                --slurpfile  cur "$tmp_meta" \
                --slurpfile  val "$tmp_inner" \
                '$cur[0] + {($k): $val[0]}')
            info "  Merged: $key"
        else
            info "  Skip (not found): $key — $scan_file"
        fi
    done

    # Compute aggregate risk score — write meta to temp file first to avoid
    # ARG_MAX if the accumulated JSON is large
    local tmp_risk
    tmp_risk=$(mktemp -t sbom_meta_risk_XXXXXX.json)
    TMP_FILES+=("$tmp_risk")
    echo "$meta" > "$tmp_risk"
    meta=$(jq '
        def safe_num: if type == "number" then . else 0 end;

        # Collect risk contributions from each section
        {
            checksum:    (.crypto_verification.risk_contribution    // 0 | safe_num),
            provenance:  (.provenance_verification.risk_contribution // 0 | safe_num),
            vuln:        (.vulnerability_scan.risk_assessment.weighted_risk // 0 | safe_num),
            license:     (.license_compliance.risk_contribution     // 0 | safe_num),
            audit:       (.dependency_audit.risk_contribution       // 0 | safe_num)
        } as $components |

        ( $components | add ) as $total |

        (
            if   $total >= 1000 then "CRITICAL"
            elif $total >= 500  then "HIGH"
            elif $total >= 100  then "MEDIUM"
            else                     "LOW"
            end
        ) as $level |

        . + {
            risk_assessment: {
                component_scores: $components,
                total_risk_score: $total,
                risk_level:       $level
            }
        }
    ' "$tmp_risk")

    echo "$meta"
}

# ── Functions: CI gate evaluation ────────────────────────────────────────────

evaluate_gates() {
    local meta_json="$1"
    local gate_failures=()

    # Gate 1: total risk score
    if [[ -n "$FAIL_ON_RISK" ]]; then
        local total_risk
        total_risk=$(echo "$meta_json" \
            | jq -r '.risk_assessment.total_risk_score // 0' 2>/dev/null || echo 0)
        if (( $(echo "$total_risk >= $FAIL_ON_RISK" | bc -l 2>/dev/null || echo 0) )); then
            gate_failures+=("Risk score $total_risk >= threshold $FAIL_ON_RISK")
        fi
    fi

    # Gate 2: vulnerability severity
    if [[ -n "$FAIL_ON_SEVERITY" ]]; then
        local sev_count=0
        case "$FAIL_ON_SEVERITY" in
            CRITICAL)
                sev_count=$(echo "$meta_json" | jq -r '
                    .vulnerability_scan.risk_assessment.vuln_counts.critical // 0
                ' 2>/dev/null || echo 0)
                [[ $sev_count -gt 0 ]] \
                    && gate_failures+=("$sev_count CRITICAL vulnerability(s) found")
                ;;
            HIGH)
                local crit high
                crit=$(echo "$meta_json" | jq -r '
                    .vulnerability_scan.risk_assessment.vuln_counts.critical // 0
                ' 2>/dev/null || echo 0)
                high=$(echo "$meta_json" | jq -r '
                    .vulnerability_scan.risk_assessment.vuln_counts.high // 0
                ' 2>/dev/null || echo 0)
                sev_count=$((crit + high))
                [[ $sev_count -gt 0 ]] \
                    && gate_failures+=("$sev_count CRITICAL/HIGH vulnerability(s) found")
                ;;
        esac
    fi

    # Gate 3: GPL compatibility
    if [[ "$FAIL_ON_GPL_INCOMPAT" == "true" ]]; then
        local gpl_compat
        gpl_compat=$(echo "$meta_json" \
            | jq -r '.license_compliance.gpl_compatible // true' 2>/dev/null || echo "true")
        [[ "$gpl_compat" == "false" ]] \
            && gate_failures+=("GPL-incompatible licenses detected")
    fi

    # Gate 4: dependency confusion / typosquat (opt-in via --fail-on-confusion)
    if [[ "$FAIL_ON_CONFUSION" == "true" ]]; then
        local confusion_count typo_count
        confusion_count=$(echo "$meta_json" | jq -r '
            .dependency_audit.summary.dependency_confusion // 0
        ' 2>/dev/null || echo 0)
        typo_count=$(echo "$meta_json" | jq -r '
            .dependency_audit.summary.typosquatting // 0
        ' 2>/dev/null || echo 0)
        [[ $confusion_count -gt 0 ]] \
            && gate_failures+=("$confusion_count dependency confusion finding(s)")
        [[ $typo_count -gt 0 ]] \
            && gate_failures+=("$typo_count typosquatting finding(s)")
    fi

    # Report
    if [[ ${#gate_failures[@]} -gt 0 ]]; then
        log_file "── CI Gate: FAILED ───────────────────────────────────"
        local msg
        for msg in "${gate_failures[@]}"; do
            log_file "  [GATE] $msg"
        done
        return 1
    else
        log_file "── CI Gate: PASSED ───────────────────────────────────"
        return 0
    fi
}

# ── Argument parsing ──────────────────────────────────────────────────────────

COMPARE_MODE=""
COMPARE_FILE_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       show_help ;;
        -s|--silent)     SILENT=true; shift ;;
        -j|--json|-sj|-js) shift ;;   # accepted for consistency; controller output is always file-based
        -v|--verbose)    VERBOSE=true; shift ;;
        -o|--output-dir)
            [[ -z "${2:-}" ]] && die "--output-dir requires an argument"
            OUTPUT_BASE="$2"; shift 2 ;;
        --keep-intermediate) KEEP_INTERMEDIATE=true; shift ;;
        --no-log)            NO_LOG=true; shift ;;
        --dry-run)           DRY_RUN=true; shift ;;
        --ecosystem)
            [[ -z "${2:-}" ]] && die "--ecosystem requires an argument"
            ECOSYSTEM="$2"
            [[ "$ECOSYSTEM" =~ ^(wordpress|typo3|drupal|packagist|npm|pypi|github|file)$ ]] \
                || die "Invalid ecosystem. Use: wordpress, typo3, drupal, packagist, npm, pypi, github, file"
            shift 2 ;;
        --source-type)
            [[ -z "${2:-}" ]] && die "--source-type requires an argument"
            SOURCE_TYPE_FLAG="$2"
            [[ "$SOURCE_TYPE_FLAG" =~ ^(wordpress|packagist|npm|pypi|github|file)$ ]] \
                || die "Invalid source-type. Use: wordpress, packagist, npm, pypi, github, file"
            shift 2 ;;
        --wp-plugin)
            [[ -z "${2:-}" ]] && die "--wp-plugin requires an argument"
            WP_PLUGIN="$2"; shift 2 ;;
        --wp-version)
            [[ -z "${2:-}" ]] && die "--wp-version requires an argument"
            WP_VERSION="$2"; shift 2 ;;
        --source-repo)
            [[ -z "${2:-}" ]] && die "--source-repo requires an argument"
            SOURCE_REPO="$2"; shift 2 ;;
        --source-commit)
            [[ -z "${2:-}" ]] && die "--source-commit requires an argument"
            SOURCE_COMMIT="$2"; shift 2 ;;
        --source-ref)
            [[ -z "${2:-}" ]] && die "--source-ref requires an argument"
            SOURCE_REF="$2"; shift 2 ;;
        --build-trigger)
            [[ -z "${2:-}" ]] && die "--build-trigger requires an argument"
            BUILD_TRIGGER="$2"; shift 2 ;;
        --build-id)
            [[ -z "${2:-}" ]] && die "--build-id requires an argument"
            BUILD_ID="$2"; shift 2 ;;
        --package-type)
            [[ -z "${2:-}" ]] && die "--package-type requires an argument"
            PACKAGE_TYPE="$2"
            [[ "$PACKAGE_TYPE" =~ ^(public|internal|prerelease|custom)$ ]] \
                || die "--package-type must be: public, internal, prerelease, or custom"
            shift 2 ;;
        --slsa-level)
            [[ -z "${2:-}" ]] && die "--slsa-level requires an argument"
            SLSA_LEVEL="$2"
            [[ "$SLSA_LEVEL" =~ ^[0123]$ ]] || die "--slsa-level must be 0, 1, 2, or 3"
            shift 2 ;;
        --builder-id)
            [[ -z "${2:-}" ]] && die "--builder-id requires an argument"
            BUILDER_ID="$2"; shift 2 ;;
        --policy-uri)
            [[ -z "${2:-}" ]] && die "--policy-uri requires an argument"
            POLICY_URI="$2"; shift 2 ;;
        --disclaimer-uri)
            [[ -z "${2:-}" ]] && die "--disclaimer-uri requires an argument"
            DISCLAIMER_URI="$2"; shift 2 ;;
        --compare)
            [[ -z "${2:-}" ]] && die "--compare requires an argument"
            COMPARE_MODE="sbom"
            COMPARE_FILE_PATH="$2"; shift 2 ;;
        --manifest)
            [[ -z "${2:-}" ]] && die "--manifest requires an argument"
            COMPARE_MODE="manifest"
            COMPARE_FILE_PATH="$2"; shift 2 ;;
        --fail-on-risk)
            [[ -z "${2:-}" ]] && die "--fail-on-risk requires an argument"
            FAIL_ON_RISK="$2"
            [[ "$FAIL_ON_RISK" =~ ^[0-9]+$ ]] || die "--fail-on-risk must be a positive integer"
            shift 2 ;;
        --fail-on-severity)
            [[ -z "${2:-}" ]] && die "--fail-on-severity requires an argument"
            FAIL_ON_SEVERITY="$2"
            [[ "$FAIL_ON_SEVERITY" =~ ^(CRITICAL|HIGH)$ ]] \
                || die "--fail-on-severity must be CRITICAL or HIGH"
            shift 2 ;;
        --require-gpl-compat)
            LICENSE_REQUIRE_GPL_COMPAT=true
            FAIL_ON_GPL_INCOMPAT=true
            shift ;;
        --fail-on-confusion)
            FAIL_ON_CONFUSION=true; shift ;;
        --allow-license-unknown)
            FAIL_ON_LICENSE_UNKNOWN=false; shift ;;
        --skip-checksum)   SKIP_CHECKSUM=true;   shift ;;
        --skip-discover)   SKIP_DISCOVER=true;   shift ;;
        --skip-sbom-gen)   SKIP_SBOM_GEN=true;   shift ;;
        --skip-vuln)       SKIP_VULN=true;        shift ;;
        --skip-license)    SKIP_LICENSE=true;     shift ;;
        --skip-audit)      SKIP_AUDIT=true;       shift ;;
        --skip-provenance) SKIP_PROVENANCE=true;  shift ;;
        --skip-compare)    SKIP_COMPARE=true;     shift ;;
        --skip-slsa)       SKIP_SLSA=true;        shift ;;
        --version)
            echo "sbom-toolkit.sh $VERSION"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$TARGET" ]]   && die "No target specified (use --help for usage)"
[[ ! -e "$TARGET" ]] && die "Target not found: $TARGET"
command -v jq &>/dev/null || die "jq is required"

CLEAN_NAME=$(sanitize_name "$TARGET")
RUN_ID="${CLEAN_NAME}-$(date +%Y%m%dT%H%M%S)-$$"
OUT_DIR="${OUTPUT_BASE}/${CLEAN_NAME}"
META_FILE="${OUT_DIR}/${CLEAN_NAME}.meta.json"

mkdir -p "$OUT_DIR" 2>/dev/null \
    || die "Cannot create output directory: $OUT_DIR"

# RUN_LOG: /dev/null when --no-log, otherwise a persistent audit trail in OUT_DIR.
# All log_file() calls tee to both stderr and RUN_LOG; pointing at /dev/null
# means the stderr output is unaffected while no file is created.
if [[ "$NO_LOG" == "true" ]]; then
    RUN_LOG="/dev/null"
else
    RUN_LOG="${OUT_DIR}/run.log"
    # Initialise run log
    echo "# sbom-toolkit run: $RUN_ID" > "$RUN_LOG"
    echo "# Target: $TARGET"           >> "$RUN_LOG"
    echo "# Started: $(date -u)"       >> "$RUN_LOG"
    echo ""                            >> "$RUN_LOG"
fi

log_file "sbom-toolkit v$VERSION"
log_file "Run ID: $RUN_ID"
log_file "Target: $TARGET"
log_file "Output: $OUT_DIR"

# Determine if target is an archive.
IS_ARCHIVE=false
if [[ -f "$TARGET" ]]; then
    case "$TARGET" in
        *.zip)                    IS_ARCHIVE=true ;;
        *.tar.gz|*.tgz)           IS_ARCHIVE=true ;;
        *.tar.bz2|*.tbz2)         IS_ARCHIVE=true ;;
        *.tar.xz|*.txz)           IS_ARCHIVE=true ;;
        *.tar.zst|*.tzst)         IS_ARCHIVE=true ;;
        *.tar)                    IS_ARCHIVE=true ;;
        *)  if tar -tf "$TARGET" &>/dev/null 2>&1; then IS_ARCHIVE=true; fi ;;
    esac
fi

# Source type flag (distinct from ecosystem)
SOURCE_TYPE_FLAG="${SOURCE_TYPE_FLAG:-}"

# Common flags passed to all subscripts
SF=$(silent_flag)
VF=$(verbose_flag)
JF=$(json_flag)

# ── Grype DB priming ──────────────────────────────────────────────────────────
# Grype auto-updates its vulnerability database once per day. If the DB is
# stale (> 26h old), trigger an update in the background before Wave 1 starts
# so it completes in parallel with SBOM generation rather than blocking vuln-scan.
# This significantly reduces total pipeline time on the first daily run.

GRYPE_DB_UPDATE_PID=""
if [[ "$SKIP_VULN" == "false" ]] && command -v grype &>/dev/null; then
    db_info=$(grype db status --output json 2>/dev/null || echo "{}")
    db_built=$(echo "$db_info" | jq -r '.built // ""' 2>/dev/null || echo "")
    db_stale=false

    if [[ -n "$db_built" ]]; then
        db_epoch=$(date -d "$db_built" +%s 2>/dev/null \
                   || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$db_built" +%s 2>/dev/null \
                   || echo "0")
        now_epoch=$(date +%s)
        db_age_h=$(( (now_epoch - db_epoch) / 3600 ))
        if [[ $db_age_h -gt 26 ]]; then
            db_stale=true
            log_file "  [DB]   Grype vulnerability database is ${db_age_h}h old — updating in background"
        else
            log_file "  [DB]   Grype vulnerability database age: ${db_age_h}h (current)"
        fi
    else
        # No DB status available — trigger update so vuln-scan doesn't time out
        db_stale=true
        log_file "  [DB]   Grype database status unknown — triggering update in background"
    fi

    if [[ "$db_stale" == "true" ]] && [[ "$DRY_RUN" == "false" ]]; then
        grype db update >> "$RUN_LOG" 2>&1 &
        GRYPE_DB_UPDATE_PID=$!
        log_file "  [DB]   Update running in background (pid $GRYPE_DB_UPDATE_PID)"
    fi
fi

# ── Wave 1: checksum-verify + sbom-discover + sbom-gen ───────────────────────

WAVE1_JOBS=()

# checksum-verify
if [[ "$SKIP_CHECKSUM" == "false" ]] && [[ "$IS_ARCHIVE" == "true" ]]; then
    CHKSUM_OUT="${OUT_DIR}/${CLEAN_NAME}.checksum.json"
    CHKSUM_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
    # Only extract when provenance-verify or dependency-audit needs the directory.
    # Syft/Grype scan archives natively; unnecessary extraction wastes time.
    if [[ "$SKIP_PROVENANCE" == "false" || "$SKIP_AUDIT" == "false" ]]; then
        CHKSUM_ARGS+=" --extract"
    fi
    # Let checksum-verify use its own default ./packages/<name>/ rather than
    # forcing extraction under the meta tree. The actual path is read back from
    # extraction.path in the JSON after wave 1 completes.
    CHKSUM_ARGS+=" --output-dir $OUT_DIR"
    [[ -n "$SOURCE_TYPE_FLAG" ]] && CHKSUM_ARGS+=" --source-type $SOURCE_TYPE_FLAG"
    [[ -n "$WP_PLUGIN"  ]] && [[ -z "$SOURCE_TYPE_FLAG" ]] \
        && CHKSUM_ARGS+=" --source-type wordpress"
    # Forward explicit name/version overrides when provided
    [[ -n "$WP_PLUGIN"  ]] && CHKSUM_ARGS+=" --pkg-name $WP_PLUGIN"
    [[ -n "$WP_VERSION" ]] && CHKSUM_ARGS+=" --pkg-version $WP_VERSION"
    CHKSUM_ARGS+=" $TARGET"
    WAVE1_JOBS+=("checksum-verify.sh|$CHKSUM_OUT|$CHKSUM_ARGS")
fi

# sbom-discover
if [[ "$SKIP_DISCOVER" == "false" ]]; then
    DISCOVER_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
    DISCOVER_ARGS+=" --output-dir $OUT_DIR"
    DISCOVER_ARGS+=" $TARGET"
    WAVE1_JOBS+=("sbom-discover.sh||$DISCOVER_ARGS")
fi

# sbom-gen
if [[ "$SKIP_SBOM_GEN" == "false" ]]; then
    SBOMGEN_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
    SBOMGEN_ARGS+=" --format both"
    SBOMGEN_ARGS+=" --output-dir $OUT_DIR"
    SBOMGEN_ARGS+=" $TARGET"
    WAVE1_JOBS+=("sbom-gen.sh||$SBOMGEN_ARGS")
fi

run_wave "Wave 1: Checksum / Discover / Generate" WAVE1_JOBS

# ── Locate generated SBOMs for wave 2 ────────────────────────────────────────
#
# sbom-gen may rename the output files to append a version suffix
# (e.g. akismet.5.3.cdx.json) when it can extract a clean semantic version from
# the SBOM metadata. We cannot assume a fixed filename. Glob for the actual files
# rather than hard-coding ${CLEAN_NAME}.cdx.json.
CDX_SBOM=""
SPDX_SBOM=""

# Prefer files whose basename starts with CLEAN_NAME and ends with the right suffix.
# If sbom-gen produced both a plain and a versioned copy, take the versioned one
# (it is the one sbom-gen left in place — it moved the plain one).
_sbom_cdx_glob=( "${OUT_DIR}/${CLEAN_NAME}"*.cdx.json )
_sbom_spdx_glob=( "${OUT_DIR}/${CLEAN_NAME}"*.spdx.json )

for _f in "${_sbom_cdx_glob[@]}";  do [[ -f "$_f" ]] && CDX_SBOM="$_f"  && break; done
for _f in "${_sbom_spdx_glob[@]}"; do [[ -f "$_f" ]] && SPDX_SBOM="$_f" && break; done
unset _sbom_cdx_glob _sbom_spdx_glob _f

# If sbom-gen was skipped, consult sbom-discover output instead
if [[ "$SKIP_SBOM_GEN" == "true" ]]; then
    DISCOVER_JSON="${OUT_DIR}/${CLEAN_NAME}.discover.json"
    if [[ -f "$DISCOVER_JSON" ]]; then
        _disc_cdx=$(jq -r '
            .sbom_discovery.valid_sboms[]?
            | select(.format == "cyclonedx") | .path
        ' "$DISCOVER_JSON" 2>/dev/null | head -n1 || echo "")
        _disc_spdx=$(jq -r '
            .sbom_discovery.valid_sboms[]?
            | select(.format == "spdx") | .path
        ' "$DISCOVER_JSON" 2>/dev/null | head -n1 || echo "")
        [[ -n "$_disc_cdx"  ]] && CDX_SBOM="$_disc_cdx"
        [[ -n "$_disc_spdx" ]] && SPDX_SBOM="$_disc_spdx"
        unset _disc_cdx _disc_spdx
    fi
fi

[[ -n "$CDX_SBOM"  ]] && log_file "  CDX SBOM:  $(basename "$CDX_SBOM")"                         || log_file "  [WARN] No CycloneDX SBOM found in $OUT_DIR"
[[ -n "$SPDX_SBOM" ]] && log_file "  SPDX SBOM: $(basename "$SPDX_SBOM")"                        || log_file "  [WARN] No SPDX SBOM found in $OUT_DIR"

# ── Extracted directory (from checksum-verify --extract or pre-existing) ─────
#
# Read the extraction path from the checksum JSON if available —
# checksum-verify writes the absolute path to extraction.path.
# Fall back to ./packages/<name>/ (checksum-verify's own default), then to TARGET
# if it is already a directory.
CHECKSUM_JSON_PATH="${OUT_DIR}/${CLEAN_NAME}.checksum.json"
EXTRACTED_DIR=""

if [[ -f "$CHECKSUM_JSON_PATH" ]]; then
    _ext_path=$(jq -r '.crypto_verification.extraction.path // ""'         "$CHECKSUM_JSON_PATH" 2>/dev/null || echo "")
    [[ -n "$_ext_path" && -d "$_ext_path" ]] && EXTRACTED_DIR="$_ext_path"
    unset _ext_path
fi

# Fallback chain
if [[ -z "$EXTRACTED_DIR" ]]; then
    _pkg_default="./packages/${CLEAN_NAME}"
    [[ -d "$_pkg_default" ]] && EXTRACTED_DIR="$_pkg_default"
    unset _pkg_default
fi
[[ -z "$EXTRACTED_DIR" ]] && [[ -d "$TARGET" ]] && EXTRACTED_DIR="$TARGET"

# ── single-subdir unwrap ────────────────────────────────────────────────────
# Many packages (WordPress plugins, npm tarballs, etc.) extract to a single
# subdirectory inside the archive root. If EXTRACTED_DIR contains exactly one
# entry and it is a directory, use that subdirectory as the effective root so
# all sub-scripts operate on the package root rather than a wrapper directory.
if [[ -d "$EXTRACTED_DIR" ]]; then
    _sub_entries=()
    while IFS= read -r -d '' _sub_e; do
        _sub_entries+=("$_sub_e")
    done < <(find "$EXTRACTED_DIR" -maxdepth 1 -mindepth 1 -print0 2>/dev/null)
    if [[ ${#_sub_entries[@]} -eq 1 && -d "${_sub_entries[0]}" ]]; then
        EXTRACTED_DIR="${_sub_entries[0]}"
    fi
    unset _sub_entries _sub_e
fi

# CHECKSUM_JSON_PATH already set above when resolving EXTRACTED_DIR

# ── Wave 2: vuln-scan + license-check + dependency-audit + provenance-verify + sbom-compare

# If a Grype DB update was triggered, wait for it now before Wave 2 begins.
# Wave 1 has already run in parallel, so the update has had maximum time to complete.
if [[ -n "$GRYPE_DB_UPDATE_PID" ]]; then
    log_file "  [DB]   Waiting for Grype DB update (pid $GRYPE_DB_UPDATE_PID)..."
    wait "$GRYPE_DB_UPDATE_PID" 2>/dev/null \
        && log_file "  [DB]   Grype DB update complete" \
        || log_file "  [WARN] Grype DB update exited non-zero — vuln-scan will use existing DB"
fi

WAVE2_JOBS=()

# vuln-scan — requires CycloneDX SBOM
if [[ "$SKIP_VULN" == "false" ]] && [[ -f "$CDX_SBOM" ]]; then
    VULN_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
    VULN_ARGS+=" --output-dir $OUT_DIR"
    VULN_ARGS+=" $CDX_SBOM"
    WAVE2_JOBS+=("vuln-scan.sh||$VULN_ARGS")
elif [[ "$SKIP_VULN" == "false" ]]; then
    log_file "  [SKIP] vuln-scan — no CycloneDX SBOM available"
fi

# license-check — requires SPDX SBOM
if [[ "$SKIP_LICENSE" == "false" ]] && [[ -f "$SPDX_SBOM" ]]; then
    LIC_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
    LIC_ARGS+=" --output-dir $OUT_DIR"
    [[ -n "$ECOSYSTEM"                  ]] && LIC_ARGS+=" --ecosystem $ECOSYSTEM"
    [[ "$LICENSE_REQUIRE_GPL_COMPAT" == "true" ]] && LIC_ARGS+=" --require-gpl-compat"
    [[ "$FAIL_ON_LICENSE_UNKNOWN" == "false"   ]] && LIC_ARGS+=" --allow-unknown"
    LIC_ARGS+=" $SPDX_SBOM"
    WAVE2_JOBS+=("license-check.sh||$LIC_ARGS")
elif [[ "$SKIP_LICENSE" == "false" ]]; then
    log_file "  [SKIP] license-check — no SPDX SBOM available"
fi

# dependency-audit — uses CycloneDX (broader component info) or SPDX
if [[ "$SKIP_AUDIT" == "false" ]]; then
    AUDIT_SBOM=""
    [[ -f "$CDX_SBOM"  ]] && AUDIT_SBOM="$CDX_SBOM"
    [[ -z "$AUDIT_SBOM" ]] && [[ -f "$SPDX_SBOM" ]] && AUDIT_SBOM="$SPDX_SBOM"
    if [[ -n "$AUDIT_SBOM" ]]; then
        AUDIT_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
        AUDIT_ARGS+=" --output-dir $OUT_DIR"
        AUDIT_ARGS+=" $AUDIT_SBOM"
        WAVE2_JOBS+=("dependency-audit.sh||$AUDIT_ARGS")
    else
        log_file "  [SKIP] dependency-audit — no SBOM available"
    fi
fi

# provenance-verify
#
# Guard: only run when there is meaningful verification work to do.
# Without at least one of --wp-plugin, --source-repo, or a .provenance.json
# file, auto mode resolves to "none" — the script runs, emits an empty result,
# and still applies a BASE_RISK penalty (300 pts) as if verification was
# expected and skipped. That's misleading. Skip explicitly instead.
#
# FUTURE: once slsa-attest (Wave 3) produces its .provenance.json, a second
# provenance-verify pass in --mode slsa could validate the attestation file
# for predicate format, builder trust, and artifact digest. Wave ordering
# currently prevents this (Wave 2 runs before the attestation exists). Options:
# (a) move provenance-verify to a Wave 4 post-attestation step, or
# (b) add a separate --verify-attestation flag that queues the validation pass
#     after Wave 3 completes and before final meta aggregation.
if [[ "$SKIP_PROVENANCE" == "false" ]]; then
    PROV_HAS_WORK=false
    [[ -n "$WP_PLUGIN"    ]] && PROV_HAS_WORK=true
    [[ -n "$SOURCE_REPO"  ]] && PROV_HAS_WORK=true

    if [[ "$PROV_HAS_WORK" == "false" ]]; then
        log_file "  [SKIP] provenance-verify — no verification context supplied"
        log_file "         Pass --wp-plugin, --source-repo, or use --skip-provenance to suppress this message"
    else
        PROV_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
        PROV_ARGS+=" --output-dir $OUT_DIR"
        PROV_ARGS+=" --package-type $PACKAGE_TYPE"
        [[ -n "$SOURCE_REPO"   ]] && PROV_ARGS+=" --source-repo $SOURCE_REPO"
        [[ -n "$SOURCE_COMMIT" ]] && PROV_ARGS+=" --source-commit $SOURCE_COMMIT"
        [[ -n "$WP_PLUGIN"     ]] && PROV_ARGS+=" --wp-plugin $WP_PLUGIN"
        [[ -n "$WP_VERSION"    ]] && PROV_ARGS+=" --wp-version $WP_VERSION"
        [[ -f "$CHECKSUM_JSON_PATH" ]] && PROV_ARGS+=" --checksum-json $CHECKSUM_JSON_PATH"
        [[ -d "$EXTRACTED_DIR" ]] && PROV_ARGS+=" --extracted-dir $EXTRACTED_DIR"
        [[ -n "$WP_PLUGIN"     ]] && PROV_ARGS+=" --mode wordpress" \
            || PROV_ARGS+=" --mode auto"
        PROV_ARGS+=" $TARGET"
        WAVE2_JOBS+=("provenance-verify.sh||$PROV_ARGS")
    fi
fi

# sbom-compare
if [[ "$SKIP_COMPARE" == "false" ]] && [[ -n "$COMPARE_MODE" ]]; then
    if [[ -n "$COMPARE_FILE_PATH" ]] && [[ -f "$COMPARE_FILE_PATH" ]]; then
        CMP_SBOM=""
        [[ -f "$SPDX_SBOM" ]] && CMP_SBOM="$SPDX_SBOM"
        [[ -z "$CMP_SBOM"  ]] && [[ -f "$CDX_SBOM" ]] && CMP_SBOM="$CDX_SBOM"
        if [[ -n "$CMP_SBOM" ]]; then
            CMP_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
            CMP_ARGS+=" --output-dir $OUT_DIR"
            [[ "$COMPARE_MODE" == "sbom"     ]] && CMP_ARGS+=" --compare  $COMPARE_FILE_PATH"
            [[ "$COMPARE_MODE" == "manifest" ]] && CMP_ARGS+=" --manifest $COMPARE_FILE_PATH"
            CMP_ARGS+=" $CMP_SBOM"
            WAVE2_JOBS+=("sbom-compare.sh||$CMP_ARGS")
        else
            log_file "  [SKIP] sbom-compare — no SBOM available to compare"
        fi
    else
        log_file "  [SKIP] sbom-compare — comparison file not found: $COMPARE_FILE_PATH"
    fi
fi

run_wave "Wave 2: Scan / Audit / Verify" WAVE2_JOBS

# ── Wave 3: slsa-attest ───────────────────────────────────────────────────────

# SLSA runs unconditionally unless --skip-slsa. slsa-attest.sh handles L0
# observer-only mode when --builder-id/--policy-uri are absent.
if [[ "$SKIP_SLSA" == "false" ]]; then

    log_file "── Wave 3: SLSA Attestation ──────────────────────────"

    SLSA_SCRIPT=$(find_script "slsa-attest.sh") || {
        log_file "  [SKIP] slsa-attest — script not found"
        SKIP_SLSA=true
    }

    if [[ "$SKIP_SLSA" == "false" ]]; then
        SLSA_ARGS="${SF:+$SF} ${VF:+$VF} $JF"
        SLSA_ARGS+=" --level $SLSA_LEVEL"
        SLSA_ARGS+=" --builder-id $BUILDER_ID"
        SLSA_ARGS+=" --policy-uri $POLICY_URI"
        SLSA_ARGS+=" --output-dir $OUT_DIR"
        [[ -n "$DISCLAIMER_URI" ]] && SLSA_ARGS+=" --disclaimer-uri $DISCLAIMER_URI"
        [[ -n "$SOURCE_TYPE_FLAG" ]] && SLSA_ARGS+=" --source-type $SOURCE_TYPE_FLAG"
        [[ -n "$SOURCE_REPO"    ]] && SLSA_ARGS+=" --source-repo $SOURCE_REPO"
        [[ -n "$SOURCE_COMMIT"  ]] && SLSA_ARGS+=" --source-commit $SOURCE_COMMIT"
        [[ -n "$SOURCE_REF"     ]] && SLSA_ARGS+=" --source-ref $SOURCE_REF"
        [[ -n "$BUILD_TRIGGER"  ]] && SLSA_ARGS+=" --build-trigger $BUILD_TRIGGER"
        [[ -n "$BUILD_ID"       ]] && SLSA_ARGS+=" --build-id $BUILD_ID"

        if [[ "$DRY_RUN" == "true" ]]; then
            log_file "  [DRY] slsa-attest.sh $SLSA_ARGS --meta-json <meta.json> $TARGET"
        else
            # Run slsa-attest after meta JSON is written — pass it in
            # temporarily write an intermediate meta for the attestation
            local_tmp_meta=$(mktemp -t toolkit_meta_XXXXXX.json)
            TMP_FILES+=("$local_tmp_meta")
            aggregate_meta "$OUT_DIR" "$CLEAN_NAME" "$RUN_ID" > "$local_tmp_meta"

            slsa_status=0
            # shellcheck disable=SC2086
            bash "$SLSA_SCRIPT" $SLSA_ARGS \
                --meta-json "$local_tmp_meta" \
                "$TARGET" >> "$RUN_LOG" 2>&1 || slsa_status=$?
            JOB_STATUS["slsa-attest.sh"]=$slsa_status
            [[ $slsa_status -eq 0 ]] \
                && log_file "  [OK]   slsa-attest.sh" \
                || log_file "  [WARN] slsa-attest.sh exited $slsa_status"
        fi
    fi
fi

# ── Aggregate meta JSON ───────────────────────────────────────────────────────

log_file "── Aggregating meta JSON ─────────────────────────────"

# Write initial aggregated meta to disk immediately — all subsequent enrichment
# works in-place on the file so that large JSON never travels through shell
# variables or command-line arguments (avoids ARG_MAX / "Argument list too long").
aggregate_meta "$OUT_DIR" "$CLEAN_NAME" "$RUN_ID" | jq . > "$META_FILE"
log_file "  [OK]   Saved: $META_FILE"

# ── Add SLSA attestation reference and gap analysis ───────────────────────────
SLSA_ATTESTATION_FILE="${OUT_DIR}/${CLEAN_NAME}.slsa-L${SLSA_LEVEL}.provenance.json"
SLSA_ASSESSMENT_FILE="${OUT_DIR}/${CLEAN_NAME}.slsa-assessment.json"
if [[ -f "$SLSA_ATTESTATION_FILE" ]]; then
    jq --arg path "$SLSA_ATTESTATION_FILE" \
        '.slsa_attestation = {file: $path}' \
        "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
fi
if [[ -f "$SLSA_ASSESSMENT_FILE" ]]; then
    jq --slurpfile assess "$SLSA_ASSESSMENT_FILE" \
        '.slsa_assessment = $assess[0].slsa_assessment' \
        "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
fi

# ── Enrich CDX SBOM with vulnerability data ───────────────────────────────────
VULN_JSON="${OUT_DIR}/${CLEAN_NAME}.vuln.json"
if [[ -f "$VULN_JSON" ]] && [[ -f "$CDX_SBOM" ]]; then
    mv "$VULN_JSON" "$CDX_SBOM" \
        && log_file "  [OK]   CDX SBOM enriched with vulnerability data: $(basename "$CDX_SBOM")" \
        || log_file "  [WARN] Could not promote vuln.json to CDX SBOM — keeping both files"
fi

# ── Merge filescan results (if run-filescans ran first) ───────────────────────
if [[ -f "$META_FILE" ]] && jq -e '.filescan' "$META_FILE" &>/dev/null 2>&1; then
    # filescan key already present (run-filescans wrote it before sbom-toolkit);
    # nothing to do — aggregate_meta reads from the same file path and the
    # filescan key is not overwritten (it's not in scan_keys).
    log_file "  [OK]   Filescan results already present in meta"
fi

# ── Mark intermediate scan JSONs for cleanup ──────────────────────────────────
if [[ "$KEEP_INTERMEDIATE" == "false" ]]; then
    for _int_f in \
        "${OUT_DIR}/${CLEAN_NAME}.checksum.json" \
        "${OUT_DIR}/${CLEAN_NAME}.discover.json" \
        "${OUT_DIR}/${CLEAN_NAME}.license.json" \
        "${OUT_DIR}/${CLEAN_NAME}.deps-audit.json" \
        "${OUT_DIR}/${CLEAN_NAME}.compare.json" \
        "${OUT_DIR}/${CLEAN_NAME}.provenance.json"
    do
        [[ -f "$_int_f" ]] && TMP_FILES+=("$_int_f")
    done
    unset _int_f
fi

# ── CI gate evaluation ────────────────────────────────────────────────────────
# evaluate_gates reads from META_FILE on disk — no large variable passing.

GATE_STATUS=0
evaluate_gates_from_file() {
    local meta_file="$1"
    local gate_failures=()
    # Re-read gates from the written file using jq queries
    if [[ -n "$FAIL_ON_RISK" ]]; then
        local total_risk
        total_risk=$(jq -r '.risk_assessment.total_risk_score // 0' "$meta_file" 2>/dev/null || echo 0)
        if (( $(echo "$total_risk >= $FAIL_ON_RISK" | bc -l 2>/dev/null || echo 0) )); then
            gate_failures+=("Risk score $total_risk >= threshold $FAIL_ON_RISK")
        fi
    fi
    if [[ -n "$FAIL_ON_SEVERITY" ]]; then
        local sev_count crit high
        case "$FAIL_ON_SEVERITY" in
            CRITICAL)
                crit=$(jq -r '.vulnerability_scan.risk_assessment.vuln_counts.critical // 0' "$meta_file" 2>/dev/null || echo 0)
                [[ $crit -gt 0 ]] && gate_failures+=("$crit CRITICAL severity finding(s)") ;;
            HIGH)
                crit=$(jq -r '.vulnerability_scan.risk_assessment.vuln_counts.critical // 0' "$meta_file" 2>/dev/null || echo 0)
                high=$(jq -r '.vulnerability_scan.risk_assessment.vuln_counts.high // 0' "$meta_file" 2>/dev/null || echo 0)
                [[ $crit -gt 0 ]] && gate_failures+=("$crit CRITICAL severity finding(s)")
                [[ $high -gt 0 ]] && gate_failures+=("$high HIGH severity finding(s)") ;;
        esac
    fi
    if [[ "$FAIL_ON_GPL_INCOMPAT" == "true" ]]; then
        local incompat
        incompat=$(jq -r '.license_compliance.summary.gpl_incompatible // 0' "$meta_file" 2>/dev/null || echo 0)
        [[ $incompat -gt 0 ]] && gate_failures+=("$incompat GPL-incompatible license(s) detected")
    fi
    if [[ "$FAIL_ON_CONFUSION" == "true" ]]; then
        local confusion_count typo_count
        confusion_count=$(jq -r '.dependency_audit.summary.dependency_confusion // 0' "$meta_file" 2>/dev/null || echo 0)
        typo_count=$(jq -r '.dependency_audit.summary.typosquatting // 0' "$meta_file" 2>/dev/null || echo 0)
        [[ $confusion_count -gt 0 ]] && gate_failures+=("$confusion_count dependency confusion finding(s)")
        [[ $typo_count -gt 0 ]] && gate_failures+=("$typo_count typosquatting finding(s)")
    fi
    if [[ ${#gate_failures[@]} -gt 0 ]]; then
        log_file "── CI Gate: FAILED ───────────────────────────────────"
        local msg
        for msg in "${gate_failures[@]}"; do
            log_file "  [GATE] $msg"
        done
        return 1
    else
        log_file "── CI Gate: PASSED ───────────────────────────────────"
        return 0
    fi
}
evaluate_gates_from_file "$META_FILE" || GATE_STATUS=$?

# ── Final summary ─────────────────────────────────────────────────────────────
# All reads come from META_FILE on disk — never from a shell variable.

TOTAL_RISK=$(jq -r '.risk_assessment.total_risk_score // "n/a"' "$META_FILE" 2>/dev/null || echo "n/a")
RISK_LEVEL=$(jq -r '.risk_assessment.risk_level // "n/a"' "$META_FILE" 2>/dev/null || echo "n/a")
SLSA_HIGHEST=$(jq -r '.slsa_assessment.highest_satisfied // "n/a"' "$META_FILE" 2>/dev/null || echo "n/a")
SLSA_MISSING=$(jq -r '[.slsa_assessment.levels // {} | to_entries[] | .value.requirements // {} | to_entries[] | select(.value.met == false) | .value.missing_flag] | map(select(. != null)) | length' \
    "$META_FILE" 2>/dev/null || echo "0")

log_file ""
log_file "── Summary ───────────────────────────────────────────"
log_file "  Target:     $(basename "$TARGET")"
log_file "  Risk score: $TOTAL_RISK ($RISK_LEVEL)"
if [[ "$SLSA_HIGHEST" != "n/a" ]]; then
    log_file "  SLSA level: L${SLSA_HIGHEST} satisfied (target: L${SLSA_LEVEL})"
    [[ "$SLSA_MISSING" -gt 0 ]] \
        && log_file "  SLSA gaps:  $SLSA_MISSING missing requirements (see $(basename "$SLSA_ASSESSMENT_FILE"))"
fi
log_file "  Meta JSON:  $META_FILE"
[[ "$NO_LOG" == "false" ]] && log_file "  Run log:    $RUN_LOG"

# Script exit status breakdown
if [[ ${#JOB_STATUS[@]} -gt 0 ]]; then
    log_file "  Script results:"
    local_script="" local_code=""
    for local_script in "${!JOB_STATUS[@]}"; do
        local_code="${JOB_STATUS[$local_script]}"
        case "$local_code" in
            0) log_file "    [OK]   $local_script" ;;
            1) log_file "    [WARN] $local_script — issues found" ;;
            *) log_file "    [FAIL] $local_script — exit $local_code" ;;
        esac
    done
fi

if [[ $GATE_STATUS -ne 0 ]]; then
    log_file ""
    log_file "  RESULT: FAIL (CI gate triggered)"
    exit 1
fi

log_file ""
log_file "  RESULT: PASS"
exit 0
