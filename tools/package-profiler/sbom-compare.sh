#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# sbom-compare.sh - compare an SBOM against a manifest or another SBOM
#
# Usage: sbom-compare.sh [OPTIONS] <sbom_file>
#
# Two modes:
#   --manifest FILE   Compare SBOM against a package manifest (composer.lock,
#                     package.json, requirements.txt, etc.) — detects packages
#                     present in the SBOM but absent from the manifest, or
#                     vice versa, and version drift between the two.
#
#   --compare FILE    Compare two SBOMs — detects added, removed, and
#                     version-changed packages between them. If both SBOMs
#                     carry embedded vulnerability data (from vuln-scan.sh),
#                     also reports the risk score delta.
#
# Output file: ./meta/<clean-name>/<clean-name>.compare.json
#
# Exit codes: 0 = no differences, 1 = differences found, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

SBOM_FILE=""
COMPARE_FILE=""
MANIFEST_FILE=""
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false

# When true, packages only in the manifest (not in the SBOM) are also reported.
# Useful when the manifest is considered the authoritative list.
REPORT_MANIFEST_ONLY=false

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/sbom_compare_*.txt /tmp/sbom_compare_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <sbom_file>

Compare an SBOM against a package manifest or another SBOM.

MODES (one required):
    --manifest FILE     Compare SBOM against a package manifest.
                        Detects packages in the SBOM but absent from the
                        manifest, and version drift between them.
    --compare FILE      Compare two SBOMs. Detects added, removed, and
                        version-changed packages. If both SBOMs contain
                        embedded vulnerability data, also reports risk delta.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show per-package diff detail
    -o, --output-dir DIR    Directory for output file
                            (default: ./meta/<clean-name>/)
    --meta-base DIR         Base directory for meta output (default: ./meta)
    --no-file               Output JSON to stdout only; do not write file
    --report-manifest-only  Also flag packages present in the manifest but
                            absent from the SBOM (--manifest mode only)
    --version               Print version and exit

ARGUMENTS:
    sbom_file           SPDX or CycloneDX SBOM JSON (the primary/newer file)

OUTPUT FILE:
    ./meta/<clean-name>/<clean-name>.compare.json

MANIFEST MODE (--manifest):
    Parses the manifest natively without invoking Syft. Supported formats:
      composer.lock       PHP/Composer — reads .packages[].name/.version
      package.json        npm — reads .dependencies (name → version string)
      package-lock.json   npm lockfile — reads .packages (or .dependencies)
      yarn.lock           Yarn — parsed with awk; name/version pairs
      requirements.txt    Python/pip — parsed with awk; name==version lines
      Pipfile.lock        Pipenv — reads .default / .develop
      go.mod              Go modules — parsed with awk; require directives

    Comparison output:
      sbom_only     Package in SBOM not found in manifest
      manifest_only Package in manifest not found in SBOM (--report-manifest-only)
      version_drift Package in both but versions differ

SBOM vs SBOM MODE (--compare):
    Reads both SBOMs using jq (SPDX and CycloneDX supported; formats may
    differ between the two files).

    Comparison output:
      added         Package in primary SBOM, not in baseline
      removed       Package in baseline, not in primary SBOM
      changed       Package in both, version differs
      risk_delta    Difference in weighted_risk scores (if vuln data present)

EXAMPLES:
    # SBOM vs Composer lockfile
    $(basename "$0") --manifest composer.lock sbom.spdx.json

    # SBOM vs npm lockfile, include manifest-only packages
    $(basename "$0") --manifest package-lock.json --report-manifest-only sbom.cdx.json

    # Compare two SBOMs (new vs baseline)
    $(basename "$0") --compare baseline.spdx.json current.spdx.json

    # Compare with risk delta (both SBOMs produced by vuln-scan.sh)
    $(basename "$0") --compare old.vuln.json new.vuln.json

    # JSON to stdout, no file
    $(basename "$0") -sj --no-file --manifest composer.lock sbom.spdx.json

DEPENDENCIES:
    jq, awk

VERSION: $VERSION (toolkit $TOOLKIT_VERSION)
EOF
    exit 0
}

log()  { [[ "$SILENT" == "false" ]] && echo "$@" >&2 || true; }
info() { [[ "$VERBOSE" == "true" ]] && echo "   $*" >&2 || true; }
die()  { echo "Error: $*" >&2; exit 2; }

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
    clean="${clean%.tgz}"
    clean="${clean%.zip}"
    clean=$(echo "$clean" | sed 's/[^a-zA-Z0-9._-]/_/g')
    [[ -z "$clean" ]] && clean="package_$(date +%s)"
    echo "$clean"
}

# ── Functions: SBOM extraction ────────────────────────────────────────────────
# Extracts "name|version" pairs from an SPDX or CycloneDX SBOM.
# exclude_root controls whether the root/primary package is skipped:
#   true  (default) — used in SBOM-vs-SBOM mode; root is the subject, not a dep
#   false           — used in manifest mode; root must be compared like any package

extract_sbom_packages() {
    local file="$1"
    local exclude_root="${2:-true}"

    # Try SPDX first
    if jq -e '.spdxVersion' "$file" &>/dev/null 2>&1; then
        local root_id
        root_id=$(jq -r '.documentDescribes[0] // ""' "$file" 2>/dev/null || echo "")
        if [[ "$exclude_root" == "true" ]]; then
            jq -r \
                --arg root "$root_id" \
                '.packages[]?
                 | select(.SPDXID != $root)
                 | [ .name, (.versionInfo // "unknown") ]
                 | join("|")' \
                "$file" 2>/dev/null | sort
        else
            jq -r \
                '.packages[]?
                 | [ .name, (.versionInfo // "unknown") ]
                 | join("|")' \
                "$file" 2>/dev/null | sort
        fi
        return
    fi

    # Try CycloneDX
    if jq -e '.bomFormat' "$file" &>/dev/null 2>&1; then
        local root_name
        root_name=$(jq -r '.metadata.component.name // ""' "$file" 2>/dev/null || echo "")
        if [[ "$exclude_root" == "true" ]]; then
            jq -r \
                --arg root "$root_name" \
                '.components[]?
                 | select(.name != $root)
                 | [ .name, (.version // "unknown") ]
                 | join("|")' \
                "$file" 2>/dev/null | sort
        else
            jq -r \
                '.components[]?
                 | [ .name, (.version // "unknown") ]
                 | join("|")' \
                "$file" 2>/dev/null | sort
        fi
        return
    fi

    die "Cannot parse SBOM: unrecognised format in $file"
}

# lookup_purl FILE PACKAGE_NAME
# Returns the purl for a named package from an SPDX or CycloneDX SBOM.
# Used to detect bundled WordPress plugins (purl starts with pkg:wordpress/).
lookup_purl() {
    local file="$1" pkg_name="$2"
    local purl=""
    # SPDX: externalRefs[] where referenceType == "purl"
    purl=$(jq -r \
        --arg name "$pkg_name" \
        '.packages[]?
         | select(.name == $name)
         | .externalRefs[]?
         | select(.referenceType == "purl")
         | .referenceLocator' \
        "$file" 2>/dev/null | head -1 || echo "")
    # CycloneDX: .components[].purl
    if [[ -z "$purl" ]]; then
        purl=$(jq -r \
            --arg name "$pkg_name" \
            '.components[]? | select(.name == $name) | .purl // ""' \
            "$file" 2>/dev/null | head -1 || echo "")
    fi
    echo "${purl:-}"
}

# ── Functions: Manifest parsing ───────────────────────────────────────────────
# Each function outputs "name|version" pairs, one per line, sorted.

parse_composer_lock() {
    local file="$1"
    jq -r '
        (.packages // []) + (."packages-dev" // [])
        | .[]
        | [ .name, (.version // "unknown") ]
        | join("|")
    ' "$file" 2>/dev/null | sort
}

parse_package_json() {
    local file="$1"
    # package.json dependencies values are version constraints, not resolved
    # versions — we report them as-is and flag as version_constraint in output
    jq -r '
        ( (.dependencies // {}) + (.devDependencies // {}) )
        | to_entries[]
        | [ .key, .value ]
        | join("|")
    ' "$file" 2>/dev/null | sort
}

parse_package_lock_json() {
    local file="$1"
    # npm v3 lockfile format: .packages object keys are "node_modules/<name>"
    # npm v2/v1 format: .dependencies object
    local version
    version=$(jq -r '.lockfileVersion // 1' "$file" 2>/dev/null || echo "1")

    if [[ "$version" -ge 3 ]]; then
        jq -r '
            .packages // {} | to_entries[]
            | select(.key != "" and (.key | startswith("node_modules/")))
            | [ (.key | ltrimstr("node_modules/")),
                (.value.version // "unknown") ]
            | join("|")
        ' "$file" 2>/dev/null | sort
    else
        jq -r '
            .dependencies // {} | to_entries[]
            | [ .key, (.value.version // "unknown") ]
            | join("|")
        ' "$file" 2>/dev/null | sort
    fi
}

parse_yarn_lock() {
    local file="$1"
    # yarn.lock format (v1):
    #   "name@version":       (or name@version:)
    #     version "x.y.z"
    # Extract name from first field of each block header, version from "version" line
    awk '
        /^"?[a-zA-Z@]/ {
            # Strip quotes, take first entry if multiple, strip @version suffix
            gsub(/^"|"$/, "")
            split($0, a, ",")   # multiple packages may share a resolution
            split(a[1], b, "@")
            # Handle scoped packages: @scope/name@version
            if (substr(a[1], 1, 1) == "@") {
                pkg = "@" b[2]
                sub(/@[^@]*$/, "", pkg)
            } else {
                pkg = b[1]
            }
            current = pkg
        }
        /^  version / {
            gsub(/"/, "", $2)
            if (current != "") print current "|" $2
            current = ""
        }
    ' "$file" 2>/dev/null | sort -u
}

parse_requirements_txt() {
    local file="$1"
    # Handle: name==version, name>=version, name~=version, name[extras]==version
    # We capture the name and the first version constraint as-is
    awk '
        /^[A-Za-z]/ {
            # Strip extras: name[extra]==version → name==version
            gsub(/\[[^\]]*\]/, "")
            # Split on first version operator
            if (match($0, /[><=!~]+/)) {
                name = substr($0, 1, RSTART-1)
                rest = substr($0, RSTART)
                # Get just the version part (before any semicolons or comments)
                split(rest, v, /[ \t;#]/)
                gsub(/^[><=!~]+/, "", v[1])
                # Trim whitespace
                gsub(/^[ \t]+|[ \t]+$/, "", name)
                if (name != "" && v[1] != "") print name "|" v[1]
            }
        }
    ' "$file" 2>/dev/null | sort
}

parse_pipfile_lock() {
    local file="$1"
    jq -r '
        ( (.default // {}) + (.develop // {}) )
        | to_entries[]
        | [ .key, (.value.version // "unknown" | ltrimstr("==")) ]
        | join("|")
    ' "$file" 2>/dev/null | sort
}

parse_go_mod() {
    local file="$1"
    # require directives: "  github.com/foo/bar v1.2.3"
    # multi-line require blocks also handled by awk
    awk '
        /^require \(/ { in_block=1; next }
        /^\)/ { in_block=0 }
        in_block && /^\t[a-zA-Z]/ {
            sub(/^\t/, "")
            split($0, a, " ")
            if (a[1] != "" && a[2] != "") print a[1] "|" a[2]
        }
        /^require [a-zA-Z]/ {
            split($0, a, " ")
            if (a[2] != "" && a[3] != "") print a[2] "|" a[3]
        }
    ' "$file" 2>/dev/null | sort
}

# Dispatch to the correct parser based on filename
parse_manifest() {
    local file="$1"
    local base
    base=$(basename "$file")
    case "$base" in
        composer.lock)       parse_composer_lock      "$file" ;;
        package.json)        parse_package_json       "$file" ;;
        package-lock.json)   parse_package_lock_json  "$file" ;;
        yarn.lock)           parse_yarn_lock          "$file" ;;
        requirements.txt)    parse_requirements_txt   "$file" ;;
        Pipfile.lock)        parse_pipfile_lock       "$file" ;;
        go.mod)              parse_go_mod             "$file" ;;
        *)
            die "Unsupported manifest format: $base
Supported: composer.lock, package.json, package-lock.json,
           yarn.lock, requirements.txt, Pipfile.lock, go.mod" ;;
    esac
}

# ── Functions: Diff engine ────────────────────────────────────────────────────
# Compares two sorted "name|version" streams using awk.
# Input: two temp files, each containing sorted "name|version" lines.
# Output: tab-separated lines: <status>\t<name>\t<version_a>\t<version_b>
#   status values: only_a | only_b | changed | same

diff_package_lists() {
    local file_a="$1"   # primary / newer
    local file_b="$2"   # baseline / manifest

    # Portable diff using sort + comm — no gawk/asorti required.
    # Both input files are already sorted "name|version" streams.

    local tmp_names_a tmp_names_b tmp_common
    tmp_names_a=$(mktemp -t sbom_diff_na_XXXXXX.txt)
    tmp_names_b=$(mktemp -t sbom_diff_nb_XXXXXX.txt)
    tmp_common=$(mktemp  -t sbom_diff_cm_XXXXXX.txt)

    cut -d'|' -f1 "$file_a" | sort > "$tmp_names_a"
    cut -d'|' -f1 "$file_b" | sort > "$tmp_names_b"

    # Names present in both lists — may be same or changed version
    comm -12 "$tmp_names_a" "$tmp_names_b" > "$tmp_common"

    # only_a: in A not in B
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name ver_a
        name=$(echo "$line" | cut -d'|' -f1)
        ver_a=$(echo "$line" | cut -d'|' -f2)
        grep -qxF "$name" "$tmp_common" || printf 'only_a\t%s\t%s\t\n' "$name" "$ver_a"
    done < "$file_a"

    # only_b: in B not in A
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name ver_b
        name=$(echo "$line" | cut -d'|' -f1)
        ver_b=$(echo "$line" | cut -d'|' -f2)
        grep -qxF "$name" "$tmp_common" || printf 'only_b\t%s\t\t%s\n' "$name" "$ver_b"
    done < "$file_b"

    # same / changed: names in both — compare versions
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local ver_a ver_b
        ver_a=$(grep "^${name}|" "$file_a" | head -n1 | cut -d'|' -f2)
        ver_b=$(grep "^${name}|" "$file_b" | head -n1 | cut -d'|' -f2)
        if [[ "$ver_a" == "$ver_b" ]]; then
            printf 'same\t%s\t%s\t%s\n' "$name" "$ver_a" "$ver_b"
        else
            printf 'changed\t%s\t%s\t%s\n' "$name" "$ver_a" "$ver_b"
        fi
    done < "$tmp_common"

    rm -f "$tmp_names_a" "$tmp_names_b" "$tmp_common"
}

# ── Functions: Risk delta ─────────────────────────────────────────────────────
# Extracts weighted_risk from a file that may be either a plain SBOM or a
# merged vuln-scan output (which has .risk_assessment.weighted_risk).

extract_risk_score() {
    local file="$1"
    local score
    score=$(jq -r '
        .risk_assessment.weighted_risk //
        .vulnerability_scan.matches // empty
        | if type == "number" then . else empty end
    ' "$file" 2>/dev/null | head -n1 || echo "")
    echo "${score:-}"
}

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       show_help ;;
        -sj|-js)         SILENT=true; JSON_OUTPUT=true; shift ;;
        -s|--silent)     SILENT=true; shift ;;
        -j|--json)       JSON_OUTPUT=true; shift ;;
        -v|--verbose)    VERBOSE=true; shift ;;
        -o|--output-dir)
            [[ -z "${2:-}" ]] && die "--output-dir requires an argument"
            OUTPUT_DIR="$2"; shift 2 ;;
        --meta-base)
            [[ -z "${2:-}" ]] && die "--meta-base requires an argument"
            META_BASE="$2"; shift 2 ;;
        --no-file)       WRITE_FILE=false; shift ;;
        --manifest)
            [[ -z "${2:-}" ]] && die "--manifest requires an argument"
            MANIFEST_FILE="$2"; shift 2 ;;
        --compare)
            [[ -z "${2:-}" ]] && die "--compare requires an argument"
            COMPARE_FILE="$2"; shift 2 ;;
        --report-manifest-only)
            REPORT_MANIFEST_ONLY=true; shift ;;
        --version)
            echo "sbom-compare.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  SBOM_FILE="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$SBOM_FILE" ]]    && die "No SBOM file specified (use --help for usage)"
[[ ! -f "$SBOM_FILE" ]]  && die "SBOM file not found: $SBOM_FILE"
jq empty "$SBOM_FILE" 2>/dev/null || die "Invalid JSON in SBOM file: $SBOM_FILE"

[[ -z "$MANIFEST_FILE" && -z "$COMPARE_FILE" ]] \
    && die "Specify --manifest FILE or --compare FILE"
[[ -n "$MANIFEST_FILE" && -n "$COMPARE_FILE" ]] \
    && die "--manifest and --compare are mutually exclusive"

command -v jq  &>/dev/null || die "jq is required"
command -v awk &>/dev/null || die "awk is required"

if [[ -n "$MANIFEST_FILE" ]]; then
    [[ ! -f "$MANIFEST_FILE" ]] && die "Manifest file not found: $MANIFEST_FILE"
    MODE="manifest"
else
    [[ ! -f "$COMPARE_FILE" ]] && die "Comparison SBOM not found: $COMPARE_FILE"
    jq empty "$COMPARE_FILE" 2>/dev/null \
        || die "Invalid JSON in comparison file: $COMPARE_FILE"
    MODE="sbom"
fi

CLEAN_NAME=$(sanitize_name "$SBOM_FILE")
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.compare.json"

# ── Extract package lists ─────────────────────────────────────────────────────

TMP_A=$(mktemp -t sbom_compare_XXXXXX.txt)
TMP_B=$(mktemp -t sbom_compare_XXXXXX.txt)

log "[COMP] Comparing: $(basename "$SBOM_FILE")"

# Primary SBOM is always file A
# Manifest mode: include root package (it IS the package being verified against the manifest)
# SBOM mode: exclude root package (it is the subject of comparison, not a dependency)
if [[ "$MODE" == "manifest" ]]; then
    extract_sbom_packages "$SBOM_FILE" "false" > "$TMP_A"
else
    extract_sbom_packages "$SBOM_FILE" "true" > "$TMP_A"
fi
A_COUNT=$(wc -l < "$TMP_A" | tr -d ' ')

if [[ "$MODE" == "manifest" ]]; then
    log "       Against manifest: $(basename "$MANIFEST_FILE")"
    parse_manifest "$MANIFEST_FILE" > "$TMP_B"
    B_LABEL="manifest"
    B_FILE="$(basename "$MANIFEST_FILE")"
else
    log "       Against SBOM: $(basename "$COMPARE_FILE")"
    extract_sbom_packages "$COMPARE_FILE" "true" > "$TMP_B"
    B_LABEL="baseline_sbom"
    B_FILE="$(basename "$COMPARE_FILE")"
fi

B_COUNT=$(wc -l < "$TMP_B" | tr -d ' ')
info "Primary packages:  $A_COUNT"
info "Baseline packages: $B_COUNT"

# ── Run diff ──────────────────────────────────────────────────────────────────

FINDINGS_ARR=()
ADDED_COUNT=0
REMOVED_COUNT=0
CHANGED_COUNT=0
SAME_COUNT=0
MANIFEST_ONLY_COUNT=0

while IFS=$'\t' read -r status pkg_name ver_a ver_b; do
    [[ -z "$pkg_name" ]] && continue

    case "$status" in
        only_a)
            # In primary SBOM, not in baseline/manifest
            if [[ "$MODE" == "manifest" ]]; then
                local_label="sbom_only"
                local_note="Present in SBOM but not in manifest"
                # Detect WordPress bundled plugins via purl (pkg:wordpress/...)
                pkg_purl=""
                pkg_purl=$(lookup_purl "$SBOM_FILE" "$pkg_name")
                if [[ "$pkg_purl" == pkg:wordpress/* ]]; then
                    local_note="Bundled WordPress plugin — present in distribution but not in dependency manifest"
                fi
            else
                local_label="added"
                local_note="Added in primary SBOM"
            fi
            ADDED_COUNT=$((ADDED_COUNT+1))
            info "  [+] $pkg_name $ver_a — $local_note"
            FINDINGS_ARR+=("$(jq -n \
                --arg status  "$local_label" \
                --arg name    "$pkg_name" \
                --arg ver_a   "$ver_a" \
                --arg ver_b   "" \
                --arg note    "$local_note" \
                '{status:$status,package:$name,
                  primary_version:$ver_a,baseline_version:$ver_b,
                  note:$note}')")
            ;;

        only_b)
            # In baseline/manifest, not in primary SBOM
            if [[ "$MODE" == "manifest" ]]; then
                local_label="manifest_only"
                local_note="Present in manifest but not in SBOM"
                MANIFEST_ONLY_COUNT=$((MANIFEST_ONLY_COUNT+1))
                # Only emit finding if requested
                [[ "$REPORT_MANIFEST_ONLY" == "false" ]] && continue
            else
                local_label="removed"
                local_note="Removed from primary SBOM"
                REMOVED_COUNT=$((REMOVED_COUNT+1))
            fi
            info "  [-] $pkg_name $ver_b — $local_note"
            FINDINGS_ARR+=("$(jq -n \
                --arg status  "$local_label" \
                --arg name    "$pkg_name" \
                --arg ver_a   "" \
                --arg ver_b   "$ver_b" \
                --arg note    "$local_note" \
                '{status:$status,package:$name,
                  primary_version:$ver_a,baseline_version:$ver_b,
                  note:$note}')")
            ;;

        changed)
            CHANGED_COUNT=$((CHANGED_COUNT+1))
            local_note="Version differs between primary and baseline"
            info "  [~] $pkg_name: $ver_b → $ver_a"
            FINDINGS_ARR+=("$(jq -n \
                --arg status  "changed" \
                --arg name    "$pkg_name" \
                --arg ver_a   "$ver_a" \
                --arg ver_b   "$ver_b" \
                --arg note    "$local_note" \
                '{status:$status,package:$name,
                  primary_version:$ver_a,baseline_version:$ver_b,
                  note:$note}')")
            ;;

        same)
            SAME_COUNT=$((SAME_COUNT+1))
            info "  [=] $pkg_name $ver_a"
            ;;
    esac

done < <(diff_package_lists "$TMP_A" "$TMP_B")

TOTAL_DIFFERENCES=$((ADDED_COUNT + REMOVED_COUNT + CHANGED_COUNT))
[[ "$MODE" == "manifest" ]] \
    && TOTAL_DIFFERENCES=$((ADDED_COUNT + CHANGED_COUNT))
[[ "$REPORT_MANIFEST_ONLY" == "true" ]] \
    && TOTAL_DIFFERENCES=$((TOTAL_DIFFERENCES + MANIFEST_ONLY_COUNT))

# ── Risk delta (SBOM vs SBOM mode only) ──────────────────────────────────────

RISK_DELTA_JSON="null"

if [[ "$MODE" == "sbom" ]]; then
    RISK_A=$(extract_risk_score "$SBOM_FILE")
    RISK_B=$(extract_risk_score "$COMPARE_FILE")

    if [[ -n "$RISK_A" ]] && [[ -n "$RISK_B" ]]; then
        RISK_DELTA=$(echo "$RISK_A $RISK_B" | awk '{printf "%.2f", $1 - $2}')
        RISK_DIRECTION="unchanged"
        if (( $(echo "$RISK_DELTA > 0" | bc -l 2>/dev/null || echo 0) )); then
            RISK_DIRECTION="increased"
        elif (( $(echo "$RISK_DELTA < 0" | bc -l 2>/dev/null || echo 0) )); then
            RISK_DIRECTION="decreased"
        fi

        RISK_DELTA_JSON=$(jq -n \
            --arg  primary   "$RISK_A" \
            --arg  baseline  "$RISK_B" \
            --arg  delta     "$RISK_DELTA" \
            --arg  direction "$RISK_DIRECTION" \
            '{primary_risk:($primary|tonumber),
              baseline_risk:($baseline|tonumber),
              delta:($delta|tonumber),
              direction:$direction}')

        log "  [RISK] $RISK_B → $RISK_A (delta: $RISK_DELTA, $RISK_DIRECTION)"
    else
        log "  [INFO] Risk delta not available (vuln data absent from one or both SBOMs)"
    fi
fi

# ── Summary log ──────────────────────────────────────────────────────────────

if [[ "$MODE" == "manifest" ]]; then
    log "[COMP] Results:"
    log "       SBOM only:       $ADDED_COUNT"
    log "       Manifest only:   $MANIFEST_ONLY_COUNT"
    log "       Version drift:   $CHANGED_COUNT"
    log "       Identical:       $SAME_COUNT"
    log "       Total diff:      $TOTAL_DIFFERENCES"
else
    log "[COMP] Results:"
    log "       Added:           $ADDED_COUNT"
    log "       Removed:         $REMOVED_COUNT"
    log "       Changed:         $CHANGED_COUNT"
    log "       Identical:       $SAME_COUNT"
    log "       Total diff:      $TOTAL_DIFFERENCES"
fi

# ── Build JSON output ─────────────────────────────────────────────────────────

FINDINGS_JSON=$(printf '%s\n' "${FINDINGS_ARR[@]+"${FINDINGS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  timestamp       "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_ver     "$TOOLKIT_VERSION" \
    --arg  mode            "$MODE" \
    --arg  primary_file    "$(basename "$SBOM_FILE")" \
    --arg  baseline_file   "${B_FILE:-}" \
    --arg  baseline_type   "${B_LABEL:-}" \
    --argjson primary_count  "$A_COUNT" \
    --argjson baseline_count "$B_COUNT" \
    --argjson added        "$ADDED_COUNT" \
    --argjson removed      "$REMOVED_COUNT" \
    --argjson changed      "$CHANGED_COUNT" \
    --argjson same         "$SAME_COUNT" \
    --argjson manifest_only "$MANIFEST_ONLY_COUNT" \
    --argjson total_diff   "$TOTAL_DIFFERENCES" \
    --argjson report_monly "$REPORT_MANIFEST_ONLY" \
    --argjson risk_delta   "$RISK_DELTA_JSON" \
    --argjson findings     "$FINDINGS_JSON" \
    '{
        sbom_comparison: {
            timestamp:       $timestamp,
            toolkit_version: $toolkit_ver,
            mode:            $mode,
            files: {
                primary:       $primary_file,
                baseline:      $baseline_file,
                baseline_type: $baseline_type
            },
            package_counts: {
                primary:  $primary_count,
                baseline: $baseline_count
            },
            summary: {
                added:         $added,
                removed:       $removed,
                changed:       $changed,
                same:          $same,
                manifest_only: $manifest_only,
                total_differences: $total_diff,
                report_manifest_only: $report_monly
            },
            risk_delta: $risk_delta,
            findings:   $findings
        }
    }')

# ── Output ────────────────────────────────────────────────────────────────────

if [[ "$WRITE_FILE" == "true" ]]; then
    echo "$OUTPUT_JSON" | jq . > "$OUTPUT_FILE"
    chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
    log "[OK]   Saved: $OUTPUT_FILE"
else
    echo "$OUTPUT_JSON" | jq .
fi

[[ $TOTAL_DIFFERENCES -gt 0 ]] && exit 1 || exit 0
