#!/usr/bin/env bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 SBOM Toolkit Contributors

#
# dependency-audit.sh - supply chain attack detection
#
# Usage: dependency-audit.sh [OPTIONS] <sbom_file>
#
# Analyses an SPDX or CycloneDX SBOM for indicators of supply chain attacks:
# typosquatting, dependency confusion, and suspicious package patterns.
#
# Output file: ./meta/<clean-name>/<clean-name>.audit.json
#
# Exit codes: 0 = no issues, 1 = issues found, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

SBOM_FILE=""
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false

CHECK_TYPOSQUAT=true
CHECK_CONFUSION=true
CHECK_SUSPICIOUS=true

# Levenshtein distance threshold for typosquat detection.
# Distance 1: catches single insertions, deletions, substitutions.
# Distance 2: also catches transpositions and two-character edits.
# Higher values increase false positives significantly.
TYPOSQUAT_MAX_DIST=2

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/dep_audit_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <sbom_file>

Detect supply chain attack indicators in an SPDX or CycloneDX SBOM.
Checks for typosquatting, dependency confusion, and suspicious package patterns.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show per-package detail
    -o, --output-dir DIR    Directory for output file
                            (default: ./meta/<clean-name>/)
    --meta-base DIR         Base directory for meta output (default: ./meta)
    --no-file               Output JSON to stdout only; do not write file
    --skip-typosquat        Skip typosquatting detection
    --skip-confusion        Skip dependency confusion detection
    --skip-suspicious       Skip suspicious pattern detection
    --max-distance N        Levenshtein distance threshold for typosquat
                            detection (default: 2; range: 1-3)
    --version               Print version and exit

ARGUMENTS:
    sbom_file               SPDX or CycloneDX SBOM JSON file

DETECTION METHODS:

1. TYPOSQUATTING
   Compares each package name against a list of popular packages using true
   Levenshtein edit distance. Catches:
     - Single-character insertions, deletions, substitutions
     - Transpositions ("requsets" for "requests")
     - Character substitutions ("l"→"1", "o"→"0")
     - Homoglyph patterns (look-alike Unicode characters)
   Method is noted as "levenshtein" in findings; distance is recorded.

2. DEPENDENCY CONFUSION
   Flags packages with internal/private scope indicators found in a public
   SBOM context:
     - Scoped npm packages with internal-looking scope names
       (@internal/, @private/, @corp/, @company/, etc.)
     - Package names containing internal namespace patterns

3. SUSPICIOUS PATTERNS
   Flags packages matching known attack-campaign patterns:
     - Version numbers suggesting hijack attempts (99.x, 0.0.x, 999.x)
     - Test/demo/temp/local in package name
     - Single-character or very short package names (length < 3)
     - Package names that are numeric only

RISK SCORING (contribution to toolkit total):
    Dependency confusion: +500 per finding
    Typosquatting:        +400 per finding
    Suspicious pattern:   +100 per finding

EXIT CODES:
    0    No issues found
    1    Issues detected
    2    Execution error

EXAMPLES:
    # Standard audit
    $(basename "$0") sbom-myplugin.cdx.json

    # Strict: lower distance threshold (fewer false positives)
    $(basename "$0") --max-distance 1 sbom.cdx.json

    # Skip typosquat (large SBOM, known-good packages)
    $(basename "$0") --skip-typosquat sbom.spdx.json

    # JSON to stdout, no file
    $(basename "$0") -sj --no-file sbom.cdx.json

DEPENDENCIES:
    jq

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
#   checksum-verify.sh, license-check.sh, provenance-verify.sh,
#   sbom-compare.sh, sbom-discover.sh, sbom-gen.sh, sbom-toolkit.sh, slsa-attest.sh
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

# ── Functions: True Levenshtein distance ──────────────────────────────────────
#
# Wagner-Fischer dynamic programming algorithm.
# Time: O(m*n) where m,n are string lengths.
# Correctly handles: insertions, deletions, substitutions, transpositions
# (transpositions count as 2 ops: delete + insert).
#
# Both inputs are lowercased before comparison.
#
# For packages of very different lengths the early-exit based on length
# difference avoids running the full DP matrix when impossible to be within
# the threshold, keeping performance acceptable on large SBOMs.
#
levenshtein() {
    local s="${1,,}"   # lowercase
    local t="${2,,}"   # lowercase
    local m=${#s}
    local n=${#t}

    # Trivial cases
    [[ "$s" == "$t" ]] && echo 0 && return
    [[ $m -eq 0 ]]     && echo "$n" && return
    [[ $n -eq 0 ]]     && echo "$m" && return

    # Early exit: length difference alone exceeds threshold
    local diff=$(( m > n ? m - n : n - m ))
    if [[ $diff -gt $TYPOSQUAT_MAX_DIST ]]; then
        echo $(( TYPOSQUAT_MAX_DIST + 1 ))
        return
    fi

    # Build DP matrix as a flat bash array (row-major)
    # prev[j] = edit distance between s[0..i-1] and t[0..j-1]
    local -a prev curr
    local i j
    for (( j=0; j<=n; j++ )); do prev[j]=$j; done

    for (( i=1; i<=m; i++ )); do
        curr[0]=$i
        for (( j=1; j<=n; j++ )); do
            local sc
            if [[ "${s:i-1:1}" == "${t:j-1:1}" ]]; then
                sc=0
            else
                sc=1
            fi
            local del=$(( prev[j] + 1 ))
            local ins=$(( curr[j-1] + 1 ))
            local sub=$(( prev[j-1] + sc ))
            # min of three
            local min=$del
            (( ins < min )) && min=$ins
            (( sub < min )) && min=$sub
            curr[j]=$min
        done
        # Copy curr → prev for next iteration
        for (( j=0; j<=n; j++ )); do prev[j]=${curr[j]}; done
    done

    echo "${prev[n]}"
}

# ── Popular package reference list ───────────────────────────────────────────
# Keyed by normalised lowercase name. Value is the canonical name (for
# reporting). Covers top packages by download count across npm, PyPI,
# Composer, and Maven. Update periodically.

declare -A POPULAR_PACKAGES

# npm (top ~40 by weekly downloads)
POPULAR_PACKAGES["react"]="react"
POPULAR_PACKAGES["vue"]="vue"
POPULAR_PACKAGES["angular"]="angular"
POPULAR_PACKAGES["express"]="express"
POPULAR_PACKAGES["lodash"]="lodash"
POPULAR_PACKAGES["axios"]="axios"
POPULAR_PACKAGES["webpack"]="webpack"
POPULAR_PACKAGES["babel"]="babel"
POPULAR_PACKAGES["typescript"]="typescript"
POPULAR_PACKAGES["jest"]="jest"
POPULAR_PACKAGES["eslint"]="eslint"
POPULAR_PACKAGES["prettier"]="prettier"
POPULAR_PACKAGES["moment"]="moment"
POPULAR_PACKAGES["jquery"]="jquery"
POPULAR_PACKAGES["bootstrap"]="bootstrap"
POPULAR_PACKAGES["next"]="next"
POPULAR_PACKAGES["nuxt"]="nuxt"
POPULAR_PACKAGES["vite"]="vite"
POPULAR_PACKAGES["rollup"]="rollup"
POPULAR_PACKAGES["chalk"]="chalk"
POPULAR_PACKAGES["commander"]="commander"
POPULAR_PACKAGES["yargs"]="yargs"
POPULAR_PACKAGES["dotenv"]="dotenv"
POPULAR_PACKAGES["cors"]="cors"

# PyPI (top ~30 by monthly downloads)
POPULAR_PACKAGES["requests"]="requests"
POPULAR_PACKAGES["numpy"]="numpy"
POPULAR_PACKAGES["pandas"]="pandas"
POPULAR_PACKAGES["django"]="django"
POPULAR_PACKAGES["flask"]="flask"
POPULAR_PACKAGES["pytest"]="pytest"
POPULAR_PACKAGES["setuptools"]="setuptools"
POPULAR_PACKAGES["boto3"]="boto3"
POPULAR_PACKAGES["sqlalchemy"]="sqlalchemy"
POPULAR_PACKAGES["pillow"]="pillow"
POPULAR_PACKAGES["scipy"]="scipy"
POPULAR_PACKAGES["matplotlib"]="matplotlib"
POPULAR_PACKAGES["urllib3"]="urllib3"
POPULAR_PACKAGES["cryptography"]="cryptography"
POPULAR_PACKAGES["paramiko"]="paramiko"
POPULAR_PACKAGES["celery"]="celery"
POPULAR_PACKAGES["pydantic"]="pydantic"
POPULAR_PACKAGES["fastapi"]="fastapi"
POPULAR_PACKAGES["aiohttp"]="aiohttp"
POPULAR_PACKAGES["tensorflow"]="tensorflow"
POPULAR_PACKAGES["torch"]="torch"
POPULAR_PACKAGES["sklearn"]="sklearn"

# Composer/PHP — unscoped names only (vendor-only entries moved to POPULAR_COMPOSER below)
POPULAR_PACKAGES["phpunit"]="phpunit"
POPULAR_PACKAGES["twig"]="twig"
POPULAR_PACKAGES["carbon"]="carbon"
POPULAR_PACKAGES["predis"]="predis"

# Maven/Java (normalised artifact IDs)
POPULAR_PACKAGES["junit"]="junit"
POPULAR_PACKAGES["slf4j"]="slf4j"
POPULAR_PACKAGES["jackson"]="jackson"
POPULAR_PACKAGES["guava"]="guava"
POPULAR_PACKAGES["hibernate"]="hibernate"
POPULAR_PACKAGES["log4j"]="log4j"
POPULAR_PACKAGES["commons"]="commons"
POPULAR_PACKAGES["mockito"]="mockito"
POPULAR_PACKAGES["spring"]="spring"

# ── Composer namespaced package reference list ───────────────────────────────
# Full "vendor/package" pairs for Composer packages that are high-value typosquat
# targets. Keyed by the full normalised name (lowercased, hyphens/underscores
# stripped from the package portion only — vendor slash is preserved as separator).
# When a Composer package is checked, THREE comparisons run:
#   1. Full "vendor/package" against this table
#   2. Vendor portion against POPULAR_PACKAGES
#   3. Package portion against POPULAR_PACKAGES
# This catches vendor-name substitution, package-name substitution, and full-name
# typosquats — all three attack vectors.

declare -A POPULAR_COMPOSER

POPULAR_COMPOSER["guzzlehttp/guzzle"]="guzzlehttp/guzzle"
POPULAR_COMPOSER["symfony/console"]="symfony/console"
POPULAR_COMPOSER["symfony/httpkernel"]="symfony/http-kernel"
POPULAR_COMPOSER["symfony/routing"]="symfony/routing"
POPULAR_COMPOSER["symfony/finder"]="symfony/finder"
POPULAR_COMPOSER["symfony/process"]="symfony/process"
POPULAR_COMPOSER["laravel/framework"]="laravel/framework"
POPULAR_COMPOSER["doctrine/orm"]="doctrine/orm"
POPULAR_COMPOSER["doctrine/dbal"]="doctrine/dbal"
POPULAR_COMPOSER["doctrine/inflector"]="doctrine/inflector"
POPULAR_COMPOSER["ramsey/uuid"]="ramsey/uuid"
POPULAR_COMPOSER["nesbot/carbon"]="nesbot/carbon"
POPULAR_COMPOSER["monolog/monolog"]="monolog/monolog"
POPULAR_COMPOSER["league/flysystem"]="league/flysystem"
POPULAR_COMPOSER["league/csv"]="league/csv"
POPULAR_COMPOSER["spatie/laravelpermission"]="spatie/laravel-permission"
POPULAR_COMPOSER["spatie/laravelmedialibrary"]="spatie/laravel-media-library"
POPULAR_COMPOSER["psr/log"]="psr/log"
POPULAR_COMPOSER["psr/container"]="psr/container"
POPULAR_COMPOSER["psr/httpclient"]="psr/http-client"
POPULAR_COMPOSER["psr/httpmessage"]="psr/http-message"
POPULAR_COMPOSER["intervention/image"]="intervention/image"
POPULAR_COMPOSER["vlucas/phpdotenv"]="vlucas/phpdotenv"
POPULAR_COMPOSER["phpunit/phpunit"]="phpunit/phpunit"

# ── Functions: Detection ──────────────────────────────────────────────────────

# normalise_pkg NAME
# Produces a normalised token suitable for Levenshtein comparison:
#   - lowercased
#   - @scope/ prefix stripped (npm)
#   - vendor/ prefix stripped (Composer) — caller handles full-name check separately
#   - hyphens and underscores removed (treat as equivalent)
normalise_pkg() {
    local name="${1,,}"
    name="${name#@*/}"                        # strip @scope/
    name=$(echo "$name" | sed 's|.*/||')      # strip vendor/
    name=$(echo "$name" | tr -d '_-')         # treat - and _ as equivalent
    echo "$name"
}

# normalise_composer_full VENDOR/PACKAGE
# Normalises only the package portion (vendor retained) for full-name table lookup.
normalise_composer_full() {
    local full="${1,,}"
    local vendor="${full%%/*}"
    local pkg
    pkg=$(echo "${full#*/}" | tr -d '_-')
    echo "${vendor}/${pkg}"
}

# check_typosquat PKG_NAME
# Returns "<canonical>|<distance>" on match; empty + exit 1 on no match.
#
# For namespaced packages (containing /) three checks run:
#   1. Full normalised "vendor/pkg" against POPULAR_COMPOSER
#   2. Vendor portion against POPULAR_PACKAGES
#   3. Package portion against POPULAR_PACKAGES
# This catches vendor-name substitution, package-name substitution, and
# full-name typosquats — all three Composer attack vectors.
check_typosquat() {
    local pkg_name="$1"
    local pkg_norm
    pkg_norm=$(normalise_pkg "$pkg_name")

    # ── Check 1 (Composer only): full "vendor/package" against POPULAR_COMPOSER ──
    if [[ "$pkg_name" == */* ]]; then
        local full_norm
        full_norm=$(normalise_composer_full "$pkg_name")
        local cpop cdist
        for cpop in "${!POPULAR_COMPOSER[@]}"; do
            local canonical="${POPULAR_COMPOSER[$cpop]}"

            # Exact full-name match → this IS the popular package, not a typosquat
            [[ "$full_norm" == "$cpop" ]] && return 1

            # Length filter on the full normalised string
            local plen=${#full_norm} clen=${#cpop}
            local ldiff=$(( plen > clen ? plen - clen : clen - plen ))
            [[ $ldiff -gt $TYPOSQUAT_MAX_DIST ]] && continue

            cdist=$(levenshtein "$full_norm" "$cpop")
            if [[ $cdist -le $TYPOSQUAT_MAX_DIST ]] && [[ $cdist -gt 0 ]]; then
                echo "${canonical}|${cdist}"
                return 0
            fi
        done

        # ── Check 2: vendor portion against POPULAR_PACKAGES ──────────────────
        local vendor_norm
        vendor_norm=$(echo "${pkg_name%%/*}" | tr '[:upper:]' '[:lower:]' | tr -d '_-')
        for popular in "${!POPULAR_PACKAGES[@]}"; do
            local canonical="${POPULAR_PACKAGES[$popular]}"
            [[ "$vendor_norm" == "$popular" ]] && return 1   # exact match → legitimate vendor
            local plen=${#vendor_norm} clen=${#popular}
            local ldiff=$(( plen > clen ? plen - clen : clen - plen ))
            [[ $ldiff -gt $TYPOSQUAT_MAX_DIST ]] && continue
            local vdist
            vdist=$(levenshtein "$vendor_norm" "$popular")
            if [[ $vdist -le $TYPOSQUAT_MAX_DIST ]] && [[ $vdist -gt 0 ]]; then
                echo "${canonical}|${vdist}"
                return 0
            fi
        done
    fi

    # ── Check 3: package portion (or full flat name) against POPULAR_PACKAGES ──
    local popular canonical dist
    for popular in "${!POPULAR_PACKAGES[@]}"; do
        canonical="${POPULAR_PACKAGES[$popular]}"
        [[ "$pkg_norm" == "$popular" ]] && return 1

        local plen=${#pkg_norm} clen=${#popular}
        local ldiff=$(( plen > clen ? plen - clen : clen - plen ))
        [[ $ldiff -gt $TYPOSQUAT_MAX_DIST ]] && continue

        dist=$(levenshtein "$pkg_norm" "$popular")
        if [[ $dist -le $TYPOSQUAT_MAX_DIST ]] && [[ $dist -gt 0 ]]; then
            echo "${canonical}|${dist}"
            return 0
        fi
    done
    return 1
}

check_confusion() {
    local pkg_name="$1"

    # Scoped npm packages with internal-looking scope names
    if [[ "$pkg_name" =~ ^@([a-zA-Z0-9_-]+)/ ]]; then
        local scope="${BASH_REMATCH[1],,}"
        if [[ "$scope" =~ ^(internal|private|corp|company|mycompany|our|team|local|dev|test)$ ]]; then
            echo "internal_scope"
            return 0
        fi
    fi

    # Unscoped names with explicit internal markers
    if echo "${pkg_name,,}" | grep -qE '^(internal|private)-|-(internal|private)$'; then
        echo "internal_name_pattern"
        return 0
    fi

    return 1
}

check_suspicious() {
    local pkg_name="$1" pkg_version="$2"

    # Version number attack patterns
    if [[ "$pkg_version" =~ ^(99\.|999\.|0\.0\.0) ]]; then
        echo "suspicious_version|$pkg_version"
        return 0
    fi

    # Test/demo/temp artifacts that shouldn't be in production SBOMs
    if echo "${pkg_name,,}" | grep -qE '(^|[-_.])(test|demo|example|temp|tmp|placeholder)([-_.]|$)'; then
        echo "test_name_pattern|$pkg_name"
        return 0
    fi

    # Very short names (< 3 chars) — legitimate but worth flagging
    local norm
    norm=$(normalise_pkg "$pkg_name")
    if [[ ${#norm} -lt 3 ]] && [[ ${#norm} -gt 0 ]]; then
        echo "very_short_name|${#norm}"
        return 0
    fi

    # Purely numeric names
    if [[ "$pkg_name" =~ ^[0-9]+$ ]]; then
        echo "numeric_name|$pkg_name"
        return 0
    fi

    return 1
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
        --skip-typosquat)  CHECK_TYPOSQUAT=false; shift ;;
        --skip-confusion)  CHECK_CONFUSION=false; shift ;;
        --skip-suspicious) CHECK_SUSPICIOUS=false; shift ;;
        --max-distance)
            [[ -z "${2:-}" ]] && die "--max-distance requires an argument"
            TYPOSQUAT_MAX_DIST="$2"
            [[ "$TYPOSQUAT_MAX_DIST" =~ ^[1-3]$ ]] \
                || die "--max-distance must be 1, 2, or 3"
            shift 2 ;;
        --version)
            echo "dependency-audit.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  SBOM_FILE="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$SBOM_FILE" ]]   && die "No SBOM file specified (use --help for usage)"
[[ ! -f "$SBOM_FILE" ]] && die "File not found: $SBOM_FILE"
command -v jq &>/dev/null || die "jq is required"
jq empty "$SBOM_FILE" 2>/dev/null || die "Invalid JSON in SBOM file: $SBOM_FILE"

CLEAN_NAME=$(sanitize_name "$SBOM_FILE")
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.deps-audit.json"

log "[AUDIT] Supply chain audit: $(basename "$SBOM_FILE")"

# ── SBOM package extraction ───────────────────────────────────────────────────
# Output: lines of "name|version|type"

extract_packages() {
    local file="$1"

    # Try SPDX first, then CycloneDX
    local spdx_out
    spdx_out=$(jq -r '
        .packages[]?
        | [ .name,
            (.versionInfo // "unknown"),
            (.packageType // .primaryPackagePurpose // "unknown") ]
        | join("|")
    ' "$file" 2>/dev/null || echo "")

    if [[ -n "$spdx_out" ]]; then
        echo "$spdx_out"
        return
    fi

    jq -r '
        .components[]?
        | [ .name,
            (.version // "unknown"),
            (.type // "unknown") ]
        | join("|")
    ' "$file" 2>/dev/null || true
}

# ── Main audit loop ───────────────────────────────────────────────────────────

TYPOSQUAT_COUNT=0
CONFUSION_COUNT=0
SUSPICIOUS_COUNT=0
FINDINGS_ARR=()

while IFS='|' read -r pkg_name pkg_version pkg_type; do
    [[ -z "$pkg_name" ]] && continue

    info "Checking: $pkg_name $pkg_version"

    # ── Typosquatting ────────────────────────────────────────────────────────
    if [[ "$CHECK_TYPOSQUAT" == "true" ]]; then
        local_result=""
        local_result=$(check_typosquat "$pkg_name") || true

        if [[ -n "$local_result" ]]; then
            local_canonical="${local_result%|*}"
            local_dist="${local_result#*|}"
            TYPOSQUAT_COUNT=$((TYPOSQUAT_COUNT+1))
            log "  [WARN] TYPOSQUAT: $pkg_name (distance $local_dist from '$local_canonical')"

            FINDINGS_ARR+=("$(jq -n \
                --arg type       "typosquatting" \
                --arg severity   "HIGH" \
                --arg pkg        "$pkg_name" \
                --arg version    "$pkg_version" \
                --arg ecosystem  "$pkg_type" \
                --arg similar_to "$local_canonical" \
                --arg method     "levenshtein" \
                --argjson dist   "$local_dist" \
                '{type:$type, severity:$severity,
                  package:$pkg, version:$version, ecosystem:$ecosystem,
                  similar_to:$similar_to,
                  detection:{method:$method, distance:$dist}}')")
        fi
    fi

    # ── Dependency confusion ─────────────────────────────────────────────────
    if [[ "$CHECK_CONFUSION" == "true" ]]; then
        local_result=""
        local_result=$(check_confusion "$pkg_name") || true

        if [[ -n "$local_result" ]]; then
            CONFUSION_COUNT=$((CONFUSION_COUNT+1))
            log "  [CRIT] CONFUSION: $pkg_name ($local_result)"

            FINDINGS_ARR+=("$(jq -n \
                --arg type      "dependency_confusion" \
                --arg severity  "CRITICAL" \
                --arg pkg       "$pkg_name" \
                --arg version   "$pkg_version" \
                --arg ecosystem "$pkg_type" \
                --arg pattern   "$local_result" \
                '{type:$type, severity:$severity,
                  package:$pkg, version:$version, ecosystem:$ecosystem,
                  reason:"Internal/private scope or name pattern found in SBOM",
                  pattern:$pattern}')")
        fi
    fi

    # ── Suspicious patterns ───────────────────────────────────────────────────
    if [[ "$CHECK_SUSPICIOUS" == "true" ]]; then
        local_result=""
        local_result=$(check_suspicious "$pkg_name" "$pkg_version") || true

        if [[ -n "$local_result" ]]; then
            local_pattern="${local_result%|*}"
            local_detail="${local_result#*|}"
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT+1))
            log "  [WARN] SUSPICIOUS: $pkg_name ($local_pattern: $local_detail)"

            FINDINGS_ARR+=("$(jq -n \
                --arg type      "suspicious_package" \
                --arg severity  "MEDIUM" \
                --arg pkg       "$pkg_name" \
                --arg version   "$pkg_version" \
                --arg ecosystem "$pkg_type" \
                --arg pattern   "$local_pattern" \
                --arg detail    "$local_detail" \
                '{type:$type, severity:$severity,
                  package:$pkg, version:$version, ecosystem:$ecosystem,
                  pattern:$pattern, detail:$detail}')")
        fi
    fi

done < <(extract_packages "$SBOM_FILE")

# ── Risk score ────────────────────────────────────────────────────────────────

TOTAL_ISSUES=$((TYPOSQUAT_COUNT + CONFUSION_COUNT + SUSPICIOUS_COUNT))
RISK_SCORE=$(( \
    CONFUSION_COUNT  * 500 + \
    TYPOSQUAT_COUNT  * 400 + \
    SUSPICIOUS_COUNT * 100 ))

# ── Progress summary ──────────────────────────────────────────────────────────

log "[AUDIT] Results:"
log "        Typosquatting:        $TYPOSQUAT_COUNT"
log "        Dependency confusion: $CONFUSION_COUNT"
log "        Suspicious patterns:  $SUSPICIOUS_COUNT"
log "        Total issues:         $TOTAL_ISSUES"
log "        Risk contribution:    $RISK_SCORE"

# ── Build JSON output ─────────────────────────────────────────────────────────

FINDINGS_JSON=$(printf '%s\n' "${FINDINGS_ARR[@]+"${FINDINGS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  timestamp        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_ver      "$TOOLKIT_VERSION" \
    --arg  sbom_file        "$(basename "$SBOM_FILE")" \
    --argjson typosquat     "$TYPOSQUAT_COUNT" \
    --argjson confusion     "$CONFUSION_COUNT" \
    --argjson suspicious    "$SUSPICIOUS_COUNT" \
    --argjson total         "$TOTAL_ISSUES" \
    --argjson risk          "$RISK_SCORE" \
    --argjson chk_typo      "$CHECK_TYPOSQUAT" \
    --argjson chk_conf      "$CHECK_CONFUSION" \
    --argjson chk_susp      "$CHECK_SUSPICIOUS" \
    --argjson max_dist      "$TYPOSQUAT_MAX_DIST" \
    --argjson findings      "$FINDINGS_JSON" \
    '{
        dependency_audit: {
            timestamp:       $timestamp,
            toolkit_version: $toolkit_ver,
            sbom_source:     $sbom_file,
            scan_status:     (if $total == 0 then "clean" else "issues_found" end),
            findings_count:  $total,
            findings_note:   (if $total == 0 then
                                "No typosquatting, dependency confusion, or suspicious patterns detected in scanned packages"
                              else
                                "\($total) issue(s) found — review findings array"
                              end),
            summary: {
                typosquatting:        $typosquat,
                dependency_confusion: $confusion,
                suspicious_packages:  $suspicious,
                total_issues:         $total
            },
            checks_performed: {
                typosquatting:        $chk_typo,
                dependency_confusion: $chk_conf,
                suspicious_patterns:  $chk_susp,
                typosquat_max_distance: $max_dist,
                typosquat_method:     "levenshtein_wagner_fischer"
            },
            risk_contribution: $risk,
            findings: $findings
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

[[ $TOTAL_ISSUES -gt 0 ]] && exit 1 || exit 0
