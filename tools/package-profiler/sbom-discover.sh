#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# sbom-discover.sh - locate embedded SBOMs and package manifests
#
# Usage: sbom-discover.sh [OPTIONS] <target>
#
# Searches a directory or archive for SBOM files (SPDX, CycloneDX) and
# package manifests (composer.lock, package.json, requirements.txt, etc.)
# without requiring full extraction. Validates found SBOMs structurally.
#
# Output file: ./meta/<clean-name>/<clean-name>.discover.json
#
# Exit codes:
#   0  At least one valid SBOM found
#   1  No SBOM found (manifests may have been found)
#   2  Execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

TARGET=""
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false

# Maximum depth for directory searches
MAX_DEPTH=8

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/sbom_discover_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Search a directory or archive for SBOM files and package manifests.
Validates found SBOMs structurally without re-generating them.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show per-file detail
    -o, --output-dir DIR    Directory for output file
                            (default: ./meta/<clean-name>/)
    --meta-base DIR         Base directory for meta output (default: ./meta)
    --no-file               Output JSON to stdout only; do not write file
    --max-depth N           Maximum directory search depth (default: 8)
    --version               Print version and exit

ARGUMENTS:
    target                  Directory to search, or archive file
                            (.zip, .tar.gz, .tgz, .tar.bz2) to inspect
                            without full extraction

OUTPUT FILE:
    ./meta/<clean-name>/<clean-name>.discover.json

SBOM FORMATS DETECTED:
    SPDX        Files named *.spdx.json or containing "spdxVersion"
    CycloneDX   Files named *.cdx.json or containing "bomFormat":"CycloneDX"

MANIFESTS DETECTED:
    composer.json / composer.lock    PHP/Composer
    package.json / package-lock.json npm/Node.js
    yarn.lock                        Yarn
    requirements.txt / Pipfile.lock  Python/pip
    Gemfile / Gemfile.lock           Ruby/Bundler
    go.mod / go.sum                  Go modules
    pom.xml / build.gradle           Maven/Gradle
    Cargo.toml / Cargo.lock          Rust/Cargo
    *.podspec / Podfile.lock         CocoaPods

VALIDATION:
    Each SBOM found is validated for:
      - Valid JSON
      - Required structural markers (spdxVersion or bomFormat)
      - Component/package count
      - Tool metadata (if present)
      - SBOM creation timestamp (if present)
    Invalid SBOMs are listed separately from valid ones.

EXIT CODES:
    0    At least one valid SBOM found
    1    No valid SBOM found (manifests may still have been found)
    2    Execution error

EXAMPLES:
    # Search a directory
    $(basename "$0") ./extracted-plugin/

    # Inspect an archive without extracting
    $(basename "$0") akismet.5.3.zip

    # Search with increased depth
    $(basename "$0") --max-depth 12 ./large-project/

    # Pipe-friendly: JSON to stdout only
    $(basename "$0") -sj --no-file ./plugin/

DEPENDENCIES:
    jq
    unzip  (for .zip archive inspection)
    tar    (for .tar.gz/.tgz/.tar.bz2 inspection)

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

# ── Functions: Path priority sorting ─────────────────────────────────────────
# Sorts a list of file paths by:
#   1. Shallower depth first (fewer path components)
#   2. Within same depth: SBOM files before manifests, named *.spdx.json and
#      *.cdx.json before generic names
# Input: newline-separated paths on stdin
# Output: sorted paths on stdout

sort_by_depth_and_priority() {
    awk '
    {
        path = $0
        # Count path depth by number of / separators
        depth = gsub("/", "/", path)
        # Assign priority score (lower = higher priority)
        priority = 50
        if (path ~ /\.spdx\.json$/)  priority = 1
        if (path ~ /\.cdx\.json$/)   priority = 2
        if (path ~ /bom\.json$/)     priority = 3
        if (path ~ /sbom\.json$/)    priority = 4
        if (path ~ /\.spdx$/)        priority = 5
        if (path ~ /composer\.lock$/) priority = 10
        if (path ~ /package-lock\.json$/) priority = 11
        if (path ~ /yarn\.lock$/)    priority = 12
        if (path ~ /Pipfile\.lock$/) priority = 13
        if (path ~ /Gemfile\.lock$/) priority = 14
        if (path ~ /go\.sum$/)       priority = 15
        if (path ~ /Cargo\.lock$/)   priority = 16
        printf "%04d %04d %s\n", depth, priority, $0
    }' | sort -n | awk '{$1=$2=""; print substr($0,3)}'
}

# ── Functions: SBOM validation ────────────────────────────────────────────────

# Validate an SBOM from a string of its content.
# Sets globals: VALID_FORMAT, VALID_TOOL, VALID_TIMESTAMP, VALID_COMPONENT_COUNT
# Returns 0 if valid, 1 if not.
validate_sbom_content() {
    local content="$1"

    VALID_FORMAT=""
    VALID_TOOL=""
    VALID_TIMESTAMP=""
    VALID_COMPONENT_COUNT=0

    # Must be valid JSON
    echo "$content" | jq empty 2>/dev/null || return 1

    # Detect format
    if echo "$content" | jq -e '.spdxVersion' &>/dev/null 2>&1; then
        VALID_FORMAT="spdx"
        VALID_COMPONENT_COUNT=$(echo "$content" \
            | jq '.packages | length // 0' 2>/dev/null || echo 0)
        VALID_TOOL=$(echo "$content" \
            | jq -r '.creationInfo.creators[]? | select(startswith("Tool:"))
                     | ltrimstr("Tool: ")' 2>/dev/null \
            | head -n1 || echo "")
        VALID_TIMESTAMP=$(echo "$content" \
            | jq -r '.creationInfo.created // ""' 2>/dev/null || echo "")

    elif echo "$content" | jq -e '.bomFormat == "CycloneDX"' &>/dev/null 2>&1; then
        VALID_FORMAT="cyclonedx"
        VALID_COMPONENT_COUNT=$(echo "$content" \
            | jq '.components | length // 0' 2>/dev/null || echo 0)
        VALID_TOOL=$(echo "$content" \
            | jq -r '.metadata.tools.components[0]?.name //
                     .metadata.tools[0]?.name // ""' 2>/dev/null || echo "")
        VALID_TIMESTAMP=$(echo "$content" \
            | jq -r '.metadata.timestamp // ""' 2>/dev/null || echo "")
    else
        return 1
    fi

    return 0
}

# ── Functions: Archive inspection ─────────────────────────────────────────────

# List all file paths inside an archive
archive_list_files() {
    local archive="$1"
    if [[ "$archive" == *.zip ]]; then
        unzip -l "$archive" 2>/dev/null \
            | awk 'NR>3 && NF>=4 {print $NF}' \
            | grep -v '/$' || true
    else
        # tar -tf auto-detects compression (.gz, .bz2, .xz, .zst, plain, etc.)
        tar -tf "$archive" 2>/dev/null \
            | grep -v '/$' || true
    fi
}

# Read a single file from an archive without extracting
archive_read_file() {
    local archive="$1" inner_path="$2"
    if [[ "$archive" == *.zip ]]; then
        unzip -p "$archive" "$inner_path" 2>/dev/null || true
    else
        # tar -xf auto-detects compression
        tar -xf "$archive" -O "$inner_path" 2>/dev/null || true
    fi
}

# ── Functions: Manifest classification ───────────────────────────────────────

classify_manifest() {
    local filename="$1"
    local base
    base=$(basename "$filename")
    case "$base" in
        composer.json)        echo "composer_metadata" ;;
        composer.lock)        echo "composer_lockfile" ;;
        package.json)         echo "npm_metadata" ;;
        package-lock.json)    echo "npm_lockfile" ;;
        yarn.lock)            echo "yarn_lockfile" ;;
        requirements.txt)     echo "pip_requirements" ;;
        Pipfile)              echo "pipenv_metadata" ;;
        Pipfile.lock)         echo "pipenv_lockfile" ;;
        Gemfile)              echo "bundler_metadata" ;;
        Gemfile.lock)         echo "bundler_lockfile" ;;
        go.mod)               echo "go_modules_metadata" ;;
        go.sum)               echo "go_modules_lockfile" ;;
        pom.xml)              echo "maven_pom" ;;
        build.gradle)         echo "gradle_build" ;;
        Cargo.toml)           echo "cargo_metadata" ;;
        Cargo.lock)           echo "cargo_lockfile" ;;
        Podfile)              echo "cocoapods_metadata" ;;
        Podfile.lock)         echo "cocoapods_lockfile" ;;
        *.podspec)            echo "cocoapods_podspec" ;;
        *)                    echo "unknown_manifest" ;;
    esac
}

is_sbom_candidate() {
    local path="$1"
    local base
    base=$(basename "$path")
    case "$base" in
        *.spdx.json|*.cdx.json|bom.json|sbom.json|*.bom.json) return 0 ;;
        *.spdx) return 0 ;;
        *)
            # Check for SBOM-like names
            echo "$base" | grep -qi 'sbom\|bom\|spdx\|cyclonedx' && return 0
            return 1 ;;
    esac
}

is_manifest_candidate() {
    local path="$1"
    local base
    base=$(basename "$path")
    case "$base" in
        composer.json|composer.lock|\
        package.json|package-lock.json|yarn.lock|\
        requirements.txt|Pipfile|Pipfile.lock|\
        Gemfile|Gemfile.lock|\
        go.mod|go.sum|\
        pom.xml|build.gradle|\
        Cargo.toml|Cargo.lock|\
        Podfile|Podfile.lock|\
        *.podspec)
            return 0 ;;
        *)  return 1 ;;
    esac
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
        --max-depth)
            [[ -z "${2:-}" ]] && die "--max-depth requires an argument"
            MAX_DEPTH="$2"
            [[ "$MAX_DEPTH" =~ ^[0-9]+$ ]] || die "--max-depth must be a positive integer"
            shift 2 ;;
        --version)
            echo "sbom-discover.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$TARGET" ]]    && die "No target specified (use --help for usage)"
[[ ! -e "$TARGET" ]]  && die "Target not found: $TARGET"
command -v jq &>/dev/null || die "jq is required"

CLEAN_NAME=$(sanitize_name "$TARGET")
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.discover.json"

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

log "[DISC] Discovering SBOMs and manifests in: $(basename "$TARGET")"
[[ "$IS_ARCHIVE" == "true" ]] && log "       Mode: archive inspection (no extraction)"

# ── Collect candidate paths ───────────────────────────────────────────────────

CANDIDATE_SBOMS=()
CANDIDATE_MANIFESTS=()

if [[ "$IS_ARCHIVE" == "true" ]]; then
    # ── Archive mode: list contents, filter candidates ───────────────────────
    command -v unzip &>/dev/null || [[ "$TARGET" != *.zip ]] \
        || die "unzip is required to inspect .zip archives"

    while IFS= read -r fpath; do
        [[ -z "$fpath" ]] && continue
        if   is_sbom_candidate "$fpath";     then CANDIDATE_SBOMS+=("$fpath")
        elif is_manifest_candidate "$fpath"; then CANDIDATE_MANIFESTS+=("$fpath")
        fi
    done < <(archive_list_files "$TARGET" | sort_by_depth_and_priority)

else
    # ── Directory mode: find candidates up to MAX_DEPTH ──────────────────────
    [[ -d "$TARGET" ]] || die "Target is not a directory or recognised archive: $TARGET"

    # Resolve target to an absolute path so we can strip it from found paths
    TARGET_ABS="$(cd "$TARGET" && pwd -P)"

    while IFS= read -r fpath; do
        [[ -z "$fpath" ]] && continue
        # Make path relative to target directory (for display/output)
        local_rel="${fpath#"${TARGET_ABS}/"}"
        local_base=$(basename "$fpath")
        if   is_sbom_candidate "$local_base";     then CANDIDATE_SBOMS+=("$fpath")
        elif is_manifest_candidate "$local_base"; then CANDIDATE_MANIFESTS+=("$fpath")
        fi
    done < <(find "$TARGET_ABS" -maxdepth "$MAX_DEPTH" -type f \
        2>/dev/null | sort_by_depth_and_priority)
fi

info "SBOM candidates found:     ${#CANDIDATE_SBOMS[@]}"
info "Manifest candidates found: ${#CANDIDATE_MANIFESTS[@]}"

# ── Validate SBOM candidates ──────────────────────────────────────────────────

VALID_SBOMS_ARR=()
INVALID_SBOMS_ARR=()

for candidate in "${CANDIDATE_SBOMS[@]+"${CANDIDATE_SBOMS[@]}"}"; do
    # Display/output path: relative to target (strip absolute prefix for directory scans)
    local_display="${candidate#"${TARGET_ABS:-}/"}"; local_display="${local_display#"${TARGET:-}/"}"
    info "Validating: $local_display"

    local_content=""
    if [[ "$IS_ARCHIVE" == "true" ]]; then
        local_content=$(archive_read_file "$TARGET" "$candidate")
    else
        local_content=$(cat "$candidate" 2>/dev/null || true)
    fi

    [[ -z "$local_content" ]] && {
        info "  SKIP: empty or unreadable"
        INVALID_SBOMS_ARR+=("$(jq -n \
            --arg path   "$local_display" \
            --arg reason "empty or unreadable" \
            '{path:$path, valid:false, reason:$reason}')")
        continue
    }

    VALID_FORMAT="" VALID_TOOL="" VALID_TIMESTAMP="" VALID_COMPONENT_COUNT=0
    if validate_sbom_content "$local_content"; then
        log "  [OK]   $local_display ($VALID_FORMAT, $VALID_COMPONENT_COUNT components)"

        VALID_SBOMS_ARR+=("$(jq -n \
            --arg path       "$local_display" \
            --arg format     "$VALID_FORMAT" \
            --arg tool       "$VALID_TOOL" \
            --arg timestamp  "$VALID_TIMESTAMP" \
            --argjson count  "$VALID_COMPONENT_COUNT" \
            '{path:$path, valid:true,
              format:$format, tool:$tool,
              timestamp:$timestamp,
              component_count:$count}')")
    else
        log "  [WARN] $local_display — not a valid SBOM (valid JSON but no SPDX/CycloneDX markers)"

        INVALID_SBOMS_ARR+=("$(jq -n \
            --arg path   "$local_display" \
            --arg reason "valid JSON but missing spdxVersion or bomFormat" \
            '{path:$path, valid:false, reason:$reason}')")
    fi
done

# ── Build manifest list ───────────────────────────────────────────────────────

MANIFESTS_ARR=()
for mpath in "${CANDIDATE_MANIFESTS[@]+"${CANDIDATE_MANIFESTS[@]}"}"; do
    local_display="${mpath#"${TARGET_ABS:-}/"}"; local_display="${local_display#"${TARGET:-}/"}"
    local_type=$(classify_manifest "$mpath")
    info "Manifest: $local_display ($local_type)"
    MANIFESTS_ARR+=("$(jq -n \
        --arg path "$local_display" \
        --arg type "$local_type" \
        '{path:$path, type:$type}')")
done

# ── Summary counts ────────────────────────────────────────────────────────────

VALID_SBOM_COUNT=${#VALID_SBOMS_ARR[@]}
INVALID_SBOM_COUNT=${#INVALID_SBOMS_ARR[@]}
MANIFEST_COUNT=${#MANIFESTS_ARR[@]}

log "[DISC] Results:"
log "       Valid SBOMs:    $VALID_SBOM_COUNT"
log "       Invalid SBOMs:  $INVALID_SBOM_COUNT"
log "       Manifests:      $MANIFEST_COUNT"

# ── Determine status ──────────────────────────────────────────────────────────

if   [[ $VALID_SBOM_COUNT   -gt 0 ]]; then STATUS="sbom_found"
elif [[ $INVALID_SBOM_COUNT -gt 0 ]]; then STATUS="sbom_invalid"
elif [[ $MANIFEST_COUNT     -gt 0 ]]; then STATUS="manifests_only"
else                                        STATUS="nothing_found"
fi

log "       Status: $STATUS"

# ── Build JSON output ─────────────────────────────────────────────────────────

VALID_JSON=$(printf '%s\n' "${VALID_SBOMS_ARR[@]+"${VALID_SBOMS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")
INVALID_JSON=$(printf '%s\n' "${INVALID_SBOMS_ARR[@]+"${INVALID_SBOMS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")
MANIFESTS_JSON=$(printf '%s\n' "${MANIFESTS_ARR[@]+"${MANIFESTS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  status          "$STATUS" \
    --arg  timestamp       "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_ver     "$TOOLKIT_VERSION" \
    --arg  target          "$(basename "$TARGET")" \
    --argjson is_archive   "$IS_ARCHIVE" \
    --argjson valid_count  "$VALID_SBOM_COUNT" \
    --argjson invalid_count "$INVALID_SBOM_COUNT" \
    --argjson manifest_count "$MANIFEST_COUNT" \
    --argjson valid_sboms  "$VALID_JSON" \
    --argjson invalid_sboms "$INVALID_JSON" \
    --argjson manifests    "$MANIFESTS_JSON" \
    '{
        sbom_discovery: {
            status:          $status,
            timestamp:       $timestamp,
            toolkit_version: $toolkit_ver,
            target: {
                name:       $target,
                is_archive: $is_archive
            },
            summary: {
                valid_sboms:    $valid_count,
                invalid_sboms:  $invalid_count,
                manifests:      $manifest_count
            },
            valid_sboms:   $valid_sboms,
            invalid_sboms: $invalid_sboms,
            manifests:     $manifests
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

# Exit 0 = valid SBOM found, 1 = no valid SBOM
[[ $VALID_SBOM_COUNT -gt 0 ]] && exit 0 || exit 1
