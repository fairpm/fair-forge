#!/usr/bin/env bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 SBOM Toolkit Contributors

#
# license-check.sh - SPDX license compliance and GPL compatibility analysis
#
# Usage: license-check.sh [OPTIONS] <sbom_file>
#
# Analyses license declarations in an SPDX or CycloneDX SBOM, categorises
# packages by license type, flags compliance issues, and produces a risk score.
#
# Output file: ./meta/<clean-name>/<clean-name>.license.json
#
# Exit codes: 0 = pass, 1 = compliance issues found, 2 = execution error
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
REQUIRE_GPL_COMPAT=false
FAIL_ON_UNKNOWN=true
ECOSYSTEM=""                # wordpress | packagist | npm | pypi | github | file

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/license_check_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <sbom_file>

Analyse license declarations in an SPDX or CycloneDX SBOM.
Categorises packages, checks GPL compatibility, and scores compliance risk.

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
    --require-gpl-compat    Exit 1 when any license is not GPL-compatible.
                            Permissive, weak copyleft, and strong copyleft
                            (GPL itself) are all GPL-compatible. Proprietary,
                            SSPL, and unknown licenses are not.
                            Use this for WordPress plugins and any ecosystem
                            where GPL compatibility of all dependencies is
                            required by the distribution license.
    --allow-unknown         Do not fail on unrecognised license identifiers
    --ecosystem TYPE        Ecosystem context for license defaults and policy:
                            wordpress | typo3 | drupal | packagist | npm | pypi | github | file
                            Ecosystems with a GPL hosting policy apply GPL-2.0-or-later
                            as the assumed root license when none is declared:
                              wordpress   WordPress.org plugin/theme repository
                              typo3       TYPO3 Extension Repository (TER)
                              drupal      Drupal.org module/theme repository
                            All three require extensions/plugins to be GPL-2.0-or-later
                            compatible. Other ecosystems leave root license unknown
                            if not declared in the SBOM.
    --version               Print version and exit

ARGUMENTS:
    sbom_file               SPDX or CycloneDX SBOM JSON file

OUTPUT FILE:
    ./meta/<clean-name>/<clean-name>.license.json

LICENSE CATEGORIES:
    Permissive      MIT, BSD-*, Apache-2.0, ISC, Unlicense, 0BSD, etc.
                    GPL-compatible; generally safe for any use.

    Weak Copyleft   LGPL-*, MPL-2.0, EPL-*, CDDL-1.0, CPL-1.0
                    GPL-compatible with conditions; review linking/usage.

    Strong Copyleft GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0
                    Requires source disclosure; legal review recommended.

    Proprietary     Commercial, All Rights Reserved, Proprietary
                    Incompatible with open-source distribution; verify rights.

    Unknown         NOASSERTION, NONE, empty, or unrecognised SPDX identifier
                    Requires investigation before distribution.

RISK SCORING (contribution to toolkit total):
    Strong copyleft:  +200 per package
    Proprietary:      +150 per package
    Unknown:          +25  per package
    (Permissive and weak copyleft contribute 0)

GPL COMPATIBILITY:
    Reports true when all licenses are permissive, weak copyleft, or strong
    copyleft (GPL-family licenses are themselves GPL-compatible). Reports false
    when any license is proprietary, SSPL-1.0, or unknown.
    Use --require-gpl-compat to enforce this as a hard failure — appropriate
    for WordPress plugins (GPL 2.0+) and any project where the distribution
    license requires all dependencies to be GPL-compatible.

    Bidirectional check (always-on):
    The root package license is extracted from the SBOM and checked against
    all dependency licenses in both directions:
      - GPL root + proprietary/incompatible dep    → dep cannot be distributed
      - Proprietary root + strong copyleft dep      → dep requires GPL disclosure
      - Any root + gpl_incompatible dep             → always flagged
      - GPL root + unknown dep                      → warning (cannot confirm compat)

    Ecosystem defaults for missing root license:
      wordpress   GPL-2.0-or-later assumed (WordPress.org hosting policy)
      others      root_license_unknown warning; bidirectional check skipped

SBOM FORMAT SUPPORT:
    SPDX:       reads .packages[].licenseConcluded / .licenseDeclared
    CycloneDX:  reads .components[].licenses[].expression / .id

EXAMPLES:
    # Standard compliance check
    $(basename "$0") sbom-myplugin.spdx.json

    # Strict: fail on GPL and unknowns
    $(basename "$0") --fail-gpl sbom-myplugin.spdx.json

    # Lenient: allow unknown licenses (e.g. internal/bespoke packages)
    $(basename "$0") --allow-unknown sbom-myplugin.spdx.json

    # JSON output to stdout, no file written
    $(basename "$0") -sj --no-file sbom.cdx.json

    # Custom output directory
    $(basename "$0") -o ./meta/myplugin sbom.spdx.json

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
#   checksum-verify.sh, dependency-audit.sh, provenance-verify.sh,
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

# ── License classification tables ────────────────────────────────────────────
# SPDX identifiers. Keys are exact SPDX IDs; value is "true" (unused but
# required for bash associative array syntax).
# Update periodically as new SPDX identifiers are registered.

declare -A PERMISSIVE=(
    ["MIT"]="true"          ["MIT-0"]="true"           ["MIT-License"]="true"
    ["BSD-2-Clause"]="true" ["BSD-3-Clause"]="true"    ["BSD-4-Clause"]="true"
    ["BSD-2-Clause-Patent"]="true" ["BSD"]="true"      ["BSD-Style"]="true"
    ["Apache-2.0"]="true"   ["Apache-1.1"]="true"      ["Apache-1.0"]="true"
    ["ISC"]="true"          ["Unlicense"]="true"        ["0BSD"]="true"
    ["Python-2.0"]="true"   ["PSF-2.0"]="true"         ["PSF"]="true"
    ["Zlib"]="true"         ["zlib"]="true"             ["BSL-1.0"]="true"
    ["W3C"]="true"          ["X11"]="true"              ["WTFPL"]="true"
    ["CC0-1.0"]="true"      ["Artistic-2.0"]="true"
    ["PHP-3.0"]="true"      ["PHP-3.01"]="true"
    ["PostgreSQL"]="true"   ["Ruby"]="true"
    ["curl"]="true"         ["Libpng"]="true"           ["libpng"]="true"
    ["CC-BY-4.0"]="true"    ["CC-BY-3.0"]="true"
    ["FTL"]="true"          ["Beerware"]="true"         ["HPND"]="true"
    ["NTP"]="true"          ["Naumen"]="true"
)

declare -A WEAK_COPYLEFT=(
    ["LGPL-2.0"]="true"         ["LGPL-2.1"]="true"         ["LGPL-3.0"]="true"
    ["LGPL-2.0-only"]="true"    ["LGPL-2.1-only"]="true"    ["LGPL-3.0-only"]="true"
    ["LGPL-2.0-or-later"]="true" ["LGPL-2.1-or-later"]="true" ["LGPL-3.0-or-later"]="true"
    ["LGPL-2.0+"]="true"        ["LGPL-2.1+"]="true"        ["LGPL-3.0+"]="true"
    ["MPL-2.0"]="true"          ["MPL-1.1"]="true"          ["MPL-1.0"]="true"
    ["EPL-1.0"]="true"          ["EPL-2.0"]="true"
    ["CDDL-1.0"]="true"         ["CPL-1.0"]="true"
    ["EUPL-1.1"]="true"         ["EUPL-1.2"]="true"
    ["OSL-3.0"]="true"          ["OSL-2.0"]="true"          ["OSL-2.1"]="true"
    ["CPAL-1.0"]="true"         ["CECILL-2.1"]="true"
    ["CC-BY-SA-4.0"]="true"     ["CC-BY-SA-3.0"]="true"
)

declare -A STRONG_COPYLEFT=(
    ["GPL-1.0"]="true"          ["GPL-1.0-only"]="true"     ["GPL-1.0-or-later"]="true"
    ["GPL-2.0"]="true"          ["GPL-2.0-only"]="true"     ["GPL-2.0-or-later"]="true"
    ["GPL-2.0+"]="true"         ["GPL-2.0-with-autoconf-exception"]="true"
    ["GPL-3.0"]="true"          ["GPL-3.0-only"]="true"     ["GPL-3.0-or-later"]="true"
    ["GPL-3.0+"]="true"
    ["AGPL-1.0"]="true"         ["AGPL-1.0-only"]="true"    ["AGPL-1.0-or-later"]="true"
    ["AGPL-3.0"]="true"         ["AGPL-3.0-only"]="true"    ["AGPL-3.0-or-later"]="true"
    ["AGPL-3.0+"]="true"
)

# Licenses that are explicitly NOT GPL-compatible.
# These are distinct from strong copyleft — GPL itself is GPL-compatible.
# SSPL-1.0: rejected by OSI; FSF considers it non-free and GPL-incompatible.
# Commons-Clause: a restriction rider that makes the underlying license
#   non-free and incompatible with GPL when applied.
declare -A GPL_INCOMPATIBLE=(
    ["SSPL-1.0"]="true"
    ["Commons-Clause"]="true"
    ["BUSL-1.1"]="true"         # Business Source License — not OSI approved
)

# ── Functions: Classification ─────────────────────────────────────────────────

classify_license() {
    # Returns: permissive | weak_copyleft | strong_copyleft | gpl_incompatible | proprietary | unknown
    # For SPDX OR expressions, appends ":dual" to signal dual_licensed status to callers.
    local lic="$1"

    # Empty / no assertion
    if [[ -z "$lic" ]] || [[ "$lic" == "NOASSERTION" ]] || [[ "$lic" == "NONE" ]]; then
        echo "unknown"; return
    fi

    # Normalise common non-SPDX forms before table lookup:
    # "GPLv2", "GPLv2+", "GPL v2 or later", "GNU GPL v2" → canonical SPDX ID
    local norm_lic="$lic"
    case "$lic" in
        GPLv1*|"GPL v1"*|"GNU GPL v1"*) norm_lic="GPL-1.0-or-later" ;;
        "GPLv2 only"|"GPL-2 only")        norm_lic="GPL-2.0-only" ;;
        GPLv2+|"GPL-2.0+"|"GPL v2+"*|"GPL v2 or later"*|"GPL-2+"*|"GNU GPL-2+"*|"GNU GPLv2+"*) norm_lic="GPL-2.0-or-later" ;;
        GPLv2|"GPL v2"|"GPL-2"|"GNU GPL v2"|"GNU GPLv2") norm_lic="GPL-2.0" ;;
        GPLv3+|"GPL-3.0+"|"GPL v3+"*|"GPL v3 or later"*|"GNU GPLv3+"*) norm_lic="GPL-3.0-or-later" ;;
        GPLv3|"GPL v3"|"GPL-3"|"GNU GPL v3"|"GNU GPLv3") norm_lic="GPL-3.0" ;;
        LGPLv2+|"LGPL-2.1+"|"LGPL v2+"*|"GNU LGPL"*"2+"*) norm_lic="LGPL-2.1-or-later" ;;
        LGPLv2|"LGPL v2"|"LGPL-2"|"GNU LGPL v2") norm_lic="LGPL-2.1" ;;
        LGPLv3+|"LGPL-3.0+"|"GNU LGPL"*"3+"*) norm_lic="LGPL-3.0-or-later" ;;
        LGPLv3|"LGPL v3"|"LGPL-3") norm_lic="LGPL-3.0" ;;
        "Apache 2"|"Apache 2.0"|"Apache License 2.0"|"Apache-2") norm_lic="Apache-2.0" ;;
        "2-Clause BSD"|"BSD 2-Clause"|"BSD-2") norm_lic="BSD-2-Clause" ;;
        "3-Clause BSD"|"BSD 3-Clause"|"BSD-3") norm_lic="BSD-3-Clause" ;;
    esac
    [[ "$norm_lic" != "$lic" ]] && lic="$norm_lic"

    # Exact SPDX table lookups — most specific first
    [[ -n "${PERMISSIVE[$lic]:-}"       ]] && { echo "permissive";        return; }
    [[ -n "${WEAK_COPYLEFT[$lic]:-}"    ]] && { echo "weak_copyleft";     return; }
    [[ -n "${STRONG_COPYLEFT[$lic]:-}"  ]] && { echo "strong_copyleft";   return; }
    [[ -n "${GPL_INCOMPATIBLE[$lic]:-}" ]] && { echo "gpl_incompatible";  return; }

    # Proprietary patterns (case-insensitive substring match)
    if echo "$lic" | grep -qiE '(commercial|proprietary|all.rights.reserved)'; then
        echo "proprietary"; return
    fi

    # SPDX compound expressions — operator semantics differ:
    #   OR  → recipient may CHOOSE either licence; classify by LEAST restrictive.
    #          e.g. "SSPL-1.0 OR MIT" → permissive (choose MIT); mark dual_licensed.
    #   AND → all licences apply simultaneously; classify by MOST restrictive.
    #          e.g. "MIT AND GPL-2.0-only" → strong_copyleft
    #   WITH → base licence + exception; classify by base licence (most restrictive).
    if echo "$lic" | grep -qE '\bOR\b'; then
        local term best="gpl_incompatible"   # start at worst, improve toward permissive
        for term in $(echo "$lic" | tr ' ' '\n' | grep -vE '^(AND|OR|WITH|\()'); do
            local cat
            cat=$(classify_license "$term")
            cat="${cat%%:*}"                 # strip any :dual suffix from recursive call
            case "$cat" in
                permissive)
                    echo "permissive:dual"; return ;;
                weak_copyleft)
                    best="weak_copyleft" ;;
                strong_copyleft)
                    [[ "$best" == "gpl_incompatible" ]] && best="strong_copyleft" ;;
                unknown)
                    [[ "$best" == "gpl_incompatible" ]] && best="unknown" ;;
            esac
        done
        echo "${best}:dual"; return
    fi

    if echo "$lic" | grep -qE '\bAND\b|\bWITH\b'; then
        local term worst="permissive"
        for term in $(echo "$lic" | tr ' ' '\n' | grep -vE '^(AND|OR|WITH|\()'); do
            local cat
            cat=$(classify_license "$term")
            cat="${cat%%:*}"
            case "$cat" in
                proprietary|gpl_incompatible) echo "$cat"; return ;;
                strong_copyleft) worst="strong_copyleft" ;;
                weak_copyleft)
                    [[ "$worst" != "strong_copyleft" ]] && worst="weak_copyleft" ;;
                unknown)
                    [[ "$worst" == "permissive" ]] && worst="unknown" ;;
            esac
        done
        echo "$worst"; return
    fi

    echo "unknown"
}

severity_for_category() {
    case "$1" in
        permissive)        echo "INFO" ;;
        weak_copyleft)     echo "INFO" ;;
        strong_copyleft)   echo "INFO" ;;
        gpl_incompatible)  echo "CRITICAL" ;;
        proprietary)       echo "CRITICAL" ;;
        unknown)           echo "WARNING" ;;
        *)                 echo "WARNING" ;;
    esac
}

reason_for_category() {
    case "$1" in
        permissive)        echo "" ;;
        weak_copyleft)     echo "Weak copyleft — review linking and usage" ;;
        strong_copyleft)   echo "Strong copyleft — source disclosure required; GPL-compatible" ;;
        gpl_incompatible)  echo "Not GPL-compatible — incompatible with GPL-licensed projects" ;;
        proprietary)       echo "Proprietary license — verify usage rights; not GPL-compatible" ;;
        unknown)           echo "Unrecognised or undeclared license — investigation required" ;;
        *)                 echo "Unclassified" ;;
    esac
}

risk_for_category() {
    case "$1" in
        gpl_incompatible) echo 200 ;;
        strong_copyleft)  echo   0 ;;
        proprietary)      echo 150 ;;
        unknown)          echo  25 ;;
        *)                echo   0 ;;
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
        --require-gpl-compat) REQUIRE_GPL_COMPAT=true; shift ;;
        --allow-unknown) FAIL_ON_UNKNOWN=false; shift ;;
        --ecosystem)
            [[ -z "${2:-}" ]] && die "--ecosystem requires an argument"
            ECOSYSTEM="$2"
            [[ "$ECOSYSTEM" =~ ^(wordpress|typo3|drupal|packagist|npm|pypi|github|file)$ ]] \
                || die "Invalid ecosystem. Use: wordpress, typo3, drupal, packagist, npm, pypi, github, file"
            shift 2 ;;
        --version)
            echo "license-check.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
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

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.license.json"

log "[LIC]  Analysing licenses in: $(basename "$SBOM_FILE")"

# ── SBOM format detection ─────────────────────────────────────────────────────

detect_sbom_format() {
    local file="$1"
    if jq -e '.spdxVersion' "$file" &>/dev/null 2>&1; then
        echo "spdx"
    elif jq -e '.bomFormat' "$file" &>/dev/null 2>&1; then
        echo "cyclonedx"
    else
        echo "unknown"
    fi
}

SBOM_FORMAT=$(detect_sbom_format "$SBOM_FILE")
info "Detected SBOM format: $SBOM_FORMAT"

if [[ "$SBOM_FORMAT" == "unknown" ]]; then
    log "  [WARN] Could not determine SBOM format; attempting both parsers"
fi

# ── Extract package/license pairs ────────────────────────────────────────────
# Output: lines of "name|license_expression"
# Handles SPDX (licenseConcluded preferred over licenseDeclared) and
# CycloneDX (licenses[].expression preferred over licenses[].id)

extract_packages() {
    local file="$1" format="$2"
    case "$format" in
        spdx)
            jq -r '
                .packages[]?
                | . as $pkg
                | ($pkg.licenseConcluded // $pkg.licenseDeclared // "NOASSERTION")
                | ltrimstr("(") | rtrimstr(")")
                | [$pkg.name, .] | join("|")
            ' "$file" 2>/dev/null ;;
        cyclonedx)
            jq -r '
                .components[]?
                | . as $cmp
                | (
                    # Prefer expression field; fall back to joining all id fields
                    (if (.licenses | length) > 0 then
                        (.licenses[0]?.expression? // null) //
                        ([.licenses[]? | .license?.id? // .id? // ""] | map(select(. != "")) | join(" OR "))
                     else "NOASSERTION" end)
                  ) | select(. != null and . != "")
                | [$cmp.name, .] | join("|")
            ' "$file" 2>/dev/null ;;
        *)
            # Try SPDX first, fall back to CycloneDX
            local out
            out=$(extract_packages "$file" "spdx")
            [[ -z "$out" ]] && out=$(extract_packages "$file" "cyclonedx")
            echo "$out" ;;
    esac
}

# ── Functions: Root license extraction ───────────────────────────────────────
# Extracts the license of the root/primary package from the SBOM.
# SPDX:      documentDescribes[] → matching package → licenseConcluded
# CycloneDX: metadata.component  → licenses[0]

extract_root_license() {
    local file="$1" format="$2"
    local lic=""

    case "$format" in
        spdx)
            # documentDescribes lists the SPDXID(s) of the root package(s)
            local root_id
            root_id=$(jq -r '.documentDescribes[0] // ""' "$file" 2>/dev/null || echo "")
            if [[ -n "$root_id" ]]; then
                lic=$(jq -r \
                    --arg id "$root_id" \
                    '.packages[]? | select(.SPDXID == $id) |
                     .licenseConcluded // .licenseDeclared // ""' \
                    "$file" 2>/dev/null | head -n1 || echo "")
            fi
            # Fallback: first package in the list
            if [[ -z "$lic" ]] || [[ "$lic" == "NOASSERTION" ]]; then
                lic=$(jq -r \
                    '.packages[0]? |
                     .licenseConcluded // .licenseDeclared // ""' \
                    "$file" 2>/dev/null || echo "")
            fi
            ;;
        cyclonedx)
            lic=$(jq -r \
                '.metadata.component.licenses[0]?.expression //
                 .metadata.component.licenses[0]?.id //
                 ""' \
                "$file" 2>/dev/null || echo "")
            ;;
        *)
            lic=$(extract_root_license "$file" "spdx")
            [[ -z "$lic" ]] && lic=$(extract_root_license "$file" "cyclonedx")
            ;;
    esac

    # Strip NOASSERTION/NONE to empty string for uniform handling downstream
    [[ "$lic" == "NOASSERTION" ]] || [[ "$lic" == "NONE" ]] && lic=""
    echo "$lic"
}

# ── Functions: Bidirectional compatibility check ──────────────────────────────
# Returns an issue JSON string if the dep is incompatible with the root,
# or empty string if compatible. Called once per dependency in the main loop.
#
# Compatibility rules (clear-cut cases only):
#   GPL root    + proprietary dep       → dep cannot be included
#   GPL root    + gpl_incompatible dep  → dep cannot be included
#   GPL root    + unknown dep           → warning (cannot confirm)
#   Proprietary root + strong_copyleft  → copyleft requires disclosure root disallows
#   Any root    + gpl_incompatible dep  → always flagged (regardless of root)
#
# Note: permissive root + strong_copyleft dep is a copyleft-effect concern
# (the dep may require the combined work to be GPL) but is highly
# context-dependent (static vs dynamic linking, etc.) and is not flagged
# here — it is already visible via the dep's category in the packages list.

check_bidirectional() {
    local root_cat="$1" dep_name="$2" dep_lic="$3" dep_cat="$4"

    # gpl_incompatible deps are always an issue regardless of root
    if [[ "$dep_cat" == "gpl_incompatible" ]]; then
        jq -n \
            --arg pkg    "$dep_name" \
            --arg lic    "$dep_lic" \
            --arg sev    "CRITICAL" \
            --arg reason "Dependency license is not GPL-compatible (affects distribution)" \
            '{type:"dep_gpl_incompatible",severity:$sev,
              package:$pkg,license:$lic,reason:$reason}'
        return
    fi

    case "$root_cat" in
        strong_copyleft)
            # GPL root: all deps must be GPL-compatible
            if [[ "$dep_cat" == "proprietary" ]]; then
                jq -n \
                    --arg pkg    "$dep_name" \
                    --arg lic    "$dep_lic" \
                    --arg sev    "CRITICAL" \
                    --arg reason "Proprietary dependency cannot be distributed with a GPL-licensed root package" \
                    '{type:"dep_incompatible_with_gpl_root",severity:$sev,
                      package:$pkg,license:$lic,reason:$reason}'
            elif [[ "$dep_cat" == "unknown" ]]; then
                jq -n \
                    --arg pkg    "$dep_name" \
                    --arg lic    "$dep_lic" \
                    --arg sev    "WARNING" \
                    --arg reason "Unknown dependency license cannot be confirmed GPL-compatible (root is GPL)" \
                    '{type:"dep_unknown_with_gpl_root",severity:$sev,
                      package:$pkg,license:$lic,reason:$reason}'
            fi
            ;;
        proprietary)
            # Proprietary root: strong copyleft deps require GPL disclosure
            if [[ "$dep_cat" == "strong_copyleft" ]]; then
                jq -n \
                    --arg pkg    "$dep_name" \
                    --arg lic    "$dep_lic" \
                    --arg sev    "CRITICAL" \
                    --arg reason "Strong copyleft dependency requires source disclosure incompatible with proprietary root license" \
                    '{type:"root_incompatible_with_copyleft_dep",severity:$sev,
                      package:$pkg,license:$lic,reason:$reason}'
            fi
            ;;
    esac
    # All other combinations: no bidirectional issue
}

# ── Root license extraction ───────────────────────────────────────────────────

ROOT_LICENSE_RAW=$(extract_root_license "$SBOM_FILE" "$SBOM_FORMAT")
ROOT_LICENSE_SOURCE="sbom"
ROOT_LICENSE_CAT=""

if [[ -z "$ROOT_LICENSE_RAW" ]]; then
    case "$ECOSYSTEM" in
        wordpress)
            ROOT_LICENSE_RAW="GPL-2.0-or-later"
            ROOT_LICENSE_SOURCE="ecosystem_default"
            log "  [INFO] Root package has no declared license"
            log "         Assuming GPL-2.0-or-later (WordPress.org hosting policy)"
            ;;
        typo3)
            ROOT_LICENSE_RAW="GPL-2.0-or-later"
            ROOT_LICENSE_SOURCE="ecosystem_default"
            log "  [INFO] Root package has no declared license"
            log "         Assuming GPL-2.0-or-later (TYPO3 extension repository policy)"
            ;;
        drupal)
            ROOT_LICENSE_RAW="GPL-2.0-or-later"
            ROOT_LICENSE_SOURCE="ecosystem_default"
            log "  [INFO] Root package has no declared license"
            log "         Assuming GPL-2.0-or-later (Drupal.org module policy)"
            ;;
        *)
            ROOT_LICENSE_SOURCE="unknown"
            log "  [WARN] Root package license not found in SBOM"
            log "         Bidirectional compatibility check will be skipped"
            [[ -n "$ECOSYSTEM" ]] || \
                log "         Use --ecosystem to apply ecosystem-aware defaults"
            ;;
    esac
fi

if [[ -n "$ROOT_LICENSE_RAW" ]]; then
    ROOT_LICENSE_CAT=$(classify_license "$ROOT_LICENSE_RAW")
    info "Root package license: $ROOT_LICENSE_RAW ($ROOT_LICENSE_CAT, source: $ROOT_LICENSE_SOURCE)"
fi

# ── Main analysis loop ────────────────────────────────────────────────────────

PERMISSIVE_COUNT=0
WEAK_COPYLEFT_COUNT=0
STRONG_COPYLEFT_COUNT=0
GPL_INCOMPATIBLE_COUNT=0
PROPRIETARY_COUNT=0
UNKNOWN_COUNT=0
TOTAL_RISK=0

ISSUES_ARR=()
PACKAGES_ARR=()

while IFS='|' read -r pkg_name pkg_lic; do
    [[ -z "$pkg_name" ]] && continue

    local_cat_raw=$(classify_license "$pkg_lic")
    # :dual suffix indicates an OR expression where the least-restrictive option was used
    local_dual=false
    if [[ "$local_cat_raw" == *:dual ]]; then
        local_dual=true
        local_cat="${local_cat_raw%%:dual}"
    else
        local_cat="$local_cat_raw"
    fi
    local_sev=$(severity_for_category "$local_cat")
    local_reason=$(reason_for_category "$local_cat")
    local_risk=$(risk_for_category "$local_cat")

    TOTAL_RISK=$((TOTAL_RISK + local_risk))

    case "$local_cat" in
        permissive)      PERMISSIVE_COUNT=$((PERMISSIVE_COUNT+1)) ;;
        weak_copyleft)   WEAK_COPYLEFT_COUNT=$((WEAK_COPYLEFT_COUNT+1)) ;;
        strong_copyleft) STRONG_COPYLEFT_COUNT=$((STRONG_COPYLEFT_COUNT+1)) ;;
        gpl_incompatible) GPL_INCOMPATIBLE_COUNT=$((GPL_INCOMPATIBLE_COUNT+1)) ;;
        proprietary)     PROPRIETARY_COUNT=$((PROPRIETARY_COUNT+1)) ;;
        unknown)         UNKNOWN_COUNT=$((UNKNOWN_COUNT+1)) ;;
    esac

    # Build package entry using jq -n for safe string handling
    PACKAGES_ARR+=("$(jq -n \
        --arg  name     "$pkg_name" \
        --arg  lic      "$pkg_lic" \
        --arg  cat      "$local_cat" \
        --arg  sev      "$local_sev" \
        --arg  reason   "$local_reason" \
        --argjson dual  "$local_dual" \
        '{name:$name, license:$lic, category:$cat,
          severity:$sev, reason:$reason, dual_licensed:$dual}')")

    info "  [$local_sev] $pkg_name: $pkg_lic ($local_cat)"

    # Accumulate issues for flagged categories
    case "$local_cat" in
        gpl_incompatible)
            ISSUES_ARR+=("$(jq -n \
                --arg pkg    "$pkg_name" \
                --arg lic    "$pkg_lic" \
                --arg sev    "CRITICAL" \
                --arg reason "$local_reason" \
                '{type:"gpl_incompatible_license",severity:$sev,
                  package:$pkg,license:$lic,reason:$reason}')")
            ;;
        strong_copyleft)
            # Strong copyleft is GPL-compatible — only flag if --require-gpl-compat
            # is NOT set but caller wants verbose awareness, or flag as INFO only
            if [[ "$REQUIRE_GPL_COMPAT" == "false" ]]; then
                # Still record in packages with INFO severity; no issue entry needed
                true
            fi
            ;;
        proprietary)
            ISSUES_ARR+=("$(jq -n \
                --arg pkg    "$pkg_name" \
                --arg lic    "$pkg_lic" \
                --arg sev    "CRITICAL" \
                --arg reason "$local_reason" \
                '{type:"proprietary_license",severity:$sev,
                  package:$pkg,license:$lic,reason:$reason}')")
            ;;
        unknown)
            if [[ "$FAIL_ON_UNKNOWN" == "true" ]]; then
                ISSUES_ARR+=("$(jq -n \
                    --arg pkg    "$pkg_name" \
                    --arg lic    "${pkg_lic:-NOASSERTION}" \
                    --arg sev    "WARNING" \
                    --arg reason "$local_reason" \
                    '{type:"unknown_license",severity:$sev,
                      package:$pkg,license:$lic,reason:$reason}')")
            fi
            ;;
    esac

    # Bidirectional compatibility check (always-on when root license is known)
    if [[ -n "$ROOT_LICENSE_CAT" ]]; then
        bidir_issue=$(check_bidirectional \
            "$ROOT_LICENSE_CAT" "$pkg_name" "$pkg_lic" "$local_cat")
        [[ -n "$bidir_issue" ]] && ISSUES_ARR+=("$bidir_issue")
    fi

done < <(extract_packages "$SBOM_FILE" "$SBOM_FORMAT")

TOTAL_PACKAGES=$((PERMISSIVE_COUNT + WEAK_COPYLEFT_COUNT + \
                  STRONG_COPYLEFT_COUNT + GPL_INCOMPATIBLE_COUNT + \
                  PROPRIETARY_COUNT + UNKNOWN_COUNT))

# ── GPL compatibility assessment ──────────────────────────────────────────────
# GPL-compatible: permissive + weak copyleft + strong copyleft (GPL itself is GPL-compatible)
# NOT GPL-compatible: gpl_incompatible (SSPL, BUSL, Commons-Clause), proprietary, unknown

GPL_COMPATIBLE=true
[[ $GPL_INCOMPATIBLE_COUNT -gt 0 ]] && GPL_COMPATIBLE=false
[[ $PROPRIETARY_COUNT      -gt 0 ]] && GPL_COMPATIBLE=false
# Unknown licenses are treated as incompatible when --require-gpl-compat is set,
# since we cannot confirm compatibility without a known identifier.
[[ "$REQUIRE_GPL_COMPAT" == "true" ]] && [[ $UNKNOWN_COUNT -gt 0 ]] && GPL_COMPATIBLE=false

if [[ "$REQUIRE_GPL_COMPAT" == "true" ]] && [[ "$GPL_COMPATIBLE" == "false" ]]; then
    ISSUES_ARR+=("$(jq -n \
        --argjson incompat "$GPL_INCOMPATIBLE_COUNT" \
        --argjson propr    "$PROPRIETARY_COUNT" \
        --argjson unk      "$UNKNOWN_COUNT" \
        '{type:"gpl_compat_required",severity:"CRITICAL",
          package:"(policy)",
          license:"(multiple)",
          reason:"--require-gpl-compat set: \(
            if $incompat > 0 then "\($incompat) GPL-incompatible" else "" end),
            \(if $propr > 0 then "\($propr) proprietary" else "" end),
            \(if $unk > 0 then "\($unk) unknown" else "" end) license(s) found"
        }')")
fi

# ── Pass/fail determination ───────────────────────────────────────────────────

STATUS="PASS"
[[ "${#ISSUES_ARR[@]}" -gt 0 ]] && STATUS="FAIL"

# ── Human-readable progress log ──────────────────────────────────────────────

log "[LIC]  Results:"
log "       Permissive:       $PERMISSIVE_COUNT"
log "       Weak copyleft:    $WEAK_COPYLEFT_COUNT"
log "       Strong copyleft:  $STRONG_COPYLEFT_COUNT"
log "       GPL-incompatible: $GPL_INCOMPATIBLE_COUNT"
log "       Proprietary:      $PROPRIETARY_COUNT"
log "       Unknown:          $UNKNOWN_COUNT"
log "       Total packages:   $TOTAL_PACKAGES"
log "       GPL compatible:   $GPL_COMPATIBLE"
log "       Status:           $STATUS | Risk contribution: $TOTAL_RISK"

if [[ "${#ISSUES_ARR[@]}" -gt 0 ]] && [[ "$SILENT" == "false" ]]; then
    log "       Issues:"
    local_i=0
    for entry in "${ISSUES_ARR[@]}"; do
        ((local_i++))
        [[ $local_i -gt 10 ]] && { log "       ... and $((${#ISSUES_ARR[@]} - 10)) more"; break; }
        log "         $(echo "$entry" | jq -r '"[\(.severity)] \(.package) (\(.license)) — \(.reason)"')"
    done
fi

# ── Build JSON output ─────────────────────────────────────────────────────────

ISSUES_JSON=$(printf '%s\n' "${ISSUES_ARR[@]+"${ISSUES_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")
PACKAGES_JSON=$(printf '%s\n' "${PACKAGES_ARR[@]+"${PACKAGES_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  status          "$STATUS" \
    --argjson gpl_compat   "$GPL_COMPATIBLE" \
    --arg  timestamp       "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_ver     "$TOOLKIT_VERSION" \
    --arg  sbom_file       "$(basename "$SBOM_FILE")" \
    --arg  sbom_format     "$SBOM_FORMAT" \
    --arg  ecosystem       "${ECOSYSTEM:-}" \
    --arg  root_lic        "${ROOT_LICENSE_RAW:-}" \
    --arg  root_lic_cat    "${ROOT_LICENSE_CAT:-unknown}" \
    --arg  root_lic_src    "$ROOT_LICENSE_SOURCE" \
    --argjson total        "$TOTAL_PACKAGES" \
    --argjson permissive   "$PERMISSIVE_COUNT" \
    --argjson weak         "$WEAK_COPYLEFT_COUNT" \
    --argjson strong       "$STRONG_COPYLEFT_COUNT" \
    --argjson gpl_incompat "$GPL_INCOMPATIBLE_COUNT" \
    --argjson proprietary  "$PROPRIETARY_COUNT" \
    --argjson unknown      "$UNKNOWN_COUNT" \
    --argjson risk         "$TOTAL_RISK" \
    --argjson req_gpl      "$REQUIRE_GPL_COMPAT" \
    --argjson fail_unknown "$FAIL_ON_UNKNOWN" \
    --argjson issues       "$ISSUES_JSON" \
    --argjson packages     "$PACKAGES_JSON" \
    '{
        license_compliance: {
            status:          $status,
            gpl_compatible:  $gpl_compat,
            timestamp:       $timestamp,
            toolkit_version: $toolkit_ver,
            sbom_source: {
                file:      $sbom_file,
                format:    $sbom_format,
                ecosystem: $ecosystem
            },
            root_package: {
                license:          $root_lic,
                license_category: $root_lic_cat,
                license_source:   $root_lic_src
            },
            summary: {
                total:            $total,
                permissive:       $permissive,
                weak_copyleft:    $weak,
                strong_copyleft:  $strong,
                gpl_incompatible: $gpl_incompat,
                proprietary:      $proprietary,
                unknown:          $unknown
            },
            policy: {
                require_gpl_compat: $req_gpl,
                fail_on_unknown:    $fail_unknown
            },
            risk_contribution: $risk,
            issues:   $issues,
            packages: $packages
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

[[ "$STATUS" == "PASS" ]] && exit 0 || exit 1
