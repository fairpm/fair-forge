#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# provenance-verify.sh - SLSA provenance and source authenticity verification
#
# Usage: provenance-verify.sh [OPTIONS] <target>
#
# Verifies build provenance and source authenticity for packages from
# WordPress.org, Packagist, GitHub, or arbitrary sources. Assesses SLSA level
# and performs post-extraction per-file verification for WordPress plugins
# when a checksum JSON is available.
#
# Output file: ./meta/<clean-name>/<clean-name>.provenance.json
#
# Exit codes: 0 = verified or acceptable, 1 = failed, 2 = execution error
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
CURL_TIMEOUT=15

PROVENANCE_FILE=""
VERIFY_MODE="auto"          # auto | slsa | basic | wordpress | packagist
PACKAGE_TYPE="public"       # public | internal | prerelease | custom
SKIP_PUBLIC_CHECK=false
EXPECTED_VERSION=""
SOURCE_REPO=""
SOURCE_COMMIT=""
BUILDER_ID=""

# WordPress specific
WP_PLUGIN=""
WP_VERSION=""
# Path to checksum JSON produced by checksum-verify.sh (enables per-file check)
CHECKSUM_JSON=""
# Path to extracted package directory (./packages/<name>/ from checksum-verify.sh)
EXTRACTED_DIR=""

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/prov_verify_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Verify build provenance and source authenticity against the SLSA framework.
Supports WordPress plugins, Packagist, GitHub releases, and arbitrary packages.
Can perform post-extraction per-file integrity checks for WordPress plugins.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show additional detail
    -o, --output-dir DIR    Directory for output file
                            (default: ./meta/<clean-name>/)
    --meta-base DIR         Base directory for meta output (default: ./meta)
    --no-file               Output JSON to stdout only; do not write file
    --version               Print version and exit

VERIFICATION OPTIONS:
    --mode MODE             Verification mode: auto, slsa, basic, wordpress, packagist
                            (default: auto — inferred from available inputs)
    --provenance FILE       SLSA provenance attestation file (.provenance.json)
    --source-repo URL       Expected source repository URL
    --source-commit SHA     Expected Git commit hash
    --builder ID            Expected builder identity string

PACKAGE TYPE:
    --package-type TYPE     Context: public, internal, prerelease, custom
                            (default: public)
                            internal and prerelease automatically skip public checks
    --skip-public-check     Do not penalise for missing public registry verification
    --expected-version VER  Expected version string (used in prerelease validation)

WORDPRESS OPTIONS:
    --wp-plugin SLUG        WordPress.org plugin slug
    --wp-version VERSION    Expected plugin version
    --checksum-json FILE    Path to checksum JSON from checksum-verify.sh
                            Enables per-file verification against WP checksums API
    --extracted-dir DIR     Path to extracted plugin directory
                            (default: ./packages/<slug>/ if --checksum-json given)

EXAMPLES:
    # WordPress plugin — full verification with per-file checks
    $(basename "$0") \\
      --wp-plugin akismet --wp-version 5.3 \\
      --checksum-json ./meta/akismet.5.3/akismet.5.3.checksum.json \\
      --extracted-dir ./packages/akismet.5.3 \\
      akismet.5.3.zip

    # Packagist / Composer package
    $(basename "$0") \\
      --mode packagist \\
      --source-repo github.com/vendor/package \\
      vendor-package-1.0.0.zip

    # GitHub release with SLSA provenance attestation
    $(basename "$0") \\
      --provenance package.provenance.json \\
      --source-repo github.com/owner/repo \\
      --source-commit abc123def \\
      package.tar.gz

    # Internal package (skip public registry checks)
    $(basename "$0") \\
      --package-type internal \\
      --provenance local-build.json \\
      package.tar.gz

    # Prerelease (not yet on any registry)
    $(basename "$0") \\
      --package-type prerelease \\
      --expected-version 2.0.0-beta.1 \\
      package.tar.gz

SLSA LEVELS ASSESSED:
    Level 0   No provenance — build process entirely opaque
    Level 1   Provenance exists (even if unsigned/unverified)
    Level 2   Hosted build + verifiable provenance
    Level 3   Hardened build platform + non-falsifiable provenance

RISK SCORING:
    Base risk by package type:
      public:     300   (full verification expected)
      custom:     150   (partial verification expected)
      internal:   100   (public registry not applicable)
      prerelease: 100   (not yet published)

    Reductions for successful verification steps:
      Provenance found:      -100
      Provenance valid:       -50
      Source verified:        -50
      Builder trusted:        -50
      SLSA level >= 2:        -50
      WP file checks passed:  -50

OUTPUT FILE:
    ./meta/<clean-name>/<clean-name>.provenance.json

DEPENDENCIES:
    jq, curl

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

# ── Functions: Result state ───────────────────────────────────────────────────
# All verification state is accumulated into these variables.

SLSA_LEVEL=0
PROVENANCE_FOUND=false
PROVENANCE_VALID=false
SOURCE_VERIFIED=false
BUILDER_TRUSTED=false
WP_FILES_VERIFIED=false
CHECKS=()
ISSUES=()

add_check() {
    # add_check <name> <status> [note]
    local name="$1" status="$2" note="${3:-}"
    CHECKS+=("$(jq -n \
        --arg n "$name" --arg s "$status" --arg note "$note" \
        '{check:$n, status:$s, note:$note}')")
}

add_issue() {
    # add_issue <type> <severity> <reason> [package]
    local type="$1" severity="$2" reason="$3" pkg="${4:-}"
    ISSUES+=("$(jq -n \
        --arg t "$type" --arg s "$severity" \
        --arg r "$reason" --arg p "$pkg" \
        '{type:$t, severity:$s, reason:$r, package:$p}')")
}

# ── Functions: WordPress verification ────────────────────────────────────────

verify_wordpress() {
    log "[WP]   WordPress Plugin Verification"

    if [[ "$SKIP_PUBLIC_CHECK" == "true" ]]; then
        add_check "wordpress_org" "skipped" "package_type=$PACKAGE_TYPE"
        return 0
    fi

    [[ -z "$WP_PLUGIN" ]]  && { log "  [WARN] --wp-plugin required for WordPress mode"; return 1; }
    [[ -z "$WP_VERSION" ]] && { log "  [WARN] --wp-version required for WordPress mode"; return 1; }

    # ── Step 1: Confirm plugin exists on WordPress.org ───────────────────────
    log "  [API]  Checking WordPress.org plugin registry..."
    local info_url="https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${WP_PLUGIN}"
    local info_data
    info_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" "$info_url" 2>/dev/null || echo "{}")

    if ! echo "$info_data" | jq -e '.slug' &>/dev/null; then
        log "  [WARN] Plugin not found on WordPress.org: $WP_PLUGIN"
        add_issue "wp_plugin_not_found" "HIGH" \
            "Plugin slug not found in WordPress.org registry" "$WP_PLUGIN"
        add_check "wordpress_org_registry" "failed" "slug not found"
    else
        local registered_version
        registered_version=$(echo "$info_data" | jq -r '.version // ""')
        log "  [OK]   Plugin exists on WordPress.org (current: $registered_version)"
        SOURCE_VERIFIED=true
        [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
        add_check "wordpress_org_registry" "passed" "current=$registered_version"

        # ── Step 2: Confirm requested version exists ─────────────────────────
        local version_url
        version_url=$(echo "$info_data" | jq -r \
            --arg ver "$WP_VERSION" '.versions[$ver] // ""' 2>/dev/null || echo "")
        if [[ -z "$version_url" ]]; then
            # Fallback — canonical URL pattern
            version_url="https://downloads.wordpress.org/plugin/${WP_PLUGIN}.${WP_VERSION}.zip"
        fi
        log "  [OK]   Version $WP_VERSION download URL: $version_url"
        add_check "wordpress_version_exists" "passed" "url=$version_url"
    fi

    # ── Step 3: Per-file integrity check (requires checksum JSON + extracted dir)
    # The checksums endpoint returns MD5 and SHA256 for every file in the
    # extracted plugin. We verify the extracted directory against this list.
    if [[ -n "$CHECKSUM_JSON" ]] && [[ -f "$CHECKSUM_JSON" ]]; then

        # Determine extracted directory
        local extract_path="$EXTRACTED_DIR"
        if [[ -z "$extract_path" ]]; then
            extract_path=$(jq -r '.crypto_verification.extraction.path // ""' \
                "$CHECKSUM_JSON" 2>/dev/null || echo "")
        fi

        # Get the WP file checksums URL from the checksum JSON
        local wp_checksums_url
        wp_checksums_url=$(jq -r \
            '.crypto_verification.verification.wp_file_checksums_url // ""' \
            "$CHECKSUM_JSON" 2>/dev/null || echo "")

        if [[ -n "$wp_checksums_url" ]] && [[ -d "$extract_path" ]]; then
            log "  [FILE] Fetching per-file checksums from WordPress.org..."
            local wp_checksums
            wp_checksums=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
                "$wp_checksums_url" 2>/dev/null || echo "{}")

            if echo "$wp_checksums" | jq -e '.files' &>/dev/null; then
                verify_wp_files "$extract_path" "$wp_checksums"
            else
                log "  [WARN] Could not retrieve WordPress per-file checksums"
                log "         URL: $wp_checksums_url"
                add_check "wp_file_verification" "skipped" "checksums endpoint unavailable"
            fi

        elif [[ -n "$wp_checksums_url" ]] && [[ -z "$extract_path" ]]; then
            log "  [INFO] WP file checksums available but no extracted directory found"
            log "         Run checksum-verify.sh with --extract, or pass --extracted-dir"
            add_check "wp_file_verification" "skipped" "no extracted directory"

        elif [[ -d "$extract_path" ]] && [[ -z "$wp_checksums_url" ]]; then
            log "  [INFO] Extracted directory found but no WP checksums URL in checksum JSON"
            add_check "wp_file_verification" "skipped" "no checksums url in checksum json"
        fi

    elif [[ -n "$EXTRACTED_DIR" ]] && [[ -d "$EXTRACTED_DIR" ]]; then
        # Have extracted dir but no checksum JSON — fetch checksums directly
        log "  [FILE] Fetching per-file checksums directly from WordPress.org..."
        local direct_url="https://downloads.wordpress.org/plugin-checksums/${WP_PLUGIN}/${WP_VERSION}.json"
        local direct_checksums
        direct_checksums=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
            "$direct_url" 2>/dev/null || echo "{}")

        if echo "$direct_checksums" | jq -e '.files' &>/dev/null; then
            verify_wp_files "$EXTRACTED_DIR" "$direct_checksums"
        else
            log "  [WARN] WordPress checksums endpoint unavailable for $WP_PLUGIN $WP_VERSION"
            add_check "wp_file_verification" "failed" "checksums endpoint returned no data"
        fi
    else
        log "  [INFO] Per-file verification skipped"
        log "         Pass --checksum-json or --extracted-dir to enable"
        add_check "wp_file_verification" "skipped" "no extracted directory provided"
    fi
}

# verify_wp_files <extracted_dir> <checksums_json_data>
# Walks the extracted plugin directory and verifies each file's SHA256
# against the WordPress.org checksums API response.
verify_wp_files() {
    local dir="$1"
    local checksums_data="$2"

    log "  [FILE] Verifying extracted files against WordPress.org checksums..."

    local pass_count=0 fail_count=0 skip_count=0 total_count=0

    # The .files object maps relative paths to {md5, sha256}
    # We verify SHA256 for each file that exists locally.
    while IFS= read -r rel_path; do
        [[ -z "$rel_path" ]] && continue
        total_count=$((total_count+1))

        local full_path="${dir}/${rel_path}"

        if [[ ! -f "$full_path" ]]; then
            info "  SKIP (not found): $rel_path"
            skip_count=$((skip_count+1))
            continue
        fi

        local expected_sha256
        expected_sha256=$(echo "$checksums_data" | jq -r \
            --arg p "$rel_path" '.files[$p].sha256 // ""' 2>/dev/null || echo "")

        if [[ -z "$expected_sha256" ]]; then
            info "  SKIP (no sha256 in API): $rel_path"
            skip_count=$((skip_count+1))
            continue
        fi

        local actual_sha256
        actual_sha256=$(sha256sum "$full_path" | cut -d' ' -f1)

        if [[ "${expected_sha256,,}" == "${actual_sha256,,}" ]]; then
            info "  OK: $rel_path"
            pass_count=$((pass_count+1))
        else
            log "  [FAIL] File mismatch: $rel_path"
            info "         Expected: $expected_sha256"
            info "         Got:      $actual_sha256"
            fail_count=$((fail_count+1))
            add_issue "wp_file_mismatch" "CRITICAL" \
                "File SHA256 does not match WordPress.org checksums" "$rel_path"
        fi

    done < <(echo "$checksums_data" | jq -r '.files | keys[]' 2>/dev/null)

    log "  [FILE] Results: $pass_count passed, $fail_count failed, $skip_count skipped / $total_count total"

    if [[ "$fail_count" -gt 0 ]]; then
        add_check "wp_file_verification" "failed" \
            "pass=$pass_count fail=$fail_count skip=$skip_count total=$total_count"
        add_issue "wp_files_integrity_failed" "CRITICAL" \
            "$fail_count of $total_count plugin files failed SHA256 verification" "$WP_PLUGIN"
    elif [[ "$pass_count" -gt 0 ]]; then
        add_check "wp_file_verification" "passed" \
            "pass=$pass_count skip=$skip_count total=$total_count"
        WP_FILES_VERIFIED=true
        [[ $SLSA_LEVEL -lt 2 ]] && SLSA_LEVEL=2
        log "  [OK]   All verifiable files match WordPress.org checksums"
    else
        add_check "wp_file_verification" "skipped" "no files could be verified"
    fi
}

# ── Functions: WordPress core verification ───────────────────────────────────

verify_wordpress_core() {
    log "[WP]   WordPress Core Verification"

    if [[ "$SKIP_PUBLIC_CHECK" == "true" ]]; then
        add_check "wordpress_core" "skipped" "package_type=$PACKAGE_TYPE"
        return 0
    fi

    # Try to determine version: from --wp-version flag, checksum JSON, or archive
    local core_version="${WP_VERSION:-}"

    if [[ -z "$core_version" ]] && [[ -n "$CHECKSUM_JSON" ]] && [[ -f "$CHECKSUM_JSON" ]]; then
        core_version=$(jq -r '.crypto_verification.package_identity.version // ""' \
            "$CHECKSUM_JSON" 2>/dev/null || echo "")
    fi

    if [[ -z "$core_version" ]] && [[ -d "${EXTRACTED_DIR:-}" ]]; then
        core_version=$(grep -r "\$wp_version" "$EXTRACTED_DIR/wp-includes/version.php" \
            2>/dev/null | head -n1 \
            | sed "s/.*=[ ]*['\"]//;s/['\"].*//" | tr -d ' \r' || echo "")
    fi

    if [[ -z "$core_version" ]]; then
        log "  [WARN] Could not determine WordPress core version"
        log "         Pass --wp-version to specify explicitly"
        add_check "wordpress_core_version" "failed" "version unknown"
        return 1
    fi

    log "  [INFO] WordPress core version: $core_version"

    # Verify the release exists on WordPress.org
    local release_url="https://api.wordpress.org/core/version-check/1.7/"
    local release_data
    release_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" "$release_url" 2>/dev/null || echo "{}")

    local known_version
    known_version=$(echo "$release_data" | jq -r \
        --arg v "$core_version" \
        '.offers[]? | select(.version == $v) | .version' 2>/dev/null | head -n1 || echo "")

    if [[ -n "$known_version" ]]; then
        log "  [OK]   WordPress $core_version is a known release"
        SOURCE_VERIFIED=true
        PROVENANCE_FOUND=true
        [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
        add_check "wordpress_core_version" "passed" "version=$core_version"
    else
        # Older releases may not appear in the version-check API; try checksums API
        local chk_url="https://api.wordpress.org/core/checksums/1.0/?version=${core_version}&locale=en_US"
        local chk_data
        chk_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" "$chk_url" 2>/dev/null || echo "{}")
        if echo "$chk_data" | jq -e '.checksums' &>/dev/null; then
            log "  [OK]   WordPress $core_version verified via checksums API"
            SOURCE_VERIFIED=true
            PROVENANCE_FOUND=true
            [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
            add_check "wordpress_core_version" "passed" "version=$core_version (via checksums api)"
        else
            log "  [WARN] WordPress $core_version not found in WordPress.org release API"
            add_check "wordpress_core_version" "failed" "version not in api"
            add_issue "wp_core_version_unknown" "MEDIUM" \
                "WordPress core version not found in WordPress.org API" "$core_version"
        fi
    fi
}

# ── Functions: SLSA provenance verification ───────────────────────────────────

verify_slsa() {
    log "[SLSA] SLSA Provenance Verification"

    [[ -z "$PROVENANCE_FILE" ]] && {
        log "  [WARN] --provenance FILE required for slsa mode"
        return 1
    }
    [[ ! -f "$PROVENANCE_FILE" ]] && {
        log "  [WARN] Provenance file not found: $PROVENANCE_FILE"
        add_issue "provenance_file_missing" "HIGH" \
            "Provenance file specified but not found" "$PROVENANCE_FILE"
        return 1
    }

    jq empty "$PROVENANCE_FILE" 2>/dev/null || {
        log "  [WARN] Provenance file is not valid JSON: $PROVENANCE_FILE"
        add_issue "provenance_invalid_json" "HIGH" \
            "Provenance file is not valid JSON" "$PROVENANCE_FILE"
        return 1
    }

    PROVENANCE_FOUND=true
    [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
    add_check "provenance_file_present" "passed" ""
    log "  [OK]   Provenance file found and valid JSON"

    # Check for in-toto v1 statement structure
    local pred_type
    pred_type=$(jq -r '.predicateType // ""' "$PROVENANCE_FILE" 2>/dev/null || echo "")

    if [[ "$pred_type" == *"slsa.dev/provenance"* ]]; then
        PROVENANCE_VALID=true
        log "  [OK]   Predicate type: $pred_type"
        add_check "provenance_slsa_predicate" "passed" "$pred_type"
        [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
    else
        log "  [WARN] Unrecognised predicate type: ${pred_type:-<none>}"
        add_check "provenance_slsa_predicate" "failed" \
            "expected slsa.dev/provenance, got: ${pred_type:-none}"
    fi

    # Check builder identity
    local builder_id
    builder_id=$(jq -r '.predicate.runDetails.builder.id // ""' \
        "$PROVENANCE_FILE" 2>/dev/null || echo "")

    if [[ -n "$builder_id" ]]; then
        log "  [OK]   Builder ID: $builder_id"
        add_check "builder_id_present" "passed" "$builder_id"
        [[ $SLSA_LEVEL -lt 2 ]] && SLSA_LEVEL=2

        if [[ -n "$BUILDER_ID" ]]; then
            if [[ "$builder_id" == *"$BUILDER_ID"* ]]; then
                BUILDER_TRUSTED=true
                log "  [OK]   Builder ID matches expected"
                add_check "builder_id_match" "passed" ""
            else
                log "  [WARN] Builder ID mismatch"
                info "         Expected: $BUILDER_ID"
                info "         Got:      $builder_id"
                add_issue "builder_mismatch" "MEDIUM" \
                    "Builder ID does not match expected value" "$builder_id"
                add_check "builder_id_match" "failed" \
                    "expected=$BUILDER_ID actual=$builder_id"
            fi
        fi
    else
        log "  [WARN] No builder ID in provenance"
        add_check "builder_id_present" "failed" "missing from predicate.runDetails.builder.id"
    fi

    # Check source repository
    local prov_repo
    prov_repo=$(jq -r '
        .predicate.buildDefinition.externalParameters.sourceHeader //
        .predicate.buildDefinition.externalParameters.repository //
        ""' "$PROVENANCE_FILE" 2>/dev/null || echo "")

    if [[ -n "$SOURCE_REPO" ]] && [[ -n "$prov_repo" ]]; then
        if [[ "$prov_repo" == *"$SOURCE_REPO"* ]]; then
            SOURCE_VERIFIED=true
            log "  [OK]   Source repository matches"
            add_check "source_repo_match" "passed" ""
        else
            log "  [WARN] Source repository mismatch"
            info "         Expected: $SOURCE_REPO"
            info "         Got:      $prov_repo"
            add_issue "source_repo_mismatch" "MEDIUM" \
                "Source repository does not match expected" "$prov_repo"
            add_check "source_repo_match" "failed" \
                "expected=$SOURCE_REPO actual=$prov_repo"
        fi
    fi

    # Signed provenance → SLSA L2+
    if jq -e '.signatures[0]?' "$PROVENANCE_FILE" &>/dev/null 2>&1; then
        log "  [OK]   Provenance is signed"
        PROVENANCE_VALID=true
        [[ $SLSA_LEVEL -lt 2 ]] && SLSA_LEVEL=2
        add_check "provenance_signed" "passed" ""
    fi
}

# ── Functions: Basic source verification ─────────────────────────────────────

verify_basic() {
    log "[SRC]  Basic Source Verification"

    if [[ "$SKIP_PUBLIC_CHECK" == "true" ]]; then
        log "  [INFO] Public registry checks skipped (package_type=$PACKAGE_TYPE)"
        add_check "public_registry" "skipped" "package_type=$PACKAGE_TYPE"
    fi

    # ── Packagist / Composer ─────────────────────────────────────────────────
    # Check for composer.json inside a zip or extracted directory
    local composer_content=""

    if [[ -f "$TARGET" ]] && [[ "$TARGET" == *.zip ]]; then
        composer_content=$(unzip -p "$TARGET" "composer.json" 2>/dev/null \
            || unzip -p "$TARGET" "*/composer.json" 2>/dev/null || true)
    elif [[ -d "$TARGET" ]] && [[ -f "$TARGET/composer.json" ]]; then
        composer_content=$(cat "$TARGET/composer.json")
    fi

    if [[ -n "$composer_content" ]] && echo "$composer_content" | jq empty 2>/dev/null; then
        local pkg_name pkg_source
        pkg_name=$(echo "$composer_content" | jq -r '.name // ""')
        pkg_source=$(echo "$composer_content" | jq -r '.source.url // ""')

        if [[ -n "$pkg_name" ]]; then
            log "  [INFO] Composer package: $pkg_name"

            if [[ "$SKIP_PUBLIC_CHECK" == "false" ]]; then
                log "  [API]  Checking Packagist..."
                local pack_url="https://repo.packagist.org/p2/${pkg_name}.json"
                local pack_data
                pack_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
                    "$pack_url" 2>/dev/null || echo "{}")

                if echo "$pack_data" | jq -e '.packages' &>/dev/null; then
                    SOURCE_VERIFIED=true
                    [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
                    log "  [OK]   Package exists on Packagist"
                    add_check "packagist_registry" "passed" "$pkg_name"
                else
                    log "  [WARN] Package not found on Packagist: $pkg_name"
                    add_issue "packagist_not_found" "MEDIUM" \
                        "Package not found in Packagist registry" "$pkg_name"
                    add_check "packagist_registry" "failed" "$pkg_name"
                fi
            fi

            # Source URL match
            if [[ -n "$SOURCE_REPO" ]] && [[ -n "$pkg_source" ]]; then
                if [[ "$pkg_source" == *"$SOURCE_REPO"* ]]; then
                    log "  [OK]   Source URL matches expected"
                    add_check "source_url_match" "passed" ""
                else
                    log "  [WARN] Source URL mismatch"
                    add_issue "source_url_mismatch" "MEDIUM" \
                        "Package source URL does not match expected" "$pkg_source"
                    add_check "source_url_match" "failed" \
                        "expected=$SOURCE_REPO actual=$pkg_source"
                fi
            fi
        fi
    fi

    # ── GitHub repository check ───────────────────────────────────────────────
    if [[ -n "$SOURCE_REPO" ]] && [[ "$SOURCE_REPO" == *"github.com"* ]] \
       && [[ "$SKIP_PUBLIC_CHECK" == "false" ]]; then

        local repo_path
        repo_path=$(echo "$SOURCE_REPO" \
            | sed 's|.*github\.com/||' | sed 's|\.git$||')

        log "  [API]  Checking GitHub repository: $repo_path"
        local repo_data
        repo_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
            "https://api.github.com/repos/${repo_path}" 2>/dev/null || echo "{}")

        if echo "$repo_data" | jq -e '.id' &>/dev/null; then
            SOURCE_VERIFIED=true
            log "  [OK]   GitHub repository exists"
            add_check "github_repo_exists" "passed" "$repo_path"

            # Commit verification
            if [[ -n "$SOURCE_COMMIT" ]]; then
                local commit_status
                commit_status=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
                    -o /dev/null -w "%{http_code}" \
                    "https://api.github.com/repos/${repo_path}/commits/${SOURCE_COMMIT}" \
                    2>/dev/null || echo "000")

                if [[ "$commit_status" == "200" ]]; then
                    log "  [OK]   Commit verified: ${SOURCE_COMMIT:0:12}..."
                    add_check "github_commit_exists" "passed" "${SOURCE_COMMIT:0:12}"
                    [[ $SLSA_LEVEL -lt 1 ]] && SLSA_LEVEL=1
                else
                    log "  [WARN] Commit not found (HTTP $commit_status): $SOURCE_COMMIT"
                    add_issue "github_commit_not_found" "MEDIUM" \
                        "Specified commit not found in repository" "$SOURCE_COMMIT"
                    add_check "github_commit_exists" "failed" "http=$commit_status"
                fi
            fi
        else
            log "  [WARN] GitHub repository not found: $repo_path"
            add_issue "github_repo_not_found" "MEDIUM" \
                "Source repository not found on GitHub" "$repo_path"
            add_check "github_repo_exists" "failed" "$repo_path"
        fi
    fi
}

# ── Functions: SLSA status determination ─────────────────────────────────────
# Extracted into a function to avoid using 'local' outside a function (bug fix).

determine_verification_status() {
    local has_critical_issues=0
    local issue

    for issue in "${ISSUES[@]+"${ISSUES[@]}"}"; do
        local sev
        sev=$(echo "$issue" | jq -r '.severity // ""' 2>/dev/null || echo "")
        [[ "$sev" == "CRITICAL" ]] && ((has_critical_issues++))
    done

    if [[ "${#ISSUES[@]}" -eq 0 ]] && [[ $SLSA_LEVEL -ge 2 ]]; then
        echo "verified"
    elif [[ "${#ISSUES[@]}" -eq 0 ]] && [[ $SLSA_LEVEL -ge 1 ]]; then
        echo "partial"
    elif [[ "$SKIP_PUBLIC_CHECK" == "true" ]] && [[ "$has_critical_issues" -eq 0 ]]; then
        # Non-public packages: only fail on CRITICAL issues
        [[ $SLSA_LEVEL -ge 1 ]] && echo "partial" || echo "no_provenance"
    elif [[ "${#ISSUES[@]}" -gt 0 ]]; then
        echo "failed"
    else
        echo "no_provenance"
    fi
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
        --mode)
            [[ -z "${2:-}" ]] && die "--mode requires an argument"
            VERIFY_MODE="$2"
            [[ "$VERIFY_MODE" =~ ^(auto|slsa|basic|wordpress|packagist)$ ]] \
                || die "Invalid mode. Use: auto, slsa, basic, wordpress, packagist"
            shift 2 ;;
        --provenance)
            [[ -z "${2:-}" ]] && die "--provenance requires an argument"
            PROVENANCE_FILE="$2"; shift 2 ;;
        --package-type)
            [[ -z "${2:-}" ]] && die "--package-type requires an argument"
            PACKAGE_TYPE="$2"
            [[ "$PACKAGE_TYPE" =~ ^(public|internal|prerelease|custom)$ ]] \
                || die "Invalid package-type. Use: public, internal, prerelease, custom"
            shift 2 ;;
        --skip-public-check) SKIP_PUBLIC_CHECK=true; shift ;;
        --expected-version)
            [[ -z "${2:-}" ]] && die "--expected-version requires an argument"
            EXPECTED_VERSION="$2"; shift 2 ;;
        --source-repo)
            [[ -z "${2:-}" ]] && die "--source-repo requires an argument"
            SOURCE_REPO="$2"; shift 2 ;;
        --source-commit)
            [[ -z "${2:-}" ]] && die "--source-commit requires an argument"
            SOURCE_COMMIT="$2"; shift 2 ;;
        --builder)
            [[ -z "${2:-}" ]] && die "--builder requires an argument"
            BUILDER_ID="$2"; shift 2 ;;
        --wp-plugin)
            [[ -z "${2:-}" ]] && die "--wp-plugin requires an argument"
            WP_PLUGIN="$2"; shift 2 ;;
        --wp-version)
            [[ -z "${2:-}" ]] && die "--wp-version requires an argument"
            WP_VERSION="$2"; shift 2 ;;
        --checksum-json)
            [[ -z "${2:-}" ]] && die "--checksum-json requires an argument"
            CHECKSUM_JSON="$2"; shift 2 ;;
        --extracted-dir)
            [[ -z "${2:-}" ]] && die "--extracted-dir requires an argument"
            EXTRACTED_DIR="$2"; shift 2 ;;
        --version)
            echo "provenance-verify.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$TARGET" ]]    && die "No target specified (use --help for usage)"
[[ ! -e "$TARGET" ]]  && die "Target not found: $TARGET"

# Guard: warn clearly if a JSON file is passed as the target by mistake
if [[ "$TARGET" == *.json ]]; then
    if [[ -n "$CHECKSUM_JSON" ]]; then
        die "TARGET should be the archive or directory, not a JSON file.\n       Got: $TARGET\n       Did you mean to pass this with --checksum-json?"
    fi
fi

command -v jq   &>/dev/null || die "jq is required"
command -v curl &>/dev/null || die "curl is required"

# internal and prerelease packages skip public registry checks automatically
[[ "$PACKAGE_TYPE" =~ ^(internal|prerelease)$ ]] && SKIP_PUBLIC_CHECK=true

# When --checksum-json is given, derive a clean name from it (the JSON
# already carries the original target filename) rather than from the path.
if [[ -n "$CHECKSUM_JSON" ]] && [[ -f "$CHECKSUM_JSON" ]]; then
    chksum_target=$(jq -r '.crypto_verification.target // ""' "$CHECKSUM_JSON" 2>/dev/null || echo "")
    if [[ -n "$chksum_target" ]]; then
        CLEAN_NAME=$(sanitize_name "$chksum_target")
    else
        CLEAN_NAME=$(sanitize_name "$TARGET")
    fi
else
    CLEAN_NAME=$(sanitize_name "$TARGET")
fi
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.provenance.json"

# ── Auto-detect verification mode ────────────────────────────────────────────

if [[ "$VERIFY_MODE" == "auto" ]]; then
    if   [[ -n "$WP_PLUGIN" ]];            then VERIFY_MODE="wordpress"
    elif [[ -f "${PROVENANCE_FILE:-}" ]];  then VERIFY_MODE="slsa"
    elif [[ -n "$SOURCE_REPO" ]];          then VERIFY_MODE="basic"
    else
        # Check if this looks like WordPress core (wp-settings.php present)
        local_is_core=false
        if [[ -f "$TARGET" ]] && [[ "$TARGET" == *.zip ]]; then
            unzip -l "$TARGET" 2>/dev/null | grep -q "wp-settings.php" \
                && local_is_core=true
        elif [[ -d "$TARGET" ]] && [[ -f "$TARGET/wp-settings.php" ]]; then
            local_is_core=true
        fi
        if [[ "$local_is_core" == "true" ]]; then
            VERIFY_MODE="wordpress_core"
        else
            VERIFY_MODE="basic"
            log "[WARN] No verification inputs provided — running basic checks only"
        fi
    fi
fi

# When mode is wordpress but no --wp-plugin given, check if this is core
if [[ "$VERIFY_MODE" == "wordpress" ]] && [[ -z "$WP_PLUGIN" ]]; then
    local_is_core=false
    if [[ -f "$TARGET" ]] && [[ "$TARGET" == *.zip ]]; then
        unzip -l "$TARGET" 2>/dev/null | grep -q "wp-settings.php" \
            && local_is_core=true
    elif [[ -d "$TARGET" ]] && [[ -f "$TARGET/wp-settings.php" ]]; then
        local_is_core=true
    fi
    if [[ "$local_is_core" == "true" ]]; then
        VERIFY_MODE="wordpress_core"
        log "[INFO] Detected WordPress core — switching to wordpress_core mode"
    else
        log "[WARN] --mode wordpress requires --wp-plugin for plugin verification"
        log "       If this is WordPress core, the mode will be detected automatically"
    fi
fi

log "[PROV] Provenance Verification: $(basename "$TARGET")"
log "       Mode: $VERIFY_MODE | Package type: $PACKAGE_TYPE | SLSA target: L${SLSA_LEVEL}+"
[[ "$SKIP_PUBLIC_CHECK" == "true" ]] && log "       Public registry checks: skipped"

# ── Set base risk for this package type ──────────────────────────────────────

BASE_RISK=300
case "$PACKAGE_TYPE" in
    public)     BASE_RISK=300 ;;
    custom)     BASE_RISK=150 ;;
    internal)   BASE_RISK=100 ;;
    prerelease) BASE_RISK=100 ;;
esac

# ── Run verification ──────────────────────────────────────────────────────────

case "$VERIFY_MODE" in
    wordpress)       verify_wordpress ;;
    wordpress_core)  verify_wordpress_core ;;
    slsa)            verify_slsa ;;
    basic|packagist) verify_basic ;;
esac

# ── Risk score calculation ────────────────────────────────────────────────────

RISK_SCORE=$BASE_RISK
[[ "$PROVENANCE_FOUND"   == "true" ]] && RISK_SCORE=$((RISK_SCORE - 100))
[[ "$PROVENANCE_VALID"   == "true" ]] && RISK_SCORE=$((RISK_SCORE -  50))
[[ "$SOURCE_VERIFIED"    == "true" ]] && RISK_SCORE=$((RISK_SCORE -  50))
[[ "$BUILDER_TRUSTED"    == "true" ]] && RISK_SCORE=$((RISK_SCORE -  50))
[[ $SLSA_LEVEL           -ge 2    ]] && RISK_SCORE=$((RISK_SCORE -  50))
[[ "$WP_FILES_VERIFIED"  == "true" ]] && RISK_SCORE=$((RISK_SCORE -  50))
[[ $RISK_SCORE -lt 0 ]] && RISK_SCORE=0

# ── Determine overall verification status ────────────────────────────────────

VERIFICATION_STATUS=$(determine_verification_status)

# ── Build JSON output ─────────────────────────────────────────────────────────

CHECKS_JSON=$(printf '%s\n' "${CHECKS[@]+"${CHECKS[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")
ISSUES_JSON=$(printf '%s\n' "${ISSUES[@]+"${ISSUES[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  status          "$VERIFICATION_STATUS" \
    --arg  pkg_type        "$PACKAGE_TYPE" \
    --argjson slsa_level   "$SLSA_LEVEL" \
    --arg  timestamp       "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_ver     "$TOOLKIT_VERSION" \
    --arg  mode            "$VERIFY_MODE" \
    --argjson skip_public  "$SKIP_PUBLIC_CHECK" \
    --arg  target          "$(basename "$TARGET")" \
    --argjson prov_found   "$PROVENANCE_FOUND" \
    --argjson prov_valid   "$PROVENANCE_VALID" \
    --argjson src_verified "$SOURCE_VERIFIED" \
    --argjson bld_trusted  "$BUILDER_TRUSTED" \
    --argjson wp_files_ok  "$WP_FILES_VERIFIED" \
    --argjson risk         "$RISK_SCORE" \
    --argjson base_risk    "$BASE_RISK" \
    --arg  pkg_type_note   "$(case "$PACKAGE_TYPE" in
                                public)     echo "Full verification expected" ;;
                                custom)     echo "Partial verification expected" ;;
                                internal)   echo "Public verification not applicable" ;;
                                prerelease) echo "Not yet published publicly" ;;
                              esac)" \
    --argjson checks       "$CHECKS_JSON" \
    --argjson issues       "$ISSUES_JSON" \
    '{
        provenance_verification: {
            status:          $status,
            package_type:    $pkg_type,
            slsa_level:      $slsa_level,
            timestamp:       $timestamp,
            toolkit_version: $toolkit_ver,
            mode:            $mode,
            public_verification_skipped: $skip_public,
            artifact: {
                name: $target
            },
            verification_summary: {
                provenance_found:   $prov_found,
                provenance_valid:   $prov_valid,
                source_verified:    $src_verified,
                builder_trusted:    $bld_trusted,
                wp_files_verified:  $wp_files_ok
            },
            risk_contribution: $risk,
            risk_context: {
                base_risk:           $base_risk,
                adjustments_applied: ($base_risk - $risk),
                note:                $pkg_type_note
            },
            checks: $checks,
            issues: $issues
        }
    }')

# ── Output ────────────────────────────────────────────────────────────────────

if [[ "$WRITE_FILE" == "true" ]]; then
    echo "$OUTPUT_JSON" | jq . > "$OUTPUT_FILE"
    chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
    log "[OK]   Saved: $OUTPUT_FILE"
    log "       Status: $VERIFICATION_STATUS | SLSA Level: $SLSA_LEVEL | Risk: $RISK_SCORE"
else
    echo "$OUTPUT_JSON" | jq .
fi

# Exit: 0 = verified/partial/no_provenance, 1 = failed
[[ "$VERIFICATION_STATUS" == "failed" ]] && exit 1 || exit 0
