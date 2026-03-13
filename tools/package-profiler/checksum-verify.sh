#!/usr/bin/env bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 SBOM Toolkit Contributors

#
# checksum-verify.sh - archive checksum verification with ecosystem API lookup
#
# Usage: checksum-verify.sh [OPTIONS] <target>
#
# Calculates SHA256/384/512 checksums for an archive, auto-detects package
# identity from embedded metadata, looks up expected checksums from the
# upstream ecosystem API, and optionally extracts the archive for further
# inspection by downstream tools.
#
# Output file: ./meta/<clean-name>/<clean-name>.checksum.json
# Extracted files (optional): ./packages/<clean-name>/
#
# Exit codes: 0 = verified or skipped, 1 = mismatch/not found, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

TARGET=""
OUTPUT_DIR=""               # default: ./meta/<clean-name>/ (set after name detection)
EXTRACT=false
EXTRACT_DIR=""              # default: ./packages/<clean-name>/ (set after name detection)
PACKAGES_BASE="./packages"
META_BASE="./meta"
OVERRIDE_PKG_NAME=""        # --pkg-name: pre-seed identity before auto-detection
OVERRIDE_PKG_VERSION=""     # --pkg-version: pre-seed identity before auto-detection
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
SKIP_VERIFY=false
CURL_TIMEOUT=15             # seconds per API call

# Override flags — if provided, skip API lookup for that algorithm
EXPECTED_SHA256=""
EXPECTED_SHA384=""
EXPECTED_SHA512=""

# Source type — auto-detected from archive contents if not specified
SOURCE_TYPE=""              # wordpress | packagist | npm | pypi | github | file

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/chksum_verify_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Verify archive integrity via checksums. Auto-detects package identity from
embedded metadata and looks up expected checksums from the upstream ecosystem
API. Optionally extracts the archive for inspection by downstream tools
(sbom-gen, provenance-verify, sbom-compare, etc.).

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show additional detail
    -o, --output-dir DIR    Directory for JSON output
                            (default: ./meta/<clean-name>/)
    --extract               Extract archive to ./packages/<clean-name>/
    --extract-dir DIR       Extract to a specific directory (implies --extract)
    --packages-base DIR     Base directory for extractions (default: ./packages)
    --meta-base DIR         Base directory for meta output (default: ./meta)
    --no-file               Output JSON to stdout only; do not write file
    --skip                  Skip API verification; calculate hashes only
    --source-type TYPE      Override auto-detected source type:
    --pkg-name NAME         Pre-seed package name (used as fallback if auto-detection fails)
    --pkg-version VERSION   Pre-seed package version (used as fallback if auto-detection fails)
                            wordpress | packagist | npm | pypi | github | file

CHECKSUM OVERRIDE OPTIONS:
    --sha256 HASH           Expected SHA256 (skip API lookup for this algorithm)
    --sha384 HASH           Expected SHA384
    --sha512 HASH           Expected SHA512

ARGUMENTS:
    target                  Archive file (.zip, .tar.gz, .tar.bz2, .tgz)
                            or a plain file to hash without API lookup

OUTPUT FILE:
    ./meta/<clean-name>/<clean-name>.checksum.json

EXTRACTION:
    --extract unpacks the archive to ./packages/<clean-name>/ so downstream
    scripts can work on the directory rather than each re-extracting the
    archive independently. The toolkit controller passes --skip-checksum
    when the target is already a directory.

AUTO-DETECTION:
    Package identity is read from the first matching metadata file found
    inside the archive (without full extraction):
      .zip / .tar.gz    composer.json     → Packagist
                        package.json      → npm
                        *.dist-info/METADATA → PyPI
                        <slug>/<slug>.php with Plugin Name header → WordPress

ECOSYSTEM API LOOKUP:
    Packagist   repo.packagist.org/p2/<vendor>/<n>.json  → dist.shasum
    WordPress   api.wordpress.org/plugins/info/1.2/      → download_link
    npm         registry.npmjs.org/<n>/<version>          → dist.integrity (SHA512 SRI)
    PyPI        pypi.org/pypi/<n>/<version>/json          → urls[].digests.sha256

    Note: Packagist and npm provide SHA1 for older entries; this is recorded
    but not used as the primary verification hash.

EXAMPLES:
    # Auto-detect, verify, write meta JSON
    $(basename "$0") akismet.5.3.zip

    # Auto-detect + extract for downstream tools
    $(basename "$0") --extract akismet.5.3.zip

    # Skip API lookup, calculate hashes only
    $(basename "$0") --skip myplugin.zip

    # Provide expected hash explicitly (no API call)
    $(basename "$0") --sha256 abc123... myplugin.zip

    # Extract to a custom location
    $(basename "$0") --extract-dir /tmp/inspect myplugin.zip

    # WordPress plugin with explicit type
    $(basename "$0") --source-type wordpress contact-form-7.5.9.zip

DEPENDENCIES:
    jq, curl, sha256sum
    sha384sum, sha512sum (optional; noted as unavailable if absent)
    unzip (for .zip archives), tar (for .tar.gz / .tgz / .tar.bz2)

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
    for cmd in jq curl sha256sum; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Missing required commands: ${missing[*]}" >&2
        exit 2
    fi
}

# ── Functions: Naming ─────────────────────────────────────────────────────────

# NOTE: sanitize_name is duplicated verbatim across all toolkit scripts.
# Any changes must be kept in sync with the same function in:
#   dependency-audit.sh, license-check.sh, provenance-verify.sh,
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

# ── Functions: Archive introspection (no full extraction) ────────────────────

zip_read_file() {
    local archive="$1" inner_path="$2"
    unzip -p "$archive" "$inner_path" 2>/dev/null || true
}

tar_read_file() {
    local archive="$1" inner_path="$2"
    local flag="-xzf"
    [[ "$archive" == *.bz2 ]] && flag="-xjf"
    tar "$flag" "$archive" -O "$inner_path" 2>/dev/null || true
}

archive_list_top() {
    local archive="$1"
    if [[ "$archive" == *.zip ]]; then
        unzip -l "$archive" 2>/dev/null \
            | awk 'NR>3 && /\// {print $NF}' \
            | cut -d'/' -f1 | sort -u | grep -v '^$' || true
    else
        # tar -tf auto-detects compression (.gz, .bz2, .xz, .zst, etc.)
        tar -tf "$archive" 2>/dev/null \
            | cut -d'/' -f1 | sort -u | grep -v '^$' || true
    fi
}

# ── Functions: Package identity detection ────────────────────────────────────
# Sets globals: PKG_NAME, PKG_VERSION, PKG_ECOSYSTEM, PKG_VENDOR

detect_package_identity() {
    local archive="$1"

    PKG_NAME=""
    PKG_VERSION=""
    PKG_ECOSYSTEM="file"
    PKG_VENDOR=""

    local top_dir
    top_dir=$(archive_list_top "$archive" | head -n1 || echo "")
    info "Archive top-level directory: ${top_dir:-<root>}"

    # ── composer.json → Packagist ────────────────────────────────────────────
    local content=""
    for path in "composer.json" "${top_dir}/composer.json"; do
        [[ "$archive" == *.zip ]] \
            && content=$(zip_read_file "$archive" "$path") \
            || content=$(tar_read_file "$archive" "$path")
        [[ -n "$content" ]] && break
    done

    if [[ -n "$content" ]] && echo "$content" | jq empty 2>/dev/null; then
        local raw_name
        raw_name=$(echo "$content" | jq -r '.name // ""')
        if [[ "$raw_name" == *"/"* ]]; then
            PKG_VENDOR=$(echo "$raw_name" | cut -d'/' -f1)
            PKG_NAME=$(echo "$raw_name" | cut -d'/' -f2)
        elif [[ -n "$raw_name" ]]; then
            PKG_NAME="$raw_name"
        fi
        PKG_VERSION=$(echo "$content" | jq -r '.version // ""')
        if [[ -n "$PKG_NAME" ]]; then
            PKG_ECOSYSTEM="packagist"
            info "Detected: Packagist ${PKG_VENDOR:+$PKG_VENDOR/}$PKG_NAME $PKG_VERSION"
            return 0
        fi
    fi

    # ── package.json → npm ───────────────────────────────────────────────────
    content=""
    for path in "package.json" "${top_dir}/package.json"; do
        [[ "$archive" == *.zip ]] \
            && content=$(zip_read_file "$archive" "$path") \
            || content=$(tar_read_file "$archive" "$path")
        [[ -n "$content" ]] && break
    done

    if [[ -n "$content" ]] && echo "$content" | jq empty 2>/dev/null; then
        PKG_NAME=$(echo "$content" | jq -r '.name // ""')
        PKG_VERSION=$(echo "$content" | jq -r '.version // ""')
        if [[ -n "$PKG_NAME" ]]; then
            PKG_ECOSYSTEM="npm"
            info "Detected: npm $PKG_NAME $PKG_VERSION"
            return 0
        fi
    fi

    # ── *.dist-info/METADATA → PyPI ──────────────────────────────────────────
    if [[ "$archive" == *.zip ]]; then
        local pypi_path
        pypi_path=$(unzip -l "$archive" 2>/dev/null \
            | awk '{print $NF}' \
            | grep -i '\.dist-info/METADATA$' | head -n1 || echo "")
        if [[ -n "$pypi_path" ]]; then
            local pypi_meta
            pypi_meta=$(zip_read_file "$archive" "$pypi_path")
            PKG_NAME=$(echo "$pypi_meta" \
                | grep -i '^Name:' | head -n1 \
                | sed 's/^[Nn]ame:[[:space:]]*//')
            PKG_VERSION=$(echo "$pypi_meta" \
                | grep -i '^Version:' | head -n1 \
                | sed 's/^[Vv]ersion:[[:space:]]*//')
            if [[ -n "$PKG_NAME" ]]; then
                PKG_ECOSYSTEM="pypi"
                info "Detected: PyPI $PKG_NAME $PKG_VERSION"
                return 0
            fi
        fi
    fi

    # ── WordPress detection: readme.txt, PHP header, or core ────────────────
    # Plugins always ship readme.txt; core ships wp-settings.php + @package WordPress.
    # Try readme.txt first (most reliable for plugins), then PHP header, then core.
    if [[ "$archive" == *.zip ]]; then

        # 1. readme.txt — present in every plugin; Stable tag is the authoritative version.
        #    Require BOTH a "=== Title ===" header AND at least one WordPress-specific
        #    field to avoid mis-classifying non-WP archives that use RST/markdown === syntax.
        local readme_content=""
        for path in "readme.txt" "${top_dir}/readme.txt" \
                    "README.txt" "${top_dir}/README.txt"; do
            readme_content=$(zip_read_file "$archive" "$path" 2>/dev/null || true)
            [[ -n "$readme_content" ]] && break
        done

        if [[ -n "$readme_content" ]] \
           && echo "$readme_content" | grep -qi "^===" \
           && echo "$readme_content" | grep -qiE "^(Stable tag|Requires at least|Tested up to|Contributors):"; then
            local rname rver
            rname=$(echo "$readme_content" \
                | grep -i "^=== " | head -n1 \
                | sed 's/^=== *//;s/ *===.*$//' | tr -d '\r')
            # Stable tag is the canonical released version
            rver=$(echo "$readme_content" \
                | grep -i "^Stable tag:" | head -n1 \
                | sed 's/^[Ss]table tag:[[:space:]]*//' | tr -d '\r ' | head -c 20)
            [[ -z "$rver" ]] && rver=$(echo "$readme_content" \
                | grep -i "^Version:" | head -n1 \
                | sed 's/^[Vv]ersion:[[:space:]]*//' | tr -d '\r ' | head -c 20)
            if [[ -n "$rname" ]]; then
                # Use top_dir as slug (canonical); readme title may have spaces
                PKG_NAME="${top_dir:-$rname}"
                PKG_VERSION="$rver"
                PKG_ECOSYSTEM="wordpress"
                info "Detected: WordPress plugin $PKG_NAME $PKG_VERSION (readme.txt)"
                return 0
            fi
        fi

        # 2. PHP plugin header — fallback when readme.txt is absent or unreadable
        if [[ -n "$top_dir" ]]; then
            local wp_content=""
            local candidates
            candidates=$(unzip -l "$archive" 2>/dev/null \
                | awk '{print $NF}' \
                | grep "^${top_dir}/[^/]*\.php$" || echo "")
            local php_path
            for php_path in "${top_dir}/${top_dir}.php" $candidates; do
                wp_content=$(zip_read_file "$archive" "$php_path" 2>/dev/null || true)
                echo "$wp_content" | grep -qi "Plugin Name:" && break
                wp_content=""
            done
            if [[ -n "$wp_content" ]]; then
                PKG_NAME="$top_dir"
                # Accept both "* Version:" and "Version:" (with or without comment star)
                PKG_VERSION=$(echo "$wp_content" \
                    | grep -i "Version:" | head -n1 \
                    | sed 's/.*Version:[[:space:]]*//' \
                    | tr -d ' */\r' | head -c 20)
                PKG_ECOSYSTEM="wordpress"
                info "Detected: WordPress plugin $PKG_NAME $PKG_VERSION (PHP header)"
                return 0
            fi
        fi

        # 3. WordPress core — identified by wp-settings.php at root or in top_dir,
        #    and @package WordPress in index.php
        local core_marker=""
        for path in "wp-settings.php" "${top_dir}/wp-settings.php"; do
            core_marker=$(zip_read_file "$archive" "$path" 2>/dev/null | head -c 200 || true)
            [[ -n "$core_marker" ]] && break
        done
        if [[ -n "$core_marker" ]]; then
            # Extract version from wp-includes/version.php  $wp_version = 'x.y.z'
            local ver_file=""
            for path in "wp-includes/version.php" "${top_dir}/wp-includes/version.php"; do
                ver_file=$(zip_read_file "$archive" "$path" 2>/dev/null || true)
                [[ -n "$ver_file" ]] && break
            done
            local core_ver=""
            core_ver=$(echo "$ver_file" \
                | grep -i "\$wp_version" | head -n1 \
                | sed "s/.*=[ ]*['\"]//;s/['\"].*//" | tr -d '\r ')
            PKG_NAME="wordpress"
            PKG_VERSION="$core_ver"
            PKG_ECOSYSTEM="wordpress"
            info "Detected: WordPress core ${PKG_VERSION:-unknown}"
            return 0
        fi
    fi

    # ── Fallback: filename only ──────────────────────────────────────────────
    PKG_NAME=$(sanitize_name "$archive")
    PKG_ECOSYSTEM="file"
    log "  [WARN] Could not detect package identity from archive contents"
    log "         Falling back to filename: $PKG_NAME"
    log "         Use --source-type to specify ecosystem explicitly"
    return 0
}

# ── Functions: Checksum calculation ──────────────────────────────────────────

CALC_SHA256="" CALC_SHA384="" CALC_SHA512=""

calculate_checksums() {
    local file="$1"
    CALC_SHA256=$(sha256sum "$file" | cut -d' ' -f1)
    CALC_SHA384=$(sha384sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
    CALC_SHA512=$(sha512sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
    info "SHA256: ${CALC_SHA256:0:16}..."
    [[ "$CALC_SHA384" != "unavailable" ]] && info "SHA384: ${CALC_SHA384:0:16}..."
    [[ "$CALC_SHA512" != "unavailable" ]] && info "SHA512: ${CALC_SHA512:0:16}..."
}

# ── Functions: Ecosystem API lookup ──────────────────────────────────────────
# Each sets: API_SHA256, API_SHA512, API_CHECKSUM_SOURCE, API_DOWNLOAD_URL
# as appropriate for the ecosystem. Returns 1 on lookup failure.

API_SHA256="" API_SHA384="" API_SHA512=""
API_EXTRA_SHA1="" API_CHECKSUM_SOURCE="none" API_DOWNLOAD_URL=""
API_WP_CHECKSUMS_URL="" API_WP_CHECKSUMS_DATA=""

api_lookup_packagist() {
    local vendor="$1" pkg="$2" version="$3"
    local full_name="${vendor}/${pkg}"
    log "  [API]  Packagist: $full_name $version"

    local data
    data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
        "https://repo.packagist.org/p2/${full_name}.json" 2>/dev/null || echo "{}")
    echo "$data" | jq empty 2>/dev/null || { log "  [WARN] Packagist: invalid response"; return 1; }

    local shasum
    shasum=$(echo "$data" | jq -r \
        --arg name "$full_name" --arg ver "$version" \
        '.packages[$name]? // [] |
         .[] | select(.version == $ver or .version == ("v"+$ver)) |
         .dist.shasum // ""' 2>/dev/null | head -n1 || echo "")

    if [[ -n "$shasum" ]]; then
        case ${#shasum} in
            40)  API_EXTRA_SHA1="$shasum"
                 API_CHECKSUM_SOURCE="packagist_api_sha1_only"
                 log "  [INFO] Packagist provides SHA1 only for this entry (recorded, not verified)"
                 ;;
            64)  API_SHA256="$shasum"
                 API_CHECKSUM_SOURCE="packagist_api"
                 log "  [OK]   Packagist SHA256 retrieved"
                 ;;
            *)   log "  [WARN] Packagist: unexpected shasum length (${#shasum})"; return 1 ;;
        esac
    else
        log "  [WARN] Packagist: no shasum for $full_name $version"
        return 1
    fi

    API_DOWNLOAD_URL=$(echo "$data" | jq -r \
        --arg name "$full_name" --arg ver "$version" \
        '.packages[$name]? // [] |
         .[] | select(.version == $ver or .version == ("v"+$ver)) |
         .dist.url // ""' 2>/dev/null | head -n1 || echo "")
}

api_lookup_wordpress() {
    local slug="$1" version="$2"
    log "  [API]  WordPress.org: $slug $version"

    # ── Plugin info API: get download URL ────────────────────────────────────
    local info_data
    info_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
        "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${slug}&request[fields][versions]=1" \
        2>/dev/null || echo "{}")

    local dl_url=""
    if echo "$info_data" | jq empty 2>/dev/null; then
        dl_url=$(echo "$info_data" | jq -r --arg ver "$version" \
            '.versions[$ver] // .download_link // ""' 2>/dev/null || echo "")
    fi

    [[ -z "$dl_url" ]] \
        && dl_url="https://downloads.wordpress.org/plugin/${slug}.${version}.zip"

    API_DOWNLOAD_URL="$dl_url"

    # ── Plugin checksums API: per-file hashes for extracted content ──────────
    # Endpoint: https://downloads.wordpress.org/plugin-checksums/<slug>/<version>.json
    # Returns MD5 and SHA256 hashes for each file inside the extracted plugin,
    # NOT a single hash of the archive itself.
    # These are used for post-extraction file integrity checks, not archive verification.
    local checksums_url="https://downloads.wordpress.org/plugin-checksums/${slug}/${version}.json"
    local checksums_data
    checksums_data=$(curl -fsSL --max-time "$CURL_TIMEOUT" "$checksums_url" 2>/dev/null || echo "{}")

    if echo "$checksums_data" | jq -e '.files' &>/dev/null 2>&1; then
        local file_count
        file_count=$(echo "$checksums_data" | jq '.files | length' 2>/dev/null || echo "0")
        API_WP_CHECKSUMS_URL="$checksums_url"
        API_WP_CHECKSUMS_DATA="$checksums_data"
        API_CHECKSUM_SOURCE="wordpress_file_checksums"
        log "  [OK]   WordPress checksums endpoint: $file_count files covered"
        log "  [INFO] These are per-file hashes for extracted content"
        log "         Archive-level SHA256 is locally calculated only"
    else
        log "  [WARN] WordPress checksums endpoint returned no data for $slug $version"
        log "         URL: $checksums_url"
        API_CHECKSUM_SOURCE="calculated_only"
    fi

    # WordPress provides no single-file hash of the .zip archive itself,
    # so API_SHA256/512 remain unset. The calculated SHA256 is recorded in
    # the output for reference; archive integrity relies on the per-file
    # checksums after extraction (see extraction.wp_file_verification).
}

api_lookup_npm() {
    local pkg="$1" version="$2"
    log "  [API]  npm registry: $pkg $version"

    local data
    data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
        "https://registry.npmjs.org/${pkg}/${version}" 2>/dev/null || echo "{}")
    echo "$data" | jq empty 2>/dev/null || { log "  [WARN] npm registry: invalid response"; return 1; }

    # dist.integrity is SRI format: sha512-<base64>
    local integrity
    integrity=$(echo "$data" | jq -r '.dist.integrity // ""' 2>/dev/null || echo "")

    if [[ "$integrity" == sha512-* ]]; then
        local b64="${integrity#sha512-}"
        local hex
        hex=$(echo "$b64" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "")
        if [[ -n "$hex" ]]; then
            API_SHA512="$hex"
            API_CHECKSUM_SOURCE="npm_registry"
            log "  [OK]   npm SHA512 (from dist.integrity) retrieved"
        fi
    fi

    local shasum
    shasum=$(echo "$data" | jq -r '.dist.shasum // ""' 2>/dev/null || echo "")
    [[ -n "$shasum" ]] && API_EXTRA_SHA1="$shasum"

    API_DOWNLOAD_URL=$(echo "$data" | jq -r '.dist.tarball // ""' 2>/dev/null || echo "")
}

api_lookup_pypi() {
    local pkg="$1" version="$2"
    log "  [API]  PyPI: $pkg $version"

    local data
    data=$(curl -fsSL --max-time "$CURL_TIMEOUT" \
        "https://pypi.org/pypi/${pkg}/${version}/json" 2>/dev/null || echo "{}")
    echo "$data" | jq empty 2>/dev/null || { log "  [WARN] PyPI API: invalid response"; return 1; }

    local sha256
    # Prefer sdist; fall back to first available file
    sha256=$(echo "$data" | jq -r '
        ( .urls[] | select(.packagetype=="sdist") | .digests.sha256 ),
        ( .urls[0].digests.sha256 )
        ' 2>/dev/null | grep -v '^null$' | head -n1 || echo "")

    if [[ -n "$sha256" ]]; then
        API_SHA256="$sha256"
        API_CHECKSUM_SOURCE="pypi_api"
        log "  [OK]   PyPI SHA256 retrieved"
    else
        log "  [WARN] PyPI: no SHA256 for $pkg $version"
        return 1
    fi

    API_DOWNLOAD_URL=$(echo "$data" | jq -r '.urls[0].url // ""' 2>/dev/null || echo "")
}

# ── Functions: Extraction ─────────────────────────────────────────────────────

extract_archive() {
    local archive="$1" dest="$2"
    log "[EXTR] Extracting: $(basename "$archive") → $dest"
    mkdir -p "$dest"

    local status=0
    if [[ "$archive" == *.zip ]]; then
        command -v unzip &>/dev/null || die "unzip is required for .zip extraction"
        unzip -q "$archive" -d "$dest" 2>/dev/null || status=$?
    elif [[ "$archive" == *.tar.gz ]] || [[ "$archive" == *.tgz ]]; then
        tar -xzf "$archive" -C "$dest" 2>/dev/null || status=$?
    elif [[ "$archive" == *.tar.bz2 ]] || [[ "$archive" == *.tbz2 ]]; then
        tar -xjf "$archive" -C "$dest" 2>/dev/null || status=$?
    elif [[ "$archive" == *.tar.xz ]] || [[ "$archive" == *.txz ]]; then
        tar -xJf "$archive" -C "$dest" 2>/dev/null || status=$?
    elif [[ "$archive" == *.tar.zst ]] || [[ "$archive" == *.tzst ]]; then
        tar --use-compress-program=zstd -xf "$archive" -C "$dest" 2>/dev/null || status=$?
    elif [[ "$archive" == *.tar ]]; then
        tar -xf "$archive" -C "$dest" 2>/dev/null || status=$?
    else
        log "  [WARN] Unrecognised archive format — attempting generic tar -xf"
        tar -xf "$archive" -C "$dest" 2>/dev/null || status=$?
    fi

    [[ "$status" -ne 0 ]] \
        && log "  [WARN] Extraction completed with warnings (status $status)" \
        || log "[OK]   Extracted to $dest ($(find "$dest" -type f | wc -l) files)"
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
        --extract)       EXTRACT=true; shift ;;
        --extract-dir)
            [[ -z "${2:-}" ]] && die "--extract-dir requires an argument"
            EXTRACT=true; EXTRACT_DIR="$2"; shift 2 ;;
        --packages-base)
            [[ -z "${2:-}" ]] && die "--packages-base requires an argument"
            PACKAGES_BASE="$2"; shift 2 ;;
        --meta-base)
            [[ -z "${2:-}" ]] && die "--meta-base requires an argument"
            META_BASE="$2"; shift 2 ;;
        --no-file)       WRITE_FILE=false; shift ;;
        --skip)          SKIP_VERIFY=true; shift ;;
        --pkg-name)
            [[ -z "${2:-}" ]] && die "--pkg-name requires an argument"
            OVERRIDE_PKG_NAME="$2"; shift 2 ;;
        --pkg-version)
            [[ -z "${2:-}" ]] && die "--pkg-version requires an argument"
            OVERRIDE_PKG_VERSION="$2"; shift 2 ;;
        --source-type)
            [[ -z "${2:-}" ]] && die "--source-type requires an argument"
            SOURCE_TYPE="$2"
            [[ "$SOURCE_TYPE" =~ ^(wordpress|packagist|npm|pypi|github|file)$ ]] \
                || die "Invalid source-type. Use: wordpress, packagist, npm, pypi, github, file"
            shift 2 ;;
        --sha256)
            [[ -z "${2:-}" ]] && die "--sha256 requires an argument"
            EXPECTED_SHA256="$2"; shift 2 ;;
        --sha384)
            [[ -z "${2:-}" ]] && die "--sha384 requires an argument"
            EXPECTED_SHA384="$2"; shift 2 ;;
        --sha512)
            [[ -z "${2:-}" ]] && die "--sha512 requires an argument"
            EXPECTED_SHA512="$2"; shift 2 ;;
        --version)
            echo "checksum-verify.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*)  die "Unknown option: $1 (use --help for usage)" ;;
        *)   TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$TARGET" ]] && die "No target specified (use --help for usage)"
[[ ! -f "$TARGET" ]] && die "Target file not found: $TARGET"

check_dependencies

CLEAN_NAME=$(sanitize_name "$TARGET")
[[ -z "$OUTPUT_DIR"  ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"
[[ -z "$EXTRACT_DIR" ]] && EXTRACT_DIR="${PACKAGES_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.checksum.json"
log "[CHKSUM] $(basename "$TARGET")"

# ── Checksums ─────────────────────────────────────────────────────────────────

log "[HASH] Calculating checksums..."
calculate_checksums "$TARGET"

# ── Identity detection ────────────────────────────────────────────────────────

log "[IDENT] Detecting package identity..."
detect_package_identity "$TARGET"

# --source-type overrides auto-detected ecosystem
[[ -n "$SOURCE_TYPE" ]] && PKG_ECOSYSTEM="$SOURCE_TYPE"

# --pkg-name / --pkg-version fill in identity when auto-detection fails or is incomplete.
# These do NOT override a successfully detected value — they only apply when the
# detection left the field empty. This means a well-structured archive still uses
# its own metadata; the flags are a fallback for unusual packaging.
[[ -z "$PKG_NAME"    && -n "$OVERRIDE_PKG_NAME"    ]] && PKG_NAME="$OVERRIDE_PKG_NAME"
[[ -z "$PKG_VERSION" && -n "$OVERRIDE_PKG_VERSION" ]] && PKG_VERSION="$OVERRIDE_PKG_VERSION"

log "  Name:      ${PKG_NAME:-unknown}"
log "  Version:   ${PKG_VERSION:-unknown}"
log "  Ecosystem: $PKG_ECOSYSTEM"
[[ -n "$PKG_VENDOR" ]] && log "  Vendor:    $PKG_VENDOR"

# ── API lookup or override ────────────────────────────────────────────────────

if [[ "$SKIP_VERIFY" == "false" ]]; then

    # Explicit overrides take precedence over API
    if [[ -n "$EXPECTED_SHA256" ]]; then
        API_SHA256="$EXPECTED_SHA256"; API_CHECKSUM_SOURCE="provided"
    fi
    if [[ -n "$EXPECTED_SHA384" ]]; then
        API_SHA384="$EXPECTED_SHA384"; API_CHECKSUM_SOURCE="provided"
    fi
    if [[ -n "$EXPECTED_SHA512" ]]; then
        API_SHA512="$EXPECTED_SHA512"; API_CHECKSUM_SOURCE="provided"
    fi

    # API lookup if no overrides and identity is sufficiently known
    if [[ "$API_CHECKSUM_SOURCE" == "none" ]] \
       && [[ -n "$PKG_NAME" ]] \
       && [[ -n "$PKG_VERSION" ]]; then

        log "[API]  Looking up reference checksums..."
        case "$PKG_ECOSYSTEM" in
            packagist) api_lookup_packagist "${PKG_VENDOR:-}" "$PKG_NAME" "$PKG_VERSION" \
                           || log "  [WARN] Packagist API lookup failed" ;;
            wordpress) api_lookup_wordpress "$PKG_NAME" "$PKG_VERSION" \
                           || log "  [WARN] WordPress API lookup failed" ;;
            npm)       api_lookup_npm "$PKG_NAME" "$PKG_VERSION" \
                           || log "  [WARN] npm registry lookup failed" ;;
            pypi)      api_lookup_pypi "$PKG_NAME" "$PKG_VERSION" \
                           || log "  [WARN] PyPI API lookup failed" ;;
            *)         log "  [INFO] No API lookup for ecosystem: $PKG_ECOSYSTEM"
                       log "         Use --sha256 to provide a reference checksum"
                       API_CHECKSUM_SOURCE="calculated_only" ;;
        esac
    elif [[ "$API_CHECKSUM_SOURCE" == "none" ]]; then
        log "  [WARN] Package identity incomplete — skipping API lookup"
        API_CHECKSUM_SOURCE="calculated_only"
    fi
fi

# ── Verification ──────────────────────────────────────────────────────────────

CHECKSUM_STATUS="not_performed"
OVERALL_VERIFIED=false
ISSUES_ARR=()
CHECKS_ARR=()

if [[ "$SKIP_VERIFY" == "true" ]]; then
    CHECKSUM_STATUS="skipped"
    log "[INFO] Verification skipped (--skip)"
else
    MATCHED=0 CHECKED=0

    # SHA256
    if [[ -n "$API_SHA256" ]]; then
        ((CHECKED++))
        if [[ "${API_SHA256,,}" == "${CALC_SHA256,,}" ]]; then
            log "  [OK]   SHA256 verified"
            ((MATCHED++))
            CHECKS_ARR+=('{"algorithm":"SHA256","status":"matched"}')
        else
            log "  [FAIL] SHA256 MISMATCH"
            info "         Expected: $API_SHA256"
            info "         Got:      $CALC_SHA256"
            ISSUES_ARR+=("$(jq -n \
                --arg alg "SHA256" --arg exp "$API_SHA256" --arg got "$CALC_SHA256" \
                '{type:"checksum_mismatch",severity:"CRITICAL",
                  algorithm:$alg,expected:$exp,actual:$got}')")
            CHECKS_ARR+=('{"algorithm":"SHA256","status":"mismatch"}')
        fi
    fi

    # SHA384 (only if API provided one — currently no ecosystem does, but --sha384 override works)
    if [[ -n "$API_SHA384" ]] && [[ "$CALC_SHA384" != "unavailable" ]]; then
        ((CHECKED++))
        if [[ "${API_SHA384,,}" == "${CALC_SHA384,,}" ]]; then
            log "  [OK]   SHA384 verified"
            ((MATCHED++))
            CHECKS_ARR+=('{"algorithm":"SHA384","status":"matched"}')
        else
            log "  [FAIL] SHA384 MISMATCH"
            ISSUES_ARR+=("$(jq -n \
                --arg alg "SHA384" --arg exp "$API_SHA384" --arg got "$CALC_SHA384" \
                '{type:"checksum_mismatch",severity:"CRITICAL",
                  algorithm:$alg,expected:$exp,actual:$got}')")
            CHECKS_ARR+=('{"algorithm":"SHA384","status":"mismatch"}')
        fi
    fi

    # SHA512
    if [[ -n "$API_SHA512" ]] && [[ "$CALC_SHA512" != "unavailable" ]]; then
        ((CHECKED++))
        if [[ "${API_SHA512,,}" == "${CALC_SHA512,,}" ]]; then
            log "  [OK]   SHA512 verified"
            ((MATCHED++))
            CHECKS_ARR+=('{"algorithm":"SHA512","status":"matched"}')
        else
            log "  [FAIL] SHA512 MISMATCH"
            ISSUES_ARR+=("$(jq -n \
                --arg alg "SHA512" --arg exp "$API_SHA512" --arg got "$CALC_SHA512" \
                '{type:"checksum_mismatch",severity:"CRITICAL",
                  algorithm:$alg,expected:$exp,actual:$got}')")
            CHECKS_ARR+=('{"algorithm":"SHA512","status":"mismatch"}')
        fi
    fi

    if [[ "$CHECKED" -eq 0 ]]; then
        CHECKSUM_STATUS="no_reference_available"
        log "  [INFO] No reference checksums available for comparison"
        log "         Hashes recorded; use --sha256 to provide a reference"
    elif [[ "$MATCHED" -eq "$CHECKED" ]]; then
        CHECKSUM_STATUS="verified"
        OVERALL_VERIFIED=true
        log "[OK]   All checksums verified ($MATCHED/$CHECKED)"
    else
        CHECKSUM_STATUS="failed"
        log "[FAIL] Checksum verification FAILED ($MATCHED/$CHECKED matched)"
    fi
fi

# ── Risk score ────────────────────────────────────────────────────────────────

RISK_SCORE=0
[[ "$CHECKSUM_STATUS" == "failed" ]]              && RISK_SCORE=$((RISK_SCORE + 500))
[[ "$CHECKSUM_STATUS" == "no_reference_available" ]] && RISK_SCORE=$((RISK_SCORE + 50))

# ── Extraction ────────────────────────────────────────────────────────────────

EXTRACTED=false
EXTRACTED_PATH=""

if [[ "$EXTRACT" == "true" ]]; then
    extract_archive "$TARGET" "$EXTRACT_DIR"
    EXTRACTED=true
    EXTRACTED_PATH="$(cd "$EXTRACT_DIR" && pwd)"
fi

# ── Build and emit JSON ───────────────────────────────────────────────────────

ISSUES_JSON=$(printf '%s\n' "${ISSUES_ARR[@]+"${ISSUES_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")
CHECKS_JSON=$(printf '%s\n' "${CHECKS_ARR[@]+"${CHECKS_ARR[@]}"}" \
    | jq -s '.' 2>/dev/null || echo "[]")

OUTPUT_JSON=$(jq -n \
    --arg  target           "$(basename "$TARGET")" \
    --arg  timestamp        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg  toolkit_version  "$TOOLKIT_VERSION" \
    --arg  pkg_name         "${PKG_NAME:-}" \
    --arg  pkg_version      "${PKG_VERSION:-}" \
    --arg  pkg_ecosystem    "$PKG_ECOSYSTEM" \
    --arg  pkg_vendor       "${PKG_VENDOR:-}" \
    --arg  sha256           "$CALC_SHA256" \
    --arg  sha384           "$CALC_SHA384" \
    --arg  sha512           "$CALC_SHA512" \
    --arg  chk_status       "$CHECKSUM_STATUS" \
    --argjson chk_verified  "$OVERALL_VERIFIED" \
    --arg  chk_source       "$API_CHECKSUM_SOURCE" \
    --arg  ref_sha256       "${API_SHA256:-}" \
    --arg  ref_sha512       "${API_SHA512:-}" \
    --arg  sha1_noted       "${API_EXTRA_SHA1:-}" \
    --arg  api_dl_url       "${API_DOWNLOAD_URL:-}" \
    --arg  wp_checksums_url "${API_WP_CHECKSUMS_URL:-}" \
    --argjson risk          "$RISK_SCORE" \
    --argjson extracted     "$EXTRACTED" \
    --arg  extracted_dir    "$(basename "${EXTRACTED_PATH:-}")" \
    --arg  extracted_path   "${EXTRACTED_PATH:-}" \
    --argjson issues        "$ISSUES_JSON" \
    --argjson checks        "$CHECKS_JSON" \
    '{
        crypto_verification: {
            target:           $target,
            timestamp:        $timestamp,
            toolkit_version:  $toolkit_version,
            package_identity: {
                name:      $pkg_name,
                version:   $pkg_version,
                ecosystem: $pkg_ecosystem,
                vendor:    $pkg_vendor
            },
            calculated_checksums: {
                sha256: $sha256,
                sha384: $sha384,
                sha512: $sha512
            },
            verification: {
                status:           $chk_status,
                verified:         $chk_verified,
                checksum_source:  $chk_source,
                reference_sha256: $ref_sha256,
                reference_sha512: $ref_sha512,
                sha1_noted:       $sha1_noted,
                api_download_url: $api_dl_url,
                wp_file_checksums_url: $wp_checksums_url,
                checks:           $checks
            },
            extraction: {
                performed:      $extracted,
                directory_name: $extracted_dir,
                path:           $extracted_path
            },
            risk_contribution: $risk,
            issues:            $issues
        }
    }')

if [[ "$WRITE_FILE" == "true" ]]; then
    echo "$OUTPUT_JSON" | jq . > "$OUTPUT_FILE"
    chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
    log "[OK]   Saved: $OUTPUT_FILE"
else
    echo "$OUTPUT_JSON" | jq .
fi

[[ "$CHECKSUM_STATUS" == "failed" ]] && exit 1 || exit 0
