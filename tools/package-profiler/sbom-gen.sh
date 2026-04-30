#!/usr/bin/env bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 SBOM Toolkit Contributors

#
# sbom-gen.sh - generate SBOMs for provenance tracking & vulnerability scans
#
# Usage: sbom-gen.sh [OPTIONS] <target>
#
# Generates SPDX and/or CycloneDX SBOMs using Syft, with provenance metadata.
# Output files go to --output-dir (default: current directory).
#
# Exit codes: 0 = success, 1 = SBOM generation failed, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# ── Default configuration ────────────────────────────────────────────────────

OUTPUT_FORMAT="both"        # spdx | cyclonedx | both
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILES=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
TIMEOUT_SECONDS=120
TRACK_PROVENANCE=true
TARGET_INPUT=""

# ── Cleanup trap ─────────────────────────────────────────────────────────────

PROV_FILE=""
cleanup() {
    [[ -n "$PROV_FILE" ]] && rm -f "$PROV_FILE"
    rm -f /tmp/sbom_gen_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Generate Software Bill of Materials (SBOM) with supply chain provenance metadata.
Produces SPDX JSON, CycloneDX JSON, or both formats via Syft.

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output (provenance block) to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show additional detail
    -f, --format FORMAT     Output format: spdx, cyclonedx, both (default: both)
    -t, --timeout SECONDS   Syft scan timeout in seconds (default: 120)
    -o, --output-dir DIR    Directory for output files (default: current dir)
    --no-files              Output to stdout only; do not write files
    --no-provenance         Skip provenance metadata collection
    --version               Print version and exit

ARGUMENTS:
    target                  File, directory, or container image to scan

OUTPUT FILES:
    <output-dir>/<name>.spdx.json      SPDX 2.3 JSON (license/compliance focus)
    <output-dir>/<name>.cdx.json       CycloneDX 1.5 JSON (security/vuln focus)

    Both files include an embedded provenance block with:
      - Generator tool and version
      - Scan timestamp
      - Syft version
      - Source hash (SHA256 of file, or directory tree hash)
      - Git commit/remote/dirty flag (if target is a git repo)
      - Scan parameters

PROVENANCE TRACKING:
    Git metadata is collected automatically when the target is a git repository.
    File and directory hashes use SHA256. Set --no-provenance to omit this block.

ENVIRONMENT:
    SYFT_ARGS    Additional arguments passed to Syft (e.g. '--scope all-layers')

EXAMPLES:
    # Generate both formats with provenance
    $(basename "$0") ./my-plugin

    # SPDX only, custom output directory
    $(basename "$0") -f spdx -o ./sboms ./my-plugin

    # CycloneDX to stdout (no file)
    $(basename "$0") --no-files -f cyclonedx ./my-plugin

    # Container image
    $(basename "$0") -t 300 nginx:latest

DEPENDENCIES:
    syft   https://github.com/anchore/syft
    jq

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
    for cmd in syft jq; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Missing required commands: ${missing[*]}" >&2
        echo "  syft: https://github.com/anchore/syft" >&2
        exit 2
    fi
}

# ── Functions: Naming ─────────────────────────────────────────────────────────

# NOTE: sanitize_name is duplicated verbatim across all toolkit scripts.
# Any changes must be kept in sync with the same function in:
#   checksum-verify.sh, dependency-audit.sh, license-check.sh,
#   provenance-verify.sh, sbom-compare.sh, sbom-discover.sh,
#   sbom-toolkit.sh, slsa-attest.sh
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

# _is_hash_version VALUE
# Returns 0 (true) if VALUE looks like a content hash rather than a version string.
# Syft uses SHA256 hashes as metadata.component.version when no semantic version
# can be determined from archive contents.
_is_hash_version() {
    local v="$1"
    # Bare hex hash (32+ chars, upper or lower): raw SHA-256/SHA-512 hex
    [[ ${#v} -ge 32 ]] && [[ "$v" =~ ^[0-9a-fA-F]+$ ]] && return 0
    # Digest-prefixed form: "sha256:abcdef...", "sha512:...", "md5:..."
    [[ "$v" =~ ^(sha256|sha512|sha384|sha1|md5)[_:][0-9a-fA-F]{16,}$ ]] && return 0
    return 1
}

# extract_version_from_sbom FILE
# Reads a generated SPDX or CycloneDX JSON and returns the root package version.
# Returns empty string if not found — callers must handle the empty case.
extract_version_from_sbom() {
    local file="$1"
    local ver=""

    # CycloneDX: metadata.component.version
    ver=$(jq -r '.metadata.component.version // ""' "$file" 2>/dev/null || echo "")
    if [[ -n "$ver" && "$ver" != "null" ]] && ! _is_hash_version "$ver"; then
        echo "$ver"; return
    fi

    # SPDX: packages[documentDescribes[0]].versionInfo
    ver=$(jq -r '
        (.documentDescribes[0] // "") as $root |
        (.packages[] | select(.SPDXID == $root) | .versionInfo) // ""
    ' "$file" 2>/dev/null || echo "")
    if [[ -n "$ver" && "$ver" != "null" ]] && ! _is_hash_version "$ver"; then
        echo "$ver"; return
    fi

    echo ""
}

# ── Functions: Provenance ─────────────────────────────────────────────────────

collect_provenance() {
    local target="$1"
    local out_file="$2"

    log "  [PROV] Collecting provenance metadata..."

    local git_sha="unknown"
    local git_remote="unknown"
    local git_dirty="false"

    if [[ -d "$target" ]]; then
        if git -C "$target" rev-parse --git-dir &>/dev/null 2>&1; then
            git_sha=$(git -C "$target" rev-parse HEAD 2>/dev/null || echo "unknown")
            git_remote=$(git -C "$target" config --get remote.origin.url 2>/dev/null || echo "unknown")
            if ! git -C "$target" diff-index --quiet HEAD -- 2>/dev/null; then
                git_dirty="true"
            fi
        fi
    fi

    local target_hash="unknown"
    if [[ -f "$target" ]]; then
        target_hash=$(sha256sum "$target" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    elif [[ -d "$target" ]]; then
        # Reproducible directory hash: sorted SHA256 of all files
        target_hash=$(find "$target" -type f -exec sha256sum {} \; 2>/dev/null \
                      | sort -k2 | sha256sum | cut -d' ' -f1 || echo "unknown")
    fi

    local syft_version
    syft_version=$(syft version 2>/dev/null | head -n1 | awk '{print $NF}' || echo "unknown")

    local display_name
    display_name=$(basename "$target")

    # Use jq -n for safe construction — no string interpolation of untrusted values
    jq -n \
        --arg gen_name    "sbom-gen.sh" \
        --arg gen_version "$VERSION" \
        --arg toolkit_ver "$TOOLKIT_VERSION" \
        --arg timestamp   "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg syft_ver    "$syft_version" \
        --arg location    "$display_name" \
        --arg hash_algo   "SHA256" \
        --arg hash_val    "$target_hash" \
        --arg git_sha     "$git_sha" \
        --arg git_remote  "$git_remote" \
        --argjson git_dirty "$git_dirty" \
        --argjson timeout  "$TIMEOUT_SECONDS" \
        --arg format      "$OUTPUT_FORMAT" \
        --arg syft_args   "${SYFT_ARGS:-none}" \
        '{
            provenance: {
                generator: {
                    name:           $gen_name,
                    version:        $gen_version,
                    toolkit_version: $toolkit_ver
                },
                timestamp: $timestamp,
                tools: {
                    syft: $syft_ver
                },
                source: {
                    location: $location,
                    hash: {
                        algorithm: $hash_algo,
                        value:     $hash_val
                    },
                    git: {
                        commit: $git_sha,
                        remote: $git_remote,
                        dirty:  $git_dirty
                    }
                },
                scan_parameters: {
                    timeout_seconds: $timeout,
                    format:          $format,
                    syft_args:       $syft_args
                }
            }
        }' > "$out_file"
}

# ── Functions: SBOM Generation ───────────────────────────────────────────────

# generate_sbom FORMAT OUTPUT_FILE TARGET PROV_FILE
# FORMAT: "spdx-json" or "cyclonedx-json"
# Returns 0 on success, 1 on failure (non-fatal to caller when running parallel)
generate_sbom() {
    local format="$1"
    local output_file="$2"
    local target="$3"
    local prov_file="$4"

    local label
    case "$format" in
        spdx-json)      label="SPDX" ;;
        cyclonedx-json) label="CycloneDX" ;;
        *)              label="$format" ;;
    esac

    log "[SCAN] Scanning [$label]: $(basename "$target")..."

    local tmp_raw tmp_clean
    tmp_raw=$(mktemp -t sbom_gen_raw_XXXXXX.json)
    tmp_clean=$(mktemp -t sbom_gen_clean_XXXXXX.json)

    # Build Syft command
    local -a syft_cmd=(syft scan "$target" -q -o "$format")
    if [[ -n "${SYFT_ARGS:-}" ]]; then
        # SC2206: intentional word-split of user-supplied extra args
        # shellcheck disable=SC2206
        syft_cmd+=($SYFT_ARGS)
    fi

    # Run Syft with timeout
    local syft_status=0
    timeout "${TIMEOUT_SECONDS}s" "${syft_cmd[@]}" > "$tmp_raw" 2>/dev/null || syft_status=$?

    if [[ "$syft_status" -eq 124 ]]; then
        log "[FAIL] $label: Syft timed out after ${TIMEOUT_SECONDS}s (try -t to increase)"
        rm -f "$tmp_raw" "$tmp_clean"
        return 1
    fi

    if [[ "$syft_status" -ne 0 ]]; then
        log "[FAIL] $label: Syft exited with status $syft_status"
        rm -f "$tmp_raw" "$tmp_clean"
        return 1
    fi

    if [[ ! -s "$tmp_raw" ]]; then
        log "[FAIL] $label: Syft produced an empty file"
        rm -f "$tmp_raw" "$tmp_clean"
        return 1
    fi

    # Post-process: sanitize absolute/relative paths + merge provenance.
    # Syft embeds the scan target path in several fields. Treatment is field-specific:
    #   .name (doc level)          — basename if the value is a filesystem path
    #   .packages[].name           — basename_if_path only (is_path rejects "vendor/pkg"
    #                                 style names — only real paths starting with /, ../, ./
    #                                 are reduced; namespaced identifiers are preserved)
    #   .packages[].fileName       — basename if path-like
    #   .packages[].sourceInfo     — prose sentence; path portion replaced with [local cache]
    #   .packages[].SPDXID         — fix_spdxid for DocumentRoot entries only
    #   .relationships[].{spdxElementId,relatedSpdxElement} — same
    local sanitize_filter
    sanitize_filter=$(cat << 'JQEOF'
      # is_path: true for strings that are filesystem paths (absolute or relative).
      # Legitimate package names (e.g. "guzzlehttp/guzzle") do NOT start with
      # /, ../, or ./ so they are never treated as paths.
      def is_path:
        type == "string"
        and (startswith("/") or startswith("../") or startswith("./"));

      # basename_if_path: reduce a path-like string to its last component.
      def basename_if_path:
        if is_path then split("/") | last else . end;

      # redact_sourceinfo: replace any path token embedded in a prose sentence
      # with the literal string [local cache].
      def redact_sourceinfo:
        if type == "string"
        then gsub("(?:/?\\.\\.?/|(?<=\\s)/)[^\\s\"]+"; "[local cache]")
        else . end;

      # fix_spdxid: DocumentRoot IDs embed path traversal as dash segments.
      # e.g. SPDXRef-DocumentRoot-Directory-..-packages-akismet
      #   →  SPDXRef-DocumentRoot-Directory-akismet
      def fix_spdxid:
        if type == "string"
           and startswith("SPDXRef-DocumentRoot-Directory-")
        then "SPDXRef-DocumentRoot-Directory-"
             + (ltrimstr("SPDXRef-DocumentRoot-Directory-") | split("-") | last)
        else . end;

      # zero_hash: true for Syft's all-zero placeholder hash values.
      # Syft emits these for synthetic/virtual packages it cannot hash (e.g. OS packages
      # reconstructed from manifests). They carry no information and pollute the SBOM.
      def zero_hash:
        type == "string" and test("^0+$");

      # observer_disclaimer: canonical notice embedded in every generated SBOM.
      # This makes the observer status of the SBOM explicit and machine-readable.
      def observer_disclaimer:
        "This SBOM was generated by an automated analysis tool acting as an observer. It records software composition facts derived from scanning the artifact, but cannot attest to the hermeticity of the build environment, the integrity of the build platform, or the completeness of dependency resolution. Where an authoritative SBOM is available from the original publisher, that document should be considered the primary source of truth.";

      # sanitize_occurrence_location: CDX evidence.occurrences[].location
      # contains absolute scanner-root paths. Reduce to basename only.
      def sanitize_occurrence_location:
        if type == "string" and (startswith("/") or (split("/") | length > 1))
        then split("/") | last
        else . end;

      # Apply field-specific transforms. Package .name is intentionally excluded
      # to preserve namespaced identifiers (Composer: vendor/pkg, GA: owner/repo).
      .name |= basename_if_path

      # ── SPDX-specific sanitization ──────────────────────────────────────────
      | if .spdxVersion then
          # documentNamespace embeds the scanner's filesystem path; replace path
          # component with a stable token while preserving the UUID suffix.
          .documentNamespace |= (
            if type == "string" then
              gsub("(?<prefix>https://[a-zA-Z0-9._/-]+/syft/(?:dir|file)/)(?<path>.+?)(?<uuid>-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)";
                   "\(.prefix)[scanner]\(.uuid)")
              | gsub("(?<prefix>https://[a-zA-Z0-9._/-]+/syft/(?:dir|file)/)(?<path>[^-]+(?:-[^-]+)*$)";
                     "\(.prefix)[scanner]")
            else . end
          )
          # Embed the observer disclaimer as a top-level document comment
          | .documentComment = observer_disclaimer
          | if .packages then
              .packages |= map(
                  .name       |= basename_if_path
                | .fileName   |= basename_if_path
                | .sourceInfo |= redact_sourceinfo
                | .SPDXID     |= fix_spdxid
                | if .checksums then
                    .checksums |= map(select(.checksumValue | zero_hash | not))
                  else . end
              )
            else . end
          | if .relationships then
              .relationships |= map(
                  .spdxElementId      |= fix_spdxid
                | .relatedSpdxElement |= fix_spdxid
              )
            else . end

        # ── CycloneDX-specific sanitization ─────────────────────────────────
        else
          # Sanitize metadata.component fields
          (if .metadata.component then
            .metadata.component.name |= basename_if_path
            | .metadata.component["bom-ref"] |= (
                if type == "string" then
                  gsub("^(?:dir|file):(?<p>.+)$"; "scanner:" + (.p | split("/") | last))
                else . end
              )
           else . end)

          # Embed observer disclaimer as a metadata property
          | .metadata.properties = ((.metadata.properties // []) +
              [{"name": "observer:disclaimer", "value": observer_disclaimer}])

          | if .components then
              .components |= map(
                  .name |= basename_if_path
                | if .hashes then
                    .hashes |= map(select(.value | zero_hash | not))
                  else . end
                # evidence.occurrences[].location — absolute scanner paths
                | if .evidence.occurrences then
                    .evidence.occurrences |= map(
                      .location |= sanitize_occurrence_location
                    )
                  else . end
              )
            else . end
        end
JQEOF
)

    local jq_status=0
    if [[ "$TRACK_PROVENANCE" == "true" ]] && [[ -f "$prov_file" ]]; then
        jq --slurpfile prov "$prov_file" \
            "$sanitize_filter | . + \$prov[0]" \
            "$tmp_raw" > "$tmp_clean" 2>/dev/null || jq_status=$?
    else
        jq "$sanitize_filter" \
            "$tmp_raw" > "$tmp_clean" 2>/dev/null || jq_status=$?
    fi

    if [[ "$jq_status" -ne 0 ]]; then
        log "[WARN] $label: jq post-processing failed — saving raw output"
        cp "$tmp_raw" "$tmp_clean"
    fi

    if [[ "$WRITE_FILES" == "true" ]]; then
        mv "$tmp_clean" "$output_file"
        chmod 664 "$output_file" 2>/dev/null || true
        log "[OK]   $label: $(basename "$output_file")"
    else
        cat "$tmp_clean"
        rm -f "$tmp_clean"
    fi

    rm -f "$tmp_raw"
    info "$label generation complete"
    return 0
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
            [[ "$OUTPUT_FORMAT" =~ ^(spdx|cyclonedx|both)$ ]] \
                || die "Invalid format '$OUTPUT_FORMAT'. Use: spdx, cyclonedx, both"
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
        --no-files)
            WRITE_FILES=false; shift ;;
        --no-provenance)
            TRACK_PROVENANCE=false; shift ;;
        --version)
            echo "sbom-gen.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*)
            die "Unknown option: $1 (use --help for usage)" ;;
        *)
            TARGET_INPUT="$1"; shift ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────

[[ -z "$TARGET_INPUT" ]] && die "No target specified (use --help for usage)"

check_dependencies

# Determine clean name (base name of target, archive extension stripped)
CLEAN_NAME=$(sanitize_name "$TARGET_INPUT")

# Default output dir: ./meta/<clean-name>/ — consistent with all other toolkit scripts
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

# Resolve output directory
if [[ "$WRITE_FILES" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
    [[ -w "$OUTPUT_DIR" ]] \
        || die "Output directory is not writable: $OUTPUT_DIR"
fi

# Initial output file paths — may be renamed after generation if version is found
SPDX_FILE="$OUTPUT_DIR/${CLEAN_NAME}.spdx.json"
CDX_FILE="$OUTPUT_DIR/${CLEAN_NAME}.cdx.json"

log "--- SBOM Generation: $CLEAN_NAME ---"

# ── Provenance collection ─────────────────────────────────────────────────────

if [[ "$TRACK_PROVENANCE" == "true" ]]; then
    PROV_FILE=$(mktemp -t sbom_gen_prov_XXXXXX.json)
    collect_provenance "$TARGET_INPUT" "$PROV_FILE"
fi

# ── SBOM generation (parallel where possible) ────────────────────────────────

SUCCESS=true

if [[ "$OUTPUT_FORMAT" == "both" ]]; then
    # Run both formats in parallel; capture PIDs
    generate_sbom "spdx-json"      "$SPDX_FILE" "$TARGET_INPUT" "${PROV_FILE:-}" &
    PID_SPDX=$!
    generate_sbom "cyclonedx-json" "$CDX_FILE"  "$TARGET_INPUT" "${PROV_FILE:-}" &
    PID_CDX=$!

    # Wait for each and check exit status
    wait "$PID_SPDX" || { log "[FAIL] SPDX generation failed"; SUCCESS=false; }
    wait "$PID_CDX"  || { log "[FAIL] CycloneDX generation failed"; SUCCESS=false; }

elif [[ "$OUTPUT_FORMAT" == "spdx" ]]; then
    generate_sbom "spdx-json" "$SPDX_FILE" "$TARGET_INPUT" "${PROV_FILE:-}" \
        || SUCCESS=false

elif [[ "$OUTPUT_FORMAT" == "cyclonedx" ]]; then
    generate_sbom "cyclonedx-json" "$CDX_FILE" "$TARGET_INPUT" "${PROV_FILE:-}" \
        || SUCCESS=false
fi

# ── Version suffix: rename outputs if version can be extracted ───────────────
# For targets like latest.zip where the filename carries no version, we read
# the version from the generated SBOM and rename the files to include it.
# If CLEAN_NAME already contains what looks like a version (digit after separator)
# we skip this step to avoid double-versioning "akismet.5.3.5.3.spdx.json".

if [[ "$SUCCESS" == "true" ]] && [[ "$WRITE_FILES" == "true" ]]; then
    # Heuristic: does the clean name already contain a version-like segment?
    already_versioned=false
    echo "$CLEAN_NAME" | grep -qE '[._-][0-9]+\.[0-9]' && already_versioned=true

    if [[ "$already_versioned" == "false" ]]; then
        # Try to read version from whichever SBOM was produced
        sbom_for_ver=""
        [[ -f "$CDX_FILE"  ]] && sbom_for_ver="$CDX_FILE"
        [[ -z "$sbom_for_ver" ]] && [[ -f "$SPDX_FILE" ]] && sbom_for_ver="$SPDX_FILE"

        if [[ -n "$sbom_for_ver" ]]; then
            pkg_ver=$(extract_version_from_sbom "$sbom_for_ver")
            if [[ -n "$pkg_ver" ]]; then
                # Safety: strip any characters invalid in filenames (colons, slashes, etc.)
                pkg_ver=$(echo "$pkg_ver" | sed 's/[^a-zA-Z0-9._-]/_/g' | sed 's/^[._-]*//')
                # Reject if still looks like a hash after stripping punctuation
                if _is_hash_version "$pkg_ver" || [[ ${#pkg_ver} -ge 32 ]]; then
                    pkg_ver=""
                fi
            fi
            if [[ -n "$pkg_ver" ]]; then
                info "Extracted version from SBOM: $pkg_ver"
                NEW_BASE="${CLEAN_NAME}.${pkg_ver}"
                NEW_SPDX="$OUTPUT_DIR/${NEW_BASE}.spdx.json"
                NEW_CDX="$OUTPUT_DIR/${NEW_BASE}.cdx.json"
                [[ -f "$SPDX_FILE" ]] && mv "$SPDX_FILE" "$NEW_SPDX" && SPDX_FILE="$NEW_SPDX"
                [[ -f "$CDX_FILE"  ]] && mv "$CDX_FILE"  "$NEW_CDX"  && CDX_FILE="$NEW_CDX"
                log "    (version suffix added: $pkg_ver)"
            fi
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

if [[ "$SUCCESS" == "true" ]]; then
    log "--- Complete ---"
    if [[ "$WRITE_FILES" == "true" ]]; then
        [[ "$OUTPUT_FORMAT" =~ (both|spdx) ]]      && log "    SPDX:      $(basename "$SPDX_FILE")"
        [[ "$OUTPUT_FORMAT" =~ (both|cyclonedx) ]] && log "    CycloneDX: $(basename "$CDX_FILE")"
    fi
    if [[ "$JSON_OUTPUT" == "true" && -n "${PROV_FILE:-}" && -f "$PROV_FILE" ]]; then
        jq '.' "$PROV_FILE"
    fi
    exit 0
else
    log "--- Completed with errors ---"
    exit 1
fi
