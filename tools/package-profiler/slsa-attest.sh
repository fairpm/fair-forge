#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# slsa-attest.sh - SLSA v1.0 provenance attestation generator
#
# Usage: slsa-attest.sh [OPTIONS] <target>
#
# Generates a SLSA v1.0 in-toto provenance attestation for a build artifact.
# Supports levels 1–3 with documented field differences per level.
# Reads scan results from a meta JSON file (produced by the toolkit controller)
# to populate the attestation with verified build context.
#
# This script operates as an OBSERVER — it records what it can verify about
# a build artifact but cannot make guarantees about the build environment
# or process it did not witness. The attestation includes a disclaimer
# to this effect.
#
# Output files:
#   <output-dir>/<clean-name>.slsa-L<level>.provenance.json  — in-toto attestation
#   <output-dir>/<clean-name>.slsa-assessment.json           — SLSA gap analysis
#
# Exit codes: 0 = attestation produced, 1 = validation failed, 2 = execution error
#

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"
IFS=$' \t\n'

TOOLKIT_VERSION="1.0.0"
VERSION="1.0.0"

# SLSA v1.0 predicate type URI
SLSA_PREDICATE_TYPE="https://slsa.dev/provenance/v1"

# in-toto v1 statement type
INTOTO_STATEMENT_TYPE="https://in-toto.io/Statement/v1"

# ── Default configuration ────────────────────────────────────────────────────

TARGET=""
OUTPUT_DIR=""
META_BASE="./meta"
WRITE_FILE=true
SILENT=false
JSON_OUTPUT=false
VERBOSE=false

SLSA_LEVEL=0
SOURCE_TYPE=""            # wordpress | packagist | npm | pypi | github | file
META_JSON=""              # path to .meta.json from controller, or individual scan JSONs

# Required fields — no hardcoded defaults
BUILDER_ID=""
POLICY_URI=""
DISCLAIMER_URI=""

# Optional build context
SOURCE_REPO=""
SOURCE_COMMIT=""
SOURCE_REF=""
BUILD_TRIGGER=""          # push | tag | manual | schedule | api
BUILD_ID=""               # CI run ID or build reference

# Invocation parameters
INVOCATION_PARAMS=""      # JSON string of build parameters, if known

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    rm -f /tmp/slsa_attest_*.json 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Functions: UI ─────────────────────────────────────────────────────────────

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <target>

Generate a SLSA v1.0 in-toto provenance attestation for a build artifact.
Operates as an observer: records verifiable facts, documents what cannot be
independently verified, and includes a disclaimer noting observer limitations.

REQUIRED OPTIONS:
    --builder-id URI        Builder identity URI (e.g. https://github.com/actions/runner)
    --policy-uri URI        Policy or trust root URI (e.g. https://example.com/policy)

OPTIONS:
    -h, --help              Show this help message
    -s, --silent            Suppress progress messages
    -j, --json              JSON output to stdout
    -sj, -js                Silent + JSON (pipe-friendly)
    -v, --verbose           Show additional detail
    -l, --level N           SLSA level to assert: 1, 2, or 3 (default: 1)
    -o, --output-dir DIR    Directory for output file (default: current dir)
    --no-file               Output JSON to stdout only; do not write file
    --version               Print version and exit

SOURCE AND BUILD CONTEXT:
    --source-type TYPE      Source ecosystem: wordpress | packagist | npm |
                            pypi | github | file
    --source-repo URL       Source repository URL
    --source-commit SHA     Source commit hash
    --source-ref REF        Source ref (branch or tag, e.g. refs/tags/v1.2.3)
    --build-trigger TYPE    What triggered the build:
                            push | tag | manual | schedule | api
    --build-id ID           CI run ID or build reference string
    --invocation-params JSON  JSON object of build parameters (optional)

META JSON INPUT:
    --meta-json FILE        Path to toolkit meta JSON (or individual scan JSON).
                            When provided, the attestation is populated with
                            verified checksums, provenance status, vulnerability
                            summary, and license compliance results from prior
                            toolkit scans.

OBSERVER DISCLAIMER:
    --disclaimer-uri URI    URI documenting observer limitations and attestation
                            scope. Included in the attestation predicate.
                            If omitted, a generic disclaimer text is embedded.

ARGUMENTS:
    target                  The artifact being attested (file path or identifier)

OUTPUT FILE:
    <output-dir>/<clean-name>.slsa-L<level>.provenance.json

SLSA LEVELS:
    Level 1   Provenance exists and is available. Build process documented.
              Fields: builder.id, artifact digest, build timestamp.
              Signing: not required.

    Level 2   Hosted build with authenticated provenance.
              Adds: source reference, build trigger, build ID.
              Signing: recommended (field present but signing itself is outside
              this script's scope — see note below).

    Level 3   Hardened build platform, non-falsifiable provenance.
              Adds: source commit hash, invocation parameters, policy URI
              with full parameterisation. Builder must be on a hardened
              platform (Sigstore, SLSA GitHub generator, etc.).
              Signing: required at this level; attestation notes if absent.

NOTE ON SIGNING:
    This script generates the attestation JSON payload. Signing (e.g. with
    cosign, sigstore, or a hardware-backed key) is a separate step performed
    by the build platform. The attestation includes a "signing_status" field
    noting whether signing was performed outside this script's scope.

OBSERVER DISCLAIMER:
    This script is an analysis tool, not a build platform. It can record
    artifact digests, reference publicly verifiable source information, and
    summarise toolkit scan results. It cannot attest to the hermeticity of
    the build environment, the absence of tampering during build, or the
    trustworthiness of the build platform — these require a SLSA-conformant
    build system. The attestation predicate documents this scope explicitly.

EXAMPLES:
    # Level 1 attestation — basic provenance record
    $(basename "$0") \\
      --builder-id https://github.com/myorg/build \\
      --policy-uri  https://myorg.example.com/slsa-policy \\
      --level 1 \\
      akismet.5.3.zip

    # Level 2 with source context and meta JSON from toolkit
    $(basename "$0") \\
      --builder-id  https://github.com/actions/runner \\
      --policy-uri  https://myorg.example.com/slsa-policy \\
      --level 2 \\
      --source-repo   https://github.com/Automattic/akismet \\
      --source-ref    refs/tags/5.3 \\
      --build-trigger tag \\
      --build-id      12345 \\
      --meta-json     ./meta/akismet.5.3/akismet.5.3.meta.json \\
      akismet.5.3.zip

    # Level 3 with full context
    $(basename "$0") \\
      --level 3 \\
      --builder-id    https://github.com/slsa-framework/slsa-github-generator \\
      --policy-uri    https://myorg.example.com/slsa-policy/v2 \\
      --disclaimer-uri https://myorg.example.com/attestation-scope \\
      --source-repo   https://github.com/owner/repo \\
      --source-commit abc123def456 \\
      --source-ref    refs/tags/v2.0.0 \\
      --build-trigger tag \\
      --build-id      run-789 \\
      --invocation-params '{"workflow":".github/workflows/release.yml"}' \\
      --meta-json     ./meta/package/package.meta.json \\
      package.tar.gz

DEPENDENCIES:
    jq, sha256sum

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

# ── Functions: Digest calculation ────────────────────────────────────────────

calculate_digests() {
    local file="$1"
    DIGEST_SHA256=$(sha256sum "$file" | cut -d' ' -f1)
    DIGEST_SHA512=$(sha512sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "")
    info "SHA256: $DIGEST_SHA256"
    [[ -n "$DIGEST_SHA512" ]] && info "SHA512: $DIGEST_SHA512"
}

# ── Functions: Meta JSON reading ──────────────────────────────────────────────
# Reads toolkit scan results from a meta JSON file.
# Sets META_* globals used when building the attestation predicate.
# Tolerant — missing fields produce empty strings, not errors.

read_meta_json() {
    local file="$1"

    jq empty "$file" 2>/dev/null \
        || { log "  [WARN] Meta JSON is not valid JSON — ignoring: $file"; return 1; }

    # Try controller meta JSON first (.toolkit), then individual scan outputs
    META_RUN_ID=$(jq -r '.toolkit.run_id // ""' "$file" 2>/dev/null || echo "")
    META_TIMESTAMP=$(jq -r '.toolkit.timestamp // ""' "$file" 2>/dev/null || echo "")
    META_TARGET=$(jq -r '.toolkit.target // ""' "$file" 2>/dev/null || echo "")

    # Checksum verification
    META_CHECKSUM_STATUS=$(jq -r '
        .crypto_verification.verification.status //
        .checksum_verification.status // ""
    ' "$file" 2>/dev/null || echo "")
    META_CHECKSUM_SHA256=$(jq -r '
        .crypto_verification.calculated_checksums.sha256 //
        .checksum_verification.sha256 // ""
    ' "$file" 2>/dev/null || echo "")

    # Provenance verification
    META_PROV_STATUS=$(jq -r '
        .provenance_verification.status // ""
    ' "$file" 2>/dev/null || echo "")
    META_SLSA_LEVEL=$(jq -r '
        .provenance_verification.slsa_level // ""
    ' "$file" 2>/dev/null || echo "")

    # Vulnerability summary
    META_VULN_TOTAL=$(jq -r '
        .vulnerability_scan.risk_assessment.vuln_counts.total //
        .risk_assessment.vuln_counts.total // ""
    ' "$file" 2>/dev/null || echo "")
    META_VULN_CRITICAL=$(jq -r '
        .vulnerability_scan.risk_assessment.vuln_counts.critical //
        .risk_assessment.vuln_counts.critical // ""
    ' "$file" 2>/dev/null || echo "")
    META_VULN_RISK=$(jq -r '
        .vulnerability_scan.risk_assessment.weighted_risk //
        .risk_assessment.weighted_risk // ""
    ' "$file" 2>/dev/null || echo "")

    # License compliance
    META_LICENSE_STATUS=$(jq -r '
        .license_compliance.status // ""
    ' "$file" 2>/dev/null || echo "")
    META_LICENSE_GPL_COMPAT=$(jq -r '
        .license_compliance.gpl_compatible // ""
    ' "$file" 2>/dev/null || echo "")

    # Total risk score
    META_TOTAL_RISK=$(jq -r '
        .risk_assessment.total_risk_score //
        .risk_assessment.weighted_risk // ""
    ' "$file" 2>/dev/null || echo "")

    info "Meta JSON loaded: run_id=${META_RUN_ID:-n/a}"
    info "  Checksum: ${META_CHECKSUM_STATUS:-n/a}"
    info "  Provenance: ${META_PROV_STATUS:-n/a}"
    info "  Vulns: ${META_VULN_TOTAL:-n/a} (risk: ${META_VULN_RISK:-n/a})"
    info "  License: ${META_LICENSE_STATUS:-n/a}"
    return 0
}

# ── Functions: Level validation ───────────────────────────────────────────────
# Checks whether the supplied inputs are sufficient for the requested level.
# Emits warnings for missing fields rather than failing hard — the attestation
# is still produced but with noted gaps (important for observer pattern).

validate_level_inputs() {
    local level="$1"
    LEVEL_WARNINGS=()

    case "$level" in
        2|3)
            [[ -z "$SOURCE_REPO" ]] \
                && LEVEL_WARNINGS+=("--source-repo recommended for Level $level")
            [[ -z "$BUILD_TRIGGER" ]] \
                && LEVEL_WARNINGS+=("--build-trigger recommended for Level $level")
            [[ -z "$BUILD_ID" ]] \
                && LEVEL_WARNINGS+=("--build-id recommended for Level $level")
            ;;&
        3)
            [[ -z "$SOURCE_COMMIT" ]] \
                && LEVEL_WARNINGS+=("--source-commit required for Level 3 — attestation integrity reduced")
            [[ -z "$INVOCATION_PARAMS" ]] \
                && LEVEL_WARNINGS+=("--invocation-params recommended for Level 3")
            ;;
    esac

    local w
    for w in "${LEVEL_WARNINGS[@]+"${LEVEL_WARNINGS[@]}"}"; do
        log "  [WARN] $w"
    done
}

# ── Functions: SLSA gap analysis ──────────────────────────────────────────────
# Builds a machine-readable assessment of which SLSA level requirements are
# met and which are missing, with remediation guidance for CI pipeline authors.
# Written to a companion .slsa-assessment.json file (separate from the in-toto
# provenance document, which only records what IS present).

build_slsa_assessment() {
    local target_level="$1"

    # ── Level 0: observer-only — always satisfied (we produced a document) ──
    local l0_sat=true

    # ── Level 1: requires non-placeholder builder-id and policy-uri ──────────
    local l1_builder_met=false l1_policy_met=false l1_sat=false
    [[ -n "$BUILDER_ID" && "$BUILDER_ID" != "observer-only" ]] && l1_builder_met=true
    [[ -n "$POLICY_URI"  ]] && l1_policy_met=true
    [[ "$l1_builder_met" == "true" && "$l1_policy_met" == "true" ]] && l1_sat=true

    # ── Level 2: check each required field ───────────────────────────────────
    local l2_repo_met=false   l2_repo_val=""
    local l2_ref_met=false    l2_ref_val=""
    local l2_trigger_met=false l2_trigger_val=""
    local l2_buildid_met=false l2_buildid_val=""

    [[ -n "$SOURCE_REPO"    ]] && { l2_repo_met=true;    l2_repo_val="$SOURCE_REPO";    }
    [[ -n "$SOURCE_REF"     ]] && { l2_ref_met=true;     l2_ref_val="$SOURCE_REF";      }
    [[ -n "$BUILD_TRIGGER"  ]] && { l2_trigger_met=true; l2_trigger_val="$BUILD_TRIGGER"; }
    [[ -n "$BUILD_ID"       ]] && { l2_buildid_met=true; l2_buildid_val="$BUILD_ID";    }

    local l2_sat=false
    [[ "$l1_sat" == "true" && "$l2_repo_met" == "true" && "$l2_ref_met" == "true" \
       && "$l2_trigger_met" == "true" && "$l2_buildid_met" == "true" ]] && l2_sat=true

    # ── Level 3: check each required field ───────────────────────────────────
    local l3_commit_met=false  l3_commit_val=""
    local l3_params_met=false  l3_params_val=""

    [[ -n "$SOURCE_COMMIT"     ]] && { l3_commit_met=true; l3_commit_val="$SOURCE_COMMIT";    }
    [[ -n "$INVOCATION_PARAMS" ]] && { l3_params_met=true; l3_params_val="$INVOCATION_PARAMS"; }

    local l3_sat=false
    [[ "$l2_sat" == "true" && "$l3_commit_met" == "true" \
       && "$l3_params_met" == "true" ]] && l3_sat=true

    # ── Highest satisfied level ───────────────────────────────────────────────
    local highest=0
    [[ "$l1_sat" == "true" ]] && highest=1
    [[ "$l2_sat" == "true" ]] && highest=2
    [[ "$l3_sat" == "true" ]] && highest=3

    # ── Remediation steps: one entry per missing requirement ─────────────────
    local remediation=()
    [[ "$l1_builder_met" == "false" ]] && remediation+=("Pass --builder-id with the builder URI (e.g. https://github.com/actions/runner) to satisfy L1")
    [[ "$l1_policy_met"  == "false" ]] && remediation+=("Pass --policy-uri with the trust/policy URI to satisfy L1")
    [[ "$l2_repo_met"     == "false" ]] && remediation+=("Pass --source-repo with the repository URL (e.g. https://github.com/org/repo) to satisfy L2")
    [[ "$l2_ref_met"      == "false" ]] && remediation+=("Pass --source-ref with the git branch or tag reference to satisfy L2")
    [[ "$l2_trigger_met"  == "false" ]] && remediation+=("Pass --build-trigger (push|tag|manual|schedule|api) to satisfy L2")
    [[ "$l2_buildid_met"  == "false" ]] && remediation+=("Pass --build-id with the CI run ID or build reference to satisfy L2")
    [[ "$l3_commit_met"   == "false" ]] && remediation+=("Pass --source-commit with the full git commit SHA to satisfy L3 (non-falsifiable source pointer)")
    [[ "$l3_params_met"   == "false" ]] && remediation+=("Pass --invocation-params as a JSON object of complete build input parameters to satisfy L3")
    if [[ "$l2_sat" == "false" ]]; then
        remediation+=("Note: L3 cannot be satisfied until all L2 requirements are met")
    fi

    local remediation_json
    remediation_json=$(printf '%s\n' "${remediation[@]+"${remediation[@]}"}" \
        | jq -Rs 'split("\n") | map(select(. != ""))' 2>/dev/null || echo "[]")

    # ── Build JSON ────────────────────────────────────────────────────────────
    jq -n \
        --arg  timestamp      "$TIMESTAMP" \
        --arg  toolkit_ver    "$TOOLKIT_VERSION" \
        --arg  artifact       "$(basename "$TARGET")" \
        --argjson target_lvl  "$target_level" \
        --argjson highest_sat "$highest" \
        --argjson l0_sat      "$l0_sat" \
        --argjson l1_sat      "$l1_sat" \
        --argjson l2_sat      "$l2_sat" \
        --argjson l3_sat      "$l3_sat" \
        --argjson l1_builder_met "$l1_builder_met" --arg  l1_builder_val "${BUILDER_ID:-}" \
        --argjson l1_policy_met  "$l1_policy_met"  --arg  l1_policy_val  "${POLICY_URI:-}" \
        --argjson l2_repo_met     "$l2_repo_met"    --arg l2_repo_val     "$l2_repo_val" \
        --argjson l2_ref_met      "$l2_ref_met"     --arg l2_ref_val      "$l2_ref_val" \
        --argjson l2_trigger_met  "$l2_trigger_met" --arg l2_trigger_val  "$l2_trigger_val" \
        --argjson l2_buildid_met  "$l2_buildid_met" --arg l2_buildid_val  "$l2_buildid_val" \
        --argjson l3_commit_met   "$l3_commit_met"  --arg l3_commit_val   "$l3_commit_val" \
        --argjson l3_params_met   "$l3_params_met" \
        --argjson remediation     "$remediation_json" \
        '{
            slsa_assessment: {
                timestamp:        $timestamp,
                toolkit_version:  $toolkit_ver,
                artifact:         $artifact,
                target_level:     $target_lvl,
                highest_satisfied: $highest_sat,
                levels: {
                    l0: {
                        satisfied: $l0_sat,
                        requirements: {
                            provenance_exists: {met: true, note: "Observer attestation document produced"},
                            artifact_digest:   {met: true, note: "SHA-256 digest calculated"},
                            observer_disclaimer: {met: true, note: "Observer disclaimer embedded in document"}
                        }
                    },
                    l1: {
                        satisfied: $l1_sat,
                        requirements: {
                            builder_id_declared: {met: $l1_builder_met, value: (if $l1_builder_val != "" and $l1_builder_val != "observer-only" then $l1_builder_val else null end), missing_flag: (if $l1_builder_met then null else "--builder-id" end), description: "Non-placeholder builder identity URI"},
                            policy_uri_declared: {met: $l1_policy_met,  value: (if $l1_policy_val  != "" then $l1_policy_val  else null end), missing_flag: (if $l1_policy_met  then null else "--policy-uri"  end), description: "Trust root or policy URI"}
                        }
                    },
                    l2: {
                        satisfied: $l2_sat,
                        requirements: {
                            source_repo:   {met: $l2_repo_met,    value: (if $l2_repo_val    != "" then $l2_repo_val    else null end), missing_flag: (if $l2_repo_met    then null else "--source-repo"    end), description: "Repository URL"},
                            source_ref:    {met: $l2_ref_met,     value: (if $l2_ref_val     != "" then $l2_ref_val     else null end), missing_flag: (if $l2_ref_met     then null else "--source-ref"     end), description: "Git branch or tag reference"},
                            build_trigger: {met: $l2_trigger_met, value: (if $l2_trigger_val != "" then $l2_trigger_val else null end), missing_flag: (if $l2_trigger_met  then null else "--build-trigger"  end), description: "What initiated the build (push/tag/manual/schedule/api)"},
                            build_id:      {met: $l2_buildid_met, value: (if $l2_buildid_val != "" then $l2_buildid_val else null end), missing_flag: (if $l2_buildid_met  then null else "--build-id"       end), description: "CI run ID or build reference"}
                        }
                    },
                    l3: {
                        satisfied: $l3_sat,
                        requirements: {
                            source_commit:      {met: $l3_commit_met, value: (if $l3_commit_val != "" then $l3_commit_val else null end), missing_flag: (if $l3_commit_met then null else "--source-commit" end), description: "Full git commit SHA — non-falsifiable source pointer"},
                            invocation_params:  {met: $l3_params_met, missing_flag: (if $l3_params_met then null else "--invocation-params" end), description: "Complete build input parameters as JSON"},
                            platform_integrity: {met: null, missing_flag: null, description: "Non-falsifiable build platform — a property of the builder, cannot be asserted in this document"}
                        }
                    }
                },
                remediation_steps: $remediation
            }
        }'
}

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       show_help ;;
        -sj|-js)         SILENT=true; JSON_OUTPUT=true; shift ;;
        -s|--silent)     SILENT=true; shift ;;
        -j|--json)       JSON_OUTPUT=true; shift ;;
        -v|--verbose)    VERBOSE=true; shift ;;
        -l|--level)
            [[ -z "${2:-}" ]] && die "--level requires an argument"
            SLSA_LEVEL="$2"
            [[ "$SLSA_LEVEL" =~ ^[0123]$ ]] \
                || die "--level must be 0, 1, 2, or 3"
            shift 2 ;;
        -o|--output-dir)
            [[ -z "${2:-}" ]] && die "--output-dir requires an argument"
            OUTPUT_DIR="$2"; shift 2 ;;
        --no-file)       WRITE_FILE=false; shift ;;
        --builder-id)
            [[ -z "${2:-}" ]] && die "--builder-id requires an argument"
            BUILDER_ID="$2"; shift 2 ;;
        --policy-uri)
            [[ -z "${2:-}" ]] && die "--policy-uri requires an argument"
            POLICY_URI="$2"; shift 2 ;;
        --disclaimer-uri)
            [[ -z "${2:-}" ]] && die "--disclaimer-uri requires an argument"
            DISCLAIMER_URI="$2"; shift 2 ;;
        --source-type)
            [[ -z "${2:-}" ]] && die "--source-type requires an argument"
            SOURCE_TYPE="$2"
            [[ "$SOURCE_TYPE" =~ ^(wordpress|packagist|npm|pypi|github|file)$ ]] \
                || die "Invalid source-type. Use: wordpress, packagist, npm, pypi, github, file"
            shift 2 ;;
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
            BUILD_TRIGGER="$2"
            [[ "$BUILD_TRIGGER" =~ ^(push|tag|manual|schedule|api)$ ]] \
                || die "Invalid build-trigger. Use: push, tag, manual, schedule, api"
            shift 2 ;;
        --build-id)
            [[ -z "${2:-}" ]] && die "--build-id requires an argument"
            BUILD_ID="$2"; shift 2 ;;
        --invocation-params)
            [[ -z "${2:-}" ]] && die "--invocation-params requires an argument"
            INVOCATION_PARAMS="$2"
            echo "$INVOCATION_PARAMS" | jq empty 2>/dev/null \
                || die "--invocation-params must be valid JSON"
            shift 2 ;;
        --meta-json)
            [[ -z "${2:-}" ]] && die "--meta-json requires an argument"
            META_JSON="$2"
            [[ ! -f "$META_JSON" ]] && die "Meta JSON file not found: $META_JSON"
            shift 2 ;;
        --version)
            echo "slsa-attest.sh $VERSION (toolkit $TOOLKIT_VERSION)"; exit 0 ;;
        -*) die "Unknown option: $1 (use --help for usage)" ;;
        *)  TARGET="$1"; shift ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -z "$TARGET" ]]    && die "No target specified (use --help for usage)"
[[ ! -f "$TARGET" ]]  && die "Target file not found: $TARGET"
# builder-id and policy-uri are optional at L0. When absent the attestation
# is produced in "observer-only" mode — all SLSA level requirements are
# recorded as unmet in the assessment, and the disclaimer makes this explicit.
[[ -z "$BUILDER_ID" ]] && BUILDER_ID="observer-only"
[[ -z "$POLICY_URI" ]] && POLICY_URI=""
command -v jq       &>/dev/null || die "jq is required"
command -v sha256sum &>/dev/null || die "sha256sum is required"

CLEAN_NAME=$(sanitize_name "$TARGET")
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"

if [[ "$WRITE_FILE" == "true" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null \
        || die "Cannot create output directory: $OUTPUT_DIR"
    [[ -w "$OUTPUT_DIR" ]] \
        || die "Output directory is not writable: $OUTPUT_DIR"
fi

OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.slsa-L${SLSA_LEVEL}.provenance.json"
ASSESSMENT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.slsa-assessment.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log "[SLSA] Generating SLSA Level $SLSA_LEVEL attestation"
log "       Artifact: $(basename "$TARGET")"
log "       Builder:  $BUILDER_ID"

# ── Validate level inputs ─────────────────────────────────────────────────────

LEVEL_WARNINGS=()
validate_level_inputs "$SLSA_LEVEL"

# ── Calculate artifact digests ────────────────────────────────────────────────

log "[HASH] Calculating artifact digests..."
DIGEST_SHA256="" DIGEST_SHA512=""
calculate_digests "$TARGET"

# ── Read meta JSON ────────────────────────────────────────────────────────────

META_RUN_ID="" META_TIMESTAMP="" META_TARGET=""
META_CHECKSUM_STATUS="" META_CHECKSUM_SHA256=""
META_PROV_STATUS="" META_SLSA_LEVEL=""
META_VULN_TOTAL="" META_VULN_CRITICAL="" META_VULN_RISK=""
META_LICENSE_STATUS="" META_LICENSE_GPL_COMPAT=""
META_TOTAL_RISK=""

if [[ -n "$META_JSON" ]]; then
    log "[META] Reading scan results from: $(basename "$META_JSON")"
    read_meta_json "$META_JSON" || true

    # If meta JSON has a SHA256, cross-check it matches our calculation
    if [[ -n "$META_CHECKSUM_SHA256" ]] \
       && [[ "${META_CHECKSUM_SHA256,,}" != "${DIGEST_SHA256,,}" ]]; then
        log "  [WARN] SHA256 in meta JSON does not match artifact"
        log "         Meta:     $META_CHECKSUM_SHA256"
        log "         Artifact: $DIGEST_SHA256"
        LEVEL_WARNINGS+=("SHA256 mismatch between meta JSON and artifact — attestation may cover a different file")
    fi
fi

# ── Build attestation ─────────────────────────────────────────────────────────

# Disclaimer: embed URI if provided, else use generic text
if [[ -n "$DISCLAIMER_URI" ]]; then
    DISCLAIMER_VALUE="$DISCLAIMER_URI"
    DISCLAIMER_TYPE="uri"
else
    DISCLAIMER_VALUE="This attestation was produced by an analysis tool acting as an observer. It records verifiable facts about the artifact (digests, scan results) but cannot attest to the hermeticity of the build environment, the integrity of the build platform, or the absence of tampering during the build process. It does not constitute a guarantee of build provenance equivalent to one produced by a SLSA-conformant build system."
    DISCLAIMER_TYPE="text"
fi

# Invocation parameters — default to empty object if not provided
if [[ -n "$INVOCATION_PARAMS" ]]; then
    INVOCATION_JSON="$INVOCATION_PARAMS"
else
    INVOCATION_JSON="{}"
fi

# Warnings array for attestation metadata
WARNINGS_JSON=$(printf '%s\n' "${LEVEL_WARNINGS[@]+"${LEVEL_WARNINGS[@]}"}" \
    | jq -Rs 'split("\n") | map(select(. != ""))' 2>/dev/null || echo "[]")

# Build the digest object — include sha512 only if available
if [[ -n "$DIGEST_SHA512" ]]; then
    DIGEST_JSON=$(jq -n \
        --arg sha256 "$DIGEST_SHA256" \
        --arg sha512 "$DIGEST_SHA512" \
        '{sha256:$sha256, sha512:$sha512}')
else
    DIGEST_JSON=$(jq -n \
        --arg sha256 "$DIGEST_SHA256" \
        '{sha256:$sha256}')
fi

# Build the toolkit scan summary block (populated from meta JSON if available)
SCAN_SUMMARY_JSON=$(jq -n \
    --arg  run_id           "${META_RUN_ID:-}" \
    --arg  scan_timestamp   "${META_TIMESTAMP:-}" \
    --arg  checksum_status  "${META_CHECKSUM_STATUS:-not_run}" \
    --arg  prov_status      "${META_PROV_STATUS:-not_run}" \
    --arg  prov_slsa_level  "${META_SLSA_LEVEL:-}" \
    --arg  vuln_total       "${META_VULN_TOTAL:-}" \
    --arg  vuln_critical    "${META_VULN_CRITICAL:-}" \
    --arg  vuln_risk        "${META_VULN_RISK:-}" \
    --arg  license_status   "${META_LICENSE_STATUS:-not_run}" \
    --arg  license_gpl      "${META_LICENSE_GPL_COMPAT:-}" \
    --arg  total_risk       "${META_TOTAL_RISK:-}" \
    '{
        run_id:              $run_id,
        scan_timestamp:      $scan_timestamp,
        checksum_status:     $checksum_status,
        provenance_status:   $prov_status,
        provenance_slsa_level: ($prov_slsa_level | if . == "" then null else (.|tonumber? // .) end),
        vulnerability_summary: {
            total:    ($vuln_total    | if . == "" then null else (.|tonumber? // .) end),
            critical: ($vuln_critical | if . == "" then null else (.|tonumber? // .) end),
            weighted_risk: ($vuln_risk | if . == "" then null else (.|tonumber? // .) end)
        },
        license_compliance: {
            status:         $license_status,
            gpl_compatible: ($license_gpl | if . == "" then null elif . == "true" then true else false end)
        },
        total_risk_score: ($total_risk | if . == "" then null else (.|tonumber? // .) end)
    }')

# ── Compose level-appropriate predicate ───────────────────────────────────────
# Each level is a strict superset of the previous.
# Fields that are N/A at the current level are omitted rather than null-padded.

build_predicate() {
    local level="$1"

    # ── Level 1 base fields ───────────────────────────────────────────────────
    local pred
    pred=$(jq -n \
        --arg  builder_id    "$BUILDER_ID" \
        --arg  policy_uri    "$POLICY_URI" \
        --arg  timestamp     "$TIMESTAMP" \
        --arg  toolkit_ver   "$TOOLKIT_VERSION" \
        --arg  artifact      "$(basename "$TARGET")" \
        --arg  source_type   "${SOURCE_TYPE:-}" \
        --arg  disc_type     "$DISCLAIMER_TYPE" \
        --arg  disc_value    "$DISCLAIMER_VALUE" \
        --argjson digests    "$DIGEST_JSON" \
        --argjson scan       "$SCAN_SUMMARY_JSON" \
        --argjson warnings   "$WARNINGS_JSON" \
        '{
            buildDefinition: {
                buildType: "https://slsa.dev/container-based-build/v0.1",
                externalParameters: {
                    artifact:    $artifact,
                    source_type: $source_type
                },
                resolvedDependencies: []
            },
            runDetails: {
                builder: {
                    id:      $builder_id,
                    version: {toolkit: $toolkit_ver}
                },
                metadata: {
                    invocationId: "",
                    startedOn:    $timestamp,
                    finishedOn:   $timestamp
                },
                byproducts: []
            },
            observer: {
                disclaimer: {
                    type:  $disc_type,
                    value: $disc_value
                },
                toolkit_scan_summary: $scan,
                attestation_warnings: $warnings
            },
            policy: {
                uri: $policy_uri
            },
            digests: $digests,
            signing_status: "not_signed_by_this_tool"
        }')

    # ── Level 2 additions ─────────────────────────────────────────────────────
    if [[ "$level" -ge 2 ]]; then
        pred=$(echo "$pred" | jq \
            --arg source_repo    "${SOURCE_REPO:-}" \
            --arg source_ref     "${SOURCE_REF:-}" \
            --arg build_trigger  "${BUILD_TRIGGER:-}" \
            --arg build_id       "${BUILD_ID:-}" \
            '.buildDefinition.externalParameters += {
                source_ref:     $source_ref,
                build_trigger:  $build_trigger
            } |
            .buildDefinition.resolvedDependencies = [
                if $source_repo != "" then {
                    uri:    $source_repo,
                    ref:    $source_ref
                } else empty end
            ] |
            .runDetails.metadata.invocationId = $build_id')
    fi

    # ── Level 3 additions ─────────────────────────────────────────────────────
    if [[ "$level" -ge 3 ]]; then
        pred=$(echo "$pred" | jq \
            --arg  source_commit  "${SOURCE_COMMIT:-}" \
            --argjson invocation  "$INVOCATION_JSON" \
            '.buildDefinition.externalParameters += {
                source_commit:       $source_commit,
                invocation_params:   $invocation
            } |
            if $source_commit != "" then
                .buildDefinition.resolvedDependencies[0].digest = {
                    sha1: $source_commit
                }
            else . end |
            .runDetails.builder.builderDependencies = [] |
            .observer.level3_note = "Level 3 requires a hardened, non-falsifiable build platform. This attestation documents the build context as observed; non-falsifiability depends on the builder platform identified in runDetails.builder.id."')
    fi

    echo "$pred"
}

PREDICATE=$(build_predicate "$SLSA_LEVEL")

# ── Compose full in-toto v1 statement ─────────────────────────────────────────

SUBJECT_JSON=$(jq -n \
    --arg  name    "$(basename "$TARGET")" \
    --argjson digest "$DIGEST_JSON" \
    '[{name: $name, digest: $digest}]')

ATTESTATION=$(jq -n \
    --arg  stmt_type   "$INTOTO_STATEMENT_TYPE" \
    --arg  pred_type   "$SLSA_PREDICATE_TYPE" \
    --argjson subject  "$SUBJECT_JSON" \
    --argjson predicate "$PREDICATE" \
    '{
        "_type":       $stmt_type,
        subject:       $subject,
        predicateType: $pred_type,
        predicate:     $predicate
    }')

# ── Build SLSA gap analysis assessment ────────────────────────────────────────

ASSESSMENT=$(build_slsa_assessment "$SLSA_LEVEL")
HIGHEST_SATISFIED=$(echo "$ASSESSMENT" | jq -r '.slsa_assessment.highest_satisfied' 2>/dev/null || echo "1")

# ── Output ────────────────────────────────────────────────────────────────────

if [[ "$WRITE_FILE" == "true" ]]; then
    echo "$ATTESTATION" | jq . > "$OUTPUT_FILE"
    chmod 664 "$OUTPUT_FILE" 2>/dev/null || true
    log "[OK]   Saved: $OUTPUT_FILE"
    log "       Level: $SLSA_LEVEL | Builder: $BUILDER_ID"
    if [[ ${#LEVEL_WARNINGS[@]} -gt 0 ]]; then
        log "       Warnings: ${#LEVEL_WARNINGS[@]} (see attestation.observer.attestation_warnings)"
    fi

    # Write companion gap analysis (separate from provenance — assessment is
    # meta-commentary about what's missing, not part of the in-toto document)
    echo "$ASSESSMENT" | jq . > "$ASSESSMENT_FILE"
    chmod 664 "$ASSESSMENT_FILE" 2>/dev/null || true
    log "[OK]   Saved: $ASSESSMENT_FILE"
    log "       SLSA highest satisfied: L$HIGHEST_SATISFIED (target: L$SLSA_LEVEL)"
    if [[ "$HIGHEST_SATISFIED" -lt "$SLSA_LEVEL" ]]; then
        local_missing=$(echo "$ASSESSMENT" \
            | jq -r '.slsa_assessment.remediation_steps[]' 2>/dev/null \
            | grep -c "to satisfy" || echo "0")
        log "       Missing requirements: $local_missing (see $(basename "$ASSESSMENT_FILE"))"
    fi
else
    echo "$ATTESTATION" | jq .
    # In --no-file mode, emit assessment to stderr so stdout stays machine-parseable
    echo "$ASSESSMENT" | jq . >&2
fi

exit 0
