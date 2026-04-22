#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# run-filescans.sh — orchestrate the complete site audit suite
#
# usage: run-filescans.sh [OPTIONS] [directory]
#
# runs the three scan scripts against a target directory:
#
#   file-stats.sh       file type statistics
#   permission-check.sh permission & symlink audit
#   deep-filescan.sh    content & MIME integrity scan  (disabled; use --deep)
#
# each script runs independently and can also be invoked on its own.
# this script adds:
#
#   - upfront dependency check (all tools, all scripts)
#   - parallel execution of enabled scans
#   - merged JSON output (single document, one section per scan)
#   - combined severity summary across all scans
#   - optional JSON save prompt for interactive runs
#   - total wall-clock elapsed time
#
# file list sharing: the three scripts each do their own find pass.
# sharing a pre-built list was evaluated and rejected; see note below.
#
# NOTE on file list sharing:
#   deep-filescan's find pass takes < 0.5s on typical trees. the dominant
#   costs are xargs file --mime-type (5-30s+) and xargs grep — both already
#   parallelised within the script. sharing a list would save < 5% of total
#   runtime. permission-check runs 7 targeted find passes with specific
#   -perm flags that a generic path list cannot replicate. file-stats needs
#   sizes from find -printf, so a path-only list still requires per-file
#   stat calls. three concurrent find passes on the same tree are cheap on
#   SSD; on spinning disk or NFS the concurrency may actually help by letting
#   the OS scheduler pipeline requests. not worth the added coupling.
#
VERSION="1.0.0"


# ─── environment ───────────────────────────────────────────────────────
#
set -u
set -o pipefail
export LC_ALL=C
IFS=$' \t\n'
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"


# NOTE: sanitize_name is duplicated verbatim across all toolkit scripts.
# Any changes must be kept in sync with the same function in:
#   checksum-verify.sh, dependency-audit.sh, license-check.sh,
#   provenance-verify.sh, sbom-compare.sh, sbom-discover.sh,
#   sbom-gen.sh, sbom-toolkit.sh, slsa-attest.sh,
#   permission-check.sh, file-stats.sh, deep-filescan.sh
sanitize_name() {
	local input="$1"
	local base
	base=$(basename "$input")
	local clean="$base"
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
	clean="${clean%.perms.json}"
	clean="${clean%.file-stats.json}"
	clean="${clean%.content-scan.json}"
	clean="${clean%.json}"
	clean="${clean%.tar.gz}"
	clean="${clean%.tar.bz2}"
	clean="${clean%.tgz}"
	clean="${clean%.zip}"
	clean=$(echo "$clean" | sed 's/[^a-zA-Z0-9._-]/_/g')
	[[ -z "$clean" ]] && clean="package_$(date +%s)"
	echo "$clean"
}


# ─── defaults ──────────────────────────────────────────────────────────
#
TARGET_DIR="."
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
DEEP_SCAN=false       # disabled until deep-filescan.sh fully supports suite mode
PERM_FIX=false        # pass --fix through to permission-check.sh
META_BASE="./meta"    # base directory for standard output
OUTPUT_DIR=""         # default: $META_BASE/<clean-name>/ (set after name detection)
WRITE_FILE=true       # set false with --no-file


# ─── cleanup / signals ─────────────────────────────────────────────────
#
TMPDIR_WORK=""
cleanup() {
	[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"
	jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
	exit 130
}
trap cleanup INT TERM
trap '[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"' EXIT


# ─── functions ─────────────────────────────────────────────────────────
#

show_help() {
	cat << EOF

FULL-SCAN:
    Orchestrate the complete site audit suite against a directory.
    run-filescans.sh Version $VERSION

USAGE:
    $(basename "$0") [OPTIONS] [directory]

OPTIONS:
    -h, --help          Show this help message
    -s, --silent        Suppress output (exit code only)
    -j, --json          Output merged results in JSON format
    -sj, -js            Silent + JSON (pipe-friendly)
    -v, --verbose       Pass verbose mode through to all sub-scripts
    -f, --fix           Pass --fix to permission-check.sh
    --deep              Enable deep-filescan.sh (content & MIME scan)
                        Disabled by default — adds significant scan time
    -o, --output-dir D  Write merged JSON output to directory D
                        (default: ./meta/<clean-name>/)
    --meta-base DIR     Base directory for meta output (default: ./meta)
    --no-file           Output JSON to stdout only; do not write file
    --version           Print version and exit

ARGUMENTS:
    [directory]         Directory to scan (default: current directory)

SCRIPTS:
    file-stats.sh         always run; file type statistics
    permission-check.sh   always run; permission & symlink audit
    deep-filescan.sh      only with --deep; content & MIME integrity

SCRIPTS LOCATION:
    Looks for scripts alongside this file, then in PATH.

OUTPUT:
    Text mode: each script's output printed in sequence with headers.
    JSON mode (-j): single merged document with one section per scan,
                    plus a combined severity summary across all scans.
                    Saved to: ./meta/<clean-name>/<clean-name>.meta.json
    Interactive (-v + terminal): offers to save JSON at the end.

EXIT CODES:
    0   All enabled scans passed (no critical/high issues)
    1   One or more scans found critical or high-severity issues
    2   Errors (missing scripts/tools, directory not found, etc.)

EXAMPLES:
    $(basename "$0") /var/www/html
    $(basename "$0") --deep -v /var/www/html
    $(basename "$0") -j --deep ./uploads > audit.json
    $(basename "$0") -j --no-file ./uploads > audit.json
    $(basename "$0") -sf /var/www/html

EOF
}


log() {
	[[ "$SILENT" == "false" && "$JSON_OUTPUT" == "false" ]] && echo "$@" >&2
}

err() {
	echo "Error: $*" >&2
}


# ─── argument parsing ───────────────────────────────────────────────────
#
while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)    show_help; exit 0 ;;
		--version)    echo "run-filescans.sh v$VERSION"; exit 0 ;;
		--verbose|-v) VERBOSE=true; shift ;;
		--silent|-s)  SILENT=true; shift ;;
		--json|-j)    JSON_OUTPUT=true; shift ;;
		--deep)       DEEP_SCAN=true; shift ;;
		--fix|-f)     PERM_FIX=true; shift ;;
		-o|--output-dir)
		              [[ -z "${2:-}" ]] && { err "--output-dir requires an argument"; exit 2; }
		              OUTPUT_DIR="$2"; shift 2 ;;
		--meta-base)
		              [[ -z "${2:-}" ]] && { err "--meta-base requires an argument"; exit 2; }
		              META_BASE="$2"; shift 2 ;;
		--no-file)    WRITE_FILE=false; shift ;;
		--)           shift; break ;;

		-[a-zA-Z][a-zA-Z]* )
			opt_string="${1#-}"
			shift
			for (( i=${#opt_string}-1; i>=0; i-- )); do
				set -- "-${opt_string:$i:1}" "$@"
			done
			;;

		-*)
			err "Unknown option '$1'"
			echo "Try '$(basename "$0") --help' for usage." >&2
			exit 2
			;;
		*)  TARGET_DIR="$1"; shift ;;
	esac
done

[[ $# -gt 0 && "$TARGET_DIR" == "." ]] && TARGET_DIR="$1"

TARGET_DIR="${TARGET_DIR:-.}"

# ─── locate sibling scripts ────────────────────────────────────────────
#
# defined here (before archive detection) so find_script is available
# when checksum-verify.sh needs to be located for archive extraction.
# look alongside this file first, then fall back to PATH.
#
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

find_script() {
	local name="$1"
	if [[ -x "$SCRIPT_DIR/$name" ]]; then
		echo "$SCRIPT_DIR/$name"
	elif command -v "$name" &>/dev/null; then
		command -v "$name"
	else
		echo ""
	fi
}

# ─── archive detection & extraction ───────────────────────────────────
#
# if the target is an archive file rather than a directory, run
# checksum-verify.sh --extract to verify the archive and unpack it,
# then use the extracted directory for all subsequent scans.
#
# supported formats: .zip  .tar.gz  .tgz  .tar.bz2
#
if [[ -f "$TARGET_DIR" ]]; then
	case "$TARGET_DIR" in
		# All archive formats: zip, tar variants (.gz/.bz2/.xz/.zst/plain), others tar can read
		*.zip|*.tar.gz|*.tgz|*.tar.bz2|*.tar.bz2|*.tbz2|*.tar.xz|*.txz|*.tar.zst|*.tzst|*.tar)
			ARCHIVE_FILE="$(cd -- "$(dirname "$TARGET_DIR")" && pwd -P)/$(basename "$TARGET_DIR")"
			ARCHIVE_DISPLAY="$(basename "$TARGET_DIR")"
			ARCHIVE_CLEAN="$(sanitize_name "$ARCHIVE_DISPLAY")"

			SCRIPT_CHECKSUM="$(find_script checksum-verify.sh)"
			if [[ -z "$SCRIPT_CHECKSUM" ]]; then
				err "checksum-verify.sh not found — required to extract archive targets"
				err "Place checksum-verify.sh alongside this script or in PATH"
				exit 2
			fi

			log "Archive target detected: $ARCHIVE_DISPLAY"
			log "Running checksum-verify.sh --extract ..."

			CHKSUM_JSON=$("$SCRIPT_CHECKSUM" -sj --no-file \
				--extract \
				"$ARCHIVE_FILE") \
				|| { err "checksum-verify.sh failed extracting '$ARCHIVE_DISPLAY'"; exit 2; }

			# Read the full extraction path that checksum-verify resolved and recorded.
			EXTRACTED_PATH=$(echo "$CHKSUM_JSON" \
				| jq -r '.crypto_verification.extraction.path // ""' 2>/dev/null || echo "")

			if [[ ! -d "$EXTRACTED_PATH" ]]; then
				err "checksum-verify.sh did not produce a valid extracted directory"
				err "Check that the archive is not corrupt and that you have write permission"
				exit 2
			fi

			TARGET_DIR="$EXTRACTED_PATH"

			log "Extracted to: $EXTRACTED_PATH"
			;;
		*)
			# Try tar probe for unrecognised extension before giving up
			if tar -tf "$TARGET_DIR" &>/dev/null 2>&1; then
				ARCHIVE_FILE="$(cd -- "$(dirname "$TARGET_DIR")" && pwd -P)/$(basename "$TARGET_DIR")"
				ARCHIVE_DISPLAY="$(basename "$TARGET_DIR")"
				ARCHIVE_CLEAN="$(sanitize_name "$ARCHIVE_DISPLAY")"
				SCRIPT_CHECKSUM="$(find_script checksum-verify.sh)"
				[[ -z "$SCRIPT_CHECKSUM" ]] && { err "checksum-verify.sh not found"; exit 2; }
				log "Archive target detected (probe): $ARCHIVE_DISPLAY"
				CHKSUM_JSON=$("$SCRIPT_CHECKSUM" -sj --no-file --extract "$ARCHIVE_FILE") \
					|| { err "checksum-verify.sh failed extracting '$ARCHIVE_DISPLAY'"; exit 2; }
				EXTRACTED_PATH=$(echo "$CHKSUM_JSON" | jq -r '.crypto_verification.extraction.path // ""' 2>/dev/null || echo "")
				[[ ! -d "$EXTRACTED_PATH" ]] && { err "Extraction produced no valid directory"; exit 2; }
				TARGET_DIR="$EXTRACTED_PATH"
				log "Extracted to: $EXTRACTED_PATH"
			else
				err "'$TARGET_DIR' is not a directory or a supported archive"
				exit 2
			fi
			exit 2
			;;
	esac
fi

# ─── directory validation ──────────────────────────────────────────────
#
if [[ ! -d "$TARGET_DIR" ]]; then
	err "Directory '$TARGET_DIR' not found"
	exit 2
fi

TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd -P)"

# ── single-subdir unwrap ────────────────────────────────────────────────────
# Many packages (WordPress plugins, npm tarballs, etc.) extract to a single
# subdirectory inside the target. If TARGET_DIR contains exactly one entry
# and it is a directory, use it as the effective root so all checks operate
# on the package root rather than a containing wrapper directory.
_sub_entries=()
while IFS= read -r -d '' _sub_e; do
	_sub_entries+=("$_sub_e")
done < <(find "$TARGET_DIR" -maxdepth 1 -mindepth 1 -print0 2>/dev/null)
if [[ ${#_sub_entries[@]} -eq 1 && -d "${_sub_entries[0]}" ]]; then
	TARGET_DIR="${_sub_entries[0]}"
fi
unset _sub_entries _sub_e

DISPLAY_NAME="${ARCHIVE_CLEAN:-$(sanitize_name "$TARGET_DIR")}"
SCAN_START=$SECONDS

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${DISPLAY_NAME}"
OUTPUT_FILE="${OUTPUT_DIR}/${DISPLAY_NAME}.meta.json"

SCRIPT_STATS="$(find_script file-stats.sh)"
SCRIPT_PERMS="$(find_script permission-check.sh)"
SCRIPT_DEEP="$(find_script deep-filescan.sh)"


# ─── dependency checks ─────────────────────────────────────────────────
#
# check all required tools up front so we don't get a partial run where
# one script fails halfway through after the others have completed
#
DEPS_OK=true

check_tool() {
	local tool="$1" required="${2:-true}"
	if ! command -v "$tool" &>/dev/null; then
		if [[ "$required" == "true" ]]; then
			err "Required tool '$tool' not found"
			DEPS_OK=false
		else
			echo "  [WARN] Optional tool '$tool' not found — some output may be degraded" >&2
		fi
	fi
}

check_script() {
	local label="$1" path="$2"
	if [[ -z "$path" ]]; then
		err "Script '$label' not found alongside this file or in PATH"
		DEPS_OK=false
	elif [[ ! -x "$path" ]]; then
		err "Script '$path' is not executable (run: chmod +x $path)"
		DEPS_OK=false
	fi
}


# tools required by all scripts
#
for tool in find file grep xargs wc stat jq; do
	check_tool "$tool"
done

# scripts
check_script "file-stats.sh"       "$SCRIPT_STATS"
check_script "permission-check.sh" "$SCRIPT_PERMS"
[[ "$DEEP_SCAN" == "true" ]] && check_script "deep-filescan.sh" "$SCRIPT_DEEP"

if [[ "$DEPS_OK" == "false" ]]; then
	exit 2
fi


# ─── working directory for temp files & JSON side-outputs ──────────────
#
TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/run-filescans.XXXXXX") || { err "Cannot create temp directory"; exit 2; }

JSON_STATS="$TMPDIR_WORK/stats.json"
JSON_PERMS="$TMPDIR_WORK/perms.json"
JSON_DEEP="$TMPDIR_WORK/deep.json"


# ─── build per-script argument lists ───────────────────────────────────
#
COMMON_ARGS=()
[[ "$VERBOSE" == "true" ]] && COMMON_ARGS+=("--verbose")
# Silence sub-scripts in both --silent and --json modes: in JSON mode sub-script
# text output would corrupt the merged JSON on stdout; in silent mode it is unwanted.
[[ "$SILENT" == "true" || "$JSON_OUTPUT" == "true" ]] && COMMON_ARGS+=("--silent")

# Sub-scripts always get --no-file when invoked from the suite:
# run-filescans.sh handles the single merged output; individual meta
# files would be redundant and may confuse tooling expecting one file.
COMMON_ARGS+=("--no-file")

STATS_ARGS=("${COMMON_ARGS[@]}" "--write-json" "$JSON_STATS" "$TARGET_DIR")
PERMS_ARGS=("${COMMON_ARGS[@]}" "--write-json" "$JSON_PERMS")
[[ "$PERM_FIX" == "true" ]] && PERMS_ARGS+=("--fix")
PERMS_ARGS+=("$TARGET_DIR")

DEEP_ARGS=("${COMMON_ARGS[@]}" "--write-json" "$JSON_DEEP" "$TARGET_DIR")


# ─── run scans ──────────────────────────────────────────────────────────
#
# file-stats and permission-check always run.
# deep-filescan does heavier lifting, so only runs when --deep is passed.
#
# - in silent+json mode, enable scans are launched in parallel & wait for all to complete & gather exit
#	codes; outputs from each script go direct to stdout/stderr with no capture or interleaving necessary
# - in text mode, scripts are run sequentially so output lines are intelligible & not interleaved
#
EXIT_STATS=0
EXIT_PERMS=0
EXIT_DEEP=0

if [[ "$JSON_OUTPUT" == "true" || "$SILENT" == "true" ]]; then

	# ── run in parallel, scripts silent & no output order needed ──
	#
	"$SCRIPT_STATS" "${STATS_ARGS[@]}" &
	PID_STATS=$!
	"$SCRIPT_PERMS" "${PERMS_ARGS[@]}" &
	PID_PERMS=$!

	if [[ "$DEEP_SCAN" == "true" ]]; then
		"$SCRIPT_DEEP" "${DEEP_ARGS[@]}" &
		PID_DEEP=$!
	fi

	wait "$PID_STATS"; EXIT_STATS=$?
	wait "$PID_PERMS"; EXIT_PERMS=$?
	[[ "$DEEP_SCAN" == "true" ]] && { wait "$PID_DEEP"; EXIT_DEEP=$?; }

else
	# ── sequentially to preserve readable text output ──
	#
	log ""
	log "════════════════════════════════════════════════════════════"
	log "  Full Scan: [$DISPLAY_NAME]"
	log "════════════════════════════════════════════════════════════"

	log ""
	log "────────────────────────────────────────────────────────────"
	log "  [1/$(  [[ "$DEEP_SCAN" == "true" ]] && echo 3 || echo 2 )]  File Statistics"
	log "────────────────────────────────────────────────────────────"
	"$SCRIPT_STATS" "${STATS_ARGS[@]}"
	EXIT_STATS=$?

	log ""
	log "────────────────────────────────────────────────────────────"
	log "  [2/$(  [[ "$DEEP_SCAN" == "true" ]] && echo 3 || echo 2 )]  Permission Audit"
	log "────────────────────────────────────────────────────────────"
	"$SCRIPT_PERMS" "${PERMS_ARGS[@]}"
	EXIT_PERMS=$?

	if [[ "$DEEP_SCAN" == "true" ]]; then
		log ""
		log "────────────────────────────────────────────────────────────"
		log "  [3/3]  Content & MIME Scan"
		log "────────────────────────────────────────────────────────────"
		"$SCRIPT_DEEP" "${DEEP_ARGS[@]}"
		EXIT_DEEP=$?
	fi
fi


# ─── JSON merged output ─────────────────────────────────────────────────
#
# gather combine per-script JSON side-output files & combine into one document, preserving individual
# 	component scores as-is; combined risk_level derived from worst severity across all scans, with no
# 	attempt	to combine numeric scores at this stage since the scoring models don't have comparable scales
#
# ─── build_json — assemble merged output document ───────────────────────
#
# Called from both JSON mode (stdout) and the write-file path.
# Writes the complete merged JSON document to stdout.
#
build_json() {
	local _elapsed=$(( SECONDS - SCAN_START ))

	local _null_obj='{"error":"scan did not complete"}'
	local _deep_enabled; _deep_enabled="$( [[ "$DEEP_SCAN" == "true" ]] && echo "true" || echo "false" )"

	COMBINED_RISK_LEVEL="CLEAN"
	[[ $EXIT_STATS -eq 2 || $EXIT_PERMS -eq 2 || $EXIT_DEEP -eq 2 ]] && COMBINED_RISK_LEVEL="ERROR"
	[[ $EXIT_STATS -eq 1 || $EXIT_PERMS -eq 1 ]] && COMBINED_RISK_LEVEL="HIGH"
	[[ "$DEEP_SCAN" == "true" && $EXIT_DEEP -eq 1 ]] && COMBINED_RISK_LEVEL="HIGH"

	local _slurp_args=()
	if [[ -s "$JSON_STATS" ]]; then
		_slurp_args+=(--slurpfile file_stats "$JSON_STATS")
	else
		_slurp_args+=(--argjson  file_stats "$_null_obj")
	fi
	if [[ -s "$JSON_PERMS" ]]; then
		_slurp_args+=(--slurpfile permissions "$JSON_PERMS")
	else
		_slurp_args+=(--argjson  permissions "$_null_obj")
	fi
	# $content_scan must always be defined — jq compiles the entire filter
	# before evaluating it, so referencing $content_scan inside a conditional
	# errors at compile time if the variable was never passed.
	if [[ "$DEEP_SCAN" == "true" ]]; then
		if [[ -s "$JSON_DEEP" ]]; then
			_slurp_args+=(--slurpfile content_scan "$JSON_DEEP")
		else
			_slurp_args+=(--argjson  content_scan "$_null_obj")
		fi
	else
		_slurp_args+=(--argjson content_scan "null")
	fi

	local _filter='
		{
			target_directory:  $dir,
			scan_suite:        "filescan",
			version:           $ver,
			elapsed_seconds:   $elapsed,
			deep_scan_enabled: ($deep == "true"),
			combined: {
				risk_level: $risk
			},
			scans: (
				{
					file_statistics: (if ($file_stats | type) == "array" then $file_stats[0] else $file_stats end),
					permissions:     (if ($permissions  | type) == "array" then $permissions[0]  else $permissions  end)
				}
				+ if ($deep == "true") then {
					content_scan: (if ($content_scan | type) == "array" then $content_scan[0] else $content_scan end)
				  } else {} end
			)
		}
	'

	jq -n \
		--arg     dir     "$DISPLAY_NAME"       \
		--arg     ver     "$VERSION"             \
		--argjson elapsed "$_elapsed"            \
		--arg     risk    "$COMBINED_RISK_LEVEL" \
		--arg     deep    "$_deep_enabled"       \
		"${_slurp_args[@]}"                      \
		"$_filter"
}


if [[ "$JSON_OUTPUT" == "true" && ( "$SILENT" == "false" || "$WRITE_FILE" == "false" ) ]]; then
	# Emit JSON to stdout when:
	#   -j (not silent): stdout for piping; file write also runs below if WRITE_FILE=true
	#   --no-file: stdout is the only destination regardless of -s
	build_json


# ─── text mode: summary footer & optional JSON save ────────────────────
#
elif [[ "$SILENT" == "false" && "$JSON_OUTPUT" == "false" ]]; then
	ELAPSED=$(( SECONDS - SCAN_START ))

	COMBINED_RISK_LEVEL="CLEAN"
	[[ $EXIT_STATS -eq 1 || $EXIT_PERMS -eq 1 ]] && COMBINED_RISK_LEVEL="HIGH"
	[[ "$DEEP_SCAN" == "true" && $EXIT_DEEP -eq 1 ]] && COMBINED_RISK_LEVEL="HIGH"
	[[ $EXIT_STATS -eq 2 || $EXIT_PERMS -eq 2 || $EXIT_DEEP -eq 2 ]] && COMBINED_RISK_LEVEL="ERROR"

	log ""
	log "════════════════════════════════════════════════════════════"
	log "  Full scan complete: [$DISPLAY_NAME]"
	log "  Combined risk level: $COMBINED_RISK_LEVEL"
	log "  Total elapsed: ${ELAPSED}s"
	if [[ "$DEEP_SCAN" == "false" ]]; then
		log "  (deep content scan not run; use --deep to enable)"
	fi
	log "════════════════════════════════════════════════════════════"
	log ""

	# ── offer to save JSON — interactive in verbose mode only ──────────────
	#
	# gated on VERBOSE + stdout is a terminal; suppressed otherwise.
	# for scripted JSON capture: run-filescans.sh -sj ./dir > file.json
	# or use -j which now also writes to ./meta/<name>/<name>.meta.json
	#
	if [[ "$VERBOSE" == "true" && -t 1 ]]; then
		printf "  Save results as JSON? [y/N]  (or re-run with -sj > file.json): "
		read -r _save_ans
		if [[ "${_save_ans,,}" =~ ^y(es)?$ ]]; then
			_default_name="${DISPLAY_NAME}.meta.json"
			printf "  Output filename [%s]: " "$_default_name"
			read -r _save_name
			[[ -z "$_save_name" ]] && _save_name="$_default_name"

			[[ "$_save_name" != /* && "$_save_name" != ./* && "$_save_name" != ../* ]] \
				&& _save_path="$PWD/$_save_name" \
				|| _save_path="$_save_name"

			_save_dir="$(dirname "$_save_path")"
			if [[ ! -d "$_save_dir" ]]; then
				mkdir -p "$_save_dir" 2>/dev/null || {
					echo "  Error: cannot create directory '$_save_dir'" >&2
					_save_path=""
				}
			fi

			if [[ -n "$_save_path" && -f "$_save_path" ]]; then
				printf "  '%s' already exists. Overwrite? [y/N]: " "$_save_name"
				read -r _overwrite
				[[ ! "${_overwrite,,}" =~ ^y(es)?$ ]] && { echo "  Cancelled."; _save_path=""; }
			fi

			if [[ -n "$_save_path" ]]; then
				build_json > "$_save_path" \
					&& echo "  Saved: $_save_name" \
					|| { echo "  Error: could not write JSON" >&2; rm -f "$_save_path"; }
			fi
		fi
	fi
fi


# ─── write JSON output ───────────────────────────────────────────────────
#
# Runs unconditionally after the output section above.
# build_json already wrote to stdout in JSON mode; this handles
# the persistent file copy. The interactive save above is a separate
# user-prompted path, independent of --no-file.
#
if [[ "$WRITE_FILE" == "true" && ( "$JSON_OUTPUT" == "true" || "$SILENT" == "true" ) ]]; then
	mkdir -p "$OUTPUT_DIR" 2>/dev/null \
		|| { err "Cannot create output directory '$OUTPUT_DIR'"; exit 2; }

	FILESCAN_JSON=$(build_json)

	# The output file is <n>.meta.json — a shared artefact that sbom-toolkit
	# also writes to. If it already exists and is valid JSON, merge the filescan
	# results in under the "filescan" key rather than overwriting, so both
	# toolsets contribute to a single combined package record.
	if [[ -f "$OUTPUT_FILE" ]] && jq empty "$OUTPUT_FILE" 2>/dev/null; then
		jq --argjson fs "$FILESCAN_JSON" \
			'. + {filescan: $fs}' \
			"$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" \
			&& mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE" \
			|| { err "Failed to merge filescan data into '$OUTPUT_FILE'"; rm -f "${OUTPUT_FILE}.tmp"; exit 2; }
	else
		# No existing meta.json: create one with filescan results under "filescan".
		# sbom-toolkit can add its own top-level keys alongside it later.
		printf '%s\n' "$FILESCAN_JSON" \
			| jq '{filescan: .}' > "$OUTPUT_FILE"
	fi

	[[ "$SILENT" == "false" ]] && log "[OK]   Saved: $OUTPUT_FILE"
fi



# ─── exit code ──────────────────────────────────────────────────────────
#
# non-zero if any enabled scan found issues or errors
#
WORST_EXIT=$(( EXIT_STATS > EXIT_PERMS ? EXIT_STATS : EXIT_PERMS ))
[[ "$DEEP_SCAN" == "true" && EXIT_DEEP -gt WORST_EXIT ]] && WORST_EXIT=$EXIT_DEEP
exit $WORST_EXIT
