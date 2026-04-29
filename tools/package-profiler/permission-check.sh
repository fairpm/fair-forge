#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# permission-check.sh — file permission auditor
#
# usage: permission-check.sh [OPTIONS] [directory]
#
# recursively audit file and directory permissions for security issues
# designed to be safe against adversarial filenames and untrusted trees
#
# (optionally fix common issues; see --help)
#
# Output file: ./meta/<clean-name>/<clean-name>.perms.json
#
VERSION="1.0.0"


# ─── environment ─────────────────────────────────────────────────
#
set -u                  # unset variables = errors
set -o pipefail         # pipe failures propagate
export LC_ALL=C         # override localizations
IFS=$' \t\n'
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"


# NOTE: sanitize_name is duplicated verbatim across all toolkit scripts.
# Any changes must be kept in sync with the same function in:
#   checksum-verify.sh, dependency-audit.sh, license-check.sh,
#   provenance-verify.sh, sbom-compare.sh, sbom-discover.sh,
#   sbom-gen.sh, sbom-toolkit.sh, slsa-attest.sh,
#   file-stats.sh, deep-filescan.sh
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




# clean exit on signals (don't leave partial output)
TMPDIR_WORK=""
cleanup() {
	[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"
	# if we were writing JSON, close it gracefully
	[[ "${IN_JSON_OUTPUT:-false}" == "true" ]] && echo '{"error": "interrupted"}' >&2
	exit 130
}
trap cleanup INT TERM
trap '[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"' EXIT


# ─── defaults ────────────────────────────────────────────────────
#
FIXIT=false
TARGET_DIR=""
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
IN_JSON_OUTPUT=false
WRITE_JSON_FILE=""    # internal: explicit path override (used by run-filescans.sh)
META_BASE="./meta"    # base directory for standard output
OUTPUT_DIR=""         # default: $META_BASE/<clean-name>/ (set after name detection)
WRITE_FILE=true       # set false with --no-file


# ─── common file extension list: these files should not have +x ───────────
#
# commonly inherited from Windows/FAT/NTFS or extracted from archives without Unix permission support
#
# is_noexec_extension() for the O(1) lookup using this list.
#
NOEXEC_EXTENSIONS_LIST="
jpg jpeg png gif bmp svg webp ico tiff tif psd ai eps
pdf doc docx xls xlsx ppt pptx odt ods odp rtf txt md rst
html htm css json xml xsl xslt yaml yml toml
csv tsv sql sqlite db log lock pid bak
env conf cfg ini htaccess gitignore gitattributes
editorconfig dockerignore nvmrc npmrc eslintrc prettierrc
ttf otf woff woff2 eot
mp3 mp4 m4a wav flac ogg avi mov mkv wmv webm mpg mpeg
zip tar gz bz2 xz 7z rar tgz
tpl twig blade mustache hbs ejs jinja jinja2 j2
map min min.css patch diff pem crt csr key pub asc
license readme changelog
php
"


# ─── sensitive file patterns ────────────────────────────────────
#
# files that may contain passwords, keys, or other credentials should be owner-only (0600/0400/0700)
# flag if group- or world-readable
#
# matched by exact name or extension using find -iname.
#
SENSITIVE_EXACT_NAMES=".env .env.local .env.production .env.staging \
.env.development .htpasswd shadow shadow- gshadow gshadow- \
id_rsa id_ed25519 id_ecdsa id_dsa credentials .netrc .pgpass"

SENSITIVE_EXTENSIONS="pem key p12 pfx jks keystore secret"


# ─── deployment artifacts ───────────────────────────────────────
#
# directories/files indicating source control, IDE, or OS metadata that don't belong in production environments
#
ARTIFACT_DIRS=".git .svn .hg .bzr .idea .vscode"
ARTIFACT_FILES=".DS_Store Thumbs.db .gitignore .gitattributes \
desktop.ini ._*"


# ─── declare the functions ──────────────────────────────────────
#

show_help() {
	cat << 'HELPEOF'

PERMISSION-CHECK:
	Recursively audit file and directory permissions for security issues.

HELPEOF
	cat << EOF
	permission-check.sh Version $VERSION

USAGE:
	$(basename "$0") [OPTIONS] [directory]

OPTIONS:
	-h, --help          Show this help message
	-s, --silent        Suppress output (exit code only)
	-j, --json          Output results in JSON format
	-sj, -js            Silent + JSON (pipe-friendly)
	-v, --verbose       Verbose output (list every finding)
	-f, --fix           Fix issues: remove world-writable perms, add sticky
	                    bits to world-writable dirs, strip exec from data
	                    files, restrict exposed sensitive files
	-o, --output-dir D  Write JSON output to directory D
	                    (default: ./meta/<clean-name>/)
	--meta-base DIR     Base directory for meta output (default: ./meta)
	--no-file           Output JSON to stdout only; do not write file
	--write-json F      Write JSON results to file F (used by run-filescans.sh)
	--version           Print version and exit

ARGUMENTS:
	[directory]         Directory to scan (default: current directory)

OUTPUT:
	./meta/<clean-name>/<clean-name>.perms.json

CHECKS FOR:
	world-writable       Files/dirs writable by any user (o+w)
	missing sticky bit   World-writable dirs without +t (deletion risk)
	privilege escalation SUID or SGID bits set
	perm inversions      Owner has fewer rights than group or others
	external symlinks    Symlinks targeting outside the scanned tree
	dangling symlinks    Symlinks whose target does not exist
	internal symlinks    Symlinks within the tree (informational)
	unnecessary exec     Data files with executable bit (cross-OS artifact)
	sensitive exposure   Private keys, .env, .htpasswd etc. not restricted
	orphaned ownership   Files owned by UIDs/GIDs with no system user/group
	deploy artifacts     .git/, .svn/, .DS_Store etc. in the tree

RISK SCORING:
	Critical issues set a risk floor. Non-critical findings add to the score.
	Hardened file permissions are noted as informational only and do not
	reduce the risk score — scores should be comparable across packages.

	Critical:     world-writable, SUID/GUID, inversions, external
	              symlinks, missing sticky bit, sensitive exposure
	Non-critical: internal/dangling symlinks, unnecessary exec,
	              orphaned files, deploy artifacts

EXIT CODES:
	0  No critical issues found (or all fixed with --fix)
	1  Critical issues found (or fix failures with --fix)
	2  Errors during execution

EXAMPLES:
	$(basename "$0")
	$(basename "$0") --fix /var/www/html
	$(basename "$0") -vj ./uploads
	$(basename "$0") -s . && echo "OK" || echo "FAIL"
	$(basename "$0") -j --no-file ./dir > audit.json

EOF
}


# write function for non-silent modes
#
log() {
	[[ "$SILENT" == "false" ]] && [[ "$JSON_OUTPUT" == "false" ]] && echo "$@" >&2
}


# json-escape $string - deal with \ " / and control characters U+0000–U+001F (see RFC 8259 §7)
#
json_esc() {
	local s="$1"
	local out=""
	local i char ord

	for (( i=0; i<${#s}; i++ )); do
		char="${s:$i:1}"
		case "$char" in
			\\) out+='\\'  ;;
			'"') out+='\"' ;;
			$'\n') out+='\n'  ;;
			$'\r') out+='\r'  ;;
			$'\t') out+='\t'  ;;
			$'\b') out+='\b'  ;;
			$'\f') out+='\f'  ;;
			*)
				# check for remaining control characters (0x00–0x1F)
				ord=$(printf '%d' "'$char" 2>/dev/null || echo 0)
				if (( ord >= 0 && ord < 32 )); then
					printf -v escaped '\\u%04x' "$ord"
					out+="$escaped"
				else
					out+="$char"
				fi
				;;
		esac
	done
	printf '%s' "$out"
}


# classify octal permissions and set
# 	IS_WORLD_WRITABLE
# 	IS_PERM_INVERSION
# 	IS_SECURE_PERM
#
classify_perms() {
	local octal="$1"

	IS_WORLD_WRITABLE=false
	IS_PERM_INVERSION=false
	IS_SECURE_PERM=false

	[[ "$octal" == "???" ]] && return

	local numeric=$((10#$octal))
	local others=$(( numeric % 10 ))
	local group=$(( (numeric / 10) % 10 ))
	local owner=$(( (numeric / 100) % 10 ))

	# others = world
	(( others & 2 )) && IS_WORLD_WRITABLE=true

	# file owner should not have lower permissions than group|world
	if (( owner < group || owner < others )); then
		IS_PERM_INVERSION=true
	fi

	local owner_w=$(( owner & 2 ))
	local group_w=$(( group & 2 ))
	local others_w=$(( others & 2 ))

	# sometimes write access removed for security, even from owner
	if (( owner_w == 0 && group_w == 0 && others_w == 0 )); then
		IS_SECURE_PERM=true
	elif (( group == 0 && others == 0 )); then
		IS_SECURE_PERM=true
	fi
}


# classify symlink target and set
# 	SYMLINK_CLASS	-  internal | external | dangling
#       SYMLINK_TARGET	- canonical path, or best-effort for dangling
#       not penalized if links within its own directory tree; links outside that are bad!
#
classify_symlink() {
	local link_path="$1"
	SYMLINK_CLASS=""
	SYMLINK_TARGET=""

	local raw_target
	raw_target=$(readlink -- "$link_path" 2>/dev/null) || { SYMLINK_CLASS="dangling"; return; }

	local resolved
	resolved=$(readlink -e -- "$link_path" 2>/dev/null)

	if [[ -z "$resolved" ]]; then
		if [[ "$raw_target" == /* ]]; then
			SYMLINK_TARGET="$raw_target"
		else
			local link_dir
			link_dir=$(dirname -- "$link_path")
			SYMLINK_TARGET=$(readlink -m -- "$link_dir/$raw_target" 2>/dev/null || echo "$link_dir/$raw_target")
		fi
		SYMLINK_CLASS="dangling"
		return
	fi

	SYMLINK_TARGET="$resolved"

	if [[ "$resolved" == "$TARGET_DIR" || "$resolved" == "$TARGET_DIR/"* ]]; then
		SYMLINK_CLASS="internal"
	else
		SYMLINK_CLASS="external"
	fi
}


# build associative array for noexec extension lookup
#
declare -A NOEXEC_SET=()
for _ext in $NOEXEC_EXTENSIONS_LIST; do
	NOEXEC_SET["$_ext"]=1
done

is_noexec_extension() {
	local filename="${1##*/}"
	local ext="${filename##*.}"
	# No extension: plain name like "Dockerfile"
	[[ "$ext" == "$filename" ]] && return 1
	# Hidden extensionless file (e.g., .gitignore, .eslintignore): treat as no extension
	[[ "$filename" == .* && "${filename#.}" != *.* ]] && return 1
	ext="${ext,,}"
	[[ -n "${NOEXEC_SET[$ext]+x}" ]] && return 0
	return 1
}


# format octal permission safely (avoid any non-numeric stat output)
#
format_perm() {
	local perm="$1"
	if [[ "$perm" =~ ^[0-9]+$ ]]; then
		printf '%04d' "$perm"
	else
		echo "????"
	fi
}


# ─── parse received args ───────────────────────────────────────────
#
while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)    show_help; exit 0 ;;
		--version)    echo "permission-check.sh v$VERSION"; exit 0 ;;
		--verbose|-v) VERBOSE=true; shift ;;
		--silent|-s)  SILENT=true; shift ;;
		--json|-j)    JSON_OUTPUT=true; shift ;;
		--fix|-f)     FIXIT=true; shift ;;
		-o|--output-dir)
		              [[ -z "${2:-}" ]] && { echo "Error: --output-dir requires an argument" >&2; exit 2; }
		              OUTPUT_DIR="$2"; shift 2 ;;
		--meta-base)
		              [[ -z "${2:-}" ]] && { echo "Error: --meta-base requires an argument" >&2; exit 2; }
		              META_BASE="$2"; shift 2 ;;
		--no-file)    WRITE_FILE=false; shift ;;
		--write-json) [[ -z "${2:-}" ]] && { echo "Error: --write-json requires a file path" >&2; exit 2; }
		              WRITE_JSON_FILE="$2"; shift 2 ;;
		--)           shift; break ;;

		-[a-zA-Z][a-zA-Z]* )
			opt_string="${1#-}"
			shift
			for (( i=${#opt_string}-1; i>=0; i-- )); do
				set -- "-${opt_string:$i:1}" "$@"
			done
			;;

		-*)
			echo "Error: Unknown option '$1'" >&2
			echo "Try '$(basename "$0") --help' for usage." >&2
			exit 2
			;;
		*)  TARGET_DIR="$1"; shift ;;
	esac
done

if [[ $# -gt 0 && -z "$TARGET_DIR" ]]; then
	TARGET_DIR="$1"
fi

TARGET_DIR="${TARGET_DIR:-.}"
if [[ ! -d "$TARGET_DIR" ]]; then
	echo "Error: Directory '$TARGET_DIR' not found" >&2
	exit 2
fi

# physical path is needed for symlink inside/outside comparison
#
TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd -P)"

# ── single-subdir unwrap ────────────────────────────────────────────────────
# Many packages extract to a single subdirectory. If TARGET_DIR contains
# exactly one entry and it is a directory, use it as the effective root.
_sub_entries=()
while IFS= read -r -d '' _sub_e; do
	_sub_entries+=("$_sub_e")
done < <(find "$TARGET_DIR" -maxdepth 1 -mindepth 1 -print0 2>/dev/null)
if [[ ${#_sub_entries[@]} -eq 1 && -d "${_sub_entries[0]}" ]]; then
	TARGET_DIR="${_sub_entries[0]}"
fi
unset _sub_entries _sub_e

CLEAN_NAME="$(sanitize_name "$TARGET_DIR")"
SCAN_START=$SECONDS

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${CLEAN_NAME}"
OUTPUT_FILE="${OUTPUT_DIR}/${CLEAN_NAME}.perms.json"

# jq is required for JSON output formatting
#
command -v jq &>/dev/null || {
	echo "Error: Required tool 'jq' not found" >&2
	exit 2
}

# working directory for temp files (findings JSONL for generate_json)
#
TMPDIR_WORK=$(mktemp -d) || { echo "Error: Cannot create temp directory" >&2; exit 2; }


declare -a FINDINGS=()

if [[ "$FIXIT" == "true" ]]; then FIXFLAG="Fixed"; else FIXFLAG="Flagged"; fi

if [[ "$JSON_OUTPUT" == "false" ]]; then
	log ""
	if [[ "$FIXIT" == "true" ]]; then
		log "[INFO] Permission audit + fix for [$CLEAN_NAME]"
	else
		log "[INFO] Permission audit for [$CLEAN_NAME]"
	fi
	[[ "$VERBOSE" == "true" ]] && log "----------------------------------------------"
fi


# ─── init counters ───────────────────────────────────────────────────
#
WRITABLE_FILES=0
WRITABLE_DIRS=0
STICKY_MISSING=0
SYMLINK_INTERNAL=0
SYMLINK_EXTERNAL=0
SYMLINK_DANGLING=0
PRIV_ESC_COUNT=0
PERM_INVERSION_COUNT=0
NOEXEC_COUNT=0
SECURE_PERM_COUNT=0
VENDOR_HARDENED_COUNT=0
SENSITIVE_COUNT=0
ORPHAN_COUNT=0
ARTIFACT_COUNT=0
FIXED_COUNT=0
FIXED_NOEXEC=0
FIXED_STICKY=0
FIXED_SENSITIVE=0
FAILED_COUNT=0
SKIPPED_LINKS=0


# ─── multi-pass scanning ────────────────────────────────────────────────
#
# using 7 targeted find commands rather than a single scan-everything approach to keep queries simple
# & work around find's inability to handle cross-field logic (e.g., "owner digit < group digit")
#

FLAGGED_ITEMS=()

# scan 1: find world-writable, SUID, SGID, & symlinks
#
while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" \( \
	-perm -002 \
	-o -perm -2000 \
	-o -perm -4000 \
	-o -type l \
	\) -print0 2>/dev/null)


# scan 2: find secure permission patterns (these are good)
#
while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" -not -type l \
	-not -perm -002 -not -perm -2000 -not -perm -4000 \
	\( \
		-perm 0400 -o -perm 0440 -o -perm 0444 \
		-o -perm 0500 -o -perm 0550 -o -perm 0555 \
		-o -perm 0600 -o -perm 0700 \
	\) -print0 2>/dev/null)


# scan 3: permission inversion (owner < group | world)
#
while IFS= read -r -d '' item; do
	perm=$(stat -c "%a" "$item" 2>/dev/null) || continue
	[[ "$perm" =~ ^[0-9]+$ ]] || continue
	numeric=$((10#$perm))
	o_digit=$(( (numeric / 100) % 10 ))
	g_digit=$(( (numeric / 10) % 10 ))
	e_digit=$(( numeric % 10 ))
	if (( o_digit < g_digit || o_digit < e_digit )); then
		FLAGGED_ITEMS+=("$item")
	fi
done < <(find "$TARGET_DIR" -not -type l \
	-not -perm -002 -not -perm -2000 -not -perm -4000 \
	-print0 2>/dev/null)


# scan 4: unnecessary executable bits
NOEXEC_FIND_EXPR=()
_first=true
for _ext in $NOEXEC_EXTENSIONS_LIST; do
	if [[ "$_first" == "true" ]]; then
		NOEXEC_FIND_EXPR+=( "-iname" "*.${_ext}" )
		_first=false
	else
		NOEXEC_FIND_EXPR+=( "-o" "-iname" "*.${_ext}" )
	fi
done

while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" -type f -perm /111 \
	\( "${NOEXEC_FIND_EXPR[@]}" \) \
	-print0 2>/dev/null)


# scan 5: sensitive files that lack restrictive permissions
SENSITIVE_FIND_EXPR=()
_first=true
for _name in $SENSITIVE_EXACT_NAMES; do
	if [[ "$_first" == "true" ]]; then
		SENSITIVE_FIND_EXPR+=( "-iname" "$_name" )
		_first=false
	else
		SENSITIVE_FIND_EXPR+=( "-o" "-iname" "$_name" )
	fi
done
for _ext in $SENSITIVE_EXTENSIONS; do
	SENSITIVE_FIND_EXPR+=( "-o" "-iname" "*.${_ext}" )
done

# exposed = readable by group or others (not 0600/0400/0700)
while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" -type f \
	\( "${SENSITIVE_FIND_EXPR[@]}" \) \
	-not -perm 0600 -not -perm 0400 -not -perm 0700 \
	-not -perm 0000 \
	-print0 2>/dev/null)


# scan 6: orphaned files without a valid user:group
#
while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" \( -nouser -o -nogroup \) \
	-print0 2>/dev/null)


# scan 7: deployment artifacts
#
ARTIFACT_DIR_EXPR=()
_first=true
for _name in $ARTIFACT_DIRS; do
	if [[ "$_first" == "true" ]]; then
		ARTIFACT_DIR_EXPR+=( "-name" "$_name" )
		_first=false
	else
		ARTIFACT_DIR_EXPR+=( "-o" "-name" "$_name" )
	fi
done

ARTIFACT_FILE_EXPR=()
_first=true
for _name in $ARTIFACT_FILES; do
	if [[ "$_first" == "true" ]]; then
		ARTIFACT_FILE_EXPR+=( "-name" "$_name" )
		_first=false
	else
		ARTIFACT_FILE_EXPR+=( "-o" "-name" "$_name" )
	fi
done

while IFS= read -r -d '' item; do
	FLAGGED_ITEMS+=("$item")
done < <(find "$TARGET_DIR" \( \
	\( -type d \( "${ARTIFACT_DIR_EXPR[@]}" \) -prune \) \
	-o \( -type f \( "${ARTIFACT_FILE_EXPR[@]}" \) \) \
	\) -print0 2>/dev/null)


# ─── deduplicate ────────────────────────────────────────────────
#
declare -A SEEN_ITEMS=()
UNIQUE_ITEMS=()
for item in "${FLAGGED_ITEMS[@]}"; do
	[[ -z "$item" ]] && continue
	if [[ -z "${SEEN_ITEMS[$item]+x}" ]]; then
		SEEN_ITEMS[$item]=1
		UNIQUE_ITEMS+=("$item")
	fi
done
FLAGGED_ITEMS=("${UNIQUE_ITEMS[@]+"${UNIQUE_ITEMS[@]}"}")


# helper function to add a finding to our JSON array
# args: status, issue_type, perms, file_path [, key, val ...]
add_finding() {
	local status="$1" issue_type="$2" perms="$3" fpath="$4"
	shift 4
	local extra=""
	while [[ $# -ge 2 ]]; do
		extra+=", \"$(json_esc "$1")\": \"$(json_esc "$2")\""
		shift 2
	done
	FINDINGS+=("{\"status\": \"$(json_esc "$status")\", \"issue_type\": \"$(json_esc "$issue_type")\", \"permissions\": \"$(json_esc "$perms")\", \"file_path\": \"$(json_esc "$fpath")\"${extra}}")
}


# create associative arrays for sensitive file lookup
#
declare -A SENSITIVE_NAME_SET=()
for _name in $SENSITIVE_EXACT_NAMES; do
	SENSITIVE_NAME_SET["${_name,,}"]=1
done
declare -A SENSITIVE_EXT_SET=()
for _ext in $SENSITIVE_EXTENSIONS; do
	SENSITIVE_EXT_SET["$_ext"]=1
done

is_sensitive_file() {
	local filename="${1##*/}"
	local lower="${filename,,}"
	[[ -n "${SENSITIVE_NAME_SET[$lower]+x}" ]] && return 0
	local ext="${filename##*.}"
	[[ "$ext" != "$filename" && -n "${SENSITIVE_EXT_SET[${ext,,}]+x}" ]] && return 0
	return 1
}


# artifact detection
#
declare -A ARTIFACT_DIR_SET=()
for _name in $ARTIFACT_DIRS; do
	ARTIFACT_DIR_SET["$_name"]=1
done
declare -A ARTIFACT_FILE_SET=()
for _name in $ARTIFACT_FILES; do
	ARTIFACT_FILE_SET["$_name"]=1
done

is_artifact() {
	local path="$1"
	local name="${path##*/}"
	if [[ -d "$path" ]]; then
		[[ -n "${ARTIFACT_DIR_SET[$name]+x}" ]] && return 0
	else
		[[ -n "${ARTIFACT_FILE_SET[$name]+x}" ]] && return 0
		# check ._* pattern (macOS resource forks)
		[[ "$name" == ._* ]] && return 0
	fi
	return 1
}


# ─── loop to process flagged items ──────────────────────────────────
#
for item in "${FLAGGED_ITEMS[@]}"; do
	[[ -z "$item" ]] && continue

	if [[ ! -e "$item" ]] && [[ ! -L "$item" ]]; then
		continue
	fi

	FOUND_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
	FORMATTED_PERMS=$(format_perm "$FOUND_PERM")
	WHERE="${item#"$TARGET_DIR"}"
	WHERE="$CLEAN_NAME${WHERE}"

	ISSUE=""
	ITEM_HAD_CRITICAL=false

	# ── symlink ──
	if [[ -L "$item" ]]; then
		classify_symlink "$item"

		case "$SYMLINK_CLASS" in
			external)
				((++SYMLINK_EXTERNAL))
				ISSUE="external_symlink"
				[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  external symlink      : $WHERE → $SYMLINK_TARGET"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "target" "$SYMLINK_TARGET"
				;;
			dangling)
				((++SYMLINK_DANGLING))
				ISSUE="dangling_symlink"
				[[ "$VERBOSE" == "true" ]] && log "[WARN] $FORMATTED_PERMS  dangling symlink      : $WHERE → $SYMLINK_TARGET (broken)"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "target" "$SYMLINK_TARGET"
				;;
			internal|*)
				((++SYMLINK_INTERNAL))
				ISSUE="internal_symlink"
				[[ "$VERBOSE" == "true" ]] && log "[INFO] $FORMATTED_PERMS  internal symlink      : $WHERE → $SYMLINK_TARGET"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "target" "$SYMLINK_TARGET"
				;;
		esac

		if [[ "$FIXIT" == "true" ]]; then
			((SKIPPED_LINKS++))
			[[ "$VERBOSE" == "true" ]] && log "[SKIP]  $FORMATTED_PERMS  symlink (skipped)    : $WHERE"
		fi
		continue
	fi

	# ── classify permissions ──
	classify_perms "$FOUND_PERM"

	# ── deployment artifacts ──
	if is_artifact "$item"; then
		((++ARTIFACT_COUNT))
		ISSUE="deploy_artifact"
		[[ "$VERBOSE" == "true" ]] && log "[WARN] $FORMATTED_PERMS  deploy artifact      : $WHERE"
		[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
	fi

	# ── orphaned owner ────────
	if [[ ! -L "$item" ]]; then
		owner_uid=$(stat -c "%u" "$item" 2>/dev/null || echo "")
		owner_gid=$(stat -c "%g" "$item" 2>/dev/null || echo "")
		is_orphan=false
		if [[ -n "$owner_uid" ]] && ! getent passwd "$owner_uid" &>/dev/null; then
			is_orphan=true
		fi
		if [[ -n "$owner_gid" ]] && ! getent group "$owner_gid" &>/dev/null; then
			is_orphan=true
		fi
		if [[ "$is_orphan" == "true" ]]; then
			((++ORPHAN_COUNT))
			ISSUE="orphaned_ownership"
			[[ "$VERBOSE" == "true" ]] && log "[WARN] $FORMATTED_PERMS  orphaned (uid=$owner_uid gid=$owner_gid) : $WHERE"
			[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "uid" "$owner_uid" "gid" "$owner_gid"
		fi
	fi

	# ── SUID/GUID ──────────────
	if [[ -u "$item" || -g "$item" ]]; then
		((++PRIV_ESC_COUNT))
		ISSUE="privilege_escalation"
		ITEM_HAD_CRITICAL=true
		[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  privilege escalation : $WHERE"
		[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
	fi

	# ── permission inversion ───
	if [[ "$IS_PERM_INVERSION" == "true" ]]; then
		((++PERM_INVERSION_COUNT))
		local_numeric=$((10#$FOUND_PERM))
		local_owner=$(( (local_numeric / 100) % 10 ))
		local_group=$(( (local_numeric / 10) % 10 ))
		local_others=$(( local_numeric % 10 ))
		ISSUE="permission_inversion"
		ITEM_HAD_CRITICAL=true
		[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  perm inversion (o=${local_owner} < g=${local_group}|e=${local_others}) : $WHERE"
		[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
	fi

	# ── world-writable ──
	if [[ "$IS_WORLD_WRITABLE" == "true" ]]; then
		ITEM_HAD_CRITICAL=true

		if [[ -d "$item" ]]; then
			((++WRITABLE_DIRS))
			ISSUE="world-writable_dir"
			[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  $ISSUE  : $WHERE"
			[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"

			# ── sticky bit check ──
			# world-writable dir without +t means any user can delete others' files
			if [[ ! -k "$item" ]]; then
				((++STICKY_MISSING))
				[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  missing sticky bit   : $WHERE"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "missing_sticky_bit" "$FORMATTED_PERMS" "$WHERE"

				if [[ "$FIXIT" == "true" ]]; then
					if chmod +t -- "$item" 2>/dev/null; then
						((FIXED_STICKY++))
						[[ "$VERBOSE" == "true" ]] && log "[FIXED] +t (sticky bit) : $WHERE"
						[[ "$JSON_OUTPUT" == "true" ]] && add_finding "fixed" "missing_sticky_bit" "$FORMATTED_PERMS" "$WHERE"
					else
						((FAILED_COUNT++))
						[[ "$VERBOSE" == "true" ]] && log "[FAIL]  could not set sticky bit : $WHERE"
						[[ "$JSON_OUTPUT" == "true" ]] && add_finding "failed" "missing_sticky_bit" "$FORMATTED_PERMS" "$WHERE"
					fi
				fi
			fi
		else
			((++WRITABLE_FILES))
			ISSUE="world-writable_file"
			[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  $ISSUE  : $WHERE"
			[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
		fi

		# fix world-writable
		if [[ "$FIXIT" == "true" ]]; then
			if chmod o-w -- "$item" 2>/dev/null; then
				FIXED_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
				((FIXED_COUNT++))
				[[ "$VERBOSE" == "true" ]] && log "[FIXED] $FOUND_PERM → $FIXED_PERM (o-w) : $WHERE"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "fixed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "new_permissions" "$(format_perm "$FIXED_PERM")"
				FOUND_PERM="$FIXED_PERM"
			else
				((FAILED_COUNT++))
				[[ "$VERBOSE" == "true" ]] && log "[FAIL]  could not fix : $WHERE"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "failed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
			fi
		fi
	fi

	# ── sensitive file exposure ──
	if [[ -f "$item" ]] && is_sensitive_file "$item"; then
		# check if group or others have ANY read access
		perm_numeric=$((10#$FOUND_PERM))
		perm_group=$(( (perm_numeric / 10) % 10 ))
		perm_others=$(( perm_numeric % 10 ))

		if (( perm_group > 0 || perm_others > 0 )); then
			((++SENSITIVE_COUNT))
			ISSUE="sensitive_exposure"
			ITEM_HAD_CRITICAL=true
			[[ "$VERBOSE" == "true" ]] && log "[CRIT] $FORMATTED_PERMS  sensitive exposure    : $WHERE"
			[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"

			if [[ "$FIXIT" == "true" ]]; then
				if chmod go= -- "$item" 2>/dev/null; then
					FIXED_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
					((FIXED_SENSITIVE++))
					[[ "$VERBOSE" == "true" ]] && log "[FIXED] $FOUND_PERM → $FIXED_PERM (go=) : $WHERE"
					[[ "$JSON_OUTPUT" == "true" ]] && add_finding "fixed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "new_permissions" "$(format_perm "$FIXED_PERM")"
					FOUND_PERM="$FIXED_PERM"
				else
					((FAILED_COUNT++))
					[[ "$VERBOSE" == "true" ]] && log "[FAIL]  could not restrict : $WHERE"
					[[ "$JSON_OUTPUT" == "true" ]] && add_finding "failed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
				fi
			fi
		fi
	fi

	# ── check for unnecessary executable bit ──
	if [[ -f "$item" && -x "$item" ]] && is_noexec_extension "$item"; then
		((++NOEXEC_COUNT))
		ext="${item##*.}"
		ISSUE="unnecessary_exec"
		[[ "$VERBOSE" == "true" ]] && log "[WARN] $FORMATTED_PERMS  unnecessary exec (.${ext,,}) : $WHERE"
		[[ "$JSON_OUTPUT" == "true" ]] && add_finding "found" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "extension" "${ext,,}"

		if [[ "$FIXIT" == "true" ]]; then
			if chmod a-x -- "$item" 2>/dev/null; then
				FIXED_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
				((FIXED_NOEXEC++))
				[[ "$VERBOSE" == "true" ]] && log "[FIXED] $FOUND_PERM → $FIXED_PERM (a-x) : $WHERE"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "fixed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE" "new_permissions" "$(format_perm "$FIXED_PERM")"
			else
				((FAILED_COUNT++))
				[[ "$VERBOSE" == "true" ]] && log "[FAIL]  could not strip exec : $WHERE"
				[[ "$JSON_OUTPUT" == "true" ]] && add_finding "failed" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
			fi
		fi

	# ── secure permissions (if no critical issues) ──
	elif [[ "$IS_SECURE_PERM" == "true" && "$ITEM_HAD_CRITICAL" == "false" ]]; then
		ISSUE="secure_permissions"
		# Vendor/third-party hardened files are tracked separately and reported only in aggregate.
		# The goal is to assess the primary package, not individual dependencies.
		if [[ "$item" == *"/vendor/"* || "$item" == *"/node_modules/"* ]]; then
			((++VENDOR_HARDENED_COUNT))
		else
			((++SECURE_PERM_COUNT))
			[[ "$VERBOSE" == "true" ]] && log "[INFO] $FORMATTED_PERMS  hardened (info)      : $WHERE"
			[[ "$JSON_OUTPUT" == "true" ]] && add_finding "info" "$ISSUE" "$FORMATTED_PERMS" "$WHERE"
		fi
	fi
done


# ─── summary stats ──────────────────────────────────────────────
#
ALL_TOTAL_FILES=$(find "$TARGET_DIR" -type f 2>/dev/null | wc -l)
ALL_TOTAL_DIRS=$(find "$TARGET_DIR" -type d 2>/dev/null | wc -l)
ALL_TOTAL=$((ALL_TOTAL_FILES + ALL_TOTAL_DIRS))
PASSED_FILES=$((ALL_TOTAL_FILES - WRITABLE_FILES))
PASSED_DIRS=$((ALL_TOTAL_DIRS - WRITABLE_DIRS))
SYMLINK_TOTAL=$((SYMLINK_INTERNAL + SYMLINK_EXTERNAL + SYMLINK_DANGLING))

TOTAL_ISSUES=$((WRITABLE_FILES + WRITABLE_DIRS + STICKY_MISSING \
	+ SYMLINK_EXTERNAL + SYMLINK_DANGLING \
	+ PRIV_ESC_COUNT + PERM_INVERSION_COUNT \
	+ SENSITIVE_COUNT + NOEXEC_COUNT \
	+ ORPHAN_COUNT + ARTIFACT_COUNT))

ALL_FIXED=$((FIXED_COUNT + FIXED_NOEXEC + FIXED_STICKY + FIXED_SENSITIVE))


# ─── risk score ────────────────────────────────────────────────
#
# critical: hard floor, cannot be reduced
CRITICAL_RISK=$(( WRITABLE_FILES * 10 + WRITABLE_DIRS * 15 \
	+ STICKY_MISSING * 20 \
	+ PRIV_ESC_COUNT * 20 + PERM_INVERSION_COUNT * 30 \
	+ SYMLINK_EXTERNAL * 25 \
	+ SENSITIVE_COUNT * 25 ))

# non-critical
OTHER_RISK=$(( SYMLINK_INTERNAL * 5 + SYMLINK_DANGLING * 10 \
	+ NOEXEC_COUNT * 3 + ORPHAN_COUNT * 10 + ARTIFACT_COUNT * 8 ))

# Score is a straight sum; no credit/offset applied.
# Hardened files are reported as informational only — they reduce real risk by narrowing
# attack surface, but crediting them against findings would mask genuine issues and
# make scores non-comparable across packages with different dependency footprints.
RISK_SCORE=$(( CRITICAL_RISK + OTHER_RISK ))


# ─── output ─────────────────────────────────────────────────────
#

# generate_json — write complete JSON document to stdout.
# all scan variables must be set before calling.
# uses TMPDIR_WORK for a scratch findings file; that dir is set up below.
#
generate_json() {
	local _findings_file="$TMPDIR_WORK/findings.jsonl"
	: > "$_findings_file"
	for (( _i=0; _i<${#FINDINGS[@]}; _i++ )); do
		printf '%s\n' "${FINDINGS[$_i]}" >> "$_findings_file"
	done

	local _elapsed=$(( SECONDS - SCAN_START ))
	local _fix_mode; _fix_mode=$( [[ "$FIXIT" == "true" ]] && echo 'true' || echo 'false' )

	jq -n \
		--arg     dir           "$CLEAN_NAME"          \
		--arg     ver           "$VERSION"              \
		--argjson elapsed       "$_elapsed"             \
		--argjson fix_mode      "$_fix_mode"            \
		--argjson total         "$ALL_TOTAL"            \
		--argjson total_issues  "$TOTAL_ISSUES"         \
		--argjson total_dirs    "$ALL_TOTAL_DIRS"       \
		--argjson passed_dirs   "$PASSED_DIRS"          \
		--argjson total_files   "$ALL_TOTAL_FILES"      \
		--argjson passed_files  "$PASSED_FILES"         \
		--argjson writ_files    "$WRITABLE_FILES"       \
		--argjson writ_dirs     "$WRITABLE_DIRS"        \
		--argjson sticky        "$STICKY_MISSING"       \
		--argjson sym_total     "$SYMLINK_TOTAL"        \
		--argjson sym_ext       "$SYMLINK_EXTERNAL"     \
		--argjson sym_dang      "$SYMLINK_DANGLING"     \
		--argjson sym_int       "$SYMLINK_INTERNAL"     \
		--argjson priv_esc      "$PRIV_ESC_COUNT"       \
		--argjson perm_inv      "$PERM_INVERSION_COUNT" \
		--argjson noexec        "$NOEXEC_COUNT"         \
		--argjson sensitive     "$SENSITIVE_COUNT"      \
		--argjson orphan        "$ORPHAN_COUNT"         \
		--argjson artifact      "$ARTIFACT_COUNT"       \
		--argjson secure        "$SECURE_PERM_COUNT"    \
		--argjson vendor_sec    "$VENDOR_HARDENED_COUNT"\
		--argjson fixed         "$ALL_FIXED"            \
		--argjson failed        "$FAILED_COUNT"         \
		--argjson skipped       "$SKIPPED_LINKS"        \
		--argjson risk_score    "$RISK_SCORE"           \
		--argjson crit_floor    "$CRITICAL_RISK"        \
		--argjson other_risk    "$OTHER_RISK"           \
		--slurpfile findings    "$_findings_file"       \
		'{
			target_directory:  $dir,
			scan_type:         "permission_audit",
			version:           $ver,
			elapsed_seconds:   $elapsed,
			fix_mode:          $fix_mode,
			summary: {
				items_checked:             $total,
				total_issues:              $total_issues,
				total_directories:         $total_dirs,
				passed_directories:        $passed_dirs,
				total_files:               $total_files,
				passed_files:              $passed_files,
				writable_files:            $writ_files,
				writable_directories:      $writ_dirs,
				missing_sticky_bit:        $sticky,
				symlinks: {
					total:    $sym_total,
					external: $sym_ext,
					dangling: $sym_dang,
					internal: $sym_int
				},
				privilege_escalation:      $priv_esc,
				permission_inversions:     $perm_inv,
				unnecessary_exec:          $noexec,
				sensitive_exposure:        $sensitive,
				orphaned_ownership:        $orphan,
				deploy_artifacts:          $artifact,
				secure_permissions:        $secure,
				vendor_secure_permissions: $vendor_sec,
				fixed:                     $fixed,
				failed:                    $failed,
				skipped_symlinks:          $skipped
			},
			risk: {
				score:          $risk_score,
				critical_floor: $crit_floor,
				other_risk:     $other_risk
			},
			findings: $findings
		}'
}


if [[ "$JSON_OUTPUT" == "true" ]]; then
	IN_JSON_OUTPUT=true
	generate_json
	IN_JSON_OUTPUT=false

else
	log "----------------------------------------------"
	log "CHECKED $ALL_TOTAL items"
	log "        $ALL_TOTAL_DIRS directories checked, $PASSED_DIRS passed"
	log "        $ALL_TOTAL_FILES files checked, $PASSED_FILES passed"
	log "----------------------------------------------"
	log "CRITICAL ISSUES"
	log "        $WRITABLE_FILES world-writable files ($FIXFLAG)"
	log "        $WRITABLE_DIRS world-writable directories ($FIXFLAG)"
	log "        $STICKY_MISSING missing sticky bits on writable dirs ($FIXFLAG)"
	log "        $PRIV_ESC_COUNT SUID/GUID bits (privilege escalation)"
	log "        $PERM_INVERSION_COUNT permission inversions (owner < group|others)"
	log "        $SYMLINK_EXTERNAL external symlinks (target outside tree)"
	log "        $SENSITIVE_COUNT sensitive files exposed ($FIXFLAG)"
	log "----------------------------------------------"
	log "WARNINGS"
	log "        $SYMLINK_DANGLING dangling symlinks (broken target)"
	log "        $NOEXEC_COUNT unnecessary executable bits ($FIXFLAG)"
	log "        $ORPHAN_COUNT orphaned files (uid/gid has no system user)"
	log "        $ARTIFACT_COUNT deployment artifacts"
	log "----------------------------------------------"
	log "INFO    $SYMLINK_INTERNAL internal symlinks"
	log "INFO    $SECURE_PERM_COUNT files with hardened permissions (primary package)"
	[[ $VENDOR_HARDENED_COUNT -gt 0 ]] && \
		log "INFO    $VENDOR_HARDENED_COUNT files with hardened permissions (in vendor/dependencies)"
	log "----------------------------------------------"
	log "RISK    score: $RISK_SCORE"

	if [[ $CRITICAL_RISK -gt 0 ]]; then
		log "        critical floor: $CRITICAL_RISK (not reducible)"
	fi

	ELAPSED=$(( SECONDS - SCAN_START ))
	log "        elapsed: ${ELAPSED}s"
	log "----------------------------------------------"

	if [[ "$FIXIT" == "true" ]]; then
		[[ $FAILED_COUNT -gt 0 ]] && log "[WARN]  $FAILED_COUNT items could not be fixed (check permissions)"
		[[ $SKIPPED_LINKS -gt 0 ]] && log "[INFO]  Skipped $SKIPPED_LINKS symbolic links"
		if [[ $ALL_FIXED -gt 0 ]]; then
			[[ $FIXED_COUNT -gt 0 ]]     && log "[DONE]  World-writable permissions removed from $FIXED_COUNT items."
			[[ $FIXED_STICKY -gt 0 ]]    && log "[DONE]  Sticky bit added to $FIXED_STICKY directories."
			[[ $FIXED_SENSITIVE -gt 0 ]] && log "[DONE]  Restricted $FIXED_SENSITIVE sensitive files to owner-only."
			[[ $FIXED_NOEXEC -gt 0 ]]    && log "[DONE]  Executable bits removed from $FIXED_NOEXEC data files."
		else
			log "[DONE]  No changes needed."
		fi
	else
		log "[DONE]  No changes made."
		log "        Use -f or --fix to correct issues."
	fi
	log ""
fi


# ─── write JSON output ───────────────────────────────────────────
#
# --write-json PATH takes priority (internal use by run-filescans.sh).
# Otherwise, write to standard meta output path unless --no-file was given.
#
if [[ -n "$WRITE_JSON_FILE" ]]; then
	generate_json > "$WRITE_JSON_FILE"
elif [[ "$WRITE_FILE" == "true" ]]; then
	mkdir -p "$OUTPUT_DIR" 2>/dev/null \
		|| { echo "Error: cannot create output directory '$OUTPUT_DIR'" >&2; exit 2; }
	generate_json > "$OUTPUT_FILE"
	log "[OK]   Saved: $OUTPUT_FILE"
fi


# ─── set exit code ──────────────────────────────────────────────────
#
if [[ "$FIXIT" == "true" ]]; then
	[[ $FAILED_COUNT -eq 0 ]] && exit 0 || exit 1
else
	CRITICAL_COUNT=$((WRITABLE_FILES + WRITABLE_DIRS + STICKY_MISSING \
		+ PRIV_ESC_COUNT + PERM_INVERSION_COUNT \
		+ SYMLINK_EXTERNAL + SENSITIVE_COUNT))
	[[ $CRITICAL_COUNT -eq 0 ]] && exit 0 || exit 1
fi

