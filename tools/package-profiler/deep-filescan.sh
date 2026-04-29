#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# deep-filescan.sh — file content analysis
#
# usage: deep-filescan.sh [OPTIONS] [directory]
#
# deep scan of file types & content for malicious patterns and
# integrity anomalies. designed to complement:
#
#   permission-check.sh  (metadata: permissions, symlinks, SUID)
#   file-stats.sh        (metadata: counts, sizes, categories)
#
# this script reads file CONTENTS, so it's heavier than
# the metadata-only scripts. optimized via batch operations:
#
#   - MIME detection: batched through xargs (1 invocation vs N)
#   - pattern matching: pre-filter finds hits, classify only those
#   - MIME + patterns run in parallel
#
# Output file: ./meta/<clean-name>/<clean-name>.content-scan.json
#
VERSION="1.0.0"

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
#   permission-check.sh, file-stats.sh
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


# ─── defaults ────────────────────────────────────────────────────
#
TARGET_DIR="."
TARGET_FILE=""        # set when a single file (not a directory) is passed as the target
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
WRITE_JSON_FILE=""    # internal: explicit path override (used by run-filescans.sh)
META_BASE="./meta"    # base directory for standard output
OUTPUT_DIR=""         # default: $META_BASE/<clean-name>/ (set after name detection)
WRITE_FILE=true       # set false with --no-file

# size limit for pattern scanning: avoid grepping through multi-GB logs or database dumps;
# MIME detection still runs on all files regardless of size
#
PATTERN_SIZE_LIMIT=$((10 * 1048576))   # 10 MB
NO_SIZE_LIMIT=false   # set true with --no-size-limit (e.g. when scanning a single large file)


# ─── cleanup / signals ──────────────────────────────────────────
#
TMPDIR_WORK=""
cleanup() {
	[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"
	# kill background jobs if any
	jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
	exit 130
}
trap cleanup INT TERM
trap '[[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]] && rm -rf "$TMPDIR_WORK"' EXIT


# ─── functions ───────────────────────────────────────────────────
#

show_help() {
	cat << EOF

CONTENT-SCAN:
    Scan file contents for malicious patterns and integrity anomalies.
    deep-filescan.sh Version $VERSION

USAGE:
    $(basename "$0") [OPTIONS] [directory|file]

OPTIONS:
    -h, --help          Show this help message
    -s, --silent        Suppress output (exit code only)
    -j, --json          Output results in JSON format
    -sj, -js            Silent + JSON (pipe-friendly)
    -v, --verbose       Show phase status, per-finding detail, and hygiene breakdown
    -o, --output-dir D  Write JSON output to directory D
                        (default: ./meta/<clean-name>/)
    --meta-base DIR     Base directory for meta output (default: ./meta)
    --no-file           Output JSON to stdout only; do not write file
    --no-size-limit     Disable the 10MB per-file skip threshold for pattern scanning
                        (useful when scanning a single known-large file)
    --write-json F      Write JSON results to file F (used by run-filescans.sh)
    --version           Print version and exit

ARGUMENTS:
    [directory|file]    Directory or single file to scan (default: current directory)
                        When a file is given, MIME and pattern checks run on that file only.
                        The subdir-unwrap step is skipped; output is named after the file.

OUTPUT:
    ./meta/<clean-name>/<clean-name>.content-scan.json

PATTERN CHECKS (on text/code files):
    Reverse shells       bash -i /dev/tcp, nc -e, python dup2, etc.
    Crypto miners        coinhive, xmrig, stratum+tcp, etc.
    Code obfuscation     eval(base64), fromCharCode chains, hex chains
    Data exfiltration    curl --data @file, wget --post-file, etc.
    Webshell patterns    system(\$_GET), shell_exec, passthru, etc.
    Embedded code        PHP tags in images, <script> in SVG, etc.

INTEGRITY CHECKS (on all files):
    MIME mismatches      Extension says .jpg but content is text/php
    Deceptive names      Double extensions like .jpg.php
    Embedded code        PHP/script injected into images; active code in SVG/XHTML/XSL

SKIPS:
    vendor/, node_modules/, venv/, .venv/, __pycache__/,
    .git/, .svn/, .hg/
    Files >10MB are skipped for pattern and embedded-code scanning (MIME still checked);
    skipped file count is reported in the summary — use --no-size-limit to override,
    or evaluate large files individually.

EXIT CODES:
    0   No critical issues found
    1   Critical or high-severity issues found
    2   Errors (directory not found, missing tools, etc.)

EXAMPLES:
    $(basename "$0")
    $(basename "$0") -v /var/www/html
    $(basename "$0") -j ./uploads > deep-filescan-audit.json
    $(basename "$0") -j --no-file ./dir > scan.json
    $(basename "$0") --no-size-limit suspicious-large-file.php

EOF
}


log() {
	# general output — suppressed in silent and json modes
	[[ "$SILENT" == "false" && "$JSON_OUTPUT" == "false" ]] && echo "$@" >&2
}

log_phase() {
	# phase transition messages — shown in all non-silent/json modes.
	# in verbose mode prefixed with [STATUS] so progress is traceable.
	[[ "$SILENT" == "true" || "$JSON_OUTPUT" == "true" ]] && return
	if [[ "$VERBOSE" == "true" ]]; then
		echo "  [STATUS] $*" >&2
	else
		echo "  $*" >&2
	fi
}

log_found() {
	# per-finding output — always shown in non-silent/json modes.
	# in verbose mode a second indented line shows the detail context.
	# args: $1=severity  $2=type  $3=rel-path  $4=detail (verbose only)
	[[ "$SILENT" == "true" || "$JSON_OUTPUT" == "true" ]] && return
	local sev="$1" typ="$2" path="$3" detail="${4:-}"
	echo "  [FOUND] [$sev] $typ: $path" >&2
	[[ "$VERBOSE" == "true" && -n "$detail" ]] && echo "          $detail" >&2
}


# ─── argument parsing ───────────────────────────────────────────
#
while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)    show_help; exit 0 ;;
		--version)    echo "deep-filescan.sh v$VERSION"; exit 0 ;;
		--verbose|-v) VERBOSE=true; shift ;;
		--silent|-s)  SILENT=true; shift ;;
		--json|-j)    JSON_OUTPUT=true; shift ;;
		-o|--output-dir)
		              [[ -z "${2:-}" ]] && { echo "Error: --output-dir requires an argument" >&2; exit 2; }
		              OUTPUT_DIR="$2"; shift 2 ;;
		--meta-base)
		              [[ -z "${2:-}" ]] && { echo "Error: --meta-base requires an argument" >&2; exit 2; }
		              META_BASE="$2"; shift 2 ;;
		--no-file)    WRITE_FILE=false; shift ;;
		--no-size-limit) NO_SIZE_LIMIT=true; shift ;;
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

[[ $# -gt 0 && "$TARGET_DIR" == "." ]] && TARGET_DIR="$1"

TARGET_DIR="${TARGET_DIR:-.}"

# ── file-mode: single file passed as target ─────────────────────────────────
# When the argument is a regular file rather than a directory, run MIME and
# pattern checks on that one file only. TARGET_DIR is set to its parent so
# relative paths display correctly. The subdir-unwrap step is skipped.
if [[ -f "$TARGET_DIR" ]]; then
	TARGET_FILE="$(cd -- "$(dirname "$TARGET_DIR")" && pwd -P)/$(basename "$TARGET_DIR")"
	TARGET_DIR="$(dirname "$TARGET_FILE")"
elif [[ ! -d "$TARGET_DIR" ]]; then
	echo "Error: '$TARGET_DIR' is not a directory or file" >&2
	exit 2
fi

if [[ -z "$TARGET_FILE" ]]; then
	TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd -P)"

	# ── single-subdir unwrap ──────────────────────────────────────────────────
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
else
	TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd -P)"
fi

DISPLAY_NAME="$(sanitize_name "${TARGET_FILE:-$TARGET_DIR}")"
SCAN_START=$SECONDS

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${DISPLAY_NAME}"
OUTPUT_FILE="${OUTPUT_DIR}/${DISPLAY_NAME}.content-scan.json"


# deps check
#
for tool in find file grep xargs wc jq; do
	command -v "$tool" &>/dev/null || {
		echo "Error: Required tool '$tool' not found" >&2
		exit 2
	}
done

# create working directory for temp files
#
TMPDIR_WORK=$(mktemp -d) || { echo "Error: Cannot create temp directory" >&2; exit 2; }

# --no-size-limit: remove the per-file skip threshold by setting it to 1 GB
#
[[ "$NO_SIZE_LIMIT" == "true" ]] && PATTERN_SIZE_LIMIT=$((1024 * 1048576))


# ─── pattern definitions ────────────────────────────────────────
#
# all patterns in a single file for batch grep. each line is one
# extended regex. the CATEGORY of each pattern is determined by
# line number ranges (see classify_match below).
#
# line layout:
#   1-8    reverse_shell     (CRITICAL)
#   9-14   crypto_miner      (CRITICAL)
#   15-22  obfuscation       (HIGH)
#   23-27  data_exfil        (HIGH)
#   28-37  webshell          (MEDIUM)
#
cat > "$TMPDIR_WORK/patterns.txt" << 'PATTERNS'
bash\s+-i\s+>&\s+/dev/tcp/
/bin/(ba)?sh\s*-i\s*<\s*/dev/tcp
nc(\s+-(e|c)|\.traditional)\s.*/bin/(ba)?sh
perl\s.*Socket.*STDIN
python[23]?\s.*socket.*\bdup2\b
ruby\s.*TCPSocket.*(exec|system|spawn)
php\s.*fsockopen.*(exec|system|passthru)
\bsocat\b.*EXEC:
coinhive
cryptonight
monero.{0,20}(min|pool)
stratum\+tcp://
\bxmrig\b
cryptoloot
eval\s*\(\s*(base64_decode|atob)\s*\(
\bFunction\s*\(\s*atob\s*\(
exec\s*\(\s*(base64\.b64decode|bytes\.fromhex)
\bfromCharCode\s*\(.{80,}\)
(\\x[0-9a-fA-F]{2}\s*\.?\s*){8,}
(chr\s*\(\s*[0-9]+\s*\)\s*\.?\s*){6,}
gzinflate\s*\(\s*base64_decode
\bpreg_replace\s*\(.*/e['"]
curl\b.+--data.*@
curl\b.+-d\s+@
wget\b.+--post-file
fetch\s*\(.+method.*POST.+document\.(cookie|location)
XMLHttpRequest.+send\s*\(.+document\.
system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)
shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
passthru\s*\(\s*\$_(GET|POST|REQUEST)
\bpopen\s*\(\s*\$_(GET|POST|REQUEST)
proc_open\s*\(\s*\$_(GET|POST|REQUEST)
\bassert\s*\(\s*\$_(GET|POST|REQUEST)
create_function\s*\(.+\$_(GET|POST|REQUEST)
\bpreg_replace\s*\(.+/e.+\$_(GET|POST)
call_user_func(_array)?\s*\(\s*\$_(GET|POST)
\$\{?\$_(GET|POST|REQUEST)\s*\[.{0,30}\]\}?\s*\(
PATTERNS

PATTERN_COUNT=$(wc -l < "$TMPDIR_WORK/patterns.txt")

# line ranges for classification (1-indexed, inclusive) must match the pattern file layout above
#
RANGE_SHELL_START=1      RANGE_SHELL_END=8
RANGE_CRYPTO_START=9     RANGE_CRYPTO_END=14
RANGE_OBFUSC_START=15    RANGE_OBFUSC_END=22
RANGE_EXFIL_START=23     RANGE_EXFIL_END=27
RANGE_WEBSHELL_START=28  RANGE_WEBSHELL_END=37

classify_pattern_line() {
	local pline=$1
	if (( pline >= RANGE_SHELL_START && pline <= RANGE_SHELL_END )); then
		echo "reverse_shell|CRITICAL"
	elif (( pline >= RANGE_CRYPTO_START && pline <= RANGE_CRYPTO_END )); then
		echo "crypto_miner|CRITICAL"
	elif (( pline >= RANGE_OBFUSC_START && pline <= RANGE_OBFUSC_END )); then
		echo "obfuscation|HIGH"
	elif (( pline >= RANGE_EXFIL_START && pline <= RANGE_EXFIL_END )); then
		echo "data_exfil|HIGH"
	elif (( pline >= RANGE_WEBSHELL_START && pline <= RANGE_WEBSHELL_END )); then
		echo "webshell|MEDIUM"
	else
		echo "suspicious|MEDIUM"
	fi
}


# ─── MIME expected type map ──────────────────────────────────────
#
# STRICT validation for binary formats with strong magic signatures: mismatches here 
# like "image/jpeg" file that is actually text/x-php are geniune threats
#
declare -A MIME_STRICT=(
	# images
	[jpg]="image/jpeg" [jpeg]="image/jpeg"
	[png]="image/png" [gif]="image/gif"
	[webp]="image/webp" [bmp]="image/(bmp|x-ms-bmp)"
	[ico]="image/(x-icon|vnd\\.microsoft\\.icon)"
	[tiff]="image/tiff" [tif]="image/tiff"
	[avif]="image/avif"
	# documents (binary office formats)
	[pdf]="application/pdf"
	[doc]="application/msword"
	# OOXML formats (.docx/.xlsx/.pptx) are ZIP-based; file(1) may return either the full
	# proprietary OOXML MIME (application/vnd.openxmlformats-officedocument.*) or application/zip.
	# Both are expected and legitimate — the full OOXML MIME is the correct canonical type.
	[docx]="application/(vnd\\.openxmlformats-officedocument\\..+|zip)"
	[xls]="application/vnd\\.ms-excel"
	[xlsx]="application/(vnd\\.openxmlformats-officedocument\\..+|zip)"
	[ppt]="application/vnd\\.ms-powerpoint"
	[pptx]="application/(vnd\\.openxmlformats-officedocument\\..+|zip)"
	# ODF formats are also ZIP-based; same reasoning applies
	[odt]="application/(vnd\\.oasis\\..+|zip)"
	[ods]="application/(vnd\\.oasis\\..+|zip)"
	# archives
	[zip]="application/zip"
	[gz]="application/(x-)?gzip"
	[tgz]="application/(x-)?gzip"
	[bz2]="application/x-bzip2"
	[xz]="application/x-xz"
	[tar]="application/x-tar"
	[7z]="application/x-7z"
	[rar]="application/(x-rar|vnd\\.rar)"
	# fonts
	[ttf]="(font/sfnt|font/ttf|application/(x-font-ttf|font-sfnt|octet-stream))"
	[otf]="(font/otf|application/(x-font-opentype|font-sfnt|vnd\\.ms-opentype))"
	[woff]="(font/woff|application/(font-woff|x-font-woff))"
	[woff2]="(font/woff2|application/font-woff2)"
	[eot]="application/vnd\\.ms-fontobject"
	# svg — text/xml format but with a well-known image/ MIME; validate exactly
	[svg]="image/svg\+xml"
	# media
	[mp3]="audio/mpeg"
	[mp4]="video/mp4"
	[wav]="audio/(x-)?wav"
	[ogg]="(audio|video)/ogg"
	[webm]="video/webm"
)

# TOLERANT validation for text-based source/config files
#
# file(1) uses content heuristics for text and constantly misidentifies languages:
# 		JS with `class {}` → text/x-java or text/x-c++, CSS → text/x-c,	Python → text/x-script.python, etc
# these vary by libmagic version & are NOT security signals, so for these we ONLY flag when the detected
# MIME is a binary type (image/*, audio/*, video/*, or specific binary application/* types),
# while text/* and application/javascript,json,xml are all acceptable
#
# TL;DR: we don't care too much if you mislabel a webp file as a jpg or a text file as markdown
#
declare -A TEXT_EXTENSIONS=(
	[js]=1 [mjs]=1 [cjs]=1 [jsx]=1 [ts]=1 [tsx]=1 [vue]=1 [svelte]=1
	[json]=1 [json5]=1 [jsonc]=1
	[xml]=1 [xsl]=1 [xslt]=1 [xsd]=1
	[html]=1 [htm]=1 [xhtml]=1
	[css]=1 [scss]=1 [sass]=1 [less]=1
	[php]=1 [phtml]=1 [php5]=1 [php7]=1
	[py]=1 [pyw]=1 [rb]=1 [pl]=1 [pm]=1
	[sh]=1 [bash]=1 [zsh]=1
	[go]=1 [rs]=1 [c]=1 [cpp]=1 [h]=1 [hpp]=1
	[java]=1 [kt]=1 [scala]=1 [groovy]=1
	[swift]=1 [cs]=1 [vb]=1
	[r]=1 [lua]=1 [sql]=1
	[md]=1 [txt]=1 [rst]=1 [tex]=1
	[csv]=1 [tsv]=1 [yaml]=1 [yml]=1 [toml]=1 [ini]=1 [conf]=1 [cfg]=1
	[rtf]=1 [env]=1 [log]=1
)

# MIME indicating binary content: text extensions returning one of these types are pretty suss
# e.g. a .js file that is actually an ELF binary = bad sign
#
BINARY_MIME_PATTERN="^(image/|audio/|video/|application/(octet-stream|x-executable|x-mach-binary|x-dosexec|x-sharedlib|x-archive|x-pie-executable|zip|gzip|pdf|msword|vnd\.))"


# executable/script MIME types:
# binary-extension files returning one of these is always a CRITICAL mismatch regardless of context
#
EXEC_MIME_PATTERN="^(text/x-(php|python|ruby|perl|shellscript|javascript)|application/(x-php|x-python|x-ruby|x-perl|x-shellscript|x-executable|x-mach-binary|x-dosexec|x-sharedlib|x-pie-executable))"


# SCRIPT_CAPABLE_EXTS: XML-family formats rendered or executed by runtimes that support active scripting
# full event-handler + script-element scan is applied for these
#   svg    		— browser-rendered; <script>, event handlers, javascript: URIs all live
#   xhtml  		— HTML served as XML; full script model
#   xht    		— same as xhtml
#   xsl, xslt   — processed by XSLT engines; <msxsl:script>, extension functions
#
declare -A SCRIPT_CAPABLE_EXTS=(
	[svg]=1 [xhtml]=1 [xht]=1 [xsl]=1 [xslt]=1
)


# BINARY_CODE_CHECK: binary formats where any embedded script/PHP tag are always malicious
# 	— no legitimate use case, check via grep -qa (binary-safe)
#
declare -A BINARY_CODE_CHECK=(
	[jpg]=1 [jpeg]=1 [png]=1 [gif]=1 [bmp]=1 [ico]=1
	[webp]=1 [tiff]=1 [tif]=1 [pdf]=1
)


# on file extensions for deceptive double-extension detection, the second 
# extension must be one of these to be suspicious
#
declare -A EXEC_EXTENSIONS=(
	[php]=1 [phtml]=1 [php5]=1 [php7]=1 [phar]=1
	[js]=1 [jsp]=1 [jspx]=1 [asp]=1 [aspx]=1
	[py]=1 [pl]=1 [rb]=1 [sh]=1 [bash]=1 [cgi]=1
	[exe]=1 [bat]=1 [cmd]=1 [com]=1 [scr]=1 [msi]=1
	[ps1]=1 [vbs]=1 [wsf]=1
)

# safe double-extension patterns (not deceptive), attempt to rule out benign filenames with . in them
# 
SAFE_DOUBLE_EXTS="tar.gz tar.bz2 tar.xz tar.zst tar.lz4 min.js min.css d.ts"


# ─── phase 1: file discovery ────────────────────────────────────
#
log ""
log "─────────────────────────────────────────────────────────────"
log "Content Scan: [$DISPLAY_NAME]"
log "─────────────────────────────────────────────────────────────"

# collect all file paths into a null-delimited list
#
if [[ -n "$TARGET_FILE" ]]; then
	# file-mode: single file
	printf '%s\0' "$TARGET_FILE" > "$TMPDIR_WORK/all_files.list"
else
	# directory-mode: recurse, excluding VCS and dependency trees
	find "$TARGET_DIR" -mount -type f \
		-not -path "*/.git/*" \
		-not -path "*/.svn/*" \
		-not -path "*/.hg/*" \
		-not -path "*/node_modules/*" \
		-not -path "*/vendor/*" \
		-not -path "*/venv/*" \
		-not -path "*/.venv/*" \
		-not -path "*/__pycache__/*" \
		-print0 2>/dev/null > "$TMPDIR_WORK/all_files.list"
fi

TOTAL_FILES=$(tr -cd '\0' < "$TMPDIR_WORK/all_files.list" | wc -c)
log_phase "Discovered $TOTAL_FILES files — starting scan..."


# ─── phase 2a: batch MIME detection (background) ────────────────
#
# runs as a background job, outputs "filepath: mime/type" per line for pattern scanning
# results are collected after the pattern scan
#
log_phase "MIME detection running in background..."
xargs -0 file --mime-type < "$TMPDIR_WORK/all_files.list" \
	> "$TMPDIR_WORK/mime_results.txt" 2>/dev/null &
MIME_PID=$!


# ─── phase 2b: batch pattern matching ───────────────────────────
#
# step 1: identify which files are text/scannable
# step 2: pre-filter with batched grep to find ANY match
# step 3: classify only the hits
#

# 1: filter scannable files: text-based extensions below size threshold
# 	- includes a generous set: code, web, config, markup, data, templates & unknown extensions
# 	(let grep decide later if it's binary)
#
declare -A SKIP_PATTERN_EXTS=(
	[jpg]=1 [jpeg]=1 [png]=1 [gif]=1 [bmp]=1 [webp]=1 [avif]=1 [ico]=1
	[tiff]=1 [tif]=1 [psd]=1 [raw]=1 [cr2]=1 [nef]=1 [heic]=1
	[mp3]=1 [mp4]=1 [m4a]=1 [wav]=1 [flac]=1 [ogg]=1 [avi]=1 [mov]=1
	[mkv]=1 [wmv]=1 [webm]=1 [mpg]=1
	[zip]=1 [tar]=1 [gz]=1 [bz2]=1 [xz]=1 [7z]=1 [rar]=1 [tgz]=1
	[jar]=1 [war]=1 [deb]=1 [rpm]=1 [dmg]=1 [iso]=1
	[ttf]=1 [otf]=1 [woff]=1 [woff2]=1 [eot]=1
	[pdf]=1 [doc]=1 [docx]=1 [xls]=1 [xlsx]=1 [ppt]=1 [pptx]=1
	[odt]=1 [ods]=1 [odp]=1 [rtf]=1 [epub]=1
	[exe]=1 [dll]=1 [so]=1 [dylib]=1 [o]=1 [obj]=1 [class]=1
	[pyc]=1 [pyo]=1 [beam]=1
	[sqlite]=1 [db]=1
)

# 2: build the filtered file list for pattern scanning
#
SIZE_SKIP_COUNT=0
while IFS= read -r -d '' fpath; do
	# size check — files over the limit are excluded from pattern and embedded-code scanning;
	# MIME is still checked for all files regardless of size
	fsize=$(stat -c "%s" "$fpath" 2>/dev/null || echo 0)
	if (( fsize > PATTERN_SIZE_LIMIT )); then
		((SIZE_SKIP_COUNT++))
		continue
	fi
	(( fsize == 0 )) && continue

	# extension check
	fname="${fpath##*/}"
	ext="${fname##*.}"
	# Hidden extensionless files (e.g., .gitignore, .eslintignore): no real extension
	if [[ "$ext" == "$fname" ]] || [[ "$fname" == .* && "${fname#.}" != *.* ]]; then
		ext=""
	else
		ext="${ext,,}"
	fi
	[[ -n "$ext" && -n "${SKIP_PATTERN_EXTS[$ext]+x}" ]] && continue

	printf '%s\0' "$fpath"
done < "$TMPDIR_WORK/all_files.list" > "$TMPDIR_WORK/scannable.list"

SCAN_COUNT=$(tr -cd '\0' < "$TMPDIR_WORK/scannable.list" | wc -c)
log_phase "Pattern scan: checking $SCAN_COUNT files..."

# 3: run batch grep with line numbers to identify patterns that matched
# 	- output format: "filepath:linenumber:matched text"
# 	-n = line numbers, -H = always print filename, -f = pattern file
#
xargs -0 grep -inHEf "$TMPDIR_WORK/patterns.txt" \
	< "$TMPDIR_WORK/scannable.list" \
	> "$TMPDIR_WORK/pattern_hits.txt" 2>/dev/null || true


# for each hit, determine WHICH pattern matched by re-testing individual patterns
# since hits are (or should be) rare, this is cheap
#
declare -A HIT_FILES=()   # file → 1 (dedup)
SHELL_COUNT=0
CRYPTO_COUNT=0
OBFUSC_COUNT=0
EXFIL_COUNT=0
WEBSHELL_COUNT=0


# findings are stored as NUL-delimited raw fields in a binary .raw temp file
# 		format per record:	kind\0sev\0type\0file\0field4\0field5\0
#   	pattern: 			P\0sev\0type\0file\0linenum\0match\0
#   	mime:    			M\0sev\0type\0file\0detail\0\0
#
# JSON assembler reads these via bash + jq --arg for safe escaping
#
: > "$TMPDIR_WORK/findings.raw"

write_pattern_finding() {
	printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
		"P" "$1" "$2" "$3" "$4" "$5" \
		>> "$TMPDIR_WORK/findings.raw"
}

write_mime_finding() {
	printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
		"M" "$1" "$2" "$3" "$4" "" \
		>> "$TMPDIR_WORK/findings.raw"
}

if [[ -s "$TMPDIR_WORK/pattern_hits.txt" ]]; then
	log_phase "Classifying pattern matches..."

	# extract unique files that had hits
	#
	while IFS=: read -r fpath _linenum _rest; do
		[[ -z "$fpath" ]] && continue
		HIT_FILES["$fpath"]=1
	done < "$TMPDIR_WORK/pattern_hits.txt"

	# for each listed hit, test each pattern category individually
	# 	- only runs on identified files with known matches
	#
	for fpath in "${!HIT_FILES[@]}"; do
		rel="${fpath#"$TARGET_DIR/"}"
		[[ "$rel" == "$fpath" ]] && rel="${fpath#"$TARGET_DIR"}"

		# read patterns line by line & test each against this file
		#
		pline=0
		declare -A _found_cats=()
		while IFS= read -r pattern; do
			((pline++))
			[[ -z "$pattern" ]] && continue

			if grep -qiE -- "$pattern" "$fpath" 2>/dev/null; then
				IFS='|' read -r ptype psev <<< "$(classify_pattern_line "$pline")"

				# dedup: only report each category once per file
				[[ -n "${_found_cats[$ptype]+x}" ]] && continue
				_found_cats[$ptype]=1

				case "$ptype" in
					reverse_shell) ((SHELL_COUNT++)) ;;
					crypto_miner)  ((CRYPTO_COUNT++)) ;;
					obfuscation)   ((OBFUSC_COUNT++)) ;;
					data_exfil)    ((EXFIL_COUNT++)) ;;
					webshell)      ((WEBSHELL_COUNT++)) ;;
				esac

				# get first matching line for context
				#
				match_line=$(grep -niE -- "$pattern" "$fpath" 2>/dev/null | head -1)
				match_linenum="${match_line%%:*}"
				match_content="${match_line#*:}"
				# ...but truncate long matches
				(( ${#match_content} > 120 )) && match_content="${match_content:0:120}..."

				write_pattern_finding "$psev" "$ptype" "$rel" "$match_linenum" "$match_content"
				log_found "$psev" "$ptype" "$rel" "line $match_linenum: $match_content"
			fi
		done < "$TMPDIR_WORK/patterns.txt"
		unset _found_cats
	done
fi


# ─── wait for MIME detection to finish ───────────────────────────
#
log_phase "Waiting for MIME detection to complete..."
wait "$MIME_PID" 2>/dev/null || true


# ─── phase 3: MIME analysis ─────────────────────────────────────
#
log_phase "Analysing MIME types and file integrity..."

MISMATCH_COUNT=0
MISMATCH_CRITICAL_COUNT=0
MISMATCH_HIGH_COUNT=0


# image→image mislabels: LOW severity, but tracked separately for hygiene analysis
# (is it consistent, like a tooling issue, or bad file hygiene?)
#
MISLABEL_LOW_COUNT=0
declare -A MISLABEL_PAIRS=()   # "ext_expected→actual_mime" → count
IMAGE_TOTAL_COUNT=0            # total files with an image/* expected MIME
DECEPTIVE_COUNT=0
EMBEDDED_CODE_COUNT=0
EMBEDDED_CODE_CRITICAL_COUNT=0
EMBEDDED_CODE_HIGH_COUNT=0


# process MIME results; format from file: "/path/to/file: mime/type"
#
while IFS= read -r line; do
	[[ -z "$line" ]] && continue

	# parse file output: "PATH: MIMETYPE" (batch mode pads spaces)
	# split at first ": " for path, extract MIME from remainder
	#
	fpath="${line%%: *}"
	mime="${line#"$fpath": }"
	mime="${mime#"${mime%%[![:space:]]*}"}"   # trim leading whitespace
	mime="${mime%"${mime##*[![:space:]]}"}"   # trim trailing whitespace

	[[ -z "$fpath" || -z "$mime" ]] && continue
	[[ ! -f "$fpath" ]] && continue

	fname="${fpath##*/}"
	ext="${fname##*.}"
	# Hidden extensionless files (e.g., .gitignore, .eslintignore): no real extension
	if [[ "$ext" == "$fname" ]] || [[ "$fname" == .* && "${fname#.}" != *.* ]]; then
		ext=""
	else
		ext="${ext,,}"
	fi
	rel="${fpath#"$TARGET_DIR/"}"
	[[ "$rel" == "$fpath" ]] && rel="${fpath#"$TARGET_DIR"}"

	# ── 2-tier MIME mismatch check ──
	#
	if [[ -n "$ext" ]]; then
		flagged=false

		if [[ -n "${MIME_STRICT[$ext]+x}" ]]; then
			# tier 1 for binary format — strict magic-byte validation
			# 		 these formats have strong signatures, so a mismatch is a genuine threat
			#
			expected="${MIME_STRICT[$ext]}"

			# track total image files for hygiene percentage calculation
			#
			[[ "$expected" =~ ^image/ ]] && ((IMAGE_TOTAL_COUNT++))

			if [[ ! "$mime" =~ ^($expected)$ ]]; then
				# allow application/octet-stream for non-image binary formats
				# (file sometimes can't determine the exact subtype)
				#
				if [[ "$mime" == "application/octet-stream" ]] && \
				   [[ ! "$ext" =~ ^(jpg|jpeg|png|gif|bmp|webp|pdf)$ ]]; then
					: # acceptable uncertainty for lesser-known binary formats
				else
					flagged=true
				fi
			fi

		elif [[ -n "${TEXT_EXTENSIONS[$ext]+x}" ]]; then
			# tier 2: text-based source/config uses tolerant validation, only flags when file(1) says it's binary
			# text/x-java, text/x-c++, text/plain etc. are all fine, just file(1) guessing the wrong language
			#
			if [[ "$mime" =~ $BINARY_MIME_PATTERN ]]; then
				flagged=true
			fi
		fi

		if [[ "$flagged" == "true" ]]; then
			((MISMATCH_COUNT++))
			if [[ -n "${MIME_STRICT[$ext]+x}" ]]; then
				# Strip regex metacharacters from the expected pattern for human-readable display.
				# MIME_STRICT values are ERE patterns (e.g., "image/(x-icon|vnd\.microsoft\.icon)");
				# displaying the raw regex in a finding detail is confusing and not informative.
				expected_display="${MIME_STRICT[$ext]}"
				expected_display="${expected_display//\\\./\.}"  # \. → . (unescape dots)
				expected_display="${expected_display//\\./.}"    # \. → . (bash double-escape variant)
				expected_display="${expected_display//\\/}"      # remove any remaining stray backslashes
				detail="expected ${expected_display}, got $mime"
			else
				detail="text extension has binary MIME: $mime"
			fi

			# severity depends on the actual file content:
			#   CRITICAL — detected MIME is executable or script
			#   LOW      — both expected and actual are image/*
			#   		   (almost certainly mislabeling by some tool, but tracked for hygiene analysis)
			#   HIGH     — everything else, including unrelated binary types
			#
			if [[ "$mime" =~ $EXEC_MIME_PATTERN ]]; then
				mismatch_sev="CRITICAL"
				((MISMATCH_CRITICAL_COUNT++))
			elif [[ "${MIME_STRICT[$ext]:-}" =~ ^image/ && "$mime" =~ ^image/ ]]; then
				mismatch_sev="LOW"
				((MISLABEL_LOW_COUNT++))
				# record the type-pair for hygiene pattern analysis in phase 4
				_pair="${ext}→${mime}"
				MISLABEL_PAIRS[$_pair]=$(( ${MISLABEL_PAIRS[$_pair]:-0} + 1 ))
			else
				mismatch_sev="HIGH"
				((MISMATCH_HIGH_COUNT++))
			fi

			write_mime_finding "$mismatch_sev" "mime_mismatch" "$rel" "$detail"
			log_found "$mismatch_sev" "mime_mismatch" "$rel" "$detail"
		fi
	fi

	# ── deceptive double extension ──
	#
	# e.g. image.jpg.php, report.pdf.exe are always CRITICAL because the true extension is always an executable type
	# this check only fires when the final ext is in EXEC_EXTENSIONS
	#
	if [[ "$fname" == *.*.* ]]; then
		# check if it's a safe pattern
		is_safe=false
		for _safe in $SAFE_DOUBLE_EXTS; do
			if [[ "${fname,,}" == *".$_safe" ]]; then
				is_safe=true
				break
			fi
		done

		if [[ "$is_safe" == "false" && -n "$ext" ]]; then
			# if the final extension is executable
			if [[ -n "${EXEC_EXTENSIONS[$ext]+x}" ]]; then
				# get the "fake" penultimate extension
				name_no_ext="${fname%.*}"
				fake_ext="${name_no_ext##*.}"
				fake_ext="${fake_ext,,}"
				# only flag if the fake ext looks like a data type
				if [[ "$fake_ext" =~ ^(jpg|jpeg|png|gif|bmp|pdf|doc|docx|xls|xlsx|txt|csv|zip|mp3|mp4)$ ]]; then
					((DECEPTIVE_COUNT++))
					write_mime_finding "CRITICAL" "deceptive_extension" "$rel" "appears to be .$fake_ext but is .$ext"
					log_found "CRITICAL" "deceptive_extension" "$rel" ".$fake_ext.${ext} — hiding .$ext executable"
				fi
			fi
		fi
	fi


	# ── embedded code check ──
	#
	# 3-tier check applied only to files within the size threshold
	#
	#   SCRIPT_CAPABLE_EXTS = could run a script: svg, xhtml, xht, xsl, xslt
	#     scan for: <script>, on* event handlers, javascript: URIs, <foreignObject>,
	#     			&  href/xlink:href javascript: references
	#     severity HIGH — script is structurally present (pattern scanner handles obfuscation/exfil separately)
	#
	#   xml (generic)
	#     sniff namespace first & apply script scan IF document declares SVG, XHTML, or XSLT namespaces
	#     - skips config XML, Maven POMs, Android manifests, WSDL, & others entirely
	#
	#   BINARY_CODE_CHECK for jpg, png, gif, etc. - scan for PHP tag injection
	#   	— any match is always CRITICAL since no legitimate use case exists for PHP inside a binary image
	#
	if [[ -n "$ext" ]]; then
		fsize=$(stat -c "%s" "$fpath" 2>/dev/null || echo 0)
		if (( fsize > 0 && fsize < PATTERN_SIZE_LIMIT )); then

			if [[ -n "${SCRIPT_CAPABLE_EXTS[$ext]+x}" ]]; then
				# full script scan for SVG, XHTML, XSL, XSLT (covers pattern as above)
				#
				if grep -qEi \
					'(<\/?script[\s>]|\bon[a-z]+\s*=|javascript\s*:|<foreignObject)' \
					"$fpath" 2>/dev/null; then
					((EMBEDDED_CODE_COUNT++))
					((EMBEDDED_CODE_HIGH_COUNT++))
					write_mime_finding "HIGH" "embedded_code" "$rel" "active script content in $ext file"
					log_found "HIGH" "embedded_code" "$rel" "active script content in .$ext file"
				fi

			elif [[ "$ext" == "xml" ]]; then
				# generic XML: scan if namespace indicates a script-capable vocab
				#
				if grep -qEi \
					'xmlns[^=]*=\s*["\x27](http://www\.w3\.org/2000/svg|http://www\.w3\.org/1999/xhtml|http://www\.w3\.org/1999/XSL/Transform)' \
					"$fpath" 2>/dev/null; then
					if grep -qEi \
						'(<\/?script[\s>]|\bon[a-z]+\s*=|javascript\s*:|<foreignObject)' \
						"$fpath" 2>/dev/null; then
						((EMBEDDED_CODE_COUNT++))
						((EMBEDDED_CODE_HIGH_COUNT++))
						write_mime_finding "HIGH" "embedded_code" "$rel" "active script content in XML (SVG/XHTML/XSLT namespace)"
						log_found "HIGH" "embedded_code" "$rel" "active script in XML with SVG/XHTML/XSLT namespace"
					fi
				fi

			elif [[ -n "${BINARY_CODE_CHECK[$ext]+x}" ]]; then
				# binary images: PHP tag injection — always CRITICAL
				#
				if grep -qaE '<\?php|<%(eval|exec|system)' "$fpath" 2>/dev/null; then
					((EMBEDDED_CODE_COUNT++))
					((EMBEDDED_CODE_CRITICAL_COUNT++))
					write_mime_finding "CRITICAL" "embedded_code" "$rel" "PHP/executable code injected into $ext file"
					log_found "CRITICAL" "embedded_code" "$rel" "PHP/executable code injected into .$ext binary file"
				fi
			fi

		fi
	fi

done < "$TMPDIR_WORK/mime_results.txt"


# ─── phase 4: results ───────────────────────────────────────────
#
log_phase "Computing results..."


# ── file hygiene analysis ────────────────────────────────────────
#
# image MIME mislabels are individually LOW (info-only), but an aggregate pattern may indicate
# a systemic tooling or process problem worth flagging
#
# escalation heuristics - evaluate in order, first match wins:
#   HIGH   — ≥10% of image files are mislabeled AND multiple label types
#            	(mixed pairs = no consistent process across the codebase)
#   MEDIUM — ≥20 mislabels in absolute count OR ≥5% of image files
#            	(volume alone suggests a tooling inconsistency)
#   otherwise: LOW findings remain as fyi, no hygiene finding raised
#
# pattern characterisation:
#   "systematic" — ≥80% of mislabels share one type-pair, likely a single tool issue
#   "mixed"      — spread across multiple type-pairs indicates a broader process problem
#
HYGIENE_SEV=""
HYGIENE_FINDING=""
HYGIENE_MEDIUM_COUNT=0
HYGIENE_HIGH_COUNT=0

if (( MISLABEL_LOW_COUNT > 0 && IMAGE_TOTAL_COUNT > 0 )); then
	# find dominant pair & its share
	dominant_pair=""
	dominant_count=0
	for _p in "${!MISLABEL_PAIRS[@]}"; do
		(( ${MISLABEL_PAIRS[$_p]} > dominant_count )) && {
			dominant_count=${MISLABEL_PAIRS[$_p]}
			dominant_pair="$_p"
		}
	done
	pair_type_count="${#MISLABEL_PAIRS[@]}"
	mislabel_pct=$(( MISLABEL_LOW_COUNT * 100 / IMAGE_TOTAL_COUNT ))
	dominant_pct=$(( dominant_count * 100 / MISLABEL_LOW_COUNT ))

	# build pair detail string for output/json
	_pair_detail=""
	for _p in "${!MISLABEL_PAIRS[@]}"; do
		_pair_detail+="${_p}:${MISLABEL_PAIRS[$_p]} "
	done
	_pair_detail="${_pair_detail% }"

	if [[ "$pair_type_count" -gt 1 && "$mislabel_pct" -ge 10 ]]; then
		HYGIENE_SEV="HIGH"
		(( HYGIENE_HIGH_COUNT++ ))
	elif (( MISLABEL_LOW_COUNT >= 20 || mislabel_pct >= 5 )); then
		HYGIENE_SEV="MEDIUM"
		(( HYGIENE_MEDIUM_COUNT++ ))
	fi

	if [[ -n "$HYGIENE_SEV" ]]; then
		if (( dominant_pct >= 80 )); then
			_pattern_desc="systematic — ${dominant_pct}% are ${dominant_pair}"
		else
			_pattern_desc="mixed — ${pair_type_count} different label types"
		fi
		HYGIENE_FINDING="${MISLABEL_LOW_COUNT} image mislabels / ${IMAGE_TOTAL_COUNT} image files (${mislabel_pct}%): ${_pattern_desc} [${_pair_detail}]"
		write_mime_finding "$HYGIENE_SEV" "file_hygiene" "(scan root)" "$HYGIENE_FINDING"
		log_found "$HYGIENE_SEV" "file_hygiene" "(scan root)" "$HYGIENE_FINDING"
	fi
fi


# ── totals ───────────────────────────────────────────────────────
#
PATTERN_TOTAL=$((SHELL_COUNT + CRYPTO_COUNT + OBFUSC_COUNT + EXFIL_COUNT + WEBSHELL_COUNT))
INTEGRITY_TOTAL=$((MISMATCH_COUNT + DECEPTIVE_COUNT + EMBEDDED_CODE_COUNT))
LOW_COUNT=$MISLABEL_LOW_COUNT
TOTAL_ISSUES=$((PATTERN_TOTAL + INTEGRITY_TOTAL + HYGIENE_MEDIUM_COUNT + HYGIENE_HIGH_COUNT))
CRITICAL_COUNT=$((SHELL_COUNT + CRYPTO_COUNT + MISMATCH_CRITICAL_COUNT + DECEPTIVE_COUNT + EMBEDDED_CODE_CRITICAL_COUNT))
HIGH_COUNT=$((OBFUSC_COUNT + EXFIL_COUNT + MISMATCH_HIGH_COUNT + EMBEDDED_CODE_HIGH_COUNT + HYGIENE_HIGH_COUNT))
MEDIUM_COUNT=$((WEBSHELL_COUNT + HYGIENE_MEDIUM_COUNT))


# calculate risk score — LOW findings & hygiene-escalated findings weighted accordingly
#
RISK_SCORE=$(( \
	SHELL_COUNT * 500 + CRYPTO_COUNT * 500 + \
	EMBEDDED_CODE_CRITICAL_COUNT * 400 + \
	MISMATCH_CRITICAL_COUNT * 300 + DECEPTIVE_COUNT * 300 + \
	OBFUSC_COUNT * 200 + EXFIL_COUNT * 200 + \
	EMBEDDED_CODE_HIGH_COUNT * 150 + MISMATCH_HIGH_COUNT * 150 + HYGIENE_HIGH_COUNT * 150 + \
	WEBSHELL_COUNT * 100 + HYGIENE_MEDIUM_COUNT * 75 ))


# ── generate_json ────────────────────────────────────────────────
#
# builds full JSON document from findings.raw + scan variables, writes to stdout;
# 	caller may redirect to file or terminal as ad desired
#
generate_json() {
	local _findings_file="$TMPDIR_WORK/findings.jsonl"
	: > "$_findings_file"

	if [[ -s "$TMPDIR_WORK/findings.raw" ]]; then
		while IFS= read -r -d '' kind && \
		      IFS= read -r -d '' sev  && \
		      IFS= read -r -d '' typ  && \
		      IFS= read -r -d '' fil  && \
		      IFS= read -r -d '' f4   && \
		      IFS= read -r -d '' f5; do
			if [[ "$kind" == "P" ]]; then
				jq -cn \
					--arg     sev   "$sev"     \
					--arg     typ   "$typ"     \
					--arg     fil   "$fil"     \
					--argjson ln    "${f4:-0}" \
					--arg     match "$f5"      \
					'{severity:$sev,type:$typ,file:$fil,line:$ln,match:$match}'
			else
				jq -cn \
					--arg sev    "$sev" \
					--arg typ    "$typ" \
					--arg fil    "$fil" \
					--arg detail "$f4"  \
					'{severity:$sev,type:$typ,file:$fil,detail:$detail}'
			fi
		done < "$TMPDIR_WORK/findings.raw" > "$_findings_file"
	fi

	local _elapsed=$(( SECONDS - SCAN_START ))

	jq -n \
		--arg     dir            "$DISPLAY_NAME"              \
		--arg     ver            "$VERSION"                    \
		--argjson elapsed        "$_elapsed"                   \
		--argjson total          "$TOTAL_FILES"                \
		--argjson scanned        "$SCAN_COUNT"                 \
		--argjson size_skipped   "$SIZE_SKIP_COUNT"            \
		--argjson issues         "$TOTAL_ISSUES"               \
		--argjson crit           "$CRITICAL_COUNT"             \
		--argjson high           "$HIGH_COUNT"                 \
		--argjson med            "$MEDIUM_COUNT"               \
		--argjson low            "$LOW_COUNT"                  \
		--argjson shells         "$SHELL_COUNT"                \
		--argjson miners         "$CRYPTO_COUNT"               \
		--argjson obfusc         "$OBFUSC_COUNT"               \
		--argjson exfil          "$EXFIL_COUNT"                \
		--argjson webshell       "$WEBSHELL_COUNT"             \
		--argjson mismatch       "$MISMATCH_COUNT"             \
		--argjson mismatch_crit  "$MISMATCH_CRITICAL_COUNT"    \
		--argjson mismatch_high  "$MISMATCH_HIGH_COUNT"        \
		--argjson mislabel_low   "$MISLABEL_LOW_COUNT"         \
		--argjson deceptive      "$DECEPTIVE_COUNT"            \
		--argjson emb_code       "$EMBEDDED_CODE_COUNT"        \
		--argjson emb_code_crit  "$EMBEDDED_CODE_CRITICAL_COUNT" \
		--argjson emb_code_high  "$EMBEDDED_CODE_HIGH_COUNT"   \
		--argjson risk           "$RISK_SCORE"                 \
		--slurpfile findings     "$_findings_file"             \
		'{
			target_directory:      $dir,
			scan_type:             "content_scan",
			version:               $ver,
			elapsed_seconds:       $elapsed,
			files_checked:         $total,
			files_pattern_scanned: $scanned,
			files_size_skipped:    $size_skipped,
			summary: {
				total_issues: $issues,
				critical:     $crit,
				high:         $high,
				medium:       $med,
				low:          $low,
				patterns: {
					reverse_shells:    $shells,
					crypto_miners:     $miners,
					obfuscation:       $obfusc,
					data_exfiltration: $exfil,
					webshell:          $webshell
				},
				integrity: {
					mime_mismatches: {
						total:    $mismatch,
						critical: $mismatch_crit,
						high:     $mismatch_high,
						low:      $mislabel_low
					},
					deceptive_extensions: $deceptive,
					embedded_code: {
						total:    $emb_code,
						critical: $emb_code_crit,
						high:     $emb_code_high
					}
				}
			},
			risk:     {score: $risk},
			findings: $findings
		}'
}


if [[ "$JSON_OUTPUT" == "true" ]]; then
	generate_json

else
	log ""
	log "─────────────────────────────────────────────────────────────"
	if (( SIZE_SKIP_COUNT > 0 )); then
		log "  Scanned: $TOTAL_FILES files ($SCAN_COUNT pattern-scanned, $SIZE_SKIP_COUNT skipped — over $(( PATTERN_SIZE_LIMIT / 1048576 ))MB)"
	else
		log "  Scanned: $TOTAL_FILES files ($SCAN_COUNT pattern-scanned)"
	fi
	log "─────────────────────────────────────────────────────────────"
	if (( TOTAL_ISSUES == 0 && LOW_COUNT == 0 )); then
		log "  No issues found."
	else
		log ""
		if (( CRITICAL_COUNT > 0 )); then
			log "  CRITICAL RISKS: $CRITICAL_COUNT"
			(( SHELL_COUNT > 0 ))                  && log "            $SHELL_COUNT reverse shell patterns"
			(( CRYPTO_COUNT > 0 ))                 && log "            $CRYPTO_COUNT crypto miner patterns"
			(( MISMATCH_CRITICAL_COUNT > 0 ))      && log "            $MISMATCH_CRITICAL_COUNT MIME type mismatches (executable content)"
			(( DECEPTIVE_COUNT > 0 ))              && log "            $DECEPTIVE_COUNT deceptive file extensions (hiding executable)"
			(( EMBEDDED_CODE_CRITICAL_COUNT > 0 )) && log "            $EMBEDDED_CODE_CRITICAL_COUNT binary files with injected code"
			log ""
		fi
		if (( HIGH_COUNT > 0 )); then
			log "  HIGH RISKS: $HIGH_COUNT"
			(( OBFUSC_COUNT > 0 ))             && log "            $OBFUSC_COUNT obfuscated code patterns"
			(( EXFIL_COUNT > 0 ))              && log "            $EXFIL_COUNT data exfiltration patterns"
			(( MISMATCH_HIGH_COUNT > 0 ))      && log "            $MISMATCH_HIGH_COUNT MIME type mismatches (unrelated binary types)"
			(( EMBEDDED_CODE_HIGH_COUNT > 0 )) && log "            $EMBEDDED_CODE_HIGH_COUNT files with embedded active script"
			(( HYGIENE_HIGH_COUNT > 0 ))       && log "            $HYGIENE_HIGH_COUNT file hygiene violations (widespread mislabeling)"
			log ""
		fi
		if (( MEDIUM_COUNT > 0 )); then
			log "  MEDIUM RISK: $MEDIUM_COUNT"
			(( WEBSHELL_COUNT > 0 ))        && log "            $WEBSHELL_COUNT webshell patterns"
			(( HYGIENE_MEDIUM_COUNT > 0 ))  && log "            $HYGIENE_MEDIUM_COUNT file hygiene violations (notable mislabeling)"
			log ""
		fi
		if (( LOW_COUNT > 0 )); then
			log "  LOW (info only): $LOW_COUNT"
			log "            $MISLABEL_LOW_COUNT image extension mislabels"
			if [[ "$VERBOSE" == "true" && ${#MISLABEL_PAIRS[@]} -gt 0 ]]; then
				for _p in "${!MISLABEL_PAIRS[@]}"; do
					log "            ${MISLABEL_PAIRS[$_p]}x  $_p"
				done
			fi
			log ""
			log "            (Low risk factors do not impact risk scoring.)"
			log ""
		fi
	fi
	ELAPSED=$(( SECONDS - SCAN_START ))
	log "─────────────────────────────────────────────────────────────"
	log "  Total issues: $TOTAL_ISSUES  (+ $LOW_COUNT informational)"
	log "  Risk score:   $RISK_SCORE"
	log "  Elapsed:      ${ELAPSED}s"
	if [[ "$VERBOSE" == "true" && SIZE_SKIP_COUNT -gt 0 ]]; then
		log "  Note: $SIZE_SKIP_COUNT files over $(( PATTERN_SIZE_LIMIT / 1048576 ))MB were excluded from pattern/embedded-code scanning."
		[[ -z "$TARGET_FILE" ]] && \
			log "        Evaluate individually: find \"$TARGET_DIR\" -type f -size +$(( PATTERN_SIZE_LIMIT / 1048576 ))M"
	fi
	log "─────────────────────────────────────────────────────────────"
	log ""
fi


# ─── write JSON output ───────────────────────────────────────────
#
# --write-json PATH takes priority (internal use by run-filescans.sh).
# Otherwise, write to standard meta output path unless --no-file was given.
# Runs unconditionally — both JSON and text mode may need a file written.
#
if [[ -n "$WRITE_JSON_FILE" ]]; then
	generate_json > "$WRITE_JSON_FILE"
elif [[ "$WRITE_FILE" == "true" ]]; then
	mkdir -p "$OUTPUT_DIR" 2>/dev/null \
		|| { echo "Error: cannot create output directory '$OUTPUT_DIR'" >&2; exit 2; }
	generate_json > "$OUTPUT_FILE"
	log "[OK]   Saved: $OUTPUT_FILE"
fi


# ─── exit code ──────────────────────────────────────────────────
#
(( CRITICAL_COUNT + HIGH_COUNT > 0 )) && exit 1 || exit 0

