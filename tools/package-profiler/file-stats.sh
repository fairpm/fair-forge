#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors

#
# file-stats.sh — tabulate file statistics by type
#
# usage: file-stats.sh [OPTIONS] [directory]
#
# scans a directory tree and reports file counts, line counts,
# and sizes grouped by category (code, web, config, images, etc.)
# with per-extension detail in verbose mode.
#
# Output file: ./meta/<clean-name>/<clean-name>.file-stats.json
#
VERSION="1.0.0"


# ─── environment ───────────────────────────────────────────────────
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
#   permission-check.sh, deep-filescan.sh
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




# ─── defaults ──────────────────────────────────────────────────────
#
TARGET_DIR="."
SILENT=false
JSON_OUTPUT=false
VERBOSE=false
WRITE_JSON_FILE=""    # internal: explicit path override (used by run-filescans.sh)
META_BASE="./meta"    # base directory for standard output
OUTPUT_DIR=""         # default: $META_BASE/<clean-name>/ (set after name detection)
WRITE_FILE=true       # set false with --no-file


# ─── categories of files ───────────────────────────────────────────
# →
# file categories by .extension: list here else = "other"
#
# CATEGORY_ORDER determines display order
#
CATEGORY_ORDER="code web markup config data docs images fonts media archives binaries secrets"


# TEXT categories get a line count, binaries (obviously) don't
#
TEXT_CATEGORIES="code web markup config data"


# map extensions by category type in associative array
#
init_extension_map() {

	# code
	for e in \
		php js ts jsx tsx mjs cjs vue svelte \
		py pyw rb pl pm sh bash zsh fish ksh csh \
		go rs c cpp cc cxx h hpp hxx hh \
		java kt kts scala clj cljs cljc groovy gradle \
		swift m mm cs fs fsx vb \
		r rmd lua zig nim v d \
		ex exs erl hrl hs lhs ml mli ocaml \
		sql plsql psql \
		asm s nasm wasm wat \
		dart coffee elm ino pde \
		tf hcl nix bat \
		makefile cmake rakefile gemfile; do
		EXT_MAP[$e]="code"
	done

	# web
	for e in html htm xhtml css scss sass less styl svg; do
		EXT_MAP[$e]="web"
	done

	# markup (or -down) & other text
	for e in md markdown mdx txt text asc rst tex latex adoc asciidoc org textile wiki \
		log changelog license licence ftl; do
		EXT_MAP[$e]="markup"
	done

	# config
	for e in \
		json json5 jsonc jsonl ndjson \
		yaml yml toml ini conf cfg \
		xml xsl xslt dtd xsd wsdl \
		env properties plist \
		htaccess htpasswd nginx \
		editorconfig gitignore gitattributes gitmodules \
		dockerignore browserslistrc babelrc eslintrc prettierrc \
		stylelintrc npmrc nvmrc yarnrc \
		flake8 pylintrc mypy isort bandit \
		rubocop gemrc \
		tsconfig lock neon dist pyml; do
		EXT_MAP[$e]="config"
	done

	# data - text-based structured data
	for e in csv tsv sql ndjson geojson graphql gql opml ics bru po pot catkeys; do
		EXT_MAP[$e]="data"
	done

	# docs - binary office/document formats other than text-based
	for e in pdf doc docx xls xlsx ppt pptx odt ods odp rtf epub mobi djvu; do
		EXT_MAP[$e]="docs"
	done

	# images
	for e in \
		jpg jpeg png gif bmp webp avif ico tiff tif \
		psd ai eps raw cr2 nef arw dng heic heif xcf; do
		EXT_MAP[$e]="images"
	done

	# fonts
	for e in ttf otf woff woff2 eot; do
		EXT_MAP[$e]="fonts"
	done

	# media
	for e in \
		mp3 mp4 m4a m4v wav flac aac ogg opus wma \
		avi mov mkv wmv webm mpg mpeg fla flv \
		3gp ogv; do
		EXT_MAP[$e]="media"
	done

	# archives
	for e in \
		zip tar gz bz2 xz zst lz4 7z rar \
		tgz tbz2 txz \
		jar war ear \
		deb rpm pkg dmg iso img; do
		EXT_MAP[$e]="archives"
	done

	# binaries (compiled/object files and self-contained executables)
	for e in \
		o obj so dll dylib a lib \
		exe com bin out elf msi appimage \
		class pyc pyo pyd whl egg \
		beam mo; do
		EXT_MAP[$e]="binaries"
	done

	# secrets — certificate and key material; security-relevant grouping
	# (pem/key may be text or binary; crt/p12/pfx/jks are binary; all treated as non-text)
	for e in pem key crt csr cer p12 pfx jks pub; do
		EXT_MAP[$e]="secrets"
	done
}


# display names for categories
#
declare -A CATEGORY_NAMES=(
	[code]="Code"
	[web]="Web"
	[markup]="Text / Markup"
	[config]="Config"
	[data]="Data"
	[docs]="Office / PDF"
	[images]="Images"
	[fonts]="Fonts"
	[media]="Media"
	[archives]="Archives"
	[binaries]="Binaries"
	[secrets]="Keys / Certs"
	[other]="Other Files"
)


# link well-known filenames without extensions to their category
#
declare -A KNOWN_NAMES=(
	[makefile]="code" [rakefile]="code" [gemfile]="code"
	[dockerfile]="config" [vagrantfile]="config" [procfile]="config"
	[cakefile]="code" [gruntfile]="code" [gulpfile]="code"
	[justfile]="code" [taskfile]="code" [brewfile]="config"
	[license]="markup" [licence]="markup" [copying]="markup"
	[readme]="markup" [changelog]="markup" [changes]="markup"
	[authors]="markup" [contributors]="markup"
	[news]="markup" [history]="markup" [todo]="markup"
	# hidden extensionless files — key includes the leading dot
	[.gitkeep]="config" [.imgbotconfig]="config"
	[.eslintignore]="config" [.prettierignore]="config"
	[.stylelintignore]="config" [.npmignore]="config"
	[.dockerignore]="config" [.hgignore]="config" [.bzrignore]="config"
)


# dislay name for well-known file extensions
#
declare -A EXT_NAMES=(
	[php]="PHP" [js]="JavaScript" [ts]="TypeScript"
	[jsx]="React" [tsx]="React TS" [vue]="Vue" [svelte]="Svelte"
	[py]="Python" [rb]="Ruby" [pl]="Perl" [sh]="Shell" [bat]="Batch"
	[go]="Go" [rs]="Rust" [c]="C" [cpp]="C++" [h]="C Header"
	[java]="Java" [kt]="Kotlin" [scala]="Scala" [cs]="C#"
	[swift]="Swift" [r]="R" [lua]="Lua" [zig]="Zig"
	[ex]="Elixir" [erl]="Erlang" [hs]="Haskell" [clj]="Clojure"
	[dart]="Dart" [sql]="SQL" [tf]="Terraform"
	[html]="HTML" [htm]="HTML" [css]="CSS" [scss]="SCSS"
	[sass]="Sass" [less]="LESS" [svg]="SVG"
	[md]="Markdown" [mdx]="MDX" [rst]="reStructuredText" [tex]="LaTeX"
	[adoc]="AsciiDoc" [org]="Org" [ftl]="Template"
	[json]="JSON" [yaml]="YAML" [yml]="YAML" [toml]="TOML"
	[xml]="XML" [ini]="INI" [csv]="CSV" [tsv]="TSV"
	[lock]="Lockfile" [neon]="NEON" [dist]="Dist Config"
	[bru]="Bruno" [po]="Gettext" [pot]="Gettext Template" [catkeys]="Catkeys"
	[pdf]="PDF" [doc]="Word" [docx]="Word" [xls]="Excel"
	[xlsx]="Excel" [ppt]="PowerPoint" [pptx]="PowerPoint"
	[jpg]="JPEG" [jpeg]="JPEG" [png]="PNG" [gif]="GIF"
	[webp]="WebP" [svg]="SVG" [ico]="Icon" [psd]="Photoshop"
	[ttf]="TrueType" [otf]="OpenType" [woff]="WOFF" [woff2]="WOFF2"
	[mp3]="MP3" [mp4]="MP4" [wav]="WAV" [mkv]="Matroska"
	[zip]="ZIP" [tar]="Tar" [gz]="Gzip" [7z]="7-Zip"
	[log]="Log" [env]="Env" [txt]="Text" [changelog]="Changelog"
	[appimage]="AppImage" [mo]="Gettext Binary"
	[pem]="PEM" [key]="Key" [crt]="Certificate" [csr]="CSR"
	[cer]="Certificate" [p12]="PKCS#12" [pfx]="PFX" [jks]="Keystore"
	[pub]="Public Key"
	[_noext]="no extension"
)


# ─── define functions ──────────────────────────────────────────────────────
#

show_help() {
	cat << EOF

FILE-STATS:
    Tabulate file statistics by type for a directory tree.
    file-stats.sh Version $VERSION

USAGE:
    $(basename "$0") [OPTIONS] [directory]

OPTIONS:
    -h, --help          Show this help message
    -s, --silent        Suppress output (exit code only)
    -j, --json          Output results in JSON format
    -sj, -js            Silent + JSON (pipe-friendly)
    -v, --verbose       Show per-extension breakdown within categories
    -o, --output-dir D  Write JSON output to directory D
                        (default: ./meta/<clean-name>/)
    --meta-base DIR     Base directory for meta output (default: ./meta)
    --no-file           Output JSON to stdout only; do not write file
    --write-json F      Write JSON results to file F (used by run-filescans.sh)
    --version           Print version and exit

ARGUMENTS:
    [directory]         Directory to scan (default: current directory)

OUTPUT:
    ./meta/<clean-name>/<clean-name>.file-stats.json

CATEGORIES:
    Files are grouped by extension into: Code, Web, Markup, Config, Data,
    Documents, Images, Fonts, Media, Archives, Binaries, & Other
    Minified files tracked separately. Lines are counted for text-based categories.

SKIPS:
    vendor/, node_modules/, venv/, .venv/, __pycache__/, .git/, .svn/, .hg/

EXIT CODES:
    0   Success
    2   Errors (directory not found, invalid option)

EXAMPLES:
    $(basename "$0")
    $(basename "$0") -v /var/www/html
    $(basename "$0") -j ./src > stats.json
    $(basename "$0") -j --no-file ./dir > stats.json

EOF
}

# write function for non-silent modes
#
log() { [[ "$SILENT" == "false" && "$JSON_OUTPUT" == "false" ]] && echo "$@" >&2; }


# json-escape $string - deal with \ " / and control characters U+0000–U+001F (see RFC 8259 §7)
#
json_esc() {
	local s="$1" out="" i char ord
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


# byte counts stop being human-readable pretty quickly
#
format_bytes() {
	local b=$1
	if (( b < 1024 )); then
		echo "${b} B"
	elif (( b < 1048576 )); then
		echo "$(( (b + 512) / 1024 )) KB"
	elif (( b < 1073741824 )); then
		# one decimal place for MB
		local mb_x10=$(( (b * 10 + 524288) / 1048576 ))
		echo "$(( mb_x10 / 10 )).$(( mb_x10 % 10 )) MB"
	else
		local gb_x10=$(( (b * 10 + 536870912) / 1073741824 ))
		echo "$(( gb_x10 / 10 )).$(( gb_x10 % 10 )) GB"
	fi
}

# guess we could also format numbers over 999
#
format_number() {
	local n=$1
	if (( n < 0 )); then
		echo "$n"
		return
	fi
	# add commas to large numbers
	local s="$n" out="" count=0 i
	for (( i=${#s}-1; i>=0; i-- )); do
		(( count > 0 && count % 3 == 0 )) && out=",$out"
		out="${s:$i:1}$out"
		((count++))
	done
	echo "$out"
}


# ─── parse args ───────────────────────────────────────────
#
while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)    show_help; exit 0 ;;
		--version)    echo "file-stats.sh v$VERSION"; exit 0 ;;
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

DISPLAY_NAME="$(sanitize_name "$TARGET_DIR")"
SCAN_START=$SECONDS

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${META_BASE}/${DISPLAY_NAME}"
OUTPUT_FILE="${OUTPUT_DIR}/${DISPLAY_NAME}.file-stats.json"

# jq is required for JSON output formatting
#
command -v jq &>/dev/null || {
	echo "Error: Required tool 'jq' not found" >&2
	exit 2
}


# ─── init extension map ─────────────────────────────────────────
#
declare -A EXT_MAP=()
init_extension_map

# set of text cat for quick lookups
#
declare -A TEXT_CAT_SET=()
for _cat in $TEXT_CATEGORIES; do
	TEXT_CAT_SET[$_cat]=1
done


# ─── step 1: scan files ────────────────────────────────────
#
# collect size and path for each file; classify in the loop later (faster performance)
#
# track per category:
#   CAT_FILES[cat]  = file count
#   CAT_BYTES[cat]  = total bytes
# track per file extension:
#   EXT_FILES[ext]  = file count
#   EXT_BYTES[ext]  = total bytes
#   EXT_TO_CAT[ext] = which category this ext belongs to
# count:
#   HIDDEN_FILES, HIDDEN_DIRS
# text file paths:
#   written to a null-delimited temp file for counting, prefixed with ext
#

declare -A CAT_FILES=() CAT_BYTES=()
declare -A EXT_FILES=() EXT_BYTES=() EXT_TO_CAT=()
declare -a SEEN_CATS=()		# ordered & deduped list of categories seen
declare -A SEEN_CAT_SET=()	# dedup

TOTAL_FILES=0
TOTAL_BYTES=0
HIDDEN_FILES=0
HIDDEN_DIRS=0
MINIFIED_FILES=0
MINIFIED_BYTES=0
MINIFIED_BY_EXT_FILES=()	# tracked overall, not by extension: .min.*
EMPTY_FILES=0


# create temp directory for scratch files
#
TMPDIR_WORK=$(mktemp -d) || { echo "Error: Cannot create temp directory" >&2; exit 2; }
trap 'rm -rf "$TMPDIR_WORK"' EXIT
TEXT_LIST="$TMPDIR_WORK/text_files.list"


log ""
log "File Stats: [$DISPLAY_NAME]"
log " ────────────────────────────────────────────────────────── " 


# count hidden files/dirs at any depth
#
HIDDEN_DIRS=$(find "$TARGET_DIR" -mindepth 1 -type d -name '.*' \
	-not -path "*/.git/*" -not -path "*/.svn/*" -not -path "*/.hg/*" \
	2>/dev/null | wc -l)

while IFS=$'\t' read -r f_size f_path; do
	[[ -z "$f_path" ]] && continue

	((TOTAL_FILES++))
	TOTAL_BYTES=$((TOTAL_BYTES + f_size))

	filename="${f_path##*/}"

	# detect .hiddenfiles
	if [[ "$filename" == .* ]]; then
		((HIDDEN_FILES++))
	fi

	# detect empty files
	(( f_size == 0 )) && ((EMPTY_FILES++))

	# convert extension to lowercase
	# Hidden files with no real extension (e.g., .gitignore, .eslintignore) are detected here:
	# if the filename starts with '.' and the part after that leading dot contains no further dot,
	# there is no extension — the whole name (including the dot) is the filename.
	ext="${filename##*.}"
	_hidden_noext=false
	if [[ "$filename" == .* && "${filename#.}" != *.* ]]; then
		_hidden_noext=true
	fi

	if [[ "$ext" == "$filename" || "$_hidden_noext" == "true" ]]; then
		# extensionless or hidden-extensionless: check known filenames
		ext=""
		lower_name="${filename,,}"
		cat="${KNOWN_NAMES[$lower_name]:-other}"
	else
		ext="${ext,,}"

		# detect minified *.min.js, *.min.css, etc.
		is_min=false
		if [[ "$filename" == *.min.* ]]; then
			is_min=true
			((MINIFIED_FILES++))
			MINIFIED_BYTES=$((MINIFIED_BYTES + f_size))
		fi

		# look up the category
		cat="${EXT_MAP[$ext]:-other}"
	fi

	# key for extensionless files
	[[ -z "$ext" ]] && ext="_noext"

	# first time finding this category? register it
	if [[ -z "${SEEN_CAT_SET[$cat]+x}" ]]; then
		SEEN_CAT_SET[$cat]=1
		SEEN_CATS+=("$cat")
	fi

	# gather category stats
	CAT_FILES[$cat]=$(( ${CAT_FILES[$cat]:-0} + 1 ))
	CAT_BYTES[$cat]=$(( ${CAT_BYTES[$cat]:-0} + f_size ))

	# gather per-extension stats
	EXT_FILES[$ext]=$(( ${EXT_FILES[$ext]:-0} + 1 ))
	EXT_BYTES[$ext]=$(( ${EXT_BYTES[$ext]:-0} + f_size ))
	EXT_TO_CAT[$ext]="$cat"

	# for non-empty text-based files, queue for batch line counting
	if [[ -n "${TEXT_CAT_SET[$cat]+x}" ]] && (( f_size > 0 )); then
		# write ext\0path\0 so we can attribute lines back to extensions
		printf '%s\0%s\0' "$ext" "$f_path" >> "$TEXT_LIST"
	fi

done < <(find "$TARGET_DIR" -mount -type f \
	-not -path "*/.git/*" \
	-not -path "*/.svn/*" \
	-not -path "*/.hg/*" \
	-not -path "*/node_modules/*" \
	-not -path "*/vendor/*" \
	-not -path "*/venv/*" \
	-not -path "*/.venv/*" \
	-not -path "*/__pycache__/*" \
	-printf '%s\t%p\n' 2>/dev/null)


# ─── step 2: batch line counting ───────────────────────────────
#
# read text file list & count lines in large batches using xargs + wc -l
# parse output per-file to accumulated line counts by extension & category
#
declare -A CAT_LINES=() EXT_LINES=()

if [[ -s "$TEXT_LIST" ]]; then
	# extract paths & feed to wc -l in batches
	# text list format: ext\0path\0ext\0path\0...
	#   - count lines per file (batch wc -l)
	#   - attrib each file's line count to its extension
	#
	# read pairs from TEXT_LIST & build null-delimited path list for xargs
	# + parallel array of extensions
	#
	declare -a LINE_EXTS=()
	declare -a LINE_PATHS=()

	while IFS= read -r -d '' ext && IFS= read -r -d '' fpath; do
		LINE_EXTS+=("$ext")
		LINE_PATHS+=("$fpath")
	done < "$TEXT_LIST"

	if (( ${#LINE_PATHS[@]} > 0 )); then
		# batch wc -l: write paths null-delimited, pipe through xargs
		# wc -l outputs "  LINES FILENAME" per file, plus a "total" line for batches
		# parse the per-file lines only
		#
		declare -a WC_RESULTS=()
		while IFS= read -r line; do
			WC_RESULTS+=("$line")
		done < <(printf '%s\0' "${LINE_PATHS[@]}" | xargs -0 wc -l 2>/dev/null)

		# parse wc output: each line is "  NNNNN path" or "  NNNNN total"
		# skip "total" lines & match paths to extensions by index
		#
		# wc -l with xargs may split into multiple batches with their own total, so
		# track a path index that skips totals
		#
		path_idx=0
		for wc_line in "${WC_RESULTS[@]}"; do
			# strip leading whitespace, extract count and name
			wc_line="${wc_line#"${wc_line%%[![:space:]]*}"}"
			wc_count="${wc_line%% *}"
			wc_name="${wc_line#* }"

			# skip total lines
			[[ "$wc_name" == "total" ]] && continue

			# attribute to the extension at this index
			if (( path_idx < ${#LINE_EXTS[@]} )); then
				e="${LINE_EXTS[$path_idx]}"
				c="${EXT_TO_CAT[$e]:-other}"
				EXT_LINES[$e]=$(( ${EXT_LINES[$e]:-0} + wc_count ))
				CAT_LINES[$c]=$(( ${CAT_LINES[$c]:-0} + wc_count ))
			fi
			((path_idx++))
		done
	fi
fi


# count total lines across all text categories
#
TOTAL_LINES=0
for _cat in $TEXT_CATEGORIES; do
	TOTAL_LINES=$(( TOTAL_LINES + ${CAT_LINES[$_cat]:-0} ))
done


# ─── step 2b: best-practice package files check ────────────────
#
# Look for convention files that well-maintained packages should ship.
# Checked only in the project root (and .github/ for CODEOWNERS/FUNDING);
# files under vendor/ or node_modules/ are excluded.
#
# Results are stored for use in both text and JSON output below.
#
declare -A BP_FOUND=()    # key → filename that satisfied it
declare -A BP_MISSING=()  # key → human description of what is expected

_bp_check() {
	# _bp_check KEY "desc" pattern [pattern ...]
	# Searches TARGET_DIR (maxdepth 1) for any of the given -iname patterns.
	# Also checks .github/ subdirectory when a second depth level is useful.
	local key="$1" desc="$2"; shift 2
	local found_file=""
	local pat
	for pat in "$@"; do
		found_file=$(find "$TARGET_DIR" -maxdepth 1 -type f -iname "$pat" 2>/dev/null | head -1)
		[[ -n "$found_file" ]] && break
	done
	if [[ -n "$found_file" ]]; then
		BP_FOUND[$key]="${found_file##*/}"
	else
		BP_MISSING[$key]="$desc"
	fi
}

_bp_check_deep() {
	# Like _bp_check but also scans .github/ at maxdepth 2, excluding vendor.
	local key="$1" desc="$2"; shift 2
	local found_file=""
	local pat
	for pat in "$@"; do
		found_file=$(find "$TARGET_DIR" -maxdepth 2 \
			-not -path "*/vendor/*" -not -path "*/node_modules/*" \
			-type f -iname "$pat" 2>/dev/null | head -1)
		[[ -n "$found_file" ]] && break
	done
	if [[ -n "$found_file" ]]; then
		# show relative path from TARGET_DIR
		local rel="${found_file#"$TARGET_DIR/"}"
		BP_FOUND[$key]="$rel"
	else
		BP_MISSING[$key]="$desc"
	fi
}

# Core governance & documentation files — checked at root (maxdepth 1), case-insensitive via -iname
_bp_check "readme"          "README.md / README.txt"          "readme.md"       "readme.txt"       "readme"
_bp_check "license"         "LICENSE / COPYING"               "license"         "license.md"       "license.txt" "copying"
_bp_check "security"        "SECURITY.md / SECURITY.txt"      "security.md"     "security.txt"
_bp_check "contributing"    "CONTRIBUTING.md"                  "contributing.md" "contributing.txt"
_bp_check "changelog"       "CHANGELOG.md"                    "changelog.md"    "changelog.txt"    "changes.md"  "history.md"
_bp_check "code_of_conduct" "CODE_OF_CONDUCT.md"              "code_of_conduct.md" "code_of_conduct.txt"
_bp_check "notice"          "NOTICE / NOTICE.md"              "notice"          "notice.md"        "notice.txt"
_bp_check "maintainers"     "MAINTAINERS / MAINTAINERS.md"    "maintainers"     "maintainers.md"   "maintainers.txt"
_bp_check "governance"      "GOVERNANCE.md"                   "governance.md"   "governance.txt"

# Files conventionally found at root or inside .github/ — checked at maxdepth 2, vendor excluded
_bp_check_deep "codeowners" "CODEOWNERS"                    "codeowners"
_bp_check_deep "sbom"       "SBOM file (sbom.json / *.cdx.json / *.spdx)" \
	"sbom.json" "sbom.xml" "bom.json" "bom.xml" "*.cdx.json" "*.spdx.json" "*.spdx" "*.spdx.txt"

BP_FOUND_COUNT=${#BP_FOUND[@]}
BP_MISSING_COUNT=${#BP_MISSING[@]}
BP_TOTAL=$(( BP_FOUND_COUNT + BP_MISSING_COUNT ))

# categories in defined order first + extras alphabetically
#
declare -a DISPLAY_CATS=()
for _cat in $CATEGORY_ORDER; do
	[[ -n "${SEEN_CAT_SET[$_cat]+x}" ]] && DISPLAY_CATS+=("$_cat")
done

# add "other files" last if we have any
#
[[ -n "${SEEN_CAT_SET[other]+x}" ]] && DISPLAY_CATS+=("other")



# ─── generate_json ──────────────────────────────────────────────
#
# Build and write the complete JSON document to stdout.
# Categories and best-practices arrays are built via jq -cn to a JSONL
# scratch file then slurped; this avoids the heredoc+string-concat
# approach which is fragile on paths with special characters.
#
generate_json() {
	local _elapsed=$(( SECONDS - SCAN_START ))

	# ── categories JSONL ──
	local _cats_file="$TMPDIR_WORK/categories.jsonl"
	: > "$_cats_file"
	for _cat in "${DISPLAY_CATS[@]}"; do
		local _is_text="false"
		[[ -n "${TEXT_CAT_SET[$_cat]+x}" ]] && _is_text="true"
		local _lines="${CAT_LINES[$_cat]:-0}"
		local _files="${CAT_FILES[$_cat]}"
		local _bytes="${CAT_BYTES[$_cat]}"
		local _label="${CATEGORY_NAMES[$_cat]:-$_cat}"

		# per-extension JSONL for this category
		local _exts_file="$TMPDIR_WORK/exts_${_cat}.jsonl"
		: > "$_exts_file"
		while IFS= read -r _ext; do
			[[ -z "$_ext" ]] && continue
			[[ "${EXT_TO_CAT[$_ext]}" != "$_cat" ]] && continue
			local _ef="${EXT_FILES[$_ext]}"
			local _eb="${EXT_BYTES[$_ext]}"
			local _el="${EXT_LINES[$_ext]:-0}"
			local _ename="${EXT_NAMES[$_ext]:-}"
			if [[ "$_is_text" == "true" ]]; then
				jq -cn \
					--arg ext   "$_ext"  \
					--arg name  "$_ename" \
					--argjson files "$_ef" \
					--argjson bytes "$_eb" \
					--argjson lines "$_el" \
					'{"extension":$ext,"files":$files,"bytes":$bytes,"lines":$lines}
					 + if $name != "" then {"name":$name} else {} end' \
					>> "$_exts_file"
			else
				jq -cn \
					--arg ext   "$_ext"  \
					--arg name  "$_ename" \
					--argjson files "$_ef" \
					--argjson bytes "$_eb" \
					'{"extension":$ext,"files":$files,"bytes":$bytes}
					 + if $name != "" then {"name":$name} else {} end' \
					>> "$_exts_file"
			fi
		done < <(printf '%s\n' "${!EXT_TO_CAT[@]}" | sort)

		if [[ "$_is_text" == "true" ]]; then
			jq -cn \
				--arg     cat    "$_cat"   \
				--arg     lbl    "$_label" \
				--argjson files  "$_files" \
				--argjson bytes  "$_bytes" \
				--argjson lines  "$_lines" \
				--slurpfile extensions "$_exts_file" \
				'{"category":$cat,"label":$lbl,"files":$files,"bytes":$bytes,
				  "lines":$lines,"is_text":true,"extensions":$extensions}' \
				>> "$_cats_file"
		else
			jq -cn \
				--arg     cat    "$_cat"   \
				--arg     lbl    "$_label" \
				--argjson files  "$_files" \
				--argjson bytes  "$_bytes" \
				--slurpfile extensions "$_exts_file" \
				'{"category":$cat,"label":$lbl,"files":$files,"bytes":$bytes,
				  "is_text":false,"extensions":$extensions}' \
				>> "$_cats_file"
		fi
	done

	# ── best-practices JSONL ──
	local _bp_file="$TMPDIR_WORK/best_practices.jsonl"
	: > "$_bp_file"
	for _bp_key in readme license security contributing changelog code_of_conduct \
	               notice maintainers governance codeowners sbom; do
		if [[ -n "${BP_FOUND[$_bp_key]+x}" ]]; then
			jq -cn --arg key "$_bp_key" --arg file "${BP_FOUND[$_bp_key]}" \
				'{"key":$key,"found":true,"file":$file}' >> "$_bp_file"
		else
			jq -cn --arg key "$_bp_key" --arg expected "${BP_MISSING[$_bp_key]:-$_bp_key}" \
				'{"key":$key,"found":false,"expected":$expected}' >> "$_bp_file"
		fi
	done

	jq -n \
		--arg     dir          "$DISPLAY_NAME"   \
		--arg     ver          "$VERSION"         \
		--argjson elapsed      "$_elapsed"        \
		--argjson total_files  "$TOTAL_FILES"     \
		--argjson total_lines  "$TOTAL_LINES"     \
		--argjson total_bytes  "$TOTAL_BYTES"     \
		--argjson empty        "$EMPTY_FILES"     \
		--argjson hidden_f     "$HIDDEN_FILES"    \
		--argjson hidden_d     "$HIDDEN_DIRS"     \
		--argjson minif        "$MINIFIED_FILES"  \
		--argjson minib        "$MINIFIED_BYTES"  \
		--argjson bp_total     "$BP_TOTAL"        \
		--argjson bp_found     "$BP_FOUND_COUNT"  \
		--argjson bp_missing   "$BP_MISSING_COUNT"\
		--slurpfile categories      "$_cats_file" \
		--slurpfile best_practices  "$_bp_file"   \
		'{
			target_directory: $dir,
			scan_type:        "file_statistics",
			version:          $ver,
			elapsed_seconds:  $elapsed,
			totals: {
				files:               $total_files,
				lines:               $total_lines,
				bytes:               $total_bytes,
				empty_files:         $empty,
				hidden_files:        $hidden_f,
				hidden_directories:  $hidden_d,
				minified_files:      $minif,
				minified_bytes:      $minib
			},
			categories: $categories,
			best_practices: {
				checked: $bp_total,
				found:   $bp_found,
				missing: $bp_missing,
				items:   $best_practices
			}
		}'
}


if [[ "$JSON_OUTPUT" == "true" ]]; then
	generate_json

elif [[ "$SILENT" == "false" ]]; then
	# ── human output ──

	# non-json output header
	printf "  %-24s %8s %10s %10s\n" "Category" "Files" "Lines" "Size"
	log " ────────────────────────────────────────────────────────── "

	for cat in "${DISPLAY_CATS[@]}"; do
		is_text=false
		[[ -n "${TEXT_CAT_SET[$cat]+x}" ]] && is_text=true

		files="${CAT_FILES[$cat]}"
		bytes="${CAT_BYTES[$cat]}"
		lines="${CAT_LINES[$cat]:-0}"
		label="${CATEGORY_NAMES[$cat]:-$cat}"

		if [[ "$is_text" == "true" ]]; then
			printf "  %-24s %8s %10s %10s\n" \
				"$label" "$(format_number "$files")" \
				"$(format_number "$lines")" "$(format_bytes "$bytes")"
		else
			printf "  %-24s %8s %10s %10s\n" \
				"$label" "$(format_number "$files")" \
				"—" "$(format_bytes "$bytes")"
		fi

		# collect extensions for category sorted file count desc
		declare -A _ext_for_cat=()
		for ext in "${!EXT_TO_CAT[@]}"; do
			[[ "${EXT_TO_CAT[$ext]}" == "$cat" ]] && _ext_for_cat[$ext]="${EXT_FILES[$ext]}"
		done

		# sorted extension list
		declare -a _sorted_exts=()
		while IFS='|' read -r _cnt _ext; do
			[[ -z "$_ext" ]] && continue
			_sorted_exts+=("$_ext")
		done < <(for ext in "${!_ext_for_cat[@]}"; do
			echo "${_ext_for_cat[$ext]}|$ext"
		done | sort -t'|' -k1,1 -rn)

		if [[ "$VERBOSE" == "true" ]]; then
			# verbose, show full per-extension table with counts, lines, sizes
			for _ext in "${_sorted_exts[@]}"; do
				_files="${EXT_FILES[$_ext]}"
				_bytes="${EXT_BYTES[$_ext]}"
				_lines="${EXT_LINES[$_ext]:-0}"

				_label="  .$_ext"
				if [[ "$_ext" == "_noext" ]]; then
					_label="  (no extension)"
				else
					_ename="${EXT_NAMES[$_ext]:-}"
					[[ -n "$_ename" ]] && _label+=" ($_ename)"
				fi

				if [[ "$is_text" == "true" ]]; then
					printf "    %-22s %8s %10s %10s\n" \
						"$_label" "$(format_number "$_files")" \
						"$(format_number "$_lines")" "$(format_bytes "$_bytes")"
				else
					printf "    %-22s %8s %10s %10s\n" \
						"$_label" "$(format_number "$_files")" \
						"—" "$(format_bytes "$_bytes")"
				fi
			done
		else
			# non-verbose default is one-line breakdown
			_parts=()
			for _ext in "${_sorted_exts[@]}"; do
				_n="${EXT_FILES[$_ext]}"
				if [[ "$_ext" == "_noext" ]]; then
					_parts+=("$_n no-ext")
				else
					_parts+=("$_n $_ext")
				fi
			done
			if (( ${#_parts[@]} > 0 )); then
				# join with ", "
				_breakdown=""
				for (( _i=0; _i<${#_parts[@]}; _i++ )); do
					(( _i > 0 )) && _breakdown+=", "
					_breakdown+="${_parts[$_i]}"
				done
				printf "    %s\n" "$_breakdown"
			fi
		fi

		unset _ext_for_cat _sorted_exts
	done

	log " ────────────────────────────────────────────────────────── "
	printf "  %-24s %8s %10s %10s\n" \
		"TOTAL" "$(format_number "$TOTAL_FILES")" \
		"$(format_number "$TOTAL_LINES")" "$(format_bytes "$TOTAL_BYTES")"
	log " ────────────────────────────────────────────────────────── "

	ELAPSED=$(( SECONDS - SCAN_START ))
	printf "  Elapsed: %ss\n" "$ELAPSED"
	log ""

	# other info not in the extension count
	#
	info_parts=()
	(( HIDDEN_FILES > 0 ))   && info_parts+=("$HIDDEN_FILES hidden files")
	(( HIDDEN_DIRS > 0 ))    && info_parts+=("$HIDDEN_DIRS hidden dirs")
	(( EMPTY_FILES > 0 ))    && info_parts+=("$EMPTY_FILES empty")
	(( MINIFIED_FILES > 0 )) && info_parts+=("$MINIFIED_FILES minified ($(format_bytes $MINIFIED_BYTES))")

	if (( ${#info_parts[@]} > 0 )); then
		# join with ", "
		info_str=""
		for (( i=0; i<${#info_parts[@]}; i++ )); do
			(( i > 0 )) && info_str+=", "
			info_str+="${info_parts[$i]}"
		done
		log "  $info_str"
		log ""
	fi

	# best-practice files report
	#
	log " ────────────────────────────────────────────────────────── "
	log "  Package Conventions ($BP_FOUND_COUNT/$BP_TOTAL present)"
	log " ────────────────────────────────────────────────────────── "
	for bp_key in readme license security contributing changelog code_of_conduct \
	              notice maintainers governance codeowners sbom; do
		if [[ -n "${BP_FOUND[$bp_key]+x}" ]]; then
			log "  [OK]  $bp_key: ${BP_FOUND[$bp_key]}"
		else
			log "  [--]  $bp_key: missing  (${BP_MISSING[$bp_key]:-$bp_key})"
		fi
	done
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

exit 0
