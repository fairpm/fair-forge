#!/bin/bash

# 
# create a quick overview of the files with statistical summary
# highlight any immediate issues
#


# 
# enviro stuff
#
set -u
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
IFS=$' \t\n'


# 
# do we have the tools we need here?
#
for tool in find grep du wc file realpath basename cut date; do
    if ! type -p "$tool" >/dev/null; then
        echo "Error: Required tool '$tool' not found." >&2; exit 1
    fi
done


# 
# check option flags for json file output or run silent
#
JSON_OUT=false; SILENT=false
while getopts "sj" opt; do
  case $opt in
    s) SILENT=true ;;
    j) JSON_OUT=true ;;
    *) echo "Usage: $0 [-s] [-j] [target_dir] (use -sj for silent JSON)" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# must have target directory
TARGET_DIR="${1:-.}"
[ ! -d "$TARGET_DIR" ] && { echo "Error: Directory not found." >&2; exit 1; }

DISPLAY_NAME=$(basename "$(realpath "$TARGET_DIR")")
JSON_FILE="${DISPLAY_NAME}_file-stats.json"

# maybe silent
log() { [ "$SILENT" = false ] && echo -e "$1"; }


# 
# make file sizes human-readable
#
format_bytes() {
    local bytes=$1
    if [[ $bytes -lt 1024 ]]; then echo "${bytes} B"
    elif [[ $bytes -lt 1048576 ]]; then echo "$(( (bytes + 512) / 1024 )) KB"
    else echo "$(( (bytes + 524288) / 1048576 )) MB"; fi
}


# 
# benchmark measures
#
FRESH_LIMIT=129600 
SCORE=100
CRIT_COUNT=0; WARN_COUNT=0; QUAL_COUNT=0
FINDINGS_JSON=""


add_finding() {
    local type="$1" sev="$2" msg="$3"
    local entry="{\"type\": \"$type\", \"severity\": \"$sev\", \"message\": \"$msg\"}"
    if [ -z "$FINDINGS_JSON" ]; then FINDINGS_JSON="$entry"; else FINDINGS_JSON="$FINDINGS_JSON, $entry"; fi
}

declare -A NAMES=(
    ["php"]="PHP" ["js"]="JavaScript" ["py"]="Python" ["rb"]="Ruby" 
    ["go"]="Go" ["c"]="C Source" ["cpp"]="C++ Source" ["sh"]="Shell Script"
    ["html"]="HTML" ["htm"]="HTML" ["shtml"]="HTML" ["xml"]="XML" ["svg"]="SVG Vector"
    ["css"]="CSS" ["scss"]="SCSS" ["less"]="LESS" ["md"]="Markdown" ["txt"]="Plain Text"
    ["json"]="JSON" ["yml"]="YAML" ["yaml"]="YAML" ["sql"]="SQL"
    ["no_ext"]="No Extension" ["minified"]="Minified Code"
    ["docs"]="Project Docs"
)
declare -A L B C
EXTENSIONS=()

log ""
log "Sentinel Code Stats for [$DISPLAY_NAME]"
log "------------------------------------------------------------"


#
# loop to check & count the things...
#
FILE_COUNT=0
while IFS='|' read -r f_size f_path; do
    [ -z "$f_path" ] && continue
    ((FILE_COUNT++))
    rel_f_path=$(realpath --relative-to="$TARGET_DIR" "$f_path")
    filename=$(basename "$f_path")
    fname_lower=$(echo "$filename" | tr '[:upper:]' '[:lower:]')
    ext="${filename##*.}"
    ext_lower=$(echo "$ext" | tr '[:upper:]' '[:lower:]')

    if [[ "$ext_lower" != "php" ]]; then
        if grep -q "<?php" "$f_path" 2>/dev/null; then
            ((CRIT_COUNT++))
            log "  [!! ALERT !!] Hidden PHP found in: ./$rel_f_path"
            add_finding "hidden_php" "CRITICAL" "./$rel_f_path"
        fi
        if grep -qE "eval\(|exec\(|password[[:space:]]*=|API_KEY|SECRET_KEY" "$f_path" 2>/dev/null; then
            ((WARN_COUNT++))
            add_finding "sensitive_string" "WARNING" "./$rel_f_path"
        fi
    fi

    if [[ "$ext_lower" =~ ^(sh|py|pl|rb)$ ]]; then
        if [[ ! "$(head -n 1 "$f_path" 2>/dev/null)" =~ ^#! ]]; then
            ((WARN_COUNT++))
            add_finding "missing_shebang" "WARNING" "./$rel_f_path"
        fi
    fi

    if [[ "$fname_lower" =~ ^(readme|security|license)\.(md|txt)$ ]]; then
        cat="docs"
    elif [[ "$fname_lower" == *.min.* ]]; then cat="minified"
    else [[ "$filename" == "$ext" ]] && ext_lower="no_ext"; cat="$ext_lower"; fi

    if [[ -z ${C[$cat]:-} ]]; then C[$cat]=0; L[$cat]=0; B[$cat]=0; EXTENSIONS+=("$cat"); fi
    ((C[$cat]++)); B[$cat]=$((B[$cat] + f_size))
    [[ "$cat" != "minified" ]] && L[$cat]=$((L[$cat] + $(wc -l < "$f_path" 2>/dev/null || echo 0)))

done < <(find "$TARGET_DIR" -mount -type f ! -path "*/vendor/*" ! -path "*/node_modules/*" ! -path "*/venv/*" ! -path "*/.venv/*" \( \
    -name "*.php" -o -name "*.js" -o -name "*.py" -o \
    -name "*.css" -o -name "*.scss" -o -name "*.html" -o \
    -name "*.md" -o -name "*.txt" -o \
    -iname "readme*" -o -iname "security*" -o -iname "license*" \
    \) -printf "%s|%p\n" 2>/dev/null)


# 
# report what we found
#
[ "$SILENT" = false ] && printf "%-25s %-10s %-12s %-12s\n" "File Type" "Files" "Lines" "Size"
GRAND_L=0; GRAND_B=0; EXT_JSON=""
for cat in $(printf "%s\n" "${EXTENSIONS[@]}" | sort); do
	[[ "$cat" != "minified" ]] && { GRAND_L=$((GRAND_L + L[$cat])); GRAND_B=$((GRAND_B + B[$cat])); }
    E_ENTRY="\"$cat\": {\"files\": ${C[$cat]}, \"lines\": ${L[$cat]:-0}, \"bytes\": ${B[$cat]}}"
    [ -z "$EXT_JSON" ] && EXT_JSON="$E_ENTRY" || EXT_JSON="$EXT_JSON, $E_ENTRY"
    if [ "$SILENT" = false ]; then
        label=".$cat"; [[ -n ${NAMES[$cat]:-} ]] && label=".$cat (${NAMES[$cat]})"
        [[ "$cat" == "docs" ]] && label="Project Documentation"
        [[ "$cat" == "minified" ]] && label="Minified (Omitted)"
        printf "%-25s %-10d %-12s %-12s\n" "   $label" "${C[$cat]}" "${L[$cat]:-N/A}" "$(format_bytes ${B[$cat]})"
    fi
done
log "------------------------------------------------------------"
[ "$SILENT" = false ] && printf "%-25s %-10s %-12d %-12s\n" "Grand Totals:" "$FILE_COUNT" "$GRAND_L" "$(format_bytes $GRAND_B)"
log "------------------------------------------------------------"

# 
# review external software sources
#
log "External Software Sources:"

GITIGNORE="$TARGET_DIR/.gitignore"; HAS_STALE=0
is_ignored() { [ -f "$GITIGNORE" ] && grep -qE "^/?$1(/|$)" "$GITIGNORE"; }


# --- .gitignore ---
if [ -f "$GITIGNORE" ]; then
    log "  [FOUND]     .gitignore configuration"
    if [ -f "$TARGET_DIR/.env" ]; then
        if grep -qE "^\.env($|[[:space:]])" "$GITIGNORE"; then log "    [SAFE]    .env is ignored"
        else log "    [CRITICAL] .env NOT in .gitignore!"; ((CRIT_COUNT++)); add_finding "gitignore_missing" "CRITICAL" ".env"; fi
    fi
else log "  [NOT FOUND] .gitignore"; fi


# --- Composer ---
if [ -d "$TARGET_DIR/vendor" ] || [ -f "$TARGET_DIR/composer.json" ]; then
    log "  [DETECTED] PHP (Composer)"
    is_ignored "vendor" || { log "    [CRITICAL] /vendor NOT in .gitignore!"; ((CRIT_COUNT++)); add_finding "gitignore_missing" "CRITICAL" "vendor/"; }
    if [ -f "$TARGET_DIR/composer.lock" ]; then
        if [ -n "$(find "$TARGET_DIR/composer.lock" -mmin +"$FRESH_LIMIT" -print)" ]; then
            log "    [STALE]   ./composer.lock (>90d)"; HAS_STALE=1; ((WARN_COUNT++)); add_finding "stale_lock" "WARNING" "composer.lock"
        else log "    [FRESH]   ./composer.lock is current."; fi
    else log "    [CRITICAL] composer.lock MISSING!"; ((CRIT_COUNT++)); add_finding "missing_lock" "CRITICAL" "composer.lock"; fi
else log "  [NOT FOUND] PHP (Composer) sources"; fi


# --- Node.js (npm) ---
if [ -d "$TARGET_DIR/node_modules" ] || [ -f "$TARGET_DIR/package.json" ]; then
    log "  [DETECTED] Node.js (npm)"
    is_ignored "node_modules" || { log "    [CRITICAL] /node_modules NOT in .gitignore!"; ((CRIT_COUNT++)); add_finding "gitignore_missing" "CRITICAL" "node_modules/"; }
    if [ -f "$TARGET_DIR/package-lock.json" ]; then
        if [ -n "$(find "$TARGET_DIR/package-lock.json" -mmin +"$FRESH_LIMIT" -print)" ]; then
            log "    [STALE]   ./package-lock.json (>90d)"; HAS_STALE=1; ((WARN_COUNT++)); add_finding "stale_lock" "WARNING" "package-lock.json"
        else log "    [FRESH]   ./package-lock.json is current."; fi
    else log "    [WARNING] package-lock.json MISSING!"; ((WARN_COUNT++)); add_finding "missing_lock" "WARNING" "package-lock.json"; fi
else log "  [NOT FOUND] Node.js (npm) sources"; fi


# --- Python ---
if [ -d "$TARGET_DIR/venv" ] || [ -d "$TARGET_DIR/.venv" ] || [ -f "$TARGET_DIR/requirements.txt" ]; then
    log "  [DETECTED] Python (PyPI)"
    if [ -d "$TARGET_DIR/venv" ] || [ -d "$TARGET_DIR/.venv" ]; then
        (is_ignored "venv" || is_ignored ".venv") || { log "    [CRITICAL] VirtualEnv NOT in .gitignore!"; ((CRIT_COUNT++)); add_finding "gitignore_missing" "CRITICAL" "venv/"; }
    fi
else log "  [NOT FOUND] Python (PyPI) sources"; fi

[ "$HAS_STALE" -eq 1 ] && log "  [NOTICE]  Stale lockfiles detected. Verify against SBOM."


# 
# Best-practice file check
#
log "Best-Practice md/txt Files:"
for doc in "README" "LICENSE" "SECURITY"; do
    d_path=$(find "$TARGET_DIR" -maxdepth 1 -type f \( -iname "$doc.md" -o -iname "$doc.txt" \) -printf "%p" -quit 2>/dev/null)
    if [[ -z "$d_path" ]]; then log "  [MISSING] $doc file"; ((QUAL_COUNT++)); add_finding "missing_doc" "QUALITY" "$doc";
    else
        d_size=$(stat -c%s "$d_path")
        d_name=$(basename "$d_path")
        if [[ $d_size -lt 300 ]]; then log "  [FOUND]   $d_name     ($d_size B) [!! TOO SMALL !!]"; ((QUAL_COUNT++)); add_finding "small_doc" "QUALITY" "$d_name";
        else log "  [FOUND]   $d_name ($(format_bytes $d_size)) [OK]"; fi
    fi
done


#
# Calculate a risk/health score
# removed this, it's too rudimentary
#
# SCORE=$(( 100 - (CRIT_COUNT * 15) - (WARN_COUNT * 5) - (QUAL_COUNT * 2) ))
[ $SCORE -lt 0 ] && SCORE=0
log "------------------------------------------------------------"
# log "Sentinel Health Score: $SCORE/100"


# 
# maybe write to json file
# 	purposely removed from json:  "health_score": $SCORE,
#
if [ "$JSON_OUT" = true ]; then
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  RAW_JSON="{\"project\":\"$DISPLAY_NAME\",\"timestamp\":\"$TIMESTAMP\",\"audit_type\":\"file_statistics\",\"metrics\":{\"total_files\":\"$FILE_COUNT\",\"total_lines\":\"$GRAND_L\",\"total_size_bytes\":\"$GRAND_B\",\"by_extension\":{$EXT_JSON}},\"counts\":{\"critical\":\"$CRIT_COUNT\",\"warnings\":\"$WARN_COUNT\",\"quality\":\"$QUAL_COUNT\"},\"findings\":[$FINDINGS_JSON]}"
echo $RAW_JSON
  # check if jq is in the path; if not, use python to pretty-print the json
  if type jq >/dev/null 2>&1; then
	  echo "$RAW_JSON" | jq . > "$JSON_FILE"
  else
	  echo "$RAW_JSON" | python3 -m json.tool > "$JSON_FILE"
  fi
fi

[ "$SILENT" = false ] && echo "JSON report generated: $JSON_FILE"
log ""

