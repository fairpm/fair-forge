#!/bin/bash

# 
# set enviro
#
set -u
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
IFS=$' \t\n'

# default options
JSON_OUT=false; SILENT=false
while getopts "sj" opt; do
  case $opt in
    s) SILENT=true ;;
    j) JSON_OUT=true ;;
    *) echo "Usage: $0 [-s] [-j] [target_dir]" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# must specify a directory to recurse from
TARGET_DIR="${1:-.}"
[ ! -d "$TARGET_DIR" ] && { echo "Error: Directory not found." >&2; exit 1; }

# drop any path indicators from output (silence cues about the environment)
DISPLAY_NAME=$(basename "$(realpath "$TARGET_DIR")")
JSON_FILE="${DISPLAY_NAME}_integrity.json"

# report human-readable file sizes
log() { [ "$SILENT" = false ] && echo -e "$1"; }
format_bytes() {
    local bytes=$1
    if [[ $bytes -lt 1024 ]]; then echo "${bytes} B"
    elif [[ $bytes -lt 1048576 ]]; then echo "$(( (bytes + 512) / 1024 )) KB"
    else echo "$(( (bytes + 524288) / 1048576 )) MB"; fi
}

#
# set up json output
#
FINDINGS_JSON=""
add_finding() {
    local type="$1" sev="$2" f_path="$3" sz="$4" mime="$5"
    local entry="{\"type\": \"$type\", \"severity\": \"$sev\", \"file\": \"$f_path\", \"size_bytes\": $sz, \"mime\": \"$mime\"}"
    if [ -z "$FINDINGS_JSON" ]; then FINDINGS_JSON="$entry"; else FINDINGS_JSON="$FINDINGS_JSON, $entry"; fi
}

# init counters
MACOS_CRUFT=0; IMG_COUNT=0; IMG_SIZE=0; BIN_COUNT=0; BIN_SIZE=0; MISMATCH_COUNT=0; EXEC_COUNT=0; SUID_COUNT=0; DUAL_EXT_COUNT=0; HIDDEN_DIRS=0

log ""
log "Sentinel File Integrity Check: [$DISPLAY_NAME]"
log "------------------------------------------------------------"
log "SCAN FOUND:"
log "-----------"

# 
# Loop: look for things and count 'em up
# 
while IFS='|' read -r f_size f_mode f_path; do
    [ -z "$f_path" ] && continue
    rel_path=$(realpath --relative-to="$TARGET_DIR" "$f_path")
    full_display_path="$DISPLAY_NAME/$rel_path"
    filename=$(basename "$f_path")
    
    # did MACOS leave stupid footprints that weren't removed?
    if [[ "$f_path" == *"__MACOSX"* || "$filename" == ".DS_Store" ]]; then
        ((MACOS_CRUFT++)); add_finding "macos_metadata" "INFO" "$full_display_path" "$f_size" "inode/directory"
        continue
    fi

    #
    # validate file extensions
    #

    # get MIME types
    mime=$(file --mime-type -b "$f_path")
    ext_lower=$(echo "${f_path##*.}" | tr '[:upper:]' '[:lower:]')

    # 
    # this part will catch a lot of false positives like version-4.2.1.zip but we're looking
    # for stuff like file.jpg.php trying to hide executable code as a known file type
    is_dual=false; [[ "$(echo "$filename" | tr -cd '.' | wc -c)" -gt 1 ]] && is_dual=true
    # 
    # is this an executable?
    is_exec=false; [[ "$mime" == "application/x-executable" || "$mime" == "application/x-sharedlib" || "$mime" == "application/x-dosexec" ]] && is_exec=true

    # 
    # validate some common file types (could add to these)
    # refer:  https://mimetype.io/all-types
    #    and  https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types/Common_types
    #
    is_valid=true
    case "$ext_lower" in
        zip)      [[ "$mime" != "application/zip" ]] && is_valid=false ;;
        gz|tgz)   [[ "$mime" != "application/gzip" ]] && is_valid=false ;;  # may be incorrect if Windows/Mac uploaded
        gz|tgz)   [[ "$mime" == "application/x-gzip" ]] && is_valid=true ;; # because Windows/Mac set nonstandard MIME type
        pdf)      [[ "$mime" != "application/pdf" ]] && is_valid=false ;;
        png)      [[ "$mime" != "image/png" ]] && is_valid=false ;;
        jpg|jpeg) [[ "$mime" != "image/jpeg" ]] && is_valid=false ;;
        gif)      [[ "$mime" != "image/gif" ]] && is_valid=false ;;
        avif)     [[ "$mime" != "image/avif" ]] && is_valid=false ;;
        webp)     [[ "$mime" != "image/webp" ]] && is_valid=false ;;
        ico)      [[ "$mime" != "image/vnd.microsoft.icon" ]] && is_valid=false ;;
    esac

    # tally image stats
    if [ "$is_valid" = true ] && [ "$is_dual" = false ] && [[ "$mime" =~ ^image/ ]]; then
        ((IMG_COUNT++)); IMG_SIZE=$((IMG_SIZE + f_size)); continue
    fi

    # tally binaries
    ((BIN_COUNT++)); BIN_SIZE=$((BIN_SIZE + f_size))
    status="                 [OK]"; sev="WARNING"
    
    # spoof warnings
    if [ "$is_valid" = false ]; then status="[!! MIME MISMATCH !!]"; ((MISMATCH_COUNT++)); sev="CRITICAL"; 
    elif [ "$is_dual" = true ]; then status="[!! DUAL EXT !!]     "; ((DUAL_EXT_COUNT++)); 
    elif [[ "$f_mode" =~ ^[4-7]...$ ]]; then status="[!! SUID !!]          "; ((SUID_COUNT++)); sev="CRITICAL"; 
    elif [ "$is_exec" = true ]; then status="[!! EXECUTABLE !!]   "; ((EXEC_COUNT++)); fi


    # tally hidden directories, excl current/parent
    if [ -d "$f_path" ] && [[ "$filename" == .* ]] && [[ "$filename" != "." && "$filename" != ".." ]]; then
        ((HIDDEN_DIRS++))
        add_finding "hidden_directory" "WARNING" "$full_display_path" "0" "inode/directory"
        log "[!! HIDDEN DIR !!]          $full_display_path"
        continue
    fi

    add_finding "${status//[\[\]\! ]/_}" "$sev" "$full_display_path" "$f_size" "$mime"
    log "$status $(format_bytes $f_size) ($mime) $full_display_path"

done < <(find "$TARGET_DIR" -mount -type f,d ! \( -name "*.php" -o -name "*.js" -o -name "*.py" -o -name "*.css" -o -name "*.scss" -o -name "*.html" -o -name "*.md" -o -name "*.txt" -o -name "*.xml" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" -o -name "*.sql" \) -printf "%s|%a|%p\n" 2>/dev/null)
#
# thus ends the loop
# done with checks
#



# 
# report
#
log "------------------------------------------------------------"
log "File Ingegrity Summary"
log "----------------------"
log "FOUND:"
log "   Verified Web Images     : $IMG_COUNT files ($(format_bytes $IMG_SIZE))"
log "   MacOS Metadata Cruft    : $MACOS_CRUFT files"
log "   Other Binaries/Archives : $BIN_COUNT files ($(format_bytes $BIN_SIZE))"
log "   Hidden Directories      : $HIDDEN_DIRS"
log ""
log "CRITICAL WARNINGS:"
log "   Mime-Type Mismatches    : $MISMATCH_COUNT"
log "   Dual-Extension Files    : $DUAL_EXT_COUNT"
log "   SUID/SGID Files         : $SUID_COUNT"
log "   Binary Executables      : $EXEC_COUNT"
log "------------------------------------------------------------"
log ""


# 
# maybe write to json file
#
if [ "$JSON_OUT" = true ]; then
  RAW_JSON="{\"project\":\"$DISPLAY_NAME\",\"audit_type\":\"file_integrity\",\"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"summary\":{\"web_images\":{\"count\":$IMG_COUNT,\"size_bytes\":$IMG_SIZE},\"macos_cruft\":{\"count\":$MACOS_CRUFT},\"midden_directories\":{\"count\":$HIDDEN_DIRS},\"other_binaries\":{\"count\":$BIN_COUNT,\"size_bytes\":$BIN_SIZE},\"anomalies\":{\"mime_mismatches\":$MISMATCH_COUNT,\"dual_extensions\":$DUAL_EXT_COUNT,\"suid_files\":$SUID_COUNT,\"executables\":$EXEC_COUNT}},\"findings\":[$FINDINGS_JSON]}"
  # check if jq is available in the path, else use python to pretty-print the json
  if type jq >/dev/null 2>&1; then echo "$RAW_JSON" | jq . > "$JSON_FILE"
  else echo "$RAW_JSON" | python3 -m json.tool > "$JSON_FILE"; fi
fi


