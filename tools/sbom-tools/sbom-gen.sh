#!/bin/bash

# configs
# exit on error NOT set globally: errors handled manually for logging purposes

# trap for cleanup, whether the script exits gracefully or not
#
cleanup() {
    # Quietly remove any temp files created by this script instance
    rm -f .tmp_*_"${CLEAN_NAME}".json 2>/dev/null
}
trap cleanup EXIT INT TERM

# dependency check
for cmd in syft jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "❌ Error: $cmd is not installed."
        exit 1
    fi
done


# validate input
#
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target>"
    echo "Tip: You can pass extra Syft flags via environment variables."
    echo "Example: SYFT_ARGS='--scope all-layers' $0 alpine:latest"
    exit 1
fi


# confirm write permission
if [ ! -w "." ]; then
    echo "❌ Error: Current directory is not writable. Cannot save reports."
    exit 1
fi

# sanitize path & name
#
TARGET_INPUT="$1"
# path: remove trailing slash, get base name
TARGET_BASE=$(basename "$(echo "$TARGET_INPUT" | sed 's:/*$::')")
# sanitize: remove extension & replace non-alphanumeric characters with underscores
CLEAN_NAME="${TARGET_BASE%.*}"
CLEAN_NAME=$(echo "$CLEAN_NAME" | sed 's/[^a-zA-Z0-9_-]/_/g')
# fallback for empty names
if [ -z "$CLEAN_NAME" ] || [ "$CLEAN_NAME" == "_" ]; then
    CLEAN_NAME="scan_target_$(date +%s)"
fi

# set sbom file names for output
SPDX_NAME="sbom-${CLEAN_NAME}.spdx.json"
CYCLONEDX_NAME="sbom-${CLEAN_NAME}.cyclonedx.json"


# 60s timeout to prevent hangs
# hide absolute path from outputs: use '.' as scan target and cd into the directory if needed,
#	or rely on Syft's relative pathing if configured. easiest fix: pass a relative path to Syft.
# get relative path if possible, or base name
#
REL_TARGET="./$(basename "$TARGET_INPUT")"

# cd to target directory to force relative scanning
DIR_NAME=$(dirname "$TARGET_INPUT")
cd "$DIR_NAME" || exit 1


# sbom generator function
#
generate_sbom() {
    local format="$1"        
    local output_file="$2"   
    local tmp_file=".tmp_${format}_${CLEAN_NAME}.json"

    echo "🔍 Scanning: [$TARGET_BASE] for format: [$format]..."

    # execution:
    # 	- include $SYFT_ARGS to allow user flexibility (e.g. platform flags)
    # 	- capture STDERR to $SYFT_LOG for debugging if it fails
    # 	- use -q to suppress Syft's internal warnings
    SYFT_LOG=$(timeout 60s syft scan "$REL_TARGET" $SYFT_ARGS -q -o "$format" 2>&1 > "$tmp_file")
    local syft_status=$?
    
    # handle timeout exit code (124)
    if [ "$syft_status" -eq 124 ]; then
        echo "❌ Error: Syft timed out after 60 seconds."
        return 1
    fi

    # success?
    if [ "$syft_status" -ne 0 ]; then
        echo "❌ Syft Failed (Exit $syft_status): $SYFT_LOG"
        return 1
    fi

    # valid json?
    if [ ! -s "$tmp_file" ]; then
        echo "❌ Error: Syft produced an empty file."
        return 1
    fi

    # process with jq; use secondary temp file for jq output
    #
    if jq --arg name "$CLEAN_NAME" 'walk(if type == "object" and has("filePath") then .filePath = $name else . end)' "$tmp_file" > "${tmp_file}.clean" 2>/dev/null; then
        mv "${tmp_file}.clean" "$output_file"
        echo "✅ Created: $output_file"
    else
        # if jq walk fails, save the raw scan so we still have the data at least
        echo "⚠️  Warning: JQ processing failed (possible version mismatch). Saving raw SBOM."
        mv "$tmp_file" "$output_file"
    fi
    
    # rm tmp_file not needed, already handled by trap on exit
}


# do the things, giving start/end status messages
#
echo "--- Starting Scan for: $CLEAN_NAME ---"

generate_sbom "spdx-json" "$SPDX_NAME"
generate_sbom "cyclonedx-json" "$CYCLONEDX_NAME"

echo "--- Process Complete ---"

