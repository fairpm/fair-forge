#!/bin/bash

# configs

# trap exit signal to ensure cleanup
cleanup() {
    rm -f .tmp_vuln_*.json 2>/dev/null
}
trap cleanup EXIT INT TERM

# deps check
#
for cmd in grype jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "❌ Error: $cmd is not installed."
        exit 1
    fi
done

# validate input
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_sbom_file>"
    exit 1
fi

INPUT_SBOM="$1"

if [ ! -f "$INPUT_SBOM" ]; then
    echo "❌ Error: File '$INPUT_SBOM' not found."
    exit 1
fi

# confirm write permissions
if [ ! -w "." ]; then
    echo "❌ Error: Current directory is not writable. Cannot save reports."
    exit 1
fi

# filename logic: sanitize non-alphanumeric, set output filename
BASENAME=$(basename "$INPUT_SBOM")
CLEAN_BASE=$(echo "${BASENAME#sbom-}" | sed 's/[^a-zA-Z0-9._-]/_/g')
OUTPUT_FILE="sbom-vulns-${CLEAN_BASE}"

# step 1, run grype.
#
TMP_VULN_FILE=".tmp_vuln_scan_$(date +%s).json"
echo "🔍 Scanning '$BASENAME' for vulnerabilities..."

# give grype a longer timeout for db updates
GRYPE_LOG=$(timeout 120s grype "$INPUT_SBOM" -o json > "$TMP_VULN_FILE" 2>&1)
GRYPE_STATUS=$?

if [ "$GRYPE_STATUS" -eq 124 ]; then
    echo "❌ Error: Grype scan timed out (database update took too long?)."
    exit 1
elif [ "$GRYPE_STATUS" -ne 0 ]; then
    echo "❌ Error: Grype scan failed (Exit Code $GRYPE_STATUS)."
    echo "--- Grype Log ---"
    echo "$GRYPE_LOG"
    exit 1
fi

# empty output check
if [ ! -s "$TMP_VULN_FILE" ]; then
    echo "❌ Error: Grype produced an empty JSON file."
    exit 1
fi


# step 2: sanitize & merge
#
echo "⚙️  Sanitizing and merging data..."

# using temp file to prevent partial writes on failure
TMP_FINAL=".tmp_final_$(date +%s).json"

jq --slurpfile v "$TMP_VULN_FILE" '
    ($v[0] | walk(
        if type == "string" and contains(".cache/grype") then 
            "[REDACTED_CACHE_PATH]" 
        else 
            . 
        end
    )) as $clean_vulns
    | 
    . + {vulnerabilities: $clean_vulns}
' "$INPUT_SBOM" > "$TMP_FINAL"

JQ_STATUS=$?

if [ $JQ_STATUS -eq 0 ] && [ -s "$TMP_FINAL" ]; then
    mv "$TMP_FINAL" "$OUTPUT_FILE"
    echo "✅ Success! Saved to: $OUTPUT_FILE"

    # Summary Count
    COUNT=$(jq '.matches | length' "$TMP_VULN_FILE")
    echo "📊 Summary: Found $COUNT vulnerabilities."
else
    echo "❌ Error: Failed to merge or sanitize JSON data."
    echo "🔍 Check input SBOM validity."
    rm -f "$TMP_FINAL"
    exit 1
fi


