#!/usr/bin/env bash

# enviro
#
set -euo pipefail

# init configs
#
TARGET_DIR="."
COMPARE=true
VERBOSE=false
JSON_OUTPUT=false
FILTER_TYPE=""
MAX_DEPTH=6		# default 6 to catch nested lockfiles
PARSE_TIMEOUT="30s"	# parsing timeout for single file prevents DoS
PRUNE_DIRS="node_modules|.git|.venv|target|dist" # ignore these directories
RESULTS_JSON=$(mktemp)


# function: check dependencies
#
check_deps() {
    for cmd in syft jq sort awk timeout; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "❌ Error: Required command '$cmd' not found." >&2
            exit 1
        fi
    done
}


# function: usage instructions
#
usage() {
    echo "Usage: $0 [directory] [options]"
    echo "Options:"
    echo "  -f, --filter TYPE     Only include packages of a certain type (npm, binary, etc.)"
    echo "  -d, --depth INT       Search depth (default: 6)"
    echo "  -n, --no-diff         Find SBOMs but do not perform comparison"
    echo "  -v, --verbose         List specific package/version differences"
    echo "  -j, --json            Output results in pretty-printed JSON"
    exit 1
}


# loop
#
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--filter)  FILTER_TYPE="$2"; shift 2 ;;
        -d|--depth)   MAX_DEPTH="$2"; shift 2 ;;
        -n|--no-diff) COMPARE=false; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -j|--json)    JSON_OUTPUT=true; shift ;;
        -h|--help)    usage ;;
        *) TARGET_DIR="$1"; shift ;;
    esac
done


check_deps

# drop trailing slash
TARGET_DIR="${TARGET_DIR%/}"


# set temp dir
# add cleanup trap
# init json structure
#
TMP_DIR=$(mktemp -d -t sbom-analysis-XXXXXX)
trap 'rm -rf "$TMP_DIR" "$RESULTS_JSON"' EXIT
echo '{"main": [], "vendor": [], "meta": {"baseline": null, "baseline_dev_count": 0}}' > "$RESULTS_JSON"


# step 1: discovery
#
if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo "🔍 Step 1: Discovering SBOMs in '$TARGET_DIR' (Depth: $MAX_DEPTH)..."
fi

VALID_SBOMS=()
HAS_LOCKFILE=false


# smart-sort function for found files to prioritize minimum-depth & explicit SBOM filenames
#
sort_by_depth_and_priority() {
    awk -v RS='\0' -v ORS='\0' '{
        # calculate depth by number of slashes in the path
        depth = gsub("/", "/"); 
        # for filename implying an explicit SBOM (spdx, cyclonedx, bom): -0.5 from the depth score
        # to ensure "./sbom.spdx.json" (score -0.5) beats "./package-lock.json" (score 0).
        if ($0 ~ /[bB][oO][mM]|[sS][pP][dD][xX]|[cC][yY][cC][lL][oO][nN][eE]/) {
            depth -= 0.5;
        }
        # print: score <TAB> filename
        print depth "\t" $0
    }' |
    # sort our list numerically by score, low score = high priority
    sort -z -n -k1 |
    # remove scores column to return a clean filename list
    cut -z -f2-
}


# do the find -> sort -> read steps
# find -o = OR: only find it once, no duplicates
#
while IFS= read -r -d '' file; do
    VALID_SBOMS+=("$file")
    [[ "$(basename "$file")" == "package-lock.json" ]] && HAS_LOCKFILE=true
    
    REL_PATH="${file#$TARGET_DIR/}"
    [[ "$JSON_OUTPUT" == "false" ]] && echo "  Found: $REL_PATH"
    
done < <(find "$TARGET_DIR" -maxdepth "$MAX_DEPTH" \
    -type d -regextype posix-extended -regex ".*($PRUNE_DIRS)$" -prune \
    -o -type f \( \
        -iname "*bom*" \
        -o -iname "*spdx*" \
        -o -iname "*cyclonedx*" \
        -o -name "*.json" \
    \) -print0 \
    | sort_by_depth_and_priority)


# what, no SBOMs?
#
if [[ ${#VALID_SBOMS[@]} -eq 0 ]]; then
    echo "❌ No potential SBOMs found at depth $MAX_DEPTH." >&2
    exit 0
fi

# in case package-lock.json is missing from results but is nested deeper
#
if [[ "$HAS_LOCKFILE" == "false" ]]; then
    if find "$TARGET_DIR" -maxdepth "$((MAX_DEPTH + 4))" -name "package-lock.json" -print -quit | grep -q .; then
        echo "⚠️  Hint: A 'package-lock.json' exists deeper than level $MAX_DEPTH." >&2
        echo "          Run with '-d $((MAX_DEPTH + 4))' to include it." >&2
    fi
fi


# step 2, process results from discovery step
#
if [[ "$COMPARE" == "true" && ${#VALID_SBOMS[@]} -gt 1 ]]; then
    
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo -e "\n⚙️  Step 2: Analyzing and Comparing..."
    fi

    BASELINE_FILE="${VALID_SBOMS[0]}"
    BASELINE_REL="${BASELINE_FILE#$TARGET_DIR/}"

    # parse SBOM data with Syft
    #
    parse_sbom() {
        local input_file="$1"
        local output_list="$2"
        local output_dev_count="$3"
        
        local filter=".artifacts[]"
        [[ -n "$FILTER_TYPE" ]] && filter+=" | select(.type == \"$FILTER_TYPE\")"
        
        local raw_json="$TMP_DIR/raw.json"
        
	# use timeout for anti-DoS
        if ! timeout "$PARSE_TIMEOUT" syft "$input_file" -o json > "$raw_json" 2>/dev/null; then
            echo "⚠️  Failed to parse $input_file (Syft error or timeout)" >&2
            touch "$output_list"
            echo "0" > "$output_dev_count"
            return 1
        fi

        # count dev dependencies if found
        # 
        jq '[.artifacts[] | select( 
            ((.metadata // {}) | (.dev == true or .dev == "true")) 
            or 
            ((.properties // [])[] | select(.name == "dev")) 
        )] | length' "$raw_json" > "$output_dev_count"

        # extract list of non-dev packages
        # 
        jq -r "$filter | select( 
            ((.metadata // {}) | (.dev == true or .dev == \"true\")) 
            or 
            ((.properties // [])[] | select(.name == \"dev\")) 
            | not 
        ) | \"\(.name)\t\(.version)\"" "$raw_json" | sort -u > "$output_list"
    }

    # baseline for comparisons
    #
    BASELINE_LIST="$TMP_DIR/baseline.list"
    BASELINE_DEV_FILE="$TMP_DIR/baseline_devs"
    
    parse_sbom "$BASELINE_FILE" "$BASELINE_LIST" "$BASELINE_DEV_FILE"
    
    # baseline dev count
    BASE_DEV_COUNT=$(cat "$BASELINE_DEV_FILE")
    BASE_DEV_COUNT=${BASE_DEV_COUNT:-0}

    # update json with baseline info (relative path)
    jq --arg b "$BASELINE_REL" --argjson dc "$BASE_DEV_COUNT" \
       '.meta.baseline = $b | .meta.baseline_dev_count = $dc' "$RESULTS_JSON" > "${RESULTS_JSON}.tmp" && mv "${RESULTS_JSON}.tmp" "$RESULTS_JSON"


    # compare SBOMs if multiple
    #
    for (( i=1; i<${#VALID_SBOMS[@]}; i++ )); do
        COMPARE_FILE="${VALID_SBOMS[$i]}"
        COMPARE_REL="${COMPARE_FILE#$TARGET_DIR/}"
        COMPARE_LIST="$TMP_DIR/comp.list"
        DEV_COUNT_FILE="$TMP_DIR/dev_count"

        if [[ "$JSON_OUTPUT" == "false" ]]; then
            echo "  Comparing: $BASELINE_REL ↔ $COMPARE_REL..."
        fi

        parse_sbom "$COMPARE_FILE" "$COMPARE_LIST" "$DEV_COUNT_FILE"
        DEV_COUNT=$(cat "$DEV_COUNT_FILE")
        DEV_COUNT=${DEV_COUNT:-0}


        # robust comparison using awk
	#
        awk -F'\t' '
            FNR==NR { base[$1]=$2; next }
            {
                if ($1 in base) {
                    if (base[$1] != $2) {
                        print "DIFF|" $1 "|" base[$1] " ➔ " $2
                    }
                    delete base[$1]
                } else {
                    print "ADDED|" $1 "|" $2
                }
            }
            END {
                for (pkg in base) {
                    print "REMOVED|" pkg "|" base[pkg]
                }
            }
        ' "$BASELINE_LIST" "$COMPARE_LIST" > "$TMP_DIR/diff_results"


        # tally results: grep -c with || true for safety
	#
        A_COUNT=$(grep -c "^ADDED" "$TMP_DIR/diff_results" || true)
        R_COUNT=$(grep -c "^REMOVED" "$TMP_DIR/diff_results" || true)
        V_COUNT=$(grep -c "^DIFF" "$TMP_DIR/diff_results" || true)

        # set up the json entry
	#
        SECTION="main"; [[ "$COMPARE_FILE" == *"/vendor/"* ]] && SECTION="vendor"

        jq -n \
           --arg target "$COMPARE_REL" \
           --argjson added "$A_COUNT" \
           --argjson removed "$R_COUNT" \
           --argjson changed "$V_COUNT" \
           --argjson dev_skipped "$DEV_COUNT" \
           '{target: $target, added_cnt: $added, removed_cnt: $removed, version_shifts_cnt: $changed, dev_skipped: $dev_skipped, details: {added: [], removed: [], version_shifts: []}}' \
           > "$TMP_DIR/entry.json"

        # if --verbose set, populate detail arrays
	#
        if [[ "$VERBOSE" == "true" ]]; then
            jq --slurpfile entry "$TMP_DIR/entry.json" -n \
               --argfile diffs "$TMP_DIR/diff_results" \
               '$entry[0] | 
               .details.added = ($diffs | split("\n") | map(select(test("^ADDED")) | split("|")[1])) |
               .details.removed = ($diffs | split("\n") | map(select(test("^REMOVED")) | split("|")[1])) |
               .details.version_shifts = ($diffs | split("\n") | map(select(test("^DIFF")) | split("|") | "\(.[1]): \(.[2])"))' \
               > "$TMP_DIR/entry_full.json" && mv "$TMP_DIR/entry_full.json" "$TMP_DIR/entry.json"
        fi

        # append output to results
	#
        jq --arg section "$SECTION" --slurpfile entry "$TMP_DIR/entry.json" \
           '.[$section] += [$entry[0]]' "$RESULTS_JSON" > "${RESULTS_JSON}.tmp" && mv "${RESULTS_JSON}.tmp" "$RESULTS_JSON"
    done
fi

# step 3: output all the things
#
if [[ "$JSON_OUTPUT" == "true" ]]; then
    jq . "$RESULTS_JSON"
else
    echo -e "\n📊 Final Variance Report"
    
    BASELINE=$(jq -r .meta.baseline "$RESULTS_JSON")
    BASE_DEV=$(jq -r .meta.baseline_dev_count "$RESULTS_JSON")
    echo "------------------------------------------------------"
    echo "📌 Baseline: $BASELINE"
    if [[ "$BASE_DEV" -gt 0 ]]; then
         echo "   ℹ️  Omitted $BASE_DEV development packages from baseline source."
    else
         echo "   ℹ️  No development packages detected in baseline."
    fi
    echo "------------------------------------------------------"
    
    for section in "main" "vendor"; do
        COUNT=$(jq ".[\"$section\"] | length" "$RESULTS_JSON")
        if [[ "$COUNT" -gt 0 ]]; then
            echo -e "\n[ ${section^^} COMPARISONS ]"
            
            jq -c ".[\"$section\"][]" "$RESULTS_JSON" | while read -r row; do
                T=$(echo "$row" | jq -r .target)
                D=$(echo "$row" | jq -r .dev_skipped)
                echo "Target: $T"
                
                # notice: omitted dev packages
                if [[ "$D" -gt 0 ]]; then
                    echo "  ℹ️  Omitted $D development packages from comparison."
                fi

                echo "  Variances: [+] $(echo "$row" | jq .added_cnt) new, [-] $(echo "$row" | jq .removed_cnt) removed, [Δ] $(echo "$row" | jq .version_shifts_cnt) version changes"
                
                if [[ "$VERBOSE" == "true" ]]; then
                    echo "$row" | jq -r '.details.version_shifts[]' 2>/dev/null | sed 's/^/      [Δ] /'
                    echo "$row" | jq -r '.details.added[]' 2>/dev/null | sed 's/^/      [+] /'
                    echo "$row" | jq -r '.details.removed[]' 2>/dev/null | sed 's/^/      [-] /'
                fi
                echo ""
            done
        fi
    done
fi

