#!/bin/bash

##
# recursively check files & directories for any world-writeable permissions
# optionally remove the offending write permission with --fix flag
# script output should reveal nothing about the current environment (e.g., absolute path)
# script should resist most direct attacks (e.g. don't chmod a symlink pointing /somewhere)
##

# enviro: exit on undefined vars, maybe prevent unintended consequences
# sanitize environment (ish); should work in most current shells
set -u
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
IFS=$' \t\n'

# init vars
FIXIT=false
TARGET_DIR=""
WRITABLE_FILES=0
WRITABLE_DIRS=0

#
# parse what we're given
#
for arg in "$@"; do
    case "$arg" in
        --fix) FIXIT=true ;;
        -*)    echo "Unknown option: $arg" >&2; exit 1 ;;
        *)     TARGET_DIR="$arg" ;;
    esac
done

[ "$FIXIT" = true ] && FIXFLAG="Fixed" || FIXFLAG="Flagged"

TARGET_DIR="${TARGET_DIR:-.}"

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory '$TARGET_DIR' not found." >&2
    exit 1
fi

# echo "Scanning: $TARGET_DIR"
echo ""
[ "$FIXIT" = true ] && echo "File permission fixes for $TARGET_DIR" || echo "File permission scan for $TARGET_DIR"
echo "------------------------------------------------------------"

# 
# what's writeable that shouldn't be? tally what we find in an array
# avoid tmp files & pipe-related exit code issues
#
mapfile -d '' WRITABLE_ITEMS < <(find "$TARGET_DIR" -perm -002 -print0 2>/dev/null)

# count 'em all up for future reference
ALL_TOTAL_FILES=$(find "$TARGET_DIR" -type f 2>/dev/null | wc -l)
ALL_TOTAL_DIRS=$(find "$TARGET_DIR" -type d 2>/dev/null | wc -l)

# 
# loop through files ("everything is a file")
#
for item in "${WRITABLE_ITEMS[@]}"; do
    [ -z "$item" ] && continue
    
    # make sure item actually exists (handle race conditions)
    [ ! -e "$item" ] && [ ! -L "$item" ] && continue

    # get octal perms
    FOUND_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
    
    if [ -d "$item" ]; then
        ((WRITABLE_DIRS++))
    else
        ((WRITABLE_FILES++))
    fi

    # 
    # maybe fix permissions, change 1 bit
    #
    if [ "$FIXIT" = true ]; then
        if [ -L "$item" ]; then
            echo "[SKIPPED-LINK] $FOUND_PERM : $item"
        else
            if chmod o-w "$item" 2>/dev/null; then
                FIXED_PERM=$(stat -c "%a" "$item" 2>/dev/null || echo "???")
                echo "[FIXED] $FOUND_PERM -> $FIXED_PERM : $item"
            else
                echo "[FAILED] $FOUND_PERM : $item"
            fi
        fi
    else
        echo "[FOUND] $FOUND_PERM : $item"
    fi
done

# 
# summary report
#
PASSED_FILES=$((ALL_TOTAL_FILES - WRITABLE_FILES))
PASSED_DIRS=$((ALL_TOTAL_DIRS - WRITABLE_DIRS))

echo "------------------------------------------------------------"
echo "$ALL_TOTAL_DIRS Directories Checked | $PASSED_DIRS Passed | $WRITABLE_DIRS $FIXFLAG"
echo "$ALL_TOTAL_FILES Files Checked | $PASSED_FILES Passed | $WRITABLE_FILES $FIXFLAG"
[ "$FIXIT" = true ] && echo "Done. World-writeable permissions have been removed." || echo "Done, with no changes made. Use --fix to correct world-writeable permissions."
echo ""

