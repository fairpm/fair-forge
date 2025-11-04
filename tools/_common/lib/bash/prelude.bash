# This file should be sourced, not run

set -o errexit
set -o nounset
set -o pipefail

# These are not exported, but will be visible in the tool if they wish to do so.
__ORIG_PWD=$PWD
__HERE=$(dirname "$0")
__HERE=$(realpath "$__HERE")

function warn  { echo "$@" >&2; }
function die   { warn "$@"; exit 1; }

function _find_aspirebuild_root {
    local dir
    dir=$(dirname "$0")
    dir=$(realpath "$dir")
    while [[ -n $dir ]]; do
        if [[ -d "$dir/tools/_common" ]]; then
            echo "$dir"
            return
        fi
        newdir=$(dirname "$dir")
        [[ $newdir = "$dir" ]] && break
        dir=$newdir
    done
    die "Could not find aspirebuild root in any parent directory of $PWD"
}

# spawned builders will set this to the new builder's .aspirebuild dir
export ASPIREBUILD=${ASPIREBUILD:-$(_find_aspirebuild_root)}
export ASPIREBUILD_DEPTH=$(( ${ASPIREBUILD_DEPTH:--1} + 1 )) # base is level 0, meaning builders will be at level 1

[[ $ASPIREBUILD_DEPTH -lt ${ASPIREBUILD_RECURSION_LIMIT:-10} ]] || die "Maximum aspirebuild recursion depth reached.  Aborted."

# We bail out early if our cwd contains spaces, rather than risk stepping on this mine later.
# We make reasonable efforts to quote bash arguments, but 'bash' and 'reasonable' do not belong in the same sentence.
[[ "$ASPIREBUILD" =~ [[:space:]] ]] && die "Refusing to deal with working directory containing whitespace.  Aborted."

cd "$ASPIREBUILD"

for file in $(shopt -s nullglob; echo "$__HERE/../lib/bash/prelude.d"/*.bash); do
    # shellcheck source=/dev/null
    source "$file"
done
