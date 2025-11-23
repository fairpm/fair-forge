# This file should be sourced, not run

set -o errexit
set -o nounset
set -o pipefail

# These are not exported, but will be visible in the tool's script if they need them
__ORIG_PWD=$PWD
__HERE=$(dirname "$0")
__HERE=$(realpath -s "$__HERE")   # canonicalize only, don't resolve symlinks

function warn  { echo "$@" >&2; }
function die   { warn "$@"; exit 1; }

# This is set in flake.nix, so this will only be blank if not in a nix environment.
[[ -n $FAIR_FORGE ]] || die "FAIR_FORGE environment variable not set.  Please set it to the absolute path of a FAIR Forge git repo."

# We bail out early if our working directory contains spaces, rather than risk stepping on this mine later.
# We make reasonable efforts to quote bash arguments, but 'bash' and 'reasonable' do not belong in the same sentence.
[[ "$FAIR_FORGE" =~ [[:space:]] ]] && die "Refusing to deal with FAIR_FORGE directory containing whitespace.  Aborted."

cd "$FAIR_FORGE"

# Run all prelude files under the current tool's lib (usually symlinked to tools/_common/lib)
preludes=$(
    shopt -s nullglob
    echo "$__HERE"/../lib/bash/prelude.d/*.bash "$__HERE"/../local/lib/bash/prelude.d/*.bash
);

for file in $preludes; do
    # shellcheck source=/dev/null
    [[ -f $file ]] && source "$file"
done
