# This file should be sourced, not run
#
# Sets PATH to include only directories under /nix
#
#   By no means does this script create a fully hermetic environment.
#   It's meant to help make builds more reproducible, but does not guarantee it.

__ORIG_PATH=$PATH

PATH=$(awk -v RS=: -v ORS=: '$0 ~ /^\/nix\/.*/' <<<"$PATH")
