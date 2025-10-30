# aspirebuild

## Requirements

* Nix, with flakes support.  I _highly_ recommend the [Determinate Systems installer](https://docs.determinate.systems/)
* Recommended: `direnv` (should be available on apt/brew/dnf/pacman/etc)

## Quick Start

```
echo "use flake" > .envrc && direnv allow   # if using direnv
nix develop
```
