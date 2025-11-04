
builder := `readlink -f $ASPIREBUILD/builder`

alias nix-shell := nix-develop

[group: 'nix']
nix-develop: nix-init
    cd {{builder}} && nix develop path:.

[group: 'nix']
nix-init:
    tools/builder/bin/init-builder-flake {{builder}}
