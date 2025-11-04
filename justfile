
builder := `readlink -f $ASPIREBUILD/builder`

nix-develop: nix-init
    cd {{builder}} && nix develop

nix-init:
    tools/builder/bin/init-builder-flake {{builder}}
