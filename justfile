# AspireBuild justfile

builder := if env('ASPIREBUILD', '')  != '' {
    `readlink -f $ASPIREBUILD/builder`
} else {
    justfile_directory()
}

#### General targets

init: php-init

php-init:
    cd {{builder}} && composer install

#### Nix targets (only in builders, not allowed in root)

alias nix-shell := nix-develop

[group: 'nix']
nix-develop: nix-init
    cd {{builder}} && nix develop path:.

[group: 'nix']
nix-init: _require-builder
    tools/builder/bin/init-builder-flake {{builder}}


#### Utility targets

@_require-builder:
    if ! [[ -d {{builder}}/.aspirebuild/builder ]]; then \
        echo '{{style("error")}}This command can only be run in a builder, not the AspireBuild root{{NORMAL}}' >&2; \
        exit 1; \
    fi

