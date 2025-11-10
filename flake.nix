{
  # a work in progress.  only devshell is supported for now.

  description = "AspireBuild";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ flake-parts, self, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        # To import an internal flake module: ./other.nix
        # To import an external flake module:
        #   1. Add foo to inputs
        #   2. Add foo as a parameter to the outputs function
        #   3. Add here: foo.flakeModule
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      # most of the flake should go in here
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        # Per-system attributes can be defined here. The self' and inputs'
        # module parameters provide easy access to attributes of the same
        # system.
        let
          buildInputs = with pkgs; [
            bashInteractive
            coreutils
            curl
            git
            gnutar
            jq
            just
            lrzip
            perl
            php
            php84Packages.composer
            subversion
            sqlite
            systemfd
            tzdata
            watchexec
            zip
            zstd
          ];
        in
        {
          devShells.default = pkgs.mkShell {
            inherit buildInputs;
          };

          # invoke with `nix fmt flake.nix`
          formatter = pkgs.nixfmt-rfc-style;
        };

      flake = {
        # system-agnostic flake attributes go here.  we don't have any yet.
      };
    };
}
