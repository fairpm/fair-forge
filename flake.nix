{
  inputs = {
#   nixpkgs.url = "github:nixos/nixpkgs";
#   nixpkgs.url = "github:nixos/nixpkgs/25.05";
#   nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    nixpkgs.url = "github:nixos/nixpkgs/a5e47a4bea3996a6511f1da3cf6ba92e71a95f04"; # (2025-10-30)
    flake-utils.url = "github:numtide/flake-utils/11707dc2f618dd54ca8739b309ec4fc024de578b"; # (2024-11-13)
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShell = with pkgs; mkShell {
          buildInputs = [
            bash
            coreutils
            curl
            gnutar
            jq
            just
            lrzip
            perl
            php
            php84Packages.composer
            subversion
            sqlite
            tzdata
            zip
            zstd
          ];
        };

        # WIP docker support
        # https://community.flake.parts/haskell-flake/docker
        packages = {
          dockerImage = pkgs.dockerTools.buildImage {
            name = "aspirebuild";
            tag = builtins.substring 0 9 (self.rev or "dev"); # tag with git revision, or 'dev' if dirty
            config = {
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                "SYSTEM_CERTIFICATE_PATH=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
        };
      }
  );
}
