{
  inputs = {
#   nixpkgs.url = "github:nixos/nixpkgs";
#   nixpkgs.url = "github:nixos/nixpkgs/25.05";
#   nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    nixpkgs.url = "github:nixos/nixpkgs/a5e47a4bea3996a6511f1da3cf6ba92e71a95f04"; # 2025-10-30
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.php = pkgs.php;
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.curl
            pkgs.php
            pkgs.php84Packages.composer
          ];
        };
      }
    );
}
