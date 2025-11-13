{
  # This flake, which I'm now calling The One Flake, describes the entire AspireBuild monorepo including all its tools.
  # The eventual goal is to make each tool its own flake, as well as each builder, with each tool and builder depending
  # on the AspireBuild flake.  However we're not there yet, so currently we manage everything through The One Flake.

  description = "AspireBuild";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-root.url = "github:srid/flake-root";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.flake-root.flakeModule ];

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
          lib,
          ...
        }:
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

          extensions = with pkgs.php84Extensions; [
            bcmath
            curl
            ffi
            filter
            gettext
            gmp
            intl
            mbstring
            pdo
            pdo_sqlite
            readline
            sockets
            sodium
            sqlite3

            # full list in /nix/store/nsybw5k5jcqwccbgslfq5psmqh3x3svs-php-with-extensions-8.4.14/lib/php.ini

            # future consideration
            #ctype
            #dom
            #fileinfo
            #iconv
            #mysqli
            #mysqlnd
            #openssl
            #pcntl
            #pdo_mysql
            #pdo_pgsql
            #pgsql
            #posix
            #session
            #simplexml
            #sockets
            #tokenizer
            #xmlreader
            #xmlwriter
            #zip
            #zlib
          ];

          zend-extensions = with pkgs.php84Extensions; [
            opcache
            xdebug
          ];

        in
        {
          devShells.default = pkgs.mkShell {
            inherit buildInputs;

            inputsFrom = [ config.flake-root.devShell ]; # sets $FLAKE_ROOT

            shellHook = ''
              export ASPIREBUILD=$FLAKE_ROOT
              export SELF_DIR=${self'.packages.default}
              export PHP_INI_SCAN_DIR=:${self'.packages.default}
            '';

            # in case $FLAKE_ROOT isn't available, this should also work
            # export ASPIREBUILD=$(${lib.getExe config.flake-root.package})
          };

          packages.default = pkgs.stdenv.mkDerivation {
            inherit buildInputs;

            name = "aspirebuild";

            src = ./.;

            php-ini =
              let
                get-extension-name = name: builtins.elemAt (builtins.split "-" name) 2; # "php-intl-8.4.13" -> "intl"
                ext-line = ext: "extension = ${ext}/lib/php/extensions/${get-extension-name ext.name}.so";
                zend-ext-line = ext: "zend_extension = ${ext}/lib/php/extensions/${get-extension-name ext.name}.so";
              in
              (map ext-line extensions) ++ (map zend-ext-line zend-extensions);

            buildPhase = ''
              mkdir -p $out

              cat << EOF > $out/php.ini
              ; PHP extensions for AspireBuild

              ${lib.concatStringsSep "\n" config.packages.default.php-ini}
              EOF
            '';

            installPhase = "true"; # if installPhase is absent or blank, it defaults to 'just' for some reason
          };

          # invoke with `nix fmt flake.nix`
          formatter = pkgs.nixfmt-rfc-style;
        };

      flake = {
        # system-agnostic flake attributes go here.  we don't have any yet.
      };
    };
}
