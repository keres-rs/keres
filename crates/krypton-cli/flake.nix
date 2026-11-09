{
  description = "krypton-cli, a command-line interface for the Krypton";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        krypton-cli = pkgs.rustPlatform.buildRustPackage {
          pname = "krypton-cli";
          version = "0.4.0";

          src = pkgs.lib.cleanSource ./.;

          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "Command-line interface for the Krypton";
            homepage = "https://github.com/kryptonoss/krypton-cli";
            license = licenses.apache-2.0;
            mainProgram = "krypton";
            platforms = platforms.unix;
          };
        };
      in
      {
        packages.default = krypton-cli;

        apps.default = {
          type = "app";
          program = "${krypton-cli}/bin/krypton";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
          ];

          shellHook = ''
            echo "krypton-cli dev shell — rustc $(rustc --version)"
          '';
        };
      }
    );
}

