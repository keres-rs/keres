{
  description = "Krypton";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Development shell: enter with `nix develop`
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
          ];

          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";

          shellHook = ''
            echo "krypton dev shell — rustc $(rustc --version)"
          '';
        };

        # Build the library crate: `nix build`
        packages.krypton = pkgs.rustPlatform.buildRustPackage {
          pname = "krypton";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };

        checks.krypton-tests = pkgs.rustPlatform.buildRustPackage {
          pname = "krypton-tests";
          version = "dev";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = true;
          buildPhase = "";
          installPhase = "mkdir -p $out";
        };
      }
    );
}
