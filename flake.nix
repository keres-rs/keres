{
  description = "Keres: encrypted files, vaults, and CLI";

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
        version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
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
            mdbook
          ];

          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";

          shellHook = ''
            echo "keres dev shell — rustc $(rustc --version)"
          '';
        };

        # Build the workspace (library + CLI): `nix build`
        packages.keres = pkgs.rustPlatform.buildRustPackage {
          pname = "keres";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = with pkgs.lib; {
            description = "Encrypted files, vaults, and CLI";
            homepage = "https://github.com/Keres-rs/keres";
            license = licenses.apache2;
            mainProgram = "keres";
            platforms = platforms.unix;
          };
        };
        packages.default = self.packages.${system}.keres;

        checks.keres-tests = pkgs.rustPlatform.buildRustPackage {
          pname = "keres-tests";
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
