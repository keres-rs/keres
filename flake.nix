{
  description = "Krypton: encrypted files, vaults, and CLI";

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
            echo "krypton dev shell — rustc $(rustc --version)"
          '';
        };

        # Build the workspace (library + CLI): `nix build`
        packages.krypton = pkgs.rustPlatform.buildRustPackage {
          pname = "krypton";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = with pkgs.lib; {
            description = "Encrypted files, vaults, and CLI";
            homepage = "https://github.com/KryptonOSS/krypton-core";
            license = licenses.apache2;
            mainProgram = "krypton";
            platforms = platforms.unix;
          };
        };
        packages.default = self.packages.${system}.krypton;

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
