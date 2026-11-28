{
  description = "Keres Desktop dev env flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;

        # Iced (winit) build/runtime libraries.
        # wgpu (GPU) is the primary renderer, with tiny-skia as the fallback;
        # gtk3/dbus are used by rfd file dialogs (portal fallback).
        libraries = with pkgs; [
          openssl
          fontconfig
          freetype
          libGL
          wayland
          libxkbcommon
          xkeyboard-config
          libx11
          libxcursor
          libxrandr
          libxi
          vulkan-loader
          xwayland
          dbus
          gtk3
          glib
          pango
          cairo
          gdk-pixbuf
          atk
        ];

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.pkg-config
            pkgs.clang
            pkgs.cmake
          ] ++ libraries;

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath libraries;

          # winit/libxkbcommon needs the XKB data files, not just the library.
          XKB_CONFIG_ROOT = "${pkgs.xkeyboard-config}/share/X11/xkb";

          # Prefer the Vulkan backend; the GLES/EGL path panics on some setups
          # (e.g. incomplete EGL in this environment). wgpu falls back to the
          # tiny-skia software renderer when Vulkan is unavailable.
          WGPU_BACKEND = "vulkan";

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          shellHook = ''
            echo "Keres Desktop GUI dev shell"
            echo "Run 'cargo run' to build and launch"
          '';
        };
      }
    );
}
