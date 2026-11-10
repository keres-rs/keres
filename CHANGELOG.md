# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Monorepo workspace containing `keres`, `keres-cli`, and the
  documentation book.
- Root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and `CHANGELOG.md`.
- Workspace-level CI for tests, linting, rustdoc, package dry-runs, and the
  mdBook build.

### Changed

- Renamed the project from Krypton to Keres:
  - library crate and Rust import path: `keres`
  - CLI package: `keres-cli`
  - binary: `keres`
  - environment variables: `KERES_HOME`, `KERES_PASSWORD`
  - default single-file extension: `.krs`
- Only `KERES\0\0\0` containers are accepted. Every other format, including
  pre-rename Krypton containers and pre-0.4 formats, returns
  `Error::IncompatibleFormat`. Use the release that wrote the data to
  extract and migrate it.
- `keres` now lives at `crates/keres`.
- `keres-cli` now depends on the local library via a path dependency.
- Release profile is defined once at the workspace root.

## [0.4.2] - 2026-08-26

### Changed

- Renamed the crates.io package to `krypton-core` while keeping the library
  name `krypton` for API compatibility.
- Updated repository metadata.

## [0.4.1] - 2026-08-24

### Changed

- Version bump and lockfile update after the 0.4.0 release.

## [0.4.0] - 2026-08-23

### Added

- Universal container format shared by `.krf` files, vault blobs, and
  manifests.
- Argon2id password derivation with per-container KDF parameters.
- Per-object HKDF subkeys, counter nonces, and AAD binding for every record.
- Vault integrity verification (`Vault::verify`).
- Crash-safe atomic writes for configs, manifests, and outputs.

### Changed

- Pre-0.4 formats are retired; old files are rejected.

[Unreleased]: https://github.com/KeresOSS/keres/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/KeresOSS/keres/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/KeresOSS/keres/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/KeresOSS/keres/releases/tag/v0.4.0
