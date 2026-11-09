# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Monorepo workspace containing `krypton-core`, `krypton-cli`, and the
  documentation book.
- Root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and `CHANGELOG.md`.
- Workspace-level CI for tests, linting, rustdoc, package dry-runs, and the
  mdBook build.

### Changed

- `krypton-core` now lives at `crates/krypton-core`.
- `krypton-cli` now depends on the local core crate via a path dependency.
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

- Pre-0.4 formats are retired; old files report `Error::RetiredFormat`.

[Unreleased]: https://github.com/KryptonOSS/krypton-core/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/KryptonOSS/krypton-core/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/KryptonOSS/krypton-core/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/KryptonOSS/krypton-core/releases/tag/v0.4.0
