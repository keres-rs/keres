# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-10

### Added

- Monorepo workspace containing `keres`, `keres-cli`, and the
  documentation book.
- Root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and `CHANGELOG.md`.
- Workspace-level CI for tests, linting, rustdoc, package dry-runs, and the
  mdBook build, now with Windows and macOS test jobs.
- Advisory vault locking (`vault.lock`): writers take an exclusive lock,
  readers a shared lock, and concurrent access fails fast with
  `Error::VaultBusy` instead of racing on the manifest.
- `Vault::replace` / `keres replace` updates an existing file entry without a
  remove-then-add window.
- `Vault::prune_orphans` / `keres verify --prune` reclaims ciphertext blobs
  and stale temp files that no manifest record references, refusing to run
  when the manifest is missing.

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
- Atomic replacement now uses `rename` directly on Windows as well, removing
  the non-atomic delete-then-rename fallback.
- `keres` now lives at `crates/keres`.
- `keres-cli` now depends on the local library via a path dependency.
- `unlock` now takes a shared advisory lock, so it cannot read the config in
  the middle of a concurrent password change.
- Release profile is defined once at the workspace root.
- Minimum supported Rust version is now 1.85, matching the current
  dependency graph (`clap`, `rpassword`, `zeroize`, `base64ct`).

### Security

- Temp files are now created with `O_CREAT | O_EXCL` and, on Unix, mode
  `0600` at creation time. Previously the file was created with the umask
  default (typically `0644`) and only then `chmod`ed, and `File::create`
  would follow a planted symlink. This affects single-file
  encryption/decryption, vault blob writes, and vault extraction; decrypted
  plaintext is no longer briefly world-readable, and a pre-created temp path
  now fails the operation instead of being written through.
- Directories created by the library now use mode `0700` at creation time
  rather than being chmod'ed afterwards.

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

[Unreleased]: https://github.com/KeresOSS/keres/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/KeresOSS/keres/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/KeresOSS/keres/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/KeresOSS/keres/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/KeresOSS/keres/releases/tag/v0.4.0
