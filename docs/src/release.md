# Release Notes

## 0.5.0

- Consolidated the library, CLI, and documentation into one Cargo workspace.
- Renamed the project from Krypton to Keres: library `keres`, CLI package
  `keres-cli`, binary `keres`, and `.krs` single-file containers.
- Added advisory vault locking: writers take an exclusive lock, readers a
  shared one, and concurrent access returns `Error::VaultBusy`.
- Added `Vault::replace` and `Vault::prune_orphans` (`keres replace`,
  `keres verify --prune`).
- Added `Vault::rename` and stable random entry IDs (manifest v3), so renames
  no longer re-encrypt data and blob identity is independent of the path.
- Added workspace-wide CI for tests on Linux, Windows, and macOS, plus
  linting, rustdoc, package dry-runs, and the mdBook build.
- Added root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and
  `CHANGELOG.md`.
- Hardened temp-file creation: files are created with `O_CREAT | O_EXCL`
  and mode `0600` (Unix) up front, so plaintext is never briefly readable
  by other users and a planted symlink cannot redirect a write.

## 0.4.2

- Renamed the crates.io package to `krypton-core` while keeping the library
  name `krypton`.
- Updated repository metadata.

## 0.4.1

- Version bump and lockfile update.

## 0.4.0

- Introduced the universal container format shared by `.krf` files, vault
  blobs, and manifests.
- Added Argon2id parameters stored in each container.
- Added per-object HKDF subkeys, counter nonces, and AAD binding.
- Added `Vault::verify`.
- Added crash-safe atomic writes.
- Retired pre-0.4 formats.

See [CHANGELOG.md](https://github.com/KeresOSS/keres/blob/main/CHANGELOG.md)
for the full history.
