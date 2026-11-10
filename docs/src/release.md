# Release Notes

## Unreleased

- Consolidated `keres`, `keres-cli`, and the documentation into one
  Cargo workspace.
- Added workspace-wide CI for tests, linting, rustdoc, package dry-runs, and
  the mdBook build.
- Added root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and
  `CHANGELOG.md`.

## 0.4.2

- Renamed the crates.io package to `keres` while keeping the library
  name `keres`.
- Updated repository metadata.

## 0.4.1

- Version bump and lockfile update.

## 0.4.0

- Introduced the universal container format shared by `.keres` files, vault
  blobs, and manifests.
- Added Argon2id parameters stored in each container.
- Added per-object HKDF subkeys, counter nonces, and AAD binding.
- Added `Vault::verify`.
- Added crash-safe atomic writes.
- Retired pre-0.4 formats.

See [CHANGELOG.md](https://github.com/KeresOSS/keres/blob/main/CHANGELOG.md)
for the full history.
