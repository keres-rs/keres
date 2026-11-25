# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- In-memory vault access: `Vault::add_from_reader`,
  `Vault::replace_from_reader`, and `Vault::extract_to_writer` store and read
  entries from any `std::io::Read`/`std::io::Write` without temporary files.
  Padded vaults require the exact plaintext length up front; unpadded vaults
  may stream an unknown length.
- Configurable Argon2id cost: `EncryptOptions` /
  `encrypt_file_with_options`, `VaultOptions` / `Vault::init_with_options`,
  and `StreamOptions::kdf`. `KdfParams` is re-exported from the crate root,
  and new keyslots inherit the vault's parameters.
- `examples/in_memory.rs` and `examples/vault_store.rs` show embedded use.
- New "Embedding Keres" book chapter covering async wrapping, key management,
  concurrency, padding, and API stability.

### Changed

- The crate is now positioned as an embedded storage engine for Rust
  applications. The CLI is documented as the reference implementation.
- The crate-level and `Vault` quick-start examples no longer call `unlock`
  immediately after `init` (which already leaves a new vault unlocked).

### Security

- Vault entry content-hash checks now compare digests in constant time.
- Reads of `vault.config` are capped at 1 MiB, so a hostile on-disk file
  cannot force a large allocation before parsing.
- Clarified in the container documentation that the envelope version is bound
  through the record AAD domain rather than key derivation; the tamper
  property is unchanged.
- The container fuzz target now exercises the v2 padding-header decoder
  directly, which is otherwise gated behind a valid AEAD record.

## [0.7.1] - 2026-11-25

This release contains no container-format, vault-format, or API changes.
Vaults and `.krs` containers written by 0.7.0 remain readable.

### Changed

- Repository layout now puts the library at the repository root, matching the
  smithay-style workspace layout. The `keres` crate occupies `src/`, `tests/`,
  and `benches/` with the root `Cargo.toml` serving as both its package
  manifest and the workspace manifest; `keres-cli` stays in `keres-cli/`.
  Install the CLI with `cargo install --path keres-cli` or, from crates.io,
  `cargo install keres-cli`.
- Documentation rewritten as a complete reference. The book is organized into
  getting started, guides, and reference chapters, with new pages for the CLI
  reference, recovery and rotation, performance, and troubleshooting. The
  README, `CONTRIBUTING.md`, `SECURITY.md`, and `ROADMAP.md` were rewritten to
  match, and the published crate now excludes repository-only files.

## [0.7.0] - 2026-11-19

### Added

- Append-only encrypted index log. Vault mutations now append authenticated
  `put`/`delete` batches to `d/.index.log` instead of rewriting the whole
  `d/.manifest.enc` snapshot. A batch is keyed from the master and a random
  per-log id, uses a fresh nonce, and binds the log header plus record index
  in its AAD. Loading decodes the snapshot and replays the log; the next save
  compacts into a fresh snapshot after 512 records or 8 MiB. Compaction is
  journaled in `d/.index.compact`, and deep rotation or migration discard any
  log encrypted under the old index.

### Changed

- Vault locking now recovers interrupted journals centrally. Both exclusive
  and shared lock acquisition finish a committed rotation or index compaction
  before the config or index is read, so a crash between a journal write and
  its cleanup cannot make the vault unreadable.
- Index state now carries an authenticated internal generation. The snapshot
  records it, a log must declare the same value as the snapshot it extends,
  and compaction advances it by one. Pre-generation snapshots read as
  generation 0. This makes snapshot/log swaps unambiguous for crash recovery;
  it is not a rollback guarantee without hardware-backed state.
- Opt-in L2 size padding. `Padding::{None, Adaptive, Fixed}` policies round
  file payloads up to a bucket before encryption, using a new envelope
  version 2 with an authenticated fixed-width prelude and a trailer that
  binds the padded length. Vault policy is stored in the authenticated
  index snapshot (`ManifestFile.padding`), so storage attackers cannot
  silently disable it. `Vault::init_with_padding` / `padding` / `set_padding`,
  `encrypt_file_with_padding`, and CLI `--padding` / `padding` expose it.
  `DecryptReader` reads padded containers; `EncryptWriter` stays unpadded.
- Conditional writes and explicit batch commit. `Vault::version()` exposes an
  authenticated index version (generation + record count); `add_if` /
  `replace_if` apply a mutation only when the captured version still matches
  (if-match), and `add_if` also refuses to overwrite an existing entry
  (if-none-match), returning `WriteOutcome`. `Vault::apply_batch` commits
  several adds/replaces/removals in a single index commit. New
  `Error::Conflict` reports a failed precondition.
- Forward key invalidation with `Vault::erase`. The entry is omitted from the
  index and every survivor is re-encrypted under a fresh master key in one
  journaled commit; the vault ends up locked under the new password. This is
  not retroactive crypto-erasure: a copy of the deleted blob captured earlier
  with the old key or config remains decryptable. Ordinary `remove` documents
  the same limitation. CLI `erase` command added. Metadata-leakage matrix
  published in `docs/src/security.md`.
- Per-entry content hashes. The authenticated index records the plaintext
  SHA-256 and size; `verify` and `extract` reject a substituted or stale blob
  even when it authenticates under the same entry ID. Legacy entries without a
  hash are size-checked only.

### Fixed

- `remove` commits the index before deleting blobs, so a failed deletion
  leaves a pruneable orphan instead of an index that points at missing data.
- `apply_batch` is all-or-nothing for the visible index: adds and replaces use
  copy-on-write entry IDs, removals only drop index records, and old blobs are
  deleted after the single commit. A failing operation leaves the prior index
  and contents intact.
- A missing `d/.manifest.enc` is now `InvalidVault` instead of an empty index.
  `init` writes the first snapshot explicitly and refuses to clobber a
  config-less vault that still has a recovery kit.
- Root entry names are single components: `add`, `add_if`, batch adds, and
  `rename` reject names containing `/`. Directory adds and directory renames
  pre-flight every destination before writing anything.
- `erase` no longer removes the entry under the old key before rotating.
  Removal and rotation commit together, so a failed rotation leaves the old
  vault and entry intact.
- `Vault::init` refuses to overwrite a vault directory whose index already
  exists, and reports a clear error when a recovery kit cannot be deleted
  after a successful recovery.
- Rotation journals record old-key blob paths, so recovery can delete them
  even though the old master is no longer available.

## [0.6.0] - 2026-11-19 (never published; folded into 0.7.0)

### Added

- Committed format test vectors with a pinned SHA-256, hidden fuzz entry
  points, a `cargo-fuzz` workspace with a seeded corpus and weekly workflow,
  and Criterion throughput benchmarks.
- `Vault::replace` / `keres replace` updates an existing file entry without a
  remove-then-add window.
- `Vault::prune_orphans` / `keres verify --prune` reclaims ciphertext blobs
  and stale temp files that no manifest record references, refusing to run
  when the manifest is missing.
- `Vault::rename` / `keres rename` renames a top-level file or directory
  without re-encrypting it. Entries now carry a stable 128-bit random ID, and
  blob paths plus container AAD derive from that ID rather than the path.
- `Vault::migrate` / `keres migrate` upgrades a 0.5.0 (manifest v2) vault in
  place: every entry is re-encrypted under a fresh stable ID, the v3 manifest
  is committed atomically, and legacy path-addressed blobs are removed. The
  master key is unchanged (this is not key rotation), and a failure before the
  commit leaves the legacy vault readable.
- Printable recovery kits: `Vault::create_recovery_kit` / `keres recovery
  create` writes a second wrapping of the master key to `vault.recovery`,
  protected by a random 160-bit Crockford Base32 code with a checksum.
  `Vault::recover` / `keres recovery use` recreates a lost or corrupt
  `vault.config`, validates the key against the encrypted index, resets the
  password, and consumes the kit.
- LUKS-style keyslots: `vault.config` v3 stores a table of independent
  passphrase wrappings of the same master key. `Vault::add_keyslot` /
  `Vault::remove_keyslot` and `keres keyslot add|remove|list` add or revoke a
  passphrase; `change_password` re-wraps only the matching slot. Version 2
  configs are read and upgraded on the next key-changing operation.
- Opt-in deep rotation: `Vault::rotate` / `keres rotate` generates a fresh
  master key, streams every entry through re-encryption, and rewrites the
  index. The new config has one keyslot under the new password, so extra
  keyslots and any recovery kit are invalidated. A `vault.rotate` journal
  lets the next open finish or roll back an interrupted run.
- Streaming API: `keres::streaming` provides `EncryptWriter` / `DecryptReader`
  `io::Write` / `io::Read` adapters plus `encrypt_stream` / `decrypt_stream`.
  `StreamOptions` supports a cumulative-byte progress callback and an
  `AtomicBool` cancellation flag; cancellation reports the new
  `Error::Cancelled`. Output is format-compatible with `encrypt_file` and
  `decrypt_file`.
- CLI password sources: `--password-file` and `--password-stdin`, with all
  password buffers zeroized. `--force` and an interactive confirmation guard
  destructive operations.
- Tag-driven release workflow: `keres` then `keres-cli` published via
  crates.io Trusted Publishing, cross-platform `keres` binary archives with
  SHA-256 checksums and build-provenance attestations, and a GitHub Release.

### Changed

- The vault manifest schema is now version 3. Each entry records a non-empty
  random ID; version 2 manifests now return `Error::MigrationRequired`
  (version 3 manifests with a missing ID are still `InvalidVault`). Blobs are
  named from the ID, so entry paths are no longer part of the on-disk layout
  or the AAD.
- `vault.config` is now version 3: a slot table instead of a single wrapped
  key. Version 2 configs still unlock and are rewritten as version 3 on the
  next key-changing operation. `Vault::change_password` now re-wraps only the
  slot that matched and leaves a locked vault locked. `Vault::recover` writes
  a fresh single-slot config, dropping any additional keyslots.
- `unlock` now takes a shared advisory lock, so it cannot read the config in
  the middle of a concurrent password change. When a rotation journal exists,
  `unlock`, `keyslots`, `verify`, and the config-changing operations take the
  exclusive lock first and finish the journal.
- CI now runs doctests explicitly and gates advisories, licenses, and sources
  with `cargo-deny`; Dependabot keeps the workflow actions current.
- Minimum supported Rust version is now 1.85, matching the current
  dependency graph (`clap`, `rpassword`, `zeroize`, `base64ct`).

### Fixed

- Adding a directory tree failed on Windows with `InvalidEntryName` because
  vault-relative names were built with the platform separator. Manifest names
  now always use `/`, independent of the host filesystem.
- `change-password` no longer reuses a `--password-file` or `KERES_PASSWORD`
  value for the new password. The new secret is prompted separately, so those
  sources can be used without a terminal conflict.

### Upgrade note

- Vaults written by 0.5.0 use manifest v2 and are rejected by the 0.6.0
  reader. Back up the vault directory, then run `keres migrate <vault>`
  (or `Vault::migrate`). The password is unchanged and the legacy blobs are
  removed after the v3 manifest is committed. Migration is one-way; keep the
  backup until you have verified the upgraded vault.

## [0.5.0] - 2026-11-10

### Added

- Monorepo workspace containing `keres`, `keres-cli`, and the
  documentation book.
- Root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and `CHANGELOG.md`.
- Workspace-level CI for tests, linting, rustdoc, package dry-runs, and the
  mdBook build, with Windows and macOS test jobs.
- Advisory vault locking (`vault.lock`): writers take an exclusive lock,
  readers a shared lock, and concurrent access fails fast with
  `Error::VaultBusy` instead of racing on the manifest.

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
- Release profile is defined once at the workspace root.

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

[0.7.1]: https://github.com/Keres-rs/keres/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Keres-rs/keres/compare/v0.5.0...v0.7.0
[0.5.0]: https://github.com/Keres-rs/keres/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Keres-rs/keres/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Keres-rs/keres/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Keres-rs/keres/releases/tag/v0.4.0
