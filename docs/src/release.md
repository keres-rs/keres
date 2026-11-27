# Release process

Keres uses tag-driven releases. The workflow in
`.github/workflows/release.yml` publishes the crates, builds binary archives,
and creates the GitHub release.

## Versioning

- The workspace version lives in `Cargo.toml` under
  `[workspace.package]`.
- `keres` and `keres-cli` share that version.
- The CLI depends on the matching published `keres` version, so the library
  must be published first.
- The container format version is independent of the crate version. Format
  compatibility is documented in
  [Compatibility and versioning](./architecture.md#compatibility-and-versioning).

## Release checklist

1. **Update the version.** Bump `[workspace.package].version` and run
   `cargo update --workspace` if needed.
2. **Update the changelog.** Add an entry to `CHANGELOG.md` describing user
   impact, format changes, and upgrade notes.
3. **Run the gates.**

   ```console
   $ cargo test --workspace --all-targets --locked
   $ cargo test --workspace --doc --locked
   $ cargo clippy --workspace --all-targets --locked -- -D warnings
   $ cargo fmt --all -- --check
   $ cargo doc --workspace --no-deps --locked
   $ cargo semver-checks --package keres
   $ cargo publish --dry-run --locked -p keres
   $ mdbook build docs
   ```

   The release workflow also runs `cargo-semver-checks`. It derives the
   release type from `[workspace.package].version`, so bump to the next minor
   version before the check if the release contains breaking API changes.

4. **Commit the release.** The release workflow requires the tag to be on
   `main`.
5. **Tag and push.**

   ```console
   $ git tag v0.7.1
   $ git push origin v0.7.1
   ```

6. **Approve the deployment.** The workflow uses the protected `release`
   environment; a reviewer must approve before publishing.

## What the workflow does

1. Verifies the tag is an ancestor of `main` and matches the workspace
   version.
2. Runs `cargo test --workspace --locked`.
3. Publishes `keres`, waits for the crate to appear on crates.io, then
   publishes `keres-cli`.
4. Builds the CLI for Linux (`x86_64-unknown-linux-gnu`), macOS
   (`aarch64-apple-darwin`), and Windows (`x86_64-pc-windows-msvc`).
5. Packages each binary with a SHA-256 checksum and build-provenance
   attestation.
6. Creates the GitHub release and attaches the archives and checksums.

The publish step is idempotent: a version already present on crates.io is
skipped, so a failed release can be re-run from the same tag. The CLI publish
retries while the registry index catches up.

## One-time repository setup

- Configure **Trusted Publishing** on crates.io for both `keres` and
  `keres-cli`, pointing at `Keres-rs/keres` and
  `.github/workflows/release.yml`.
- Create a `release` environment in GitHub with required reviewers.
- Allow `id-token: write` and `attestations: write` in the repository's
  Actions policy.

## Supported versions

Keres is pre-1.0. Security fixes are applied to the latest published release
(currently the 0.7.x line). Only the current container format is supported;
legacy formats must be decrypted with the release that wrote them. A 0.5.x
vault can be upgraded in place with `keres migrate`.

## Release notes

`CHANGELOG.md` is the source of truth for user-visible changes. The GitHub
release should summarize upgrade notes and link to the changelog rather than
duplicating it.
