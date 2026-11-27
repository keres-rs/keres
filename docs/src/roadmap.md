# Roadmap

Keres is developed security-first. This page lists the work that remains, not
the work that is finished; completed changes are recorded in
[CHANGELOG.md](https://github.com/Keres-rs/keres/blob/main/CHANGELOG.md).

Anything that weakens an authenticated property will not be accepted for
compatibility or convenience.

## 0.7.x follow-ups

- **Group commit.** Coalesce concurrent writers into one durable index batch
  so a busy vault pays for one `sync_data` per group instead of per mutation.
- **Timing and count hardening.** Explore optional timing jitter and mutation
  count bucketing for the index log. Access-pattern hiding remains out of
  scope.
- **Dependency slimming.** Remove `walkdir` from the production dependency
  graph by replacing the directory walk with a small `std::fs::read_dir`
  implementation that preserves ordering and symlink behavior.
- **Rollback detection.** Investigate a MAC'd monotonically increasing
  generation stored outside the vault directory. Without trusted external
  state this improves detection, not prevention.
- **Documentation and examples.** Keep the book, rustdoc, and CLI help in
  sync; add end-to-end examples for recovery and rotation.
- **Embedding ergonomics.** Continue widening the in-memory API (for example
  streaming `Read` handles for vault entries), and add a flagship application
  example that looks like a real local-first app rather than a toy.

## 1.0 readiness

- **External security audit.** A professional review of the container format,
  key hierarchy, and implementation. No amount of internal review substitutes
  for this.
- **Memory locking.** Evaluate `mlock` and core-dump suppression behind a
  small audited unsafe boundary, feature-gated and disabled by default.
- **Hardware-backed factors.** Optional TPM, Secure Enclave, or FIDO2
  `hmac-secret` support combined with a password. Plain password vaults remain
  the default.
- **API stabilization.** Freeze the public Rust API and commit to semantic
  versioning. `#[non_exhaustive]`, `#[must_use]`, `cargo-semver-checks`, and
  the [MSRV policy](./stability.md) are already in place; the remaining work
  is the 1.0 review. Until then, minor releases may change APIs.
- **Format freeze.** Declare the current envelope, config, and manifest
  versions stable and document the long-term compatibility promise.
- **Operational hardening.** More crash-injection testing, cross-platform
  filesystem tests, and recovery drills for interrupted rotation,
  compaction, and migration.

## Explicitly out of scope

- **Plausible deniability / hidden volumes.** The container magic is a
  feature; deniable schemes conflict with authenticated formats and invite
  catastrophic user error.
- **Backward-compatibility readers for retired formats.** Only the current
  format is accepted. The sole exception is the one-way v2 → v3 vault upgrade
  in `keres migrate`.
- **Access-pattern hiding (ORAM).** Keres documents access-pattern leakage
  rather than claiming to hide it.
- **Network synchronization.** Keres encrypts local files; syncing services
  are outside the trust boundary.

## How priorities are chosen

1. Security defects and data-loss risks.
2. Correctness and crash safety.
3. Documentation and usability gaps that can cause data loss.
4. Performance and ergonomics.

Proposals that add a new format, a new primitive, or a new privileged code
path need a written design and tests before implementation.
