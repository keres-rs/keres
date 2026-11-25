# Roadmap

Keres is pre-1.0 and developed security-first. This page summarizes the
current priorities; the detailed, itemized roadmap is in
[docs/src/roadmap.md](docs/src/roadmap.md), and completed work is recorded in
[CHANGELOG.md](CHANGELOG.md).

## Before 1.0

- **External security audit.** A professional review of the container format,
  key hierarchy, and implementation. Internal review and fuzzing are not a
  substitute.
- **API and format freeze.** Stabilize the public Rust API and commit to the
  current envelope, config, and manifest versions as the long-term
  compatibility contract.
- **Memory locking.** Evaluate `mlock` and core-dump suppression behind a
  small, audited unsafe boundary. Disabled by default.
- **Hardware-backed factors.** Optional TPM, Secure Enclave, or FIDO2
  `hmac-secret` support alongside a password.

## Operational hardening

- Group commit for concurrent vault writers.
- Crash-injection tests for rotation, compaction, and migration.
- Cross-platform filesystem coverage, including behavior on network and
  FUSE filesystems.
- Optional timing and mutation-count coarsening for the index log.

## Performance and ergonomics

- A parallel chunk pipeline. The format already permits it: chunks are
  independent.
- Entry metadata (mode, mtime) and recursive listing.
- Multi-recipient keys (X25519).

## Out of scope

- Plausible deniability and hidden volumes. The container magic is deliberate;
  deniable schemes conflict with authenticated formats and invite user error.
- Backward-compatibility readers for retired formats. The one exception is
  the one-way v2 → v3 vault upgrade in `keres migrate`.
- Access-pattern hiding (ORAM). Keres documents access-pattern leakage rather
  than claiming to hide it.
- Network synchronization. Keres encrypts local files; syncing services are
  outside the trust boundary.

## How priorities are chosen

1. Security defects and data-loss risks.
2. Correctness and crash safety.
3. Documentation and usability gaps that can cause data loss.
4. Performance and ergonomics.

Proposals that add a new format, a new primitive, or a new privileged code
path need a written design and tests before implementation.
