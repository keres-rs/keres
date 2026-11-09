# Roadmap

The detailed, security-first roadmap lives in
[`docs/src/roadmap.md`](docs/src/roadmap.md). This page tracks the work that
matters most for the monorepo.

## Now

- [x] Consolidate the core, CLI, and documentation into one workspace.
- [ ] Vault-level file locking (`flock`) so concurrent processes cannot
      clobber the manifest.
- [ ] Cross-platform CI (Windows and macOS) and an atomic replace path for
      Windows.
- [ ] Fuzzing for container, manifest, and config parsers.
- [ ] `cargo-audit` / `cargo-deny` supply-chain checks and signed releases.
- [ ] Published test vectors for the container format.

## Next

- [ ] Decouple entry identity from the mutable path so `rename`/`update` do
      not require re-encryption.
- [ ] Public streaming API (`Read`/`Write` adapters), progress, and
      cancellation.
- [ ] Entry metadata (mtime, mode) and `list --recursive` / `stat`.
- [ ] Multi-recipient keys (X25519), LUKS-style key slots, and a printable
      recovery kit.
- [ ] Orphan garbage collection (`verify --prune`).
- [ ] Parallel chunk pipeline.

## Later

- [ ] Optional size-hiding padding buckets.
- [ ] Snapshot/version history and restore.
- [ ] Hardware-backed keys (TPM, Secure Enclave, FIDO2).
- [ ] External security audit and a 1.0 release.

## Out of scope

- Plausible deniability / hidden volumes.
- Backwards-compatible readers for pre-0.4 formats.
