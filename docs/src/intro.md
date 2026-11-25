# Introduction

Keres is an embedded encrypted storage engine for Rust applications: a
library (`keres`) for storing application files, plus a reference
command-line program (`keres`) built on the same container format and
cryptographic core.

It is aimed at developers building local-first apps, desktop clients, and
services that own files on disk. Keres supplies authenticated streaming,
encrypted metadata, crash-safe updates, key rotation, and recovery, so the
application does not have to design its own format. The CLI is the reference
implementation and a scripting/debugging tool, not the product.

Keres is designed around one rule: **do not release plaintext until its
authenticity has been checked.** Every record is authenticated, and metadata
is encrypted wherever the format can carry it.

## Two modes, one format

| Mode | Rust entry points | CLI commands | Use when |
|---|---|---|---|
| Single file | `encrypt_file`, `decrypt_file`, `encrypt_file_with_padding` | `keres encrypt`, `keres decrypt` | You need one self-contained `.krs` file |
| Vault | `Vault` | `keres init`, `add`, `list`, `extract`, … | You need many files, directory trees, metadata protection, and password rotation |

Both modes use the same authenticated container:

- an 8-byte `KERES\0\0\0` magic;
- a versioned envelope header;
- 64 KiB AES-256-GCM chunk records;
- an authenticated trailer that records the payload type, original name,
  size, and chunk count.

Vaults add a key hierarchy, an encrypted index, keyslots, and crash-recovery
journals on top of that container.

## Design principles

1. **Authenticate before use.** Chunk index and payload type are bound into
   every AEAD tag. Headers participate in key derivation. A modified,
   reordered, truncated, or transplanted ciphertext fails before plaintext is
   returned.
2. **Encrypt metadata where possible.** Filenames, directory structure, and
   the vault index are encrypted. Exact sizes are not hidden by default;
   opt-in padding rounds them to buckets.
3. **Make crashes boring.** New data is written first and committed last.
   Configs, indexes, and outputs use temp-file + `fsync` + `rename`. A crash
   can lose the operation in flight, never the previous consistent state.
4. **Keep the trusted surface small.** One container format, one chunk
   engine, one error type, no async runtime, no network code, and no
   `unsafe` (`#![forbid(unsafe_code)]`).
5. **Separate passwords from data keys.** In a vault, the password derives a
   key-encryption key that wraps a random master key. Changing a password
   re-wraps that key; it does not rewrite stored ciphertext.

## Project status

Keres is **pre-1.0**. The current line is 0.7.x.

- The wire format is versioned and covered by committed test vectors.
- The public Rust API may change between minor releases until 1.0.
- The project has not yet had an independent security audit.
- Only the current container format is accepted. A 0.5.x vault can be
  upgraded in place with `keres migrate`; other legacy formats must be
  decrypted with the release that wrote them.

See [Security model](./security.md) for the threat model and a list of
limitations that are deliberate, not bugs.

## Non-goals

Keres does **not** try to provide:

- plausible deniability or hidden volumes;
- protection against malware, keyloggers, or a compromised OS while a vault
  is unlocked;
- access-pattern hiding (ORAM) or exact entry-count hiding;
- hardware-backed anti-rollback guarantees;
- compatibility readers for retired formats.

## Where to go next

- [Installation](./install.md) — install the CLI or add the library.
- [Quick start](./usage.md) — encrypt a file and create a vault.
- [Library guide](./library-usage.md) — API patterns and examples.
- [Embedding Keres](./embedding.md) — integration guidance for applications.
- [CLI guide](./cli-usage.md) — workflows and command behavior.
- [Architecture](./architecture.md) — wire format, key hierarchy, and crash
  safety.
- [Security model](./security.md) — attacker model, guarantees, and
  limitations.
