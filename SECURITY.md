# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Keres-rs/keres/security/advisories/new).
Do not open a public issue.

A useful report includes:

- the affected version and platform;
- a minimal reproducer or proof of concept;
- the security property you believe is broken;
- whether the issue requires a modified vault, a specific filesystem, or
  physical access.

We aim to acknowledge reports within 72 hours and will coordinate disclosure
with you. Please allow time for a fix to be released before publishing
details.

## Supported versions

Keres is pre-1.0. Security fixes go to the latest published release, currently
the 0.7.x line, and are noted in [CHANGELOG.md](CHANGELOG.md).

Only the current container format is supported. Pre-rename Krypton containers
and pre-0.4 formats are rejected with `Error::IncompatibleFormat`; decrypt
them with the release that wrote them. A 0.5.x vault (manifest v2) is upgraded
in place with `keres migrate`.

## Scope

The security surface of this repository is the library in `src/` and the CLI
in `keres-cli/`. The GUI and Python bindings are separate projects with their
own reporting processes.

## What Keres protects against

Keres protects data at rest. The adversary is assumed to have read access to
the storage medium — a stolen disk, a leaked backup, a synced folder — and may
also modify stored files.

Under that model:

- file contents, vault entry names, and directory structure are encrypted;
- modification, truncation, reordering, and transplantation of ciphertext are
  detected before the affected plaintext is released;
- vault metadata and the index are authenticated, and entry blobs are bound to
  stable entry IDs rather than paths;
- passwords can be changed without rewriting stored ciphertext.

## What Keres does not protect against

- Malware, keyloggers, or a compromised operating system while a vault is
  unlocked.
- An attacker who knows the password or can read the memory of an unlocked
  process.
- Coercion to reveal a password or recovery code.
- Size and access-pattern leakage. Exact file sizes are visible unless opt-in
  padding is enabled; entry counts, directory shape, and read/write timing
  remain observable even with padding.
- Rollback of an entire vault directory to an older valid copy. Content hashes
  and index generations detect a substituted blob for the same entry, but
  there is no hardware-backed anti-rollback counter.
- Retroactive crypto-erasure. `Vault::erase` rotates the master key so old key
  material stops working against the vault, but a copy of a deleted blob
  captured earlier with the old key remains decryptable.
- Secure erasure of deleted ciphertext on SSDs and journaling filesystems.
- Deniability: the container magic and vault layout identify the data as
  Keres.

The full threat model, key hierarchy, and leakage matrix are in
[the security chapter](docs/src/security.md).

## Audit status

Keres has not had an independent security audit. The design and test suite are
documented, but that is not a substitute for external review before relying on
Keres for high-value data.
