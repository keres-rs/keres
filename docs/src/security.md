# Security model

Keres protects data **at rest**. The primary adversary has read access to the
storage medium — a stolen laptop, a leaked backup, a seized disk, or a
compromised sync folder — and may also modify stored files.

Keres does not protect against an attacker who can run code on the machine
while a vault is unlocked, observe the screen or keyboard, or control the
operating system. Those cases are outside the threat model.

> **Audit status:** Keres has not yet had an independent security audit. This
> document describes the intended design and the properties the test suite
> checks; it is not a substitute for review before high-value deployment.

## Security goals

In priority order:

1. **Confidentiality of content and metadata.** File contents, names, and
   directory structure are encrypted.
2. **Tamper evidence.** Modification, truncation, reordering, splicing, or
   transplantation of ciphertext is detected before plaintext is released.
3. **No accidental data loss.** Corruption fails loudly; writes are atomic;
   interrupted operations never leave a half-written config or a dangling
   index.
4. **A small, auditable surface.** One container format, one chunk engine,
   no async runtime, no network code, and no `unsafe`
   (`#![forbid(unsafe_code)]`).

## Cryptographic primitives

All primitives come from RustCrypto crates (`aes-gcm`, `argon2`, `hkdf`,
`sha2`, `subtle`). Randomness comes from the operating system CSPRNG.

| Primitive | Parameters | Role |
|---|---|---|
| AES-256-GCM | 96-bit nonces, 128-bit tags | Every byte of ciphertext |
| Argon2id | Default 64 MiB, t=4, p=4; stored per container | Password → key-encryption key |
| HKDF-SHA256 | Random 32-byte salt per object | Master key → per-object content keys; index-log keys |
| SHA-256 | — | Blob path derivation and per-entry plaintext content hashes |
| `subtle::ConstantTimeEq` | — | Comparisons on secrets where needed |

KDF parameters travel inside containers so defaults can evolve. When reading
untrusted input they are bounded to prevent denial of service:

| Field | Default | Accepted range |
|---|---|---|
| `m_cost_kib` | 65,536 KiB (64 MiB) | 8 MiB – 4 GiB |
| `t_cost` | 4 | 1 – 64 |
| `p_cost` | 4 | 1 – 16 |

## Key hierarchy

```text
Standalone .krs (password-derived):

  password ──Argon2id(argon_salt, params)──► KEK
           ──HKDF(object_salt)──► content key

Vault:

  password ──Argon2id(slot salt, params)──► KEK
           ──AES-GCM-wrap──► master key (vault.config, one wrapping per keyslot)

  master key ──HKDF(object_salt, identity)──► per-entry content key
             ──HKDF(object_salt, "vault-manifest")──► index content key
```

Properties that follow:

- **Per-object keys.** Every entry gets a fresh random object salt and an
  independent HKDF subkey.
- **Password changes do not rewrite data.** Only the wrapped master key in
  `vault.config` changes.
- **No offline verifier.** There is no password hash to check guesses against;
  each guess costs a full Argon2id run plus GCM verification.
- **Keyslot revocation is not rotation.** Removing a slot drops one wrapping;
  the master key stays the same. See [Known limitations](#known-limitations).

## Nonces and associated data

| Record | Nonce | AAD |
|---|---|---|
| Data chunk *i* | 4 zero bytes ‖ `i` as u64 BE | `"keres-container-v1/<type>"` ‖ chunk index |
| Padded metadata | `[0xFE; 12]` | `"keres-container-v2/padding"` |
| Trailer | `[0xFF; 12]` | chunk context ‖ index ‖ `"/trailer"` |
| Config slot | Random 96-bit nonce | `"keres-vault-config-v3/"` ‖ slot id |
| Recovery kit | Random 96-bit nonce | `"keres-vault-recovery-v1"` |
| Index-log record | Random 96-bit nonce | log header bytes ‖ record index |

Consequences:

- Reordering chunks or moving records between positions fails authentication.
- Moving records between payload types or containers fails because the
  context or object key differs.
- The unauthenticated end-of-chunks marker is harmless: the authenticated
  trailer's `chunk_count` and `size` must match what was actually read.
- Counter nonces are collision-free within an object regardless of size or
  restarts.

See [Architecture](./architecture.md) for the exact wire layout.

## Key management

### Passwords and keyslots

A vault starts with one keyslot. Each slot wraps the same random master key
under a KEK derived from that slot's password and salt. Unlocking tries the
slots until one AEAD tag verifies.

`change_password` re-wraps one slot. `add_keyslot` appends a new wrapping.
`remove_keyslot` deletes a wrapping and requires authorization from a slot
that remains; the last slot cannot be removed.

Slot ids and the slot count are plaintext metadata in `vault.config`. A wrong
password and a tampered wrapping are both reported as
`Error::Authentication`.

### Recovery kits

A recovery kit is an independent wrapping of the master key under a random
160-bit code, printed once. `recover` uses the kit to recreate a lost or
damaged `vault.config`, validates the recovered key against the encrypted
index, writes a fresh single-slot config, and deletes the kit.

The code is not stored. The recovery file is a second offline guessing target;
160 bits plus Argon2id makes exhaustive search infeasible, but the code must
be stored separately and handled like a password.

### Rotation and erasure

`rotate` generates a new master key, re-encrypts every entry, and writes a
fresh single-slot config. `erase` does the same while omitting one entry.

Both are forward-looking. They stop old key material from working against the
vault from now on, but they cannot revoke ciphertext that an attacker already
copied together with the old key or config.

## Memory handling

- Keys live in `Zeroizing<[u8; 32]>`; buffers containing secrets are zeroized
  on drop.
- `Debug` for `Key` and `RecoveryCode` redacts the value.
- Keys are not serialized, logged, or included in errors.
- `Vault::lock` drops the in-memory master key.

Keres does **not** use `mlock`, `madvise`, or core-dump suppression. With
`#![forbid(unsafe_code)]`, those would require an audited unsafe boundary;
they are on the roadmap. On a machine without encrypted swap, unlocked keys
can reach disk.

## Filesystem and crash safety

- All persistent writes use: create a temp file in the same directory →
  restrict permissions → write → `sync_all` → `rename` → `sync_dir`.
- Temp files are opened with `O_CREAT | O_EXCL`, so an existing path or
  planted symlink causes failure instead of being written through. On Unix
  they are mode `0600` from creation.
- Vault directories and single-file outputs are created with owner-only
  permissions (`0700`/`0600`) on Unix.
- Names recovered from containers are sanitized before path joins. Absolute
  paths, `..`, separators, and control characters are rejected.
- Adds write blobs first and commit the index last. A crash leaves
  unreferenced blobs, never an index pointing at missing data.
- Removals commit the index first and delete blobs afterwards. A failed
  deletion leaves a pruneable orphan.
- Replaces are copy-on-write: a new blob and entry ID are written, the index
  is committed, and only then is the old blob deleted.
- Rotation and index compaction are journaled; the next lock acquisition
  completes or rolls back an interrupted run.
- Vault access uses non-blocking advisory locks (`flock` on Unix,
  `LockFileEx` on Windows). Writers lock exclusively, readers share the lock,
  and contention returns `Error::VaultBusy`.

The lock coordinates well-behaved processes; it is not a security boundary.

## Metadata leakage

Keres uses two informal levels in its documentation:

- **Default** — names and structure encrypted; exact entry sizes visible.
- **Padded** — opt-in size padding (`Padding::Adaptive` or `Padding::Fixed`).

| Signal | Default | Padded | Notes |
|---|---|---|---|
| Container magic / format existence | Visible | Visible | Deniability is out of scope |
| Vault existence and layout | Visible | Visible | Directory names and structure identify a vault |
| File names | Hidden | Hidden | Encrypted in the index or trailer |
| Directory structure | Hidden | Hidden | Encrypted in the index |
| Entry sizes | Exact | Bucket only | Manifests and directory placeholders are never padded |
| Number of top-level entries | Visible | Visible (coarse) | Count bucketing is not implemented |
| Access patterns | Visible | Visible | No ORAM; reads/writes and timing are observable |
| Modification times | OS-level | OS-level | Not coarsened |
| Index mutation count / order | Visible via log size | Visible via log size | Group commit and timing jitter are future work |
| Deleted-entry recoverability | Blob removed | Blob removed | Old copies remain decryptable unless `erase` is used |
| Rollback to an older valid copy | Possible | Possible | No hardware-backed anti-rollback counter |

Padding hides exact sizes, not which blob was accessed or when. It also adds
storage overhead: adaptive padding wastes up to the current bucket size.

## Verification

`Vault::verify` / `keres verify` authenticates the replayed index and every
blob. In addition to AEAD tags it checks:

- the payload type;
- the recorded plaintext size;
- the SHA-256 content hash stored in the authenticated index.

The content hash detects a substituted older blob under the same entry ID.
Entries written by releases before content hashes existed are size-checked
only. Verification does not detect a rollback of the entire vault directory.

## Known limitations

1. **No memory locking.** Keys can be swapped or captured in a core dump if
   the OS allows it.
2. **No retroactive key rotation.** Rotation re-encrypts the current vault,
   but cannot reach copies an attacker already took.
3. **No deniability.** The container magic and vault layout identify their
   contents as Keres data.
4. **Single-factor authentication.** Passwords, keyslots, and recovery codes
   are all knowledge factors. There is no hardware token or multi-party
   split.
5. **Size leakage by default.** Ciphertext length reveals plaintext length
   unless padding is enabled. Padding is opt-in.
6. **No hardware-backed anti-rollback.** Restoring an older valid vault
   directory is possible. Content hashes and index generations detect some
   local substitutions, not a full-directory rollback. A truncated index-log
   tail is indistinguishable from an interrupted append.
7. **Operation-pattern leakage.** The index log reveals how many mutations
   occurred and roughly when. Access patterns are not hidden.
8. **No independent audit.** The implementation has not been reviewed by an
   external cryptography or security firm.
9. **No key commitment.** AES-GCM is not key-committing: an attacker who
   controls a file could in principle construct one ciphertext that
   authenticates under two different keys. Keres limits the impact by using a
   single key per container, a fresh random object salt, and an authenticated,
   structured trailer (payload type, size, chunk count) that must also parse.
   A wrong password therefore still fails in practice, but the format has no
   formal commitment tag. This is tracked for a future envelope version and
   for the audit.

## Audit scope

The first independent audit should focus on the following, in priority order.
This list is also the starting point for quote requests.

1. **Container format and stream engine.** Header binding, AAD domains,
   deterministic nonce construction, trailer and padding records, record and
   chunk-count limits, and parser behavior on truncated or oversized input.
   Fuzz targets cover the container reader, manifest decoder, config parser,
   and padding header.
2. **Key hierarchy.** Argon2id parameter handling and bounds, HKDF domain
   separation between object kinds, keyslot wrapping and slot-id binding,
   recovery-kit construction, and the rotation and erasure journals.
3. **Key commitment and partitioning oracles.** Whether the absence of a
   commitment tag is exploitable for password-derived `.krs` files, and
   whether single-key containers are sufficient in practice.
4. **Rollback and truncation.** Whole-directory rollback, index-log tail
   truncation, and the interaction between content hashes, generation
   numbers, and compaction.
5. **Metadata leakage.** What the padding scheme actually hides, and whether
   this document matches the implementation.
6. **Filesystem and crash safety.** Temp-file handling, permissions,
   symlink and race behavior, and recovery from interrupted rotation,
   compaction, and migration.
7. **API misuse resistance.** Whether the hardened public API makes it hard
   to reuse a key accidentally, skip authentication, or ignore an error.

Out of scope for the first audit: ORAM and access-pattern hiding, plausible
deniability, network synchronization, and hardware-backed factors.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Follow the process
in [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md),
including a minimal reproducer and the affected version.
