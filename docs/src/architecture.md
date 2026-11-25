# Architecture

Keres has four layers:

1. **Primitives** — AES-256-GCM, Argon2id, HKDF-SHA256, SHA-256, and the OS
   CSPRNG.
2. **Stream engine** — 64 KiB authenticated records.
3. **Container** — the universal envelope shared by `.krs` files, vault
   blobs, and the vault index.
4. **Vault** — key hierarchy, encrypted index, keyslots, journals, and file
   operations.

The layers are deliberately separate. A format change should not require a
new crypto primitive, and a new vault operation should not need a new
container format.

## Cryptographic primitives

All primitives come from RustCrypto crates (`aes-gcm`, `argon2`, `hkdf`,
`sha2`, `subtle`). Randomness comes from the operating system CSPRNG.

| Primitive | Parameters | Used for |
|---|---|---|
| AES-256-GCM | 96-bit nonces, 128-bit tags | Every byte of ciphertext |
| Argon2id | Default 64 MiB, t=4, p=4; stored per container | Password → KEK |
| HKDF-SHA256 | Random 32-byte salt per object | Master/subkey separation and index-log keys |
| SHA-256 | — | Blob path derivation and per-entry content hashes |
| `subtle::ConstantTimeEq` | — | Secret comparisons where needed |

### KDF parameter bounds

Parameters travel inside containers so defaults can evolve. Because they are
attacker-visible input, parsing enforces hard bounds to prevent denial of
service:

| Field | Default | Accepted range when reading |
|---|---|---|
| `m_cost_kib` | 65,536 (64 MiB) | 8 MiB – 4 GiB |
| `t_cost` | 4 | 1 – 64 |
| `p_cost` | 4 | 1 – 16 |

A hostile container can force at most a bounded amount of derivation work —
never unbounded allocation or an infinite loop.

## Key hierarchy

Two derivations exist, selected per container by a kind byte.

```text
Standalone .krs (kind = password):

  password ──Argon2id(argon_salt, params)──► KEK
           ──HKDF(object_salt, info)───────► content key

Vault objects (kind = hkdf):

  vault.config: password ──Argon2id(slot salt, params)──► KEK
                ──AES-GCM-wrap──► master key

  entry blob:   master ──HKDF(object_salt, "keres-container-v1/" ‖ entry_id)──► content key
  manifest:     master ──HKDF(object_salt, "keres-container-v1/vault-manifest")──► content key
  index log:    master ──HKDF(log_id, "keres-vault-index-log-v1")──► log key
```

Properties that follow:

- **Per-object keys.** Every object has a fresh 32-byte object salt and an
  independent HKDF subkey.
- **Password changes do not touch ciphertext.** Only the wrapped master key
  in `vault.config` is re-encrypted.
- **No offline verifier.** There is no password hash to check guesses against;
  every guess costs a full Argon2id run plus GCM verification.
- **Renames do not re-encrypt.** Vault blobs are bound to a stable random entry
  ID, not to the mutable path.

## The universal container format

Every object the library produces — `.krs` files, vault blobs, manifests — is
one envelope. It is defined in `src/container.rs`; constants are public where
meaningful (`MAGIC`, `ENVELOPE_VERSION`).

### Wire layout

```text
offset  size                     field
────────────────────────────────────────────────────────────────
0       8    "KERES\0\0\0"          magic (NUL is a control byte:
                                  cannot occur in ordinary text)
8       2    u16 LE               envelope version (1, or 2 with padding)
10      1    kind                 0 = HKDF-from-master
                                  1 = password-derived
11      32   (kind 0)             object_salt
11      76   (kind 1)             argon_salt[32] ‖ object_salt[32]
                                  ‖ KdfParams[12] (three u32 LE)
…       var  chunk records         [len u32 LE][ciphertext‖tag], repeated
…       4    00 00 00 00          end-of-chunks marker (unauthenticated;
                                  safe — see below)
…       4    len u32 LE           trailer length (≤ 1 MiB enforced)
…       len  trailer              AES-GCM ct‖tag of JSON
```

Header sizes: 43 bytes for kind 0 and 87 bytes for kind 1. Padded containers
add a 25-byte authenticated prelude after the header (see
[Size padding](#size-padding)).

### Header authentication

There is no separate header MAC. The header is authenticated implicitly: the
magic and version are checked directly, while the kind, salts, and KDF
parameters feed key derivation. Flipping any of those bytes yields a wrong
key or an early parse error, so the first GCM tag check fails.

Any file whose magic is not exactly `KERES\0\0\0` is rejected with
`Error::IncompatibleFormat`. That includes pre-rename Krypton containers,
pre-0.4 formats, and unrelated files. A newer envelope version fails with
`UnsupportedVersion`. Vaults are the one exception: a readable 0.5.x manifest
is reported as `MigrationRequired` and can be upgraded with `keres migrate`.

### Trailer

After the chunk section, one final record carries a JSON document sealed with
the same content key under the reserved nonce `[0xFF; 12]`:

```json
{
  "typ": "file" | "directory" | "manifest",
  "name": "original-filename.txt",
  "size": 12345,
  "chunk_count": 1
}
```

`name` is present for standalone `.krs` files and absent for vault objects.
On read, the trailer is cross-checked against observation:

- `typ` must equal the caller-requested payload type;
- `size` must equal the decrypted byte count;
- `chunk_count` must equal the number of records read;
- nothing may follow the trailer.

Truncation, extension, and appended-junk attacks fail here even if a naive
reader would have accepted a valid prefix.

### Identity binding

Containers carry a caller-supplied identity string that participates in key
derivation: `info = "keres-container-v1/" ‖ identity`.

| Object | Identity | Effect |
|---|---|---|
| Vault entry blob | Stable random entry ID, e.g. `"00112233…"` | Copying one entry's blob over another's slot fails authentication; renaming does not invalidate a blob |
| Manifest | `"vault-manifest"` | Fixed constant; the manifest location is canonical |
| Standalone `.krs` | Empty | Files are self-contained; there is nothing to bind |

Each entry gets a random 128-bit ID when it is added. The ID is stored in the
manifest and never changes, so blob location and AAD are independent of the
entry's mutable path. This closes the blob-transplant attack: swapping two
blobs in the vault directory yields `Corrupted` entries from `verify()` and
errors on extract, never silently wrong content. The authenticated index also
records the plaintext SHA-256, so replaying an older valid blob under the same
entry ID is rejected.

### Payload types

`PayloadType` has three variants: `File`, `Directory`, and `Manifest`. Adding
a new container kind means adding a variant with a new AAD context string —
never changing existing ones.

## Chunking, nonces, and AAD binding

`src/stream.rs` implements record framing shared by all containers.

### Chunk records

Plaintext streams through in 64 KiB chunks (`CHUNK_SIZE`). Each becomes one
record: `[len u32 LE][ciphertext ‖ 16-byte GCM tag]`. Lengths outside
`16 ..= 64 KiB + 16` are rejected before allocation. There is no compression,
so there is no decompression-bomb analogue.

The maximum object size is `2^24` chunks × 64 KiB = **1 TiB**. The
`MAX_CHUNK_COUNT` guard prevents nonce-space exhaustion and counter overflow.

### Nonce strategy

| Record type | Nonce | Rationale |
|---|---|---|
| Data chunk *i* | `[0x00; 4] ‖ i as u64 BE` | Counter-based; collision-free within an object regardless of restarts |
| Padding metadata | `[0xFE; 12]` | Reserved domain, distinct from data and trailer |
| Trailer | `[0xFF; 12]` | Reserved domain, distinct from data |
| Config slot | Random 96-bit nonce | Fresh wrapping per slot write |
| Recovery kit | Random 96-bit nonce | Fresh wrapping per kit |
| Index-log record | Random 96-bit nonce | Fresh nonce per record under a per-log key |

Counter nonces eliminate the birthday-bound reuse risk of random nonces per
chunk. Combined with per-object salts, every (object, position) pair has a
unique `(key, nonce)` tuple.

### AAD matrix

Every GCM operation binds context. Nothing is decrypted "bare":

| Operation | AAD |
|---|---|
| Data chunk *i* | `"keres-container-v1/{file\|directory\|manifest}"` ‖ index bytes |
| Padded metadata | `"keres-container-v2/padding"` |
| Trailer | chunk context ‖ index ‖ `"/trailer"` |
| Config slot | `"keres-vault-config-v3/"` ‖ slot id |
| Recovery kit | `"keres-vault-recovery-v1"` |
| Index-log record | `"keres-index-log-v1"` ‖ log header ‖ record index |

Consequences:

- Reordering two chunks fails authentication.
- Moving a record between positions fails.
- Moving records between payload types fails because the context differs.
- Transplanting whole containers between logical locations fails because key
  derivation differs.
- The end-of-chunks marker is unauthenticated but harmless: it cannot be
  forged into extra data because the authenticated trailer's `chunk_count` and
  `size` must match observation exactly.

## Single-file mode

`encrypt_file(password, input, output)`:

1. Generates a fresh `argon_salt` and `object_salt`.
2. Builds a kind-1 container streaming the file (identity = empty) and stores
   the original filename in the trailer.
3. Writes atomically: temp file (mode `0600`) in the destination directory →
   `fsync` → `rename`. On Windows, `rename` replaces the destination via
   `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`, with no pre-delete window.
4. If no output path is given, produces
   `<sha256(argon_salt ‖ object_salt)>.krs` — an opaque name that leaks
   nothing about content.

`decrypt_file(password, input, output)` authenticates the whole container
while streaming, recovers the original filename from the trailer, sanitizes
it, and returns it. Plaintext is also written through temp + rename.

Memory use is bounded by one chunk buffer (plus tag) regardless of file size.

### Streaming API

`keres::streaming` exposes the same wire format to library code that does not
have files:

| Type / function | Direction |
|---|---|
| `EncryptWriter` | `Write`: plaintext in, ciphertext out; `finish()` writes the trailer |
| `DecryptReader` | `Read`: ciphertext in, authenticated plaintext out; EOF verifies the trailer |
| `encrypt_stream` / `decrypt_stream` | Convenience loops that preserve the typed `Error` |

`StreamOptions` adds a cumulative-byte progress callback and an `AtomicBool`
cancellation flag polled once per chunk. Cancellation returns
`Error::Cancelled`; through the `io` adapters it is wrapped in an
`io::Error`, with the typed error recoverable from its source.

Every chunk is authenticated before its plaintext is yielded, but the trailer
holds the total size and chunk count, so a truncated or trailer-tampered
stream can deliver authenticated plaintext before the final error. File
writers should stage output through temp + rename, exactly as `decrypt_file`
does. This is inherent to streaming, not a weakness in chunk authentication.

## Vault layout

A vault is a directory:

```text
myvault/
├── vault.config              bootstrap JSON: keyslots wrapping the master key
├── vault.recovery            optional second wrapping (recovery kit)
├── vault.rotate              transient deep-rotation journal
├── vault.lock                advisory inter-process lock (empty)
└── d/
    ├── .manifest.enc         compacted index snapshot (kind-0 container)
    ├── .index.log            encrypted append-only mutations
    ├── .index.compact        transient compaction journal
    ├── .manifest.enc.next    staged manifest during rotation
    ├── .index.log.next       staged log during compaction
    ├── .index.snapshot.next  staged snapshot during compaction
    └── <h2>/<h48>.enc        one blob per entry
```

Every mutation takes an exclusive advisory lock on `vault.lock`; reads
(`list`, `extract`, `verify`) take a shared lock. Locks are non-blocking: a
second process receives `Error::VaultBusy` instead of waiting and racing on a
stale index. The lock is released when the operation returns. `flock(2)` is
used on Unix and `LockFileEx` on Windows via `fs4`.

If a rotation or index compaction committed but did not finish, the next
operation that takes the lock recovers it first. A reader that only needs a
shared lock silently upgrades to the exclusive lock for that recovery step.

### vault.config

`vault.config` is a small JSON document — not a container, because it must be
parseable before any key exists. Version 3 holds a table of independent
keyslots, each wrapping the same master key under its own password-derived
KEK:

```json
{
  "version": 3,
  "slots": [
    {
      "id": "0123456789abcdef",
      "kdf": {"m_cost_kib": 65536, "t_cost": 4, "p_cost": 4},
      "salt": [/* 32 bytes */],
      "nonce": [/* 12 bytes */],
      "wrapped_master_key": [/* master ‖ GCM tag */]
    }
  ]
}
```

The master key is generated once at `init`. Each slot has a fresh random salt,
a random 96-bit nonce, and AAD `"keres-vault-config-v3/" + slot_id`, so
wrapped keys cannot be transplanted between slots. Unlocking tries each slot;
`change_password` re-wraps only the slot that matched; `add_keyslot` appends a
slot; `remove_keyslot` deletes one and must be authorized by a passphrase from
a slot that remains. Slot ids are plaintext, like the rest of the bootstrap
structure. Wrong password and tampered config are both `Authentication`; a
structurally malformed slot is `InvalidVault`.

Version 2 configs (the 0.5.x single implicit slot, fixed nonce, AAD
`"keres-vault-config-v2"`) are still read and are rewritten as version 3 the
next time a key operation changes the config. The existing password does not
change during that upgrade.

### vault.recovery

Optional. Created by `keres recovery create` /
`Vault::create_recovery_kit`: a second, independent wrapping of the same
master key.

```json
{
  "version": 1,
  "kdf": {"m_cost_kib": 65536, "t_cost": 4, "p_cost": 4},
  "salt": [/* 32 bytes */],
  "nonce": [/* 12 bytes */],
  "wrapped_master_key": [/* master ‖ GCM tag */]
}
```

The KEK is Argon2id over a random 160-bit code, printed once as nine groups of
four Crockford Base32 symbols with a 16-bit checksum. The code is never
stored. The file is not a container because it must be parsed before any key
exists; AEAD with a random nonce and AAD `"keres-vault-recovery-v1"`
authenticates it.

`Vault::recover` validates the unwrapped master against the encrypted index,
re-wraps `vault.config` as a fresh single-slot config, and consumes the kit.
Losing `vault.config` no longer bricks the vault; losing the code still does.
Any extra keyslots are lost in recovery and must be re-added.

### vault.rotate

`Vault::rotate` / `keres rotate` performs an opt-in **deep rotation**: it
generates a fresh master key, streams every blob through re-encryption, and
rewrites the index under the new key. The new config has exactly one keyslot
under the new password; other keyslots and the recovery kit wrapped the old
master key and are discarded.

Rotation writes `d/.manifest.enc.next`, then a small `vault.rotate` journal
containing the new config (already wrapped) and the SHA-256 of the staged
manifest — never a plaintext key:

```json
{
  "version": 1,
  "manifest_sha256": "…64 hex…",
  "config": "{…v3 config…}",
  "old_blobs": ["d/ab/cd….enc", "…"]
}
```

The journal write is the commit point. After it, the staged manifest is
renamed over `.manifest.enc`, the config is replaced, the old recovery kit is
removed, and the journal is deleted. If the process dies after the journal but
before completion, the next operation that opens the vault finishes the swap:
it compares the journal hash against the canonical and staged manifests,
promotes the staged one when it matches, and installs the config. If neither
manifest matches, the rotation is rolled back and the journal is discarded.
Before the journal exists, the old vault is untouched and the staged blobs are
ordinary orphans for `prune_orphans`.

`old_blobs` lists the old-key ciphertext paths so recovery can delete them
even though the old master is no longer available. Only paths under `d/`
ending in `.enc` (other than `.manifest.enc`) are accepted. Rotation removes
them best-effort after the swap; leftovers are reclaimed by
`verify --prune`.

`Vault::erase` reuses this machinery: the entry to erase is added to the
rotation's removed set, so omission and re-encryption commit together. If
rotation fails, the old vault (including the entry) is left intact.

### Blob locations

```text
blob_path(entry_id) = d / sha256(master_key ‖ entry_id)[..2] /
                          sha256(...)[2..50] + ".enc"
```

Paths are deterministic (stable across restarts and renames), keyed by the
master key (so unrelated vaults never share blob names), and leak nothing but
entry count and rough sizes via the tree shape. Because the hash input is the
entry's stable ID rather than its path, renaming an entry only updates the
encrypted index; no ciphertext is re-encrypted.

### Index: snapshot + append-only log

The logical index is a `BTreeMap<String, EntryMetadata>` serialized to JSON.
Each entry records a non-empty 128-bit hex `id`, original name, size,
directory flag, child lists, and an optional SHA-256 of the plaintext
(`content_hash`). The hash binds a blob to the exact contents recorded by the
index; it is `None` for entries written by releases before the field existed,
which are size-checked only.

The index is stored in two parts:

- `d/.manifest.enc` — a compacted snapshot, written as a kind-0 container with
  payload type `Manifest`.
- `d/.index.log` — encrypted, authenticated mutation batches appended after
  that snapshot.

Saving an operation does **not** rewrite the whole snapshot. The library loads
the logical index (snapshot plus replayed log), computes the `put`/`delete`
records that turn it into the new map, and appends one batch. Reading decodes
the snapshot once and replays each batch in order.

```text
log header:  b"KERESIDX" | version u16 | generation u64 |
             snapshot_sha256[32] | log_id[32]
log record:  len u32 | index u64 | nonce[12] | ciphertext ‖ GCM tag
```

Each log gets a random `log_id`; its record key is
`HKDF(master, log_id, "keres-vault-index-log-v1")`. Record AAD binds the full
header bytes and the record index, so records cannot be moved between logs,
reordered, or replayed under another generation. The header's snapshot hash
ties the log to exactly one snapshot: mixing a log with a different snapshot
is `InvalidVault`, and a log whose key does not authenticate is
`Authentication`.

The snapshot's authenticated JSON also carries a monotonic `generation`
(pre-generation v3 snapshots read as `0`). A log must declare the same
generation as the snapshot it extends; a mismatch is `InvalidVault`.
Compaction writes `generation + 1` into the new snapshot and its empty log.
Generations make replace/compaction swaps unambiguous, but without
hardware-backed state they are not rollback detectors.

A log batch is written with one `write_all` plus `sync_data`. A crash may
leave a torn final record; replay stops at the last valid record and the next
append truncates the tail. Damage in the middle of the log is an error, never
a silent truncation.

When the log reaches 512 records or 8 MiB, the next save compacts it: a fresh
snapshot is written, a new empty log is created that names it by SHA-256, and
the old log is removed. Compaction is journaled in `d/.index.compact`; an
interrupted compaction is finished on the next lock acquisition. Deep rotation
and migration install a new snapshot and remove any log encrypted under the
old index key.

Version 2 manifests are rejected by the reader with `MigrationRequired` (and
an empty ID in a version 3 manifest is rejected as `InvalidVault`; IDs are the
root of blob identity, so a missing one cannot be repaired safely).
`Vault::migrate` / `keres migrate` upgrades a v2 vault in place: it
re-encrypts every entry under a fresh ID, then commits the v3 snapshot
atomically. A failure before that commit leaves the legacy manifest intact.

Load semantics:

| State | Result |
|---|---|
| Snapshot absent | **error** — only `init` creates the first snapshot; treating it as empty would drop every record on the next save |
| Snapshot present but damaged, truncated, or unauthentic | **error** — never silently empty |
| Log present but snapshot absent, or bound to another snapshot/generation | **error** |
| Snapshot larger than the 64 MiB read cap | rejected before allocation |

### Vault operations

| API | Behavior |
|---|---|
| `init(pw)` | Creates the directory (mode `0700`) and empty index snapshot, then writes the config; refuses to clobber a config-less vault that still has a recovery kit |
| `unlock` / `lock` | Unwraps the master into memory / drops it |
| `add(src, name)` | Validates a single-component root name, rejects collisions, pre-flights directories, writes every blob via temp + rename, appends the index batch last |
| `replace(src, name)` | Writes a fresh blob under a new entry ID (copy-on-write), appends the index record, then deletes the old blob; directory entries are rejected |
| `rename(from, to)` | Top-level only; pre-checks every destination in the moved subtree; appends `put` records for new keys and child lists without touching ciphertext |
| `add_if` / `replace_if` | Conditional variants; return `WriteOutcome` and write nothing when the precondition fails |
| `apply_batch(ops)` | Applies adds/replaces/removes with one index commit; old blobs are deleted after the commit |
| `list()` | Reads snapshot + log only; no blobs touched |
| `extract(name, dest)` | Recreates hierarchy, sanitizes names, verifies size and content hash, writes outputs via temp + rename |
| `remove(name)` | Drops subtree index records and commits, then deletes blobs best-effort; a failed deletion leaves a pruneable orphan, never a dangling index |
| `erase(name, new_pw)` | Omits the subtree and performs a deep rotation in one journaled commit; on failure the old vault and entry remain |
| `change_password(old, new)` | Verifies old, re-wraps only that keyslot; ciphertext and other slots untouched |
| `rotate(old, new)` | Deep rotation: fresh master key, all blobs re-encrypted, snapshot rewritten, old log removed; collapses to one keyslot, removes the recovery kit, leaves the vault locked |
| `keyslots()` | Lists plaintext slot ids; no password required |
| `add_keyslot(existing, new)` | Verifies an existing passphrase and appends an independent slot; upgrades a legacy config |
| `remove_keyslot(id, pw)` | Revokes a slot, authorized by a passphrase from a slot that remains; the last slot is refused |
| `verify(pw)` | Decrypts every blob (type-checked), checks size and content hash against the replayed index; returns `IntegrityReport` |
| `prune_orphans()` | Deletes `.enc` blobs and stale `.tmp-*` files under `d/` that no index record references; refuses if the snapshot is missing |
| `migrate(pw)` | One-way v2 → v3 upgrade: re-encrypts every entry under a fresh ID, swaps the snapshot atomically, then removes legacy blobs |
| `create_recovery_kit(pw)` | Verifies the password, writes `vault.recovery`, returns a one-time `RecoveryCode` |
| `recover(code, new_pw)` | Unwraps the master with the code, validates it against the index, re-wraps the config, consumes the kit |

Directory removal walks the manifest's own child lists (and the `/`-prefixed
range, so a stale child list cannot strand descendants), so removing a
directory removes everything beneath it even if nested names were added out of
order.

### Path-traversal defense

Names recovered from trailers and manifests pass through `src/sanitize.rs`:
absolute paths, `..` components, drive letters, separators, and NUL bytes are
rejected or rewritten before joining. An encrypted archive cannot plant files
outside the destination.

## Crash safety and durability

Invariant: a crash may lose the *current* operation, never corrupt *previous*
state.

- All persistent writes go through: create a temp file in the same directory →
  restrict to owner-only → write → `sync_all()` → `rename()` over the target
  → `sync_dir()` on the parent directory.
- Containers and snapshots are immutable once written; updates replace whole
  files via temp + rename. The index log is the one append-in-place file; it is
  record-framed so a torn final write is detected and truncated.
- A failure mid-add leaves unreferenced blobs (the index batch was not
  appended). They are invisible to readers and reclaimed by
  `verify --prune` / `Vault::prune_orphans`.
- Replaces are copy-on-write: a fresh blob and entry ID are written, the index
  is committed, and only then is the old blob deleted. A failed replace leaves
  the previous version fully readable.
- Removals commit the index first and delete blobs afterwards, so a deletion
  failure can leave an orphan but never an index that points at missing data.
- `apply_batch` writes all new blobs and computes the final index in memory
  before its single commit. A failure leaves the index unchanged; fresh blobs
  become pruneable orphans.
- Deep rotation commits through `vault.rotate` before touching the canonical
  index, so an interrupted run is either rolled back or completed on the next
  open. A staged `.manifest.enc.next` without a journal is ignored.
- Index compaction commits through `d/.index.compact` before the snapshot/log
  swap. An interrupted run promotes or discards the staged pair on the next
  lock acquisition; staged files without a journal are deleted.

## Memory hygiene

- Every key is `Key(Zeroizing<[u8; 32]>)`; plaintext buffers that contain
  secrets (master key, manifest JSON, trailer records) use
  `Zeroizing<Vec<u8>>`. They are overwritten on drop.
- `Debug` for `Key` prints `Key([REDACTED])`; keys are passed by reference and
  never serialized or logged.
- Chunk buffers are reused; scratch vectors holding secret material are
  zeroizing types.
- Not implemented by design, because `forbid(unsafe_code)` blocks the calls:
  `mlock` and core-dump suppression. These are roadmapped behind a small
  audited unsafe boundary.

## Size padding

By default a container's ciphertext length tracks its plaintext length. That
leaks the file size to anyone who can measure the storage medium. Opt-in
padding rounds the plaintext up to a bucket before encryption, so an observer
learns only the bucket.

Padding is selected per container:

- `.krs`: a `Padding` passed to `encrypt_file_with_padding` (CLI:
  `--padding`).
- Vault: a `Padding` stored in the authenticated index snapshot
  (`ManifestFile.padding`, default `None`), so a storage attacker cannot
  silently disable it. `Vault::padding` / `set_padding` expose it.
- Manifests and directory placeholders are always unpadded.

When padding is not `None`, the container uses **envelope version 2**. The
wire layout gains one authenticated fixed-width (25-byte) record after the
header and before the chunk section:

```text
8 real size (BE) ‖ 8 padded size (BE) ‖ 1 mode ‖ 8 fixed bucket (BE)
```

It is sealed under nonce `[0xFE; 12]` with AAD `keres-container-v2/padding`.
The chunk section then contains exactly `padded_size` plaintext bytes: the
real bytes followed by zero-filled padding. Chunk boundaries depend only on
`padded_size`, so the last record's length reveals only the bucket. The
trailer's `size` field binds the **padded** length, so its variable-length
JSON does not leak the number of digits in the real size. On read, the reader
trims to the real size from the prelude and normalizes `trailer.size` to it
before returning.

Policies (`Padding`):

- `None` — no padding (default, compact format).
- `Adaptive` — next power of two, clamped to `[4 KiB, 16 MiB]`; larger
  payloads round to the next multiple of 16 MiB.
- `Fixed { size }` — next multiple of `size`, which must lie in the same
  range.

`DecryptReader` supports v2 containers and yields only real plaintext.
`EncryptWriter` remains unpadded because it cannot know the total length
upfront.

## Compatibility and versioning

Rules that keep the ecosystem stable:

1. The 8-byte magic **never changes**, including the NUL control bytes.
2. Envelope revisions bump the `u16` version field; readers reject unknown
   versions with `UnsupportedVersion`. Released versions remain readable.
3. A released `PayloadType` never changes meaning. New object kinds are new
   types with new AAD contexts.
4. Schema-bearing payloads (config v3, manifest v3) carry their own inner
   version integers, checked after authentication.
5. Only the current format is accepted. Any other magic returns
   `IncompatibleFormat`; extract old data with the release that wrote it, then
   re-add it. A 0.5.x vault manifest (v2) returns `MigrationRequired` and is
   upgraded in place with `keres migrate`.
6. Vault directories are forward-only. Since 0.7 a vault may contain an
   append-only `d/.index.log`; pre-0.7 releases do not know about it and can
   silently show or write a stale index. Do not alternate releases on the same
   vault directory.
7. The Rust API is not stable before 1.0. The container format and on-disk
   vault layout are the compatibility contract.

## Error taxonomy

One enum (`Error`, via `thiserror`), with `Result<T> = std::result::Result<T, Error>`:

| Variant | Meaning |
|---|---|
| `Authentication` | Wrong password/key **or** any tampering — indistinguishable on purpose |
| `InvalidHeader` | Malformed kind, lengths, or trailer |
| `UnsupportedVersion(u32)` | Envelope/schema/config version newer than supported |
| `MigrationRequired` | Legacy vault manifest; run `keres migrate` |
| `IncompatibleFormat` | File is not a current Keres container |
| `InvalidVault` | Vault structure problems (bad config, damaged manifest) |
| `VaultLocked` / `VaultUnlocked` | State-machine misuse |
| `VaultBusy` | Another process holds the vault lock |
| `Cancelled` | A streaming operation was stopped by its cancellation flag |
| `EntryExists` / `EntryNotFound` | Name conflicts |
| `Conflict` | A conditional write's precondition failed; the vault was not modified |
| `InvalidEntryName(String)` | Validation failure (preview truncated to 32 characters) |
| `Operation(String)` | User-level operation could not be performed |
| `Io(std::io::Error)` | Filesystem layer |
| `Encryption` / `KeyDerivation` / `InvalidKdfParams` / `MalformedPayload` | Internal/crypto-layer failures |

Callers cannot distinguish "wrong password" from "corrupted file" — both are
`Authentication`. This prevents error messages from becoming a tamper oracle.
