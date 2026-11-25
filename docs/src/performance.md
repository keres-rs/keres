# Performance

Keres is built for streaming and bounded memory, not for benchmark records.
Throughput is dominated by AES-256-GCM and by Argon2id for the first key
derivation. This page explains where time goes and how to measure it.

## Representative measurements

The following numbers come from a development machine in August 2026 (x86_64,
AES-NI, release build). They are indicative, not a guarantee. Run the
benchmarks on your own hardware before sizing an operation.

| Scenario | Time | Notes |
|---|---|---|
| Encrypt a small file | ~0.19 s | Almost entirely Argon2id (64 MiB, t=4) |
| Encrypt 200 MB | ~0.56 s (~360 MB/s) | Single thread |
| Decrypt 200 MB | ~0.53 s (~380 MB/s) | Byte-identical round trip |
| Vault add, 200 files | ~0.68 s | One unlock plus 200 blob writes |
| Vault list | ~0.17 s | Index only; no blob I/O |
| Vault verify, 201 entries | ~0.18 s | AEAD and content hash over every blob |

### Analysis

- **Argon2id sets the floor for small operations.** Every password-based
  unlock or `.krs` encryption pays the full KDF cost. That cost is the
  brute-force defense; do not lower it casually.
- **Bulk throughput is single-threaded.** 64 KiB chunks and per-record AAD
  construction are cheap, but chunks are processed sequentially. A parallel
  pipeline is on the roadmap and can be added without changing the format,
  because chunks are independent.
- **Vault operations batch well.** Unlock once, then add many entries. After
  unlock, per-entry work is essentially AES plus filesystem writes.
- **`verify` is cheaper than a full rotation** because it does not rewrite
  data, but it still reads and authenticates every byte once.
- **Deep rotation is the most expensive operation.** It reads and rewrites
  every entry under a new master key.

## Measuring locally

The Criterion benchmark covers the container engine and single-file mode:

```console
$ cargo bench -p keres --bench throughput
```

For an end-to-end CLI measurement, use a release build:

```console
$ cargo build --release -p keres-cli
$ /usr/bin/time -v target/release/keres encrypt large.bin out.krs
```

Keep the following fixed when comparing runs:

- release build, same CPU and filesystem;
- same file size and whether it is cached;
- same padding policy (padding increases I/O and changes bucket sizes);
- whether the vault is already unlocked (the CLI unlocks per invocation).

## Memory and storage

- Streaming encryption uses one 64 KiB plaintext buffer plus ciphertext and
  tag space. Memory does not scale with file size.
- Argon2id uses 64 MiB by default per derivation. Several concurrent
  processes each pay that cost.
- Vaults store one ciphertext blob per entry, plus the index snapshot and log.
  Renames do not duplicate blobs; replaces use copy-on-write and briefly need
  space for both versions.
- Padding increases storage: adaptive padding can waste up to the current
  bucket size, and fixed buckets can waste almost a full bucket per entry.

## Limits

- An object is capped at 1 TiB (2^24 chunks of 64 KiB).
- A trailer is capped at 1 MiB.
- A manifest payload is capped at 64 MiB on read.
- Index-log batches are capped at 64 MiB and compacted after 512 records or
  8 MiB.

These limits are hostile-input guards, not tuning knobs.
