# Krypton

A high-quality Rust **library** for encrypted vaults and single-file encryption with full **metadata protection** - built on AES-256-GCM and Argon2id.

**[Full technical documentation](https://kryptonoss.github.io/documentation)**

See [SECURITY](https://kryptonoss.github.io/security) for the threat model, design decisions and known limitations.

See [ROADMAP](https://kryptonoss.github.io/roadmap) for the upcoming planned work.

If you are interested in contributing to the project, contribution rules are mentioned in [CONTRIBUTING.md](CONTRIBUTING.md).

## Library Usage

```rust
use krypton::{encrypt_file, decrypt_file, Vault};
use std::path::Path;

// Single file: filename is encrypted inside the container.
let out = encrypt_file("correct horse", Path::new("document.pdf"), None)?;
let original_name = decrypt_file("correct horse", &out, Path::new("restored.pdf"))?;
assert_eq!(original_name, "document.pdf");

// Multi-file encrypted vault.
let mut vault = Vault::new("myvault".into());
vault.init("correct horse")?;
vault.unlock("correct horse")?;
vault.add(Path::new("secret.pdf"), None)?;
vault.add(Path::new("photos"), Some("photos"))?; // whole trees
let entries = vault.list()?;
vault.extract("photos", Path::new("./restored"))?;
vault.change_password("correct horse", "new password")?; // no re-encryption needed
vault.lock();
```

### Public API

| Module | Contents |
|---|---|
| `krypton::*` | `encrypt_file` / `decrypt_file` (`.krf` containers), `Vault`, `EntryInfo`, `IntegrityReport` |
| `krypton::crypto` | Low-level primitives: `Key`, `seal`/`open` (AAD), `derive_key`, HKDF subkeys, constant-time compare |
| `krypton::kdf` | `KdfParams` — Argon2id parameters with validation bounds |
| `krypton::sanitize` | Entry-name validation / traversal defense |
| `krypton::error` | `Error`, `Result` |

Run `cargo doc --open` for full documentation with examples on every public item.

## Security Features

- **AES-256-GCM** authenticated encryption for every byte of ciphertext
- **Argon2id** key derivation (64 MiB, t=4) with parameters *stored in each container*, so defaults can evolve without breaking old files
- **Per-object subkeys** via HKDF-SHA256 — every file gets an independent content key
- **Deterministic counter nonces** per chunk — eliminates random-nonce birthday collisions on large files and makes reordering detectable
- **AAD everywhere** — chunk index and record context are bound into each AEAD operation; truncation, splicing and extension are all detected
- **Streaming** — 64 KiB chunks with constant memory use; files of any size
- **Metadata privacy** — original filenames never appear unencrypted; `.krf` outputs get random hashed names
- **Hardened memory** — keys live in zeroizing buffers, scrubbed on drop; `#![forbid(unsafe_code)]`
- **Crash safety** — configs, manifests and plaintext outputs are written via temp file + rename; interrupted operations never leave half-written data or bricked vaults
- **Traversal defense** — names recovered from containers are sanitized before touching the filesystem
- **One universal container format** — `.krf` files, vault blobs and manifests share a single envelope; new object types are new payload types, never new formats

## File Format

Every object is a *krypton container*:

```
"KRYPTON\0"       magic (8 bytes, never changes)
[u16 LE]          envelope version (currently 1)
[u8 kind]         key derivation:
                    0 = HKDF(master key, object salt[32])          — vault objects
                    1 = Argon2id(password, salt[32], params[12])
                        then HKDF with object salt[32]             — .krf files
[len u32][ct‖tag] …   chunk records (64 KiB plaintext each)
[00000000]        end-of-chunks marker
[len u32][ct‖tag] authenticated trailer: {type: file|directory|manifest,
                                           name?, size, chunk_count}
```

Header bytes are bound to key derivation; the payload type is bound into
every record's AAD, so records cannot be transplanted between containers.

### Vault

```
vault/
├── vault.config        JSON v2: wrapped master key + KDF params (atomic writes)
└── d/
    ├── .manifest.enc   encrypted index incl. directory child lists
    └── <hash>/<hash>.enc  per-entry blobs
```

Entry paths are derived from `SHA256(master_key ‖ path)`; blob contents use per-entry subkeys. Directory removal deletes the entire subtree — blobs and manifest records alike.

## Key Hierarchy

```
Password ──Argon2id(salt) -> KEK ──AES-GCM-wrap -> vault.config holds Master Key -> SHA256(master ‖ path) → blob location
                                                                    │ 
                                            HKDF(master, per-file salt) → content key
                                                                    │
                                            counter nonces + AAD(index) → AES-GCM chunks
```

Changing the password only re-wraps the master key — stored data is never re-encrypted.

## Development

```bash
cargo test         # 55 tests: unit, integration, doc examples
cargo clippy       # clean
```

## License

Licensed under [Apache-2.0](LICENSE).
