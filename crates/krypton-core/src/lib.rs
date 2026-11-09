//! # krypton
//!
//! Encrypted vaults and single-file encryption with full metadata
//! protection, built on AES-256-GCM and Argon2id.
//!
//! ## Highlights
//!
//! * **Authenticated encryption** — every byte of ciphertext is covered by a
//!   GCM tag; headers are bound through key derivation and AAD.
//! * **Memory-hard key derivation** — Argon2id (64 MiB, t=4) with parameters
//!   stored inside each container so they can evolve without breaking old
//!   files.
//! * **Per-object subkeys** — HKDF-SHA256 derives an independent content key
//!   per file; deterministic counter nonces eliminate random-nonce collision
//!   risk on large files.
//! * **Streaming** — 64 KiB chunks with constant memory use for files of any
//!   size.
//! * **Metadata privacy** — original filenames never appear unencrypted,
//!   neither in `.krf` containers nor inside vaults.
//! * **Crash safety** — vault configs, manifests and outputs are written via
//!   temp file + rename; interrupted operations never leave half-written
//!   plaintext or bricked containers.
//! * **Hardened memory** — keys live in [`zeroize::Zeroizing`] buffers and
//!   are scrubbed on drop.
//!
//! ## Quick start
//!
//! ```no_run
//! use std::path::Path;
//!
//! // Single file round trip.
//! let out = krypton::encrypt_file("correct horse", Path::new("document.pdf"), None).unwrap();
//! let name = krypton::decrypt_file("correct horse", &out, Path::new("restored.pdf")).unwrap();
//! assert_eq!(name, "document.pdf");
//!
//! // Multi-file vault.
//! let mut vault = krypton::Vault::new("myvault".into());
//! vault.init("correct horse").unwrap();
//! vault.unlock("correct horse").unwrap();
//! vault.add(Path::new("secret.pdf"), None).unwrap();
//! for e in vault.list().unwrap() {
//!     println!("{} ({} bytes)", e.name, e.size);
//! }
//! vault.lock();
//! ```
//!
//! ## Choosing an API
//!
//! * **One file in, one file out?** Use [`encrypt_file`] / [`decrypt_file`].
//!   The container is self-contained: it carries the KDF parameters and the
//!   original filename inside the encryption boundary.
//! * **Many files with one password?** Use [`Vault`]. Entries keep their
//!   names encrypted, whole directory trees can be stored and restored, and
//!   the password can be changed later without re-encrypting data.
//! * **Building blocks only?** The [`crypto`] module exposes the AEAD, key
//!   type and derivation functions used internally.
//!
//! ## Error handling
//!
//! All fallible operations return [`Result`] with a small [`Error`] enum.
//! Wrong passwords and tampered ciphertext deliberately map to the same
//! [`Error::Authentication`] variant so error messages never leak which one
//! occurred:
//!
//!
//! ```
//! use krypton::{decrypt_file, Error};
//! use std::path::Path;
//!
//! match decrypt_file("pw", Path::new("backup.krf"), Path::new("out.bin")) {
//!     Ok(original_name) => println!("restored {original_name}"),
//!     Err(Error::Authentication) => eprintln!("wrong password or corrupted data"),
//!     Err(e) => eprintln!("failed: {e}"),
//! }
//! ```
//!
//! ## Security model
//!
//! See `SECURITY.md` in the repository for the full write-up including
//! threat model and known limitations. In short: confidentiality and
//! integrity against attackers with read/write access to the stored files,
//! as long as the password remains secret. The tool does not hide file sizes
//! beyond filename padding, does not provide plausible deniability, and — as
//! with all password-based encryption — security ultimately rests on password
//! strength.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// Universal encrypted container format shared by all objects.
pub(crate) mod container;
/// Cryptographic primitives: keys, AEAD, KDF.
pub mod crypto;
/// Error types.
pub mod error;
mod fsutil;
/// Argon2id parameter types.
pub mod kdf;
/// Entry-name validation helpers.
pub mod sanitize;
/// Single-file `.krf` containers.
mod single_file;
/// Chunked streaming encryption engine.
mod stream;
/// Multi-file encrypted vaults.
pub mod vault;

/// Convenience re-exports covering everyday use.
pub mod prelude {
    pub use crate::crypto::Key;
    pub use crate::error::{Error, Result};
    pub use crate::single_file::{decrypt_file, encrypt_file};
    pub use crate::vault::{EntryInfo, IntegrityReport, Vault};
}

pub use error::{Error, Result};
pub use single_file::{decrypt_file, encrypt_file};
pub use vault::{EntryInfo, IntegrityReport, Vault};

/// Crate version, handy for CLI `--version` output.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
