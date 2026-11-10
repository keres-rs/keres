//! The universal keres container format.
//!
//! Every encrypted object the library produces — single-file `.krs`
//! containers, vault entry blobs and vault manifests — uses this one
//! envelope. Future object kinds are new trailer payload types, never new
//! formats.
//!
//! # Wire layout
//!
//! ```text
//! b"KERES\0\0\0"     8-byte magic (never changes)
//! [u16 LE = 1]     envelope format version
//! [u8 kind]        key-derivation selector:
//!                    0 = content key is HKDF(master, object_salt[32])
//!                    1 = password-derived: argon2 salt[32] +
//!                        object salt[32] + KDF parameters[12]
//! [kind data]      kind-specific bytes (see above)
//! [len u32][ct||tag] …   chunk records (64 KiB plaintext each)
//! [00 00 00 00]    end-of-chunks marker
//! [len u32][ct||tag]     authenticated trailer record
//! ```
//!
//! All header bytes are bound to key derivation: flipping any of them
//! yields a wrong key and authentication fails. The payload type is bound
//! into every chunk and trailer AAD, so records cannot be transplanted
//! between containers of different types.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::kdf::KdfParams;
use crate::stream;

/// Magic header shared by every Keres container.
///
/// The trailing NUL bytes are control bytes: they prevent the magic from
/// occurring in ordinary text and survive naive character-set mangling.
pub const MAGIC: &[u8; 8] = b"KERES\0\0\0";

/// Current envelope version. Written into every container; readers reject
/// any other value with [`Error::UnsupportedVersion`].
pub const ENVELOPE_VERSION: u16 = 1;

pub(crate) const SALT_LEN: usize = crate::crypto::SALT_LEN;
const HKDF_INFO: &[u8] = b"keres-container-v1";
const KIND_HKDF: u8 = 0;
const KIND_PASSWORD: u8 = 1;

/// What a container holds. Serialized into the authenticated trailer and
/// bound into chunk AAD, so records cannot be transplanted between payload
/// types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadType {
    /// Encrypted file contents (standalone `.krs` or vault blob).
    File,
    /// Directory placeholder (vault only); carries no chunks.
    Directory,
    /// Vault index JSON (vault only).
    Manifest,
}

impl PayloadType {
    fn context(self) -> Vec<u8> {
        let mut c = b"keres-container-v1/".to_vec();
        c.extend_from_slice(match self {
            PayloadType::File => &b"file"[..],
            PayloadType::Directory => &b"directory"[..],
            PayloadType::Manifest => &b"manifest"[..],
        });
        c
    }
}

/// How a container's content key is derived.
#[derive(Debug, Clone)]
pub(crate) enum KeyDerivation {
    /// Content key = HKDF(master key, random per-object salt). Used inside
    /// vaults, where the master key is already unlocked in memory.
    Hkdf {
        /// Random HKDF salt; gives each object an independent subkey.
        object_salt: [u8; SALT_LEN],
    },
    /// Content key = HKDF(Argon2id(password, argon2_salt, params),
    /// object_salt). Used for standalone `.krs` files decryptable from a
    /// password alone.
    Password {
        /// Argon2id salt.
        argon_salt: [u8; SALT_LEN],
        /// Per-object HKDF salt.
        object_salt: [u8; SALT_LEN],
        /// Argon2id cost parameters, stored so defaults can evolve.
        params: KdfParams,
    },
}

impl KeyDerivation {
    fn kind(&self) -> u8 {
        match self {
            KeyDerivation::Hkdf { .. } => KIND_HKDF,
            KeyDerivation::Password { .. } => KIND_PASSWORD,
        }
    }

    fn header_len(&self) -> usize {
        MAGIC.len()
            + 2
            + 1
            + match self {
                KeyDerivation::Hkdf { .. } => SALT_LEN,
                KeyDerivation::Password { .. } => 2 * SALT_LEN + KdfParams::SERIALIZED_LEN,
            }
    }

    fn write_header<W: Write>(&self, w: &mut W) -> Result<()> {
        let mut head = Vec::with_capacity(self.header_len());
        head.extend_from_slice(MAGIC);
        head.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        head.push(self.kind());
        match self {
            KeyDerivation::Hkdf { object_salt } => head.extend_from_slice(object_salt),
            KeyDerivation::Password {
                argon_salt,
                object_salt,
                params,
            } => {
                let mut pbuf = [0u8; KdfParams::SERIALIZED_LEN];
                params.write_to(&mut pbuf);
                head.extend_from_slice(argon_salt);
                head.extend_from_slice(object_salt);
                head.extend_from_slice(&pbuf);
            }
        }
        w.write_all(&head)?;
        Ok(())
    }

    fn parse_header(head: &[u8]) -> Result<Self> {
        if head.len() < MAGIC.len() + 3 || &head[..MAGIC.len()] != MAGIC {
            return Err(retired_or_invalid(head));
        }
        let version = u16::from_le_bytes([head[8], head[9]]);
        if version != ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion(u32::from(version)));
        }
        let body = &head[11..];
        match head[10] {
            KIND_HKDF => {
                if body.len() != SALT_LEN {
                    return Err(Error::InvalidHeader);
                }
                let mut object_salt = [0u8; SALT_LEN];
                object_salt.copy_from_slice(body);
                Ok(KeyDerivation::Hkdf { object_salt })
            }
            KIND_PASSWORD => {
                if body.len() != 2 * SALT_LEN + KdfParams::SERIALIZED_LEN {
                    return Err(Error::InvalidHeader);
                }
                let mut argon_salt = [0u8; SALT_LEN];
                argon_salt.copy_from_slice(&body[..SALT_LEN]);
                let mut object_salt = [0u8; SALT_LEN];
                object_salt.copy_from_slice(&body[SALT_LEN..2 * SALT_LEN]);
                let params = KdfParams::read_from(&body[2 * SALT_LEN..])?;
                Ok(KeyDerivation::Password {
                    argon_salt,
                    object_salt,
                    params,
                })
            }
            _ => Err(Error::InvalidHeader),
        }
    }

    fn content_key(
        &self,
        password: Option<&str>,
        master: Option<&Key>,
        identity: &[u8],
    ) -> Result<Key> {
        let mut info = Vec::with_capacity(HKDF_INFO.len() + 1 + identity.len());
        info.extend_from_slice(HKDF_INFO);
        info.extend_from_slice(b"/");
        info.extend_from_slice(identity);
        match self {
            KeyDerivation::Hkdf { object_salt } => {
                let m = master.ok_or(Error::InvalidHeader)?;
                Ok(crypto::derive_subkey(m, object_salt, &info))
            }
            KeyDerivation::Password {
                argon_salt,
                object_salt,
                params,
            } => {
                let pw = password.ok_or(Error::InvalidHeader)?;
                let kek = crypto::derive_key(pw.as_bytes(), argon_salt, *params)?;
                Ok(crypto::derive_subkey(&kek, object_salt, &info))
            }
        }
    }
}

/// Recognizes retired magics so old files produce a helpful error instead of
/// a generic one. No parsing of retired formats remains.
fn retired_or_invalid(head: &[u8]) -> Error {
    const RETIRED: [&[u8]; 3] = [b"KRYPTON\0", b"KRYPTON2\n", b"KRYPTON3\n"];
    if RETIRED.iter().any(|m| head.starts_with(m)) {
        Error::RetiredFormat
    } else {
        Error::InvalidHeader
    }
}

/// Authenticated trailer describing the whole container.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Trailer {
    /// Payload type; also bound into all record AADs.
    pub typ: PayloadType,
    /// Original filename (single-file `.krs` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Total plaintext length across all chunks.
    pub size: u64,
    /// Number of preceding chunk records.
    pub chunk_count: u32,
}

fn trailer_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(context.len() + 8);
    aad.extend_from_slice(context);
    aad.extend_from_slice(b"/trailer");
    aad
}

/// Writes a complete container: header, chunks streamed from `src`, then
/// the authenticated trailer. Returns `(plaintext_bytes, chunk_count)`.
///
/// `identity` binds the container to its logical location (e.g. a vault
/// entry path); readers must pass the same value or authentication fails.
/// Pass `b""` for self-contained objects. `src: None` yields chunk-less
/// payloads (directory placeholders). Exactly one of `password`/`master`
/// is required, matching `kd`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_container<W: Write>(
    dst: &mut W,
    kd: &KeyDerivation,
    password: Option<&str>,
    master: Option<&Key>,
    typ: PayloadType,
    identity: &[u8],
    src: Option<&mut dyn Read>,
    trailer_name: Option<&str>,
) -> Result<(u64, u32)> {
    let content_key = kd.content_key(password, master, identity)?;
    kd.write_header(dst)?;
    let context = typ.context();

    let (total, count) = match src {
        Some(r) => stream::write_chunks(dst, r, &content_key, &context)?,
        None => (0, 0),
    };

    let mut payload = Zeroizing::new(
        serde_json::to_vec(&Trailer {
            typ,
            name: trailer_name.map(String::from),
            size: total,
            chunk_count: count,
        })
        .map_err(|_| Error::Encryption)?,
    );
    crypto::seal_in_place(
        &stream::TRAILER_NONCE,
        &mut payload,
        &content_key,
        &trailer_aad(&context),
    )?;
    dst.write_all(&stream::CHUNKS_END_MARKER)?;
    dst.write_all(&(payload.len() as u32).to_le_bytes())?;
    dst.write_all(payload.as_slice())?;
    Ok((total, count))
}

/// Reads and authenticates a whole container, streaming plaintext chunks to
/// `sink`. Verifies the trailer against observed bytes and checks the
/// payload type matches `expected`. Returns the trailer.
pub(crate) fn read_container<R: Read>(
    mut inner: R,
    password: Option<&str>,
    master: Option<&Key>,
    expected: PayloadType,
    identity: &[u8],
    sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Trailer> {
    let mut first = vec![0u8; MAGIC.len() + 3];
    inner
        .read_exact(&mut first)
        .map_err(|_| Error::InvalidHeader)?;
    if &first[..MAGIC.len()] != MAGIC {
        return Err(retired_or_invalid(&first));
    }
    let extra = match first[10] {
        KIND_HKDF => SALT_LEN,
        KIND_PASSWORD => 2 * SALT_LEN + KdfParams::SERIALIZED_LEN,
        _ => return Err(Error::InvalidHeader),
    };
    let mut rest = vec![0u8; extra];
    inner
        .read_exact(&mut rest)
        .map_err(|_| Error::InvalidHeader)?;
    first.extend_from_slice(&rest);

    let kd = KeyDerivation::parse_header(&first)?;
    let content_key = kd.content_key(password, master, identity)?;
    let context = expected.context();

    let (total, count) = stream::read_chunks(&mut inner, &content_key, &context, sink)?;

    let mut rec = Zeroizing::new(stream::read_record(&mut inner, stream::MAX_TRAILER_LEN)?);
    crypto::open_in_place(
        &stream::TRAILER_NONCE,
        &mut rec,
        &content_key,
        &trailer_aad(&context),
    )?;
    let trailer: Trailer =
        serde_json::from_slice(rec.as_slice()).map_err(|_| Error::MalformedPayload)?;

    if trailer.typ != expected || trailer.size != total || trailer.chunk_count != count {
        return Err(Error::Authentication);
    }

    // Nothing may follow the trailer.
    let mut probe = [0u8; 1];
    match inner.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => return Err(Error::InvalidHeader),
        Err(e) => return Err(e.into()),
    }
    Ok(trailer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hkdf_kd() -> KeyDerivation {
        KeyDerivation::Hkdf {
            object_salt: [7u8; SALT_LEN],
        }
    }

    fn pw_kd() -> KeyDerivation {
        KeyDerivation::Password {
            argon_salt: [9u8; SALT_LEN],
            object_salt: [8u8; SALT_LEN],
            params: KdfParams {
                m_cost_kib: 8 * 1024,
                t_cost: 1,
                p_cost: 1,
            },
        }
    }

    fn seal(
        kd: &KeyDerivation,
        pw: Option<&str>,
        m: Option<&Key>,
        data: &[u8],
        typ: PayloadType,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut src = Cursor::new(data.to_vec());
        write_container(&mut out, kd, pw, m, typ, b"", Some(&mut src), None).unwrap();
        out
    }

    fn unseal(blob: &[u8], pw: Option<&str>, m: Option<&Key>, typ: PayloadType) -> Trailer {
        let mut collected = Vec::new();
        let t = read_container(Cursor::new(blob.to_vec()), pw, m, typ, b"", |c| {
            collected.extend_from_slice(c);
            Ok(())
        })
        .unwrap();
        assert_eq!(collected.len(), t.size as usize);
        t
    }

    fn unseal_id(
        blob: &[u8],
        pw: Option<&str>,
        m: Option<&Key>,
        typ: PayloadType,
        identity: &[u8],
    ) -> Result<Trailer> {
        read_container(Cursor::new(blob.to_vec()), pw, m, typ, identity, |_| Ok(()))
    }

    #[test]
    fn roundtrip_both_kinds_and_types() {
        let master = Key::generate();
        let cases: [(KeyDerivation, Option<&str>, Option<&Key>, PayloadType); 3] = [
            (pw_kd(), Some("pw"), None, PayloadType::File),
            (hkdf_kd(), None, Some(&master), PayloadType::Manifest),
            (hkdf_kd(), None, Some(&master), PayloadType::Directory),
        ];
        for (kd, pw, m, typ) in cases {
            for data in [&b""[..], b"hello", &[42u8; 200_000][..]] {
                let blob = seal(&kd, pw, m, data, typ);
                let t = unseal(&blob, pw, m, typ);
                assert_eq!(t.typ, typ);
                assert_eq!(t.size, data.len() as u64);
            }
        }
    }

    #[test]
    fn wrong_payload_type_rejected() {
        let blob = seal(
            &hkdf_kd(),
            None,
            Some(&Key::generate()),
            b"data",
            PayloadType::File,
        );
        assert!(read_container(
            Cursor::new(blob),
            None,
            Some(&Key::generate()),
            PayloadType::Manifest,
            b"",
            |_| Ok(())
        )
        .is_err());
    }

    #[test]
    fn wrong_password_rejected() {
        let blob = seal(&pw_kd(), Some("pw"), None, b"data", PayloadType::File);
        assert!(matches!(
            read_container(
                Cursor::new(blob.clone()),
                Some("nope"),
                None,
                PayloadType::File,
                b"",
                |_| Ok(())
            ),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn tampered_byte_rejected_everywhere() {
        let blob = seal(
            &pw_kd(),
            Some("pw"),
            None,
            b"important data",
            PayloadType::File,
        );
        for pos in [0usize, 12, 40, blob.len() - 30, blob.len() - 1] {
            let mut corrupt = blob.clone();
            corrupt[pos] ^= 0x01;
            assert!(
                read_container(
                    Cursor::new(corrupt),
                    Some("pw"),
                    None,
                    PayloadType::File,
                    b"",
                    |_| Ok(())
                )
                .is_err(),
                "tamper at byte {pos} was not detected"
            );
        }
    }

    #[test]
    fn truncation_and_extension_rejected() {
        let blob = seal(&pw_kd(), Some("pw"), None, &[1u8; 500], PayloadType::File);
        assert!(read_container(
            Cursor::new(blob[..blob.len() - 1].to_vec()),
            Some("pw"),
            None,
            PayloadType::File,
            b"",
            |_| Ok(())
        )
        .is_err());
        let mut ext = blob.clone();
        ext.push(0);
        assert!(read_container(
            Cursor::new(ext),
            Some("pw"),
            None,
            PayloadType::File,
            b"",
            |_| Ok(())
        )
        .is_err());
    }

    #[test]
    fn retired_magics_reported() {
        for magic in [b"KRYPTON\0".as_slice(), b"KRYPTON2\n", b"KRYPTON3\n"] {
            let mut head = magic.to_vec();
            head.extend_from_slice(b"rest");
            let err = read_container(
                Cursor::new(head),
                None,
                None,
                PayloadType::File,
                b"",
                |_| Ok(()),
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::RetiredFormat),
                "{magic:?} should be reported as retired, got {err:?}"
            );
        }
    }

    #[test]
    fn bad_version_rejected() {
        let mut blob = seal(
            &hkdf_kd(),
            None,
            Some(&Key::generate()),
            b"x",
            PayloadType::Manifest,
        );
        blob[8] = 99; // envelope version low byte
        assert!(matches!(
            read_container(
                Cursor::new(blob),
                None,
                Some(&Key::generate()),
                PayloadType::Manifest,
                b"",
                |_| Ok(())
            ),
            Err(Error::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn wrong_identity_rejected() {
        let master = Key::generate();
        let blob = seal(&hkdf_kd(), None, Some(&master), b"data", PayloadType::File);
        // Whole-container transplant to a different logical location.
        assert!(unseal_id(
            &blob,
            None,
            Some(&master),
            PayloadType::File,
            b"other-entry"
        )
        .is_err());
        // Correct location still works and returns the trailer.
        assert!(unseal_id(&blob, None, Some(&master), PayloadType::File, b"").is_ok());
    }
}
