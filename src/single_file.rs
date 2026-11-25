//! Single-file encryption (the `.krs` container).
//!
//! A `.krs` file is a universal keres container (see [`crate::container`])
//! with password-based key derivation (`kind = 1`) and payload type
//! `file`. The original filename travels inside the authenticated trailer.
//!
//! Files are processed in 64 KiB chunks with constant memory usage, so
//! files of any size can be encrypted without loading them into RAM.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::container::{self, KeyDerivation, PayloadType};
use crate::kdf::KdfParams;
use crate::padding::Padding;

use crate::error::{Error, Result};

/// Options for encrypting a single file into a `.krs` container.
///
/// The defaults match [`encrypt_file`]: no size padding and the library's
/// standard Argon2id parameters.
///
/// ```no_run
/// use keres::{EncryptOptions, KdfParams, Padding};
///
/// let options = EncryptOptions::new()
///     .padding(Padding::Adaptive)
///     .kdf(KdfParams {
///         m_cost_kib: 32 * 1024,
///         t_cost: 3,
///         p_cost: 2,
///     });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptOptions {
    /// Size-padding policy. Defaults to [`Padding::None`].
    pub padding: Padding,
    /// Argon2id parameters. Defaults to [`KdfParams::new`].
    pub kdf: KdfParams,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptOptions {
    /// No padding and the standard Argon2id parameters.
    pub const fn new() -> Self {
        Self {
            padding: Padding::None,
            kdf: KdfParams::new(),
        }
    }

    /// Sets the size-padding policy.
    pub const fn padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// Sets the Argon2id parameters.
    pub const fn kdf(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }
}

/// Encrypts `input` into a `.krs` container.
///
/// * `password` - the encryption password.
/// * `input` - file to encrypt.
/// * `output` - destination path; when `None` a random-looking hashed name
///   ending in `.krs` is generated (the original filename never appears on
///   disk unencrypted).
///
/// Returns the path of the written container. Output is produced atomically
/// (temp file + rename) with owner-only permissions on Unix.
///
/// The container is unpadded and uses the standard Argon2id parameters. Use
/// [`encrypt_file_with_options`] to change either.
///
/// ```no_run
/// use std::path::Path;
/// let out = keres::encrypt_file("correct horse", Path::new("document.pdf"), None).unwrap();
/// ```
pub fn encrypt_file(password: &str, input: &Path, output: Option<&Path>) -> Result<PathBuf> {
    encrypt_file_with_options(password, input, output, EncryptOptions::new())
}

/// Encrypts `input` into a `.krs` container using `padding`.
///
/// Behaves like [`encrypt_file`], but rounds the plaintext up to `padding`'s
/// bucket before encryption so the ciphertext length reveals only the bucket,
/// not the exact file size. See [`crate::padding`] for the policies.
pub fn encrypt_file_with_padding(
    password: &str,
    input: &Path,
    output: Option<&Path>,
    padding: Padding,
) -> Result<PathBuf> {
    encrypt_file_with_options(
        password,
        input,
        output,
        EncryptOptions::new().padding(padding),
    )
}

/// Encrypts `input` into a `.krs` container with explicit options.
///
/// This is the general form of [`encrypt_file`]. Use it to select a
/// non-default Argon2id cost, for example a lower memory budget on a
/// memory-constrained device or a higher one for long-term storage, or to
/// enable size padding.
pub fn encrypt_file_with_options(
    password: &str,
    input: &Path,
    output: Option<&Path>,
    options: EncryptOptions,
) -> Result<PathBuf> {
    options.padding.validate()?;
    options.kdf.validate()?;

    let input_path = input
        .canonicalize()
        .map_err(|_| Error::invalid_name(input.display()))?;
    if !input_path.is_file() {
        return Err(Error::invalid_name(input.display()));
    }
    let source_len = std::fs::metadata(&input_path)?.len();

    let original_name = input_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut argon_salt = [0u8; container::SALT_LEN];
    let mut object_salt = [0u8; container::SALT_LEN];
    crate::crypto::fill_random(&mut argon_salt);
    crate::crypto::fill_random(&mut object_salt);

    let kd = KeyDerivation::Password {
        argon_salt,
        object_salt,
        params: options.kdf,
    };

    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            // Random-looking name from public randomness; not secret, just opaque.
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(argon_salt);
            hasher.update(object_salt);
            PathBuf::from(format!("{:x}.krs", hasher.finalize()))
        }
    };

    let tmp_path = crate::fsutil::sibling_temp_path(&output_path);
    let result = (|| -> Result<()> {
        let mut out_file = crate::fsutil::create_private_file(&tmp_path)?;

        let mut src = File::open(&input_path)?;
        {
            let mut w = BufWriter::new(&mut out_file);
            container::write_container(
                &mut w,
                &kd,
                Some(password),
                None,
                PayloadType::File,
                b"",
                Some(&mut src),
                Some(&original_name),
                options.padding,
                Some(source_len),
            )?;
            w.flush()?;
        }
        out_file.sync_all()?;
        drop(out_file);

        std::fs::rename(&tmp_path, &output_path)?;
        crate::fsutil::restrict_perms(&output_path);
        crate::fsutil::sync_dir(output_path.parent().unwrap_or_else(|| Path::new(".")));
        Ok(())
    })();

    match result {
        Ok(()) => Ok(output_path),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Decrypts a `.krs` container into `output`.
///
/// Returns the original filename recovered from the authenticated trailer.
///
/// Security notes:
/// * The plaintext is written via temp-file + rename; an interrupted
///   decryption never leaves a half-written file behind.
/// * The returned filename originates inside the encrypted container. Treat
///   it as untrusted data; if used to build filesystem paths, pass it through
///   [`crate::sanitize::sanitize_stored_name`] first.
pub fn decrypt_file(password: &str, input: &Path, output: &Path) -> Result<String> {
    let file = BufReader::new(File::open(input)?);

    let tmp_path = crate::fsutil::sibling_temp_path(output);
    let outcome = (|| -> Result<String> {
        let tmp = crate::fsutil::create_private_file(&tmp_path)?;
        let mut sink = BufWriter::new(tmp);

        let trailer = container::read_container(
            file,
            Some(password),
            None,
            PayloadType::File,
            b"",
            |chunk| sink.write_all(chunk).map_err(Error::from),
        )?;
        sink.flush()?;
        drop(sink);

        let name = trailer.name.ok_or(Error::MalformedPayload)?;

        std::fs::rename(&tmp_path, output)?;
        crate::fsutil::sync_dir(output.parent().unwrap_or_else(|| Path::new(".")));
        Ok(name)
    })();

    match outcome {
        Ok(name) => Ok(name),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}
