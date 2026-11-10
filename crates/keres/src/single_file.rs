//! Single-file encryption (the `.keres` container).
//!
//! A `.keres` file is a universal keres container (see [`crate::container`])
//! with password-based key derivation (`kind = 1`) and payload type
//! `file`. The original filename travels inside the authenticated trailer.
//!
//! Files are processed in 64 KiB chunks with constant memory usage, so
//! files of any size can be encrypted without loading them into RAM.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::container::{self, KeyDerivation, PayloadType};

use crate::error::{Error, Result};

/// Encrypts `input` into a `.keres` container.
///
/// * `password` - the encryption password.
/// * `input` - file to encrypt.
/// * `output` - destination path; when `None` a random-looking hashed name
///   ending in `.keres` is generated (the original filename never appears on
///   disk unencrypted).
///
/// Returns the path of the written container. Output is produced atomically
/// (temp file + rename) with owner-only permissions on Unix.
///
/// ```no_run
/// use std::path::Path;
/// let out = keres::encrypt_file("correct horse", Path::new("document.pdf"), None).unwrap();
/// ```
pub fn encrypt_file(password: &str, input: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let input_path = input
        .canonicalize()
        .map_err(|_| Error::invalid_name(input.display()))?;
    if !input_path.is_file() {
        return Err(Error::invalid_name(input.display()));
    }

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
        params: crate::kdf::KdfParams::new(),
    };

    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            // Random-looking name from public randomness; not secret, just opaque.
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(argon_salt);
            hasher.update(object_salt);
            PathBuf::from(format!("{:x}.keres", hasher.finalize()))
        }
    };

    let tmp_path = crate::fsutil::sibling_temp_path(&output_path);
    let result = (|| -> Result<()> {
        let mut out_file = File::create(&tmp_path)?;
        crate::fsutil::restrict_perms(&tmp_path);

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
            )?;
            w.flush()?;
        }
        out_file.sync_all()?;
        drop(out_file);

        #[cfg(windows)]
        if output_path.exists() {
            std::fs::remove_file(&output_path)?;
        }
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

/// Decrypts a `.keres` container into `output`.
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
        let tmp = File::create(&tmp_path)?;
        crate::fsutil::restrict_perms(&tmp_path);
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

        #[cfg(windows)]
        if output.exists() {
            std::fs::remove_file(output)?;
        }
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
