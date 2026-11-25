//! Streaming encryption and decryption adapters.
//!
//! These types let callers pipe data through the `.krs` container format
//! without materializing whole objects:
//!
//! * [`EncryptWriter`] implements [`std::io::Write`]: plaintext written to it
//!   is chunked, encrypted, and forwarded to an underlying writer. Call
//!   [`EncryptWriter::finish`] to write the authenticated trailer.
//! * [`DecryptReader`] implements [`std::io::Read`]: ciphertext is chunked,
//!   authenticated, and yielded as plaintext. The trailer is verified at
//!   end-of-stream.
//!
//! The free functions [`encrypt_stream`] and [`decrypt_stream`] wrap those
//! adapters for the common "source to sink" case and keep the typed
//! [`Error`] instead of an [`std::io::Error`].
//!
//! # Integrity while streaming
//!
//! Every chunk is authenticated *before* its plaintext is yielded, but the
//! trailer — which binds the total size and chunk count — can only be checked
//! after the last chunk. A truncated or trailer-tampered stream therefore
//! delivers some authenticated plaintext before the final error. When writing
//! to a file, stage the output (temp file plus rename) and discard it on
//! error, as [`crate::decrypt_file`] does. Callers that need whole-container
//! verification before using any plaintext must buffer the result or use the
//! in-memory container helpers.
//!
//! # Cancellation and progress
//!
//! [`StreamOptions`] carries an optional progress callback (cumulative
//! plaintext bytes) and an optional [`std::sync::atomic::AtomicBool`] checked
//! before each chunk. A cancelled operation returns [`Error::Cancelled`]
//! from the free functions; through the [`std::io`] adapters the same error is
//! wrapped in an [`std::io::Error`] and can be recovered with
//! `err.get_ref().and_then(|e| e.downcast_ref::<Error>())`.
//!
//! Output produced before a cancellation is not a valid container: the
//! trailer is only written by a successful [`EncryptWriter::finish`].
//!
//! # Example
//!
//! ```
//! use std::io::Cursor;
//! use keres::streaming::{decrypt_stream, encrypt_stream, StreamOptions};
//!
//! let payload = b"streamed in 64 KiB chunks".to_vec();
//! let mut ciphertext = Vec::new();
//! encrypt_stream(
//!     "correct horse",
//!     &mut Cursor::new(payload.clone()),
//!     &mut ciphertext,
//!     Some("note.txt"),
//!     StreamOptions::new(),
//! )?;
//!
//! let mut plaintext = Vec::new();
//! let info = decrypt_stream(
//!     "correct horse",
//!     Cursor::new(ciphertext),
//!     &mut plaintext,
//!     StreamOptions::new(),
//! )?;
//! assert_eq!(plaintext, payload);
//! assert_eq!(info.original_name.as_deref(), Some("note.txt"));
//! # Ok::<(), keres::Error>(())
//! ```

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::container::{self, PayloadType};
use crate::crypto::Key;
use crate::error::{Error, Result};
use crate::stream::{self, CHUNK_SIZE};

/// Per-stream callbacks: progress and cooperative cancellation.
///
/// The callback receives cumulative plaintext bytes after each processed
/// chunk. Cancellation is polled before each chunk, so a flag set by any
/// thread stops the stream at roughly 64 KiB granularity.
#[derive(Default)]
pub struct StreamOptions<'a> {
    on_progress: Option<&'a mut dyn FnMut(u64)>,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> StreamOptions<'a> {
    /// No progress callback and no cancellation flag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports cumulative plaintext bytes after each chunk.
    pub fn on_progress(mut self, callback: &'a mut dyn FnMut(u64)) -> Self {
        self.on_progress = Some(callback);
        self
    }

    /// Stops the stream with [`Error::Cancelled`] when `flag` becomes `true`.
    pub fn cancel(mut self, flag: &'a AtomicBool) -> Self {
        self.cancel = Some(flag);
        self
    }

    fn check_cancel(&self) -> Result<()> {
        if self.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    fn progress(&mut self, bytes: u64) {
        if let Some(callback) = self.on_progress.as_mut() {
            callback(bytes);
        }
    }
}

/// Description of a decrypted stream, available after end-of-stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamInfo {
    /// Original filename carried in the authenticated trailer, if any.
    pub original_name: Option<String>,
    /// Total plaintext bytes produced.
    pub bytes: u64,
    /// Number of authenticated data chunks.
    pub chunks: u32,
}

/// A [`std::io::Write`] adapter that encrypts `.krs` containers.
///
/// Construct it with [`EncryptWriter::new`] or
/// [`EncryptWriter::with_options`], write plaintext, then call
/// [`EncryptWriter::finish`] to append the trailer and recover the underlying
/// writer. Dropping without `finish` leaves an invalid, trailer-less stream.
///
/// The output is byte-for-byte the same format as [`crate::encrypt_file`].
pub struct EncryptWriter<'a, W: Write> {
    inner: W,
    key: Key,
    context: Vec<u8>,
    buffer: Zeroizing<Vec<u8>>,
    count: u32,
    total: u64,
    original_name: Option<String>,
    options: StreamOptions<'a>,
}

impl<'a, W: Write> EncryptWriter<'a, W> {
    /// Starts an unnamed stream under `password`.
    pub fn new(password: &str, inner: W) -> Result<Self> {
        Self::with_options(password, inner, None, StreamOptions::new())
    }

    /// Starts a stream, optionally recording an authenticated original name.
    pub fn with_options(
        password: &str,
        mut inner: W,
        original_name: Option<&str>,
        options: StreamOptions<'a>,
    ) -> Result<Self> {
        let kd = container::password_key_derivation();
        let key = kd.content_key(Some(password), None, b"")?;
        let context = PayloadType::File.context(container::ENVELOPE_VERSION)?;
        kd.write_header(&mut inner, container::ENVELOPE_VERSION)?;

        Ok(Self {
            inner,
            key,
            context,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + crate::crypto::TAG_LEN)),
            count: 0,
            total: 0,
            original_name: original_name.map(str::to_owned),
            options,
        })
    }

    /// Encrypts and forwards all of `data`.
    ///
    /// This is the typed equivalent of [`std::io::Write::write_all`]: errors
    /// keep their [`Error`] variant instead of being wrapped in
    /// [`std::io::Error`].
    pub fn write_plain(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.options.check_cancel()?;

        let mut offset = 0;
        while offset < data.len() {
            let space = CHUNK_SIZE - self.buffer.len();
            let take = space.min(data.len() - offset);
            self.buffer.extend_from_slice(&data[offset..offset + take]);
            offset += take;
            if self.buffer.len() == CHUNK_SIZE {
                self.emit_chunk()?;
            }
        }
        Ok(())
    }

    /// Cumulative plaintext bytes accepted so far.
    pub fn bytes_written(&self) -> u64 {
        self.total + self.buffer.len() as u64
    }

    /// Number of chunks already emitted.
    pub fn chunks_written(&self) -> u32 {
        self.count
    }

    /// Writes any buffered plaintext, the trailer, and returns the underlying
    /// writer.
    ///
    /// Fails with [`Error::Cancelled`] if the cancellation flag is set.
    pub fn finish(mut self) -> Result<W> {
        self.options.check_cancel()?;
        if !self.buffer.is_empty() {
            self.emit_chunk()?;
        }
        container::write_trailer(
            &mut self.inner,
            &self.key,
            PayloadType::File,
            container::ENVELOPE_VERSION,
            self.original_name.as_deref(),
            self.total,
            self.count,
        )?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn emit_chunk(&mut self) -> Result<()> {
        let plaintext_len = self.buffer.len() as u64;
        stream::seal_chunk(
            &mut self.inner,
            &self.key,
            &self.context,
            self.count,
            &mut self.buffer,
        )?;
        self.buffer.clear();
        self.total += plaintext_len;
        self.count += 1;
        if self.count >= stream::MAX_CHUNK_COUNT {
            return Err(Error::Encryption);
        }
        self.options.progress(self.total);
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_plain(buf).map_err(to_io_error)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // A short chunk is legal, so flushing pushes buffered plaintext
        // downstream instead of retaining it.
        if !self.buffer.is_empty() {
            self.emit_chunk().map_err(to_io_error)?;
        }
        self.inner.flush()
    }
}

/// A [`std::io::Read`] adapter that decrypts `.krs` containers.
///
/// The header is parsed and the key derived in [`DecryptReader::new`]; chunks
/// are authenticated as they are read. Reaching EOF verifies the trailer,
/// total size, chunk count, and that nothing follows the container. Read the
/// stream to EOF (or call [`DecryptReader::finish`]) before trusting
/// [`DecryptReader::original_name`].
///
/// See the module documentation for the streaming integrity caveat.
pub struct DecryptReader<'a, R: Read> {
    inner: R,
    key: Key,
    context: Vec<u8>,
    version: u16,
    /// Padded plaintext length from the v2 prelude, or `None` for v1.
    padded_size: Option<u64>,
    /// Real plaintext bytes still owed to the caller (padded streams only).
    remaining: Option<u64>,
    /// Total chunk plaintext observed, including padding.
    padded_read: u64,
    pending: Zeroizing<Vec<u8>>,
    pos: usize,
    count: u32,
    total: u64,
    finished: bool,
    original_name: Option<String>,
    options: StreamOptions<'a>,
}

impl<'a, R: Read> DecryptReader<'a, R> {
    /// Reads the header from `inner` and derives the content key.
    pub fn new(password: &str, inner: R) -> Result<Self> {
        Self::with_options(password, inner, StreamOptions::new())
    }

    /// Like [`DecryptReader::new`], with progress and cancellation.
    pub fn with_options(password: &str, mut inner: R, options: StreamOptions<'a>) -> Result<Self> {
        let header = container::read_header(&mut inner)?;
        let version = header.version;
        let key = header.kd.content_key(Some(password), None, b"")?;
        let context = PayloadType::File.context(version)?;

        // Padded (envelope v2) containers start with an authenticated prelude
        // that tells us the real size before any chunk is yielded.
        let (padded_size, remaining) = if version == container::ENVELOPE_VERSION_PADDED {
            let padding = container::read_padding_header(&mut inner, &key)?;
            (Some(padding.padded_size), Some(padding.size))
        } else {
            (None, None)
        };

        Ok(Self {
            inner,
            key,
            context,
            version,
            padded_size,
            remaining,
            padded_read: 0,
            pending: Zeroizing::new(Vec::new()),
            pos: 0,
            count: 0,
            total: 0,
            finished: false,
            original_name: None,
            options,
        })
    }

    /// Decrypts the next chunk into `out`, returning bytes written.
    ///
    /// Returns `Ok(0)` only after the trailer has been authenticated. Errors
    /// keep their [`Error`] variant.
    pub fn read_plain(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if self.pos < self.pending.len() {
                let n = out.len().min(self.pending.len() - self.pos);
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos == self.pending.len() {
                    // Drop the remaining plaintext copy as soon as it is
                    // consumed; the buffer itself is zeroizing.
                    self.pending.clear();
                    self.pos = 0;
                }
                return Ok(n);
            }

            if self.finished {
                return Ok(0);
            }

            self.options.check_cancel()?;
            match stream::read_chunk(&mut self.inner, &self.key, &self.context, self.count)? {
                Some(mut chunk) => {
                    self.count += 1;
                    if self.count >= stream::MAX_CHUNK_COUNT {
                        return Err(Error::InvalidHeader);
                    }
                    self.padded_read += chunk.len() as u64;

                    // For a padded stream, only the first `remaining` bytes of
                    // the chunk section are real; the rest is zero padding.
                    let take = match self.remaining.as_mut() {
                        Some(left) => {
                            let take = (*left).min(chunk.len() as u64) as usize;
                            *left -= take as u64;
                            take
                        }
                        None => chunk.len(),
                    };
                    if take < chunk.len() {
                        chunk.truncate(take);
                    }
                    self.total += take as u64;
                    self.pending = chunk;
                    self.pos = 0;
                    if take > 0 {
                        self.options.progress(self.total);
                    }
                }
                None => {
                    self.verify_trailer()?;
                    self.finished = true;
                    return Ok(0);
                }
            }
        }
    }

    /// Reads and discards the rest of the stream, verifying the trailer.
    ///
    /// Useful when the caller stops consuming plaintext early but still wants
    /// whole-container authentication.
    pub fn finish(&mut self) -> Result<()> {
        let mut scratch = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
        while self.read_plain(&mut scratch)? > 0 {}
        Ok(())
    }

    /// The original filename, available after EOF or a successful
    /// [`DecryptReader::finish`].
    pub fn original_name(&self) -> Option<&str> {
        self.original_name.as_deref()
    }

    /// Plaintext bytes yielded so far.
    pub fn bytes_read(&self) -> u64 {
        self.total
    }

    /// Chunks authenticated so far.
    pub fn chunks_read(&self) -> u32 {
        self.count
    }

    fn verify_trailer(&mut self) -> Result<()> {
        let trailer =
            container::read_trailer(&mut self.inner, &self.key, PayloadType::File, self.version)?;

        // The v2 trailer binds the padded length and chunk count; the real
        // size lives in the authenticated prelude.
        let expected_size = self.padded_size.unwrap_or(self.total);
        if trailer.size != expected_size || trailer.chunk_count != self.count {
            return Err(Error::Authentication);
        }
        if let Some(padded) = self.padded_size {
            if self.padded_read != padded || self.remaining != Some(0) {
                return Err(Error::Authentication);
            }
        }
        container::ensure_eof(&mut self.inner)?;
        self.original_name = trailer.name;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_plain(buf).map_err(to_io_error)
    }
}

/// Encrypts everything readable from `src` into `dst`.
///
/// `original_name` is stored in the authenticated trailer (pass `None` for an
/// unnamed stream). Returns the plaintext byte count. The typed [`Error`] is
/// preserved, including [`Error::Cancelled`].
pub fn encrypt_stream<R: Read, W: Write>(
    password: &str,
    src: &mut R,
    dst: W,
    original_name: Option<&str>,
    options: StreamOptions<'_>,
) -> Result<u64> {
    let mut writer = EncryptWriter::with_options(password, dst, original_name, options)?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let n = src.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_plain(&buffer[..n])?;
    }
    let bytes = writer.bytes_written();
    writer.finish()?;
    Ok(bytes)
}

/// Decrypts everything readable from `src` and writes plaintext to `dst`.
///
/// Returns metadata from the authenticated trailer after verifying the stream
/// to EOF. See the module documentation for the streaming integrity caveat.
pub fn decrypt_stream<R: Read, W: Write>(
    password: &str,
    src: R,
    dst: &mut W,
    options: StreamOptions<'_>,
) -> Result<StreamInfo> {
    let mut reader = DecryptReader::with_options(password, src, options)?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let n = reader.read_plain(&mut buffer)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buffer[..n])?;
    }
    Ok(StreamInfo {
        original_name: reader.original_name().map(str::to_owned),
        bytes: reader.bytes_read(),
        chunks: reader.chunks_read(),
    })
}

fn to_io_error(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        other => io::Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn adapters_roundtrip_across_chunks() {
        let data = payload(200_000);
        let mut encrypted = Vec::new();
        let mut encrypt_progress = Vec::new();
        let mut on_encrypt = |bytes| encrypt_progress.push(bytes);
        {
            let mut writer = EncryptWriter::with_options(
                "pw",
                &mut encrypted,
                Some("doc.bin"),
                StreamOptions::new().on_progress(&mut on_encrypt),
            )
            .unwrap();
            writer.write_all(&data).unwrap();
            writer.flush().unwrap();
            writer.finish().unwrap();
        }

        let mut decrypt_progress = Vec::new();
        let mut on_decrypt = |bytes| decrypt_progress.push(bytes);
        let mut reader = DecryptReader::with_options(
            "pw",
            Cursor::new(encrypted),
            StreamOptions::new().on_progress(&mut on_decrypt),
        )
        .unwrap();
        let mut restored = Vec::new();
        reader.read_to_end(&mut restored).unwrap();

        assert_eq!(restored, data);
        assert_eq!(reader.original_name(), Some("doc.bin"));
        assert_eq!(reader.bytes_read(), data.len() as u64);
        assert_eq!(reader.chunks_read(), 4);
        assert_eq!(encrypt_progress, decrypt_progress);
        assert_eq!(encrypt_progress.last(), Some(&(data.len() as u64)));
    }

    #[test]
    fn free_functions_roundtrip_and_preserve_the_name() {
        let data = payload(70_000);
        let mut encrypted = Vec::new();
        let bytes = encrypt_stream(
            "pw",
            &mut Cursor::new(data.clone()),
            &mut encrypted,
            Some("note.txt"),
            StreamOptions::new(),
        )
        .unwrap();
        assert_eq!(bytes, data.len() as u64);

        let mut restored = Vec::new();
        let info = decrypt_stream(
            "pw",
            Cursor::new(encrypted),
            &mut restored,
            StreamOptions::new(),
        )
        .unwrap();
        assert_eq!(restored, data);
        assert_eq!(info.bytes, data.len() as u64);
        assert_eq!(info.chunks, 2);
        assert_eq!(info.original_name.as_deref(), Some("note.txt"));
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let mut encrypted = Vec::new();
        encrypt_stream(
            "right",
            &mut Cursor::new(b"secret".to_vec()),
            &mut encrypted,
            None,
            StreamOptions::new(),
        )
        .unwrap();

        let mut out = Vec::new();
        let err = decrypt_stream(
            "wrong",
            Cursor::new(encrypted),
            &mut out,
            StreamOptions::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn truncation_is_detected_at_end_of_stream() {
        let mut encrypted = Vec::new();
        encrypt_stream(
            "pw",
            &mut Cursor::new(payload(10_000)),
            &mut encrypted,
            None,
            StreamOptions::new(),
        )
        .unwrap();
        encrypted.pop();

        let mut out = Vec::new();
        assert!(
            decrypt_stream("pw", Cursor::new(encrypted), &mut out, StreamOptions::new(),).is_err()
        );
    }

    #[test]
    fn cancellation_stops_both_directions() {
        let flag = AtomicBool::new(false);
        let mut encrypted = Vec::new();
        let mut writer = EncryptWriter::with_options(
            "pw",
            &mut encrypted,
            None,
            StreamOptions::new().cancel(&flag),
        )
        .unwrap();

        flag.store(true, Ordering::Relaxed);
        assert!(matches!(writer.write_plain(b"x"), Err(Error::Cancelled)));
        assert!(matches!(writer.finish(), Err(Error::Cancelled)));

        // Build a valid stream with cancellation disabled, then cancel the
        // reader before the first chunk.
        let secret_flag = AtomicBool::new(false);
        let mut valid = Vec::new();
        encrypt_stream(
            "pw",
            &mut Cursor::new(b"data".to_vec()),
            &mut valid,
            None,
            StreamOptions::new().cancel(&secret_flag),
        )
        .unwrap();

        let mut reader = DecryptReader::with_options(
            "pw",
            Cursor::new(valid),
            StreamOptions::new().cancel(&secret_flag),
        )
        .unwrap();
        secret_flag.store(true, Ordering::Relaxed);
        let mut out = [0u8; 16];
        assert!(matches!(reader.read_plain(&mut out), Err(Error::Cancelled)));
    }

    #[test]
    fn interoperates_with_the_file_api() {
        let dir = tempfile::Builder::new()
            .prefix("keres-stream")
            .tempdir()
            .unwrap();
        let plain = dir.path().join("input.bin");
        std::fs::write(&plain, payload(150_000)).unwrap();

        // Streaming writer -> decrypt_file.
        let from_streaming = dir.path().join("streaming.krs");
        {
            let mut output = std::fs::File::create(&from_streaming).unwrap();
            let mut input = std::fs::File::open(&plain).unwrap();
            encrypt_stream(
                "pw",
                &mut input,
                &mut output,
                Some("input.bin"),
                StreamOptions::new(),
            )
            .unwrap();
        }
        let restored = dir.path().join("restored.bin");
        assert_eq!(
            crate::decrypt_file("pw", &from_streaming, &restored).unwrap(),
            "input.bin"
        );
        assert_eq!(std::fs::read(&restored).unwrap(), payload(150_000));

        // encrypt_file -> streaming reader.
        let from_file = crate::encrypt_file("pw", &plain, None).unwrap();
        let mut output = std::fs::File::create(dir.path().join("streamed.bin")).unwrap();
        let info = decrypt_stream(
            "pw",
            std::fs::File::open(&from_file).unwrap(),
            &mut output,
            StreamOptions::new(),
        )
        .unwrap();
        assert_eq!(info.original_name.as_deref(), Some("input.bin"));
        assert_eq!(
            std::fs::read(dir.path().join("streamed.bin")).unwrap(),
            payload(150_000)
        );
        assert!(Path::new(&from_file).is_file());
    }
}
