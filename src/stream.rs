//! Chunked, memory-bounded encryption stream engine.
//!
//! The record layout shared by all containers:
//!
//! ```text
//! [data chunk 0] [data chunk 1] ... [data chunk N-1] [end marker] [trailer]
//! ```
//!
//! Each record on disk is `[length: u32 LE][ciphertext || GCM tag]`.
//!
//! # Nonce strategy
//!
//! Chunk `i` is encrypted under an object-specific subkey with the
//! deterministic nonce `[0x00 ×4 || i: u64 BE]`. Counter nonces eliminate
//! the random-nonce birthday collision risk when many chunks share one key,
//! and embedding the index makes reordering detectable.
//!
//! The trailer uses the reserved all-`0xFF` nonce, which data chunks can
//! never produce; see [`crate::container`] for the trailer itself.
//!
//! # Tamper resistance
//!
//! * Chunk index is bound via nonce **and** AAD (`context || index`).
//! * Record lengths are capped before allocation, so hostile files cannot
//!   trigger huge allocations.

use std::io::{Read, Write};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, Key, TAG_LEN};
use crate::error::{Error, Result};

/// Maximum plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// Upper bound accepted for a trailer record (hostile-input guard).
pub(crate) const MAX_TRAILER_LEN: usize = 1024 * 1024;
/// Sanity cap on chunk count (~1 TiB with 64 KiB chunks).
pub(crate) const MAX_CHUNK_COUNT: u32 = 1 << 24;

/// Reserved nonce used exclusively by the trailer record.
pub(crate) const TRAILER_NONCE: crypto::Nonce12 = [0xFFu8; 12];

/// Marks the boundary between the chunk section and the trailer.
///
/// The marker is deliberately unauthenticated: moving or removing it always
/// causes the authenticated trailer's chunk-count/size checks (or the chunk
/// authentication) to fail, so tampering gains nothing.
pub(crate) const CHUNKS_END_MARKER: [u8; 4] = [0u8; 4];

/// Reads one framed record `[len u32 LE][payload]`, enforcing `max`.
pub(crate) fn read_record<R: Read>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max {
        return Err(Error::InvalidHeader);
    }
    let mut rec = vec![0u8; len];
    r.read_exact(&mut rec)?;
    Ok(rec)
}

/// Encrypts one buffered chunk and writes `[len u32 LE][ciphertext || tag]`.
///
/// `buf` holds plaintext on entry and ciphertext (plus tag) on return.
pub(crate) fn seal_chunk<W: Write>(
    dst: &mut W,
    key: &Key,
    context: &[u8],
    index: u32,
    buf: &mut Zeroizing<Vec<u8>>,
) -> Result<()> {
    crypto::seal_in_place(&chunk_nonce(index), buf, key, &chunk_aad(context, index))?;
    dst.write_all(&(buf.len() as u32).to_le_bytes())?;
    dst.write_all(buf)?;
    Ok(())
}

/// Reads and authenticates one chunk.
///
/// Returns `None` at the end-of-chunks marker, leaving the stream positioned
/// at the trailer record. Rejects oversized length prefixes before
/// allocation and requires the length to cover a tag and at most
/// [`CHUNK_SIZE`] plaintext bytes.
pub(crate) fn read_chunk<R: Read>(
    src: &mut R,
    key: &Key,
    context: &[u8],
    index: u32,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len_bytes = [0u8; 4];
    match src.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::InvalidHeader); // missing trailer entirely
        }
        Err(e) => return Err(e.into()),
    }

    if len_bytes == CHUNKS_END_MARKER {
        return Ok(None);
    }

    let len = u32::from_le_bytes(len_bytes) as usize;
    if !(TAG_LEN..=CHUNK_SIZE + TAG_LEN).contains(&len) {
        return Err(Error::InvalidHeader);
    }

    let mut rec = Zeroizing::new(vec![0u8; len]);
    src.read_exact(rec.as_mut())?;
    crypto::open_in_place(
        &chunk_nonce(index),
        &mut rec,
        key,
        &chunk_aad(context, index),
    )?;
    Ok(Some(rec))
}

/// Encrypts everything readable from `src` into `dst` as chunk records.
///
/// Returns `(total_plaintext_bytes, chunk_count)`.
pub(crate) fn write_chunks<W: Write>(
    dst: &mut W,
    src: &mut dyn Read,
    key: &Key,
    context: &[u8],
) -> Result<(u64, u32)> {
    let mut buf = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_LEN));
    let mut total: u64 = 0;
    let mut count: u32 = 0;

    loop {
        buf.resize(CHUNK_SIZE, 0);
        let n = src.read(&mut buf[..CHUNK_SIZE]).inspect_err(|_| {
            // Source failed mid-stream; scrub whatever was buffered.
            buf.zeroize();
        })?;
        buf.truncate(n);
        if n == 0 {
            break;
        }

        seal_chunk(dst, key, context, count, &mut buf)?;

        total += n as u64;
        count += 1;
        if count >= MAX_CHUNK_COUNT {
            return Err(Error::Encryption);
        }
    }

    Ok((total, count))
}

/// Encrypts exactly `padded_len` plaintext bytes from `src`, filling the tail
/// with zeros after the source ends.
///
/// `expected_len` is the caller's authenticated source length. It must equal
/// the number of real bytes read; a file that grew or shrank between `stat`
/// and read fails the operation instead of producing a misleading container.
///
/// Chunk boundaries depend only on `padded_len`, never on `expected_len`: a
/// partially-read final chunk is zero-filled to its full length before it is
/// sealed. Without that property, the last record's length would reveal the
/// exact plaintext size and defeat the bucket.
///
/// Returns `(real_plaintext_bytes, chunk_count)`.
pub(crate) fn write_chunks_padded<W: Write>(
    dst: &mut W,
    src: &mut dyn Read,
    key: &Key,
    context: &[u8],
    expected_len: u64,
    padded_len: u64,
) -> Result<(u64, u32)> {
    debug_assert!(padded_len >= expected_len);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut remaining = padded_len;
    let mut real_total: u64 = 0;
    let mut count: u32 = 0;
    let mut eof = false;

    while remaining > 0 {
        let want = remaining.min(CHUNK_SIZE as u64) as usize;
        // Reset the buffer to exactly `want` plaintext bytes; the previous
        // iteration left ciphertext behind for efficiency.
        buf.resize(want, 0);
        let mut filled = 0usize;
        if !eof {
            while filled < want {
                let n = match src.read(&mut buf[filled..want]) {
                    Ok(n) => n,
                    Err(e) => {
                        // Source failed mid-stream; scrub whatever was buffered
                        // before reporting.
                        buf.zeroize();
                        return Err(e.into());
                    }
                };
                if n == 0 {
                    eof = true;
                    break;
                }
                filled += n;
            }
        }
        // After EOF the rest of this chunk (and all later chunks) is padding.
        buf[filled..want].fill(0);
        seal_chunk(dst, key, context, count, &mut buf)?;

        real_total += filled as u64;
        remaining -= want as u64;
        count = count.checked_add(1).ok_or(Error::Encryption)?;
        if count >= MAX_CHUNK_COUNT {
            return Err(Error::Encryption);
        }
    }

    if !eof {
        let mut probe = [0u8; 1];
        if src.read(&mut probe)? != 0 {
            return Err(Error::Operation(
                "input changed while it was being encrypted".into(),
            ));
        }
    }

    if real_total != expected_len {
        return Err(Error::Operation(
            "input changed while it was being encrypted".into(),
        ));
    }

    Ok((real_total, count))
}

fn chunk_nonce(index: u32) -> crypto::Nonce12 {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&(u64::from(index)).to_be_bytes());
    n
}

fn chunk_aad(context: &[u8], index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(context.len() + 8);
    aad.extend_from_slice(context);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Decrypts and verifies all chunk records, feeding plaintext slices to
/// `sink`. Returns `(total_bytes, chunk_count)`.
///
/// Stops at the end-of-chunks marker; the stream is then positioned at the
/// trailer record for the caller to authenticate.
pub(crate) fn read_chunks<R: Read>(
    src: &mut R,
    key: &Key,
    context: &[u8],
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<(u64, u32)> {
    let mut total: u64 = 0;
    let mut count: u32 = 0;

    loop {
        match read_chunk(src, key, context, count)? {
            Some(rec) => {
                // After in-place decryption the buffer holds plaintext only.
                sink(&rec)?;
                total += rec.len() as u64;
                count += 1;
                if count >= MAX_CHUNK_COUNT {
                    return Err(Error::InvalidHeader);
                }
            }
            None => return Ok((total, count)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn nonce_layout_leaves_trailer_domain() {
        // Highest chunk counter must never collide with the trailer nonce.
        let n = chunk_nonce(u32::MAX);
        assert_ne!(n, TRAILER_NONCE);
        assert_eq!(&n[..4], &[0u8; 4]);
        assert_eq!(&n[4..], &u64::from(u32::MAX).to_be_bytes());
    }

    #[test]
    fn oversized_length_prefix_rejected_before_alloc() {
        // A record length beyond any legal chunk is refused without
        // allocating; exercised through read_chunks with a bogus prefix.
        let mut malicious = u32::MAX.to_le_bytes().to_vec();
        malicious.extend_from_slice(&[0u8; TAG_LEN]);
        let mut src = Cursor::new(malicious);
        let err = read_chunks(&mut src, &Key::generate(), b"ctx", |_| Ok(())).unwrap_err();
        assert!(matches!(err, Error::InvalidHeader));
    }
}
