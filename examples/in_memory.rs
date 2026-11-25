//! Encrypt and decrypt bytes entirely in memory.
//!
//! The streaming API works with any [`std::io::Read`] and [`std::io::Write`],
//! so an application can keep ciphertext in a `Vec`, a network socket, or an
//! object-store upload without creating temporary files.
//!
//! Run with:
//!
//! ```console
//! cargo run --example in_memory
//! ```

use std::io::Cursor;

use keres::streaming::{decrypt_stream, encrypt_stream, StreamOptions};
use keres::Result;

fn main() -> Result<()> {
    let plaintext = b"encrypted in a Vec, never written to disk".to_vec();

    let mut ciphertext = Vec::new();
    encrypt_stream(
        "correct horse",
        &mut Cursor::new(&plaintext),
        &mut ciphertext,
        Some("note.txt"),
        StreamOptions::new(),
    )?;

    let mut restored = Vec::new();
    let info = decrypt_stream(
        "correct horse",
        Cursor::new(&ciphertext),
        &mut restored,
        StreamOptions::new(),
    )?;

    assert_eq!(restored, plaintext);
    println!(
        "restored {} bytes in {} chunks (original name: {:?})",
        info.bytes,
        info.chunks,
        info.original_name.as_deref().unwrap_or("<unnamed>")
    );
    println!("ciphertext size: {} bytes", ciphertext.len());

    Ok(())
}
