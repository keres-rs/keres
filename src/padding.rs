//! Opt-in size padding (L2+ metadata protection).
//!
//! Encryption hides *what* is stored, not *how much*. Without padding, the
//! ciphertext length of a vault entry or `.krs` file reveals its exact
//! plaintext size to anyone who can read the storage medium. Padding rounds
//! every payload up to a bucket before encryption, so an observer learns only
//! the bucket.
//!
//! Padding is **opt-in**: [`Padding::None`] (the default) preserves the
//! compact on-disk format. [`Padding::Adaptive`] rounds to the next power of
//! two clamped to [`crate::padding::MIN_BUCKET`]..=[`crate::padding::MAX_BUCKET`], and larger payloads round
//! to the next multiple of [`crate::padding::MAX_BUCKET`]. [`Padding::Fixed`] rounds to a
//! caller-supplied bucket in the same range.
//!
//! The original size is carried inside the authenticated container metadata
//! and repeated in the trailer, so readers always trim back to it. Padding
//! never hides access patterns, exact entry counts, operating-system
//! timestamps, or the existence of an encrypted object; see the project
//! threat model for the full non-guarantee list.
//!
//! # Example
//!
//! ```
//! use keres::Padding;
//!
//! assert_eq!(Padding::Adaptive.padded_len(0).unwrap(), 4096);
//! assert_eq!(Padding::Adaptive.padded_len(4097).unwrap(), 8192);
//! assert_eq!(Padding::fixed(65536).unwrap().padded_len(70_000).unwrap(), 131_072);
//! ```
//!
//! # Storage cost
//!
//! Adaptive buckets waste at most the current bucket size minus one byte. The
//! default 4 KiB floor is deliberately small: it hides the difference between
//! an empty file and a few kilobytes, which is where most metadata leaks are
//! cheapest to exploit. Users who prefer uniform buckets can select
//! [`Padding::Fixed`].

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Smallest bucket produced by any padding policy.
pub const MIN_BUCKET: u64 = 4 * 1024;

/// Largest adaptive bucket. Payloads above this are rounded up to the next
/// multiple of `MAX_BUCKET` instead of doubling without bound.
pub const MAX_BUCKET: u64 = 16 * 1024 * 1024;

/// How plaintext is padded before encryption.
///
/// The policy is stored in the authenticated vault index; it is not a secret,
/// but it is part of the vault's integrity-protected configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Padding {
    /// No padding. Ciphertext length tracks plaintext length exactly.
    #[default]
    None,
    /// Round up to the next power of two, clamped to
    /// [`crate::padding::MIN_BUCKET`]..=[`crate::padding::MAX_BUCKET`]; larger payloads round to the next
    /// multiple of [`crate::padding::MAX_BUCKET`].
    Adaptive,
    /// Round up to the next multiple of `size`, which must lie in
    /// [`crate::padding::MIN_BUCKET`]..=[`crate::padding::MAX_BUCKET`].
    Fixed {
        /// Bucket size in bytes.
        size: u64,
    },
}

impl Padding {
    /// Builds a fixed-bucket policy after validating `size`.
    pub fn fixed(size: u64) -> Result<Self> {
        let padding = Self::Fixed { size };
        padding.validate()?;
        Ok(padding)
    }

    /// Whether this policy leaves payloads unpadded.
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }

    /// Rejects a fixed bucket outside [`crate::padding::MIN_BUCKET`]..=[`crate::padding::MAX_BUCKET`].
    pub fn validate(self) -> Result<()> {
        match self {
            Self::Fixed { size } if !(MIN_BUCKET..=MAX_BUCKET).contains(&size) => {
                Err(Error::Operation(format!(
                    "padding bucket must be between {MIN_BUCKET} and {MAX_BUCKET} bytes"
                )))
            }
            _ => Ok(()),
        }
    }

    /// Smallest bucket that can hold `len` bytes under this policy.
    ///
    /// An empty payload is padded to the smallest bucket when padding is
    /// enabled, so empty files are indistinguishable from tiny ones.
    pub fn padded_len(self, len: u64) -> Result<u64> {
        match self {
            Self::None => Ok(len),
            Self::Adaptive => {
                if len <= MIN_BUCKET {
                    return Ok(MIN_BUCKET);
                }
                if len <= MAX_BUCKET {
                    return len
                        .checked_next_power_of_two()
                        .ok_or_else(|| Error::Operation("payload is too large".into()));
                }
                let remainder = len % MAX_BUCKET;
                if remainder == 0 {
                    Ok(len)
                } else {
                    len.checked_add(MAX_BUCKET - remainder)
                        .ok_or_else(|| Error::Operation("payload is too large".into()))
                }
            }
            Self::Fixed { size } => {
                self.validate()?;
                if len == 0 {
                    return Ok(size);
                }
                let remainder = len % size;
                if remainder == 0 {
                    Ok(len)
                } else {
                    len.checked_add(size - remainder)
                        .ok_or_else(|| Error::Operation("payload is too large".into()))
                }
            }
        }
    }
}

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Adaptive => f.write_str("adaptive"),
            Self::Fixed { size } => write!(f, "fixed ({size} bytes)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_rounds_to_powers_of_two_with_a_floor() {
        assert_eq!(Padding::Adaptive.padded_len(0).unwrap(), MIN_BUCKET);
        assert_eq!(Padding::Adaptive.padded_len(1).unwrap(), MIN_BUCKET);
        assert_eq!(
            Padding::Adaptive.padded_len(MIN_BUCKET).unwrap(),
            MIN_BUCKET
        );
        assert_eq!(
            Padding::Adaptive.padded_len(MIN_BUCKET + 1).unwrap(),
            2 * MIN_BUCKET
        );
        assert_eq!(Padding::Adaptive.padded_len(65536).unwrap(), 65536);
        assert_eq!(Padding::Adaptive.padded_len(65537).unwrap(), 131_072);
        assert_eq!(
            Padding::Adaptive.padded_len(MAX_BUCKET).unwrap(),
            MAX_BUCKET
        );
    }

    #[test]
    fn adaptive_caps_growth_at_the_max_bucket() {
        assert_eq!(
            Padding::Adaptive.padded_len(MAX_BUCKET + 1).unwrap(),
            2 * MAX_BUCKET
        );
        assert_eq!(
            Padding::Adaptive.padded_len(3 * MAX_BUCKET).unwrap(),
            3 * MAX_BUCKET
        );
        assert_eq!(
            Padding::Adaptive.padded_len(3 * MAX_BUCKET + 1).unwrap(),
            4 * MAX_BUCKET
        );
    }

    #[test]
    fn fixed_buckets_round_up_and_validate_their_size() {
        let padding = Padding::fixed(65536).unwrap();
        assert_eq!(padding.padded_len(0).unwrap(), 65536);
        assert_eq!(padding.padded_len(1).unwrap(), 65536);
        assert_eq!(padding.padded_len(65536).unwrap(), 65536);
        assert_eq!(padding.padded_len(65537).unwrap(), 131_072);

        assert!(Padding::fixed(MIN_BUCKET - 1).is_err());
        assert!(Padding::fixed(MAX_BUCKET + 1).is_err());
    }

    #[test]
    fn none_is_exact() {
        assert_eq!(Padding::None.padded_len(0).unwrap(), 0);
        assert_eq!(Padding::None.padded_len(123).unwrap(), 123);
    }

    #[test]
    fn policies_serialize_as_structured_json() {
        let cases = [
            (Padding::None, r#"{"mode":"none"}"#),
            (Padding::Adaptive, r#"{"mode":"adaptive"}"#),
            (
                Padding::Fixed { size: 8192 },
                r#"{"mode":"fixed","size":8192}"#,
            ),
        ];
        for (padding, json) in cases {
            assert_eq!(serde_json::to_string(&padding).unwrap(), json);
            let parsed: Padding = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, padding);
        }
    }

    #[test]
    fn display_is_human_readable() {
        assert_eq!(Padding::None.to_string(), "none");
        assert_eq!(Padding::Adaptive.to_string(), "adaptive");
        assert_eq!(
            Padding::Fixed { size: MIN_BUCKET }.to_string(),
            "fixed (4096 bytes)"
        );
    }
}
