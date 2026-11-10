//! Entry-name validation and sanitization.
//!
//! Encrypted containers store filenames. A malicious container (or a hostile
//! peer) can embed names like `../../.ssh/id_rsa`; anything reconstructed
//! from stored names and joined onto a user-supplied destination must pass
//! through [`sanitize_stored_name`](crate::sanitize::sanitize_stored_name)
//! first.

use crate::error::{Error, Result};

/// Maximum accepted entry-name length in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Validates a name supplied for a *new* vault entry.
///
/// Rules: non-empty, at most [`MAX_NAME_LEN`] bytes, no NUL, no `/` or `\`
/// separators, no `.`/`..` components, not absolute.
pub fn validate_new_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::invalid_name(name));
    }
    if name.contains('\0') {
        return Err(Error::invalid_name(name));
    }
    let path = std::path::Path::new(name);
    if path.is_absolute() {
        return Err(Error::invalid_name(name));
    }
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(_) => {}
            _ => return Err(Error::invalid_name(name)),
        }
    }
    // Backslash is a separator on Windows and confusing everywhere else.
    if name.contains('\\') {
        return Err(Error::invalid_name(name));
    }
    Ok(())
}

/// Makes an untrusted, previously-stored name safe to join onto a filesystem
/// path.
///
/// This is defense in depth: names recovered from authenticated storage are
/// normally already valid, but extraction must stay safe even when the vault
/// was produced by a hostile implementation. Any name that cannot be made
/// safe is rejected rather than mangled into something silently different.
pub fn sanitize_stored_name(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::invalid_name(name));
    }
    validate_new_name(name)?;
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_names() {
        assert!(validate_new_name("report.pdf").is_ok());
        assert!(validate_new_name("photos").is_ok());
        assert!(validate_new_name("photos/vacation/img.png").is_ok());
        assert!(validate_new_name("ünïcødé.txt").is_ok());
    }

    #[test]
    fn rejects_traversal_and_specials() {
        assert!(validate_new_name("").is_err());
        assert!(validate_new_name("../evil").is_err());
        assert!(validate_new_name("a/../b").is_err());
        assert!(validate_new_name("/abs").is_err());
        assert!(validate_new_name("C:\\\\x").is_err());
        assert!(validate_new_name("a\\b").is_err());
        assert!(validate_new_name("nul\0").is_err());
        assert!(validate_new_name(&"x".repeat(256)).is_err());
    }

    #[test]
    fn sanitize_passthrough_valid() {
        assert_eq!(sanitize_stored_name("ok.txt").unwrap(), "ok.txt");
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize_stored_name("../../etc/passwd").is_err());
    }
}
