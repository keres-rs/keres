//! Store application data in a vault without temporary files.
//!
//! This mirrors a local-first application that already has attachment bytes
//! in memory (from an upload, a database, or a document editor) and wants
//! authenticated, encrypted storage under one passphrase.
//!
//! Run with:
//!
//! ```console
//! cargo run --example vault_store
//! ```
//!
//! Pass a directory to keep the vault, or omit it to use a temporary one that
//! is removed when the example exits.

use std::path::PathBuf;

use keres::{KdfParams, Result, Vault, VaultOptions};

fn main() -> Result<()> {
    let vault_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("keres-example-vault-{}", std::process::id()))
        });
    let ephemeral = std::env::args().nth(1).is_none();

    let mut vault = Vault::new(vault_dir.clone());
    if vault.exists() {
        vault.unlock("correct horse")?;
    } else {
        // A real application would usually keep the defaults. Lowering the
        // cost makes this example fast; the parameters are stored in the
        // keyslot and inherited by later keyslot changes.
        vault.init_with_options(
            "correct horse",
            VaultOptions::new().kdf(KdfParams {
                m_cost_kib: 8 * 1024,
                t_cost: 1,
                p_cost: 1,
            }),
        )?;
    }

    let attachment = b"the contents of an uploaded file".to_vec();
    vault.add_from_reader("report.txt", &attachment[..], Some(attachment.len() as u64))?;

    for entry in vault.list()? {
        println!(
            "{}{} ({} bytes)",
            entry.name,
            if entry.is_directory { "/" } else { "" },
            entry.size
        );
    }

    let mut restored = Vec::new();
    let size = vault.extract_to_writer("report.txt", &mut restored)?;
    assert_eq!(restored, attachment);
    println!("read back {size} authenticated bytes");

    vault.lock();

    if ephemeral {
        std::fs::remove_dir_all(&vault_dir)?;
    }
    Ok(())
}
