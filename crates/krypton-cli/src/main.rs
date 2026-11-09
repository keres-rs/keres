use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use krypton::prelude::*;

use krypton::Vault;

fn vault_root() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("KRYPTON_HOME") {
        if dir.is_empty() {
            return Err(Error::Operation("KRYPTON_HOME is set but empty".into()));
        }
        return Ok(PathBuf::from(dir).join("vaults"));
    }
    match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(home) if !home.is_empty() => {
            Ok(PathBuf::from(home).join(".krypton").join("vaults"))
        }
        Some(_) => Err(Error::Operation(
            "HOME is set but empty; unset it or set KRYPTON_HOME".into(),
        )),
        None => Err(Error::Operation(
            "cannot determine home directory; set HOME or KRYPTON_HOME".into(),
        )),
    }
}

fn vault_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(Error::Operation(format!(
            "invalid vault name {name:?}: use a plain name, not a path"
        )));
    }
    let path = vault_root()?.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::Operation(format!(
                "refusing to use vault {}: it is a symlink",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::Operation(format!(
                "cannot access vault {}: {e}",
                path.display()
            )));
        }
    }
    Ok(path)
}

fn new_vault_path(name: &str) -> Result<PathBuf> {
    let path = vault_path(name)?;
    if path.exists() {
        return Err(Error::Operation(format!(
            "vault {name:?} already exists at {}",
            path.display()
        )));
    }
    Ok(path)
}

fn existing_vault_path(name: &str) -> Result<PathBuf> {
    let path = vault_path(name)?;
    if !path.is_dir() {
        return Err(Error::Operation(format!(
            "no vault named {name:?} at {} (create it with `krypton init {name}`)",
            path.display()
        )));
    }
    Ok(path)
}

#[derive(Parser)]
#[command(name = "krypton")]
#[command(version = krypton::VERSION)]
#[command(about = "Encrypt your personal files or secrets", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault.
    Init {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
    },
    /// Add a file or folder to the vault.
    Add {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
        /// Path to the file or folder to add.
        path: PathBuf,
        /// Custom name in vault.
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Remove a file or folder from the vault.
    Remove {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
        /// Name of the file/folder in vault.
        name: String,
    },
    /// List vault contents.
    List {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
    },
    /// Extract/decrypt a file from the vault.
    Extract {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
        /// Name of the file in vault.
        name: String,
        /// Destination path.
        dest: PathBuf,
    },
    /// Change the vault password.
    ChangePassword {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
    },
    /// Verify the integrity of all vault entries (full authentication).
    Verify {
        /// Vault name (stored in ~/.krypton/vaults/<name>).
        vault: String,
    },
    /// Encrypt a single file.
    Encrypt {
        /// Path to the file to encrypt.
        input: PathBuf,
        /// Output encrypted file (default: random hashed name).
        output: Option<PathBuf>,
    },
    /// Decrypt a single file.
    Decrypt {
        /// Path to the encrypted file (.krf).
        input: PathBuf,
        /// Output decrypted file.
        output: PathBuf,
    },
}

fn prompt_password(prompt: &str) -> Result<String> {
    if let Ok(pwd) = std::env::var("KRYPTON_PASSWORD") {
        return Ok(pwd);
    }
    print!("{prompt}: ");
    io::stdout().flush().ok();
    if io::stdin().is_terminal() {
        rpassword::read_password().map_err(|_| Error::Operation("failed to read password".into()))
    } else {
        // No TTY (piped input): read a plain line so scripts and CI can drive us.
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|_| Error::Operation("failed to read password".into()))?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }
}

fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    match size {
        s if s >= GB => format!("{:.2} GB", s as f64 / GB as f64),
        s if s >= MB => format!("{:.2} MB", s as f64 / MB as f64),
        s if s >= KB => format!("{:.2} KB", s as f64 / KB as f64),
        s => format!("{s} B"),
    }
}

fn print_report(report: &IntegrityReport) {
    println!("Vault integrity check:");
    println!("  Entries total:   {}", report.total_entries);
    println!("  Entries verified: {}", report.verified);
    if report.missing.is_empty() && report.corrupted.is_empty() {
        println!("  Status: OK — all files present and authenticated");
        return;
    }
    println!("  Status: ISSUES FOUND");
    if !report.missing.is_empty() {
        println!("  Missing ({}):", report.missing.len());
        for name in &report.missing {
            println!("    - {name}");
        }
    }
    if !report.corrupted.is_empty() {
        println!("  Corrupted ({}):", report.corrupted.len());
        for name in &report.corrupted {
            println!("    - {name}");
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Init { vault } => {
            let path = new_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let confirm = prompt_password("Confirm password")?;
            if password != confirm {
                return Err(Error::Operation("passwords don't match".into()));
            }
            Vault::new(path.clone()).init(&password)?;
            println!("Vault '{}' created at {}", vault, path.display());
        }
        Commands::Add { vault, path, name } => {
            let dir = existing_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(&password)?;
            v.add(&path, name.as_deref())?;
            println!("Added successfully!");
        }
        Commands::Remove { vault, name } => {
            let dir = existing_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(&password)?;
            v.remove(&name)?;
            println!("Removed successfully!");
        }
        Commands::List { vault } => {
            let dir = existing_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(&password)?;
            let files = v.list()?;
            if files.is_empty() {
                println!("Vault is empty");
                return Ok(());
            }
            println!("{:<40} {:>12} TYPE", "NAME", "SIZE");
            println!("{}", "-".repeat(60));
            for e in files {
                let size_str = if e.is_directory {
                    "-".to_string()
                } else {
                    format_size(e.size)
                };
                let type_str = if e.is_directory { "dir" } else { "file" };
                println!("{:<40} {:>12} {}", e.name, size_str, type_str);
            }
        }
        Commands::Extract { vault, name, dest } => {
            let dir = existing_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(&password)?;
            let out = v.extract(&name, &dest)?;
            println!("Extracted to: {}", out.display());
        }
        Commands::ChangePassword { vault } => {
            let dir = existing_vault_path(&vault)?;
            let old = prompt_password("Current password")?;
            let new = prompt_password("New password")?;
            let confirm = prompt_password("Confirm new password")?;
            if new != confirm {
                return Err(Error::Operation("new passwords don't match".into()));
            }
            Vault::new(dir).change_password(&old, &new)?;
            println!("Password changed successfully!");
        }
        Commands::Verify { vault } => {
            let dir = existing_vault_path(&vault)?;
            let password = prompt_password("Enter vault password")?;
            let report = Vault::new(dir).verify(&password)?;
            let ok = report.missing.is_empty() && report.corrupted.is_empty();
            print_report(&report);
            if !ok {
                std::process::exit(1);
            }
        }
        Commands::Encrypt { input, output } => {
            let password = prompt_password("Enter encryption password")?;
            let out_path = krypton::encrypt_file(&password, &input, output.as_deref())?;
            println!("Encrypted to: {}", out_path.display());
        }
        Commands::Decrypt { input, output } => {
            let password = prompt_password("Enter decryption password")?;
            let original_name = krypton::decrypt_file(&password, &input, &output)?;
            println!("Decrypted '{original_name}' to: {}", output.display());
        }
    }
    Ok(())
}
