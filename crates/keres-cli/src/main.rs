use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use keres::prelude::*;

use keres::Vault;

fn vault_root() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("KERES_HOME") {
        if dir.is_empty() {
            return Err(Error::Operation("KERES_HOME is set but empty".into()));
        }
        return Ok(PathBuf::from(dir).join("vaults"));
    }
    match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".keres").join("vaults")),
        Some(_) => Err(Error::Operation(
            "HOME is set but empty; unset it or set KERES_HOME".into(),
        )),
        None => Err(Error::Operation(
            "cannot determine home directory; set HOME or KERES_HOME".into(),
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
            "no vault named {name:?} at {} (create it with `keres init {name}`)",
            path.display()
        )));
    }
    Ok(path)
}

#[derive(Parser)]
#[command(name = "keres")]
#[command(version = keres::VERSION)]
#[command(about = "Encrypt your personal files or secrets", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Read the password from the first line of this file.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        conflicts_with = "password_stdin"
    )]
    password_file: Option<PathBuf>,

    /// Read the password from the first line of standard input.
    #[arg(long, global = true, conflicts_with = "password_file")]
    password_stdin: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault.
    Init {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
    /// Add a file or folder to the vault.
    Add {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Path to the file or folder to add.
        path: PathBuf,
        /// Custom name in vault.
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Replace an existing file entry with a new file.
    Replace {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Path to the new file contents.
        path: PathBuf,
        /// Name of the existing file entry in the vault.
        name: String,
    },
    /// Remove a file or folder from the vault.
    Remove {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Name of the file/folder in vault.
        name: String,
        /// Remove without an interactive confirmation.
        #[arg(short, long)]
        force: bool,
    },
    /// List vault contents.
    List {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
    /// Extract/decrypt a file from the vault.
    Extract {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Name of the file in vault.
        name: String,
        /// Destination path.
        dest: PathBuf,
        /// Overwrite the destination if it already exists.
        #[arg(short, long)]
        force: bool,
    },
    /// Change the vault password.
    ChangePassword {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
    /// Verify the integrity of all vault entries (full authentication).
    Verify {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// After a successful check, delete blobs that no entry references.
        #[arg(long)]
        prune: bool,
    },
    /// Encrypt a single file.
    Encrypt {
        /// Path to the file to encrypt.
        input: PathBuf,
        /// Output encrypted file (default: random hashed name).
        output: Option<PathBuf>,
        /// Overwrite the output if it already exists.
        #[arg(short, long)]
        force: bool,
    },
    /// Decrypt a single file.
    Decrypt {
        /// Path to the encrypted file (.krs).
        input: PathBuf,
        /// Output decrypted file.
        output: PathBuf,
        /// Overwrite the output if it already exists.
        #[arg(short, long)]
        force: bool,
    },
}

/// Where the password for this invocation comes from.
///
/// Explicit flags win over `KERES_PASSWORD`, which wins over an interactive
/// prompt. Every value is held in a [`Zeroizing`] buffer so it is scrubbed
/// when the command finishes.
struct PasswordSource {
    file: Option<PathBuf>,
    stdin: bool,
}

impl PasswordSource {
    fn read(&self, prompt: &str) -> Result<Zeroizing<String>> {
        let password = self.read_inner(prompt)?;
        if password.is_empty() {
            return Err(Error::Operation("password must not be empty".into()));
        }
        Ok(password)
    }

    fn read_inner(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if let Some(path) = &self.file {
            let raw = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                Error::Operation(format!("cannot read password file {}: {e}", path.display()))
            })?);
            return Ok(Zeroizing::new(first_line(&raw).to_string()));
        }
        if self.stdin {
            return read_stdin_line();
        }
        if let Ok(password) = std::env::var("KERES_PASSWORD") {
            return Ok(Zeroizing::new(password));
        }
        prompt_interactive(prompt)
    }
}

fn first_line(text: &str) -> &str {
    text.split(['\n', '\r']).next().unwrap_or("")
}

fn read_stdin_line() -> Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    io::stdin()
        .read_line(&mut line)
        .map_err(|_| Error::Operation("failed to read password from stdin".into()))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn prompt_interactive(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{prompt}: ");
    io::stdout().flush().ok();
    if io::stdin().is_terminal() {
        let password = rpassword::read_password()
            .map_err(|_| Error::Operation("failed to read password".into()))?;
        Ok(Zeroizing::new(password))
    } else {
        // No TTY (piped input): read a plain line so scripts and CI can drive us.
        read_stdin_line()
    }
}

/// Asks for a yes/no answer. Returns an error when there is no terminal to
/// ask on, so a destructive operation in a script must opt in with `--force`.
fn confirm(prompt: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(Error::Operation(
            "confirmation requires a terminal; pass --force to proceed".into(),
        ));
    }
    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| Error::Operation("failed to read confirmation".into()))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn refuse_overwrite(path: &Path, force: bool) -> Result<()> {
    if !force && path.exists() {
        return Err(Error::Operation(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        )));
    }
    Ok(())
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
    let passwords = PasswordSource {
        file: cli.password_file,
        stdin: cli.password_stdin,
    };
    if let Err(e) = run(cli.command, &passwords) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(command: Commands, passwords: &PasswordSource) -> Result<()> {
    match command {
        Commands::Init { vault } => {
            let path = new_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let confirm = passwords.read("Confirm password")?;
            if password.as_str() != confirm.as_str() {
                return Err(Error::Operation("passwords don't match".into()));
            }
            Vault::new(path.clone()).init(password.as_str())?;
            println!("Vault '{}' created at {}", vault, path.display());
        }
        Commands::Add { vault, path, name } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            v.add(&path, name.as_deref())?;
            println!("Added successfully!");
        }
        Commands::Replace { vault, path, name } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            v.replace(&path, &name)?;
            println!("Replaced successfully!");
        }
        Commands::Remove { vault, name, force } => {
            let dir = existing_vault_path(&vault)?;
            if !force
                && !confirm(&format!(
                    "Remove '{name}' from vault '{vault}'? This cannot be undone."
                ))?
            {
                println!("Aborted.");
                return Ok(());
            }
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            v.remove(&name)?;
            println!("Removed successfully!");
        }
        Commands::List { vault } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
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
        Commands::Extract {
            vault,
            name,
            dest,
            force,
        } => {
            let dir = existing_vault_path(&vault)?;
            refuse_overwrite(&dest, force)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            let out = v.extract(&name, &dest)?;
            println!("Extracted to: {}", out.display());
        }
        Commands::ChangePassword { vault } => {
            let dir = existing_vault_path(&vault)?;
            let old = passwords.read("Current password")?;
            let new = passwords.read("New password")?;
            let confirm = passwords.read("Confirm new password")?;
            if new.as_str() != confirm.as_str() {
                return Err(Error::Operation("new passwords don't match".into()));
            }
            if new.as_str() == old.as_str() {
                return Err(Error::Operation(
                    "new password must differ from the current password".into(),
                ));
            }
            Vault::new(dir).change_password(old.as_str(), new.as_str())?;
            println!("Password changed successfully!");
        }
        Commands::Verify { vault, prune } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            let report = v.verify(password.as_str())?;
            let ok = report.missing.is_empty() && report.corrupted.is_empty();
            print_report(&report);
            if !ok {
                std::process::exit(1);
            }
            if prune {
                v.unlock(password.as_str())?;
                let removed = v.prune_orphans()?;
                println!("Pruned {removed} orphaned file(s)");
            }
        }
        Commands::Encrypt {
            input,
            output,
            force,
        } => {
            if let Some(out) = &output {
                refuse_overwrite(out, force)?;
            }
            let password = passwords.read("Enter encryption password")?;
            let out_path = keres::encrypt_file(password.as_str(), &input, output.as_deref())?;
            println!("Encrypted to: {}", out_path.display());
        }
        Commands::Decrypt {
            input,
            output,
            force,
        } => {
            refuse_overwrite(&output, force)?;
            let password = passwords.read("Enter decryption password")?;
            let original_name = keres::decrypt_file(password.as_str(), &input, &output)?;
            println!("Decrypted '{original_name}' to: {}", output.display());
        }
    }
    Ok(())
}
