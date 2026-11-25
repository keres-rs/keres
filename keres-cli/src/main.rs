use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use keres::padding::Padding;
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
        /// Size-padding policy (none, adaptive, or a fixed bucket like 65536).
        #[arg(long, default_value = "none")]
        padding: String,
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
    /// Rename a top-level file or directory in the vault.
    Rename {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Current name in the vault.
        from: String,
        /// New name in the vault.
        to: String,
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
    /// Re-encrypt every entry under a fresh master key (deep rotation).
    ///
    /// Unlike change-password, this changes the data key itself. All other
    /// keyslots and any recovery kit are invalidated, and the vault ends up
    /// locked under the new password.
    Rotate {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Rotate without an interactive confirmation.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify the integrity of all vault entries (full authentication).
    Verify {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// After a successful check, delete blobs that no entry references.
        #[arg(long)]
        prune: bool,
    },
    /// Show or change the vault's size-padding policy.
    Padding {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Set the policy (none, adaptive, or a fixed bucket like 65536).
        #[arg(long)]
        set: Option<String>,
    },
    /// Remove an entry and rotate the master key (forward key invalidation).
    Erase {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Name of the file/folder to erase.
        name: String,
        /// Erase without an interactive confirmation.
        #[arg(short, long)]
        force: bool,
    },
    /// Upgrade a vault written by an older release (0.5.x) to the current format.
    Migrate {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Migrate without an interactive confirmation.
        #[arg(short, long)]
        force: bool,
    },
    /// Create or use a printable recovery kit.
    Recovery {
        #[command(subcommand)]
        action: RecoveryCommands,
    },
    /// Manage vault passphrases (keyslots).
    Keyslot {
        #[command(subcommand)]
        action: KeyslotCommands,
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
        /// Size-padding policy (none, adaptive, or a fixed bucket like 65536).
        #[arg(long, default_value = "none")]
        padding: String,
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

#[derive(Subcommand)]
enum RecoveryCommands {
    /// Create or replace the vault's printable recovery kit.
    Create {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Replace an existing kit (its old code stops working).
        #[arg(short, long)]
        force: bool,
    },
    /// Reset the vault password with a recovery code, consuming the kit.
    Use {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
}

#[derive(Subcommand)]
enum KeyslotCommands {
    /// List keyslot ids (stored in plaintext in vault.config).
    List {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
    /// Add an additional passphrase that unlocks the same vault.
    Add {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
    },
    /// Revoke a keyslot, authorized by a passphrase that will remain.
    Remove {
        /// Vault name (stored in `~/.keres/vaults/<name>`).
        vault: String,
        /// Keyslot id from `keres keyslot list`.
        slot: String,
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

/// Reads a recovery code directly; password sources do not apply.
fn read_recovery_code() -> Result<Zeroizing<String>> {
    let code = prompt_interactive("Recovery code")?;
    if code.trim().is_empty() {
        return Err(Error::Operation("recovery code must not be empty".into()));
    }
    Ok(code)
}

/// Reads a new secret twice and checks the entries match.
///
/// The first password source may be a file or `KERES_PASSWORD`, so the new
/// secret is always prompted (or read from the next stdin lines when input is
/// piped) rather than reusing that source.
fn read_new_password(prompt: &str) -> Result<Zeroizing<String>> {
    let first = prompt_interactive(prompt)?;
    let second = prompt_interactive("Confirm new password")?;
    if first.as_str() != second.as_str() {
        return Err(Error::Operation("new passwords don't match".into()));
    }
    if first.is_empty() {
        return Err(Error::Operation("password must not be empty".into()));
    }
    Ok(first)
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

fn parse_padding(value: &str) -> Result<Padding> {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(Padding::None),
        "adaptive" => Ok(Padding::Adaptive),
        other => {
            let size: u64 = other
                .parse()
                .map_err(|_| Error::Operation(format!("unknown padding policy: {value}")))?;
            Padding::fixed(size)
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
        Commands::Init { vault, padding } => {
            let path = new_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let confirm = passwords.read("Confirm password")?;
            if password.as_str() != confirm.as_str() {
                return Err(Error::Operation("passwords don't match".into()));
            }
            let padding = parse_padding(&padding)?;
            Vault::new(path.clone()).init_with_padding(password.as_str(), padding)?;
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
        Commands::Rename { vault, from, to } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            v.rename(&from, &to)?;
            println!("Renamed '{from}' to '{to}'");
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
            let new = read_new_password("New password")?;
            if new.as_str() == old.as_str() {
                return Err(Error::Operation(
                    "new password must differ from the current password".into(),
                ));
            }
            Vault::new(dir).change_password(old.as_str(), new.as_str())?;
            println!("Password changed successfully!");
        }
        Commands::Rotate { vault, force } => {
            let dir = existing_vault_path(&vault)?;
            let v = Vault::new(dir.clone());
            let slots = v.keyslots()?.len();
            let has_kit = v.has_recovery_kit();
            let extra: Vec<String> = [
                (slots.saturating_sub(1) > 0).then(|| {
                    format!(
                        "{} other keyslot{} will be revoked",
                        slots - 1,
                        if slots == 2 { "" } else { "s" }
                    )
                }),
                has_kit.then(|| "the recovery kit will be deleted".to_string()),
            ]
            .into_iter()
            .flatten()
            .collect();
            let consequences = if extra.is_empty() {
                String::new()
            } else {
                format!(" {};", extra.join(" and "))
            };
            if !force
                && !confirm(&format!(
                    "Rotate vault '{vault}'? Every entry is re-encrypted under a fresh master key;{} the vault is left locked under the new password.",
                    consequences
                ))?
            {
                println!("Aborted.");
                return Ok(());
            }
            let old = passwords.read("Current password")?;
            let new = read_new_password("New password")?;
            if new.as_str() == old.as_str() {
                return Err(Error::Operation(
                    "new password must differ from the current password".into(),
                ));
            }
            let report = Vault::new(dir).rotate(old.as_str(), new.as_str())?;
            println!(
                "Rotated: re-encrypted {} {} ({}).",
                report.entries,
                if report.entries == 1 {
                    "entry"
                } else {
                    "entries"
                },
                format_size(report.bytes)
            );
            if report.discarded_keyslots > 0 {
                println!(
                    "Revoked {} other keyslot{}.",
                    report.discarded_keyslots,
                    if report.discarded_keyslots == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
            if report.recovery_kit_removed {
                println!(
                    "Removed the old recovery kit; create a new one with `keres recovery create`."
                );
            }
            println!("The vault is locked; unlock it with the new password.");
        }
        Commands::Keyslot { action } => match action {
            KeyslotCommands::List { vault } => {
                let dir = existing_vault_path(&vault)?;
                let slots = Vault::new(dir).keyslots()?;
                println!("{:<20} NOTE", "SLOT");
                println!("{}", "-".repeat(60));
                for slot in slots {
                    let note = if slot.id == "legacy" {
                        "legacy config; converted on the next key change"
                    } else {
                        ""
                    };
                    println!("{:<20} {}", slot.id, note);
                }
            }
            KeyslotCommands::Add { vault } => {
                let dir = existing_vault_path(&vault)?;
                let current = passwords.read("Current vault password")?;
                let new = read_new_password("New passphrase")?;
                if new.as_str() == current.as_str() {
                    return Err(Error::Operation(
                        "new passphrase must differ from the current passphrase".into(),
                    ));
                }
                let slot = Vault::new(dir).add_keyslot(current.as_str(), new.as_str())?;
                println!("Added keyslot {}.", slot.id);
                println!(
                    "Store the new passphrase separately; any keyslot unlocks the same vault."
                );
            }
            KeyslotCommands::Remove { vault, slot } => {
                let dir = existing_vault_path(&vault)?;
                let password = passwords.read("Password for a keyslot that will remain")?;
                Vault::new(dir).remove_keyslot(&slot, password.as_str())?;
                println!("Removed keyslot {slot}.");
            }
        },
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
        Commands::Padding { vault, set } => {
            let dir = existing_vault_path(&vault)?;
            let password = passwords.read("Enter vault password")?;
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            if let Some(value) = set {
                let padding = parse_padding(&value)?;
                v.set_padding(padding)?;
                println!("Padding policy set to {}", padding);
            } else {
                let padding = v.padding()?;
                println!("Padding policy: {}", padding);
            }
        }
        Commands::Erase { vault, name, force } => {
            let dir = existing_vault_path(&vault)?;
            if !force
                && !confirm(&format!(
                    "Erase '{name}' from vault '{vault}'? This re-encrypts every other entry under a fresh master key."
                ))?
            {
                println!("Aborted.");
                return Ok(());
            }
            let password = passwords.read("Enter vault password")?;
            let new_password = read_new_password("New password after erase")?;
            if new_password.as_str() == password.as_str() {
                return Err(Error::Operation(
                    "new password must differ from the current password".into(),
                ));
            }
            let mut v = Vault::new(dir);
            v.unlock(password.as_str())?;
            let report = v.erase(&name, new_password.as_str())?;
            println!(
                "Erased '{}': re-encrypted {} {} ({}).",
                name,
                report.entries,
                if report.entries == 1 {
                    "entry"
                } else {
                    "entries"
                },
                format_size(report.bytes)
            );
        }
        Commands::Migrate { vault, force } => {
            let dir = existing_vault_path(&vault)?;
            if !force
                && !confirm(&format!(
                    "Migrate vault '{vault}' to the current format? Every entry is re-encrypted in place."
                ))?
            {
                println!("Aborted.");
                return Ok(());
            }
            let password = passwords.read("Enter vault password")?;
            let report = Vault::new(dir).migrate(password.as_str())?;
            println!(
                "Migrated {} {} ({} re-encrypted).",
                report.entries,
                if report.entries == 1 {
                    "entry"
                } else {
                    "entries"
                },
                format_size(report.bytes)
            );
        }
        Commands::Recovery { action } => match action {
            RecoveryCommands::Create { vault, force } => {
                let dir = existing_vault_path(&vault)?;
                let mut v = Vault::new(dir.clone());
                if v.has_recovery_kit() && !force {
                    return Err(Error::Operation(format!(
                        "vault {vault:?} already has a recovery kit; pass --force to replace it (the old code will stop working)"
                    )));
                }
                let password = passwords.read("Enter vault password")?;
                let code = v.create_recovery_kit(password.as_str())?;
                println!("Recovery code (store it offline; it will not be shown again):");
                println!("  {}", code.expose());
                println!(
                    "A wrapped copy of the master key was written to {}.",
                    dir.join("vault.recovery").display()
                );
                println!("Keep the code separate from the vault: either alone is not enough.");
            }
            RecoveryCommands::Use { vault } => {
                let dir = existing_vault_path(&vault)?;
                let code = read_recovery_code()?;
                let new = read_new_password("New password")?;
                Vault::new(dir).recover(code.as_str(), new.as_str())?;
                println!(
                    "Vault recovered. The recovery kit was consumed; create a new one if needed."
                );
            }
        },
        Commands::Encrypt {
            input,
            output,
            force,
            padding,
        } => {
            if let Some(out) = &output {
                refuse_overwrite(out, force)?;
            }
            let password = passwords.read("Enter encryption password")?;
            let padding = parse_padding(&padding)?;
            let out_path = if padding.is_none() {
                keres::encrypt_file(password.as_str(), &input, output.as_deref())?
            } else {
                keres::encrypt_file_with_padding(
                    password.as_str(),
                    &input,
                    output.as_deref(),
                    padding,
                )?
            };
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
