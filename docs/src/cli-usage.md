# CLI guide

The `keres` binary has two families of commands:

- `keres encrypt` / `keres decrypt` for standalone `.krs` containers.
- `keres init`, `add`, `list`, `extract`, and related commands for vaults.

Run `keres help` for the command list, `keres <command> --help` for a single
command, or see the [CLI reference](./cli-reference.md) for every option.

## Global behavior

| Behavior | Detail |
|---|---|
| Password prompts | Interactive terminal prompt by default |
| Non-interactive sources | `--password-file`, `--password-stdin`, `KERES_PASSWORD` |
| Exit status | `0` on success; `1` on any error, including failed verification |
| Vault location | `$KERES_HOME/vaults/<name>` or `~/.keres/vaults/<name>` |
| Overwrite policy | Refuses existing outputs unless `--force` |
| Destructive operations | Ask for confirmation on a terminal; require `--force` otherwise |

## Single files

### Encrypt

```console
$ keres encrypt document.pdf
Encrypted to: 8e2f...b71.krs
```

With an explicit output path:

```console
$ keres encrypt document.pdf backup.krs
```

The original filename is stored inside the container, not in the output
filename. Use `--padding adaptive` (or a fixed bucket) to hide the exact file
size:

```console
$ keres encrypt document.pdf --padding adaptive
$ keres encrypt document.pdf backup.krs --padding 65536
```

### Decrypt

```console
$ keres decrypt backup.krs restored.pdf
Decrypted 'document.pdf' to: restored.pdf
```

`decrypt` refuses to overwrite an existing output unless `--force` is passed.
The source `.krs` file is never modified.

## Vault basics

### Create a vault

```console
$ keres init personal
Vault 'personal' created at /home/you/.keres/vaults/personal
```

`init` prompts twice for the password and fails if the vault already exists.
To choose a padding policy at creation time:

```console
$ keres init private --padding adaptive
$ keres init records --padding 65536
```

### Add entries

```console
$ keres add personal ./notes.txt
Added successfully!

$ keres add personal ./photos --name pictures
Added successfully!
```

Without `--name`, the source basename is used. Directories are added
recursively. Symlinks and special files are skipped. A name collision is an
error; use `replace` for a file or `remove` first.

### List entries

```console
$ keres list personal
NAME                                              SIZE TYPE
------------------------------------------------------------
notes.txt                                          4.2 KB file
pictures                                                - dir
```

Only top-level entries are listed. A nested entry is addressed by its full
`parent/child` path in commands that accept an entry name.

### Extract

```console
$ keres extract personal notes.txt ./out
Extracted to: ./out/notes.txt

$ keres extract personal pictures ./out
Extracted to: ./out/pictures
```

Extraction recreates directory structure under the destination. It refuses to
overwrite an existing destination path unless `--force` is passed. Stored
names are sanitized before joining paths, so a malicious vault cannot write
outside the destination.

## Modifying a vault

```console
$ keres replace personal ./notes-v2.txt notes.txt
Replaced successfully!

$ keres rename personal notes.txt journal.txt
Renamed 'notes.txt' to 'journal.txt'

$ keres remove personal journal.txt
Remove 'journal.txt' from vault 'personal'? This cannot be undone. [y/N]
```

- `replace` writes new ciphertext under a fresh entry ID and removes the old
  blob after the index commit. It works on files, not directories.
- `rename` changes the top-level name in the encrypted index; ciphertext is
  not rewritten.
- `remove` deletes files, or a directory and its entire subtree. On a
  non-interactive stdin it requires `--force`.

## Verify and repair

```console
$ keres verify personal
Vault integrity check:
  Entries total:   42
  Entries verified: 42
  Status: OK — all files present and authenticated
```

`verify` decrypts every entry and checks its AEAD tags, recorded size, and
content hash. Missing and corrupted entries are listed, and the command exits
with status `1`.

Interrupted operations can leave unreferenced blobs behind. After a successful
check, remove them with:

```console
$ keres verify personal --prune
```

`--prune` only runs after a successful integrity check and refuses to run if
the index snapshot is missing.

## Padding policy

```console
$ keres padding personal
Padding policy: None

$ keres padding personal --set adaptive
Padding policy set to Adaptive

$ keres padding personal --set 65536
Padding policy set to Fixed { size: 65536 }
```

The policy is stored in the authenticated index. It affects future adds and
replaces; existing blobs are not rewritten. `--padding none` restores exact
sizes. Padding hides exact sizes, not access patterns.

## Passwords and automation

By default the CLI prompts on the terminal without echoing. For scripts, use
one of the following sources. They are consulted in this order:

1. `--password-file <path>` or `--password-stdin` (mutually exclusive)
2. `KERES_PASSWORD`
3. interactive prompt (or a plain line when stdin is not a terminal)

```console
# First line of a file, kept out of the environment.
$ keres --password-file /run/secrets/keres init personal

# First line of standard input.
$ printf '%s\n' "$SECRET" | keres --password-stdin list personal

# Environment variable. Convenient, but visible in /proc on many systems.
$ KERES_PASSWORD="$SECRET" keres add personal ./report.pdf
```

Every password value is held in a zeroizing buffer and scrubbed when the
process exits. On shared machines, prefer the terminal prompt or a
permission-restricted password file over `KERES_PASSWORD`.

Commands that set a new password (`change-password`, `rotate`, `erase`,
`recovery use`) still prompt for the new secret and its confirmation, even if
the current password came from a file or environment variable. With
`--password-stdin`, the new password is read from the next stdin lines.

## Destructive operations

These commands can delete data or invalidate credentials:

| Command | Effect |
|---|---|
| `remove <vault> <name>` | Deletes an entry and its subtree |
| `rotate <vault>` | Re-encrypts everything under a new master key; revokes other keyslots and the recovery kit |
| `erase <vault> <name>` | Removes an entry and rotates in one commit |
| `migrate <vault>` | One-way upgrade of a 0.5.x vault |

They ask for confirmation when stdin is a terminal. In scripts, pass
`--force`. Read [Recovery, rotation, and migration](./operations.md) before
using `rotate`, `erase`, or `migrate`.

## Recovery and keyslots

Keyslot commands manage additional passphrases:

```console
$ keres keyslot list personal
$ keres keyslot add personal
$ keres keyslot remove personal 0123456789abcdef
```

Recovery kits let you regain access if `vault.config` is lost:

```console
$ keres recovery create personal
Recovery code (store it offline; it will not be shown again):
  XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

`recovery use personal` consumes the kit and resets the password. The full
procedures and caveats are in
[Recovery, rotation, and migration](./operations.md).

## Exit status and output

- `0` — command completed successfully.
- `1` — any error: invalid password, missing entry, failed verification,
  declined confirmation, I/O failure, or an unsupported format.
- Human-readable progress and results go to stdout; errors go to stderr as
  `Error: <message>`.

There is no machine-readable (JSON) output mode yet. Scripts that need to
parse results should prefer the library API.
