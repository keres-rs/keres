# CLI reference

This page is the command reference for the `keres` binary. For task-oriented
examples, see the [CLI guide](./cli-usage.md).

## Synopsis

```text
keres [GLOBAL OPTIONS] <COMMAND> [ARGS]
```

```console
$ keres --version
keres 0.7.1
```

## Global options

| Option | Meaning |
|---|---|
| `--password-file <PATH>` | Read the password from the first line of `PATH` |
| `--password-stdin` | Read the password from the first line of standard input |
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print the version |

`--password-file` and `--password-stdin` conflict. Both are global and may be
placed before or after the subcommand. If neither is given, the CLI uses
`KERES_PASSWORD`, then an interactive prompt.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `KERES_HOME` | CLI | Base directory for vaults; vaults live in `$KERES_HOME/vaults/` |
| `KERES_PASSWORD` | CLI | Password fallback when no explicit source is given |
| `HOME` / `USERPROFILE` | CLI | Default home directory when `KERES_HOME` is unset |

An empty `KERES_HOME`, or an empty home directory, is an error rather than a
silent fallback.

## Vault commands

Vault names are plain names, not paths. The CLI rejects names containing `/`
or `\`, `.`/`..`, an empty name, and vault locations that are symlinks.

### `keres init`

```text
keres init <VAULT> [--padding <POLICY>]
```

Creates a vault under the default vault directory and leaves it unlocked for
that process only. Prompts twice for the password.

| Argument | Meaning |
|---|---|
| `<VAULT>` | Vault name |
| `--padding <POLICY>` | `none` (default), `adaptive`, or a fixed bucket size in bytes |

Example:

```console
$ keres init personal --padding adaptive
```

### `keres add`

```text
keres add <VAULT> <PATH> [--name <NAME>]
```

Adds a file or a directory tree recursively. The default name is the source
basename. Symlinks and special files are skipped. A colliding name is an
error.

| Option | Meaning |
|---|---|
| `-n`, `--name <NAME>` | Name in the vault instead of the source basename |

### `keres replace`

```text
keres replace <VAULT> <PATH> <NAME>
```

Replaces the contents of an existing file entry with `PATH`. Directory
entries cannot be replaced. The operation is copy-on-write and commits the
index before deleting the old blob.

### `keres rename`

```text
keres rename <VAULT> <FROM> <TO>
```

Renames a top-level file or directory. Nested paths are not accepted. Stored
ciphertext is not rewritten.

### `keres remove`

```text
keres remove <VAULT> <NAME> [--force]
```

Removes a file, or a directory and its entire subtree. Asks for confirmation
on a terminal; requires `--force` on a non-interactive stdin.

### `keres list`

```text
keres list <VAULT>
```

Lists top-level entries with name, size, and type. Directory sizes are shown
as `-`. Does not touch entry blobs.

### `keres extract`

```text
keres extract <VAULT> <NAME> <DEST> [--force]
```

Extracts a file or directory tree under `DEST`. Recovered names are sanitized
before path joins. The destination must not already exist unless `--force` is
given.

### `keres change-password`

```text
keres change-password <VAULT>
```

Re-wraps one keyslot under a new password. Stored data and other keyslots are
untouched. Prompts for the current password, then the new password twice.
The new password must differ from the current one.

### `keres verify`

```text
keres verify <VAULT> [--prune]
```

Authenticates the index and every entry, checks recorded sizes and content
hashes, and prints missing/corrupted entries. Exits with status `1` if any
entry fails.

| Option | Meaning |
|---|---|
| `--prune` | After a successful check, delete unreferenced blobs and stale temp files under `d/` |

### `keres padding`

```text
keres padding <VAULT> [--set <POLICY>]
```

Without `--set`, prints the current policy. With `--set`, changes it for
future writes. Existing blobs keep their original sizes.

### `keres rotate`

```text
keres rotate <VAULT> [--force]
```

Deep rotation: generates a fresh master key, re-encrypts every entry, rewrites
the index, collapses the vault to one keyslot under the new password, and
removes any recovery kit. The vault is left locked. Asks for confirmation on
a terminal; requires `--force` otherwise.

### `keres erase`

```text
keres erase <VAULT> <NAME> [--force]
```

Removes one entry and performs a deep rotation in a single journaled commit.
Survivors are re-encrypted under a fresh master key. Other keyslots and the
recovery kit are removed. Leaves the vault locked under a new password.

### `keres migrate`

```text
keres migrate <VAULT> [--force]
```

One-way upgrade of a 0.5.x vault (manifest v2) to the current format. Every
entry is re-encrypted in place, the same password is kept, and legacy blobs
are removed after the commit. Back up the vault directory first.

## Recovery commands

### `keres recovery create`

```text
keres recovery create <VAULT> [--force]
```

Creates or replaces `vault.recovery`, writes a second wrapping of the master
key, and prints a one-time recovery code. `--force` replaces an existing kit;
the old code stops working.

### `keres recovery use`

```text
keres recovery use <VAULT>
```

Prompts for the recovery code, validates it against the encrypted index, sets
a new password, and consumes the kit. Additional keyslots are lost.

## Keyslot commands

### `keres keyslot list`

```text
keres keyslot list <VAULT>
```

Lists plaintext slot ids from `vault.config`. No password required.

### `keres keyslot add`

```text
keres keyslot add <VAULT>
```

Adds an independent passphrase that unlocks the same master key. Prompts for
an existing passphrase, then the new one twice.

### `keres keyslot remove`

```text
keres keyslot remove <VAULT> <SLOT>
```

Revokes a slot. Prompts for a passphrase from a slot that will remain, so a
mistyped target cannot remove the only credential. The last slot cannot be
removed.

## Single-file commands

### `keres encrypt`

```text
keres encrypt <INPUT> [OUTPUT] [--force] [--padding <POLICY>]
```

Encrypts one file into a `.krs` container. With no `OUTPUT`, a hash-derived
name is written in the current directory. Refuses to overwrite an existing
output unless `--force` is given.

| Option | Meaning |
|---|---|
| `-f`, `--force` | Overwrite an existing output |
| `--padding <POLICY>` | `none` (default), `adaptive`, or a fixed bucket size |

### `keres decrypt`

```text
keres decrypt <INPUT> <OUTPUT> [--force]
```

Decrypts a `.krs` container, recovers the original filename, and writes the
plaintext to `OUTPUT`. Refuses to overwrite an existing output unless
`--force` is given.

## Padding policies

| Value | Behavior |
|---|---|
| `none` | No padding; exact plaintext size is visible in ciphertext length |
| `adaptive` | Next power of two in 4 KiB–16 MiB; larger files round to the next 16 MiB multiple |
| integer | Fixed bucket size in bytes; must be in 4 KiB–16 MiB |

Examples: `--padding none`, `--padding adaptive`, `--padding 65536`.

Padding hides exact sizes, not access patterns. The vault policy is stored in
the authenticated index; the single-file policy is recorded in the container.

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success |
| `1` | Error, failed verification, declined confirmation, or unsupported format |

Errors are printed to stderr as `Error: <message>`. Prompts and results are
printed to stdout.

## Files written by the CLI

| Path | Contents |
|---|---|
| `$KERES_HOME/vaults/<name>/` or `~/.keres/vaults/<name>/` | Vault directory |
| `<hash>.krs` | Single-file container when no output is given |
| `vault.recovery` | Recovery kit, if created |

The vault directory layout is documented in
[Vault layout](./architecture.md#vault-layout).
