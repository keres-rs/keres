# Troubleshooting

This page covers common errors and recovery steps. If a step here would
delete data, stop and make a copy of the vault directory first.

## `Authentication failed: wrong password or corrupted data`

Keres deliberately reports wrong passwords and tampered ciphertext with the
same error, so the message cannot be used as a tamper oracle.

Check, in order:

1. The password source. `--password-file` reads only the first line;
   `--password-stdin` consumes one line; `KERES_PASSWORD` is used only when
   no explicit flag is present.
2. Whitespace or shell quoting around the password.
3. Whether the container or vault was copied completely. Truncated downloads
   and partially synced folders fail authentication.
4. Whether the file is a Keres container at all. A wrong magic returns
   `IncompatibleFormat`, not `Authentication`.

If the password is correct and the data still fails, restore from a known-good
backup. Do not repeatedly rewrite the vault.

## `vault not found`

The CLI resolves a vault to `$KERES_HOME/vaults/<name>` or
`~/.keres/vaults/<name>`. Check:

- `KERES_HOME` is set in the current shell and is not empty;
- the vault name matches the directory name exactly;
- the path is a directory, not a symlink (the CLI refuses symlinked vaults);
- on Windows, `USERPROFILE` is set if `KERES_HOME` is not.

## `vault is busy: another process is using it`

Another process holds the advisory lock on `vault.lock`. Wait for it to finish
or stop it. The lock is released when the process exits; the empty
`vault.lock` file is always present and is not a stale-lock indicator.

Do not delete `vault.lock` while a process is running. It is the coordination
point, not a record of ownership.

## `vault uses a legacy format; run keres migrate`

A 0.5.x vault (manifest v2) was opened by a current release. Back up the vault
directory, then run:

```console
$ keres migrate <vault>
```

Migration is one-way. See
[Recovery, rotation, and migration](./operations.md#migrating-a-05x-vault).

## `incompatible container format`

The file is not a current Keres container. This includes pre-rename Krypton
files and pre-0.4 formats. Use the release that wrote the file to decrypt it,
then re-encrypt with the current release. There is no compatibility reader
for retired formats.

## `unsupported container version`

The file was written by a newer Keres release than the one you are running.
Upgrade to that release or newer. Do not patch the version byte; the format
may have changed.

## `entry already exists` / `entry not found`

- `add` refuses to overwrite. Use `replace` for a file, or `remove` first.
- `replace` and `remove` match top-level names or full `parent/child` paths
  exactly. `list` shows only top-level entries; pass the full path for a
  nested entry.
- Names containing `/`, `\`, `..`, or control characters are rejected.

## Verification reports missing or corrupted entries

`keres verify` exits with status `1` and lists the affected entries.

- **Missing** means the index references a blob that is not on disk. Restore
  the vault directory from a backup, or accept that the entry is lost.
- **Corrupted** means the blob exists but fails authentication, size, or
  content-hash checks. Restore that entry from a backup.

If the vault is otherwise healthy and you have interrupted operations, remove
unreferenced blobs after a successful check:

```console
$ keres verify <vault> --prune
```

`--prune` never runs after a failed check and never runs if the index snapshot
is missing.

## `vault.config` is missing or damaged

Use the recovery kit:

```console
$ keres recovery use <vault>
```

You need both the vault directory and the recovery code. Recovery writes a
fresh single-slot config and consumes the kit. Additional keyslots are lost.

Without a recovery kit, a lost or damaged `vault.config` means the vault cannot
be unlocked. Do not delete the directory; a future release may add recovery
tooling, and the ciphertext is still there.

## A rotation, erase, or migration was interrupted

Do not delete `vault.rotate`, `d/.index.compact`, or `*.next` files manually.
The next operation that opens the vault completes or rolls back the journaled
operation. Then run:

```console
$ keres verify <vault>
$ keres verify <vault> --prune
```

If the process ran out of disk space, free space first. The old vault remains
readable when rotation has not reached its commit point.

## `confirmation requires a terminal; pass --force`

Destructive commands ask for `y/N` on a terminal. In scripts or CI, pass
`--force` explicitly:

```console
$ keres remove --force personal old-notes.txt
```

Only use `--force` after checking the vault name and entry name.

## `already exists; pass --force to overwrite`

`encrypt`, `decrypt`, and `extract` refuse to replace an existing destination.
Pass `--force` if replacement is intended. For extraction, the destination
path itself must not exist unless `--force` is given.

## Password file or stdin fails

- `--password-file` must be readable and contain the password on the first
  line.
- `--password-file` and `--password-stdin` cannot be combined.
- New passwords for `change-password`, `rotate`, `erase`, and `recovery use`
  are still prompted (or read from subsequent stdin lines), even when the
  current password came from a file or `KERES_PASSWORD`.
- With `--password-stdin`, provide consecutive lines in the order the prompts
  appear.

## Operations are slower than expected

- The first unlock or `.krs` encryption pays Argon2id: 64 MiB and four passes
  by default. This is intentional.
- Bulk encryption is single-threaded today.
- Padding increases the amount of data written and may add I/O.
- Network filesystems and cloud-synced folders can be much slower than local
  disks, and some do not provide reliable atomic rename.

See [Performance](./performance.md) for measurement guidance.

## Permissions

On Unix, Keres creates files with owner-only permissions (`0600`) and vault
directories with `0700`. If a vault was copied with different ownership or
modes, restore access deliberately; do not loosen permissions on a shared
machine.

## Getting more help

Include the following in a bug report:

- Keres version (`keres --version`);
- operating system and filesystem;
- the exact command and error text (with secrets removed);
- whether the vault was created by an older release;
- whether a process was interrupted, killed, or ran out of disk space.

For suspected vulnerabilities, follow
[SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md)
instead of opening a public issue.
