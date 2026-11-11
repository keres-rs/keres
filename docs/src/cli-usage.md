# Keres CLI usage

Run `keres help` or `keres <command> --help` for the built-in reference.

## Single files

```console
# Encrypt to a random-looking `.krs` name.
$ keres encrypt document.pdf

# Encrypt to an explicit path.
$ keres encrypt document.pdf backup.krs

# Decrypt; the original filename is recovered from the container.
$ keres decrypt backup.krs restored.pdf
```

## Vaults

Vaults are named and stored under `~/.keres/vaults/<name>` by default.

```console
$ keres init personal
$ keres add personal ./notes.txt
$ keres add personal ./photos --name photos
$ keres replace personal ./notes-v2.txt notes.txt
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
$ keres verify personal --prune
$ keres change-password personal
$ keres remove personal notes.txt
```

### Commands

| Command | Description |
|---|---|
| `init <vault>` | Create a new vault |
| `add <vault> <path> [--name NAME]` | Add a file or directory tree |
| `replace <vault> <path> <name>` | Replace an existing file entry |
| `remove <vault> <name> [--force]` | Remove an entry and, for directories, its subtree |
| `list <vault>` | List top-level entries |
| `extract <vault> <name> <dest> [--force]` | Restore an entry |
| `verify <vault> [--prune]` | Authenticate every entry; `--prune` deletes unreferenced blobs |
| `change-password <vault>` | Re-wrap the master key under a new password |
| `encrypt <input> [output] [--force]` | Encrypt one file |
| `decrypt <input> <output> [--force]` | Decrypt one file |

## Overwriting and destructive operations

`remove` asks for confirmation on a terminal and refuses to run without
`--force` when standard input is not a terminal. `extract`, `encrypt`, and
`decrypt` refuse to overwrite an existing destination unless `--force` is
given.

`verify --prune` deletes ciphertext blobs under `d/` that no manifest entry
references (left behind by an interrupted add) and cleans up stale temp
files. It only prunes after a successful integrity check and refuses to run
if the manifest is missing.

## Passwords in scripts

`keres` prompts on a terminal. For scripts and CI, choose one of:

```console
# Read the first line of a file (kept out of the environment).
$ keres --password-file /run/secrets/keres init personal

# Read from standard input.
$ printf '%s\n' "$SECRET" | keres --password-stdin list personal

# Environment variable (convenient, but visible to the same user in /proc).
$ KERES_PASSWORD="$SECRET" keres add personal ./report.pdf
```

Explicit flags take priority over `KERES_PASSWORD`, which takes priority over
an interactive prompt. Password values are held in zeroizing buffers and
scrubbed when the command finishes. Prefer a terminal prompt or a
permission-restricted password file on shared machines.

`change-password` reads one password per prompt, so with
`--password-stdin` it expects the current password, the new password, and the
confirmation on three consecutive lines. With `--password-file` or
`KERES_PASSWORD` every prompt gets the same value, which is rejected because
the new password must differ from the current one.
