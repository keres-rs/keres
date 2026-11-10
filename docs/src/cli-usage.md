# Keres CLI usage

Run `keres help` or `keres <command> --help` for the built-in reference.

## Single files

```console
# Encrypt to a random-looking `.keres` name.
$ keres encrypt document.pdf

# Encrypt to an explicit path.
$ keres encrypt document.pdf backup.keres

# Decrypt; the original filename is recovered from the container.
$ keres decrypt backup.keres restored.pdf
```

## Vaults

Vaults are named and stored under `~/.keres/vaults/<name>` by default.

```console
$ keres init personal
$ keres add personal ./notes.txt
$ keres add personal ./photos --name photos
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
$ keres change-password personal
$ keres remove personal notes.txt
```

### Commands

| Command | Description |
|---|---|
| `init <vault>` | Create a new vault |
| `add <vault> <path> [--name NAME]` | Add a file or directory tree |
| `remove <vault> <name>` | Remove an entry and, for directories, its subtree |
| `list <vault>` | List top-level entries |
| `extract <vault> <name> <dest>` | Restore an entry |
| `verify <vault>` | Authenticate every entry |
| `change-password <vault>` | Re-wrap the master key under a new password |
| `encrypt <input> [output]` | Encrypt one file |
| `decrypt <input> <output>` | Decrypt one file |

## Passwords in scripts

`keres` prompts on a terminal. For scripts and CI, set
`KERES_PASSWORD`:

```console
$ KERES_PASSWORD="$SECRET" keres add personal ./report.pdf
```

This is convenient but exposes the password to the process environment.
Prefer a terminal prompt on shared machines.
