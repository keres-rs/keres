# Krypton CLI usage

Run `krypton help` or `krypton <command> --help` for the built-in reference.

## Single files

```console
# Encrypt to a random-looking `.krf` name.
$ krypton encrypt document.pdf

# Encrypt to an explicit path.
$ krypton encrypt document.pdf backup.krf

# Decrypt; the original filename is recovered from the container.
$ krypton decrypt backup.krf restored.pdf
```

## Vaults

Vaults are named and stored under `~/.krypton/vaults/<name>` by default.

```console
$ krypton init personal
$ krypton add personal ./notes.txt
$ krypton add personal ./photos --name photos
$ krypton list personal
$ krypton extract personal photos ./restored
$ krypton verify personal
$ krypton change-password personal
$ krypton remove personal notes.txt
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

`krypton` prompts on a terminal. For scripts and CI, set
`KRYPTON_PASSWORD`:

```console
$ KRYPTON_PASSWORD="$SECRET" krypton add personal ./report.pdf
```

This is convenient but exposes the password to the process environment.
Prefer a terminal prompt on shared machines.
