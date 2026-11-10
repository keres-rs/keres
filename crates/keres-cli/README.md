# Keres CLI

The `keres` command-line interface for encrypted single-file containers
and multi-file vaults. It is a thin wrapper over
[`keres`](https://crates.io/crates/keres).

## Install

From the workspace root:

```console
$ cargo install --path crates/keres-cli
```

Or, once published:

```console
$ cargo install keres-cli
```

With Nix:

```console
$ nix run . -- --help
```

## Usage

```console
$ keres help
```

### Single files

```console
# Encrypt to a random-looking .keres name.
$ keres encrypt document.pdf

# Encrypt to an explicit path.
$ keres encrypt document.pdf backup.keres

# Decrypt; the original filename is recovered from the container.
$ keres decrypt backup.keres restored.pdf
```

### Vaults

Vaults live under `~/.keres/vaults/<name>` by default. Set `KERES_HOME`
to use a different base directory.

```console
$ keres init personal
$ keres add personal ./photos --name photos
$ keres add personal ./notes.txt
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
$ keres change-password personal
$ keres remove personal notes.txt
```

Passwords are read from a terminal prompt, or from the `KERES_PASSWORD`
environment variable for scripts and CI. The library's threat model still
applies: see [SECURITY.md](https://github.com/KeresOSS/keres/blob/main/SECURITY.md).

## Development

```console
$ cargo run -p keres-cli -- help
$ cargo test --workspace
```

## License

Apache-2.0. See [LICENSE](https://github.com/KeresOSS/keres/blob/main/LICENSE).
