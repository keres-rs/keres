# Krypton CLI

The `krypton` command-line interface for encrypted single-file containers
and multi-file vaults. It is a thin wrapper over
[`krypton-core`](https://crates.io/crates/krypton-core).

## Install

From the workspace root:

```console
$ cargo install --path crates/krypton-cli
```

Or, once published:

```console
$ cargo install krypton-cli
```

With Nix:

```console
$ nix run . -- --help
```

## Usage

```console
$ krypton help
```

### Single files

```console
# Encrypt to a random-looking .krf name.
$ krypton encrypt document.pdf

# Encrypt to an explicit path.
$ krypton encrypt document.pdf backup.krf

# Decrypt; the original filename is recovered from the container.
$ krypton decrypt backup.krf restored.pdf
```

### Vaults

Vaults live under `~/.krypton/vaults/<name>` by default. Set `KRYPTON_HOME`
to use a different base directory.

```console
$ krypton init personal
$ krypton add personal ./photos --name photos
$ krypton add personal ./notes.txt
$ krypton list personal
$ krypton extract personal photos ./restored
$ krypton verify personal
$ krypton change-password personal
$ krypton remove personal notes.txt
```

Passwords are read from a terminal prompt, or from the `KRYPTON_PASSWORD`
environment variable for scripts and CI. The core library's threat model still
applies: see [SECURITY.md](https://github.com/KryptonOSS/krypton-core/blob/main/SECURITY.md).

## Development

```console
$ cargo run -p krypton-cli -- help
$ cargo test --workspace
```

## License

Apache-2.0. See [LICENSE](https://github.com/KryptonOSS/krypton-core/blob/main/LICENSE).
