# CLI installation

The CLI package is `keres-cli`; the installed binary is `keres`.

## From crates.io

```console
$ cargo install keres-cli
$ keres --version
```

`cargo install` compiles the CLI and the library on your machine. Release
builds use size optimization for the binary, so a local debug install is
larger and slower.

## Prebuilt binaries

The release workflow publishes archives for:

- `x86_64-unknown-linux-gnu` (`.tar.gz`)
- `aarch64-apple-darwin` (`.tar.gz`)
- `x86_64-pc-windows-msvc` (`.zip`)

Each archive has a matching `.sha256` file. Download them from
[GitHub Releases](https://github.com/Keres-rs/keres/releases), verify the
checksum, and place the `keres` binary on `PATH`.

## From a checkout

```console
$ cargo install --path keres-cli
```

To run without installing:

```console
$ cargo run -p keres-cli -- help
```

## With Nix

From the repository root:

```console
$ nix run . -- --help
$ nix develop
```

`nix build` builds the workspace and installs the `keres` binary.

## Where vaults are stored

By default:

| Platform | Location |
|---|---|
| Linux, macOS | `$HOME/.keres/vaults/<name>` |
| Windows | `%USERPROFILE%\.keres\vaults\<name>` |
| Any (override) | `$KERES_HOME/vaults/<name>` |

Set `KERES_HOME` to keep vaults on an encrypted volume or a synced directory:

```console
$ export KERES_HOME="$HOME/sync/keres"
```

An empty `KERES_HOME` is rejected rather than silently falling back to the
home directory. Vault names are plain names, not paths; slashes, `..`, and
symlinked vault directories are rejected by the CLI.

## Passwords

Interactive prompts are the default. For non-interactive use, the CLI
supports:

- `--password-file <path>`: read the first line of a file.
- `--password-stdin`: read the first line of standard input.
- `KERES_PASSWORD`: read the password from the environment.

See [Passwords and automation](./cli-usage.md#passwords-and-automation) for
priority rules and security trade-offs.

## Next steps

- [CLI guide](./cli-usage.md)
- [CLI reference](./cli-reference.md)
- [Quick start](./usage.md)
