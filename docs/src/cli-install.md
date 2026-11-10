# Keres CLI

The `keres` binary provides single-file encryption and vault management from
the terminal.

## From crates.io

```console
$ cargo install keres-cli
$ keres --version
```

## From this workspace

```console
$ cargo install --path crates/keres-cli
```

or run it without installing:

```console
$ cargo run -p keres-cli -- help
```

## With Nix

From the workspace root:

```console
$ nix run . -- --help
$ nix develop
```

## Default locations

Vaults are stored under `~/.keres/vaults/<name>` by default. Set
`KERES_HOME` to use a different base directory:

```console
$ export KERES_HOME="$HOME/sync/keres"
```

Next: [use the CLI](cli-usage.md).
