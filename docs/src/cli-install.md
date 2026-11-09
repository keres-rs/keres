# Krypton CLI

The `krypton` binary provides single-file encryption and vault management from
the terminal.

## From crates.io

```console
$ cargo install krypton-cli
$ krypton --version
```

## From this workspace

```console
$ cargo install --path crates/krypton-cli
```

or run it without installing:

```console
$ cargo run -p krypton-cli -- help
```

## With Nix

From the workspace root:

```console
$ nix run . -- --help
$ nix develop
```

## Default locations

Vaults are stored under `~/.krypton/vaults/<name>` by default. Set
`KRYPTON_HOME` to use a different base directory:

```console
$ export KRYPTON_HOME="$HOME/sync/krypton"
```

Next: [use the CLI](cli-usage.md).
