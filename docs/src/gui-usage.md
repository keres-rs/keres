# Keres Desktop

`keres-desktop/` is a graphical client for Keres. It is a Rust +
iced application that embeds the library directly; it does not shell out to
the CLI.

The GUI is a separate Cargo workspace and is excluded from the library
workspace. It is a reference consumer and a showcase, not part of the library's
compatibility contract.

## What it shows

- The full vault lifecycle: create with padding and KDF options, unlock, lock,
  verify, migrate a legacy v2 manifest, rotate the master key, and crypto-erase
  an entry.
- Keyslots and recovery: independent passphrases, a one-time recovery kit, and
  recovery of a closed vault.
- The in-memory reader/writer APIs: the password store never writes plaintext
  to a temporary file.
- Honest security UX: a page that lists the threat model, known limitations,
  and the lack of an independent audit.
- Readability controls: the navbar scales all text from 80% to 300%, and the
  visual style uses sharp corners throughout.

The app is focused on storage. The generic symmetric, hash, key, and sign
pages were removed so the vault, password store, and file containers lead.

## Build and run

```console
cd keres-desktop
cargo run
```

A graphical session is required. On Linux, use the included Nix flake for the
toolchain and system libraries:

```console
cd keres-desktop
nix develop
cargo run
```

See `keres-desktop/README.md` for the data layout, `KERES_HOME`, legacy
`~/.krypton` fallback, and development commands.

## Security status

Keres has not had an independent security audit. The desktop app is a showcase
and a reference consumer, not a security boundary. Read the
[security model](./security.md) and the [stability policy](./stability.md)
before using it with high-value data.
