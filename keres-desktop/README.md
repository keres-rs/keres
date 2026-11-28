# Keres Desktop

A local-first desktop client for [Keres](../README.md), built with Rust and
[iced](https://iced.rs). It is a reference integration for the library and a
reference for how to embed Keres in a real application.

The GUI lives in its own Cargo workspace and is excluded from the library
workspace, so `cargo test --workspace` in the repository root stays fast and
portable.

## What it demonstrates

- **Vault lifecycle.** Create, unlock, lock, inspect, verify, migrate a legacy
  manifest, rotate the master key, and crypto-erase an entry.
- **Creation options.** Size padding (`none`, `adaptive`, or fixed buckets) and
  Argon2id cost presets through `VaultOptions`.
- **Keyslots and recovery.** Add or revoke independent passphrases, create a
  one-time recovery kit, and recover a closed vault from the code.
- **Reader/writer APIs.** The password store keeps plaintext in process memory
  with `Vault::add_from_reader` / `Vault::extract_to_writer`; it never writes a
  secret to a temporary file.
- **Error mapping.** `keres::Error` is `#[non_exhaustive]`, so the UI handles
  known variants explicitly and falls back to a readable message for new ones.
- **Honest security UX.** A dedicated page lists the threat model, known
  limitations, and the fact that Keres has not had an independent audit.

The app is deliberately focused on storage. The earlier generic tools
(symmetric envelopes, hashing, key generation, and signing) were removed so
the vault, password store, and file containers lead the experience and the
dependency tree stays small.

## Build and run

```console
cd keres-desktop
cargo run
```

The app needs a graphical session. On Linux it uses X11 or Wayland and the
usual iced/winit system libraries. The included Nix flake provides a working
toolchain and libraries:

```console
cd keres-desktop
nix develop
cargo run
```

Offline check and tests:

```console
cd keres-desktop
cargo check --offline
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

## Interface

The navbar has zoom controls (`−`, `+`, `reset`) that scale all text from 80%
to 300%. The default is 115% for readability. The visual style uses sharp
corners throughout.

Keyboard shortcuts: `Ctrl/Cmd+1..4` switches pages (vault, passwords,
containers, security), and `Ctrl/Cmd` with `+`, `-`, `0` adjusts or resets the
zoom. `Enter` submits the focused password or rename field.

The zoom level is saved to `~/.keres/ui.toml` and restored on the next
launch.

## Where data lives

By default the app stores state under `~/.keres`:

```
~/.keres/
├── vaults/<name>/      # one Keres vault directory per name
└── passwords/          # the password-store vault
```

Set `KERES_HOME` to override the base directory. If `~/.keres` does not exist
but the pre-rename `~/.krypton` directory does, the app falls back to the old
location and shows a notice in the navbar. Legacy vaults written by
`krypton-core 0.4.x` use manifest v2; unlocking one reports that migration is
required, and the dashboard offers an in-place **migrate** action.

> Back up a vault directory before migrating or rotating it. Migration and
> rotation are crash-safe, but a backup is still the right habit.

## Layout

| Path | Responsibility |
| --- | --- |
| `src/app.rs` | Application state, messages, and update logic |
| `src/vaults.rs` | Vault session service: create, unlock, migrate, entries, keyslots, recovery, rotation |
| `src/passwords.rs` | Password-store vault using in-memory reader/writer APIs |
| `src/files.rs` | Whole-file containers |
| `src/ui/` | Navbar, pages, and shared widgets |
| `src/theme.rs` | Palette and widget styles |

## Security status

Keres has **not** had an independent security audit. This application is a
showcase and a reference consumer, not a security boundary. See
[the security model](../docs/src/security.md) for the threat model, known
limitations, and the prioritized audit scope, and
[the stability policy](../docs/src/stability.md) for the API contract.

## License

Apache-2.0. See [LICENSE](LICENSE).
