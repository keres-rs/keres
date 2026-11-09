# Using Krypton

Krypton has two encryption modes over one shared engine:

| Mode | Entry points | Use case |
|---|---|---|
| **Single-file** | `encrypt_file`, `decrypt_file`, `krypton encrypt/decrypt` | One self-contained `.krf` container |
| **Vault** | `Vault`, `krypton init/add/list/...` | Many files and directories under one password |

Both modes share the same container format, chunk engine, and cryptographic
primitives. Choose the library if you are embedding Krypton in a Rust
application; choose the CLI for ad-hoc files and terminal workflows.

- [Krypton Core usage](core-usage.md)
- [Krypton CLI usage](cli-usage.md)
