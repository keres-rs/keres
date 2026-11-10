# Using Keres

Keres has two encryption modes over one shared engine:

| Mode | Entry points | Use case |
|---|---|---|
| **Single-file** | `encrypt_file`, `decrypt_file`, `keres encrypt/decrypt` | One self-contained `.keres` container |
| **Vault** | `Vault`, `keres init/add/list/...` | Many files and directories under one password |

Both modes share the same container format, chunk engine, and cryptographic
primitives. Choose the library if you are embedding Keres in a Rust
application; choose the CLI for ad-hoc files and terminal workflows.

- [Keres library usage](core-usage.md)
- [Keres CLI usage](cli-usage.md)
