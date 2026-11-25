# Preface

This book is the reference documentation for Keres: a Rust library and
command-line tool for encrypting files and directory trees at rest.

It is written for two audiences:

- **Users** who want to encrypt files or keep an encrypted vault and need to
  understand the commands, defaults, and failure modes.
- **Developers** who are embedding the `keres` crate, reviewing the format,
  or contributing to the project.

## How to read it

If you are new to Keres, start with the [Introduction](./intro.md) and
[Quick start](./usage.md). The [Library guide](./library-usage.md) and
[CLI guide](./cli-usage.md) cover day-to-day use. The
[Architecture](./architecture.md) and [Security model](./security.md)
chapters explain the design and its limits; they are required reading before
making format or cryptographic changes.

Commands in this book are shown for a POSIX shell. On Windows, replace `$HOME`
with `%USERPROFILE%` and adjust path separators. Keres stores vaults in a
platform-neutral layout and uses native file locking on both Unix and
Windows.

## Version

This documentation targets Keres **0.7.x**. The container format is
versioned; the Rust API is not yet stable. Compatibility rules are described
in [Compatibility](./architecture.md#compatibility-and-versioning).

## Getting help

- Usage questions and bug reports: [GitHub
  issues](https://github.com/Keres-rs/keres/issues).
- Security reports: follow [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md)
  and do not open a public issue.
- Changes between releases: [CHANGELOG.md](https://github.com/Keres-rs/keres/blob/main/CHANGELOG.md).
