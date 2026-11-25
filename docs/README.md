# Keres Documentation

Source for the Keres book. It covers installation, the CLI and library
guides, the container format, the security model, and project policies.

The book is built with [mdBook](https://rust-lang.github.io/mdBook/):

```console
$ mdbook serve docs     # local preview at http://localhost:3000
$ mdbook build docs     # static output in docs/book/
```

Start at the [Preface](src/preface.md) or the
[Introduction](src/intro.md). The page order is defined in
[`src/SUMMARY.md`](src/SUMMARY.md).

## Writing conventions

- Use relative links between pages (`./architecture.md`).
- Keep CLI examples runnable as written; use placeholders such as
  `<vault>` only where a real name would distract.
- Put normative format details in the architecture chapter, not in guides.
- Treat security claims as claims: state the attacker and the guarantee.

## License

The documentation is licensed under CC0-1.0; see [LICENSE](LICENSE). The code
is Apache-2.0; see the repository root.
