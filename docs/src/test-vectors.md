# Format test vectors

The container format has a committed, deterministic fixture so that an
unintentional change to the wire layout fails loudly.

## Fixture

`tests/vectors/standalone.krs` is a standalone `.krs` container built with
fixed inputs:

| Input | Value |
|---|---|
| Password | `correct horse battery staple` |
| Original name | `hello.txt` |
| Plaintext | 100,000 bytes, `bytes[i] = i % 251` for `i` in `0..100_000` |
| Argon2id salt | 32 × `0x11` |
| HKDF object salt | 32 × `0x22` |
| Argon2id parameters | `m = 8192 KiB`, `t = 1`, `p = 1` |

The KDF parameters are the minimum accepted by `KdfParams::validate`, chosen
so tests and external tools can derive the key quickly. They are explicit in
the container header, not implicit.

SHA-256 of the fixture:

```text
978e1085b8ff2d199d70b52d0b4cff391ebadaa0efcc11298e3eaeff584f19d2
```

## What the tests pin

`tests/vectors.rs` asserts that:

1. The committed bytes equal the output of the generator
   (`keres::test_vectors::standalone`).
2. The SHA-256 digest matches the value above.
3. The public `decrypt_file` API recovers the exact plaintext and name.
4. A wrong password returns `Error::Authentication`.
5. A foreign magic returns `Error::IncompatibleFormat`.
6. A flipped trailer byte returns `Error::Authentication`.
7. A truncated container is rejected.

These checks catch accidental changes to header layout, KDF encoding, chunk
framing, trailer JSON, or AAD construction. They do not replace the tamper
sweeps in the unit and integration tests.

## Regenerating

A format change is deliberate: update the generator, regenerate the fixture,
record the new digest here, and explain the change in `CHANGELOG.md`. The
fixture can be rebuilt with:

```rust,ignore
let plaintext: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
let bytes = keres::test_vectors::standalone(
    "correct horse battery staple",
    &plaintext,
    "hello.txt",
);
std::fs::write("tests/vectors/standalone.krs", bytes)?;
# Ok::<(), std::io::Error>(())
```

`keres::test_vectors` is a hidden developer module, not part of the stable
API. It exists so the fixture can be reproduced without reimplementing the
format.

## Using the fixture outside Rust

The fixture is a normal container. A compatible implementation can open it
with the password above and should recover:

- the filename `hello.txt`;
- exactly 100,000 plaintext bytes;
- the `bytes[i] = i % 251` pattern.

It is also useful for checking a parser against malformed input: truncate the
fixture at every record boundary, flip bytes in each header field, and
confirm that no mutation is accepted.
