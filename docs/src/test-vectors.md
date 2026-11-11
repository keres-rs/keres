# Test vectors

The container format has a committed, deterministic vector so that any
unintentional change to the wire layout fails loudly.

## Fixture

`crates/keres/tests/vectors/standalone.krs` is a standalone `.krs` container
built with fixed inputs:

| Input | Value |
|---|---|
| Password | `correct horse battery staple` |
| Original name | `hello.txt` |
| Plaintext | 100,000 bytes, `bytes[i] = i % 251` for `i` in `0..100_000` |
| Argon2id salt | 32 × `0x11` |
| HKDF object salt | 32 × `0x22` |
| Argon2id parameters | `m = 8192 KiB`, `t = 1`, `p = 1` |

The Argon2id parameters are the minimum accepted by
[`KdfParams::validate`], chosen so that tests and external tools can derive
the key quickly. They are explicit in the container header, not implicit.

SHA-256 of the fixture:

```text
978e1085b8ff2d199d70b52d0b4cff391ebadaa0efcc11298e3eaeff584f19d2
```

## What the tests pin

`crates/keres/tests/vectors.rs` asserts that:

1. The committed bytes equal the output of the generator
   (`keres::test_vectors::standalone`).
2. The SHA-256 digest matches the value above.
3. The public `decrypt_file` API recovers the exact plaintext and name.
4. A wrong password returns `Error::Authentication`.
5. A foreign magic returns `Error::IncompatibleFormat`.
6. A flipped trailer byte returns `Error::Authentication`.
7. A truncated container is rejected.

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
std::fs::write("crates/keres/tests/vectors/standalone.krs", bytes)?;
# Ok::<(), std::io::Error>(())
```

`keres::test_vectors` is a hidden developer module, not part of the stable
public API.

[`KdfParams::validate`]: https://docs.rs/keres/latest/keres/kdf/struct.KdfParams.html#method.validate
