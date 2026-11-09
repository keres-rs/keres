# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers through
GitHub's [private vulnerability reporting](https://github.com/KryptonOSS/krypton-core/security/advisories/new)
or by opening a draft security advisory. Do not open a public issue for a
vulnerability. Include:

- affected version(s) and platform,
- a minimal reproducer or proof of concept,
- the security property you believe is broken.

We aim to acknowledge reports within 72 hours and will coordinate disclosure.
Please give us a reasonable window to ship a fix before publishing details.

## What Krypton protects against

Krypton protects data at rest against an attacker with read access to the
storage medium (stolen disk, leaked backup, synced cloud folder) and against
an attacker with write access who modifies, truncates, reorders, or
transplants ciphertext. Authenticated encryption covers every chunk and the
trailer; vault object locations are keyed by the master key.

## What it does not protect against

- Malware, keyloggers, or a compromised OS while a vault is unlocked.
- An attacker who knows the password or has the unlocked process memory.
- Coercion to reveal the password.
- Traffic analysis of *sizes*: entry counts, directory shape, and approximate
  file sizes leak unless padding is added. This is a documented limitation,
  not a bug.
- Rollback to an older valid snapshot of the vault directory. A generation
  counter is on the roadmap.
- Secure erasure of deleted ciphertext on SSDs or journaling filesystems.

The full threat model and design rationale are in
[`docs/src/security.md`](docs/src/security.md).

## Scope

The security surface is the code in `crates/krypton-core` and
`crates/krypton-cli`. The GUI and Python bindings are separate projects and
have their own reporting processes.

## Supported versions

Krypton is pre-1.0. Security fixes are applied to the latest 0.4.x release.
Pre-0.4 container formats are retired and unsupported.
