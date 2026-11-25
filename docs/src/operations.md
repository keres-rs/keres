# Recovery, rotation, and migration

This chapter covers operations that change credentials, keys, or the on-disk
format. Read the relevant section before running the command: several of these
operations are deliberately destructive.

## Password changes versus key rotation

| Operation | What changes | Stored ciphertext | Other keyslots | Recovery kit | Cost |
|---|---|---|---|---|---|
| Change password | The wrapped master key in one keyslot | Untouched | Keep working | Keep working | One Argon2id derivation |
| Deep rotation | A new master key and config | Re-encrypted | Revoked | Removed | Reads and rewrites every entry |
| Erase | New master key; one entry removed | Survivors re-encrypted | Revoked | Removed | Full rotation |
| Migration | Manifest v2 → v3 with fresh entry IDs | Re-encrypted | Kept | Kept | Reads and rewrites every entry |

Changing a password is cheap and should be the default. Rotate only when the
data key itself may be compromised, or when policy requires periodic
re-encryption.

## Keyslots

A keyslot is an independent wrapping of the vault's master key. Every slot
unlocks the same vault; none is more privileged than another.

```console
$ keres keyslot list personal
SLOT                 NOTE
------------------------------------------------------------
0123456789abcdef

$ keres keyslot add personal
Current vault password:
New passphrase:
Confirm new password:
Added keyslot 89abcdef01234567.
Store the new passphrase separately; any keyslot unlocks the same vault.

$ keres keyslot remove personal 0123456789abcdef
Password for a keyslot that will remain:
Removed keyslot 0123456789abcdef.
```

Rules enforced by the CLI and library:

- A slot is identified by a random 16-hex-character id.
- Adding a slot requires an existing passphrase.
- Removing a slot requires a passphrase from a slot that will **remain**, so a
  mistyped target cannot delete your only credential.
- The last slot cannot be removed.
- New passphrases must differ from the authorizing passphrase.

Slot ids and the slot count are plaintext metadata in `vault.config`. The
passphrases and master key are not.

### Revocation is not rotation

Removing a keyslot drops that wrapping. It does **not** change the master
key. Anyone who already used the revoked passphrase to unwrap the master key
can still decrypt existing ciphertext. If a passphrase or device was
compromised, run a deep rotation.

## Recovery kits

A recovery kit is a second wrapping of the master key, protected by a random
160-bit code printed once. It exists so a lost or damaged `vault.config` does
not brick the vault.

### Create a kit

```console
$ keres recovery create personal
Enter vault password:
Recovery code (store it offline; it will not be shown again):
  XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
A wrapped copy of the master key was written to /home/you/.keres/vaults/personal/vault.recovery.
Keep the code separate from the vault: either alone is not enough.
```

Store the code offline, separately from the vault directory. Anyone holding
both the vault directory and the code can unlock the vault.

Creating a new kit replaces the old file and invalidates the old code:

```console
$ keres recovery create personal --force
```

### Recover after losing the config

If `vault.config` is missing or corrupt but `vault.recovery` survives:

```console
$ keres recovery use personal
Recovery code:
New password:
Confirm new password:
Vault recovered. The recovery kit was consumed; create a new one if needed.
```

Recovery:

1. unwraps the master key with the code;
2. verifies that key against the encrypted index;
3. writes a fresh single-slot `vault.config` under the new password;
4. deletes the kit so the code cannot be replayed.

Any additional keyslots are lost and must be re-added. If both the password
and the recovery code are lost, the vault is unrecoverable.

The code is a second offline guessing target. It is 160 bits plus Argon2id,
which makes exhaustive search infeasible, but it must still be handled like a
password.

## Deep rotation

Deep rotation generates a new master key and re-encrypts every entry. Use it
when:

- a password or master key may have leaked;
- you are retiring a device that held a keyslot;
- policy requires re-encrypting stored data.

```console
$ keres rotate personal
Rotate vault 'personal'? Every entry is re-encrypted under a fresh master key; 2 other keyslots will be revoked and the recovery kit will be deleted; the vault is left locked under the new password. [y/N] y
Current password:
New password:
Confirm new password:
Rotated: re-encrypted 42 entries (1.2 GB).
Revoked 2 other keyslots.
Removed the old recovery kit; create a new one with `keres recovery create`.
The vault is locked; unlock it with the new password.
```

Consequences:

- All entries are re-encrypted under a fresh master key.
- The vault ends up with exactly one keyslot, under the new password.
- Other keyslots stop working.
- Any recovery kit is removed; create a new one afterwards.
- The vault is left locked.
- The operation can take a long time and temporarily needs extra disk space
  for the new blobs.

If the process dies mid-rotation, the next operation that opens the vault
either completes or rolls back the rotation using the `vault.rotate` journal.
Old-key blobs listed in the journal are deleted; leftovers can be reclaimed
with `keres verify --prune`.

Rotation is not retroactive: ciphertext copied by an attacker before the
rotation remains decryptable with the old key material.

## Erasure

`erase` combines removal with rotation. It omits one entry and re-encrypts
every survivor under a fresh master key in one journaled commit.

```console
$ keres erase personal old-secret.txt
Erase 'old-secret.txt' from vault 'personal'? This re-encrypts every other entry under a fresh master key. [y/N] y
Enter vault password:
New password after erase:
Confirm new password:
Erased 'old-secret.txt': re-encrypted 41 entries (1.1 GB).
```

Use it when a deleted entry's old ciphertext must stop being usable with the
current key. The old entry is left out of the new index, and survivors are
re-encrypted. If the rotation fails, the old vault (including the entry) is
left intact.

Erasure is forward-looking. It cannot revoke a copy of the deleted blob that
was captured earlier together with the old key or config.

## Migrating a 0.5.x vault

Keres 0.5.x wrote manifest version 2. The current reader rejects it with
`MigrationRequired`; it does not silently upgrade.

```console
$ keres migrate legacy-vault
Migrate vault 'legacy-vault' to the current format? Every entry is re-encrypted in place. [y/N] y
Enter vault password:
Migrated 128 entries (640 MB re-encrypted).
```

Before migrating:

1. Stop any process using the vault.
2. Back up the entire vault directory, including `d/`.
3. Keep the old release available until the migration is verified.

Migration is one-way. It keeps the same password, re-encrypts every entry
under a fresh entry ID, commits the new manifest atomically, and removes the
legacy blobs. A failure before the commit leaves the legacy manifest intact.
Afterwards, run `keres verify` and confirm access to a few entries before
deleting the backup.

## Changing padding policy

```console
$ keres padding personal --set adaptive
Padding policy set to Adaptive
```

The policy is stored in the authenticated index and applies to future adds and
replaces. Existing blobs keep their original size until they are rewritten.
Changing the policy does not rewrite the vault. To re-bucket existing entries,
replace each entry one by one (or rewrite the vault).

## Backup and restore

There is no special backup command. A vault is a directory; copy it while no
process is writing. Include every file, including `vault.config`, `d/`, and
`vault.recovery` if present.

Restoring an older copy of the directory rolls the vault back to that point.
Keres detects snapshot/log swaps and substituted blobs, but it does not have a
hardware-backed anti-rollback counter. Treat backups as sensitive data: they
contain ciphertext and the config material needed to attempt offline password
guesses.

After any interrupted add, remove, rotation, or compaction, run:

```console
$ keres verify personal
$ keres verify personal --prune
```

`--prune` deletes only unreferenced blobs and stale temp files, and only after
a successful verification.
