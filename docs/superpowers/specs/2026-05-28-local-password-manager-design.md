# Local Password Manager Design

## Goal

Build a local-first password manager for personal daily use. The first version is a Rust command-line tool that stores one encrypted vault file locally, supports basic account password management, and keeps the design simple enough to audit and test.

The tool is named `mypass`.

## Non-Goals

- No cloud sync.
- No browser extension.
- No multi-device merge.
- No multi-user sharing or permissions.
- No unlocked session cache in the first version.
- No full-screen TUI in the first version.

## Product Shape

The first version is a command-style CLI. Each command that reads or writes vault data asks for the master password. Password values are entered through hidden prompts, not command-line arguments.

Commands:

```text
mypass init
mypass add <entry>
mypass get <entry> [--show]
mypass update <entry>
mypass delete <entry>
mypass list
mypass change-master
```

Global option:

```text
--vault <path>
```

`--vault` always means a vault file path, not a directory. If omitted, the default vault path comes from the operating system's user data directory, with a filename of `vault.mypass`.

## Command Behavior

### `mypass init`

Creates a new vault.

Prompt flow:

```text
Create master password:
Confirm master password:
Vault initialized at <path>
```

If the target vault file already exists, the command fails with a clear message. The first version does not include `--force`.

Examples:

```text
mypass init
mypass --vault ./work.mypass init
```

### `mypass add <entry>`

Adds a new account entry.

Prompt flow:

```text
Master password:
Username:
Password:
Confirm password:
Saved entry: <entry>
```

If the entry already exists, the command fails.

### `mypass get <entry> [--show]`

Gets an account password.

Default behavior copies the password to the clipboard:

```text
Master password:
Password copied to clipboard. It will be cleared in 30 seconds.
```

With `--show`, the command prints the entry:

```text
Master password:
Username: <username>
Password: <password>
```

If the entry does not exist, the command fails.

### `mypass update <entry>`

Updates an existing account entry.

Prompt flow:

```text
Master password:
Username [current username]:
New password:
Confirm new password:
Updated entry: <entry>
```

Pressing enter at the username prompt keeps the existing username.

### `mypass delete <entry>`

Deletes an account entry.

Prompt flow:

```text
Master password:
Delete entry "<entry>"? Type the entry name to confirm:
Deleted entry: <entry>
```

The user must type the exact entry name to confirm deletion.

### `mypass list`

Lists account entries without showing passwords.

Prompt flow:

```text
Master password:
github    clyde@example.com
gmail     clyde@gmail.com
```

### `mypass change-master`

Changes the master password for a vault.

Prompt flow:

```text
Current master password:
New master password:
Confirm new master password:
Master password changed.
```

The old master password must successfully unlock the vault before any write occurs. The new master password must not be identical to the old one.

## Security Model

The vault uses a two-layer key model:

- The user remembers a master password.
- The program generates a random data encryption key, or DEK.
- Argon2id derives a key encryption key, or KEK, from the master password and a per-vault salt.
- The KEK encrypts the DEK.
- The DEK encrypts the vault data.

The vault file stores metadata, salts, nonces, the encrypted DEK, and encrypted vault data. It never stores the master password, plaintext KEK, plaintext DEK, or plaintext entries.

Unlock flow:

```text
master password + salt
-> Argon2id
-> KEK
-> decrypt encrypted_dek
-> DEK
-> decrypt vault ciphertext
-> entries
```

Changing the master password decrypts the DEK with the old KEK, derives a new KEK from the new master password and a new salt, then re-encrypts the same DEK. The vault data does not need to be re-encrypted during master password changes.

This design primarily protects against offline attacks after someone obtains the vault file. It does not claim to protect against a compromised local machine that can record keystrokes, read process memory, or intercept clipboard contents.

## Cryptography

Use established Rust crates rather than custom cryptography.

Planned primitives:

- Key derivation: Argon2id.
- Authenticated encryption: ChaCha20-Poly1305.
- Randomness: operating system CSPRNG through Rust crypto crates.
- Sensitive memory cleanup: `secrecy` and `zeroize` where practical.

Initial Argon2id parameters:

```text
memory_kib = 65536
iterations = 3
parallelism = 1
```

The parameters are stored in the vault file so future versions can still unlock old vaults and can migrate settings later.

## Vault File Format

The outer vault file is JSON. Binary fields are base64 encoded. The inner business data is JSON encrypted as one authenticated ciphertext.

Outer structure:

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "base64..."
  },
  "key_wrap": {
    "algorithm": "chacha20poly1305",
    "nonce": "base64...",
    "encrypted_dek": "base64..."
  },
  "data": {
    "algorithm": "chacha20poly1305",
    "nonce": "base64...",
    "ciphertext": "base64..."
  }
}
```

Inner plaintext before encryption:

```json
{
  "entries": {
    "github": {
      "username": "clyde@example.com",
      "password": "secret",
      "created_at": "2026-05-28T00:00:00Z",
      "updated_at": "2026-05-28T00:00:00Z"
    }
  }
}
```

## Architecture

Modules:

```text
src/main.rs        CLI entry point
src/cli.rs         clap command definitions and prompt orchestration
src/vault.rs       vault loading, saving, locking, and entry operations
src/crypto.rs      Argon2id, ChaCha20-Poly1305, salts, nonces, DEK handling
src/model.rs       serializable vault and entry structs
src/clipboard.rs   clipboard copy and delayed clear
src/errors.rs      typed errors and user-friendly messages
```

Responsibilities:

- CLI layer handles arguments, prompts, and output.
- Vault layer owns file-level workflows and entry operations.
- Crypto layer owns key derivation, encryption, decryption, and randomness.
- Model layer owns serializable data structures.
- Clipboard layer isolates platform clipboard behavior.

## Error Handling

User-facing errors should be specific and non-leaky:

- Vault does not exist.
- Vault already exists.
- Master password is incorrect or vault authentication failed.
- Entry already exists.
- Entry not found.
- Password confirmation does not match.
- Delete confirmation does not match.
- Vault file is unreadable, malformed, or unsupported.
- Clipboard is unavailable.

Authentication failure and wrong master password can share the same user-facing message to avoid implying whether a file was tampered with or a password was merely wrong.

## Testing Strategy

Unit tests:

- Argon2id derivation succeeds with stored parameters.
- Encryption round trip succeeds.
- Decryption fails with the wrong key.
- Tampered ciphertext fails authentication.
- Vault serialization round trip preserves metadata.

Integration tests:

- `init` creates a vault.
- Wrong master password cannot unlock a vault.
- `add`, `get`, `update`, `delete`, and `list` work across process-like flows.
- Duplicate `add` fails.
- Missing entry fails.
- `change-master` makes the old master password invalid and the new one valid.

Clipboard behavior should be isolated so command behavior can be tested without depending on a real system clipboard.

## Implementation Notes

- Do not accept passwords through command-line flags.
- Avoid logging secrets.
- Avoid printing passwords unless `--show` is explicitly passed.
- Use atomic file writes where practical: write a temporary file, fsync if reasonable, then rename.
- Create parent directories for the default vault path if needed.
- Restrict file permissions on Unix-like systems where practical.
- Keep the first version small and auditable.
