# MyPass

MyPass is a local-first password manager written in Rust. It stores account
credentials in an encrypted local vault file and opens directly into a small
terminal UI for daily use.

The project is intentionally simple: no cloud sync, no browser extension, no
remote account system, and no unlocked background session. A vault is just a
local encrypted file.

## Features

- Start directly in TUI mode with `./mypass`.
- Create a vault from the TUI when the selected vault file does not exist.
- Add account credentials.
- View or copy credentials by entry name.
- Update an existing entry.
- Delete an entry with explicit confirmation.
- List saved entries without showing passwords.
- Change the master password without re-encrypting every entry.

## Security Model

MyPass does not save the master password. It uses a layered key model:

1. You remember a master password.
2. MyPass generates a random data encryption key, or DEK.
3. MyPass derives a key encryption key, or KEK, from the master password with
   Argon2id and a per-vault random salt.
4. The KEK encrypts the DEK.
5. The DEK encrypts the vault data.

The vault file stores metadata, KDF parameters, salts, nonces, the encrypted
DEK, and encrypted vault data. It does not store the master password, plaintext
KEK, plaintext DEK, or plaintext entries.

Unlock flow:

```text
master password + salt
-> Argon2id
-> KEK
-> decrypt encrypted DEK
-> DEK
-> decrypt vault data
-> entries
```

Changing the master password does not re-encrypt every account entry. MyPass
uses the current master password to unlock the DEK, derives a new KEK from the
new master password, then re-encrypts the same DEK.

## Cryptography

Current primitives:

- Key derivation: Argon2id
- Authenticated encryption: ChaCha20-Poly1305
- Randomness: operating system CSPRNG
- Binary fields in the vault file: base64 encoded

Initial Argon2id parameters:

```text
memory_kib = 65536
iterations = 3
parallelism = 1
```

The encrypted vault is a JSON file with base64 fields. The account data itself
is serialized to JSON and encrypted as one authenticated ciphertext.

## Threat Model

MyPass mainly protects against offline attacks where someone obtains the vault
file. They still need the master password to derive the correct KEK and decrypt
the DEK.

It does not fully protect against a compromised local machine. Malware that can
record keystrokes, read process memory, inspect the clipboard, or control your
terminal can still compromise secrets.

## Build

Install Rust first. This project has been built with:

```text
rustc 1.87.0
cargo 1.87.0
```

Development build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

To put a runnable binary in the project root:

```bash
cp target/release/mypass ./mypass
```

## Test And Checks

Run the test suite:

```bash
cargo test
```

Check formatting:

```bash
cargo fmt --check
```

Run clippy:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Usage

Start MyPass:

```bash
./mypass
```

MyPass prompts for a vault file path:

```text
Vault path [default: ~/personal.mypass]:
```

Press enter to use the default path, or type a different vault file path. If the
file does not exist, MyPass creates a new vault after prompting for a master
password. If the file already exists, MyPass prompts for the master password and
unlocks the vault.

After unlocking, use commands inside the TUI:

```text
/list
/view <entry> [-u <username>]
/copy <entry> [-u <username>]
/add <entry>
/update <entry> [-u <username>]
/delete <entry> [-u <username>]
/change-master
/help
/exit
```

`/exit` leaves the session and drops the unlocked vault state and in-memory
master password.

### Add Entry

```text
mypass> /add github
Username:
Password:
Confirm password:
```

The entry name is the service name. The username is stored under that service,
so the same service can have multiple usernames.

### View Entry

```text
mypass> /view github
```

If a service has more than one username, specify the username:

```text
mypass> /view github -u alice@example.com
```

### Copy Password

```text
mypass> /copy github
```

MyPass copies the password to the clipboard, waits 30 seconds, and clears the
clipboard only if it still contains the copied password.

### Update Entry

```text
mypass> /update github
Username [current username]:
New password:
Confirm new password:
```

Press enter at the username prompt to keep the current username.

If a service has more than one username, specify which one to update:

```text
mypass> /update github -u alice@example.com
```

### Delete Entry

```text
mypass> /delete github
Delete entry "github"? Type the entry name to confirm:
```

Only an exact confirmation deletes the entry.

If a service has more than one username, specify which one to delete:

```text
mypass> /delete github -u alice@example.com
```

### List Entries

```text
mypass> /list
github  alice@example.com
github  bob@example.com
```

The list output shows entry names and usernames, not passwords.

### Change Master Password

```text
mypass> /change-master
New master password:
Confirm new master password:
```

This re-wraps the vault DEK with a KEK derived from the new master password.
Account entries are not re-encrypted one by one.

## Notes

- Do not pass passwords as command-line arguments.
- Keep backups of important vault files.
- Losing the master password means losing access to the vault.
