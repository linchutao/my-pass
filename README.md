# MyPass

MyPass is a local-first password manager written in Rust. It stores account
credentials in an encrypted local vault file and exposes a small command-line
interface for daily use.

The project is intentionally simple: no cloud sync, no browser extension, no
remote account system, and no unlocked background session. A vault is just a
local encrypted file.

## Features

- Initialize a local encrypted vault.
- Add account credentials.
- Get credentials by entry name.
- Update an existing entry.
- Delete an entry with explicit confirmation.
- List saved entries without showing passwords.
- Change the master password without re-encrypting every entry.
- Use a default vault path or specify a vault file with `--vault <path>`.

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
uses the old master password to unlock the DEK, derives a new KEK from the new
master password, then re-encrypts the same DEK.

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

Verify:

```bash
./mypass --version
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

Use the default vault location:

```bash
mypass init
```

The default vault file is `~/personal.mypass`.

Or specify a vault file:

```bash
mypass --vault ./personal.mypass init
```

`--vault` means a vault file path, not a directory. Use the same `--vault` value
for later commands if you do not want the default vault.

### Interactive Mode

Start a command-style interactive session:

```bash
mypass tui
```

Or open a specific vault:

```bash
mypass --vault ./personal.mypass tui
```

When `--vault` is omitted, MyPass prompts for a vault file path. Press enter to
use the default vault path. After that, enter the master password once to unlock
the vault for the session.

Available interactive commands:

```text
/list
/view <entry> [--username <username>]
/copy <entry> [--username <username>]
/add <entry>
/update <entry> [--username <username>]
/delete <entry> [--username <username>]
/change-master
/help
/exit
```

`/exit` leaves the session and drops the unlocked vault state and in-memory
master password.

### Initialize

```bash
mypass --vault ./personal.mypass init
```

Prompts:

```text
Create master password:
Confirm master password:
```

### Add Entry

```bash
mypass --vault ./personal.mypass add github
```

Prompts:

```text
Master password:
Username:
Password:
Confirm password:
```

The entry name is the service name. The username is stored under that service,
so the same service can have multiple usernames:

```bash
mypass --vault ./personal.mypass add github
# Username: alice@example.com

mypass --vault ./personal.mypass add github
# Username: bob@example.com
```

### Get Entry

Default behavior copies the password to the clipboard:

```bash
mypass --vault ./personal.mypass get github
```

MyPass prints a copied message immediately, waits 30 seconds, and clears the
clipboard only if it still contains the copied password.

To print the password explicitly:

```bash
mypass --vault ./personal.mypass get github --show
```

If a service has more than one username, specify the username:

```bash
mypass --vault ./personal.mypass get github --username alice@example.com --show
```

### Update Entry

```bash
mypass --vault ./personal.mypass update github
```

Prompts:

```text
Master password:
Username [current username]:
New password:
Confirm new password:
```

Press enter at the username prompt to keep the current username.

If a service has more than one username, specify which one to update:

```bash
mypass --vault ./personal.mypass update github --username alice@example.com
```

### Delete Entry

```bash
mypass --vault ./personal.mypass delete github
```

Prompts:

```text
Master password:
Delete entry "github"? Type the entry name to confirm:
```

The entry is deleted only when the confirmation exactly matches the entry name.

If a service has more than one username, specify which one to delete:

```bash
mypass --vault ./personal.mypass delete github --username alice@example.com
```

### List Entries

```bash
mypass --vault ./personal.mypass list
```

This shows service names and usernames only. It does not show passwords.

### Change Master Password

```bash
mypass --vault ./personal.mypass change-master
```

Prompts:

```text
Current master password:
New master password:
Confirm new master password:
```

The old master password stops working after this succeeds.

## Examples

```bash
./mypass --vault ./demo.mypass init
./mypass --vault ./demo.mypass add github
./mypass --vault ./demo.mypass get github --show
./mypass --vault ./demo.mypass update github
./mypass --vault ./demo.mypass list
./mypass --vault ./demo.mypass change-master
./mypass --vault ./demo.mypass delete github
```

## Notes

- Do not pass passwords as command-line arguments.
- Keep vault backups if the data matters.
- Use a long, high-entropy master password.
- The root-level `mypass` binary is a local build artifact. Rebuild it after
  source changes with `cargo build --release`.
