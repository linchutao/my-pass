# Local Password Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `mypass`, a Rust CLI that stores account passwords in a local encrypted vault and supports init, add, get, update, delete, list, and change-master.

**Architecture:** The binary entry point delegates to a CLI module. The CLI module prompts for input and calls a vault service. The vault service owns file workflows and uses a crypto module for Argon2id key derivation and ChaCha20-Poly1305 authenticated encryption.

**Tech Stack:** Rust 1.87, clap, serde, serde_json, thiserror, anyhow, argon2, chacha20poly1305, rand_core, secrecy, zeroize, rpassword, directories, arboard, chrono, tempfile, assert_cmd, predicates.

---

## File Structure

- `Cargo.toml`: package metadata, runtime dependencies, dev dependencies.
- `src/main.rs`: application entry point and process exit behavior.
- `src/cli.rs`: command definitions, prompt orchestration, and user-facing command execution.
- `src/model.rs`: serializable vault file structures and decrypted entry structures.
- `src/crypto.rs`: random byte generation, Argon2id derivation, and ChaCha20-Poly1305 encryption/decryption.
- `src/vault.rs`: vault path resolution, atomic file writes, init/unlock/save workflows, and entry operations.
- `src/clipboard.rs`: clipboard abstraction and production clipboard implementation.
- `src/errors.rs`: typed application errors and display messages.
- `tests/cli.rs`: integration tests for command behavior using test vault files.

## Task 1: Scaffold Rust Project

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`

- [ ] **Step 1: Create package metadata and dependencies**

Add this `Cargo.toml`:

```toml
[package]
name = "mypass"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1"
argon2 = "0.5"
arboard = "3"
base64 = "0.22"
chacha20poly1305 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
directories = "5"
rand_core = { version = "0.6", features = ["getrandom"] }
rpassword = "7"
secrecy = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
zeroize = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

- [ ] **Step 2: Create the library module shell**

Add this `src/lib.rs`:

```rust
pub mod cli;
pub mod clipboard;
pub mod crypto;
pub mod errors;
pub mod model;
pub mod vault;
```

- [ ] **Step 3: Create the binary entry point**

Add this `src/main.rs`:

```rust
use anyhow::Result;

fn main() -> Result<()> {
    mypass::cli::run()
}
```

- [ ] **Step 4: Run format and build to expose missing modules**

Run:

```bash
cargo fmt
cargo check
```

Expected: `cargo check` fails because the modules declared in `src/lib.rs` do not exist yet.

- [ ] **Step 5: Commit scaffold**

Run:

```bash
git add Cargo.toml src/lib.rs src/main.rs
git commit -m "chore: scaffold rust project"
```

## Task 2: Add Models and Error Types

**Files:**
- Create: `src/model.rs`
- Create: `src/errors.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write model tests**

Add this test module at the bottom of `src/model.rs` after creating the file in Step 2:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_file_round_trips_through_json() {
        let vault = VaultFile {
            version: 1,
            kdf: KdfConfig {
                algorithm: "argon2id".to_string(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                salt: "salt".to_string(),
            },
            key_wrap: CipherBlob {
                algorithm: "chacha20poly1305".to_string(),
                nonce: "nonce".to_string(),
                ciphertext: "encrypted-dek".to_string(),
            },
            data: CipherBlob {
                algorithm: "chacha20poly1305".to_string(),
                nonce: "data-nonce".to_string(),
                ciphertext: "vault-ciphertext".to_string(),
            },
        };

        let json = serde_json::to_string(&vault).expect("serialize vault");
        let decoded: VaultFile = serde_json::from_str(&json).expect("deserialize vault");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.kdf.algorithm, "argon2id");
        assert_eq!(decoded.key_wrap.ciphertext, "encrypted-dek");
        assert_eq!(decoded.data.ciphertext, "vault-ciphertext");
    }
}
```

- [ ] **Step 2: Implement model structs**

Add this `src/model.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VAULT_VERSION: u32 = 1;
pub const KDF_ALGORITHM: &str = "argon2id";
pub const CIPHER_ALGORITHM: &str = "chacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: KdfConfig,
    pub key_wrap: CipherBlob,
    pub data: CipherBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfConfig {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherBlob {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
}

impl VaultData {
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

- [ ] **Step 3: Implement typed errors**

Add this `src/errors.rs`:

```rust
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Vault does not exist: {0}")]
    VaultMissing(PathBuf),
    #[error("Vault already exists: {0}")]
    VaultExists(PathBuf),
    #[error("Master password is incorrect or the vault could not be authenticated")]
    AuthenticationFailed,
    #[error("Entry already exists: {0}")]
    EntryExists(String),
    #[error("Entry not found: {0}")]
    EntryNotFound(String),
    #[error("Password confirmation does not match")]
    PasswordMismatch,
    #[error("Delete confirmation does not match")]
    DeleteConfirmationMismatch,
    #[error("New master password must be different from the current master password")]
    MasterPasswordUnchanged,
    #[error("Unsupported vault format version: {0}")]
    UnsupportedVersion(u32),
    #[error("Unsupported algorithm in vault file")]
    UnsupportedAlgorithm,
    #[error("Clipboard is unavailable: {0}")]
    ClipboardUnavailable(String),
    #[error("Default vault directory is unavailable on this system")]
    DefaultVaultDirUnavailable,
    #[error("Vault file is malformed: {0}")]
    MalformedVault(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type AppResult<T> = Result<T, AppError>;
```

- [ ] **Step 4: Run model tests**

Run:

```bash
cargo test model
```

Expected: PASS.

- [ ] **Step 5: Commit models and errors**

Run:

```bash
git add src/model.rs src/errors.rs src/lib.rs
git commit -m "feat: add vault models and errors"
```

## Task 3: Implement Crypto Primitives

**Files:**
- Create: `src/crypto.rs`
- Test: unit tests in `src/crypto.rs`

- [ ] **Step 1: Write crypto tests**

Add this test module at the bottom of `src/crypto.rs` after creating the file in Step 2:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_round_trips() {
        let key = random_key();
        let encrypted = encrypt(&key, b"hello vault").expect("encrypt");
        let plaintext = decrypt(&key, &encrypted).expect("decrypt");
        assert_eq!(plaintext, b"hello vault");
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = random_key();
        let wrong_key = random_key();
        let encrypted = encrypt(&key, b"hello vault").expect("encrypt");
        let err = decrypt(&wrong_key, &encrypted).expect_err("wrong key should fail");
        assert!(matches!(err, AppError::AuthenticationFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let mut encrypted = encrypt(&key, b"hello vault").expect("encrypt");
        encrypted.ciphertext.push('A');
        let err = decrypt(&key, &encrypted).expect_err("tampered data should fail");
        assert!(matches!(err, AppError::AuthenticationFailed | AppError::MalformedVault(_)));
    }

    #[test]
    fn password_derivation_is_repeatable_with_same_salt() {
        let salt = random_salt();
        let config = default_kdf_config(salt.clone());
        let first = derive_kek("correct horse", &config).expect("derive first");
        let second = derive_kek("correct horse", &config).expect("derive second");
        assert_eq!(first.as_slice(), second.as_slice());
    }
}
```

- [ ] **Step 2: Implement crypto module**

Add this `src/crypto.rs`:

```rust
use crate::errors::{AppError, AppResult};
use crate::model::{CIPHER_ALGORITHM, CipherBlob, KDF_ALGORITHM, KdfConfig};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn random_salt() -> Vec<u8> {
    let mut salt = vec![0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn default_kdf_config(salt: Vec<u8>) -> KdfConfig {
    KdfConfig {
        algorithm: KDF_ALGORITHM.to_string(),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
        salt: STANDARD.encode(salt),
    }
}

pub fn derive_kek(master_password: &str, config: &KdfConfig) -> AppResult<[u8; KEY_LEN]> {
    if config.algorithm != KDF_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }

    let salt = STANDARD
        .decode(&config.salt)
        .map_err(|err| AppError::MalformedVault(err.to_string()))?;
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| AppError::MalformedVault(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut output)
        .map_err(|err| AppError::MalformedVault(err.to_string()))?;
    Ok(output)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> AppResult<CipherBlob> {
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| AppError::AuthenticationFailed)?;

    Ok(CipherBlob {
        algorithm: CIPHER_ALGORITHM.to_string(),
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt(key: &[u8; KEY_LEN], blob: &CipherBlob) -> AppResult<Vec<u8>> {
    if blob.algorithm != CIPHER_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }

    let nonce_bytes = STANDARD
        .decode(&blob.nonce)
        .map_err(|err| AppError::MalformedVault(err.to_string()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(AppError::MalformedVault("invalid nonce length".to_string()));
    }

    let ciphertext = STANDARD
        .decode(&blob.ciphertext)
        .map_err(|err| AppError::MalformedVault(err.to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| AppError::AuthenticationFailed)
}

pub fn wrap_dek(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> AppResult<CipherBlob> {
    encrypt(kek, dek)
}

pub fn unwrap_dek(kek: &[u8; KEY_LEN], encrypted_dek: &CipherBlob) -> AppResult<[u8; KEY_LEN]> {
    let mut plaintext = decrypt(kek, encrypted_dek)?;
    if plaintext.len() != KEY_LEN {
        plaintext.zeroize();
        return Err(AppError::MalformedVault("invalid DEK length".to_string()));
    }

    let mut dek = [0_u8; KEY_LEN];
    dek.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(dek)
}
```

- [ ] **Step 3: Run crypto tests**

Run:

```bash
cargo test crypto
```

Expected: PASS.

- [ ] **Step 4: Commit crypto primitives**

Run:

```bash
git add src/crypto.rs Cargo.toml
git commit -m "feat: add vault cryptography"
```

## Task 4: Implement Vault Workflows

**Files:**
- Create: `src/vault.rs`
- Test: unit tests in `src/vault.rs`

- [ ] **Step 1: Write vault tests**

Add this test module at the bottom of `src/vault.rs` after creating the file in Step 2:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_and_unlock_empty_vault() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.mypass");
        init_vault(&path, "master").expect("init");

        let unlocked = unlock_vault(&path, "master").expect("unlock");
        assert!(unlocked.data.entries.is_empty());
    }

    #[test]
    fn wrong_master_password_fails() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.mypass");
        init_vault(&path, "master").expect("init");

        let err = unlock_vault(&path, "wrong").expect_err("wrong password");
        assert!(matches!(err, AppError::AuthenticationFailed));
    }

    #[test]
    fn entry_crud_flow_persists() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.mypass");
        init_vault(&path, "master").expect("init");

        add_entry(&path, "master", "github", "clyde@example.com", "secret").expect("add");
        let entry = get_entry(&path, "master", "github").expect("get");
        assert_eq!(entry.username, "clyde@example.com");
        assert_eq!(entry.password, "secret");

        update_entry(&path, "master", "github", Some("new@example.com"), "new-secret")
            .expect("update");
        let updated = get_entry(&path, "master", "github").expect("get updated");
        assert_eq!(updated.username, "new@example.com");
        assert_eq!(updated.password, "new-secret");

        let entries = list_entries(&path, "master").expect("list");
        assert_eq!(entries, vec![("github".to_string(), "new@example.com".to_string())]);

        delete_entry(&path, "master", "github").expect("delete");
        let err = get_entry(&path, "master", "github").expect_err("deleted");
        assert!(matches!(err, AppError::EntryNotFound(_)));
    }

    #[test]
    fn duplicate_add_fails() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.mypass");
        init_vault(&path, "master").expect("init");
        add_entry(&path, "master", "github", "clyde@example.com", "secret").expect("add");

        let err = add_entry(&path, "master", "github", "other@example.com", "secret")
            .expect_err("duplicate add");
        assert!(matches!(err, AppError::EntryExists(_)));
    }

    #[test]
    fn change_master_invalidates_old_password() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.mypass");
        init_vault(&path, "old-master").expect("init");
        add_entry(&path, "old-master", "github", "clyde@example.com", "secret").expect("add");

        change_master_password(&path, "old-master", "new-master").expect("change master");

        let old_err = unlock_vault(&path, "old-master").expect_err("old password");
        assert!(matches!(old_err, AppError::AuthenticationFailed));

        let entry = get_entry(&path, "new-master", "github").expect("new password");
        assert_eq!(entry.password, "secret");
    }
}
```

- [ ] **Step 2: Implement vault module**

Add this `src/vault.rs`:

```rust
use crate::crypto::{
    default_kdf_config, derive_kek, encrypt, random_key, random_salt, unwrap_dek, wrap_dek,
};
use crate::errors::{AppError, AppResult};
use crate::model::{CIPHER_ALGORITHM, Entry, KDF_ALGORITHM, VAULT_VERSION, VaultData, VaultFile};
use chrono::Utc;
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct UnlockedVault {
    pub file: VaultFile,
    pub data: VaultData,
    dek: [u8; 32],
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

pub fn default_vault_path() -> AppResult<PathBuf> {
    let dirs = ProjectDirs::from("", "", "mypass").ok_or(AppError::DefaultVaultDirUnavailable)?;
    Ok(dirs.data_dir().join("vault.mypass"))
}

pub fn init_vault(path: &Path, master_password: &str) -> AppResult<()> {
    if path.exists() {
        return Err(AppError::VaultExists(path.to_path_buf()));
    }

    let salt = random_salt();
    let kdf = default_kdf_config(salt);
    let mut kek = derive_kek(master_password, &kdf)?;
    let mut dek = random_key();
    let key_wrap = wrap_dek(&kek, &dek)?;
    let plaintext = serde_json::to_vec(&VaultData::empty())?;
    let data = encrypt(&dek, &plaintext)?;

    let file = VaultFile {
        version: VAULT_VERSION,
        kdf,
        key_wrap,
        data,
    };

    write_vault_file(path, &file)?;
    kek.zeroize();
    dek.zeroize();
    Ok(())
}

pub fn unlock_vault(path: &Path, master_password: &str) -> AppResult<UnlockedVault> {
    let file = read_vault_file(path)?;
    validate_vault_file(&file)?;

    let mut kek = derive_kek(master_password, &file.kdf)?;
    let dek = match unwrap_dek(&kek, &file.key_wrap) {
        Ok(dek) => dek,
        Err(AppError::AuthenticationFailed) => {
            kek.zeroize();
            return Err(AppError::AuthenticationFailed);
        }
        Err(err) => {
            kek.zeroize();
            return Err(err);
        }
    };
    kek.zeroize();

    let plaintext = crate::crypto::decrypt(&dek, &file.data)?;
    let data = serde_json::from_slice(&plaintext)?;

    Ok(UnlockedVault { file, data, dek })
}

pub fn add_entry(
    path: &Path,
    master_password: &str,
    name: &str,
    username: &str,
    password: &str,
) -> AppResult<()> {
    let mut unlocked = unlock_vault(path, master_password)?;
    if unlocked.data.entries.contains_key(name) {
        return Err(AppError::EntryExists(name.to_string()));
    }

    let now = Utc::now();
    unlocked.data.entries.insert(
        name.to_string(),
        Entry {
            username: username.to_string(),
            password: password.to_string(),
            created_at: now,
            updated_at: now,
        },
    );
    save_unlocked(path, &mut unlocked)
}

pub fn get_entry(path: &Path, master_password: &str, name: &str) -> AppResult<Entry> {
    let unlocked = unlock_vault(path, master_password)?;
    unlocked
        .data
        .entries
        .get(name)
        .cloned()
        .ok_or_else(|| AppError::EntryNotFound(name.to_string()))
}

pub fn update_entry(
    path: &Path,
    master_password: &str,
    name: &str,
    username: Option<&str>,
    password: &str,
) -> AppResult<()> {
    let mut unlocked = unlock_vault(path, master_password)?;
    let entry = unlocked
        .data
        .entries
        .get_mut(name)
        .ok_or_else(|| AppError::EntryNotFound(name.to_string()))?;

    if let Some(username) = username {
        entry.username = username.to_string();
    }
    entry.password = password.to_string();
    entry.updated_at = Utc::now();
    save_unlocked(path, &mut unlocked)
}

pub fn delete_entry(path: &Path, master_password: &str, name: &str) -> AppResult<()> {
    let mut unlocked = unlock_vault(path, master_password)?;
    if unlocked.data.entries.remove(name).is_none() {
        return Err(AppError::EntryNotFound(name.to_string()));
    }
    save_unlocked(path, &mut unlocked)
}

pub fn list_entries(path: &Path, master_password: &str) -> AppResult<Vec<(String, String)>> {
    let unlocked = unlock_vault(path, master_password)?;
    Ok(unlocked
        .data
        .entries
        .iter()
        .map(|(name, entry)| (name.clone(), entry.username.clone()))
        .collect())
}

pub fn change_master_password(
    path: &Path,
    old_master_password: &str,
    new_master_password: &str,
) -> AppResult<()> {
    if old_master_password == new_master_password {
        return Err(AppError::MasterPasswordUnchanged);
    }

    let mut unlocked = unlock_vault(path, old_master_password)?;
    let new_kdf = default_kdf_config(random_salt());
    let mut new_kek = derive_kek(new_master_password, &new_kdf)?;
    unlocked.file.kdf = new_kdf;
    unlocked.file.key_wrap = wrap_dek(&new_kek, &unlocked.dek)?;
    new_kek.zeroize();
    save_unlocked(path, &mut unlocked)
}

fn save_unlocked(path: &Path, unlocked: &mut UnlockedVault) -> AppResult<()> {
    let plaintext = serde_json::to_vec(&unlocked.data)?;
    unlocked.file.data = encrypt(&unlocked.dek, &plaintext)?;
    write_vault_file(path, &unlocked.file)
}

fn read_vault_file(path: &Path) -> AppResult<VaultFile> {
    if !path.exists() {
        return Err(AppError::VaultMissing(path.to_path_buf()));
    }
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_vault_file(path: &Path, file: &VaultFile) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension("tmp");
    let text = serde_json::to_string_pretty(file)?;
    fs::write(&temp_path, text)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(temp_path, path)?;
    Ok(())
}

fn validate_vault_file(file: &VaultFile) -> AppResult<()> {
    if file.version != VAULT_VERSION {
        return Err(AppError::UnsupportedVersion(file.version));
    }
    if file.kdf.algorithm != KDF_ALGORITHM
        || file.key_wrap.algorithm != CIPHER_ALGORITHM
        || file.data.algorithm != CIPHER_ALGORITHM
    {
        return Err(AppError::UnsupportedAlgorithm);
    }
    Ok(())
}
```

- [ ] **Step 3: Run vault tests**

Run:

```bash
cargo test vault
```

Expected: PASS.

- [ ] **Step 4: Commit vault workflows**

Run:

```bash
git add src/vault.rs
git commit -m "feat: add vault workflows"
```

## Task 5: Implement CLI and Clipboard

**Files:**
- Create: `src/clipboard.rs`
- Create: `src/cli.rs`
- Modify: `src/main.rs`
- Test: unit tests in `src/cli.rs`

- [ ] **Step 1: Write CLI argument tests**

Add this test module at the bottom of `src/cli.rs` after creating the file in Step 3:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_get_show_with_custom_vault() {
        let cli = Cli::parse_from([
            "mypass",
            "--vault",
            "./work.mypass",
            "get",
            "github",
            "--show",
        ]);

        assert_eq!(cli.vault.as_deref(), Some(std::path::Path::new("./work.mypass")));
        match cli.command {
            Commands::Get { entry, show } => {
                assert_eq!(entry, "github");
                assert!(show);
            }
            _ => panic!("expected get command"),
        }
    }
}
```

- [ ] **Step 2: Implement clipboard wrapper**

Add this `src/clipboard.rs`:

```rust
use crate::errors::{AppError, AppResult};
use arboard::Clipboard;
use std::thread;
use std::time::Duration;

pub fn copy_and_clear_later(secret: String, clear_after: Duration) -> AppResult<()> {
    let mut clipboard =
        Clipboard::new().map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    clipboard
        .set_text(secret)
        .map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;

    thread::spawn(move || {
        thread::sleep(clear_after);
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text(String::new());
        }
    });

    Ok(())
}
```

- [ ] **Step 3: Implement CLI module**

Add this `src/cli.rs`:

```rust
use crate::clipboard::copy_and_clear_later;
use crate::errors::{AppError, AppResult};
use crate::vault;
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "mypass", version, about = "Local encrypted password manager")]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Init,
    Add {
        entry: String,
    },
    Get {
        entry: String,
        #[arg(long)]
        show: bool,
    },
    Update {
        entry: String,
    },
    Delete {
        entry: String,
    },
    List,
    ChangeMaster,
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let result = run_cli(cli);
    match result {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow::anyhow!(err)),
    }
}

pub fn run_cli(cli: Cli) -> AppResult<()> {
    let vault_path = match cli.vault {
        Some(path) => path,
        None => vault::default_vault_path()?,
    };

    match cli.command {
        Commands::Init => {
            let master = prompt_confirmed_password("Create master password: ", "Confirm master password: ")?;
            vault::init_vault(&vault_path, &master)?;
            println!("Vault initialized at {}", vault_path.display());
        }
        Commands::Add { entry } => {
            let master = prompt_password("Master password: ")?;
            let username = prompt_line("Username: ")?;
            let password = prompt_confirmed_password("Password: ", "Confirm password: ")?;
            vault::add_entry(&vault_path, &master, &entry, &username, &password)?;
            println!("Saved entry: {entry}");
        }
        Commands::Get { entry, show } => {
            let master = prompt_password("Master password: ")?;
            let found = vault::get_entry(&vault_path, &master, &entry)?;
            if show {
                println!("Username: {}", found.username);
                println!("Password: {}", found.password);
            } else {
                copy_and_clear_later(found.password, Duration::from_secs(30))?;
                println!("Password copied to clipboard. It will be cleared in 30 seconds.");
            }
        }
        Commands::Update { entry } => {
            let master = prompt_password("Master password: ")?;
            let existing = vault::get_entry(&vault_path, &master, &entry)?;
            let username_prompt = format!("Username [{}]: ", existing.username);
            let username_input = prompt_line(&username_prompt)?;
            let username = if username_input.trim().is_empty() {
                None
            } else {
                Some(username_input.as_str())
            };
            let password = prompt_confirmed_password("New password: ", "Confirm new password: ")?;
            vault::update_entry(&vault_path, &master, &entry, username, &password)?;
            println!("Updated entry: {entry}");
        }
        Commands::Delete { entry } => {
            let master = prompt_password("Master password: ")?;
            let confirmation = prompt_line(&format!(
                "Delete entry \"{entry}\"? Type the entry name to confirm: "
            ))?;
            if confirmation != entry {
                return Err(AppError::DeleteConfirmationMismatch);
            }
            vault::delete_entry(&vault_path, &master, &entry)?;
            println!("Deleted entry: {entry}");
        }
        Commands::List => {
            let master = prompt_password("Master password: ")?;
            for (name, username) in vault::list_entries(&vault_path, &master)? {
                println!("{name}\t{username}");
            }
        }
        Commands::ChangeMaster => {
            let current = prompt_password("Current master password: ")?;
            let new = prompt_confirmed_password("New master password: ", "Confirm new master password: ")?;
            vault::change_master_password(&vault_path, &current, &new)?;
            println!("Master password changed.");
        }
    }

    Ok(())
}

fn prompt_confirmed_password(prompt: &str, confirm_prompt: &str) -> AppResult<String> {
    let password = prompt_password(prompt)?;
    let confirmation = prompt_password(confirm_prompt)?;
    if password != confirmation {
        return Err(AppError::PasswordMismatch);
    }
    Ok(password)
}

fn prompt_line(prompt: &str) -> AppResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}
```

- [ ] **Step 4: Run CLI tests**

Run:

```bash
cargo test cli
```

Expected: PASS.

- [ ] **Step 5: Commit CLI and clipboard**

Run:

```bash
git add src/cli.rs src/clipboard.rs src/main.rs
git commit -m "feat: add password manager cli"
```

## Task 6: Add End-to-End CLI Tests

**Files:**
- Create: `tests/cli.rs`
- Modify: `src/clipboard.rs` if needed to disable real clipboard in tests.

- [ ] **Step 1: Write integration tests**

Add this `tests/cli.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn init_and_show_entry_flow() {
    let dir = tempdir().expect("tempdir");
    let vault = dir.path().join("test.mypass");

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized at"));

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "add", "github"])
        .write_stdin("master\nclyde@example.com\nsecret\nsecret\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Saved entry: github"));

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "get", "github", "--show"])
        .write_stdin("master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: clyde@example.com"))
        .stdout(predicate::str::contains("Password: secret"));
}

#[test]
fn change_master_flow() {
    let dir = tempdir().expect("tempdir");
    let vault = dir.path().join("test.mypass");

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "init"])
        .write_stdin("old-master\nold-master\n")
        .assert()
        .success();

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "add", "github"])
        .write_stdin("old-master\nclyde@example.com\nsecret\nsecret\n")
        .assert()
        .success();

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "change-master"])
        .write_stdin("old-master\nnew-master\nnew-master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Master password changed."));

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "get", "github", "--show"])
        .write_stdin("old-master\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Master password is incorrect"));

    Command::cargo_bin("mypass")
        .expect("binary")
        .args(["--vault", vault.to_str().unwrap(), "get", "github", "--show"])
        .write_stdin("new-master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Password: secret"));
}
```

- [ ] **Step 2: Run integration tests**

Run:

```bash
cargo test --test cli
```

Expected: PASS.

- [ ] **Step 3: Commit integration tests**

Run:

```bash
git add tests/cli.rs
git commit -m "test: add cli integration flows"
```

## Task 7: Final Verification and Cleanup

**Files:**
- Modify only files required by verification findings.

- [ ] **Step 1: Run full test suite**

Run:

```bash
cargo test
```

Expected: PASS.

- [ ] **Step 2: Run formatting check**

Run:

```bash
cargo fmt --check
```

Expected: PASS.

- [ ] **Step 3: Run static checks**

Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 4: Manually smoke-test a temporary vault**

Run:

```bash
TMPDIR="$(mktemp -d)"
cargo run -- --vault "$TMPDIR/demo.mypass" init
cargo run -- --vault "$TMPDIR/demo.mypass" add github
cargo run -- --vault "$TMPDIR/demo.mypass" get github --show
cargo run -- --vault "$TMPDIR/demo.mypass" list
cargo run -- --vault "$TMPDIR/demo.mypass" change-master
cargo run -- --vault "$TMPDIR/demo.mypass" delete github
```

Expected: Each command follows the prompt flow from the design and exits successfully when valid input is supplied.

- [ ] **Step 5: Commit final cleanup if needed**

If verification required code changes, run:

```bash
git add <changed files>
git commit -m "chore: finalize password manager"
```

If no files changed, do not create an empty commit.

## Self-Review

Spec coverage:

- CLI commands are covered by Tasks 5 and 6.
- Vault file format and models are covered by Task 2.
- Crypto model, Argon2id, ChaCha20-Poly1305, DEK wrapping, and master password change are covered by Tasks 3 and 4.
- `--vault <path>` behavior is covered by Tasks 5 and 6.
- Error handling is covered by Task 2 and exercised in Tasks 4 and 6.
- Testing and verification are covered by Tasks 2 through 7.

Placeholder scan:

- No TBD, TODO, or "implement later" placeholders remain.

Type consistency:

- The plan consistently uses `VaultFile`, `KdfConfig`, `CipherBlob`, `VaultData`, `Entry`, `AppError`, and `AppResult`.
- The plan consistently uses `change_master_password` in the vault layer and `ChangeMaster` in the CLI enum.
