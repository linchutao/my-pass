use crate::crypto::{
    decrypt, default_kdf_config, derive_kek, encrypt, random_key, random_salt, unwrap_dek, wrap_dek,
};
use crate::errors::{AppError, AppResult};
use crate::model::{
    CipherBlob, Entry, VaultData, VaultFile, CIPHER_ALGORITHM, KDF_ALGORITHM, VAULT_VERSION,
};
use chrono::Utc;
use directories::ProjectDirs;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub struct UnlockedVault {
    pub file: VaultFile,
    pub data: VaultData,
    dek: [u8; 32],
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedVault")
            .field("file", &self.file)
            .field("data", &self.data)
            .field("dek", &"<redacted>")
            .finish()
    }
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

    let kdf = default_kdf_config(random_salt());
    let mut kek = derive_kek(master_password, &kdf)?;
    let mut dek = random_key();
    let key_wrap = wrap_dek(&kek, &dek)?;
    let data = encrypt_vault_data(&dek, &VaultData::empty())?;
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
    let dek_result = unwrap_dek(&kek, &file.key_wrap);
    kek.zeroize();
    let dek = dek_result?;

    let plaintext = decrypt(&dek, &file.data)?;
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
    let mut vault = unlock_vault(path, master_password)?;
    if vault.data.entries.contains_key(name) {
        return Err(AppError::EntryExists(name.to_string()));
    }

    let now = Utc::now();
    vault.data.entries.insert(
        name.to_string(),
        Entry {
            username: username.to_string(),
            password: password.to_string(),
            created_at: now,
            updated_at: now,
        },
    );
    save_unlocked(path, &mut vault)
}

pub fn get_entry(path: &Path, master_password: &str, name: &str) -> AppResult<Entry> {
    let vault = unlock_vault(path, master_password)?;
    vault
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
    let mut vault = unlock_vault(path, master_password)?;
    let entry = vault
        .data
        .entries
        .get_mut(name)
        .ok_or_else(|| AppError::EntryNotFound(name.to_string()))?;

    if let Some(username) = username {
        entry.username = username.to_string();
    }
    entry.password = password.to_string();
    entry.updated_at = Utc::now();
    save_unlocked(path, &mut vault)
}

pub fn delete_entry(path: &Path, master_password: &str, name: &str) -> AppResult<()> {
    let mut vault = unlock_vault(path, master_password)?;
    if vault.data.entries.remove(name).is_none() {
        return Err(AppError::EntryNotFound(name.to_string()));
    }
    save_unlocked(path, &mut vault)
}

pub fn list_entries(path: &Path, master_password: &str) -> AppResult<Vec<(String, String)>> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault
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

    let mut vault = unlock_vault(path, old_master_password)?;
    let kdf = default_kdf_config(random_salt());
    let mut kek = derive_kek(new_master_password, &kdf)?;
    let key_wrap = wrap_dek(&kek, &vault.dek)?;
    kek.zeroize();

    vault.file.kdf = kdf;
    vault.file.key_wrap = key_wrap;
    save_unlocked(path, &mut vault)
}

fn read_vault_file(path: &Path) -> AppResult<VaultFile> {
    if !path.exists() {
        return Err(AppError::VaultMissing(path.to_path_buf()));
    }

    let contents = fs::read(path)?;
    Ok(serde_json::from_slice(&contents)?)
}

fn write_vault_file(path: &Path, file: &VaultFile) -> AppResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temp_vault_path(path);
    let contents = serde_json::to_vec_pretty(file)?;
    fs::write(&temp_path, contents)?;

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
    validate_cipher_blob(&file.key_wrap)?;
    validate_cipher_blob(&file.data)?;
    Ok(())
}

fn save_unlocked(path: &Path, vault: &mut UnlockedVault) -> AppResult<()> {
    vault.file.data = encrypt_vault_data(&vault.dek, &vault.data)?;
    write_vault_file(path, &vault.file)
}

fn encrypt_vault_data(dek: &[u8; 32], data: &VaultData) -> AppResult<CipherBlob> {
    let plaintext = serde_json::to_vec(data)?;
    encrypt(dek, &plaintext)
}

fn validate_cipher_blob(blob: &CipherBlob) -> AppResult<()> {
    if blob.algorithm != CIPHER_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }
    Ok(())
}

fn temp_vault_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.mypass");
    path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::AppError;

    fn vault_path(tempdir: &tempfile::TempDir) -> std::path::PathBuf {
        tempdir.path().join("vault.mypass")
    }

    #[test]
    fn init_and_unlock_empty_vault() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);

        init_vault(&path, "correct horse battery staple").expect("init vault");
        let unlocked = unlock_vault(&path, "correct horse battery staple").expect("unlock vault");

        assert_eq!(unlocked.file.version, crate::model::VAULT_VERSION);
        assert!(unlocked.data.entries.is_empty());
    }

    #[test]
    fn wrong_master_password_fails() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "correct horse battery staple").expect("init vault");

        let err = unlock_vault(&path, "wrong password").expect_err("wrong password should fail");

        assert!(matches!(err, AppError::AuthenticationFailed));
    }

    #[test]
    fn entry_crud_flow_persists() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "master").expect("init vault");

        add_entry(&path, "master", "github", "clyde", "first").expect("add entry");
        add_entry(&path, "master", "bank", "clyde@example.com", "money").expect("add second");

        assert_eq!(
            list_entries(&path, "master").expect("list entries"),
            vec![
                ("bank".to_string(), "clyde@example.com".to_string()),
                ("github".to_string(), "clyde".to_string()),
            ]
        );

        let created = get_entry(&path, "master", "github").expect("get entry");
        assert_eq!(created.username, "clyde");
        assert_eq!(created.password, "first");
        assert_eq!(created.created_at, created.updated_at);

        update_entry(&path, "master", "github", Some("new-clyde"), "second").expect("update entry");
        let updated = get_entry(&path, "master", "github").expect("get updated");
        assert_eq!(updated.username, "new-clyde");
        assert_eq!(updated.password, "second");
        assert_eq!(updated.created_at, created.created_at);
        assert!(updated.updated_at >= created.updated_at);

        delete_entry(&path, "master", "github").expect("delete entry");
        let err =
            get_entry(&path, "master", "github").expect_err("deleted entry should be missing");
        assert!(matches!(err, AppError::EntryNotFound(name) if name == "github"));
        assert_eq!(
            list_entries(&path, "master").expect("list after delete"),
            vec![("bank".to_string(), "clyde@example.com".to_string())]
        );
    }

    #[test]
    fn duplicate_add_fails() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "master").expect("init vault");
        add_entry(&path, "master", "github", "clyde", "first").expect("add entry");

        let err = add_entry(&path, "master", "github", "someone", "second")
            .expect_err("duplicate should fail");

        assert!(matches!(err, AppError::EntryExists(name) if name == "github"));
    }

    #[test]
    fn change_master_invalidates_old_password() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "old-master").expect("init vault");
        add_entry(&path, "old-master", "github", "clyde", "secret").expect("add entry");

        change_master_password(&path, "old-master", "new-master").expect("change master password");

        let err = unlock_vault(&path, "old-master").expect_err("old password should fail");
        assert!(matches!(err, AppError::AuthenticationFailed));

        let entry = get_entry(&path, "new-master", "github").expect("new password unlocks");
        assert_eq!(entry.username, "clyde");
        assert_eq!(entry.password, "secret");
    }
}
