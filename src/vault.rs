use crate::crypto::{
    decrypt, default_kdf_config, derive_kek, encrypt, random_key, random_salt, unwrap_dek, wrap_dek,
};
use crate::errors::{AppError, AppResult};
use crate::model::{
    CIPHER_ALGORITHM, CipherBlob, Entry, KDF_ALGORITHM, VAULT_VERSION, VaultData, VaultFile,
};
use chrono::Utc;
use directories::ProjectDirs;
use rand_core::{OsRng, RngCore};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

struct SecretKey([u8; 32]);

impl SecretKey {
    fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn into_inner(mut self) -> [u8; 32] {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

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
    let kdf = default_kdf_config(random_salt());
    let kek = SecretKey::new(derive_kek(master_password, &kdf)?);
    let dek = SecretKey::new(random_key());
    let key_wrap = wrap_dek(kek.expose(), dek.expose())?;
    let data = encrypt_vault_data(dek.expose(), &VaultData::empty())?;
    let file = VaultFile {
        version: VAULT_VERSION,
        kdf,
        key_wrap,
        data,
    };

    create_vault_file(path, &file)?;
    Ok(())
}

pub fn unlock_vault(path: &Path, master_password: &str) -> AppResult<UnlockedVault> {
    let file = read_vault_file(path)?;
    validate_vault_file(&file)?;

    let kek = SecretKey::new(derive_kek(master_password, &file.kdf)?);
    let dek = SecretKey::new(unwrap_dek(kek.expose(), &file.key_wrap)?);

    let plaintext = SecretBytes::new(decrypt(dek.expose(), &file.data)?);
    let data = serde_json::from_slice(plaintext.expose())?;

    Ok(UnlockedVault {
        file,
        data,
        dek: dek.into_inner(),
    })
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
    let kek = SecretKey::new(derive_kek(new_master_password, &kdf)?);
    let key_wrap = wrap_dek(kek.expose(), &vault.dek)?;

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
    ensure_parent_dir(path)?;

    let contents = serde_json::to_vec_pretty(file)?;
    let (temp_path, mut temp_file) = create_private_temp_file(path)?;
    temp_file.write_all(&contents)?;
    temp_file.sync_all()?;
    drop(temp_file);

    replace_vault_file(&temp_path, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn create_vault_file(path: &Path, file: &VaultFile) -> AppResult<()> {
    ensure_parent_dir(path)?;

    let contents = serde_json::to_vec_pretty(file)?;
    let mut output = create_private_output_file(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::VaultExists(path.to_path_buf())
        } else {
            AppError::Io(err)
        }
    })?;
    output.write_all(&contents)?;
    output.sync_all()?;
    drop(output);

    sync_parent_dir(path)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> AppResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
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
    let plaintext = SecretBytes::new(serde_json::to_vec(data)?);
    encrypt(dek, plaintext.expose())
}

fn validate_cipher_blob(blob: &CipherBlob) -> AppResult<()> {
    if blob.algorithm != CIPHER_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }
    Ok(())
}

fn temp_vault_path(path: &Path, random_suffix: u64) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.mypass");
    path.with_file_name(format!(".{file_name}.tmp-{random_suffix:016x}"))
}

fn create_private_temp_file(path: &Path) -> AppResult<(PathBuf, File)> {
    let mut last_error = None;

    for _ in 0..16 {
        let temp_path = temp_vault_path(path, OsRng.next_u64());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }

        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("could not create temporary vault file"))
        .into())
}

fn create_private_output_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    options.open(path)
}

fn replace_vault_file(temp_path: &Path, path: &Path) -> AppResult<()> {
    #[cfg(not(windows))]
    {
        fs::rename(temp_path, path)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        let backup_path = move_existing_vault_to_backup(path)?;
        if let Err(err) = fs::rename(temp_path, path) {
            let _ = fs::rename(&backup_path, path);
            return Err(err.into());
        }

        let _ = fs::remove_file(backup_path);
        Ok(())
    }
}

#[cfg(windows)]
fn move_existing_vault_to_backup(path: &Path) -> AppResult<PathBuf> {
    let mut last_error = None;

    for _ in 0..16 {
        let backup_path = temp_vault_path(path, OsRng.next_u64());
        match fs::rename(path, &backup_path) {
            Ok(()) => return Ok(backup_path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("could not create temporary vault backup"))
        .into())
}

fn sync_parent_dir(path: &Path) -> AppResult<()> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Ok(());
    }

    #[cfg(unix)]
    {
        let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Ok(());
        };

        File::open(parent)?.sync_all()?;
        Ok(())
    }
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
    fn init_existing_vault_fails_without_overwriting() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "first-master").expect("init vault");
        let original = fs::read(&path).expect("read original vault");

        let err = init_vault(&path, "second-master").expect_err("existing vault should fail");

        assert!(matches!(err, AppError::VaultExists(existing) if existing == path));
        assert_eq!(
            fs::read(&path).expect("read vault after failed init"),
            original
        );
        unlock_vault(&path, "first-master").expect("original master still works");
    }

    #[cfg(unix)]
    #[test]
    fn init_writes_private_vault_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);

        init_vault(&path, "correct horse battery staple").expect("init vault");

        let mode = fs::metadata(&path)
            .expect("vault metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
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

    #[test]
    fn change_master_rejects_same_password() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "master").expect("init vault");

        let err = change_master_password(&path, "master", "master")
            .expect_err("same master password should fail");

        assert!(matches!(err, AppError::MasterPasswordUnchanged));
        unlock_vault(&path, "master").expect("original master still works");
    }

    #[test]
    fn change_master_rejects_wrong_current_password() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = vault_path(&tempdir);
        init_vault(&path, "old-master").expect("init vault");

        let err = change_master_password(&path, "wrong-master", "new-master")
            .expect_err("wrong current master should fail");

        assert!(matches!(err, AppError::AuthenticationFailed));
        unlock_vault(&path, "old-master").expect("old master still works");
    }
}
