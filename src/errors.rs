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
