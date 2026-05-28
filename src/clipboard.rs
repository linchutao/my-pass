use crate::errors::{AppError, AppResult};
use arboard::Clipboard;
use std::time::Duration;

pub fn copy_and_clear_later(secret: String, clear_after: Duration) -> AppResult<()> {
    let mut clipboard =
        Clipboard::new().map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    clipboard
        .set_text(secret.clone())
        .map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;

    std::thread::sleep(clear_after);

    if clipboard.get_text().ok().as_deref() == Some(secret.as_str()) {
        clipboard
            .set_text(String::new())
            .map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    }

    Ok(())
}

pub fn copy_secret(secret: &str) -> AppResult<()> {
    let mut clipboard =
        Clipboard::new().map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    clipboard
        .set_text(secret.to_string())
        .map_err(|err| AppError::ClipboardUnavailable(err.to_string()))
}

pub fn clear_if_unchanged(secret: &str) -> AppResult<()> {
    let mut clipboard =
        Clipboard::new().map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    if clipboard.get_text().ok().as_deref() == Some(secret) {
        clipboard
            .set_text(String::new())
            .map_err(|err| AppError::ClipboardUnavailable(err.to_string()))?;
    }

    Ok(())
}
