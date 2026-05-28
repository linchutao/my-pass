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
