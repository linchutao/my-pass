use crate::clipboard::{clear_if_unchanged, copy_secret};
use crate::errors::{AppError, AppResult};
use crate::vault::{self, UnlockedVault};
use rpassword::prompt_password;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiCommand {
    List,
    View {
        entry: String,
        username: Option<String>,
    },
    Copy {
        entry: String,
        username: Option<String>,
    },
    Add {
        entry: String,
    },
    Update {
        entry: String,
        username: Option<String>,
    },
    Delete {
        entry: String,
        username: Option<String>,
    },
    ChangeMaster,
    Help,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiParseError {
    Empty,
    UnknownCommand(String),
    MissingEntry(&'static str),
    UnexpectedArgument(String),
    MissingUsernameValue,
}

pub fn parse_command(input: &str) -> Result<TuiCommand, TuiParseError> {
    let mut parts = input.split_whitespace();
    let command = parts.next().ok_or(TuiParseError::Empty)?;

    match command {
        "/list" => parse_no_args(TuiCommand::List, parts),
        "/help" => parse_no_args(TuiCommand::Help, parts),
        "/exit" => parse_no_args(TuiCommand::Exit, parts),
        "/change-master" => parse_no_args(TuiCommand::ChangeMaster, parts),
        "/view" => {
            let (entry, username) = parse_entry_args("/view", parts)?;
            Ok(TuiCommand::View { entry, username })
        }
        "/copy" => {
            let (entry, username) = parse_entry_args("/copy", parts)?;
            Ok(TuiCommand::Copy { entry, username })
        }
        "/add" => {
            let entry = parse_required_entry("/add", &mut parts)?;
            if let Some(extra) = parts.next() {
                return Err(TuiParseError::UnexpectedArgument(extra.to_string()));
            }
            Ok(TuiCommand::Add { entry })
        }
        "/update" => {
            let (entry, username) = parse_entry_args("/update", parts)?;
            Ok(TuiCommand::Update { entry, username })
        }
        "/delete" => {
            let (entry, username) = parse_entry_args("/delete", parts)?;
            Ok(TuiCommand::Delete { entry, username })
        }
        unknown => Err(TuiParseError::UnknownCommand(unknown.to_string())),
    }
}

fn parse_no_args<'a>(
    command: TuiCommand,
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<TuiCommand, TuiParseError> {
    if let Some(extra) = parts.next() {
        return Err(TuiParseError::UnexpectedArgument(extra.to_string()));
    }
    Ok(command)
}

fn parse_required_entry<'a>(
    command: &'static str,
    parts: &mut impl Iterator<Item = &'a str>,
) -> Result<String, TuiParseError> {
    parts
        .next()
        .map(str::to_string)
        .ok_or(TuiParseError::MissingEntry(command))
}

fn parse_entry_args<'a>(
    command: &'static str,
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<(String, Option<String>), TuiParseError> {
    let entry = parse_required_entry(command, &mut parts)?;
    let mut username = None;

    while let Some(arg) = parts.next() {
        match arg {
            "--username" => {
                let value = parts.next().ok_or(TuiParseError::MissingUsernameValue)?;
                username = Some(value.to_string());
            }
            other => return Err(TuiParseError::UnexpectedArgument(other.to_string())),
        }
    }

    Ok((entry, username))
}

pub fn run(vault_arg: Option<PathBuf>) -> AppResult<()> {
    let default_vault_path = vault::default_vault_path()?;
    let vault_path = match vault_arg {
        Some(path) => path,
        None => {
            let input = prompt_line(&format!(
                "Vault path [default: {}]: ",
                default_vault_path.display()
            ))?;
            if input.is_empty() {
                default_vault_path
            } else {
                PathBuf::from(input)
            }
        }
    };

    let mut master_password = prompt_secret("Master password: ")?;
    let mut unlocked = vault::unlock_vault(&vault_path, master_password.as_str())?;
    println!("Unlocked vault: {}", vault_path.display());
    println!("Type /help for commands.");

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    run_repl(
        &vault_path,
        &mut unlocked,
        &mut master_password,
        &mut input,
        &mut output,
    )
}

fn run_repl<R: BufRead, W: Write>(
    vault_path: &std::path::Path,
    unlocked: &mut UnlockedVault,
    master_password: &mut Zeroizing<String>,
    input: &mut R,
    output: &mut W,
) -> AppResult<()> {
    loop {
        write!(output, "mypass> ")?;
        output.flush()?;

        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            writeln!(output, "Bye.")?;
            return Ok(());
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_command(line) {
            Ok(TuiCommand::Exit) => {
                writeln!(output, "Bye.")?;
                return Ok(());
            }
            Ok(command) => {
                if let Err(error) = handle_command(
                    vault_path,
                    unlocked,
                    master_password,
                    command,
                    input,
                    output,
                ) {
                    writeln!(output, "Error: {error}")?;
                }
            }
            Err(error) => writeln!(output, "{}", format_parse_error(error))?,
        }
    }
}

fn handle_command<R: BufRead, W: Write>(
    vault_path: &std::path::Path,
    unlocked: &mut UnlockedVault,
    master_password: &mut Zeroizing<String>,
    command: TuiCommand,
    input: &mut R,
    output: &mut W,
) -> AppResult<()> {
    match command {
        TuiCommand::List => {
            for (name, username) in vault::list_entries_unlocked(unlocked) {
                writeln!(output, "{name}\t{username}")?;
            }
        }
        TuiCommand::View { entry, username } => {
            if let Some(username) = username {
                let found = vault::get_entry_unlocked(unlocked, &entry, Some(&username))?;
                writeln!(output, "Username: {}", found.username)?;
                writeln!(output, "Password: {}", found.password)?;
            } else {
                for found in vault::get_entries_unlocked(unlocked, &entry)? {
                    writeln!(output, "Username: {}", found.username)?;
                    writeln!(output, "Password: {}", found.password)?;
                }
            }
        }
        TuiCommand::Copy { entry, username } => {
            let found = vault::get_entry_unlocked(unlocked, &entry, username.as_deref())?;
            copy_secret(&found.password)?;
            writeln!(
                output,
                "Password copied to clipboard. It will be cleared in 30 seconds."
            )?;
            output.flush()?;
            std::thread::sleep(Duration::from_secs(30));
            clear_if_unchanged(&found.password)?;
            writeln!(output, "Clipboard cleared if unchanged.")?;
        }
        TuiCommand::Add { entry } => {
            let username = read_prompt(input, output, "Username: ")?;
            let password = read_confirmed(input, output, "Password: ", "Confirm password: ")?;
            vault::add_entry_unlocked(vault_path, unlocked, &entry, &username, password.as_str())?;
            writeln!(output, "Saved entry: {entry}")?;
        }
        TuiCommand::Update { entry, username } => {
            let existing = vault::get_entry_unlocked(unlocked, &entry, username.as_deref())?;
            let username_prompt = format!("Username [{}]: ", existing.username);
            let username_input = read_prompt(input, output, &username_prompt)?;
            let new_username = if username_input.is_empty() {
                None
            } else {
                Some(username_input.as_str())
            };
            let password =
                read_confirmed(input, output, "New password: ", "Confirm new password: ")?;
            vault::update_entry_unlocked(
                vault_path,
                unlocked,
                &entry,
                username.as_deref(),
                new_username,
                password.as_str(),
            )?;
            writeln!(output, "Updated entry: {entry}")?;
        }
        TuiCommand::Delete { entry, username } => {
            let confirmation = read_prompt(
                input,
                output,
                &format!("Delete entry \"{entry}\"? Type the entry name to confirm: "),
            )?;
            if confirmation != entry {
                return Err(AppError::DeleteConfirmationMismatch);
            }
            vault::delete_entry_unlocked(vault_path, unlocked, &entry, username.as_deref())?;
            writeln!(output, "Deleted entry: {entry}")?;
        }
        TuiCommand::ChangeMaster => {
            let new = read_confirmed(
                input,
                output,
                "New master password: ",
                "Confirm new master password: ",
            )?;
            if master_password.as_str() == new.as_str() {
                return Err(AppError::MasterPasswordUnchanged);
            }
            vault::change_master_password_unlocked(vault_path, unlocked, new.as_str())?;
            *master_password = new;
            writeln!(output, "Master password changed.")?;
        }
        TuiCommand::Help => write_help(output)?,
        TuiCommand::Exit => {}
    }

    Ok(())
}

fn write_help(output: &mut impl Write) -> AppResult<()> {
    writeln!(output, "/list")?;
    writeln!(output, "/view <entry> [--username <username>]")?;
    writeln!(output, "/copy <entry> [--username <username>]")?;
    writeln!(output, "/add <entry>")?;
    writeln!(output, "/update <entry> [--username <username>]")?;
    writeln!(output, "/delete <entry> [--username <username>]")?;
    writeln!(output, "/change-master")?;
    writeln!(output, "/help")?;
    writeln!(output, "/exit")?;
    Ok(())
}

fn format_parse_error(error: TuiParseError) -> String {
    match error {
        TuiParseError::Empty => "Empty command".to_string(),
        TuiParseError::UnknownCommand(command) => {
            format!("Unknown command: {command}. Type /help for commands.")
        }
        TuiParseError::MissingEntry(command) => {
            format!("Missing entry for {command}")
        }
        TuiParseError::UnexpectedArgument(argument) => {
            format!("Unexpected argument: {argument}")
        }
        TuiParseError::MissingUsernameValue => "Missing value after --username".to_string(),
    }
}

fn read_confirmed<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
    confirm_prompt: &str,
) -> AppResult<Zeroizing<String>> {
    let password = Zeroizing::new(read_prompt(input, output, prompt)?);
    let confirmation = read_prompt(input, output, confirm_prompt)?;
    if password.as_str() != confirmation {
        return Err(AppError::PasswordMismatch);
    }
    Ok(password)
}

fn read_prompt<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
) -> AppResult<String> {
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut value = String::new();
    input.read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_secret(prompt: &str) -> AppResult<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return Ok(Zeroizing::new(prompt_password(prompt)?));
    }

    Ok(Zeroizing::new(prompt_line(prompt)?))
}

fn prompt_line(prompt: &str) -> AppResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exit_command() {
        assert_eq!(parse_command("/exit"), Ok(TuiCommand::Exit));
    }

    #[test]
    fn parses_entry_command_with_username() {
        assert_eq!(
            parse_command("/view github --username alice@example.com"),
            Ok(TuiCommand::View {
                entry: "github".to_string(),
                username: Some("alice@example.com".to_string()),
            })
        );
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(matches!(
            parse_command("/nope"),
            Err(TuiParseError::UnknownCommand(command)) if command == "/nope"
        ));
    }
}
