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
    run_cli(cli).map_err(|err| anyhow::anyhow!(err))
}

pub fn run_cli(cli: Cli) -> AppResult<()> {
    let vault_path = match cli.vault {
        Some(path) => path,
        None => vault::default_vault_path()?,
    };

    match cli.command {
        Commands::Init => {
            let master =
                prompt_confirmed_password("Create master password: ", "Confirm master password: ")?;
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
            let username = if username_input.is_empty() {
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
            let new = prompt_confirmed_password(
                "New master password: ",
                "Confirm new master password: ",
            )?;
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

        assert_eq!(
            cli.vault.as_deref(),
            Some(std::path::Path::new("./work.mypass"))
        );
        match cli.command {
            Commands::Get { entry, show } => {
                assert_eq!(entry, "github");
                assert!(show);
            }
            _ => panic!("expected get command"),
        }
    }
}
