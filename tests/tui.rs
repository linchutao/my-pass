use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn mypass() -> Command {
    Command::cargo_bin("mypass").expect("mypass binary should build")
}

#[test]
fn executable_starts_tui_and_creates_missing_vault() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("new.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .write_stdin(format!(
            "{vault}\nmaster\nmaster\n/add github\nclyde@example.com\nsecret\nsecret\n/list\n/view github\n/exit\n"
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault path [default:"))
        .stdout(predicate::str::contains("Vault not found. Create a new vault."))
        .stdout(predicate::str::contains("Vault initialized:"))
        .stdout(predicate::str::contains("Welcome back to MyPass."))
        .stdout(predicate::str::contains("Vault unlocked:"))
        .stdout(predicate::str::contains(
            "Your secrets are ready. Type /help for commands.",
        ))
        .stdout(predicate::str::contains("Saved entry: github"))
        .stdout(predicate::str::contains("github\tclyde@example.com"))
        .stdout(predicate::str::contains("Username: clyde@example.com"))
        .stdout(predicate::str::contains("Password: secret"))
        .stdout(predicate::str::contains("Bye."));
}

#[test]
fn executable_reopens_existing_vault() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("existing.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .write_stdin(format!(
            "{vault}\nmaster\nmaster\n/add github\nclyde@example.com\nsecret\nsecret\n/exit\n"
        ))
        .assert()
        .success();

    mypass()
        .write_stdin(format!("{vault}\nmaster\n/view github\n/exit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Welcome back to MyPass."))
        .stdout(predicate::str::contains("Username: clyde@example.com"))
        .stdout(predicate::str::contains("Password: secret"))
        .stdout(predicate::str::contains("Bye."));
}

#[test]
fn executable_rejects_cli_arguments() {
    mypass()
        .args(["--vault", "anything.mypass"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "mypass no longer accepts command-line arguments",
        ));
}

#[test]
fn tui_view_shows_all_usernames_for_entry() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .write_stdin(format!(
            "{vault}\nmaster\nmaster\n/add 163\n18814384446\nphone-secret\nphone-secret\n/add 163\nlinchutaomail@163.com\nmail-secret\nmail-secret\n/view 163\n/exit\n"
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: 18814384446"))
        .stdout(predicate::str::contains("Password: phone-secret"))
        .stdout(predicate::str::contains("Username: linchutaomail@163.com"))
        .stdout(predicate::str::contains("Password: mail-secret"));
}

#[test]
fn tui_add_password_mismatch_stays_in_session() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .write_stdin(format!(
            "{vault}\nmaster\nmaster\n/add github\nclyde@example.com\nfirst\nsecond\n/list\n/exit\n"
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Error: Password confirmation does not match",
        ))
        .stdout(predicate::str::contains("mypass> mypass>"))
        .stdout(predicate::str::contains("Bye."));
}

#[test]
fn tui_command_errors_stay_in_session() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .write_stdin(format!(
            "{vault}\nmaster\nmaster\n/add github\nalice@example.com\nalice-secret\nalice-secret\n/add github\nbob@example.com\nbob-secret\nbob-secret\n/copy github\n/update github -u alice@example.com\n\nnew\nnope\n/delete github -u alice@example.com\nwrong\n/change-master\nmaster\nmaster\n/exit\n"
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains("Error: Multiple usernames found"))
        .stdout(predicate::str::contains(
            "Error: Password confirmation does not match",
        ))
        .stdout(predicate::str::contains(
            "Error: Delete confirmation does not match",
        ))
        .stdout(predicate::str::contains(
            "Error: New master password must be different",
        ))
        .stdout(predicate::str::contains("Bye."));
}
