use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn mypass() -> Command {
    Command::cargo_bin("mypass").expect("mypass binary should build")
}

#[test]
fn init_and_show_entry_flow() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized at"));

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nclyde@example.com\nsecret\nsecret\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Saved entry: github"));

    mypass()
        .args(["--vault", &vault, "get", "github", "--show"])
        .write_stdin("master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: clyde@example.com"))
        .stdout(predicate::str::contains("Password: secret"));
}

#[test]
fn change_master_flow() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("old-master\nold-master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized at"));

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("old-master\nclyde@example.com\nsecret\nsecret\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Saved entry: github"));

    mypass()
        .args(["--vault", &vault, "change-master"])
        .write_stdin("old-master\nnew-master\nnew-master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Master password changed."));

    mypass()
        .args(["--vault", &vault, "get", "github", "--show"])
        .write_stdin("old-master\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Master password is incorrect"));

    mypass()
        .args(["--vault", &vault, "get", "github", "--show"])
        .write_stdin("new-master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Password: secret"));
}

#[test]
fn same_entry_supports_multiple_usernames() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nalice@example.com\nalice-secret\nalice-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nbob@example.com\nbob-secret\nbob-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "get", "github", "--show"])
        .write_stdin("master\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Multiple usernames found"));

    mypass()
        .args([
            "--vault",
            &vault,
            "get",
            "github",
            "--username",
            "alice@example.com",
            "--show",
        ])
        .write_stdin("master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: alice@example.com"))
        .stdout(predicate::str::contains("Password: alice-secret"));

    mypass()
        .args([
            "--vault",
            &vault,
            "get",
            "github",
            "--username",
            "bob@example.com",
            "--show",
        ])
        .write_stdin("master\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: bob@example.com"))
        .stdout(predicate::str::contains("Password: bob-secret"));
}

#[test]
fn tui_lists_views_and_exits_with_custom_vault() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nclyde@example.com\nsecret\nsecret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "tui"])
        .write_stdin("master\n/list\n/view github\n/exit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Welcome back to MyPass."))
        .stdout(predicate::str::contains("Vault unlocked:"))
        .stdout(predicate::str::contains(
            "Your secrets are ready. Type /help for commands.",
        ))
        .stdout(predicate::str::contains("github\tclyde@example.com"))
        .stdout(predicate::str::contains("Username: clyde@example.com"))
        .stdout(predicate::str::contains("Password: secret"))
        .stdout(predicate::str::contains("Bye."));
}

#[test]
fn tui_view_shows_all_usernames_for_entry() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("test.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "163"])
        .write_stdin("master\n18814384446\nphone-secret\nphone-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "163"])
        .write_stdin("master\nlinchutaomail@163.com\nmail-secret\nmail-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "tui"])
        .write_stdin("master\n/view 163\n/exit\n")
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
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "tui"])
        .write_stdin("master\n/add github\nclyde@example.com\nfirst\nsecond\n/list\n/exit\n")
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
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nalice@example.com\nalice-secret\nalice-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "add", "github"])
        .write_stdin("master\nbob@example.com\nbob-secret\nbob-secret\n")
        .assert()
        .success();

    mypass()
        .args(["--vault", &vault, "tui"])
        .write_stdin(
            "master\n/copy github\n/update github -u alice@example.com\n\nnew\nnope\n/delete github -u alice@example.com\nwrong\n/change-master\nmaster\nmaster\n/exit\n",
        )
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

#[test]
fn tui_prompts_for_vault_when_not_specified() {
    let temp = tempdir().expect("tempdir should be created");
    let vault_path = temp.path().join("prompted.mypass");
    let vault = vault_path.to_string_lossy().into_owned();

    mypass()
        .args(["--vault", &vault, "init"])
        .write_stdin("master\nmaster\n")
        .assert()
        .success();

    mypass()
        .args(["tui"])
        .write_stdin(format!("{vault}\nmaster\n/exit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault path [default:"))
        .stdout(predicate::str::contains("Welcome back to MyPass."))
        .stdout(predicate::str::contains("Vault unlocked:"))
        .stdout(predicate::str::contains(
            "Your secrets are ready. Type /help for commands.",
        ))
        .stdout(predicate::str::contains("Bye."));
}
