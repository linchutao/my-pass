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
