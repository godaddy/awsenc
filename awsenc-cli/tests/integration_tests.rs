#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

/// Helper: build a Command for the `awsenc` binary with HOME set to
/// an isolated temp directory so tests never touch the real user config.
fn awsenc_cmd(tmp: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("awsenc").unwrap();
    cmd.env("HOME", tmp.path());
    // Clear any env vars that could leak into the test
    cmd.env_remove("AWSENC_PROFILE");
    cmd.env_remove("AWS_PROFILE");
    cmd.env_remove("XDG_CONFIG_HOME");
    cmd
}

// ---------------------------------------------------------------------------
// Help and basic commands
// ---------------------------------------------------------------------------

#[test]
fn help_shows_description() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Hardware-backed AWS credential manager",
        ));
}

#[test]
fn auth_help_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["auth", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Authenticate"));
}

#[test]
fn serve_help_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("credential_process"));
}

#[test]
fn exec_help_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["exec", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("command"));
}

#[test]
fn install_help_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["install", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("profile"));
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_exits_zero_and_shows_paths() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .arg("config")
        .assert()
        .success()
        .stderr(predicate::str::contains("Configuration paths"));
}

// ---------------------------------------------------------------------------
// Completions
// ---------------------------------------------------------------------------

#[test]
fn completions_bash_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn completions_zsh_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn completions_fish_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn completions_powershell_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["completions", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

// ---------------------------------------------------------------------------
// Shell init
// ---------------------------------------------------------------------------

#[test]
fn shell_init_bash_contains_awsenc_use() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["shell-init", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("awsenc-use"));
}

#[test]
fn shell_init_zsh_contains_preexec() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["shell-init", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("preexec"));
}

#[test]
fn shell_init_fish_contains_function() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["shell-init", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("function"));
}

#[test]
fn shell_init_powershell_contains_function() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["shell-init", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("function"));
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[test]
fn list_exits_zero_with_no_profiles() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp).arg("list").assert().success();
}

#[test]
fn list_json_exits_zero_and_is_valid_json() {
    let tmp = tempfile::tempdir().unwrap();
    let output = awsenc_cmd(&tmp)
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value =
        serde_json::from_slice(&output).expect("list --json output should be valid JSON");
    assert!(parsed.is_array(), "list --json should output a JSON array");
}

// ---------------------------------------------------------------------------
// Serve without profile
// ---------------------------------------------------------------------------

#[test]
fn serve_without_profile_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .arg("serve")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn serve_with_nonexistent_profile_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["serve", "--profile", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

#[test]
fn clear_all_force_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["clear", "--all", "--force"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Cleared 0 cached credential(s)"));
}

// ---------------------------------------------------------------------------
// Invalid commands
// ---------------------------------------------------------------------------

#[test]
fn nonexistent_subcommand_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp).arg("nonexistent").assert().failure();
}

// ---------------------------------------------------------------------------
// Migrate
// ---------------------------------------------------------------------------

#[test]
fn migrate_dry_run_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    awsenc_cmd(&tmp)
        .args(["migrate", "--dry-run"])
        .assert()
        .success()
        .stderr(predicate::str::contains("No aws-okta-processor entries found"));
}
