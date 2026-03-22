// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `set` command

use crate::cli::common::{cmd, setup_workspace};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_set_creates_new_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");

    // Set a key-value pair
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify file was created
    assert!(default_file.exists(), "Default file should be created");

    // Verify file content
    let content = fs::read_to_string(&default_file).unwrap();
    assert!(content.contains("DATABASE_URL"), "File should contain key");
}

#[test]
fn test_set_updates_existing_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set initial value
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("initial_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Update the value
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("updated_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the value was updated (by getting it)
    cmd()
        .arg("get")
        .arg("API_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("updated_value"));
}

#[test]
fn test_set_multiple_keys() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set multiple keys
    cmd()
        .arg("set")
        .arg("KEY1")
        .arg("value1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("KEY2")
        .arg("value2")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify both keys exist
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY1"))
        .stdout(predicate::str::contains("KEY2"));
}

#[test]
fn test_set_without_workspace_fails() {
    let home_dir = TempDir::new().unwrap();

    // workspace を設定せずに set を実行 → エラーになることを確認
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .env("SECRETENV_HOME", home_dir.path())
        .current_dir("/tmp")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("SSH key")
                .or(predicate::str::contains("workspace"))
                .or(predicate::str::contains("member_id not configured")),
        );
}

#[test]
fn test_set_stdin_creates_new_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a key-value pair via --stdin
    cmd()
        .arg("set")
        .arg("SECRET_TOKEN")
        .arg("--stdin")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .write_stdin("super-secret-token")
        .assert()
        .success();

    // Verify file was created and key exists
    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(default_file.exists(), "Default file should be created");
    let content = fs::read_to_string(&default_file).unwrap();
    assert!(content.contains("SECRET_TOKEN"), "File should contain key");

    // Verify the value can be retrieved
    cmd()
        .arg("get")
        .arg("SECRET_TOKEN")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-token"));
}

#[test]
fn test_set_stdin_and_value_arg_conflicts() {
    let home_dir = TempDir::new().unwrap();

    // --stdin と VALUE 引数の両方を指定するとエラー
    cmd()
        .arg("set")
        .arg("KEY")
        .arg("some_value")
        .arg("--stdin")
        .env("SECRETENV_HOME", home_dir.path())
        .current_dir("/tmp")
        .write_stdin("stdin_value")
        .assert()
        .failure();
}

#[test]
fn test_set_without_stdin_and_without_value_fails() {
    let home_dir = TempDir::new().unwrap();

    // VALUE も --stdin も指定しないとエラー
    cmd()
        .arg("set")
        .arg("KEY")
        .env("SECRETENV_HOME", home_dir.path())
        .current_dir("/tmp")
        .assert()
        .failure();
}
