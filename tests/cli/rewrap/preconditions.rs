// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_rewrap_requires_workspace() {
    let (temp_dir, _workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = None;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let rewrap_args = default_rewrap_args(common_opts, ALICE_MEMBER_ID);
    let invalid_workspace = temp_dir.path().join("workspace-does-not-exist");
    let result = with_vars(
        [(
            "SECRETENV_WORKSPACE",
            Some(invalid_workspace.to_str().expect("invalid path as str")),
        )],
        || rewrap::run(rewrap_args),
    );

    assert!(result.is_err(), "Should fail without workspace");
}

#[test]
fn test_rewrap_with_no_files_fails_gracefully() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let rewrap_args = default_rewrap_args(common_opts, ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_err(), "Should fail with no files in secrets/");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("No encrypted files"),
        "Error should mention no files found: {}",
        err_msg
    );
}

#[test]
fn test_rewrap_nonexistent_workspace_fails() {
    let (_ssh_temp, ssh_priv, _ssh_pub, _pub_content) = create_temp_ssh_keypair();
    let home_dir = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg("/tmp/nonexistent_workspace_secretenv_test")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_rewrap_help() {
    cmd()
        .arg("rewrap")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rewrap"));
}
