// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for ExecutionContext::resolve() dispatch behavior.
//!
//! Verifies that resolve() correctly dispatches to load_from_env()
//! when ssh_ctx is None, and handles workspace / env var requirements.

use crate::test_utils::EnvGuard;
use secretenv::app::context::{CommonCommandOptions, ExecutionContext};
use tempfile::TempDir;

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";
const ENV_WORKSPACE: &str = "SECRETENV_WORKSPACE";
const ENV_HOME: &str = "SECRETENV_HOME";

/// Build options pointing to an isolated temp directory that is NOT a workspace.
/// This prevents auto-detection from finding a real workspace in the dev environment.
fn build_options_no_workspace(home: &TempDir, non_workspace: &TempDir) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: Some(non_workspace.path().to_path_buf()),
        ssh_signer: None,
    }
}

fn expect_err(result: secretenv::Result<ExecutionContext>) -> String {
    match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error but got Ok"),
    }
}

#[test]
fn test_resolve_none_ssh_ctx_requires_workspace() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();
    let non_workspace = TempDir::new().unwrap();
    let options = build_options_no_workspace(&home, &non_workspace);

    // Set env var so load_from_env progresses past key loading,
    // but workspace path lacks required structure — should fail at require_workspace.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(ExecutionContext::resolve(&options, None, None, None));
    assert!(
        err.contains("not a valid workspace"),
        "Expected workspace validation error, got: {}",
        err
    );
}

#[test]
fn test_resolve_none_ssh_ctx_without_env_var_fails() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_PRIVATE_KEY);
    std::env::remove_var(ENV_KEY_PASSWORD);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();
    let workspace = TempDir::new().unwrap();
    // Provide a valid workspace directory so require_workspace doesn't fail first.
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let options = CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: Some(workspace.path().to_path_buf()),
        ssh_signer: None,
    };

    let err = expect_err(ExecutionContext::resolve(&options, None, None, None));
    assert!(
        err.contains("not set"),
        "Expected 'not set' error for missing SECRETENV_PRIVATE_KEY, got: {}",
        err
    );
}

#[test]
fn test_resolve_rejects_member_id_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: None,
        ssh_signer: None,
    };

    // Provide member_id with ssh_ctx=None to trigger the error path.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(ExecutionContext::resolve(
        &options,
        Some("alice@example.com".to_string()),
        None,
        None,
    ));
    assert!(
        err.contains("--member-id cannot be used"),
        "Expected --member-id rejection error, got: {}",
        err
    );
}

#[test]
fn test_resolve_rejects_kid_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: None,
        ssh_signer: None,
    };

    // Provide explicit_kid with ssh_ctx=None to trigger the error path.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(ExecutionContext::resolve(
        &options,
        None,
        Some("01HTEST00000000000000ALICE"),
        None,
    ));
    assert!(
        err.contains("--kid cannot be used"),
        "Expected --kid rejection error, got: {}",
        err
    );
}
