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

fn build_options(home: &TempDir) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: None,
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
    let options = build_options(&home);

    // Set env var so load_from_env progresses past key loading,
    // but workspace is missing — should fail at require_workspace.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(ExecutionContext::resolve(&options, None, None, None));
    assert!(
        err.contains("Workspace is required"),
        "Expected 'Workspace is required' error, got: {}",
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
    let mut options = build_options(&home);
    options.workspace = Some(workspace.path().to_path_buf());

    // Create minimal workspace structure so path validation passes.
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let err = expect_err(ExecutionContext::resolve(&options, None, None, None));
    assert!(
        err.contains("not set"),
        "Expected 'not set' error for missing SECRETENV_PRIVATE_KEY, got: {}",
        err
    );
}

#[test]
fn test_resolve_warns_on_member_id_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();
    let options = build_options(&home);

    // Provide member_id with ssh_ctx=None to trigger the warning path.
    // It should still dispatch to load_from_env and fail on workspace requirement.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(ExecutionContext::resolve(
        &options,
        Some("alice@example.com".to_string()),
        None,
        None,
    ));
    assert!(
        err.contains("Workspace is required"),
        "Expected dispatch to load_from_env (workspace error), got: {}",
        err
    );
}
