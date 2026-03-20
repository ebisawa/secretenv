// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for member_id and ssh_key resolution
//!
//! Tests the priority order for resolving member_id:
//! 1. CLI argument (--member-id)
//! 2. Environment variable (SECRETENV_MEMBER_ID)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Single member_id in keystore
//!
//! Tests the priority order for resolving ssh_key (Phase 1.5):
//! 1. CLI option (-i)
//! 2. Environment variable (SECRETENV_SSH_KEY)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default (~/.ssh/id_ed25519)

use crate::test_utils::EnvGuard;
use secretenv::config::resolution::member_id::resolve_member_id as resolve_member_id_impl;
use secretenv::config::resolution::ssh_key::resolve_ssh_key as resolve_ssh_key_impl;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn resolve_member_id(member_id_opt: Option<String>) -> secretenv::Result<String> {
    resolve_member_id_impl(member_id_opt, None)
}

fn resolve_ssh_key(ssh_key_opt: Option<PathBuf>) -> secretenv::Result<PathBuf> {
    resolve_ssh_key_impl(ssh_key_opt, None)
}

/// Helper to create global config (SECRETENV_HOME/config.toml)
fn create_global_config(temp_home: &TempDir, member_id: &str) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, format!("member_id = \"{}\"\n", member_id)).unwrap();
}

/// Helper to create keystore structure with member directories
fn create_keystore_with_members(temp_home: &TempDir, member_ids: &[&str]) {
    let keys_dir = temp_home.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    for member_id in member_ids {
        let member_dir = keys_dir.join(member_id);
        fs::create_dir_all(&member_dir).unwrap();
    }
}

#[test]
#[serial]
fn test_resolve_member_id_from_cli_argument() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Priority 1: CLI argument should always take precedence
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    create_global_config(&temp_home, "global-member");

    let result = resolve_member_id(Some("cli-member".to_string())).unwrap();
    assert_eq!(result, "cli-member");
}

#[test]
#[serial]
fn test_resolve_member_id_from_env_var() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Priority 2: Environment variable when no CLI argument
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");

    // Create empty keystore to avoid errors
    let keys_dir = temp_home.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "env-member");
}

#[test]
#[serial]
fn test_resolve_member_id_from_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Priority 3: Global config when no CLI argument or env var
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    create_global_config(&temp_home, "global-member");

    // Create empty keystore to avoid fallback to keystore resolution
    let keys_dir = temp_home.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "global-member");
}

#[test]
#[serial]
fn test_resolve_member_id_from_single_keystore() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Priority 5: Single member_id in keystore
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");

    // No global config - ensure it doesn't exist
    // Create keystore with only one member
    create_keystore_with_members(&temp_home, &["alice"]);

    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "alice");
}

#[test]
#[serial]
fn test_resolve_member_id_multiple_keystore_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Multiple member_ids in keystore should fail
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");

    // No global config
    // Create keystore with multiple members
    create_keystore_with_members(&temp_home, &["alice", "bob"]);

    let result = resolve_member_id(None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("multiple member_ids found"));
    assert!(err_msg.contains("Specify --member-id <id>"));
    assert!(err_msg.contains("export SECRETENV_MEMBER_ID=<id>"));
    assert!(err_msg.contains("secretenv config set member_id <id>"));
}

#[test]
#[serial]
fn test_resolve_member_id_no_source_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // No source at all should fail
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");

    // Empty keystore
    let keys_dir = temp_home.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let result = resolve_member_id(None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("member_id not configured"));
}

#[test]
#[serial]
fn test_resolve_member_id_priority_order() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Verify that higher priority overrides lower priority
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    create_global_config(&temp_home, "global-member");
    create_keystore_with_members(&temp_home, &["keystore-member"]);

    // Test 1: CLI argument should override everything
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    let result = resolve_member_id(Some("cli-member".to_string())).unwrap();
    assert_eq!(result, "cli-member");

    // Test 2: Env var should override global/keystore
    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "env-member");

    // Test 3: Global config should override keystore
    env::remove_var("SECRETENV_MEMBER_ID");
    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "global-member");

    // Test 4: Keystore should be used when no configs
    fs::remove_file(temp_home.path().join("config.toml")).unwrap();
    let result = resolve_member_id(None).unwrap();
    assert_eq!(result, "keystore-member");
}

#[test]
#[serial]
fn test_resolve_member_id_empty_keystore() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Empty keystore directory should be treated as no keystore
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");

    // No global config
    // Create empty keystore directory
    let keys_dir = temp_home.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let result = resolve_member_id(None);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_id_nonexistent_keystore() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);

    // Non-existent keystore directory should be treated as no keystore
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");

    // No keystore directory at all
    let result = resolve_member_id(None);
    assert!(result.is_err());
}

// ========== SSH Key Resolution Tests (Phase 1.5) ==========

/// Helper to create a temporary SSH key file
fn create_ssh_key_file(dir: &TempDir, name: &str) -> PathBuf {
    let key_path = dir.path().join(name);
    fs::write(&key_path, "dummy ssh key content").unwrap();
    key_path
}

/// Helper to create global config with ssh_key
fn create_global_config_with_ssh_key(temp_home: &TempDir, ssh_key_path: &str) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, format!("ssh_key = \"{}\"\n", ssh_key_path)).unwrap();
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_cli_option() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);

    // Priority 1: CLI option should always take precedence
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    // Create multiple key files
    let cli_key = create_ssh_key_file(&temp_keys, "cli_key");
    let global_key = create_ssh_key_file(&temp_keys, "global_key");

    // Create global config
    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    // CLI option should win
    let result = resolve_ssh_key(Some(cli_key.clone())).unwrap();
    assert_eq!(result, cli_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);

    // Priority 3: Global config when no CLI option or env var
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let global_key = create_ssh_key_file(&temp_keys, "global_key");
    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    let result = resolve_ssh_key(None).unwrap();
    assert_eq!(result, global_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_default_path() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);

    // Priority 4: Default path (~/.ssh/id_ed25519)
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    // Create a fake HOME directory with .ssh/id_ed25519
    let fake_home = tempfile::tempdir().unwrap();
    let ssh_dir = fake_home.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let default_key = ssh_dir.join("id_ed25519");
    fs::write(&default_key, "dummy default key").unwrap();

    // Temporarily override HOME
    env::set_var("HOME", fake_home.path());

    let result = resolve_ssh_key(None).unwrap();
    assert_eq!(result, default_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_file_not_found_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);

    // Should fail if file doesn't exist
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let nonexistent_key = temp_keys.path().join("nonexistent_key");
    create_global_config_with_ssh_key(&temp_home, nonexistent_key.to_str().unwrap());

    let result = resolve_ssh_key(None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("does not exist") || err_msg.contains("not found"));
}

#[test]
#[serial]
fn test_resolve_ssh_key_no_source_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);

    // Should fail if no source at all (including default)
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    // Create a fake HOME without .ssh/id_ed25519
    let fake_home = tempfile::tempdir().unwrap();
    env::set_var("HOME", fake_home.path());

    let result = resolve_ssh_key(None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not configured") || err_msg.contains("not found"));
}

#[test]
#[serial]
fn test_resolve_ssh_key_priority_order() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);

    // Verify that higher priority overrides lower priority
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let cli_key = create_ssh_key_file(&temp_keys, "cli_key");
    let global_key = create_ssh_key_file(&temp_keys, "global_key");

    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    // Test 1: CLI option should override everything
    let result = resolve_ssh_key(Some(cli_key.clone())).unwrap();
    assert_eq!(result, cli_key);

    // Test 2: Global config should be used when no CLI option
    let result = resolve_ssh_key(None).unwrap();
    assert_eq!(result, global_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_tilde_expansion() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);

    // Should expand ~ in paths
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    // Create a fake HOME with a key
    let fake_home = tempfile::tempdir().unwrap();
    let ssh_dir = fake_home.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let key_path = ssh_dir.join("my_key");
    fs::write(&key_path, "dummy key").unwrap();

    env::set_var("HOME", fake_home.path());

    // Create global config with tilde path
    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "ssh_key = \"~/.ssh/my_key\"\n").unwrap();

    let result = resolve_ssh_key(None).unwrap();
    assert_eq!(result, key_path);
}

// Additional tests for resolve_ssh_key_candidate
use secretenv::config::resolution::ssh_key::{resolve_ssh_key_candidate, SshKeySource};

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_default_missing() {
    let _guard = EnvGuard::new(&["HOME", "SECRETENV_SSH_KEY"]);
    env::set_var("HOME", "/tmp/test_home");
    env::remove_var("SECRETENV_SSH_KEY");

    // Default path doesn't exist
    let result = resolve_ssh_key_candidate(None, None).unwrap();
    assert_eq!(result.source, SshKeySource::Default);
    assert_eq!(result.path, PathBuf::from("/tmp/test_home/.ssh/id_ed25519"));
    assert!(!result.exists);
}

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_explicit_missing() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_KEY"]);
    env::set_var("SECRETENV_SSH_KEY", "/nonexistent/key/path");

    let result = resolve_ssh_key_candidate(None, None).unwrap();
    assert_eq!(result.source, SshKeySource::Env);
    assert_eq!(result.path, PathBuf::from("/nonexistent/key/path"));
    assert!(!result.exists);
}

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_cli_priority() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_KEY"]);
    env::set_var("SECRETENV_SSH_KEY", "/env/key/path");

    let cli_path = PathBuf::from("/cli/key/path");
    let result = resolve_ssh_key_candidate(Some(cli_path.clone()), None).unwrap();
    assert_eq!(result.source, SshKeySource::Cli);
    assert_eq!(result.path, cli_path);
}

// ========== GitHub User Resolution Tests ==========

use secretenv::config::resolution::github_user::resolve_github_user;

#[test]
#[serial]
fn test_resolve_github_user_from_cli() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "env-user");

    let result = resolve_github_user(Some("cli-user".to_string()), None).unwrap();
    assert_eq!(result, Some("cli-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_from_env() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "env-user");

    let result = resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("env-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_from_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_GITHUB_USER");

    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "github_user = \"config-user\"\n").unwrap();

    let result = resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("config-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_none_when_no_source() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_GITHUB_USER");

    let result = resolve_github_user(None, None).unwrap();
    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_github_user_priority_order() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "github_user = \"config-user\"\n").unwrap();

    // CLI > env > config
    env::set_var("SECRETENV_GITHUB_USER", "env-user");
    let result = resolve_github_user(Some("cli-user".to_string()), None).unwrap();
    assert_eq!(result, Some("cli-user".to_string()));

    // env > config
    let result = resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("env-user".to_string()));

    // config only
    env::remove_var("SECRETENV_GITHUB_USER");
    let result = resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("config-user".to_string()));
}

// Additional tests for expand_tilde
use secretenv::config::resolution::common::expand_tilde;

#[test]
#[serial]
fn test_expand_tilde_with_slash() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~/.ssh/id_ed25519").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser/.ssh/id_ed25519"));
}

#[test]
#[serial]
fn test_expand_tilde_alone() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser"));
}

#[test]
fn test_expand_tilde_no_tilde() {
    let result = expand_tilde("/absolute/path").unwrap();
    assert_eq!(result, PathBuf::from("/absolute/path"));
}
