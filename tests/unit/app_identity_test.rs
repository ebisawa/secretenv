// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for app::identity::resolve_member_id_with_fallback
//!
//! Tests the priority order for resolving member_id:
//! 1. CLI argument (member_id parameter)
//! 2. Environment variable (SECRETENV_MEMBER_ID)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Single member_id in keystore (only when exactly one exists)

use crate::test_utils::EnvGuard;
use secretenv::app::identity::resolve_member_id_with_fallback;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn setup_keystore(temp_dir: &TempDir, member_ids: &[&str]) -> PathBuf {
    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();
    for &id in member_ids {
        fs::create_dir_all(keystore_root.join(id)).unwrap();
    }
    keystore_root
}

fn write_global_config(temp_home: &TempDir, member_id: &str) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(config_path, format!("member_id = \"{}\"\n", member_id)).unwrap();
}

fn call(
    cli: Option<&str>,
    keystore_root: &Path,
    base_dir: Option<&Path>,
) -> secretenv::Result<Option<String>> {
    resolve_member_id_with_fallback(cli.map(str::to_string), keystore_root, base_dir)
}

// ===== Priority 1: CLI argument =====

#[test]
#[serial]
fn test_resolve_member_id_from_cli_argument() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    write_global_config(&temp_home, "config-member");
    let keystore_root = setup_keystore(&temp_dir, &["keystore-member"]);

    let result = call(Some("cli-member"), &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("cli-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_cli_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(
        Some("invalid member id!"),
        &keystore_root,
        Some(temp_home.path()),
    );

    assert!(result.is_err());
}

// ===== Priority 2: Environment variable =====

#[test]
#[serial]
fn test_resolve_member_id_from_env_var() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    write_global_config(&temp_home, "config-member");
    let keystore_root = setup_keystore(&temp_dir, &["keystore-member"]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("env-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_env_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "invalid member!");
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(None, &keystore_root, Some(temp_home.path()));

    assert!(result.is_err());
}

// ===== Priority 3: Global config =====

#[test]
#[serial]
fn test_resolve_member_id_from_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    write_global_config(&temp_home, "config-member");
    let keystore_root = setup_keystore(&temp_dir, &["keystore-member"]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_config_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    write_global_config(&temp_home, "invalid member!");
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(None, &keystore_root, Some(temp_home.path()));

    assert!(result.is_err());
}

// ===== Priority 4: Keystore =====

#[test]
#[serial]
fn test_resolve_member_id_from_keystore_single_member() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    let keystore_root = setup_keystore(&temp_dir, &["keystore-member"]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("keystore-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_keystore_multiple_members_returns_none() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    let keystore_root = setup_keystore(&temp_dir, &["alice", "bob"]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_member_id_keystore_empty_returns_none() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

// ===== Priority ordering =====

#[test]
#[serial]
fn test_resolve_member_id_priority_cli_over_env() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(Some("cli-member"), &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("cli-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_priority_env_over_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_ID", "env-member");
    write_global_config(&temp_home, "config-member");
    let keystore_root = setup_keystore(&temp_dir, &[]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("env-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_id_priority_config_over_keystore() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_ID"]);
    let temp_dir = TempDir::new().unwrap();
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_ID");
    write_global_config(&temp_home, "config-member");
    let keystore_root = setup_keystore(&temp_dir, &["keystore-member"]);

    let result = call(None, &keystore_root, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}
