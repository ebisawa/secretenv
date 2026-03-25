// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use secretenv::app::context::options::CommonCommandOptions;
use secretenv::app::context::ssh::resolve_ssh_context_by_active_key;
use tempfile::TempDir;

#[test]
fn test_resolve_ssh_context_by_active_key_honors_member_id_option() {
    let base_dir = TempDir::new().unwrap();

    // Create a keystore with multiple member directories.
    // This would normally require --member-id (or config/env) to disambiguate.
    let keys_dir = base_dir.path().join("keys");
    fs::create_dir_all(keys_dir.join("alice@example.com")).unwrap();
    fs::create_dir_all(keys_dir.join("bob@example.com")).unwrap();

    let options = CommonCommandOptions {
        home: Some(base_dir.path().to_path_buf()),
        identity: None,
        quiet: true,
        verbose: false,
        workspace: None,
        ssh_signer: None,
    };

    // With explicit member_id, we should not get the "multiple member_ids found" config error.
    // It will still fail later because no active key exists for that member, which is expected.
    let err =
        match resolve_ssh_context_by_active_key(&options, Some("alice@example.com".to_string())) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
    let msg = format!("{err}");
    assert!(
        msg.contains("No active key for member"),
        "unexpected error: {msg}"
    );
}
