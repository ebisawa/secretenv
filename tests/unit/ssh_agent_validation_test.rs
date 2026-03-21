// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH agent validation - key matching logic

use secretenv::io::ssh::agent::validation::find_key_in_agent;
use ssh_agent_client_rs::Identity;
use ssh_key::PublicKey;

const ED25519_KEY_NO_COMMENT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT";

const ED25519_KEY_WITH_COMMENT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-key-1";

const ED25519_OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM4In5W7fTd0kSImZziZtVYeU8IuJFGh2zSPQSH9kc1f test-key-2";

#[test]
fn test_find_key_matches_same_key_with_different_comments() {
    let key_no_comment = PublicKey::from_openssh(ED25519_KEY_NO_COMMENT).unwrap();
    let key_with_comment = PublicKey::from_openssh(ED25519_KEY_WITH_COMMENT).unwrap();

    let identities = vec![Identity::from(key_with_comment)];
    let result = find_key_in_agent(&identities, &key_no_comment).unwrap();
    assert!(result, "key should match regardless of comment difference");
}

#[test]
fn test_find_key_matches_identical_keys() {
    let key1 = PublicKey::from_openssh(ED25519_KEY_WITH_COMMENT).unwrap();
    let key2 = PublicKey::from_openssh(ED25519_KEY_WITH_COMMENT).unwrap();

    let identities = vec![Identity::from(key1)];
    let result = find_key_in_agent(&identities, &key2).unwrap();
    assert!(result);
}

#[test]
fn test_find_key_no_match_different_key() {
    let agent_key = PublicKey::from_openssh(ED25519_OTHER_KEY).unwrap();
    let target_key = PublicKey::from_openssh(ED25519_KEY_NO_COMMENT).unwrap();

    let identities = vec![Identity::from(agent_key)];
    let result = find_key_in_agent(&identities, &target_key).unwrap();
    assert!(!result);
}

#[test]
fn test_find_key_empty_identities() {
    let target_key = PublicKey::from_openssh(ED25519_KEY_NO_COMMENT).unwrap();
    let identities: Vec<Identity> = vec![];
    let result = find_key_in_agent(&identities, &target_key).unwrap();
    assert!(!result);
}
