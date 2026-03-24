// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for cli::identity_prompt::select_ssh_key

use secretenv::app::context::ssh::SshKeyCandidateView;
use secretenv::cli::identity_prompt::select_ssh_key;

#[test]
fn test_select_ssh_key_empty_candidates_fails() {
    let candidates: Vec<SshKeyCandidateView> = vec![];
    let result = select_ssh_key(&candidates);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("No ssh-ed25519 key found"),
        "unexpected error: {err_msg}"
    );
}

#[test]
fn test_select_ssh_key_single_candidate_returns_zero() {
    let candidates = vec![SshKeyCandidateView {
        public_key: "ssh-ed25519 AAAA test@host".to_string(),
        fingerprint: "SHA256:abc123".to_string(),
        comment: "test@host".to_string(),
    }];
    let result = select_ssh_key(&candidates);
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_select_ssh_key_multiple_candidates_non_tty_fails() {
    // Skip when running in an interactive terminal
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }

    let candidates = vec![
        SshKeyCandidateView {
            public_key: "ssh-ed25519 AAAA test@host".to_string(),
            fingerprint: "SHA256:abc123".to_string(),
            comment: "test@host".to_string(),
        },
        SshKeyCandidateView {
            public_key: "ssh-ed25519 BBBB work@host".to_string(),
            fingerprint: "SHA256:def456".to_string(),
            comment: "work@host".to_string(),
        },
    ];
    let result = select_ssh_key(&candidates);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Multiple Ed25519 keys found"),
        "unexpected error: {err_msg}"
    );
}
