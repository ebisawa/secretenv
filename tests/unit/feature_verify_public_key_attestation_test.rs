// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::create_temp_ssh_keypair_in_dir;
use secretenv::config::types::SshSigner;
use secretenv::feature::key::generate::{generate_key, KeyGenerationOptions};
use secretenv::feature::verify::public_key::verify_public_key_with_attestation;
use secretenv::io::keystore::storage::load_public_key;
use serial_test::serial;
use tempfile::TempDir;

const MAX_KEYGEN_ATTEMPTS: usize = 3;

fn generate_real_ssh_attested_public_key(
    temp_dir: &TempDir,
) -> secretenv::model::public_key::PublicKey {
    let (ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair_in_dir(temp_dir);
    let home_dir = temp_dir.path().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();

    let result = retry_on_nondeterministic(MAX_KEYGEN_ATTEMPTS, || {
        generate_key(KeyGenerationOptions {
            member_id: "attestation-test@example.com".to_string(),
            home: Some(home_dir.clone()),
            ssh_key: Some(ssh_priv.clone()),
            ssh_signer: Some(SshSigner::SshKeygen),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-12-31T23:59:59Z".to_string(),
            no_activate: false,
            debug: false,
            github_account: None,
            verbose: false,
        })
    });

    load_public_key(
        &home_dir.join("keys"),
        "attestation-test@example.com",
        &result.kid,
    )
    .unwrap()
}

fn retry_on_nondeterministic<T>(
    max_attempts: usize,
    mut f: impl FnMut() -> secretenv::Result<T>,
) -> T {
    for attempt in 1..=max_attempts {
        match f() {
            Ok(v) => return v,
            Err(e) if e.to_string().contains("W_SSH_NONDETERMINISTIC") => {
                if attempt == max_attempts {
                    panic!(
                        "failed after {max_attempts} attempts due to non-deterministic SSH signatures: {e}"
                    );
                }
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    unreachable!()
}

#[test]
fn generated_public_key_verifies_with_attestation() {
    let temp_dir = TempDir::new().unwrap();
    let public_key = generate_real_ssh_attested_public_key(&temp_dir);
    verify_public_key_with_attestation(&public_key, false).unwrap();
}

#[test]
#[serial]
fn generated_public_key_verifies_with_attestation_repeatedly() {
    for _ in 0..5 {
        let temp_dir = TempDir::new().unwrap();
        let public_key = generate_real_ssh_attested_public_key(&temp_dir);
        verify_public_key_with_attestation(&public_key, false).unwrap();
    }
}
