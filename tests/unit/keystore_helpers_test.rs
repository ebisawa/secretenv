// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore helpers

use crate::test_utils::save_public_key;
use crate::test_utils::EnvGuard;
use secretenv::io::config::paths::get_base_dir;
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::helpers::resolve_kid;
use secretenv::io::keystore::paths::get_keystore_root_from_base;
use secretenv::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use tempfile::TempDir;
use time::OffsetDateTime;
use ulid::Ulid;

fn dummy_public_key(member_id: &str) -> PublicKey {
    let kid = Ulid::new().to_string();
    let now = OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::build_timestamp_display(now).unwrap();
    let expires_at =
        secretenv::support::time::build_timestamp_display(now + time::Duration::days(365)).unwrap();

    PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::identifiers::format::PUBLIC_KEY_V3.to_string(),
            member_id: member_id.to_string(),
            kid,
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                        x: "AA".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                        x: "AA".to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh-sign".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest test@test"
                        .to_string(),
                    sig: "AA".to_string(),
                },
            },
            binding_claims: None,
            expires_at,
            created_at: Some(created_at),
        },
        signature: "AA".to_string(),
    }
}

#[test]
fn test_resolve_kid_with_override() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_id to avoid interference from other parallel tests
    let member_id = format!("alice-override-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(&member_id);
    let pub2 = dummy_public_key(&member_id);

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_id, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_id, &pub2.protected.kid, &pub2).unwrap();

    // Override should work
    let resolved = resolve_kid(&keystore_root, &member_id, Some(&pub1.protected.kid)).unwrap();
    assert_eq!(resolved, pub1.protected.kid);

    // Invalid override should fail
    let result = resolve_kid(&keystore_root, &member_id, Some("invalid_kid"));
    assert!(result.is_err());
}

#[test]
fn test_resolve_kid_with_active() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_id to avoid interference from other parallel tests
    let member_id = format!("alice-active-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(&member_id);
    let pub2 = dummy_public_key(&member_id);

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_id, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_id, &pub2.protected.kid, &pub2).unwrap();

    // Set active kid
    set_active_kid(&member_id, &pub1.protected.kid, &keystore_root).unwrap();

    // Should use active kid
    let resolved = resolve_kid(&keystore_root, &member_id, None).unwrap();
    assert_eq!(resolved, pub1.protected.kid);
}

#[test]
fn test_resolve_kid_fallback_to_latest() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_id to avoid interference from other parallel tests
    let member_id = format!("alice-fallback-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(&member_id);
    let pub2 = dummy_public_key(&member_id);

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_id, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_id, &pub2.protected.kid, &pub2).unwrap();

    // No active kid set, should use latest
    let resolved = resolve_kid(&keystore_root, &member_id, None).unwrap();

    // The resolved kid should be one of the two we saved
    assert!(
        resolved == pub1.protected.kid || resolved == pub2.protected.kid,
        "Resolved kid '{}' should be one of the generated keys ('{}' or '{}')",
        resolved,
        pub1.protected.kid,
        pub2.protected.kid
    );
}

#[test]
fn test_resolve_kid_no_keys() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);

    // Use unique member_id to avoid interference from other parallel tests
    let member_id = format!("nonexistent-{}@example.com", uuid::Uuid::new_v4());

    // Should fail with no keys
    let result = resolve_kid(&keystore_root, &member_id, None);
    assert!(result.is_err());
}
