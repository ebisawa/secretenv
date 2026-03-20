use super::*;
use crate::feature::key::generate::{build_identity_keys, build_public_key, generate_keypairs};
use crate::model::public_key::{Attestation, Identity};
use crate::model::verification::VerifyingKeySource;

fn create_test_public_key(expires_at: &str) -> (PublicKey, String) {
    let (kid, _kem_sk, kem_pk, sig_sk, sig_pk) = generate_keypairs().unwrap();
    let identity_keys = build_identity_keys(&kem_pk, &sig_pk).unwrap();
    let identity = Identity {
        keys: identity_keys,
        attestation: Attestation {
            method: "test".to_string(),
            pub_: String::new(),
            sig: String::new(),
        },
    };
    let params = crate::feature::key::generate::PublicKeyBuildParams {
        member_id: "test@example.com",
        kid: &kid,
        identity,
        created_at: "2026-01-01T00:00:00Z",
        expires_at,
        sig_sk: &sig_sk,
        debug: false,
        github_account: None,
    };
    let public_key = build_public_key(&params).unwrap();
    (public_key, kid)
}

#[test]
fn expired_key_returns_error_for_signing() {
    let (public_key, _kid) = create_test_public_key("2020-01-01T00:00:00Z");
    let result = check_key_expiry_for_signing(&public_key);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired"),
        "Error should mention expiry: {}",
        err_msg
    );
}

#[test]
fn expired_key_returns_warning_for_verification() {
    let (public_key, _kid) = create_test_public_key("2020-01-01T00:00:00Z");
    let result = check_key_expiry_for_verification(&public_key).unwrap();
    assert!(result.is_some(), "Should return a warning for expired key");
    assert!(result.unwrap().contains("expired"));
}

#[test]
fn valid_key_passes_expiry_check() {
    let (public_key, _kid) = create_test_public_key("2099-12-31T23:59:59Z");
    assert!(check_key_expiry_for_signing(&public_key).is_ok());
    assert!(check_key_expiry_for_verification(&public_key)
        .unwrap()
        .is_none());
}

#[test]
fn empty_expires_at_passes() {
    let (mut public_key, _kid) = create_test_public_key("2099-12-31T23:59:59Z");
    public_key.protected.expires_at = String::new();
    assert!(check_key_expiry_for_signing(&public_key).is_ok());
    assert!(check_key_expiry_for_verification(&public_key)
        .unwrap()
        .is_none());
}

#[test]
fn valid_key_with_test_attestation_passes_verification() {
    let (public_key, kid) = create_test_public_key("2099-12-31T23:59:59Z");
    let result = build_loaded_verifying_key(
        &public_key,
        &kid,
        VerifyingKeySource::SignerPubEmbedded,
        "test",
        false,
    );
    assert!(result.is_ok());
    let loaded = result.unwrap();
    assert!(loaded.warnings.is_empty());
}

#[test]
fn expired_key_with_test_attestation_returns_warning() {
    let (public_key, kid) = create_test_public_key("2020-01-01T00:00:00Z");
    let result = build_loaded_verifying_key(
        &public_key,
        &kid,
        VerifyingKeySource::SignerPubEmbedded,
        "test",
        false,
    );
    assert!(result.is_ok());
    let loaded = result.unwrap();
    assert!(!loaded.warnings.is_empty());
    assert!(loaded.warnings[0].contains("expired"));
}
