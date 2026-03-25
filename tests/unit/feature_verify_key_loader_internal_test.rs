use super::*;
use crate::feature::key::material::{build_identity_keys, generate_keypairs};
use crate::feature::key::public_key_document::{
    build_attestation, build_public_key, PublicKeyBuildParams,
};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
use crate::model::public_key::{Identity, PublicKey};
use crate::model::ssh::SshDeterminismStatus;
use crate::model::verification::VerifyingKeySource;
use std::path::Path;

/// Build SSH binding context from test SSH keypair
fn build_test_ssh_context(ssh_key_path: &Path, ssh_pubkey: &str) -> SshBindingContext {
    let fingerprint = build_sha256_fingerprint(ssh_pubkey).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path.to_path_buf()),
    ));
    SshBindingContext {
        public_key: ssh_pubkey.to_string(),
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Verified,
    }
}

/// Create a temp SSH keypair and return (private_key_path, public_key_content)
fn create_ssh_keypair() -> (tempfile::TempDir, std::path::PathBuf, String) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let ssh_dir = temp_dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let private_key_path = ssh_dir.join("test_ed25519");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&private_key_path)
        .args(["-N", "", "-C", "test@example.com"])
        .output()
        .expect("Failed to generate SSH keypair");
    let public_key_content = std::fs::read_to_string(ssh_dir.join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    (temp_dir, private_key_path, public_key_content)
}

fn create_test_public_key(expires_at: &str) -> (PublicKey, String) {
    let (ssh_temp, ssh_priv, ssh_pub_content) = create_ssh_keypair();
    let ssh_context = build_test_ssh_context(&ssh_priv, &ssh_pub_content);

    let (_kem_sk, kem_pk, sig_sk, sig_pk) = generate_keypairs().unwrap();
    let identity_keys = build_identity_keys(&kem_pk, &sig_pk).unwrap();
    let attestation = build_attestation(&ssh_context, &identity_keys).unwrap();
    let identity = Identity {
        keys: identity_keys,
        attestation,
    };
    let params = PublicKeyBuildParams {
        member_id: "test@example.com",
        identity,
        created_at: "2026-01-01T00:00:00Z",
        expires_at,
        sig_sk: &sig_sk,
        debug: false,
        github_account: None,
    };
    let public_key = build_public_key(&params).unwrap();
    // Keep ssh_temp alive until public_key is built
    drop(ssh_temp);
    let kid = public_key.protected.kid.clone();
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
