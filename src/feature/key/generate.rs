// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation logic.

use super::KeyNewResult;
use crate::feature::context::ssh::SshSigningContext;
pub use crate::feature::key::material::{build_identity_keys, generate_keypairs};
use crate::feature::key::protection::{self, PrivateKeyEncryptionParams};
pub use crate::feature::key::public_key_document::{build_public_key, PublicKeyBuildParams};
use crate::feature::key::{material, public_key_document};
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::save_key_pair_atomic;
use crate::model::private_key::PrivateKey;
use crate::model::public_key::{GithubAccount, Identity, PublicKey};
use crate::model::ssh::SshDeterminismStatus;
use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Options for key generation.
pub struct KeyGenerationOptions {
    pub member_id: String,
    pub home: Option<PathBuf>,
    pub created_at: String,
    pub expires_at: String,
    pub no_activate: bool,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
    pub verbose: bool,
    /// Pre-resolved SSH signing context.
    pub ssh_context: SshSigningContext,
}

/// Generate a new key pair and save to keystore.
pub fn generate_key(opts: KeyGenerationOptions) -> Result<KeyNewResult> {
    let KeyGenerationOptions {
        member_id,
        home,
        created_at,
        expires_at,
        no_activate,
        debug,
        github_account,
        verbose: _,
        ssh_context,
    } = opts;

    let keystore_root = ensure_keystore_dir(&home)?;
    ensure_determinism(&ssh_context.determinism)?;
    let (kid, kem_sk, kem_pk, sig_sk, sig_pk) = material::generate_keypairs()?;

    let identity_keys = material::build_identity_keys(&kem_pk, &sig_pk)?;
    let attestation = public_key_document::build_attestation(&ssh_context, &identity_keys)?;
    let public_key = build_public_key_document(
        &member_id,
        &kid,
        identity_keys,
        attestation,
        &created_at,
        &expires_at,
        &sig_sk,
        debug,
        github_account,
    )?;

    let private_key = encrypt_private_key_document(
        &kem_sk,
        &kem_pk,
        &sig_sk,
        &sig_pk,
        &member_id,
        &kid,
        &ssh_context,
        &created_at,
        &expires_at,
        debug,
    )?;

    save_and_activate(
        &keystore_root,
        &member_id,
        &kid,
        &private_key,
        &public_key,
        no_activate,
    )?;

    let key_dir = keystore_root.join(&member_id).join(&kid);
    Ok(KeyNewResult {
        member_id,
        kid,
        created_at,
        expires_at,
        keystore_root,
        key_dir,
        activated: !no_activate,
        ssh_fingerprint: ssh_context.fingerprint,
        ssh_public_key: ssh_context.public_key,
        ssh_determinism: ssh_context.determinism,
    })
}

fn ensure_determinism(status: &SshDeterminismStatus) -> Result<()> {
    if let SshDeterminismStatus::Failed { message } = status {
        return Err(crate::Error::Crypto {
            message: message.clone(),
            source: None,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_public_key_document(
    member_id: &str,
    kid: &str,
    identity_keys: crate::model::public_key::IdentityKeys,
    attestation: crate::model::public_key::Attestation,
    created_at: &str,
    expires_at: &str,
    sig_sk: &SigningKey,
    debug: bool,
    github_account: Option<GithubAccount>,
) -> Result<PublicKey> {
    let identity = Identity {
        keys: identity_keys,
        attestation,
    };
    public_key_document::build_public_key(&public_key_document::PublicKeyBuildParams {
        member_id,
        kid,
        identity,
        created_at,
        expires_at,
        sig_sk,
        debug,
        github_account,
    })
}

#[allow(clippy::too_many_arguments)]
fn encrypt_private_key_document(
    kem_sk: &X25519SecretKey,
    kem_pk: &X25519PublicKey,
    sig_sk: &SigningKey,
    sig_pk: &VerifyingKey,
    member_id: &str,
    kid: &str,
    ssh_context: &SshSigningContext,
    created_at: &str,
    expires_at: &str,
    debug: bool,
) -> Result<PrivateKey> {
    let plaintext = material::build_private_key_plaintext(kem_sk, kem_pk, sig_sk, sig_pk);
    protection::encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        backend: ssh_context.backend.as_ref(),
        ssh_pubkey: &ssh_context.public_key,
        ssh_fpr: ssh_context.fingerprint.clone(),
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
        debug,
    })
}

/// Ensure keystore directory exists.
pub(crate) fn ensure_keystore_dir(home: &Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::resolve_and_ensure(home.as_ref())
}

/// Save and activate key.
pub(crate) fn save_and_activate(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    no_activate: bool,
) -> Result<()> {
    save_key_pair_atomic(keystore_root, member_id, kid, private_key, public_key)?;
    if !no_activate {
        set_active_kid(member_id, kid, keystore_root)?;
    }
    Ok(())
}
