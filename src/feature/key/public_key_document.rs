// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key document builders used during key generation.

use crate::crypto::sign::sign_bytes;
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::format::jcs;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::SshError;
use crate::model::identifiers::alg;
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, PublicKey,
};
use crate::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use tracing::debug;

/// Parameters for building a public key.
pub struct PublicKeyBuildParams<'a> {
    pub member_id: &'a str,
    pub kid: &'a str,
    pub identity: Identity,
    pub created_at: &'a str,
    pub expires_at: &'a str,
    pub sig_sk: &'a SigningKey,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
}

/// Build public key with self-signature.
pub fn build_public_key(params: &PublicKeyBuildParams<'_>) -> Result<PublicKey> {
    let protected = PublicKey::new(
        params.member_id.to_string(),
        params.kid.to_string(),
        params.identity.clone(),
        params.github_account.clone().map(|g| BindingClaims {
            github_account: Some(g),
        }),
        params.expires_at.to_string(),
        Some(params.created_at.to_string()),
        String::new(),
    )
    .protected;

    let protected_jcs = jcs::normalize(&protected)?;
    if params.debug {
        debug!("[CRYPTO] Ed25519: sign_bytes (kid: {})", params.kid);
    }
    let signature_obj = sign_bytes(
        &protected_jcs,
        params.sig_sk,
        params.kid,
        None,
        alg::SIGNATURE_ED25519,
    )?;
    let signature = signature_obj.sig;

    Ok(PublicKey {
        protected,
        signature,
    })
}

/// Build attestation for identity keys.
pub fn build_attestation(
    ssh_binding: &SshBindingContext,
    identity_keys: &IdentityKeys,
) -> Result<Attestation> {
    let identity_keys_jcs = jcs::normalize(identity_keys)?;

    let raw_sig = ssh_binding
        .backend
        .sign_for_ikm(&ssh_binding.public_key, &identity_keys_jcs)
        .map_err(|e| {
            crate::Error::from(SshError::operation_failed_with_source(
                format!("Failed to sign attestation: {}", e),
                e,
            ))
        })?;

    let sig_b64url = URL_SAFE_NO_PAD.encode(raw_sig.as_bytes());

    Ok(Attestation {
        method: ssh::ATTESTATION_METHOD_SSH_SIGN.to_string(),
        pub_: ssh_binding.public_key.clone(),
        sig: sig_b64url,
    })
}
