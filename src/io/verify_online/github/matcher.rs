// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fingerprint matching helpers for GitHub verification.

use super::GitHubKeyRecord;
use crate::io::ssh::protocol::fingerprint;
use crate::io::verify_online::VerificationResult;
use crate::model::public_key::{PublicKey, VerifiedBindingClaims};
use crate::model::verification::BindingVerificationProof;
use tracing::debug;

pub(super) fn compute_attestation_fingerprint(
    public_key: &PublicKey,
    verbose: bool,
) -> Option<String> {
    let member_id = &public_key.protected.member_id;
    if verbose {
        debug!(
            "[VERIFY] Verify {}: computing fingerprint from attestation.pub",
            member_id
        );
    }

    match fingerprint::build_sha256_fingerprint(&public_key.protected.identity.attestation.pub_) {
        Ok(fingerprint) => {
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: attestation fingerprint {}",
                    member_id, fingerprint
                );
            }
            Some(fingerprint)
        }
        Err(_) => {
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: failed to compute fingerprint",
                    member_id
                );
            }
            None
        }
    }
}

pub(super) fn match_key_by_fingerprint(
    public_key: &PublicKey,
    our_fingerprint: &str,
    github_keys: &[GitHubKeyRecord],
    id_used: u64,
    login_for_keys: &str,
    verbose: bool,
) -> Option<VerificationResult> {
    let member_id = &public_key.protected.member_id;

    for github_key in github_keys {
        let Ok(github_fingerprint) = fingerprint::build_sha256_fingerprint(&github_key.key) else {
            continue;
        };
        if github_fingerprint != our_fingerprint {
            continue;
        }

        if verbose {
            debug!(
                "[VERIFY] Verify {}: fingerprint match (GitHub key id={})",
                member_id, github_key.id
            );
        }
        let verified_bindings =
            build_verified_bindings(public_key, our_fingerprint, github_key.id)?;
        return Some(VerificationResult::verified(
            member_id,
            format!(
                "SSH key verified on GitHub (id={}, login={})",
                id_used, login_for_keys
            ),
            our_fingerprint.to_string(),
            github_key.id,
            verified_bindings,
        ));
    }

    None
}

fn build_verified_bindings(
    public_key: &PublicKey,
    fingerprint: &str,
    matched_key_id: i64,
) -> Option<VerifiedBindingClaims> {
    let claims = public_key.protected.binding_claims.clone()?;
    let proof = BindingVerificationProof::new(
        "github".to_string(),
        Some(fingerprint.to_string()),
        Some(matched_key_id),
    );
    Some(VerifiedBindingClaims::new(claims, proof))
}
