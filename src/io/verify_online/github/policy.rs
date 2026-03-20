// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verification policy helpers for GitHub binding checks.

use super::{matcher::match_key_by_fingerprint, GitHubApi};
use crate::io::verify_online::VerificationResult;
use crate::model::public_key::PublicKey;
use crate::{Error, Result};
use tracing::debug;

pub(super) async fn resolve_github_identity(
    api: &impl GitHubApi,
    login: &str,
    document_id: u64,
    known: &Option<(u64, String)>,
    member_id: &str,
    verbose: bool,
) -> Result<(u64, String)> {
    match known {
        Some((id_known, login_known)) => {
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: using known github id (skip GET /users)",
                    member_id
                );
            }
            Ok((*id_known, login_known.clone()))
        }
        None => resolve_github_identity_from_api(api, login, document_id, member_id, verbose).await,
    }
}

async fn resolve_github_identity_from_api(
    api: &impl GitHubApi,
    login: &str,
    document_id: u64,
    _member_id: &str,
    verbose: bool,
) -> Result<(u64, String)> {
    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/users/{}",
            login
        );
    }

    let (id_from_api, _) = api.fetch_user_by_login(login).await?;
    if verbose {
        debug!(
            "[VERIFY] GitHub API: user id={} (document id={})",
            id_from_api, document_id
        );
    }

    if id_from_api != document_id {
        return Err(Error::Verify {
            rule: "V-GITHUB-API".to_string(),
            message: format!(
                "GitHub user id mismatch: document id {} vs API id {}",
                document_id, id_from_api
            ),
        });
    }

    Ok((id_from_api, login.to_string()))
}

pub(super) async fn fetch_and_match_github_keys(
    api: &impl GitHubApi,
    public_key: &PublicKey,
    our_fingerprint: &str,
    id_used: u64,
    login_for_keys: &str,
    verbose: bool,
) -> Result<VerificationResult> {
    let member_id = &public_key.protected.member_id;

    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/users/{}/keys",
            login_for_keys
        );
    }

    let github_keys = api.fetch_keys(login_for_keys).await?;
    if verbose {
        debug!("[VERIFY] GitHub API: fetched {} key(s)", github_keys.len());
    }

    if github_keys.is_empty() {
        return Ok(VerificationResult::failed(
            member_id,
            format!("No SSH keys found for GitHub user id {}", id_used),
            None,
        ));
    }

    if let Some(result) = match_key_by_fingerprint(
        public_key,
        our_fingerprint,
        &github_keys,
        id_used,
        login_for_keys,
        verbose,
    ) {
        return Ok(result);
    }

    if verbose {
        debug!(
            "[VERIFY] Verify {}: no matching key among {} key(s)",
            member_id,
            github_keys.len()
        );
    }

    Ok(VerificationResult::failed(
        member_id,
        format!(
            "SSH key not found on GitHub (id={}, checked {} keys)",
            id_used,
            github_keys.len()
        ),
        Some(our_fingerprint.to_string()),
    ))
}
