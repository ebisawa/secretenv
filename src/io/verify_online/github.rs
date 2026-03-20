// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub verification logic
//!
//! Verification uses binding_claims.github_account (login, id): GET /users/{login} to verify id
//! match, then GET /users/{login}/keys. REST only, no authentication required.

use crate::model::public_key::PublicKey;
use crate::Result;
use std::future::Future;
use std::pin::Pin;
use tracing::debug;

use self::http::{build_http_client, fetch_github_keys, fetch_github_user_by_login};
use self::matcher::compute_attestation_fingerprint;
use self::policy::{fetch_and_match_github_keys, resolve_github_identity};
use super::VerificationResult;

mod http;
mod matcher;
mod policy;

/// SSH key metadata fetched from GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubKeyRecord {
    pub id: i64,
    pub key: String,
}

/// Boxed future used by GitHub API abstractions.
pub type GitHubApiFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Injectable GitHub API interface used by verification flows.
pub trait GitHubApi {
    fn fetch_user_by_login<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, (u64, String)>;
    fn fetch_keys<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>>;
}

struct GitHubApiClient {
    client: reqwest::Client,
}

impl GitHubApiClient {
    fn new() -> Result<Self> {
        Ok(Self {
            client: build_http_client()?,
        })
    }
}

impl GitHubApi for GitHubApiClient {
    fn fetch_user_by_login<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async move { fetch_github_user_by_login(&self.client, login).await })
    }

    fn fetch_keys<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move { fetch_github_keys(&self.client, login).await })
    }
}

/// Resolve GitHub username (login) to (id, login) via REST API.
/// Used by key new --github-user to populate binding_claims.github_account.
pub async fn resolve_github_id_by_username(login: &str, verbose: bool) -> Result<(u64, String)> {
    let api = GitHubApiClient::new()?;
    resolve_github_id_by_username_with_api(login, verbose, &api).await
}

/// Resolve GitHub username (login) via an injected API implementation.
pub async fn resolve_github_id_by_username_with_api(
    login: &str,
    verbose: bool,
    api: &impl GitHubApi,
) -> Result<(u64, String)> {
    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/users/{}",
            login
        );
    }
    let (id, login_str) = api.fetch_user_by_login(login).await?;
    if verbose {
        debug!("[VERIFY] GitHub API: user id={}, login={}", id, login_str);
    }
    Ok((id, login_str))
}

/// Verify a PublicKey's binding_claims.github_account against GitHub using REST only (login -> id match, then keys).
/// When `known_github_account` is `Some((id, login))`, skips GET /users/{login} and uses the given (id, login) for keys fetch.
pub async fn verify_github_account(
    public_key: &PublicKey,
    verbose: bool,
    known_github_account: Option<(u64, String)>,
) -> Result<VerificationResult> {
    let api = GitHubApiClient::new()?;
    verify_github_account_with_api(public_key, verbose, known_github_account, &api).await
}

/// Verify a PublicKey's GitHub binding using an injected API implementation.
pub async fn verify_github_account_with_api(
    public_key: &PublicKey,
    verbose: bool,
    known_github_account: Option<(u64, String)>,
    api: &impl GitHubApi,
) -> Result<VerificationResult> {
    let member_id = &public_key.protected.member_id;
    let github = match public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|b| b.github_account.as_ref())
    {
        Some(b) => b,
        None => {
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: no binding_claims.github_account configured (skipped)",
                    member_id
                );
            }
            let fingerprint = compute_attestation_fingerprint(public_key, verbose);
            return Ok(VerificationResult::not_configured(
                member_id,
                "No binding_claims.github_account configured",
                fingerprint,
            ));
        }
    };

    let our_fingerprint = match compute_attestation_fingerprint(public_key, verbose) {
        Some(fp) => fp,
        None => {
            return Ok(VerificationResult::not_configured(
                member_id,
                "Invalid attestation.pub (cannot compute fingerprint)",
                None,
            ));
        }
    };

    let (id_used, login_for_keys) = resolve_github_identity(
        api,
        &github.login,
        github.id,
        &known_github_account,
        member_id,
        verbose,
    )
    .await?;

    fetch_and_match_github_keys(
        api,
        public_key,
        &our_fingerprint,
        id_used,
        &login_for_keys,
        verbose,
    )
    .await
}
