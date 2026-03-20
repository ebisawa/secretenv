// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::verify_online::github::{resolve_github_id_by_username, verify_github_account};
use crate::io::verify_online::VerificationStatus;
use crate::model::public_key::{GithubAccount, PublicKey};
use crate::support::runtime::run_blocking_result;
use crate::{Error, Result};

pub(crate) fn resolve_github_account(
    github_user: Option<String>,
    verbose: bool,
) -> Result<Option<GithubAccount>> {
    let Some(login) = github_user else {
        return Ok(None);
    };

    let (id, login) = run_blocking_result(resolve_github_id_by_username(&login, verbose))?;
    Ok(Some(GithubAccount { id, login }))
}

pub(crate) fn verify_generated_key_github_binding(
    public_key: &PublicKey,
    github_account: Option<&GithubAccount>,
    verbose: bool,
) -> Result<VerificationStatus> {
    let Some(account) = github_account else {
        return Ok(VerificationStatus::NotConfigured);
    };

    let result = run_blocking_result(verify_github_account(
        public_key,
        verbose,
        Some((account.id, account.login.clone())),
    ))?;
    if !result.is_verified() {
        return Err(Error::Verify {
            rule: "V-GITHUB-KEY-NEW".to_string(),
            message: result.message,
        });
    }

    Ok(VerificationStatus::Verified)
}
