// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::verify_online::github::preflight::verify_ssh_key_on_github;
use crate::io::verify_online::github::resolve_github_id_by_username;
use crate::io::verify_online::VerificationStatus;
use crate::model::public_key::GithubAccount;
use crate::support::runtime::block_on_result;
use crate::Result;

pub(crate) fn resolve_github_account(
    github_user: Option<String>,
    verbose: bool,
) -> Result<Option<GithubAccount>> {
    let Some(login) = github_user else {
        return Ok(None);
    };

    let (id, login) = block_on_result(resolve_github_id_by_username(&login, verbose))?;
    Ok(Some(GithubAccount { id, login }))
}

/// Verify SSH public key is registered on GitHub before key generation.
pub(crate) fn verify_preflight_github_binding(
    ssh_pub_key: &str,
    account: &GithubAccount,
    verbose: bool,
) -> Result<VerificationStatus> {
    let status = block_on_result(verify_ssh_key_on_github(ssh_pub_key, account, verbose))?;
    Ok(status)
}
