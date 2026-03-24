// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::identity::resolve_member_id_with_fallback;
use crate::io::keystore::storage;
use crate::{Error, Result};

pub(crate) struct ResolvedKeyIdentity {
    pub member_id: String,
}

pub(crate) fn resolve_required_key_identity(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<ResolvedKeyIdentity> {
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = require_member_id(resolve_member_id_with_fallback(
        member_id,
        &keystore_root,
        options.home.as_deref(),
    )?)?;
    Ok(ResolvedKeyIdentity { member_id })
}

pub(crate) fn resolve_member_id_for_removal(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: &str,
) -> Result<String> {
    let keystore_root = options.resolve_keystore_root()?;
    match resolve_member_id_with_fallback(
        member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    ) {
        Ok(Some(member_id)) => Ok(member_id),
        Ok(None) if member_id.is_none() => storage::find_member_by_kid(&keystore_root, kid),
        Ok(None) => Err(missing_member_id_error()),
        Err(error) => Err(error),
    }
}

fn require_member_id(member_id: Option<String>) -> Result<String> {
    member_id.ok_or_else(missing_member_id_error)
}

fn missing_member_id_error() -> Error {
    Error::Config {
        message: "member_id is required but could not be determined.\n\
                  Options:\n\
                  1. Specify --member-id <id>\n\
                  2. Set environment variable: export SECRETENV_MEMBER_ID=<id>\n\
                  3. Set in config: secretenv config set member_id <id>"
            .to_string(),
    }
}
