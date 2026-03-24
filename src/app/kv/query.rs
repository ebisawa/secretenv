// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use tracing::warn;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::errors::handle_kv_key_not_found_error;
use crate::feature::context::expiry::build_key_expiry_warning;
use crate::feature::kv::query::{
    decrypt_all_kv_values, decrypt_kv_value, list_kv_keys_with_disclosed,
};
use crate::feature::run::build_env_from_kv_contents;
use crate::{Error, Result};

use super::session::KvFileSession;
use super::types::{KvReadMode, KvReadResult};

struct ResolvedKvQuery {
    file: KvFileSession,
    execution: ExecutionContext,
}

pub(crate) fn list_kv_command(
    options: &CommonCommandOptions,
    file_name: Option<&str>,
) -> Result<Vec<(String, bool)>> {
    let session = KvFileSession::load(options, file_name)?;
    list_kv_keys_with_disclosed(&session.kv_content())
}

pub(crate) fn get_kv_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    key: Option<&str>,
    all: bool,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<KvReadResult> {
    let resolved = resolve_kv_query(options, member_id, file_name, ssh_ctx)?;
    let disclosed = list_kv_keys_with_disclosed(&resolved.file.kv_content())?;
    let mode = if all {
        KvReadMode::All
    } else {
        KvReadMode::Single(key.ok_or_else(|| Error::InvalidOperation {
            message: "KEY argument is required (or use --all to get all entries)".to_string(),
        })?)
    };
    load_kv_values(
        &resolved.file,
        &resolved.execution,
        &disclosed,
        mode,
        options.verbose,
    )
}

pub(crate) fn build_run_env_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<BTreeMap<String, String>> {
    let resolved = resolve_kv_query(options, member_id, file_name, ssh_ctx)?;
    let content = resolved.file.content().to_string();
    build_env_from_kv_contents(
        &[&content],
        &resolved.execution.member_id,
        &resolved.execution.key_ctx,
        options.verbose,
    )
}

fn resolve_kv_query(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<ResolvedKvQuery> {
    let file = KvFileSession::load(options, file_name)?;
    let execution = ExecutionContext::resolve(options, member_id, None, ssh_ctx)?;
    if let Some(warning) = build_key_expiry_warning(&execution.key_ctx.expires_at)? {
        warn!("{}", warning);
    }
    Ok(ResolvedKvQuery { file, execution })
}

fn load_kv_values(
    file: &KvFileSession,
    execution: &ExecutionContext,
    disclosed: &[(String, bool)],
    mode: KvReadMode<'_>,
    debug: bool,
) -> Result<KvReadResult> {
    let content = file.kv_content();
    let values = match mode {
        KvReadMode::All => {
            decrypt_all_kv_values(&content, &execution.member_id, &execution.key_ctx, debug)?
                .into_iter()
                .collect()
        }
        KvReadMode::Single(key) => {
            let value = decrypt_kv_value(
                &content,
                &execution.member_id,
                &execution.key_ctx,
                key,
                debug,
            )
            .map_err(|e| handle_kv_key_not_found_error(e, &file.target.file_path, key))?;
            BTreeMap::from([(key.to_string(), value)])
        }
    };
    Ok(KvReadResult {
        values,
        disclosed: disclosed.to_vec(),
    })
}
