// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::context::options::CommonCommandOptions;
use crate::app::errors::handle_kv_key_not_found_error;
use crate::feature::context::ssh::SshSigningContext;
use crate::feature::kv::{decrypt_all_kv_values, decrypt_kv_value, list_kv_keys_with_disclosed};
use crate::feature::run::build_env_from_kv_contents;
use crate::{Error, Result};

use super::session::{KvFileSession, KvReadSession};
use super::types::{KvReadMode, KvReadResult};

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
    ssh_ctx: Option<SshSigningContext>,
) -> Result<KvReadResult> {
    let session = KvReadSession::load(options, member_id, file_name, ssh_ctx)?;
    let mode = if all {
        KvReadMode::All
    } else {
        KvReadMode::Single(key.ok_or_else(|| Error::InvalidOperation {
            message: "KEY argument is required (or use --all to get all entries)".to_string(),
        })?)
    };
    read_kv_values(&session, mode, options.verbose)
}

pub(crate) fn build_run_env_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<BTreeMap<String, String>> {
    let session = KvReadSession::load(options, member_id, file_name, ssh_ctx)?;
    let content = session.file.content().to_string();
    build_env_from_kv_contents(
        &[&content],
        &session.execution.member_id,
        &session.execution.key_ctx,
        options.verbose,
    )
}

fn read_kv_values(
    session: &KvReadSession,
    mode: KvReadMode<'_>,
    debug: bool,
) -> Result<KvReadResult> {
    let content = session.file.kv_content();
    let values = match mode {
        KvReadMode::All => decrypt_all_kv_values(
            &content,
            &session.execution.member_id,
            &session.execution.key_ctx,
            debug,
        )?
        .into_iter()
        .collect(),
        KvReadMode::Single(key) => {
            let value = decrypt_kv_value(
                &content,
                &session.execution.member_id,
                &session.execution.key_ctx,
                key,
                debug,
            )
            .map_err(|e| handle_kv_key_not_found_error(e, &session.file.target.file_path, key))?;
            BTreeMap::from([(key.to_string(), value)])
        }
    };
    Ok(KvReadResult {
        values,
        disclosed: session.disclosed.clone(),
    })
}
