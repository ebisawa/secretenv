// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::errors::handle_kv_key_not_found_error;
use crate::feature::context::ssh::SshSigningContext;
use crate::feature::kv::{set_kv_entry, unset_kv_entry};
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::{Error, Result};

use super::session::KvWriteSession;
use super::types::{KvImportResult, KvWriteOutcome};

pub(crate) fn set_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    entries: Vec<(String, String)>,
    no_signer_pub: bool,
    success_message: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<KvWriteOutcome> {
    let session = KvWriteSession::new(options, member_id, file_name, true, ssh_ctx)?;
    session.execute(
        no_signer_pub,
        success_message,
        |existing_content, ctx, target| {
            let result = set_kv_entry(
                existing_content,
                &entries,
                target.workspace_root.root_path.as_path(),
                ctx,
            )?;
            Ok(result.encrypted.as_str().to_owned())
        },
    )
}

pub(crate) fn unset_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    key: &str,
    no_signer_pub: bool,
    success_message: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<KvWriteOutcome> {
    let session = KvWriteSession::new(options, member_id, file_name, false, ssh_ctx)?;
    session.execute(
        no_signer_pub,
        success_message,
        |existing_content, ctx, target| {
            let kv_content = existing_content.ok_or_else(|| Error::Config {
                message: "File content is required".to_string(),
            })?;
            unset_kv_entry(kv_content, key, ctx)
                .map_err(|e| handle_kv_key_not_found_error(e, &target.file_path, key))
        },
    )
}

pub(crate) fn import_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    dotenv_content: &str,
    no_signer_pub: bool,
    success_message: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<(KvWriteOutcome, usize)> {
    let result = import_kv_command_result(
        options,
        member_id,
        file_name,
        dotenv_content,
        no_signer_pub,
        success_message,
        ssh_ctx,
    )?;
    Ok((result.write_outcome, result.entry_count))
}

pub(crate) fn import_kv_command_result(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    dotenv_content: &str,
    no_signer_pub: bool,
    success_message: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<KvImportResult> {
    validate_dotenv_strict(dotenv_content)?;
    let kv_map = parse_dotenv(dotenv_content)?;
    let entries: Vec<(String, String)> = kv_map.into_iter().collect();
    let entry_count = entries.len();
    let write_outcome = set_kv_command(
        options,
        member_id,
        file_name,
        entries,
        no_signer_pub,
        success_message,
        ssh_ctx,
    )?;
    Ok(KvImportResult {
        write_outcome,
        entry_count,
    })
}
