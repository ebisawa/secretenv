// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer KV file sessions.

use crate::app::context::{CommonCommandOptions, ExecutionContext, SshSigningContext};
use crate::app::errors::default_kv_file_not_found_error;
use crate::app::errors::handle_kv_key_not_found_error;
use crate::feature::kv::KvWriteContext;
use crate::feature::kv::{
    decrypt_all_kv_values, decrypt_kv_value, list_kv_keys_with_disclosed, set_kv_entry,
    unset_kv_entry,
};
use crate::feature::run::build_env_from_kv_contents;
use crate::format::content::KvEncContent;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::io::workspace::detection::{resolve_workspace, WorkspaceRoot};
use crate::support::fs::load_text;
use crate::support::fs::{atomic, lock};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Resolved KV file target.
struct KvFileTarget {
    workspace_root: WorkspaceRoot,
    file_path: PathBuf,
}

impl KvFileTarget {
    /// Resolve a workspace-scoped KV file target by logical name.
    fn resolve(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let workspace_root = resolve_workspace(options.workspace.clone())?;
        let name = file_name.unwrap_or(DEFAULT_KV_ENC_BASENAME);
        let file_path = workspace_root
            .secrets_dir()
            .join(format!("{name}{KV_ENC_EXTENSION}"));

        Ok(Self {
            workspace_root,
            file_path,
        })
    }
}

/// Loaded KV file session without crypto context.
struct KvFileSession {
    target: KvFileTarget,
    content: String,
}

impl KvFileSession {
    /// Resolve and load an existing KV file.
    fn load(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let target = KvFileTarget::resolve(options, file_name)?;
        if !target.file_path.exists() {
            return Err(default_kv_file_not_found_error(&target.file_path));
        }

        let content = load_text(&target.file_path)?;
        Ok(Self { target, content })
    }

    /// Borrow loaded content.
    fn content(&self) -> &str {
        &self.content
    }

    /// Wrap loaded content as a KV document.
    fn kv_content(&self) -> KvEncContent {
        KvEncContent::new_unchecked(self.content.clone())
    }
}

/// Loaded KV file session with decryption materials.
struct KvReadSession {
    file: KvFileSession,
    execution: ExecutionContext,
}

impl KvReadSession {
    /// Resolve, load, and prepare decryption for an existing KV file.
    fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        file_name: Option<&str>,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<Self> {
        let file = KvFileSession::load(options, file_name)?;
        let execution = ExecutionContext::resolve(options, member_id, None, ssh_ctx)?;
        Ok(Self { file, execution })
    }
}

/// Mutating KV file session with locking and save orchestration.
struct KvWriteSession {
    options: CommonCommandOptions,
    member_id: Option<String>,
    target: KvFileTarget,
    allow_missing: bool,
    ssh_ctx: Option<SshSigningContext>,
}

pub struct KvWriteOutcome {
    pub message: Option<String>,
}

impl KvWriteSession {
    /// Resolve a KV file target for a write workflow.
    fn new(
        options: CommonCommandOptions,
        member_id: Option<String>,
        file_name: Option<&str>,
        allow_missing: bool,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<Self> {
        let target = KvFileTarget::resolve(&options, file_name)?;
        Ok(Self {
            options,
            member_id,
            target,
            allow_missing,
            ssh_ctx,
        })
    }

    /// Execute a write operation under a file lock and save the result atomically.
    fn execute<F>(
        self,
        no_signer_pub: bool,
        success_message: Option<&str>,
        operation: F,
    ) -> Result<KvWriteOutcome>
    where
        F: FnOnce(Option<&KvEncContent>, &KvWriteContext, &KvFileTarget) -> Result<String>,
    {
        let Self {
            options,
            member_id,
            target,
            allow_missing,
            ssh_ctx,
        } = self;
        let file_path = target.file_path.clone();
        lock::with_file_lock(&file_path, move || {
            let execution = ExecutionContext::resolve(&options, member_id, None, ssh_ctx)?;
            let member_id = execution.member_id;
            let write_ctx = KvWriteContext::new(
                &member_id,
                execution.key_ctx,
                no_signer_pub,
                options.verbose,
            );

            let existing_content = load_existing_content(&target, allow_missing)?;
            let encrypted = operation(existing_content.as_ref(), &write_ctx, &target)?;

            atomic::save_text(&target.file_path, &encrypted)?;
            Ok(KvWriteOutcome {
                message: success_message.map(ToOwned::to_owned),
            })
        })
    }
}

fn load_existing_content(
    target: &KvFileTarget,
    allow_missing: bool,
) -> Result<Option<KvEncContent>> {
    if target.file_path.exists() {
        let content = load_text(&target.file_path)?;
        Ok(Some(KvEncContent::new_unchecked(content)))
    } else if allow_missing {
        Ok(None)
    } else {
        Err(Error::Config {
            message: format!("File not found: {}", target.file_path.display()),
        })
    }
}

pub fn list_kv_command(
    options: &CommonCommandOptions,
    file_name: Option<&str>,
) -> Result<Vec<(String, bool)>> {
    let session = KvFileSession::load(options, file_name)?;
    list_kv_keys_with_disclosed(&session.kv_content())
}

pub fn get_kv_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    key: Option<&str>,
    all: bool,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<BTreeMap<String, String>> {
    let session = KvReadSession::load(options, member_id, file_name, ssh_ctx)?;
    let content = session.file.kv_content();

    if all {
        let kv_map = decrypt_all_kv_values(
            &content,
            &session.execution.member_id,
            &session.execution.key_ctx,
            options.verbose,
        )?;
        Ok(kv_map.into_iter().collect())
    } else {
        let key = key.ok_or_else(|| Error::InvalidOperation {
            message: "KEY argument is required (or use --all to get all entries)".to_string(),
        })?;
        let value = decrypt_kv_value(
            &content,
            &session.execution.member_id,
            &session.execution.key_ctx,
            key,
            options.verbose,
        )
        .map_err(|e| handle_kv_key_not_found_error(e, &session.file.target.file_path, key))?;
        Ok(BTreeMap::from([(key.to_string(), value)]))
    }
}

pub fn set_kv_command(
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

pub fn unset_kv_command(
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

pub fn import_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    dotenv_content: &str,
    no_signer_pub: bool,
    success_message: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<(KvWriteOutcome, usize)> {
    validate_dotenv_strict(dotenv_content)?;
    let kv_map = parse_dotenv(dotenv_content)?;
    let entries: Vec<(String, String)> = kv_map.into_iter().collect();
    let entry_count = entries.len();
    let outcome = set_kv_command(
        options,
        member_id,
        file_name,
        entries,
        no_signer_pub,
        success_message,
        ssh_ctx,
    )?;
    Ok((outcome, entry_count))
}

pub fn build_run_env_command(
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
