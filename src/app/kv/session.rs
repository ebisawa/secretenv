// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::errors::default_kv_file_not_found_error;
use crate::feature::context::ssh::SshSigningContext;
use crate::feature::kv::{list_kv_keys_with_disclosed, KvWriteContext};
use crate::format::content::KvEncContent;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::fs::load_text;
use crate::support::fs::{atomic, lock};
use crate::{Error, Result};

use super::types::KvWriteOutcome;

pub(crate) struct KvFileTarget {
    pub workspace_root: WorkspaceRoot,
    pub file_path: PathBuf,
}

impl KvFileTarget {
    pub(crate) fn resolve(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let workspace_root = require_workspace(options, "kv access")?;
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

pub(crate) struct KvFileSession {
    pub target: KvFileTarget,
    content: String,
}

impl KvFileSession {
    pub(crate) fn load(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let target = KvFileTarget::resolve(options, file_name)?;
        if !target.file_path.exists() {
            return Err(default_kv_file_not_found_error(&target.file_path));
        }

        let content = load_text(&target.file_path)?;
        Ok(Self { target, content })
    }

    pub(crate) fn content(&self) -> &str {
        &self.content
    }

    pub(crate) fn kv_content(&self) -> KvEncContent {
        KvEncContent::new_unchecked(self.content.clone())
    }
}

pub(crate) struct KvReadSession {
    pub file: KvFileSession,
    pub execution: ExecutionContext,
    pub disclosed: Vec<(String, bool)>,
}

impl KvReadSession {
    pub(crate) fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        file_name: Option<&str>,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<Self> {
        let file = KvFileSession::load(options, file_name)?;
        let execution = ExecutionContext::resolve(options, member_id, None, ssh_ctx)?;
        let disclosed = list_kv_keys_with_disclosed(&file.kv_content())?;
        Ok(Self {
            file,
            execution,
            disclosed,
        })
    }
}

pub(crate) struct KvWriteSession {
    options: CommonCommandOptions,
    member_id: Option<String>,
    target: KvFileTarget,
    allow_missing: bool,
    ssh_ctx: Option<SshSigningContext>,
}

impl KvWriteSession {
    pub(crate) fn new(
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

    pub(crate) fn execute<F>(
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

pub(crate) fn load_existing_content(
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
