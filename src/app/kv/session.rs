// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::errors::default_kv_file_not_found_error;
use crate::format::content::KvEncContent;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::fs::load_text;
use crate::{Error, Result};

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
