// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use zeroize::Zeroizing;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::feature::decrypt::decrypt_document;
use crate::format::content::FileEncContent;
use crate::support::fs::load_text;
use crate::Result;

/// Decrypt command inputs resolved at the application layer.
struct DecryptFileSession {
    content: FileEncContent,
}

impl DecryptFileSession {
    fn load_input(input_path: &Path) -> Result<Self> {
        let content = FileEncContent::detect(load_text(input_path)?)?;
        Ok(Self { content })
    }

    fn load_execution(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        kid: Option<&str>,
        ssh_ctx: Option<ResolvedSshSigner>,
    ) -> Result<ExecutionContext> {
        ExecutionContext::resolve(options, member_id, kid, ssh_ctx)
    }
}

pub fn validate_decrypt_input(input_path: &Path) -> Result<()> {
    let _ = DecryptFileSession::load_input(input_path)?;
    Ok(())
}

pub fn decrypt_file_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<&str>,
    input_path: &Path,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<Zeroizing<Vec<u8>>> {
    let session = DecryptFileSession::load_input(input_path)?;
    let execution = DecryptFileSession::load_execution(options, member_id, kid, ssh_ctx)?;
    decrypt_document(
        &session.content,
        &execution.member_id,
        &execution.key_ctx,
        options.verbose,
    )
}
