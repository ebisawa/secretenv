// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer file workflow sessions.

use crate::app::context::{load_optional_workspace, CommonCommandOptions, ExecutionContext};
use crate::feature::decrypt::decrypt_document;
use crate::feature::encrypt::encrypt_file_document;
use crate::feature::envelope::signature::{build_signing_context, SigningContext};
use crate::feature::inspect::inspect_document_with_verification;
use crate::feature::inspect::verification::{
    build_online_verification_display, OnlineVerificationDisplay,
};
use crate::feature::verify::recipients::verify_recipient_public_keys;
use crate::format::content::{EncryptedContent, FileEncContent};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationResult as OnlineVerificationResult;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::{list_active_member_ids, load_member_files};
use crate::support::fs::{load_bytes, load_text};
use crate::support::path::display_path_relative_to_cwd;
use crate::support::runtime::run_blocking_result;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Encrypt command inputs resolved at the application layer.
struct EncryptFileSession {
    pub execution: ExecutionContext,
    pub workspace_root: WorkspaceRoot,
    pub member_ids: Vec<String>,
    pub input_bytes: Vec<u8>,
}

impl EncryptFileSession {
    fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        input_path: &Path,
    ) -> Result<Self> {
        let execution = ExecutionContext::load(options, member_id, None)?;
        let workspace_root = execution
            .workspace_root
            .clone()
            .ok_or_else(|| Error::Config {
                message: "Workspace is required for encrypt".to_string(),
            })?;
        let member_ids = list_active_member_ids(&workspace_root.root_path)?;
        let input_bytes = load_bytes(input_path)?;

        Ok(Self {
            execution,
            workspace_root,
            member_ids,
            input_bytes,
        })
    }

    fn verified_recipient_keys(
        &self,
        debug: bool,
    ) -> Result<Vec<crate::model::public_key::VerifiedPublicKeyAttested>> {
        let public_keys = load_member_files(&self.workspace_root.root_path, &self.member_ids)?;
        verify_recipient_public_keys(&public_keys, debug)
    }

    fn signing_context<'a>(
        &'a self,
        no_signer_pub: bool,
        debug: bool,
    ) -> Result<SigningContext<'a>> {
        build_signing_context(&self.execution.key_ctx, no_signer_pub, debug)
    }
}

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
    ) -> Result<ExecutionContext> {
        ExecutionContext::load(options, member_id, kid)
    }
}

/// Inspect command inputs resolved at the application layer.
struct InspectFileSession {
    content: EncryptedContent,
    input_display: String,
    workspace_root: Option<WorkspaceRoot>,
}

impl InspectFileSession {
    fn load(options: &CommonCommandOptions, input_path: &Path) -> Result<Self> {
        let content = EncryptedContent::detect(load_text(input_path)?)?;
        let workspace_root = load_optional_workspace(options)?;

        Ok(Self {
            content,
            input_display: display_path_relative_to_cwd(input_path),
            workspace_root,
        })
    }
}

pub fn validate_decrypt_input(input_path: &Path) -> Result<()> {
    let _ = DecryptFileSession::load_input(input_path)?;
    Ok(())
}

/// Resolve output path for file-enc format.
///
/// Returns `<input_filename>.encrypted` in current directory if `--out` is not specified.
pub fn resolve_encrypted_output_path(
    explicit_out: Option<&PathBuf>,
    input_path: &Path,
) -> Result<Option<PathBuf>> {
    if let Some(out) = explicit_out {
        return Ok(Some(out.clone()));
    }

    let input_filename = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::InvalidArgument {
            message: format!(
                "Cannot derive filename from input path: {}",
                display_path_relative_to_cwd(input_path)
            ),
        })?;

    if input_filename.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidArgument {
            message: format!("E_NAME_INVALID: invalid input filename: {}", input_filename),
        });
    }

    let output_filename = format!("{}.encrypted", input_filename);
    let current_dir = std::env::current_dir().map_err(|e| Error::Io {
        message: format!("Failed to get current directory: {}", e),
        source: Some(e),
    })?;
    Ok(Some(current_dir.join(output_filename)))
}

pub fn encrypt_file_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    no_signer_pub: bool,
    input_path: &Path,
) -> Result<String> {
    let session = EncryptFileSession::load(options, member_id, input_path)?;
    let verified_keys = session.verified_recipient_keys(options.verbose)?;
    let signing = session.signing_context(no_signer_pub, options.verbose)?;
    encrypt_file_document(
        &session.input_bytes,
        &session.member_ids,
        &verified_keys,
        &signing,
    )
}

pub fn decrypt_file_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<&str>,
    input_path: &Path,
) -> Result<Zeroizing<Vec<u8>>> {
    let session = DecryptFileSession::load_input(input_path)?;
    let execution = DecryptFileSession::load_execution(options, member_id, kid)?;
    decrypt_document(
        &session.content,
        &execution.member_id,
        &execution.key_ctx,
        options.verbose,
    )
}

pub fn inspect_file_command(
    options: &CommonCommandOptions,
    input_path: &Path,
) -> Result<(String, String)> {
    let session = InspectFileSession::load(options, input_path)?;
    let inspect_output = inspect_document_with_verification(
        &session.content,
        &session.input_display,
        session
            .workspace_root
            .as_ref()
            .map(|w| w.root_path.as_path()),
        options.verbose,
    )?;

    let mut output = inspect_output.formatted;
    let report = &inspect_output.signature_report;

    if report.verified {
        if let Some(ref public_key) = report.signer_public_key {
            if let Some(ref binding_claims) = public_key.protected.binding_claims {
                if let Some(github) = binding_claims.github_account.as_ref() {
                    let result = match run_blocking_result(verify_github_account(
                        public_key,
                        options.verbose,
                        None,
                    )) {
                        Ok(r) => r,
                        Err(e) => OnlineVerificationResult::failed(
                            &public_key.protected.member_id,
                            format!("{}", e),
                            None,
                        ),
                    };
                    build_online_verification_display(
                        &OnlineVerificationDisplay::GithubResult(result),
                        Some(&github.login),
                        Some(github.id),
                        &mut output,
                    );
                } else {
                    build_online_verification_display(
                        &OnlineVerificationDisplay::NoSupportedBinding,
                        None,
                        None,
                        &mut output,
                    );
                }
            }
        }
    }

    Ok((session.input_display, output))
}
