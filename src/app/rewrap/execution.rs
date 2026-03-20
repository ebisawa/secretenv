// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::ExecutionContext;
use crate::app::member::promote_members;
use crate::feature::rewrap::file::rewrap_file_document;
use crate::feature::rewrap::kv::rewrap_kv_document;
use crate::feature::rewrap::RewrapOptions;
use crate::format::content::{EncryptedContent, FileEncContent, KvEncContent};
use crate::format::token::TokenCodec;
use crate::support::fs::{atomic, load_text, lock};
use crate::Result;
use std::path::Path;

use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, RewrapFileFailure, RewrapFileSuccess,
};

/// Execute a batch rewrap over already planned files.
pub fn execute_rewrap_batch(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
) -> Result<RewrapBatchOutcome> {
    if !request.accepted_promotions.is_empty() {
        promote_members(&plan.workspace_root, &request.accepted_promotions)?;
    }

    let execution = ExecutionContext::load(&request.options, request.member_id.clone(), None)?;
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();

    for file_path in &plan.file_paths {
        match process_rewrap_file(file_path, plan, &execution, request) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: file_path.clone(),
            }),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: file_path.clone(),
                error_message: error.to_string(),
            }),
        }
    }

    Ok(RewrapBatchOutcome {
        processed_files,
        failed_files,
    })
}

fn process_rewrap_file(
    file_path: &Path,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<()> {
    let file_path_buf = file_path.to_path_buf();
    lock::with_file_lock(&file_path_buf, || {
        let content = load_text(file_path)?;
        let rewritten = match EncryptedContent::detect(content)? {
            EncryptedContent::FileEnc(file_content) => {
                rewrap_file_content(&file_content, plan, execution, request)?
            }
            EncryptedContent::KvEnc(kv_content) => {
                rewrap_kv_content(&kv_content, plan, execution, request)?
            }
        };

        atomic::save_text(file_path, &rewritten)
    })
}

fn rewrap_file_content(
    content: &FileEncContent,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<String> {
    let options = build_rewrap_options(request, None);
    rewrap_file_document(
        &options,
        content,
        &execution.member_id,
        &execution.key_ctx,
        Some(plan.workspace_root.as_path()),
    )
}

fn rewrap_kv_content(
    content: &KvEncContent,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<String> {
    let options = build_rewrap_options(request, Some(TokenCodec::JsonJcs));
    rewrap_kv_document(
        &options,
        content,
        &execution.member_id,
        &execution.key_ctx,
        Some(plan.workspace_root.as_path()),
    )
}

fn build_rewrap_options(
    request: &RewrapBatchRequest,
    token_codec: Option<TokenCodec>,
) -> RewrapOptions {
    RewrapOptions {
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        token_codec,
        no_signer_pub: request.no_signer_pub,
        debug: request.options.verbose,
    }
}
