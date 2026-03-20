// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared context setup for rewrap command flows.

use super::RewrapArgs;
use crate::app::context::{CommonCommandOptions, ExecutionContext};
use crate::app::rewrap::{CryptoContext, RewrapOptions};
use crate::format::token::TokenCodec;
use crate::Result;
use std::path::PathBuf;

pub(crate) struct RewrapCommandContext {
    pub member_id: String,
    pub key_ctx: CryptoContext,
    pub workspace_root: Option<PathBuf>,
}

pub(crate) fn run_rewrap<C, F>(
    args: &RewrapArgs,
    content: &C,
    token_codec: Option<TokenCodec>,
    flow: F,
) -> Result<String>
where
    F: FnOnce(&RewrapOptions, &C, &str, &CryptoContext, Option<&std::path::Path>) -> Result<String>,
{
    let ctx = setup_rewrap_command_context(args)?;
    let options = build_rewrap_options(args, token_codec);

    flow(
        &options,
        content,
        &ctx.member_id,
        &ctx.key_ctx,
        ctx.workspace_root.as_deref(),
    )
}

fn setup_rewrap_command_context(args: &RewrapArgs) -> Result<RewrapCommandContext> {
    let options = CommonCommandOptions::from(&args.common);
    let execution = ExecutionContext::load(&options, args.member_id.clone(), None)?;

    Ok(RewrapCommandContext {
        member_id: execution.member_id,
        key_ctx: execution.key_ctx,
        workspace_root: execution.workspace_root.map(|ws| ws.root_path),
    })
}

fn build_rewrap_options(args: &RewrapArgs, token_codec: Option<TokenCodec>) -> RewrapOptions {
    RewrapOptions {
        rotate_key: args.rotate_key,
        clear_disclosure_history: args.clear_disclosure_history,
        token_codec,
        no_signer_pub: args.no_signer_pub,
        debug: args.common.verbose,
    }
}
