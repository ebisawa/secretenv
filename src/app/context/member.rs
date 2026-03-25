// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::ResolvedCommandPaths;
use crate::config::resolution::member_id::resolve_member_id;
use crate::Result;

#[derive(Debug, Clone)]
pub struct ResolvedMemberContext {
    pub member_id: String,
    pub paths: ResolvedCommandPaths,
}

pub fn resolve_member_context(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<ResolvedMemberContext> {
    let paths = ResolvedCommandPaths::load(options)?;
    let member_id = resolve_member_id(member_id, Some(paths.base_dir.as_path()))?;
    Ok(ResolvedMemberContext { member_id, paths })
}
