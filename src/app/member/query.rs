// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::io::workspace::members::{
    load_active_member_files, load_incoming_member_files, load_member_file,
};
use crate::Result;

use super::types::{MemberListResult, MemberShowResult};
use super::view::{build_member_document_view, build_member_list_entry};

pub fn list_members(options: &CommonCommandOptions) -> Result<MemberListResult> {
    let workspace = require_workspace(options, "member list")?;
    Ok(MemberListResult {
        active: load_active_member_files(&workspace.root_path)?
            .into_iter()
            .map(build_member_list_entry)
            .collect::<Result<Vec<_>>>()?,
        incoming: load_incoming_member_files(&workspace.root_path)?
            .into_iter()
            .map(build_member_list_entry)
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn show_member(options: &CommonCommandOptions, member_id: &str) -> Result<MemberShowResult> {
    let workspace = require_workspace(options, "member show")?;
    let (member, status) = load_member_file(&workspace.root_path, member_id)?;
    Ok(MemberShowResult {
        member: build_member_document_view(member)?,
        status,
    })
}
