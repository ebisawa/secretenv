// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member add feature - add external public key to incoming.

use crate::io::json::parse_json_str;
use crate::io::workspace::members::{save_member_content, MemberStatus};
use crate::model::public_key::PublicKey;
use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;
use std::path::Path;

/// Add a member's public key file to members/incoming/.
///
/// Reads the file, validates it as a PublicKey JSON, and saves to incoming.
/// Returns the member_id extracted from the public key.
pub fn add_member_from_file(
    workspace_path: &Path,
    file_path: &Path,
    force: bool,
) -> Result<String> {
    let content = load_text(file_path)?;

    let public_key: PublicKey = parse_json_str(
        &content,
        "PublicKey JSON",
        &display_path_relative_to_cwd(file_path),
    )?;

    let member_id = public_key.protected.member_id.clone();

    save_member_content(
        workspace_path,
        MemberStatus::Incoming,
        &member_id,
        &content,
        force,
    )?;

    Ok(member_id)
}
