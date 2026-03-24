// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::paths::{
    ensure_members_dir, incoming_member_file_path, member_file_path, members_dir, MemberStatus,
};
use super::store::{
    ensure_workspace_member_kid_uniqueness, load_json_files_in_dir, load_member_file_from_path,
    MemberKidCandidate,
};
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

struct PromotionPlan {
    source: PathBuf,
    destination: PathBuf,
    member_id: String,
}

fn build_promotion_plan(
    workspace_path: &Path,
    member_ids: Option<&[String]>,
) -> Result<Vec<PromotionPlan>> {
    let incoming_dir = members_dir(workspace_path, MemberStatus::Incoming);
    let active_dir = members_dir(workspace_path, MemberStatus::Active);

    let plans = match member_ids {
        Some(ids) => ids
            .iter()
            .map(|member_id| {
                let source = incoming_member_file_path(workspace_path, member_id);
                if !source.exists() {
                    return Err(Error::NotFound {
                        message: format!("Member '{}' not found in incoming/", member_id),
                    });
                }

                let destination = member_file_path(workspace_path, MemberStatus::Active, member_id);
                if destination.exists() {
                    return Err(Error::InvalidOperation {
                        message: format!(
                            "Member '{}' already exists in active/. Cannot promote from incoming/.",
                            member_id
                        ),
                    });
                }

                Ok(PromotionPlan {
                    source,
                    destination,
                    member_id: member_id.clone(),
                })
            })
            .collect::<Result<Vec<_>>>(),
        None => load_json_files_in_dir(&incoming_dir)?
            .into_iter()
            .map(|source| {
                let member_id = source
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(String::from)
                    .ok_or_else(|| Error::Io {
                        message: format!(
                            "Invalid file name: {}",
                            display_path_relative_to_cwd(&source)
                        ),
                        source: None,
                    })?;

                let destination = active_dir.join(format!("{}.json", member_id));
                if destination.exists() {
                    return Err(Error::InvalidOperation {
                        message: format!(
                            "Member '{}' already exists in active/. Cannot promote from incoming/.",
                            member_id
                        ),
                    });
                }

                Ok(PromotionPlan {
                    source,
                    destination,
                    member_id,
                })
            })
            .collect::<Result<Vec<_>>>(),
    }?;
    ensure_promotion_kids_are_unique(workspace_path, &plans)?;
    Ok(plans)
}

fn execute_promotion_plan(workspace_path: &Path, plans: &[PromotionPlan]) -> Result<Vec<String>> {
    if plans.is_empty() {
        return Ok(Vec::new());
    }

    ensure_members_dir(workspace_path, MemberStatus::Active)?;

    for plan in plans {
        fs::rename(&plan.source, &plan.destination).map_err(|e| Error::Io {
            message: format!("Failed to promote member '{}': {}", plan.member_id, e),
            source: Some(e),
        })?;
    }

    Ok(plans.iter().map(|plan| plan.member_id.clone()).collect())
}

pub fn promote_incoming_members(workspace_path: &Path) -> Result<Vec<String>> {
    let plans = build_promotion_plan(workspace_path, None)?;
    execute_promotion_plan(workspace_path, &plans)
}

pub fn promote_specified_incoming_members(
    workspace_path: &Path,
    member_ids: &[String],
) -> Result<Vec<String>> {
    let plans = build_promotion_plan(workspace_path, Some(member_ids))?;
    execute_promotion_plan(workspace_path, &plans)
}

fn ensure_promotion_kids_are_unique(workspace_path: &Path, plans: &[PromotionPlan]) -> Result<()> {
    let candidates = plans
        .iter()
        .map(|plan| {
            let public_key = load_member_file_from_path(&plan.source)?;
            Ok(MemberKidCandidate {
                member_id: plan.member_id.clone(),
                kid: public_key.protected.kid,
                status: MemberStatus::Active,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_workspace_member_kid_uniqueness(
        workspace_path,
        &candidates,
        &[],
        &[MemberStatus::Active],
    )
}
