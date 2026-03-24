// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::paths::{
    active_member_file_path, ensure_members_dir, find_member_path, incoming_member_file_path,
    members_dir, MemberStatus,
};
use crate::format::schema::document::{parse_public_key_file, parse_public_key_str};
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(super) struct MemberKidCandidate {
    pub member_id: String,
    pub kid: String,
    pub status: MemberStatus,
}

pub(super) fn load_json_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = list_dir(dir)?;

    let mut paths: Vec<PathBuf> = entries
        .map(|entry| -> Result<Option<PathBuf>> {
            let entry = entry.map_err(|e| Error::Io {
                message: format!(
                    "Failed to read directory entry in {}: {}",
                    display_path_relative_to_cwd(dir),
                    e
                ),
                source: Some(e),
            })?;
            let path = entry.path();
            Ok(
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    Some(path)
                } else {
                    None
                },
            )
        })
        .filter_map(|r| r.transpose())
        .collect::<Result<Vec<_>>>()?;

    paths.sort();
    Ok(paths)
}

fn load_sorted_members_from_dir(dir: &Path) -> Result<Vec<PublicKey>> {
    let paths = load_json_files_in_dir(dir)?;
    let mut members: Vec<PublicKey> = paths
        .into_iter()
        .map(|path| load_member_file_from_path(&path))
        .collect::<Result<Vec<_>>>()?;

    members.sort_by(|a, b| a.protected.member_id.cmp(&b.protected.member_id));
    Ok(members)
}

fn save_member_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).map_err(|e| Error::Io {
        message: format!(
            "Failed to write {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(e),
    })
}

pub fn ensure_member_document_kid_is_unique(
    workspace_path: &Path,
    status: MemberStatus,
    member_id: &str,
    kid: &str,
    allow_replace_self: bool,
) -> Result<()> {
    let ignored_existing = if allow_replace_self {
        vec![(status, member_id.to_string())]
    } else {
        Vec::new()
    };
    let candidate = MemberKidCandidate {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        status,
    };
    ensure_workspace_member_kid_uniqueness(
        workspace_path,
        &[candidate],
        &ignored_existing,
        &[MemberStatus::Active, MemberStatus::Incoming],
    )
}

pub(super) fn ensure_workspace_member_kid_uniqueness(
    workspace_path: &Path,
    candidates: &[MemberKidCandidate],
    ignored_existing: &[(MemberStatus, String)],
    existing_statuses: &[MemberStatus],
) -> Result<()> {
    let mut seen: BTreeMap<String, MemberKidCandidate> = BTreeMap::new();

    for existing in load_member_kid_candidates(workspace_path, existing_statuses, ignored_existing)?
    {
        seen.insert(existing.kid.clone(), existing);
    }

    for candidate in candidates {
        if let Some(existing) = seen.get(&candidate.kid) {
            return Err(duplicate_kid_error(existing, candidate));
        }
        seen.insert(candidate.kid.clone(), candidate.clone());
    }

    Ok(())
}

pub fn save_member_content(
    workspace_path: &Path,
    status: MemberStatus,
    member_id: &str,
    content: &str,
    overwrite: bool,
) -> Result<()> {
    ensure_members_dir(workspace_path, status)?;
    let source_name = format!("member content for {}", member_id);
    let public_key = parse_public_key_str(content, &source_name)?;
    let path = match status {
        MemberStatus::Active => active_member_file_path(workspace_path, member_id),
        MemberStatus::Incoming => incoming_member_file_path(workspace_path, member_id),
    };
    if !overwrite && path.exists() {
        return Err(Error::InvalidOperation {
            message: format!(
                "Member '{}' already exists in {}/ (use --force to overwrite)",
                member_id,
                member_status_dir_name(status)
            ),
        });
    }
    ensure_member_document_kid_is_unique(
        workspace_path,
        status,
        member_id,
        &public_key.protected.kid,
        overwrite && path.exists(),
    )?;
    save_member_file(&path, content)
}

fn member_status_dir_name(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Active => "active",
        MemberStatus::Incoming => "incoming",
    }
}

pub fn load_active_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members_from_dir(&members_dir(workspace_path, MemberStatus::Active))
}

pub fn load_incoming_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members_from_dir(&members_dir(workspace_path, MemberStatus::Incoming))
}

pub fn list_active_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Active))
}

pub fn list_incoming_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Incoming))
}

pub fn list_active_member_ids(workspace_root: &Path) -> Result<Vec<String>> {
    let paths = load_json_files_in_dir(&members_dir(workspace_root, MemberStatus::Active))?;

    let mut member_ids: Vec<String> = paths
        .into_iter()
        .filter_map(|path| path.file_stem().and_then(|s| s.to_str()).map(String::from))
        .collect();

    if member_ids.is_empty() {
        return Err(Error::NotFound {
            message: "No members found in workspace".to_string(),
        });
    }

    member_ids.sort();
    Ok(member_ids)
}

pub fn load_member_files(workspace_path: &Path, member_ids: &[String]) -> Result<Vec<PublicKey>> {
    let mut members = Vec::with_capacity(member_ids.len());

    for member_id in member_ids {
        let (public_key, _status) = load_member_file(workspace_path, member_id)?;
        if public_key.protected.member_id != *member_id {
            return Err(Error::InvalidArgument {
                message: format!(
                    "Member ID mismatch: file '{}' contains ID '{}'",
                    member_id, public_key.protected.member_id
                ),
            });
        }
        members.push(public_key);
    }

    Ok(members)
}

pub fn load_active_member_index_by_kid(
    workspace_path: &Path,
) -> Result<BTreeMap<String, PublicKey>> {
    let mut index = BTreeMap::new();

    for member in load_active_member_files(workspace_path)? {
        let kid = member.protected.kid.clone();
        if index.insert(kid.clone(), member).is_some() {
            return Err(Error::Config {
                message: format!("Ambiguous key: kid '{}' found in multiple members", kid),
            });
        }
    }

    Ok(index)
}

pub fn find_active_member_by_kid(workspace_path: &Path, kid: &str) -> Result<Option<PublicKey>> {
    Ok(load_active_member_index_by_kid(workspace_path)?.remove(kid))
}

pub fn load_member_file(
    workspace_path: &Path,
    member_id: &str,
) -> Result<(PublicKey, MemberStatus)> {
    if let Some((path, status)) = find_member_path(workspace_path, member_id) {
        let key = load_member_file_from_path(&path)?;
        return Ok((key, status));
    }

    Err(Error::NotFound {
        message: format!("Member '{}' not found in workspace", member_id),
    })
}

pub fn list_member_file_paths(
    workspace_path: &Path,
    member_ids: &[String],
) -> Result<Vec<PathBuf>> {
    if member_ids.is_empty() {
        let mut paths = load_json_files_in_dir(&members_dir(workspace_path, MemberStatus::Active))?;
        paths.extend(load_json_files_in_dir(&members_dir(
            workspace_path,
            MemberStatus::Incoming,
        ))?);
        return Ok(paths);
    }

    member_ids
        .iter()
        .map(|member_id| {
            find_member_path(workspace_path, member_id)
                .map(|(path, _)| path)
                .ok_or_else(|| Error::NotFound {
                    message: format!("Member '{}' not found in workspace", member_id),
                })
        })
        .collect()
}

pub fn delete_member(workspace_path: &Path, member_id: &str) -> Result<()> {
    let active_path = active_member_file_path(workspace_path, member_id);
    if !active_path.exists() {
        return Err(Error::NotFound {
            message: format!("Member '{}' not found in active/", member_id),
        });
    }

    fs::remove_file(&active_path).map_err(|e| Error::Io {
        message: format!("Failed to delete member '{}': {}", member_id, e),
        source: Some(e),
    })?;

    Ok(())
}

pub fn load_member_file_from_path(path: &Path) -> Result<PublicKey> {
    parse_public_key_file(path)
}

fn load_member_kid_candidates(
    workspace_path: &Path,
    statuses: &[MemberStatus],
    ignored_existing: &[(MemberStatus, String)],
) -> Result<Vec<MemberKidCandidate>> {
    let mut candidates = Vec::new();
    for status in statuses {
        for path in load_json_files_in_dir(&members_dir(workspace_path, *status))? {
            let Some(member_id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(String::from)
            else {
                continue;
            };
            if ignored_existing
                .iter()
                .any(|(ignored_status, ignored_member_id)| {
                    *ignored_status == *status && *ignored_member_id == member_id
                })
            {
                continue;
            }
            let member = load_member_file_from_path(&path)?;
            candidates.push(MemberKidCandidate {
                member_id,
                kid: member.protected.kid.clone(),
                status: *status,
            });
        }
    }
    Ok(candidates)
}

fn duplicate_kid_error(existing: &MemberKidCandidate, candidate: &MemberKidCandidate) -> Error {
    Error::Config {
        message: format!(
            "Duplicate kid '{}' in workspace members: {}/'{}' conflicts with {}/'{}'",
            candidate.kid,
            member_status_dir_name(existing.status),
            existing.member_id,
            member_status_dir_name(candidate.status),
            candidate.member_id
        ),
    }
}
