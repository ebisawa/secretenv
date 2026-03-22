// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Interactive identity and registration prompts for CLI commands.

use dialoguer::{Confirm, Input, Select};
use std::io::IsTerminal;
use std::path::Path;

use crate::app::identity::{resolve_github_user_with_fallback, resolve_member_id_with_fallback};
use crate::io::ssh::external::pubkey::SshKeyCandidate;
use crate::io::ssh::SshError;
use crate::support::validation;
use crate::{Error, Result};

pub fn resolve_member_id(
    member_id: Option<String>,
    keystore_root: &Path,
    base_dir: Option<&Path>,
) -> Result<String> {
    if let Some(member_id) = resolve_member_id_with_fallback(member_id, keystore_root, base_dir)? {
        return Ok(member_id);
    }

    if is_prompt_available() {
        return prompt_member_id();
    }

    Err(Error::Config {
        message: "member_id is required but could not be determined.\n\
                  Options:\n\
                  1. Specify --member-id <id>\n\
                  2. Set environment variable: export SECRETENV_MEMBER_ID=<id>\n\
                  3. Set in config: secretenv config set member_id <id>\n\
                  4. Run in an interactive terminal for prompt"
            .to_string(),
    })
}

pub fn resolve_github_user(
    cli_value: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    if let Some(github_user) = resolve_github_user_with_fallback(cli_value, base_dir)? {
        return Ok(Some(github_user));
    }

    if is_prompt_available() {
        return prompt_github_user();
    }

    Ok(None)
}

pub fn confirm_member_overwrite(member_id: &str) -> Result<bool> {
    Confirm::new()
        .with_prompt(format!(
            "Member '{}' already exists in workspace. Update with current key?",
            member_id
        ))
        .default(false)
        .interact()
        .map_err(|e| Error::Io {
            message: format!("Failed to read confirmation: {}", e),
            source: None,
        })
}

/// Select a key from candidates.
/// 0 candidates → error (no Ed25519 key found)
/// 1 candidate  → automatic selection (return index 0)
/// n candidates → TTY: interactive dialoguer::Select / non-TTY: error
pub fn select_ssh_key(candidates: &[SshKeyCandidate]) -> Result<usize> {
    if candidates.is_empty() {
        return Err(SshError::operation_failed(
            "No ssh-ed25519 key found in ssh-agent.\n\
             Check available keys: ssh-add -L\n\
             Ensure your SSH agent (e.g., 1Password) has an Ed25519 key available.",
        )
        .into());
    }

    if candidates.len() == 1 {
        return Ok(0);
    }

    if !is_prompt_available() {
        return Err(Error::Config {
            message: "Multiple Ed25519 keys found in ssh-agent.\n\
                      Specify which key to use with -i <path> or \
                      SECRETENV_SSH_KEY environment variable."
                .to_string(),
        });
    }

    let items: Vec<String> = candidates.iter().map(format_candidate).collect();

    Select::new()
        .with_prompt("Multiple SSH keys found. Select one")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| Error::Config {
            message: format!("Failed to read selection: {e}"),
        })
}

/// Format a candidate for display in the interactive selector.
fn format_candidate(candidate: &SshKeyCandidate) -> String {
    if candidate.comment.is_empty() {
        candidate.fingerprint.clone()
    } else {
        format!("{} ({})", candidate.fingerprint, candidate.comment)
    }
}

pub fn is_prompt_available() -> bool {
    std::io::stdin().is_terminal() && std::env::var("CI").is_err()
}

fn prompt_member_id() -> Result<String> {
    Input::new()
        .with_prompt("Enter your member ID (alphanumeric and .@_+-)")
        .validate_with(|input: &String| {
            validation::validate_member_id(input)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .interact_text()
        .map_err(|e| Error::Config {
            message: format!("Failed to read input: {}", e),
        })
}

fn prompt_github_user() -> Result<Option<String>> {
    let input: String = Input::new()
        .with_prompt("Enter your GitHub username (optional)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| Error::Config {
            message: format!("Failed to read input: {}", e),
        })?;

    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}
