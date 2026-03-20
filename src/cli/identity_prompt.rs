// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Interactive identity and registration prompts for CLI commands.

use dialoguer::{Confirm, Input};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::app::identity::{resolve_github_user_with_fallback, resolve_member_id_with_fallback};
use crate::support::validation;
use crate::{Error, Result};

pub fn resolve_member_id(
    member_id: Option<String>,
    workspace: Option<&PathBuf>,
    keystore_root: &Path,
) -> Result<String> {
    if let Some(member_id) = resolve_member_id_with_fallback(member_id, workspace, keystore_root)? {
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
