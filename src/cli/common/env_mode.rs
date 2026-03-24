// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use crate::app::context::crypto::is_env_key_mode;
use crate::Result;

fn is_env_mode_command_allowed(command_label: &str) -> bool {
    matches!(command_label, "run" | "decrypt" | "get" | "list")
}

pub fn ensure_env_mode_command_allowed(command_label: &str) -> Result<()> {
    if !is_env_key_mode() {
        return Ok(());
    }

    if is_env_mode_command_allowed(command_label) {
        return Ok(());
    }

    Err(crate::Error::invalid_operation(format!(
        "'{}' is unavailable in environment-variable key mode; env mode only supports \
         these commands: run, decrypt, get, list.",
        command_label
    )))
}
