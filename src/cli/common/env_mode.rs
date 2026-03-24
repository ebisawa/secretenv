// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use crate::app::context::crypto::is_env_key_mode;
use crate::Result;

pub fn reject_env_key_mode(command_label: &str) -> Result<()> {
    if !is_env_key_mode() {
        return Ok(());
    }

    Err(crate::Error::invalid_operation(format!(
        "'{}' is unavailable in environment-variable key mode because it requires a local \
         keystore and SSH signer; run it on a developer machine.",
        command_label
    )))
}
