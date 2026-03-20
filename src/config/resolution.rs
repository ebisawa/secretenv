// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration resolution.
//!
//! Provides resolution functions for various configuration values based on priority order:
//! 1. CLI arguments/options
//! 2. Environment variables
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default values

pub mod common;
pub mod github_user;
pub mod member_id;
pub mod ssh_key;
pub mod ssh_signer;
pub mod workspace;
