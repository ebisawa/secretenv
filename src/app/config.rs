// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for config commands.

use crate::feature::config::{self};
use crate::io::config::store::{set_config_value, unset_config_value};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Global,
}

pub struct ConfigSetResult {
    pub key: String,
    pub value: String,
    pub scope: ConfigScope,
}

pub struct ConfigUnsetResult {
    pub key: String,
    pub scope: ConfigScope,
}

pub fn get_config(key: &str) -> Result<String> {
    let normalized = config::normalize_key(key)?;
    let value = config::resolve_config_value(&normalized)?.0;
    value.ok_or_else(|| Error::NotFound {
        message: format!("Configuration key '{}' not found", key),
    })
}

pub fn list_config() -> Result<BTreeMap<String, String>> {
    config::load_global_config()
}

pub fn set_config(key: &str, value: &str) -> Result<ConfigSetResult> {
    let normalized = config::normalize_key(key)?;
    let (config_path, scope) = config::get_config_path_and_scope()?;
    set_config_value(&config_path, &normalized, value)?;
    Ok(ConfigSetResult {
        key: key.to_string(),
        value: value.to_string(),
        scope: scope.into(),
    })
}

pub fn unset_config(key: &str) -> Result<ConfigUnsetResult> {
    let normalized = config::normalize_key(key)?;
    let (config_path, scope) = config::get_config_path_and_scope()?;
    unset_config_value(&config_path, &normalized)?;
    Ok(ConfigUnsetResult {
        key: key.to_string(),
        scope: scope.into(),
    })
}

impl From<crate::feature::config::ConfigScope> for ConfigScope {
    fn from(scope: crate::feature::config::ConfigScope) -> Self {
        match scope {
            crate::feature::config::ConfigScope::Global => Self::Global,
        }
    }
}
