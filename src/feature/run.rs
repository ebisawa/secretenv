// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Run feature - build environment variables from kv-enc files.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::kv::decrypt_all_kv_values;
use crate::format::content::KvEncContent;
use crate::Result;
use std::collections::BTreeMap;

/// Build environment variables from kv-enc contents.
pub fn build_env_from_kv_contents(
    contents: &[&str],
    member_id: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<BTreeMap<String, String>> {
    let mut env_vars = BTreeMap::new();
    for content in contents {
        let kv_content = KvEncContent::new_unchecked(content.to_string());
        let kv_map = decrypt_all_kv_values(&kv_content, member_id, key_ctx, debug)?;
        env_vars.extend(kv_map);
    }
    Ok(env_vars)
}
