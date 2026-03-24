// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key::types::KeyExportResult;
use crate::io::keystore::storage::load_public_key;
use crate::Result;
use std::path::PathBuf;

use super::common::{resolve_active_kid, resolve_keystore_root};

pub fn export_key(
    home: Option<PathBuf>,
    member_id: String,
    kid: Option<String>,
) -> Result<KeyExportResult> {
    let keystore_root = resolve_keystore_root(home)?;
    let kid = resolve_active_kid(&keystore_root, &member_id, kid)?;
    let public_key = load_public_key(&keystore_root, &member_id, &kid)?;

    Ok(KeyExportResult {
        member_id,
        kid,
        public_key,
    })
}
