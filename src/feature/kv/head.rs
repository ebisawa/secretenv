// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::kv_enc::{KvEncDocument, KvHeader};
use crate::support::time::current_timestamp;
use crate::Result;

pub(crate) fn build_updated_head(doc: &KvEncDocument) -> Result<KvHeader> {
    Ok(KvHeader {
        sid: doc.head.sid,
        created_at: doc.head.created_at.clone(),
        updated_at: current_timestamp()?,
    })
}
