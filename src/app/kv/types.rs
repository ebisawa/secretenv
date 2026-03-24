// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

pub(crate) struct KvWriteOutcome {
    pub message: Option<String>,
}

pub(crate) struct KvReadResult {
    pub values: BTreeMap<String, String>,
    pub disclosed: Vec<(String, bool)>,
}

pub(crate) struct KvImportResult {
    pub write_outcome: KvWriteOutcome,
    pub entry_count: usize,
}

pub(crate) enum KvReadMode<'a> {
    All,
    Single(&'a str),
}
