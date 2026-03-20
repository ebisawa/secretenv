// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! file-enc format rewrap operations (CLI wrapper)

use crate::app::rewrap::rewrap_file_content;
use crate::format::content::FileEncContent;
use crate::Result;

use super::{run_rewrap, RewrapArgs};

/// Rewrap a file-enc v3 file (returns updated content).
pub fn rewrap_file(args: &RewrapArgs, content: &FileEncContent) -> Result<String> {
    run_rewrap(args, content, None, rewrap_file_content)
}
