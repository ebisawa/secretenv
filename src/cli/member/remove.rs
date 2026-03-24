// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::member::mutation::remove_member;
use crate::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&args.common);
    let result = remove_member(&options, &args.member_id, args.force)?;
    eprintln!("Removed member '{}'", result.member_id);

    Ok(())
}
