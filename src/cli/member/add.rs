// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::member::mutation::add_member;
use crate::Error;

use super::AddArgs;

pub(crate) fn run(args: AddArgs) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&args.common);
    let member_id = add_member(&options, &args.filename, args.force)?;
    eprintln!("Added member '{}' to incoming/", member_id);
    Ok(())
}
