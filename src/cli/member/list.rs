// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::member::query::list_members;
use crate::cli::common::output::json::print_json_output;
use crate::Error;

use super::ListArgs;

pub(crate) fn run(args: ListArgs) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&args.common);
    let result = list_members(&options)?;
    let active = result.active;
    let incoming = result.incoming;

    if active.is_empty() && incoming.is_empty() {
        if args.common.json {
            println!("{{\"active\":[],\"incoming\":[]}}");
        } else {
            println!("No members found in workspace");
        }
        return Ok(());
    }

    if args.common.json {
        let output = serde_json::json!({
            "active": active.iter().map(|member| &member.document).collect::<Vec<_>>(),
            "incoming": incoming.iter().map(|member| &member.document).collect::<Vec<_>>(),
        });
        print_json_output(&output)?;
    } else {
        println!("Active:");
        for member in &active {
            println!("  {}", member.member_id);
        }

        if !incoming.is_empty() {
            println!();
            println!("Incoming:");
            for member in &incoming {
                println!("  {}", member.member_id);
            }
        }
    }

    Ok(())
}
