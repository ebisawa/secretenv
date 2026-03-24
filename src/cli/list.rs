// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::read::list_kv_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::output::json::print_json_output;
use crate::Result;

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,
}

pub fn run(args: ListArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let keys_with_disclosed = list_kv_command(&options, args.name.as_deref())?;

    if args.common.json {
        let keys: Vec<&str> = keys_with_disclosed
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        print_json_output(&serde_json::json!({ "keys": keys }))?;
    } else {
        for (key, disclosed) in &keys_with_disclosed {
            if *disclosed {
                println!("{} [DISCLOSED]", key);
            } else {
                println!("{}", key);
            }
        }
    }

    Ok(())
}
