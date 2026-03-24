// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use std::collections::BTreeMap;

use clap::Args;

use crate::app::context::CommonCommandOptions;
use crate::app::kv::{get_kv_command, list_kv_command};
use crate::cli::common::options::CommonOptions;
use crate::cli::common::output::json::print_json_output;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::Result;

#[derive(Args)]
pub struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Output all entries
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Output in KEY="VALUE" format
    #[arg(long, short = 'k')]
    pub with_key: bool,

    /// Key name to retrieve
    pub key: Option<String>,
}

pub fn run(args: GetArgs) -> Result<()> {
    if args.all && args.key.is_some() {
        return Err(crate::Error::InvalidOperation {
            message: "--all and KEY argument cannot be used together".to_string(),
        });
    }
    if !args.all && args.key.is_none() {
        return Err(crate::Error::InvalidOperation {
            message: "KEY argument is required (or use --all to get all entries)".to_string(),
        });
    }

    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options)?;
    let kv_map = get_kv_command(
        &options,
        args.member_id.clone(),
        args.name.as_deref(),
        args.key.as_deref(),
        args.all,
        ssh_ctx,
    )?;
    let disclosed = list_kv_command(&options, args.name.as_deref())?;

    if args.all {
        run_all(&kv_map, &disclosed, &args)
    } else {
        run_single(&kv_map, &disclosed, &args)
    }
}

fn format_value(key: &str, value: &str, with_key: bool) -> String {
    if with_key {
        format!(
            "{}=\"{}\"",
            key,
            value.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        value.to_string()
    }
}

fn warn_disclosed(keys: &[(String, bool)]) {
    for (key, is_disclosed) in keys {
        if *is_disclosed {
            eprintln!(
                "Warning: Entry '{}' may have been disclosed to a removed recipient. \
                 Consider rotating the secret value.",
                key
            );
        }
    }
}

fn run_all(
    kv_map: &BTreeMap<String, String>,
    disclosed: &[(String, bool)],
    args: &GetArgs,
) -> Result<()> {
    warn_disclosed(disclosed);

    if args.common.json {
        let map: BTreeMap<&str, &str> = kv_map
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        print_json_output(&map)?;
    } else {
        let mut entries: Vec<_> = kv_map.iter().collect();
        entries.sort_by_key(|(k, _)| k.as_str());
        for (key, value) in entries {
            println!("{}", format_value(key, value, args.with_key));
        }
    }
    Ok(())
}

fn run_single(
    kv_map: &BTreeMap<String, String>,
    disclosed: &[(String, bool)],
    args: &GetArgs,
) -> Result<()> {
    let key = args.key.as_deref().unwrap();
    let value = kv_map.get(key).cloned().unwrap_or_default();

    if disclosed
        .iter()
        .any(|(name, is_disclosed)| name == key && *is_disclosed)
    {
        eprintln!(
            "Warning: Entry '{}' may have been disclosed to a removed recipient. \
             Consider rotating the secret value.",
            key
        );
    }

    if args.common.json {
        let mut map = BTreeMap::new();
        map.insert(key, value.as_str());
        print_json_output(&map)?;
    } else {
        println!("{}", format_value(key, &value, args.with_key));
    }
    Ok(())
}
