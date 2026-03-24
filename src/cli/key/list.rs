// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key listing (key list) implementation

use serde::Serialize;

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::manage::list_keys_command;
use crate::app::key::types::{KeyInfo, KeyListResult};
use crate::cli::common::output::json::print_json_output;
use crate::Result;

use super::ListArgs;

/// Print human-readable key listing output.
fn print_key_list(all_key_infos: &[(String, Vec<KeyInfoView>)], total_keys: usize, verbose: bool) {
    for (member_id, key_infos) in all_key_infos {
        if key_infos.is_empty() {
            continue;
        }
        println!("Keys for member: {}", member_id);
        println!();
        for key_info in key_infos {
            let active_marker = if key_info.active { " (ACTIVE)" } else { "" };
            println!("  Kid:        {}{}", key_info.kid, active_marker);
            if verbose {
                println!("  Format:     {}", key_info.format);
                println!("  Member ID:  {}", key_info.member_id);
                println!("  Created:    {}", key_info.created_at);
            }
            println!("  Expires:    {}", key_info.expires_at);
            println!();
        }
    }
    if all_key_infos.len() > 1 {
        println!(
            "Total: {} member(s), {} key(s)",
            all_key_infos.len(),
            total_keys
        );
    } else {
        println!("Total: {} key(s)", total_keys);
    }
}

/// Main entry point for key listing
pub fn run(args: ListArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let result = list_keys_command(&options, args.member_id.clone())?;
    if result.entries.is_empty() {
        if args.common.json {
            println!("[]");
        } else {
            println!("No members found in keystore");
        }
        return Ok(());
    }

    let all_key_infos = convert_key_infos(&result);

    if args.common.json {
        let flattened: Vec<&KeyInfoView> = all_key_infos
            .iter()
            .flat_map(|(_, keys)| keys.iter())
            .collect();
        print_json_output(&flattened)?;
    } else {
        print_key_list(&all_key_infos, result.total_keys, args.common.verbose);
    }

    Ok(())
}

#[derive(Serialize)]
struct KeyInfoView {
    kid: String,
    member_id: String,
    created_at: String,
    expires_at: String,
    active: bool,
    format: String,
}

fn convert_key_infos(result: &KeyListResult) -> Vec<(String, Vec<KeyInfoView>)> {
    result
        .entries
        .iter()
        .map(|(member_id, keys)| {
            let converted = keys.iter().map(map_key_info).collect();
            (member_id.clone(), converted)
        })
        .collect()
}

fn map_key_info(key: &KeyInfo) -> KeyInfoView {
    KeyInfoView {
        kid: key.kid.clone(),
        member_id: key.member_id.clone(),
        created_at: key.created_at.clone(),
        expires_at: key.expires_at.clone(),
        active: key.active,
        format: key.format.clone(),
    }
}
