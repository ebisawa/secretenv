// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::CommonCommandOptions;
use crate::app::member::verify_members;
use crate::cli::common::output::json::print_json_output;
use crate::Error;

use super::VerifyArgs;

pub(crate) fn run(args: VerifyArgs) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&args.common);
    let results = verify_members(&options, &args.member_ids, args.common.verbose)?;

    if results.is_empty() {
        eprintln!("No members found in workspace");
        return Ok(());
    }

    // Output results
    if args.common.json {
        let output = serde_json::json!({
            "results": results.iter().map(|r| serde_json::json!({
                "member_id": r.member_id,
                "verified": r.verified,
                "message": r.message,
                "fingerprint": r.fingerprint,
                "matched_key_id": r.matched_key_id,
            })).collect::<Vec<_>>(),
        });
        print_json_output(&output)?;
    } else {
        for result in &results {
            if result.verified {
                eprintln!("✓ {}: {}", result.member_id, result.message);
            } else {
                eprintln!("✗ {}: {}", result.member_id, result.message);
            }
            if let Some(fp) = &result.fingerprint {
                eprintln!("  SSH key fingerprint: {}", fp);
            }
        }

        // Summary
        let verified_count = results.iter().filter(|r| r.verified).count();
        let total_count = results.len();
        eprintln!("\nVerified {}/{} members", verified_count, total_count);
    }

    Ok(())
}
