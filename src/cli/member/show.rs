// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::member::query::show_member;
use crate::Error;

use super::ShowArgs;

pub(crate) fn run(args: ShowArgs) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&args.common);
    let result = show_member(&options, &args.member_id)?;
    let member = result.member;
    let status = result.status;

    if args.common.json {
        println!("{}", serde_json::to_string_pretty(&member.document)?);
    } else {
        let membership_str = status.as_str();
        println!("Member: {}", member.member_id);
        println!("Membership:   {}", membership_str);
        println!("Key ID: {}", member.kid);
        println!("Format: {}", member.format);
        println!("Expires: {}", member.expires_at);
        println!("Status: {}", member.verification_status.as_str());
        if let Some(ref created) = member.created_at {
            println!("Created: {}", created);
        }
        println!();
        println!("KEM Key: {}/{}", member.kem_key_type, member.kem_curve);
        println!(
            "Signature Key: {}/{}",
            member.sig_key_type, member.sig_curve
        );
        println!();
        println!("SSH Attestation:");
        println!("  Method: {}", member.ssh_attestation_method);
        println!("  SSH Pubkey: {}", member.ssh_attestation_pubkey);

        if let Some(ref github) = member.github_account {
            println!();
            println!("GitHub Account:");
            println!("  GitHub ID: {}", github.id);
            println!("  GitHub username: {}", github.login);
        }
    }

    for warning in &member.verification_warnings {
        eprintln!("Warning: {}", warning);
    }

    Ok(())
}
