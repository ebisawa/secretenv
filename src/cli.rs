// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI commands for secretenv v3

// Common utilities (enabled for v3)
pub mod common;
pub mod error;
pub mod file_output;
pub mod identity_prompt;

// Active v3 commands
pub mod decrypt;
pub mod encrypt;
pub mod get;
pub mod import;
pub mod init;
pub mod inspect;
pub mod join;
pub mod key;
pub mod list;
pub mod member;
mod registration;
pub mod rewrap;
pub mod run;
pub mod set;
pub mod unset;

pub mod config;

// Removed (deprecated in v3)
// pub mod share;
// pub mod verify;

use clap::{Parser, Subcommand};

use crate::Error;

/// Serverless CLI for secure secret sharing
#[derive(Parser)]
#[command(name = "secretenv")]
#[command(version)]
#[command(about = "Serverless CLI for secure secret sharing with HPKE encryption")]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Configuration management
    Config(config::ConfigArgs),

    /// Decrypt a file
    Decrypt(decrypt::DecryptArgs),

    /// Encrypt a file
    Encrypt(encrypt::EncryptArgs),

    /// Get a secret value
    Get(get::GetArgs),

    /// Import secrets from .env file
    Import(import::ImportArgs),

    /// Initialize workspace
    Init(init::InitArgs),

    /// Inspect encrypted file metadata
    Inspect(inspect::InspectArgs),

    /// Join an existing workspace
    Join(join::JoinArgs),

    /// Key management
    Key(key::KeyArgs),

    /// List all secrets
    List(list::ListArgs),

    /// Member management
    Member(member::MemberArgs),

    /// Re-encrypt secrets for updated members
    Rewrap(rewrap::RewrapArgs),

    /// Run command with decrypted environment variables
    Run(run::RunArgs),

    /// Set a secret value
    Set(set::SetArgs),

    /// Remove a secret
    Unset(unset::UnsetArgs),
}

pub fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Config(args) => config::run(args),
        Commands::Decrypt(args) => decrypt::run(args),
        Commands::Encrypt(args) => encrypt::run(args),
        Commands::Get(args) => get::run(args),
        Commands::Import(args) => import::run(args),
        Commands::Init(args) => init::run(args),
        Commands::Inspect(args) => inspect::run(args),
        Commands::Join(args) => join::run(args),
        Commands::Key(args) => key::run(args),
        Commands::List(args) => list::run(args),
        Commands::Member(args) => member::run(args),
        Commands::Rewrap(args) => rewrap::run(args),
        Commands::Run(args) => run::run(args),
        Commands::Set(args) => set::run(args),
        Commands::Unset(args) => unset::run(args),
    }
}
