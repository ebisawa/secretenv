// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! config command implementation

use clap::{Args, Subcommand};

use crate::app::config;
use crate::cli::common::options::CommonOptions;
use crate::Error;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Get configuration value
    Get(GetArgs),

    /// List all configurations
    List(ListArgs),

    /// Set configuration value
    Set(SetArgs),

    /// Remove configuration value
    Unset(UnsetArgs),
}

#[derive(Args)]
pub struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Configuration key
    pub key: String,
}

#[derive(Args)]
pub struct SetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Configuration key
    pub key: String,

    /// Configuration value
    pub value: String,
}

#[derive(Args)]
pub struct UnsetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Configuration key
    pub key: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,
}

pub fn run(args: ConfigArgs) -> Result<(), Error> {
    match args.command {
        ConfigCommands::Get(args) => run_get(args),
        ConfigCommands::List(args) => run_list(args),
        ConfigCommands::Set(args) => run_set(args),
        ConfigCommands::Unset(args) => run_unset(args),
    }
}

fn run_get(args: GetArgs) -> Result<(), Error> {
    println!("{}", config::get_config(&args.key)?);
    Ok(())
}

fn run_set(args: SetArgs) -> Result<(), Error> {
    let result = config::set_config(&args.key, &args.value)?;
    eprintln!(
        "Set '{}' = '{}' in {} config",
        result.key,
        result.value,
        scope_label(result.scope)
    );
    Ok(())
}

fn run_unset(args: UnsetArgs) -> Result<(), Error> {
    let result = config::unset_config(&args.key)?;
    eprintln!(
        "Unset '{}' from {} config",
        result.key,
        scope_label(result.scope)
    );
    Ok(())
}

fn run_list(_args: ListArgs) -> Result<(), Error> {
    let config = config::list_config()?;

    for (key, value) in config {
        println!("{} = {}", key, value);
    }

    Ok(())
}

fn scope_label(scope: config::ConfigScope) -> &'static str {
    match scope {
        config::ConfigScope::Global => "global",
    }
}
