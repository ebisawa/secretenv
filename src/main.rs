// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv CLI entry point.
//!
//! Phase 2.7: Re-enabled with decrypt command

use secretenv::cli;
use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    let verbose = std::env::args().any(|arg| arg == "--verbose" || arg == "-v");
    let default_filter = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    fmt().with_env_filter(filter).with_target(false).init();

    if let Err(e) = cli::run() {
        cli::error::print_error(&e);
        std::process::exit(1);
    }
}
