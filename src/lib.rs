// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv - Serverless CLI for secure secret sharing

pub mod app;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod feature;
pub mod format;
pub mod io;
pub mod model;
pub mod support;

pub use error::{Error, Result};
