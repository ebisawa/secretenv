// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Async runtime utilities.

use crate::{Error, Result};
use std::future::Future;

/// Create a new blocking Tokio runtime.
pub fn new_blocking_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|e| Error::Config {
        message: format!("Failed to create async runtime: {}", e),
    })
}

/// Run an async operation on a temporary blocking runtime.
pub fn block_on<F, T>(future: F) -> Result<T>
where
    F: Future<Output = T>,
{
    let rt = new_blocking_runtime()?;
    Ok(rt.block_on(future))
}

/// Run an async operation that returns `Result<T>` on a temporary blocking runtime.
pub fn block_on_result<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let rt = new_blocking_runtime()?;
    rt.block_on(future)
}
