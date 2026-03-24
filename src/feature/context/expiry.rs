// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key expiration checking for private key operations.
//!
//! Provides functions to check key expiry status and enforce PRD §11.3.3:
//! expired keys must not be used for encryption (wrap) or signing.

use time::OffsetDateTime;
use tracing::warn;

use crate::{Error, Result};

const EXPIRY_WARNING_DAYS: i64 = 30;

/// Key expiration status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExpiryStatus {
    /// Key is valid and not close to expiring
    Valid,
    /// Key will expire within EXPIRY_WARNING_DAYS
    ExpiringSoon {
        expires_at: String,
        days_remaining: i64,
    },
    /// Key has expired
    Expired { expires_at: String },
}

/// Check the expiration status of a key.
///
/// Accepts `now` as a parameter for testability.
pub fn check_key_expiry(expires_at: &str, now: OffsetDateTime) -> Result<KeyExpiryStatus> {
    let expiry = parse_expires_at(expires_at)?;

    if now >= expiry {
        return Ok(KeyExpiryStatus::Expired {
            expires_at: expires_at.to_string(),
        });
    }

    let remaining = expiry - now;
    let days_remaining = remaining.whole_days();

    if days_remaining <= EXPIRY_WARNING_DAYS {
        return Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at: expires_at.to_string(),
            days_remaining,
        });
    }

    Ok(KeyExpiryStatus::Valid)
}

/// Enforce that a key is not expired for write operations (encrypt/sign).
///
/// Returns `Err` if the key has expired. Logs a warning if expiring soon.
pub fn enforce_key_not_expired_for_signing(expires_at: &str) -> Result<()> {
    match check_key_expiry(expires_at, OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(()),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => {
            warn!(
                "Private key expires in {} days (expires_at: {})",
                days_remaining, expires_at
            );
            Ok(())
        }
        KeyExpiryStatus::Expired { expires_at } => Err(Error::Verify {
            rule: "key-expiry".to_string(),
            message: format!(
                "Private key has expired (expires_at: {}). \
                 Expired keys cannot be used for encryption or signing.",
                expires_at
            ),
        }),
    }
}

/// Build a warning message if the key is expired or expiring soon.
///
/// For read operations (decrypt/verify) that allow expired keys with a warning.
pub fn build_key_expiry_warning(expires_at: &str) -> Result<Option<String>> {
    match check_key_expiry(expires_at, OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format!(
            "Private key expires in {} days (expires_at: {})",
            days_remaining, expires_at
        ))),
        KeyExpiryStatus::Expired { expires_at } => Ok(Some(format!(
            "Private key has expired (expires_at: {})",
            expires_at
        ))),
    }
}

fn parse_expires_at(expires_at: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339).map_err(|e| {
        Error::Parse {
            message: format!("Invalid expires_at format: {}", e),
            source: Some(Box::new(e)),
        }
    })
}
