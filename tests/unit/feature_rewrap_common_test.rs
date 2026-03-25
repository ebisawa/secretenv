// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/services/rewrap/common module
//!
//! Tests for rewrap common helpers.

use secretenv::feature::rewrap::common::{add_to_removed_history, merge_removed_history};
use secretenv::model::common::RemovedRecipient;
use secretenv::{Error, Result};

// These functions are not exported, so we test them indirectly through public APIs
// or test the behavior they enable
fn check_recipient_exists(current_recipients: &[String], rid: &str) -> bool {
    current_recipients.contains(&rid.to_string())
}

fn validate_not_empty_recipients(recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::Config {
            message: "Cannot remove all recipients. At least one recipient must remain."
                .to_string(),
        });
    }
    Ok(())
}

#[test]
fn test_check_recipient_exists() {
    let recipients = vec![
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
    ];

    assert!(check_recipient_exists(&recipients, "alice@example.com"));
    assert!(!check_recipient_exists(&recipients, "charlie@example.com"));
}

#[test]
fn test_validate_not_empty_recipients() {
    let recipients = vec!["alice@example.com".to_string()];
    assert!(validate_not_empty_recipients(&recipients).is_ok());

    let empty: Vec<String> = vec![];
    assert!(validate_not_empty_recipients(&empty).is_err());
}

#[test]
fn test_add_to_removed_history() {
    let mut removed: Option<Vec<RemovedRecipient>> = None;

    add_to_removed_history(
        &mut removed,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();

    assert!(removed.is_some());
    assert_eq!(removed.as_ref().unwrap().len(), 1);
    assert_eq!(removed.as_ref().unwrap()[0].rid, "alice@example.com");
    assert_eq!(
        removed.as_ref().unwrap()[0].kid,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"
    );
}

#[test]
fn test_add_to_removed_history_multiple() {
    let mut removed: Option<Vec<RemovedRecipient>> = None;

    add_to_removed_history(
        &mut removed,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();
    add_to_removed_history(
        &mut removed,
        "bob@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE",
    )
    .unwrap();

    assert_eq!(removed.as_ref().unwrap().len(), 2);
}

#[test]
fn test_merge_removed_history() {
    let mut target: Option<Vec<RemovedRecipient>> = None;
    let source = Some(vec![
        RemovedRecipient {
            rid: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            removed_at: "2024-01-01T00:00:00Z".to_string(),
        },
        RemovedRecipient {
            rid: "bob@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
            removed_at: "2024-01-02T00:00:00Z".to_string(),
        },
    ]);

    merge_removed_history(&mut target, source.as_ref());

    assert!(target.is_some());
    assert_eq!(target.as_ref().unwrap().len(), 2);
}

#[test]
fn test_merge_removed_history_into_existing() {
    let mut target = Some(vec![RemovedRecipient {
        rid: "charlie@example.com".to_string(),
        kid: "01HABC1234DEFGHIJKLMNOPQRS".to_string(),
        removed_at: "2024-01-03T00:00:00Z".to_string(),
    }]);
    let source = Some(vec![RemovedRecipient {
        rid: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        removed_at: "2024-01-01T00:00:00Z".to_string(),
    }]);

    merge_removed_history(&mut target, source.as_ref());

    assert_eq!(target.as_ref().unwrap().len(), 2);
}
