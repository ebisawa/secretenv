// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Output path-related encryption tests

use crate::cli::common::{default_common_options, set_ssh_key_from_temp_dir, ALICE_MEMBER_ID};
use crate::test_utils::{setup_test_workspace, with_temp_cwd};
use secretenv::cli::encrypt;
use secretenv::model::identifiers::format;
use std::fs;

#[test]
fn test_encrypt_default_output_is_encrypted_in_cwd() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, b"some data").unwrap();

    with_temp_cwd(&workspace_dir, || {
        let mut common_opts = default_common_options();
        common_opts.home = Some(temp_dir.path().to_path_buf());
        common_opts.workspace = Some(workspace_dir.clone());
        set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

        let args = encrypt::EncryptArgs {
            common: common_opts,
            member_id: Some(ALICE_MEMBER_ID.to_string()),
            input: input_path.clone(),
            out: None,
            no_signer_pub: false,
        };
        encrypt::run(args).unwrap();

        // Default output: <input_filename>.encrypted in current dir (= workspace_dir)
        let expected = workspace_dir.join("data.bin.encrypted");
        assert!(expected.exists(), "Should create data.bin.encrypted in cwd");

        let content = fs::read_to_string(&expected).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V3);
    })
}

#[test]
fn test_encrypt_explicit_out_option() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"data").unwrap();
    let explicit_output = workspace_dir.join("custom_output.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        input: input_path,
        out: Some(explicit_output.clone()),
        no_signer_pub: false,
    };
    encrypt::run(args).unwrap();

    assert!(
        explicit_output.exists(),
        "File should be at explicit --out path"
    );
}
