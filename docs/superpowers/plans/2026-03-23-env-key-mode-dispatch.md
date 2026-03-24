# Environment Variable Key Mode Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up the existing `SECRETENV_PRIVATE_KEY` / `SECRETENV_KEY_PASSWORD` env var key loading path so that all encrypt/decrypt/rewrap CLI commands work in CI environments without SSH.

**Architecture:** CLI layer checks `is_env_key_mode()` to decide whether SSH context resolution is needed. App layer receives `Option<SshSigningContext>` and dispatches to either `ExecutionContext::load()` (SSH) or `ExecutionContext::load_from_env()` (env). Feature layer is unchanged.

**Tech Stack:** Rust, clap, tracing

**Spec:** `docs/superpowers/specs/2026-03-23-env-key-mode-dispatch-design.md`

---

### Task 1: Add `ExecutionContext::resolve()` dispatcher

**Files:**
- Modify: `src/app/context.rs:74-123`
- Test: `tests/unit/app_context_test.rs` (create)

- [ ] **Step 1: Write test for resolve() dispatching to load_from_env when ssh_ctx is None**

In `tests/unit/app_context_test.rs`:

```rust
// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::app::context::ExecutionContext;

#[test]
fn test_resolve_returns_error_without_workspace_when_env_mode() {
    // When ssh_ctx is None (env mode), load_from_env requires a workspace.
    // Without a workspace configured, it should return a Config error.
    let options = secretenv::app::context::CommonCommandOptions {
        home: None,
        identity: None,
        quiet: false,
        verbose: false,
        workspace: None,
        ssh_signer: None,
    };
    let result = ExecutionContext::resolve(&options, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Workspace is required"),
        "Expected workspace error, got: {}",
        err
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test unit test_resolve_returns_error_without_workspace_when_env_mode`
Expected: compilation error — `resolve` does not exist yet.

- [ ] **Step 3: Add `ExecutionContext::resolve()` to `src/app/context.rs`**

Add after `load_from_env()` (after line 123):

```rust
/// Dispatch to SSH-based or environment variable key loading.
///
/// When `ssh_ctx` is `None`, env-var mode is assumed and
/// `load_from_env()` handles key resolution.
pub fn resolve(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    explicit_kid: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<Self> {
    match ssh_ctx {
        Some(ctx) => Self::load(options, member_id, explicit_kid, ctx),
        None => {
            if member_id.is_some() {
                tracing::warn!(
                    "Ignoring --member-id in environment variable key mode \
                     (member_id is derived from SECRETENV_PRIVATE_KEY)"
                );
            }
            Self::load_from_env(options)
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test unit test_resolve_returns_error_without_workspace_when_env_mode`
Expected: PASS

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 6: Commit**

```bash
git add src/app/context.rs tests/unit/app_context_test.rs
git commit -m "feat: add ExecutionContext::resolve() dispatcher for env/SSH key mode"
```

---

### Task 2: Add `resolve_ssh_context_optional()` CLI helper

**Files:**
- Modify: `src/cli/common/ssh.rs`
- Test: (existing unit test infrastructure; the function delegates to already-tested helpers)

- [ ] **Step 1: Add `resolve_ssh_context_optional()` to `src/cli/common/ssh.rs`**

Add the import at top:

```rust
use crate::feature::context::env_key::is_env_key_mode;
```

Add after `resolve_ssh_context_for_active_key()`:

```rust
/// Resolve SSH context if needed, skipping in env-var key mode.
///
/// Returns `None` when `SECRETENV_PRIVATE_KEY` is set (CI mode),
/// causing the app layer to use environment variable key loading.
pub fn resolve_ssh_context_optional(
    options: &CommonCommandOptions,
) -> Result<Option<SshSigningContext>> {
    if is_env_key_mode() {
        debug!("[SSH] Environment variable key mode active, skipping SSH resolution");
        Ok(None)
    } else {
        Ok(Some(resolve_ssh_context_for_active_key(options)?))
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo build`
Expected: success (function is unused for now, no warnings since it's pub)

- [ ] **Step 3: Commit**

```bash
git add src/cli/common/ssh.rs
git commit -m "feat: add resolve_ssh_context_optional() for CI env key dispatch"
```

---

### Task 3: Wire up app/file.rs to accept `Option<SshSigningContext>`

**Files:**
- Modify: `src/app/file.rs`

- [ ] **Step 1: Change `EncryptFileSession::load()` signature**

In `src/app/file.rs`, change:

```rust
    fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        input_path: &Path,
        ssh_ctx: SshSigningContext,
    ) -> Result<Self> {
        let execution = ExecutionContext::load(options, member_id, None, ssh_ctx)?;
```

To:

```rust
    fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        input_path: &Path,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<Self> {
        let execution = ExecutionContext::resolve(options, member_id, None, ssh_ctx)?;
```

- [ ] **Step 2: Change `DecryptFileSession::load_execution()` signature**

Change:

```rust
    fn load_execution(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        kid: Option<&str>,
        ssh_ctx: SshSigningContext,
    ) -> Result<ExecutionContext> {
        ExecutionContext::load(options, member_id, kid, ssh_ctx)
    }
```

To:

```rust
    fn load_execution(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        kid: Option<&str>,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<ExecutionContext> {
        ExecutionContext::resolve(options, member_id, kid, ssh_ctx)
    }
```

- [ ] **Step 3: Change public functions**

`encrypt_file_command`: change `ssh_ctx: SshSigningContext` to `ssh_ctx: Option<SshSigningContext>`.

`decrypt_file_command`: change `ssh_ctx: SshSigningContext` to `ssh_ctx: Option<SshSigningContext>`.

- [ ] **Step 4: Verify compilation**

Run: `cargo build`
Expected: errors in CLI callers (type mismatch) — expected at this point.

- [ ] **Step 5: Commit**

```bash
git add src/app/file.rs
git commit -m "refactor: change app/file.rs to accept Option<SshSigningContext>"
```

---

### Task 4: Wire up app/kv.rs to accept `Option<SshSigningContext>`

**Files:**
- Modify: `src/app/kv.rs`

- [ ] **Step 1: Change internal session types**

`KvReadSession::load()`: change `ssh_ctx: SshSigningContext` → `ssh_ctx: Option<SshSigningContext>`, replace `ExecutionContext::load(...)` with `ExecutionContext::resolve(...)`.

`KvWriteSession::new()` and field: change `ssh_ctx: SshSigningContext` → `ssh_ctx: Option<SshSigningContext>`.

Inside `KvWriteSession::execute()`, change `ExecutionContext::load(...)` to `ExecutionContext::resolve(...)`.

- [ ] **Step 2: Change all public functions**

All of these change `ssh_ctx: SshSigningContext` → `ssh_ctx: Option<SshSigningContext>`:

- `get_kv_command()`
- `set_kv_command()`
- `unset_kv_command()`
- `import_kv_command()` (passes through to `set_kv_command`)
- `build_run_env_command()`

- [ ] **Step 3: Verify compilation**

Run: `cargo build`
Expected: errors in CLI callers — expected at this point.

- [ ] **Step 4: Commit**

```bash
git add src/app/kv.rs
git commit -m "refactor: change app/kv.rs to accept Option<SshSigningContext>"
```

---

### Task 5: Wire up app/run.rs and app/rewrap/execution.rs

**Files:**
- Modify: `src/app/run.rs`
- Modify: `src/app/rewrap/execution.rs`

- [ ] **Step 1: Change `app/run.rs`**

`execute_env_command()`: change `ssh_ctx: SshSigningContext` → `ssh_ctx: Option<SshSigningContext>`.

Inside `build_run_env_command()` call, pass `ssh_ctx` through (it already accepts `Option` from Task 4).

- [ ] **Step 2: Change `app/rewrap/execution.rs`**

`execute_rewrap_batch()`: change `ssh_ctx: SshSigningContext` → `ssh_ctx: Option<SshSigningContext>`.

Inside, change:
```rust
let execution =
    ExecutionContext::load(&request.options, request.member_id.clone(), None, ssh_ctx)?;
```
To:
```rust
let execution =
    ExecutionContext::resolve(&request.options, request.member_id.clone(), None, ssh_ctx)?;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build`
Expected: errors in CLI callers — expected at this point.

- [ ] **Step 4: Commit**

```bash
git add src/app/run.rs src/app/rewrap/execution.rs
git commit -m "refactor: change app/run.rs and app/rewrap to accept Option<SshSigningContext>"
```

---

### Task 6: Update CLI commands to use `resolve_ssh_context_optional()`

**Files:**
- Modify: `src/cli/decrypt.rs`
- Modify: `src/cli/encrypt.rs`
- Modify: `src/cli/get.rs`
- Modify: `src/cli/run.rs`
- Modify: `src/cli/set.rs`
- Modify: `src/cli/unset.rs`
- Modify: `src/cli/import.rs`
- Modify: `src/cli/rewrap/batch.rs`

- [ ] **Step 1: Update imports in each file**

In each file, change import:
```rust
use crate::cli::common::ssh::resolve_ssh_context_for_active_key;
```
To:
```rust
use crate::cli::common::ssh::resolve_ssh_context_optional;
```

- [ ] **Step 2: Update call sites in each file**

Replace `resolve_ssh_context_for_active_key(&options)?` with `resolve_ssh_context_optional(&options)?` in:

| File | Line |
|------|------|
| `cli/decrypt.rs` | ~51 |
| `cli/encrypt.rs` | ~43 |
| `cli/get.rs` | ~56 |
| `cli/run.rs` | ~43 |
| `cli/set.rs` | ~65 |
| `cli/unset.rs` | ~42 |
| `cli/import.rs` | ~41 |
| `cli/rewrap/batch.rs` | ~20 |

- [ ] **Step 3: Build successfully**

Run: `cargo build`
Expected: success — all type mismatches resolved.

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: all existing tests pass.

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy -- -D warnings && cargo fmt -- --check`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add src/cli/decrypt.rs src/cli/encrypt.rs src/cli/get.rs src/cli/run.rs \
        src/cli/set.rs src/cli/unset.rs src/cli/import.rs src/cli/rewrap/batch.rs
git commit -m "feat: wire up CLI commands to use env key mode dispatch"
```

---

### Task 7: Clean up dead code in cli/rewrap/context.rs

**Files:**
- Delete: `src/cli/rewrap/context.rs`

- [ ] **Step 1: Verify the file is not a registered module**

Check `src/cli/rewrap.rs` — confirm no `mod context;` declaration.
(Already confirmed: `cli/rewrap.rs` only has `mod batch; mod promotion;`.)

- [ ] **Step 2: Delete the dead file**

```bash
rm src/cli/rewrap/context.rs
```

- [ ] **Step 3: Build and test**

Run: `cargo build && cargo test`
Expected: success — file was never compiled.

- [ ] **Step 4: Commit**

```bash
git add -A src/cli/rewrap/context.rs
git commit -m "chore: remove dead cli/rewrap/context.rs (not registered as module)"
```

---

### Task 8: Add integration test for env key mode dispatch

**Files:**
- Create: `tests/unit/app_context_env_dispatch_test.rs`

This test verifies that `ExecutionContext::resolve()` correctly dispatches
based on presence/absence of `SECRETENV_PRIVATE_KEY`. The existing
`feature_context_env_key_test.rs` and `feature_context_env_key_integration_test.rs`
already test the underlying key loading; this test covers the dispatch layer.

- [ ] **Step 1: Write dispatch integration test**

```rust
// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for ExecutionContext::resolve() dispatch behavior.

use secretenv::app::context::{CommonCommandOptions, ExecutionContext};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

/// Guard that restores environment variables on drop.
struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn new(names: &[&str]) -> Self {
        let vars = names
            .iter()
            .map(|name| (name.to_string(), std::env::var(name).ok()))
            .collect();
        Self { vars }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, original) in &self.vars {
            match original {
                Some(val) => std::env::set_var(name, val),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn test_options() -> CommonCommandOptions {
    CommonCommandOptions {
        home: None,
        identity: None,
        quiet: false,
        verbose: false,
        workspace: None,
        ssh_signer: None,
    }
}

#[test]
fn test_resolve_none_ssh_ctx_requires_workspace() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let result = ExecutionContext::resolve(&test_options(), None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Workspace is required"),
        "Expected workspace required error, got: {}",
        err
    );
}

#[test]
fn test_resolve_none_ssh_ctx_without_env_var_requires_workspace() {
    // When ssh_ctx is None but SECRETENV_PRIVATE_KEY is also not set,
    // load_from_env will fail with "not set" error.
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::remove_var(ENV_PRIVATE_KEY);
    std::env::remove_var(ENV_KEY_PASSWORD);

    let options = test_options();
    let result = ExecutionContext::resolve(&options, None, None, None);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Register test file in `tests/unit.rs`**

Check how unit tests are registered (via `#[path]` or `mod` statements) and add the new test module.

- [ ] **Step 3: Run new tests**

Run: `cargo test --test unit app_context_env_dispatch`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `cargo test`
Expected: all tests pass

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy -- -D warnings && cargo fmt -- --check`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add tests/unit/app_context_env_dispatch_test.rs
git commit -m "test: add dispatch tests for ExecutionContext::resolve()"
```

---

### Task 9: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: all tests pass, no new warnings

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: clean

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt -- --check`
Expected: clean

- [ ] **Step 4: Verify no unused imports or dead code**

Run: `cargo build 2>&1 | grep -i warning`
Expected: no warnings
