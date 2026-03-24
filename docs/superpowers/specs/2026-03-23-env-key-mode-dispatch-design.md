# Environment Variable Key Mode Dispatch

## Problem

`SECRETENV_PRIVATE_KEY` environment variable support is implemented at the feature/app layer
(`env_key::load_private_key_from_env`, `ExecutionContext::load_from_env`) but never invoked.
All CLI commands unconditionally call `resolve_ssh_context_for_active_key()`, which fails in
CI environments where no SSH agent or local keystore is available.

## Approach

CLI-layer dispatch: each command checks `is_env_key_mode()` before attempting SSH resolution.
When env mode is active, SSH context resolution is skipped entirely and the app layer receives
`None` for the SSH context, triggering `ExecutionContext::load_from_env()`.

## Design

### CLI Layer

Add a helper in `cli/common/ssh.rs`:

```rust
pub fn resolve_ssh_context_optional(
    options: &CommonCommandOptions,
) -> Result<Option<SshSigningContext>> {
    if is_env_key_mode() {
        Ok(None)
    } else {
        Ok(Some(resolve_ssh_context_for_active_key(options)?))
    }
}
```

Each CLI command replaces `resolve_ssh_context_for_active_key(&options)?`
with `resolve_ssh_context_optional(&options)?`.

The existing `resolve_ssh_context_for_active_key()` is retained for commands
that always require SSH (e.g., `key new`, `key export --private`).

### App Layer

All public app functions that participate in normal encrypt/decrypt/rewrap workflows
change `SshSigningContext` to `Option<SshSigningContext>`.

Internal dispatch via a unified method on `ExecutionContext`:

```rust
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

### Affected Files

**CLI layer** (replace `resolve_ssh_context_for_active_key` with `resolve_ssh_context_optional`):

| File | Function |
|------|----------|
| `cli/decrypt.rs` | `run()` |
| `cli/encrypt.rs` | `run()` |
| `cli/get.rs` | `run()` |
| `cli/run.rs` | `run()` |
| `cli/set.rs` | `run()` |
| `cli/unset.rs` | `run()` |
| `cli/import.rs` | `run()` |
| `cli/rewrap/batch.rs` | `execute_batch_rewrap()` |

**CLI unchanged** (always require SSH, not supported in CI mode):

| File | Reason |
|------|--------|
| `cli/key/new.rs` | Key generation requires SSH for protection |
| `cli/key/operations.rs` (`run_export_private`) | Decrypts from local keystore via SSH |

**App layer** (change `SshSigningContext` to `Option<SshSigningContext>`):

| File | Functions |
|------|-----------|
| `app/context.rs` | Add `ExecutionContext::resolve()` |
| `app/file.rs` | `encrypt_file_command()`, `decrypt_file_command()` (+ internal `EncryptFileSession::load()`, `DecryptFileSession::load_execution()`) |
| `app/kv.rs` | `get_kv_command()`, `set_kv_command()`, `unset_kv_command()`, `import_kv_command()`, `build_run_env_command()` (+ internal `KvReadSession::load()`, `KvWriteSession::new()`) |
| `app/run.rs` | `execute_env_command()` |
| `app/rewrap/execution.rs` | `execute_rewrap_batch()` |

**App layer unchanged**:

| File | Reason |
|------|--------|
| `app/key.rs` | `export_private_key_command()` always uses SSH to decrypt from keystore |

**CLI legacy** (fix existing issue):

| File | Issue |
|------|-------|
| `cli/rewrap/context.rs` | `ExecutionContext::load()` called with wrong arity (3 args instead of 4); align with new `resolve()` |

### Behavior

- `SECRETENV_PRIVATE_KEY` set: skip SSH, load key from env vars, resolve public keys from workspace
- `SECRETENV_PRIVATE_KEY` not set: existing SSH-based flow unchanged
- `member_id` and `explicit_kid` from CLI args are ignored in env mode (derived from env key);
  a warning is logged when `--member-id` is explicitly passed
- If `SECRETENV_PRIVATE_KEY` is set but `SECRETENV_KEY_PASSWORD` is missing,
  `load_private_key_from_env()` returns a clear error (existing behavior, no change needed)

### Unaffected Commands

Commands that do not use `ExecutionContext` or `SshSigningContext` are unaffected:
- `inspect`, `list`, `verify` (read-only, no private key needed or use workspace keys only)
- `init`, `join`, `member` (workspace management, uses key generation flow)
- `config` (configuration only)

### Test Strategy

- Unit test: `resolve_ssh_context_optional()` returns `None` when env var set, `Some` otherwise
- Unit test: `ExecutionContext::resolve()` dispatches to `load_from_env` when `ssh_ctx` is `None`
- Unit test: warning logged when `member_id` is `Some` and `ssh_ctx` is `None`
- Error case test: `SECRETENV_PRIVATE_KEY` set without `SECRETENV_KEY_PASSWORD` produces clear error
- Integration test: set both env vars, run decrypt/get commands against a test workspace
- Regression: all existing tests pass unchanged (env vars not set = SSH path)
