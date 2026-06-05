# Command TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `mypass tui`, a command-style interactive mode that unlocks once, supports entry operations, and exits by dropping unlocked secrets.

**Architecture:** Add `src/tui.rs` for REPL parsing and prompt orchestration. Extend `src/vault.rs` with operations that work on `UnlockedVault` so the REPL does not re-derive the key for every command. Keep existing one-shot CLI commands intact.

**Tech Stack:** Rust 2024, clap, rpassword, zeroize, existing vault/clipboard modules, assert_cmd integration tests.

---

## File Structure

- `src/cli.rs`: add the `tui` subcommand and dispatch into `tui::run`.
- `src/tui.rs`: parse slash commands, run interactive loop, and format output.
- `src/vault.rs`: expose unlocked-vault CRUD helpers and master-password change.
- `src/lib.rs`: export the new `tui` module.
- `tests/cli.rs`: add integration coverage for the interactive flow.
- `README.md`: document `mypass tui`.

## Tasks

- [ ] Add failing tests for TUI command parsing.
- [ ] Implement `src/tui.rs` command parsing.
- [ ] Add failing tests for unlocked vault operations.
- [ ] Implement unlocked vault helpers in `src/vault.rs`.
- [ ] Add failing integration test for `mypass --vault <path> tui`.
- [ ] Wire the CLI subcommand and REPL runner.
- [ ] Document the new interactive mode.
- [ ] Run `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.
