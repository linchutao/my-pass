# Command TUI Design

## Goal

Add a command-style interactive mode to `mypass` so a user can choose a vault,
enter the master password once, inspect and manage entries, then exit with
unlocked secrets dropped from memory.

## User Experience

The new mode is entered with `mypass tui`. The existing one-shot CLI commands
remain available. `--vault <path>` still means a vault file path. When `--vault`
is omitted, interactive mode prompts for a vault path and uses the default path
when the user presses enter.

Startup flow:

```text
Vault path [default: <default vault path>]:
Master password:
mypass>
```

Interactive commands:

```text
/list
/view <entry> [--username <username>]
/copy <entry> [--username <username>]
/add <entry>
/update <entry> [--username <username>]
/delete <entry> [--username <username>]
/change-master
/help
/exit
```

`/view` prints username and password. `/copy` copies the password to the
clipboard and clears it after the same delay used by the current CLI behavior.
`/exit` and EOF leave the loop.

## Architecture

The existing CLI parser gets a new `tui` subcommand. The interactive
implementation lives in `src/tui.rs`; it owns prompt orchestration, command
parsing, and output formatting. Core vault mutations remain in `src/vault.rs`.

`vault.rs` exposes unlocked-vault operations so the TUI can unlock once and
reuse the decrypted vault state:

- list entries from an `UnlockedVault`
- get an entry from an `UnlockedVault`
- add, update, delete, and save through an `UnlockedVault`
- change the master password while preserving the unlocked DEK

## Security

The master password is held in a `Zeroizing<String>` only for the lifetime of
the interactive session. The session also holds `UnlockedVault`, whose DEK is
zeroized on drop. Exiting the REPL drops both values. The design does not claim
to protect against a compromised terminal, process memory inspection, or
clipboard monitoring.

## Testing

Tests cover command parsing, unlocked-vault operations, and integration-level
startup with `/list`, `/view`, and `/exit`. Existing CLI behavior must continue
to pass.
