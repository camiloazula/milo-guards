//! Holds the shell guard's grammars to how the real shells parse a line,
//! without running one.
//!
//! The shell guard judges the tree its tree-sitter grammar gives it, so a line
//! the grammar splits otherwise than the shell that runs it is judged as
//! another line. This tool reads every POSIX and PowerShell line of the case
//! files, and a set generated from their words, as the guard does, and asks
//! the real shells how they parse each: bash in no-exec mode (`-n`), which
//! says whether it accepts it, and, with `--with pwsh`, PowerShell's own
//! parser (`ParseInput`), which gives its whole tree. It prints every difference,
//! sorted, and fails on one that is not on the known list
//! (`tools/grammar-check/known.cases`). `docs/design/shell.md` says what it
//! holds and what it cannot; `CONTRIBUTING.md` how to run it (`just
//! grammars`). zsh is not asked: its no-exec mode still expands words
//! ([`shells`] says how).
//!
//! It is a tool of the repository, not a guard: it starts processes, which no
//! crate under `crates/` may, and it is never published. It never runs a
//! line: every shell is started by [`room::Room::start`], with the layers that
//! module lists, and its tests show each layer: `tests/no_line_runs.rs` on
//! canary lines, which leave a file behind if bash runs them, with and without
//! bash's restricted mode; `tests/room.rs` and `tests/startup.rs` on plain
//! programs and on a bash given no text. PowerShell's half
//! ([`powershell`]) has not run anywhere yet and is off unless asked for.

pub mod base64;
pub mod cases;
pub mod check;
pub mod compare;
pub mod guard;
pub mod known;
pub mod lines;
pub mod powershell;
pub mod room;
pub mod shells;
