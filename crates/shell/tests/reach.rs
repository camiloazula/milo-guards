//! The `Reach` of a POSIX line that only reads: `Workspace` when every read
//! stays in a workspace folder or a temporary folder, `Beyond` for a place
//! beyond them or a secret, and `Unknown` (never a reach) for what cannot be
//! placed: the plain workspace, other working directories, protected paths,
//! the home folder as the workspace and `~/.config` as the workspace. The
//! plain readers of the plain workspace are in `effect.rs`; PowerShell and
//! cmd are in `reach_windows.rs`.
//!
//! The lines and their answers, one section per set of paths, are in
//! `tests/cases/reach.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("reach");
}
