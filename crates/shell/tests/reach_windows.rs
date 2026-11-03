//! The `Reach` of a PowerShell or cmd line that only reads: where its reads
//! land from the workspace and from other working directories, a protected
//! `.agent` at the workspace's root (the workspace's own), a Windows wildcard
//! that matches a hidden name and so reaches a hidden folder that holds a
//! secret, and the values of `Get-ChildItem -Depth` and `-Attributes`. The
//! plain readers of the plain workspace are in `effect.rs`; POSIX is in
//! `reach.rs`.
//!
//! The lines and their answers are in `tests/cases/reach_windows.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("reach_windows");
}
