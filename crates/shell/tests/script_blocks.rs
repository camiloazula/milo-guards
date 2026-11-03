//! PowerShell code known only when it runs, given to a cmdlet as a script
//! block or built from text: `Invoke-Command $b`, `[scriptblock]::Create(…)`,
//! `InvokeScript(…)`, `Start-Job`, a splat on a cmdlet that runs a block, a
//! hook the host runs, a method called by a name, `ExpandString`,
//! `Where-Object` and `Trace-Command`. A block written out is read where it
//! stands, and text given to build code is read too.
//!
//! The lines and their answers are in `tests/cases/script_blocks.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("script_blocks");
}
