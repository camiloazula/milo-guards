//! A device spelling is the same in any folder, so a redirect to it after a
//! `cd`, even to a place the guard cannot read, is not a write to a file
//! there. `$null` is the null value only in PowerShell and only unquoted, and
//! even there it is no device where a cmdlet takes it for the folder the line
//! is in (a copy's destination, the path of `New-Item`). A part after
//! `/dev/fd/<digits>` or a descriptor alias makes it a folder, so a `..` after
//! it is no longer the descriptor's own place.
//!
//! The lines and their answers are in `tests/cases/devices.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("devices");
}
