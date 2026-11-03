//! Where `Set-Location` leaves a PowerShell line, so what follows is judged
//! in that provider: a drive made with `New-PSDrive` (a name of any character
//! but `: / \ . ~`, made later in the text) is a drive; in the registry,
//! `Env:`, `Function:` and the like a bare `NUL` or `CON` is an item there,
//! not the device; a rooted path or `~` after a `cd` stays on the drive of
//! that `cd`; a single letter is a disk unless the line makes it a drive; and
//! a `Set-Location` fed by the pipeline, `cd -` and `cd -- -` go to a place
//! only known when it runs. A move the guard cannot follow (`& $b`, `iex $s`,
//! `[Environment]::CurrentDirectory`) leaves later paths known only when they
//! run; `Pop-Location` goes back to the folder the line saved; a relative
//! `FileSystem::` path and a rooted one after a `cd` to a share are read
//! from where the line is; a block that runs later is judged from where the
//! line may be then; and a job starts in its `-WorkingDirectory`.
//!
//! The lines and their answers are in `tests/cases/powershell_locations.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("powershell_locations");
}
