//! How the machine spells another system's drives (`Paths::drive_mounts`),
//! in every shell: WSL's `/mnt/c` and Git Bash's `/c` are `C:\` once the
//! caller names the mount, for a read, a send, a write, a delete and
//! `effect`. The cases are in `tests/cases/drives.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("drives");
}
