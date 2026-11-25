//! Code judged on a machine that mounts another system's drives
//! (`Paths::drive_mounts`): a path through WSL's `/mnt/c` is judged where
//! `C:\` lands. The cases are in `tests/cases/drives.cases`.

mod common;

#[test]
fn a_path_through_a_drive_mount_is_judged_on_the_drive() {
    common::cases::check("drives");
}
