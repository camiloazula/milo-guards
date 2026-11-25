//! How the machine spells another system's drives (`Paths::drive_mounts`):
//! a read or a write through WSL's `/mnt/c` is judged where `C:\` lands,
//! with the Windows home the caller names as a home directory. The cases are
//! in `tests/cases/drives.cases`.

mod common;

#[test]
fn a_path_through_a_drive_mount_is_judged_on_the_drive() {
    common::cases::check("drives");
}
