//! How a machine spells another system's drives (`Paths::drive_mounts`):
//! WSL's `/mnt/c`, Git Bash's `/c`, Cygwin's `/cygdrive/c`, each placed where
//! the drive's path lands once the caller names the mount, and the Windows
//! home a WSL caller names (`Paths::windows_home`). The cases are in
//! `tests/cases/drives.cases`.

mod common;

#[test]
fn a_mounted_drive_is_placed_where_the_drive_lands() {
    common::cases::check("drives");
}
