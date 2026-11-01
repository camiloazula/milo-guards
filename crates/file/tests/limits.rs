//! What the guard does not see, kept as rows so a change to any of them is a
//! decision and not an accident. A row here is a limit named in
//! `docs/design/file.md`, not a goal: a symlink is judged by its own name,
//! and core's table lists places known to hold a secret, not every one.

mod common;

use common::{exactly, posix, risky, safe, windows};
use milo_guards_file::{Access, Paths, Protected, Rule};

#[test]
fn a_symlink_is_judged_by_its_own_name() {
    // A link in the workspace to `~/.ssh` looks like any file in it. (The
    // kernel's own links, `/proc/self/root` and `cwd`, are refused by name.)
    safe(
        Access::Read,
        &posix(),
        &["link-to-ssh/id_rsa", "/dev/stdin"],
    );
}

#[test]
fn a_place_not_in_the_table_is_read_for_what_it_says() {
    safe(
        Access::Read,
        &posix(),
        &[
            ".env",
            "config/secrets.yml",
            "~/.mozilla/firefox/x/cookies.sqlite",
            "/mnt/c/Users/me/.ssh/id_rsa",
        ],
    );
}

#[test]
fn a_name_that_differs_by_unicode_normal_form_is_a_different_name() {
    // A file system that ignores the difference between `é` and `e` and an
    // accent reads these as one folder; the guard compares code points. The
    // path is still beyond the workspace, but it is `write_outside`, not the
    // caller's `write_protected`.
    let paths = Paths::new("/home/josé/x", "/home/josé", ["/home/josé/x"]).with_protected([
        Protected::folder("/home/josé/.agent", "the agent's settings"),
    ]);
    exactly(
        Access::Write,
        &paths,
        &[
            ("/home/josé/.agent/x", &[Rule::WriteProtected][..]),
            ("/home/jose\u{301}/.agent/x", &[Rule::WriteOutside][..]),
        ],
    );
}

#[test]
fn a_path_as_another_system_spells_it_is_read_as_this_one_does() {
    // Git Bash's `/c/Users/...` is `C:\c\Users\...` to Windows itself.
    safe(
        Access::Read,
        &windows(),
        &[
            "/c/Users/me/.ssh/id_rsa",
            "/cygdrive/c/Users/me/.ssh/id_rsa",
        ],
    );
}

#[test]
fn a_windows_reserved_device_name_is_a_file_here() {
    safe(Access::Write, &windows(), &["COM1", "PRN", "AUX", "LPT1"]);
}

#[test]
fn a_workspace_of_the_root_makes_a_system_write_safe() {
    // The caller chose it: a workspace is where the agent may write, and the
    // root holds everything. Keys and the repository's history stay what
    // they are.
    let paths = Paths::new("/", "/home/me", ["/"]);
    exactly(
        Access::Write,
        &paths,
        &[
            ("/etc/hosts", &[][..]),
            ("/usr/local/bin/x", &[][..]),
            ("/home/me/notes.txt", &[][..]),
            ("/home/me/.ssh/authorized_keys", &[Rule::WriteSensitive][..]),
            ("/home/me/.zshrc", &[Rule::WriteSensitive][..]),
            ("/etc/shadow", &[Rule::WriteSensitive][..]),
            (".git/config", &[Rule::WriteSensitive][..]),
        ],
    );
}

#[test]
fn a_company_onedrive_folder_is_not_the_onedrive_folder() {
    // The profile moved by `OneDrive - Org` is beyond the workspace, but not
    // named a startup file.
    exactly(
        Access::Write,
        &windows(),
        &[(
            r"C:\Users\me\OneDrive - Org\Documents\PowerShell\profile.ps1",
            &[Rule::WriteOutside][..],
        )],
    );
}

#[test]
fn a_few_places_are_accepted_false_alarms_for_a_read() {
    // The folder and the descriptors folder themselves, and a process's
    // status: anything under `/dev` and `/proc` that is not on the short
    // whitelist is refused.
    risky(
        Access::Read,
        &posix(),
        &[
            ("/dev", Rule::ReadSecret),
            ("/dev/fd", Rule::ReadSecret),
            ("/proc/self/status", Rule::ReadSecret),
        ],
    );
    // A workspace directly under `/home` is a home directory to core, so its
    // own `.npmrc` is a login.
    let paths = Paths::new("/home/ws", "/home/me", ["/home/ws"]);
    risky(
        Access::Read,
        &paths,
        &[
            (".npmrc", Rule::ReadSecret),
            ("/home/ws/.ssh/config", Rule::ReadSecret),
        ],
    );
    safe(Access::Read, &paths, &["src/main.rs", "package.json"]);
}
