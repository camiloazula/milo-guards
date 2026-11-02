//! Where a `cd`, `pushd` or cmd `cd` leaves the line, so the line that
//! follows is judged from there.
//!
//! `pushd` takes its own options before the folder, as `cd` does: `-n` (the
//! stack changes and the shell stays), `-L` and `-P`. None of them is the
//! folder, and an option the guard does not know makes the folder only known
//! when it runs.
//!
//! cmd's `cd` without `/d` sets another drive's working directory and does
//! not leave the drive the line is on, so a later relative path is judged
//! against where the line really is. A path on a drive's own working
//! directory (`D:x`) is unknown, and a `cd` with more than one word goes to
//! the words joined as written.

mod common;

use common::{check, check_effect, exact, lists, posix};
use milo_guards_shell::{effect_paths, Effect, Paths, Reach, Rule, Shell};

/// A machine whose working directory is on `C:` and whose workspaces are on
/// `C:` and `D:`.
fn two_drives() -> Paths {
    Paths::new(
        r"C:\Users\me\repo",
        r"C:\Users\me",
        [r"C:\Users\me\repo", r"D:\ws"],
    )
}

fn deletes(lines: &[&'static str]) -> Vec<(&'static str, Rule)> {
    lines.iter().map(|line| (*line, Rule::Delete)).collect()
}

#[test]
fn an_option_of_pushd_is_not_the_folder_it_moves_to() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // `-n` only changes the stack: what follows runs where the line
            // began.
            "pushd -n ~/.ssh && cat id_rsa",
            "pushd -n /etc && cat shadow",
            "pushd -n ~",
            "pushd -n",
            "pushd -nP ~/.ssh && cat README.md",
            "pushd -n -P ~/.ssh && cat README.md",
            "pushd -n -- ~/.ssh && cat README.md",
            "pushd -n +1 && cat README.md",
            "pushd -n $dir && cat README.md",
        ],
        &[
            ("pushd -P ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -L ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -PL ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P -L ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.ssh; cat id_rsa", Rule::ReadSecret),
            ("pushd -P -- ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -- ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.ssh >/dev/null; cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.aws && cat credentials", Rule::ReadSecret),
            ("pushd ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("cd -P ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -L /etc && cat shadow", Rule::ReadSecret),
            ("pushd -P /etc && cat shadow", Rule::ReadSecret),
        ],
    );
}

#[test]
fn the_line_after_pushd_is_read_from_where_pushd_leaves_it() {
    let src = "/home/me/work/repo/src";
    lists(
        Shell::Posix,
        &posix(),
        &[
            // `-n` does not move the line.
            (
                "pushd -n ~/.ssh && cat id_rsa",
                vec![exact("/home/me/work/repo/id_rsa")],
            ),
            (
                "pushd -n -P /etc && cat shadow",
                vec![exact("/home/me/work/repo/shadow")],
            ),
            (
                "pushd -nP ~/.ssh && cat src/a.rs",
                vec![exact("/home/me/work/repo/src/a.rs")],
            ),
            ("pushd -n ~/.ssh", vec![]),
            // `-P`, `-L` and `--` move it to the folder written.
            (
                "pushd -P ~/.ssh && cat id_rsa",
                vec![exact("/home/me/.ssh"), exact("/home/me/.ssh/id_rsa")],
            ),
            (
                "pushd -L /etc && cat shadow",
                vec![exact("/etc"), exact("/etc/shadow")],
            ),
            (
                "pushd -P src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -P src && cat ../../x",
                vec![exact(src), exact("/home/me/work/repo/src/../../x")],
            ),
            (
                "pushd -PL src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -- src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -- -P && cat a",
                vec![
                    exact("/home/me/work/repo/-P"),
                    exact("/home/me/work/repo/-P/a"),
                ],
            ),
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Workspace),
        &[
            "pushd -n ~/.ssh && cat id_rsa",
            "pushd -n ~",
            "pushd -P src && cat a.rs",
            "pushd -P src && cat ../x",
        ],
    );
    // `cat ../../x` from `src` reads outside the workspace.
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Beyond),
        &[
            "pushd -P src && cat ../../x",
            "pushd -L src && cat ../../x",
            "pushd -P ~/.ssh && cat id_rsa",
        ],
    );
    // An option the guard does not know: nothing says where these go, so
    // what follows is judged from nowhere known, never from a folder named
    // for the option, and no path is listed.
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Unknown,
        &[
            "pushd -q ~/.ssh && cat id_rsa",
            "pushd -s ~/.ssh && cat id_rsa",
            "pushd --help && cat id_rsa",
            "pushd --foo ~/.ssh && cat id_rsa",
            "pushd -P -q ~/.ssh && cat id_rsa",
            "pushd -Pq ~/.ssh && cat id_rsa",
            "pushd +1 && cat id_rsa",
            "pushd -1 && cat id_rsa",
            "pushd - && cat id_rsa",
            "pushd && cat id_rsa",
            "pushd -P && cat id_rsa",
            "pushd -P $dir && cat id_rsa",
            "pushd $opt ~/.ssh && cat id_rsa",
            "pushd -- && cat id_rsa",
        ],
    );
}

#[test]
fn no_option_of_pushd_is_listed_as_a_path() {
    let paths = posix();
    for line in [
        "pushd -P src && ls",
        "pushd -L src && ls",
        "pushd -n -P src && ls",
        "pushd -n src && ls",
        "pushd -n",
        "pushd -nL",
        "pushd -- src && ls",
    ] {
        let list = effect_paths(line, Shell::Posix, &paths).unwrap();
        for read in &list {
            let name = read.path.file_name().unwrap_or_default().to_string_lossy();
            assert!(!name.starts_with('-'), "{line}: {list:?}");
        }
    }
}

#[test]
fn a_cmd_cd_to_another_drive_moves_the_line_only_with_d() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            // With `/d`, or on the same drive, the line moves.
            r"cd /d D:\ws\a & rd /s /q b",
            r"cd /D D:\ws\a & rd /s /q b",
            r"chdir /d D:\ws\a & rd /s /q b",
            r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q c",
            r"cd C:\Users\me\repo\a & rd /s /q b",
            r"cd c:\Users\me\repo\a & rd /s /q b",
            r"cd sub & del *.obj",
            r"cd sub\deep & rd /s /q build",
            r"pushd D:\ws\a & rd /s /q b",
            r"D: & cd D:\ws\a & rd /s /q b",
            // A drive alone without `/d` shows its folder and moves nothing.
            r"cd D: & del *.obj",
            r"cd C: & del *.obj",
        ],
        &deletes(&[
            // Without `/d` the line stays where it was.
            r"cd D:\ws\a\b\c & rd /s /q ..\..",
            r"chdir D:\ws\a\b\c & rd /s /q ..\..",
            r"cd d:\ws\a\b\c & rd /s /q ..\..",
            r"cd D:\ws\a & rd /s /q ..\..\..\Users",
            // It stays on the first drive, so the folder is judged there.
            r"cd /d D:\ws\a & cd C:\x & rd /s /q ..\..",
            r"cd D:\ws\a & cd C:\x & rd /s /q ..\..",
            // With `/d`, or on the same drive, a `..` goes up from where it
            // moved.
            r"cd /d D:\ws\a & rd /s /q ..\..",
            r"cd /d D:\ws\a & rd /s /q ..\..\..",
            r"cd C:\Users\me\repo\sub & rd /s /q ..\..",
            r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q ..\..",
            r"pushd D:\ws\a\b\c & rd /s /q ..\..\..\..",
            r"cd /d D: & del *.obj",
            // Each really deletes under `C:\Windows`: the move to `D:` does
            // not run (a branch that is not taken, a pipe stage, `start`) or
            // fails, so the `cd C:\Windows` that follows really moves the
            // line.
            r"ver || cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"dir q && cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"if exist q (cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
            r"(if exist q cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
            r"ver | cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"start cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"ver || pushd D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"ver || D: & cd D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"cd /d D:\ws\nonexist & cd C:\Windows & rd /s /q System32",
            r"pushd D:\ws\a & cd C:\Windows & del /q System32\x.dll",
            r"cd /d D:\ws\a & cd C:\Users\me\repo\x & rd /s /q b",
        ]),
    );
}

#[test]
fn a_cmd_cd_that_may_have_changed_the_drive_leaves_the_place_unknown() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &deletes(&[
            // `/d` that is not first, or glued to the path: whether cmd reads
            // it is not known.
            r"cd D:\ws\a /d & rd /s /q b",
            r"cd /dD:\ws\a & rd /s /q b",
            // The drive the line is on is not known after `popd`, a path
            // only known when it runs, or a program only known when it runs.
            r"popd & cd D:\ws\a & rd /s /q b",
            r"cd %X% & cd D:\ws\a & rd /s /q b",
            r"%X% & cd D:\ws\a & rd /s /q b",
        ]),
    );
    // A working directory on no drive: the drive the line is on is not known.
    check(
        Shell::Cmd,
        &Paths::new(r"\\host\share\repo", r"C:\Users\me", [r"D:\ws"]),
        &[],
        &deletes(&[r"cd D:\ws\a & rd /s /q b"]),
    );
}

#[test]
fn a_drive_relative_path_is_unknown_in_cmd() {
    // On the drive the line is on, and on another one.
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            ("del C:x", Rule::Delete),
            ("rd /s /q C:x", Rule::Delete),
            ("del C:*.obj", Rule::Delete),
            (r"del C:..\x", Rule::Delete),
            ("del C:", Rule::Delete),
            ("del D:x", Rule::Delete),
            ("rd /s /q D:b", Rule::Delete),
            (r"del D:..\x", Rule::Delete),
            ("del D:", Rule::Delete),
            (r"cd sub & del C:x", Rule::Delete),
            (r"cd D:\ws\a & del D:x", Rule::Delete),
            (r"cd D:\ws\a & rd /s /q D:b", Rule::Delete),
            (r"cd D:\ws\a && rd /s /q D:b", Rule::Delete),
            (r"(cd D:\ws\a) & rd /s /q D:b", Rule::Delete),
            (r"(cd D:\ws\a & rd /s /q D:b)", Rule::Delete),
            (r"cd D:\ws\a && echo ok & rd /s /q D:b", Rule::Delete),
            (r"dir x & cd D:\ws\a & rd /s /q D:b", Rule::Delete),
            // A write is as unknown as a delete.
            ("echo hi >> C:x", Rule::Overwrite),
            ("echo hi > D:x", Rule::Overwrite),
        ],
    );
    // The working directory is on `D:`.
    check(
        Shell::Cmd,
        &Paths::new(r"D:\work\repo", r"D:\Users\me", [r"D:\work\repo"]),
        &["del *.obj"],
        &deletes(&["del D:*.obj", "del D:x", "rd /s /q C:x"]),
    );
    // What the guard reads from the line's own folder when it matters is
    // still judged as it lands: a key is a key.
    check(
        Shell::Cmd,
        &Paths::new(r"C:\Users\me", r"C:\Users\me", [r"C:\Users\me\repo"]),
        &[],
        &[
            (r"type C:..\..\.ssh\config", Rule::ReadSecret),
            (r"type C:..\..\.ssh\id_rsa", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_cmd_cd_with_more_than_one_word_goes_to_the_words_joined_as_written() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            "cd My Folder & del *.obj",
            "chdir My Folder & del *.obj",
            "pushd My Folder & del *.obj",
            "cd /d My Folder & del *.obj",
            "cd My  Folder   & del *.obj",
            "cd a b c & del *.obj",
            r"cd My Folder\sub & del x",
            // The spaces are part of the name, so `..` goes up from it.
            r"cd x y\.. & del z",
            r"cd x %USERPROFILE%\.. & del z",
        ],
        &deletes(&[
            r"cd x y\..\..\.. & del z",
            r"cd /d x y\..\..\.. & del z",
            r"pushd x y\..\..\.. & del z",
            r"cd x y\..\.. & del z",
            // A word only known when it runs, or a later `/d`, leaves the
            // folder unknown.
            "cd x %X% & del z",
            "cd %X% y & del z",
            "cd My Folder %X% & del *.obj",
            "cd My /d Folder & del z",
        ]),
    );
}
