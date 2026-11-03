//! A redirect on a `cd`, `chdir`, `pushd`, `Set-Location` or cmd `cd` is
//! opened before the command runs, so its file is placed from the folder the
//! command starts in, not from the folder it goes to. `cd sub <
//! ../../.ssh/id_rsa` opens the same key `cat ../../.ssh/id_rsa` does, and
//! `cd ../.. < f` reads `f` where the line is, not two folders up.
//!
//! The lines and their answers are in `tests/cases/redirect_on_cd.cases`;
//! here are the paths a read lists and the time a long line takes.

mod common;

use common::{exact, lists, posix, took, windows};
use milo_guards_shell::Shell;

#[test]
fn every_case_holds() {
    common::cases::check("redirect_on_cd");
}

#[test]
fn the_paths_of_a_cd_with_a_read_are_placed_from_where_it_starts() {
    let repo = "/home/me/work/repo";
    let key_then_sub = || {
        vec![
            exact(&format!("{repo}/../../.ssh/id_rsa")),
            exact(&format!("{repo}/sub")),
        ]
    };
    lists(
        Shell::Posix,
        &posix(),
        &[
            (
                "cd x < f",
                vec![exact(&format!("{repo}/f")), exact(&format!("{repo}/x"))],
            ),
            ("cd sub < ../../.ssh/id_rsa", key_then_sub()),
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
            // After `&&` or `|`.
            ("true && cd sub < ../../.ssh/id_rsa", key_then_sub()),
            ("true | cd sub < ../../.ssh/id_rsa", key_then_sub()),
            // After a here-document start.
            ("cd sub <<EOF < ../../.ssh/id_rsa\nx\nEOF", key_then_sub()),
            (
                "pushd sub <<EOF < ../../.ssh/id_rsa\nx\nEOF",
                key_then_sub(),
            ),
        ],
    );
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
    let lines: [Line; 9] = [
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
        // What a `cd`'s words and here-strings run is read from where it
        // starts, each time from the same place.
        (
            Shell::Posix,
            |subs, strings| {
                format!(
                    "cd sub{}{}",
                    " $(cat f)".repeat(subs),
                    " <<< \"$(cat g)\"".repeat(strings)
                )
            },
            2_500,
            1_500,
        ),
        (
            Shell::PowerShell,
            |subs, _| format!("Set-Location{}", " $(Get-Content f)".repeat(subs)),
            3_000,
            0,
        ),
        // In a loop, arguments that move the session in turn with ones that
        // read a file: each read from where the last one left it.
        (
            Shell::PowerShell,
            |pairs, _| {
                format!(
                    "foreach ($i in 1) {{ cd a{} }}",
                    " $(cd b) $(gc f)".repeat(pairs)
                )
            },
            3_600,
            0,
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
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let big = line(subs, redirects);
        assert!(big.len() <= 64 * 1024, "{}", big.len());
        let small = line(subs / 4, redirects / 4);
        // `effect`, `explain` and `effect_paths` agree with `classify` on
        // both lines.
        let _ = common::classify(&small, shell, &paths);
        let _ = common::classify(&big, shell, &paths);
        let mut last = (std::time::Duration::ZERO, std::time::Duration::ZERO);
        let linear = (0..3).any(|_| {
            last = (took(&small, shell, &paths), took(&big, shell, &paths));
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
