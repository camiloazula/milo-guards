//! A redirect on a `cd`, `chdir`, `pushd`, `Set-Location` or cmd `cd` is
//! opened before the command runs, so its file is placed from the folder the
//! command starts in, not from the folder it goes to. `cd sub <
//! ../../.ssh/id_rsa` opens the same key `cat ../../.ssh/id_rsa` does, and
//! `cd ../.. < f` reads `f` where the line is, not two folders up.
//!
//! The lines and their answers are in `tests/cases/redirect_on_cd.cases`;
//! here are the paths a read lists and a long line of many redirects, whose
//! time is in `tests/timing.rs`.

mod common;

use common::lines::redirects_and_substitutions;
use common::{exact, lists, posix, windows};
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
fn many_redirects_and_substitutions_on_one_command_are_read_alike_by_each_reading() {
    // `effect`, `explain` and `effect_paths` agree with `classify` on the
    // line at the length limit and on the one a quarter as long, which
    // `timing.rs` compares the time of.
    for (shell, line, subs, redirects) in redirects_and_substitutions() {
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let big = line(subs, redirects);
        assert!(big.len() <= 64 * 1024, "{}", big.len());
        let small = line(subs / 4, redirects / 4);
        let _ = common::classify(&small, shell, &paths);
        let _ = common::classify(&big, shell, &paths);
    }
}
