//! A redirect on a group, a branch, a loop or a function call is opened before
//! its body runs, so from the folder the line is in then, not from the one a
//! `cd` in the body leaves it in. `{ cd sub; cat; } < ../../.ssh/id_rsa` opens
//! the same key `cat ../../.ssh/id_rsa` does, and `{ cd ../..; ls; } > x`
//! writes `x` where the line is, not two folders up.

mod common;

use std::path::PathBuf;

use common::{check, path_disagreement, posix};
use milo_guards_shell::{effect_paths, How, ReadPath, Rule, Shell};

fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

#[test]
fn a_read_on_a_group_is_placed_from_where_the_group_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The key is not at the end of `../..` from `sub`.
            "{ cd ../..; cat; } < .ssh/id_rsa",
            "{ cd ../..; } < .ssh/id_rsa",
            "{ cd ../..; ls; } < .ssh/id_rsa",
            "{ cd ~; cat; } < .ssh/id_rsa",
            "{ cd sub; cat; } < ../x",
            // A group that does not move the line.
            "{ ls; } < ../x",
            // A subshell was already read this way.
            "(cd sub; cat) < ../x",
            // The commands after the group, and the ones in it, are placed
            // from where the line is then.
            "{ cd sub; }; cat < ../../.ssh/id_rsa",
            "{ cd sub; } && cat < ../../.ssh/id_rsa",
            "{ cd sub; cat < ../../.ssh/id_rsa; }",
            // After a `cd` the group starts in the folder it went to.
            "cd a; { cd b; } < ../../.ssh/id_rsa",
        ],
        &[
            ("{ cd sub; cat; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } 0< ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } <> ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; cd sub2; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ ls; cd sub; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ { cd sub; }; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } < ../../.ssh/id_rsa < ../x", Rule::ReadSecret),
            ("{ cd sub; } < ../x < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } < ../../.ssh/id_rsa | cat", Rule::ReadSecret),
            ("{ cd sub; } < ../../.ssh/id_rsa && ls", Rule::ReadSecret),
            ("ls; { cd sub; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("ls && { cd sub; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("{ cd sub; } < ~/.ssh/id_rsa", Rule::ReadSecret),
            // A subshell, as before.
            ("(cd sub) < ../../.ssh/id_rsa", Rule::ReadSecret),
            // After a `cd`, the folder the group starts in is that one.
            ("cd a; { cd b; } < ../../../.ssh/id_rsa", Rule::ReadSecret),
            (
                "{ cd a; { cd b; } < ../../../.ssh/id_rsa; }",
                Rule::ReadSecret,
            ),
            (
                "{ cd sub; } <<EOF < ../../.ssh/id_rsa\nx\nEOF",
                Rule::ReadSecret,
            ),
            (
                "{ cd sub; } <<-EOF < ../../.ssh/id_rsa\nx\nEOF",
                Rule::ReadSecret,
            ),
        ],
    );
}

#[test]
fn a_read_on_a_loop_or_a_branch_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "while read l; do cd ../..; done < .ssh/id_rsa",
            "if true; then cd ../..; fi < .ssh/id_rsa",
            "for x in 1; do cd ../..; done < .ssh/id_rsa",
            "while read l; do cd sub; done < ../x",
            "if true; then cd sub; fi < ../x",
            "case x in x) cd ../..;; esac < .ssh/id_rsa",
        ],
        &[
            (
                "while read l; do cd sub; done < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "until false; do cd sub; done < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "for x in 1; do cd sub; done < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "for ((i = 0; i < 1; i++)); do cd sub; done < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "if true; then cd sub; fi < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "if true; then ls; else cd sub; fi < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "case x in x) cd sub;; esac < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "while read l; do cd sub; done < ../../.ssh/id_rsa | cat",
                Rule::ReadSecret,
            ),
            (
                "ls || if true; then cd sub; fi < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
        ],
    );
}

#[test]
fn a_redirect_on_a_group_in_a_loop_or_after_a_cd_that_may_not_run_is_placed_from_both_folders() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // The first pass starts where the line is, the next where the
            // last one left it (`..` of `sub`, here the repository).
            (
                "for i in 1 2; do { cd sub; } < ../../.ssh/id_rsa; done",
                Rule::ReadSecret,
            ),
            // The first `cd` may not have run, and the line is then where
            // it began.
            (
                "ls || cd a; { cd b; } < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            ("ls || { cd sub; } < ../../.ssh/id_rsa", Rule::ReadSecret),
            (
                "f() { { cd sub; } < ../../.ssh/id_rsa; }; f",
                Rule::ReadSecret,
            ),
            (
                "if true; then { cd sub; } < ../../.ssh/id_rsa; fi",
                Rule::ReadSecret,
            ),
        ],
    );
}

#[test]
fn a_redirect_on_a_call_to_a_function_that_moves_the_line_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A function that does not move the line.
            "f() { cat; }; f < ../x",
            "f() { (cd sub; cat); }; f < ../x",
            // The function is not called.
            "f() { cd sub; cat; }; cat < ../x",
        ],
        &[
            (
                "f() { cd sub; cat; }; f < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            ("f() { cd sub; }; f < ../../.ssh/id_rsa", Rule::ReadSecret),
            (
                "function f { cd sub; cat; }; f < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "f() ( cd sub; cat ); f < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "f() { cd sub; }; command f < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "f() { cd sub; }; f < ../../.ssh/id_rsa | cat",
                Rule::ReadSecret,
            ),
            (
                "f() { cd sub; }; true && f < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            // In a group that is redirected.
            (
                "f() { cd sub; }; { f; cat; } < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "f() { cd sub; }; { f; } < ../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            // Called twice: the second call starts where the first left
            // the line.
            (
                "f() { cd sub; }; f; f < ../../../.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            ("f() { cd sub; }; f > ../x", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_write_on_a_group_a_loop_or_a_function_call_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A file in the folder the line is in is inside the workspace.
            "{ cd ../..; ls; } > x",
            "{ cd ../..; } > x",
            "{ cd ../..; } >> x",
            "for x in 1; do cd ../..; done > x",
            "while read l; do cd ../..; done > x",
            "if true; then cd ../..; fi > x",
            "{ cd sub; ls; } > out.txt",
            "{ ls; } > out.txt 2> out2.txt",
        ],
        &[
            ("{ cd sub; ls; } > ../x", Rule::Overwrite),
            ("{ cd sub; } > ../x", Rule::Overwrite),
            ("{ cd sub; } >> ../x", Rule::Overwrite),
            ("{ cd sub; } 2> ../x", Rule::Overwrite),
            ("{ cd sub; } &> ../x", Rule::Overwrite),
            ("for x in 1; do cd sub; done > ../x", Rule::Overwrite),
            ("while read l; do cd sub; done > ../x", Rule::Overwrite),
            ("if true; then cd sub; fi > ../x", Rule::Overwrite),
            ("case x in x) cd sub;; esac > ../x", Rule::Overwrite),
            ("{ cd sub; } > ../x | cat", Rule::Overwrite),
            ("(cd sub) > ../x", Rule::Overwrite),
            ("f() { cd sub; }; f > ../x", Rule::Overwrite),
            ("{ cd sub; } <<EOF > ../x\nx\nEOF", Rule::Overwrite),
        ],
    );
}

#[test]
fn the_paths_of_a_group_are_placed_from_where_it_starts() {
    let repo = "/home/me/work/repo";
    let paths = posix();
    let rows = [
        (
            "{ cd sub; cat; } < ../../.ssh/id_rsa",
            vec![
                exact(&format!("{repo}/../../.ssh/id_rsa")),
                exact(&format!("{repo}/sub")),
            ],
        ),
        (
            "{ cd ../..; cat; } < .ssh/id_rsa",
            vec![exact("/home/me"), exact(&format!("{repo}/.ssh/id_rsa"))],
        ),
        (
            "{ cd sub; } < ../x",
            vec![
                exact(&format!("{repo}/../x")),
                exact(&format!("{repo}/sub")),
            ],
        ),
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, Shell::Posix, &paths);
            let disagree = path_disagreement(Shell::Posix, &paths, line);
            (got.as_ref() != Some(want) || disagree.is_some())
                .then(|| format!("{line}\n    want {want:?}\n    got  {got:?}\n    {disagree:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
