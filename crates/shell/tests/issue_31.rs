//! Two more ways to let a wildcard match a hidden name: `GLOBIGNORE` set by
//! an expansion (`${GLOBIGNORE:=x}`) or by `++` in arithmetic, and zsh's
//! `(D)` glob qualifier, which does it for one pattern.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn an_expansion_that_assigns_globignore_turns_hidden_names_on() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Empty, or not an assignment, or not `GLOBIGNORE`.
            ": ${GLOBIGNORE:=}; rm -rf *git",
            ": ${GLOBIGNORE=}; rm -rf *git",
            ": ${GLOBIGNORE:=''}; rm -rf *git",
            ": ${GLOBIGNORE:-x}; rm -rf *git",
            ": ${GLOBIGNORE:+x}; rm -rf *git",
            ": ${GLOBIGNORE-x}; rm -rf *git",
            ": ${GLOBIGNORE:?x}; rm -rf *git",
            ": ${GLOBIGNORE}; rm -rf *git",
            ": ${GLOBIGNORE:0:1}; rm -rf *git",
            ": ${GLOBIGNOREX:=x}; rm -rf *git",
            ": ${XGLOBIGNORE:=x}; rm -rf *git",
            ": ${OTHER:=x}; rm -rf *git",
            "echo ${GLOBIGNORE}; rm -rf *git",
            // The assignment comes after the wildcard is read.
            "rm -rf *git; : ${GLOBIGNORE:=x}",
            "rm -rf *git && : ${GLOBIGNORE:=x}",
            // Turned off again, where the line is sure to run it.
            ": ${GLOBIGNORE:=x}; unset GLOBIGNORE; rm -rf *git",
            // Not the variable.
            "(( GLOBIGNORE == 1 )); rm -rf *git",
            "(( x++ )); rm -rf *git",
            "(( -GLOBIGNORE )); rm -rf *git",
            // `let` reads each word as arithmetic: naming the variable, a
            // comparison, or another variable does not set it.
            "let GLOBIGNORE; rm -rf *git",
            "let GLOBIGNORE<=1; rm -rf *git",
            "let x++; rm -rf *git",
            "let XGLOBIGNORE++; rm -rf *git",
            "let GLOBIGNORE=; rm -rf *git",
            "let x=GLOBIGNORE+1; rm -rf *git",
            "echo '${GLOBIGNORE:=x}'; rm -rf *git",
            // With the option on, a pattern that cannot match a hidden name
            // is as safe as it was.
            ": ${GLOBIGNORE:=x}; rm -f *.o",
            ": ${GLOBIGNORE:=x}; rm -f build/*.o",
            "(( GLOBIGNORE++ )); rm -f *.o",
        ],
        &[
            (": ${GLOBIGNORE:=x}; rm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE=x}; rm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE:=x} && rm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE:=x}\nrm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE:=$x}; rm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE:=x*}; rm -rf *git", Rule::Delete),
            (": ${GLOBIGNORE[0]:=x}; rm -rf *git", Rule::Delete),
            ("echo ${GLOBIGNORE:=x}; rm -rf *git", Rule::Delete),
            ("echo \"${GLOBIGNORE:=x}\"; rm -rf *git", Rule::Delete),
            ("x=${GLOBIGNORE:=y}; rm -rf *git", Rule::Delete),
            ("x=\"${GLOBIGNORE:=y}\"; rm -rf *git", Rule::Delete),
            ("export x=${GLOBIGNORE:=y}; rm -rf *git", Rule::Delete),
            ("true ${GLOBIGNORE:=x} && rm -rf *git", Rule::Delete),
            ("[[ -n ${GLOBIGNORE:=x} ]]; rm -rf *git", Rule::Delete),
            (
                "for v in ${GLOBIGNORE:=x}; do :; done; rm -rf *git",
                Rule::Delete,
            ),
            // Expanded before the command's own wildcards are.
            ("rm -rf ${GLOBIGNORE:=x}*git", Rule::Delete),
            ("rm ${GLOBIGNORE:=x} -rf *git", Rule::Delete),
            // Where it reaches: a script that inherits it, a listing, a
            // function body.
            (": ${GLOBIGNORE:=x}; bash -c 'rm -rf *git'", Rule::Delete),
            ("bash -c ': ${GLOBIGNORE:=x}; rm -rf *git'", Rule::Delete),
            ("sh -c ': ${GLOBIGNORE:=x}; rm -rf *git'", Rule::Delete),
            (
                ": ${GLOBIGNORE:=x}; ls -d *git | xargs rm -rf",
                Rule::Delete,
            ),
            ("f() { rm -rf *git; }; : ${GLOBIGNORE:=x}; f", Rule::Delete),
            ("f() { : ${GLOBIGNORE:=x}; }; f; rm -rf *git", Rule::Delete),
            ("eval ': ${GLOBIGNORE:=x}'; rm -rf *git", Rule::Delete),
            // Not sure to run, which does not matter for an assignment.
            ("true || : ${GLOBIGNORE:=x}; rm -rf *git", Rule::Delete),
            (
                "if true; then : ${GLOBIGNORE:=x}; fi; rm -rf *git",
                Rule::Delete,
            ),
            // Not certain to be unset again.
            (
                ": ${GLOBIGNORE:=x}; true || unset GLOBIGNORE; rm -rf *git",
                Rule::Delete,
            ),
            // The arithmetic forms, which turn an empty variable into 1 or -1.
            ("(( GLOBIGNORE=1 )); rm -rf *git", Rule::Delete),
            ("(( GLOBIGNORE++ )); rm -rf *git", Rule::Delete),
            ("(( GLOBIGNORE-- )); rm -rf *git", Rule::Delete),
            ("(( ++GLOBIGNORE )); rm -rf *git", Rule::Delete),
            ("(( --GLOBIGNORE )); rm -rf *git", Rule::Delete),
            ("x=$(( GLOBIGNORE++ )); rm -rf *git", Rule::Delete),
            ("echo $(( GLOBIGNORE+=2 )); rm -rf *git", Rule::Delete),
            ("(( GLOBIGNORE += 1 )); rm -rf *git", Rule::Delete),
            // `let` does the same with each of its words, `++` and `+=`
            // included, quoted or not, and in any part of a word.
            ("let GLOBIGNORE=1; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE++; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE--; rm -rf *git", Rule::Delete),
            ("let ++GLOBIGNORE; rm -rf *git", Rule::Delete),
            ("let --GLOBIGNORE; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE+=1; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE-=1; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE*=2; rm -rf *git", Rule::Delete),
            ("let \"GLOBIGNORE+=1\"; rm -rf *git", Rule::Delete),
            ("let 'GLOBIGNORE += 1'; rm -rf *git", Rule::Delete),
            ("let \"GLOBIGNORE++\"; rm -rf *git", Rule::Delete),
            ("let '++ GLOBIGNORE'; rm -rf *git", Rule::Delete),
            ("let \"GLOBIGNORE[0]+=1\"; rm -rf *git", Rule::Delete),
            ("let x=1,GLOBIGNORE-=1; rm -rf *git", Rule::Delete),
            ("let x=GLOBIGNORE++; rm -rf *git", Rule::Delete),
            ("let x=GLOBIGNORE=1; rm -rf *git", Rule::Delete),
            ("let a=1 GLOBIGNORE+=1; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE+=$x; rm -rf *git", Rule::Delete),
            ("let GLOBIGNORE++ && rm -rf *git", Rule::Delete),
        ],
    );
}

#[test]
fn a_d_glob_qualifier_lets_that_commands_wildcards_match_hidden_names() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A pattern that cannot match a hidden name stays as safe as
            // it was.
            "rm -rf *.o(D)",
            "rm -f *.o(D) *.a(D)",
            "rm -f src/*.o(D)",
            "rm -rf *.o(.D)",
            "rm -rf *.o(D.)",
            "rm -rf *.o(D/)",
            "rm -rf *.o(oD)",
            "rm -rf build/*(D)",
            "rm -rf target*(D)",
            "rm -rf *.o(^D)",
            "rm -rf **/*.o(D)",
            "rm -rf ***/*.o(D)",
            // `**/` takes in the folder itself, and a name without a dot
            // that way is still no hidden name.
            "rm -rf **/*git",
            "rm -rf **/*.o",
            // The history of a folder below the workspace is not the
            // workspace's, with `dotglob` as with the qualifier.
            "cd sub; rm -rf *git(D)",
            "rm -rf */*git(D)",
            "ls *git(D)",
            "cat *.md(D)",
            "echo *git(D)",
            // The qualifier is for its own command.
            "rm -rf *.o(D); rm -rf *git",
            "rm -rf *.o(D) && rm -rf *git",
            "rm -rf *.o(D)\nrm -rf *git",
            "ls *.o(D); rm -rf *git",
            "echo *.o(D) | rm -rf *git",
            "( rm -rf *.o(D) ); rm -rf *git",
            // Not a qualifier: quoted, escaped, or another construct.
            "echo '*git(D)'",
            "echo \"*git(D)\"",
            "echo '*git(D)'; rm -rf *git",
            "echo \"x(D)\"; rm -rf *git",
            "echo x\\(D\\); rm -rf *git",
            "echo $(echo D); rm -rf *git",
            "echo <(echo D); rm -rf *git",
            "echo $((1 + 2)); rm -rf *git",
            "(echo D); rm -rf *git",
            "( rm -rf *.o )",
            "x=(D); rm -rf *git",
            "x=(a D); rm -rf *git",
            "f() { rm -rf *.o; }; f",
            "f(){ rm -rf *.o; }; f",
            "if (( 1 )); then rm -rf *.o; fi",
            "case x in (D) rm -rf *.o;; esac",
            "case x in D) rm -rf *.o;; esac",
            "rm -rf *.o # *git(D)",
            "rm -rf *.o #(D)",
            // A heredoc body is text.
            "cat <<EOF\n*git(D)\nEOF\nrm -rf *.o",
            // A qualifier on a word that is only a name.
            "ls .git(D)",
            "ls README.md(D)",
        ],
        &[
            ("rm -rf *git(D)", Rule::Delete),
            ("rm -rf -- *git(D)", Rule::Delete),
            ("rm -r *git(D)", Rule::Delete),
            ("rm -rf *git(D) x", Rule::Delete),
            ("rm -rf x *git(D)", Rule::Delete),
            ("rm -rf *git(D);", Rule::Delete),
            ("rm -rf *git(D);rm -rf x", Rule::Delete),
            ("rm -rf *git(D)&", Rule::Delete),
            ("rm -rf *git(D)|cat", Rule::Delete),
            ("rm -rf *git(D) > out", Rule::Delete),
            ("rm -rf *git(D)>out", Rule::Delete),
            ("rm -rf *git(D) 2>&1", Rule::Delete),
            ("echo hi; rm -rf *git(D)", Rule::Delete),
            ("echo hi && rm -rf *git(D)", Rule::Delete),
            ("rm -rf *git(D)\necho hi", Rule::Delete),
            ("( rm -rf *git(D) )", Rule::Delete),
            ("{ rm -rf *git(D); }", Rule::Delete),
            ("if true; then rm -rf *git(D); fi", Rule::Delete),
            ("f() { rm -rf *git(D); }; f", Rule::Delete),
            ("sudo rm -rf *git(D)", Rule::Delete),
            ("env rm -rf *git(D)", Rule::Delete),
            ("noglob rm -rf *git(D)", Rule::Delete),
            ("command rm -rf *git(D)", Rule::Delete),
            ("time rm -rf *git(D)", Rule::Delete),
            // Other spellings of the pattern and the qualifier.
            ("rm -rf ?git(D)", Rule::Delete),
            ("rm -rf *git*(D)", Rule::Delete),
            ("rm -rf *.*(D)", Rule::Delete),
            ("rm -rf *(D)", Rule::Delete),
            ("rm -rf ./*git(D)", Rule::Delete),
            ("rm -rf [.]git(D)", Rule::Delete),
            ("rm -rf *git(.D)", Rule::Delete),
            ("rm -rf *git(D.)", Rule::Delete),
            ("rm -rf *git(D/)", Rule::Delete),
            ("rm -rf *git(Dn)", Rule::Delete),
            ("rm -rf *git(^D)", Rule::Delete),
            ("rm -rf *git(D,.)", Rule::Delete),
            ("rm -rf *git(mh-1D)", Rule::Delete),
            ("rm -rf *git(-D)", Rule::Delete),
            // `**/` and `***/` match no folder too, so `*git` is read in the
            // workspace folder itself, where `.git` is.
            ("rm -rf **/*git(D)", Rule::Delete),
            ("rm -rf **/*git(D/)", Rule::Delete),
            ("rm -rf ./**/*git(D)", Rule::Delete),
            ("rm -rf ***/*git(D)", Rule::Delete),
            ("rm -rf **/**/*git(D)", Rule::Delete),
            ("ls -d **/*git(D) | xargs rm -rf", Rule::Delete),
            ("shopt -s dotglob globstar; rm -rf **/*git", Rule::Delete),
            // The names a listing or a loop hands on.
            ("ls -d *git(D) | xargs rm -rf", Rule::Delete),
            ("for f in *git(D); do rm -rf \"$f\"; done", Rule::Delete),
            ("for f in *git(D); do rm -rf $f; done", Rule::Delete),
            // A script it starts reads the qualifier itself.
            ("bash -c 'rm -rf *git(D)'", Rule::Delete),
            ("zsh -c 'rm -rf *git(D)'", Rule::Delete),
            ("sh -c \"rm -rf *git(D)\"", Rule::Delete),
            ("zsh -c 'echo hi; rm -rf *git(D)'", Rule::Delete),
            ("eval 'rm -rf *git(D)'", Rule::Delete),
            ("echo $(rm -rf *git(D))", Rule::Delete),
            // A redirect target.
            ("cat x > *git(D)", Rule::Overwrite),
            // Reading a key, and the qualifier lets `*` match `.ssh`.
            ("cat ~/.ssh/*(D)", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_qualifier_that_can_run_code_or_is_not_read_stays_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // `e` runs a string and `+` a function: not read, and so risky as
            // they were before.
            ("rm -rf *(e:'rm -rf ~':)", Rule::Unreadable),
            ("rm -rf *git(De:'x':)", Rule::Unreadable),
            ("rm -rf *git(D+f)", Rule::Unreadable),
            ("rm -rf *git(+f)", Rule::Unreadable),
            ("rm -rf *git(D:t)", Rule::Unreadable),
            ("rm -rf *git(D[1])", Rule::Unreadable),
            ("rm -rf *git(D$x)", Rule::Unreadable),
            ("rm -rf *git(D)x", Rule::Unreadable),
            // No `D`.
            ("rm -rf *.o(N)", Rule::Unreadable),
            ("rm -rf *.o(.)", Rule::Unreadable),
            ("rm -rf *.o()", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_qualifier_with_p_stays_unreadable() {
    // `P` adds the string it holds as a word before each match, so `mv
    // *(DP./usr.)` is `mv /usr` and every name: not a pattern of names.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("mv *(DP./usr.)", Rule::Unreadable),
            ("mv *(DP./root.)", Rule::Unreadable),
            ("mv *(DP./usr/local/bin.)", Rule::Unreadable),
            ("mv *(DP./opt.)", Rule::Unreadable),
            ("chmod *(DP.777.)", Rule::Unreadable),
            ("chmod *(DP.-R.P.777.)", Rule::Unreadable),
            ("chown *(DP.-R.P.root.)", Rule::Unreadable),
            ("ln *(DP.-sf.P./usr/bin/x.)", Rule::Unreadable),
            ("cp *(DP.-t.) /tmp/x", Rule::Unreadable),
            ("rm -rf *.o(PD)", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_word_with_an_extended_glob_operator_stays_unreadable() {
    // With `extendedglob` (on in an rc file, or by `setopt`), `^x` is every
    // name but `x`, `a~b` is `a` but not `b`, and `#` repeats: `.git` is
    // among them. A word with one is not read as a plain pattern.
    check(
        Shell::Posix,
        &posix(),
        &[
            // The `^` in the qualifier is the qualifier's, and `~` first is
            // the home folder, which the qualifier is still read after.
            "rm -rf *.o(^D)",
            "ls ~/*.o(D)",
            // Only the word in front of the qualifier is looked at.
            "echo ^x; rm -rf *.o(D)",
            "echo a~b; rm -rf *.o(D)",
        ],
        &[
            ("zsh -o extendedglob -c 'rm -rf ^x(D)'", Rule::Unreadable),
            (
                "zsh -o extendedglob -c 'rm -rf *git~x(D)'",
                Rule::Unreadable,
            ),
            (
                "zsh -c 'setopt extendedglob; rm -rf ^x(D)'",
                Rule::Unreadable,
            ),
            ("setopt extendedglob; rm -rf ^x(D)", Rule::Unreadable),
            ("setopt extended_glob; rm -rf ^x(D)", Rule::Unreadable),
            ("setopt extendedglob; rm -rf *git~x(D)", Rule::Unreadable),
            ("setopt extendedglob; rm -rf .#git(D)", Rule::Unreadable),
            // Without the option on in the line, an rc file may have it.
            ("rm -rf ^x(D)", Rule::Unreadable),
            ("rm -rf *git~x(D)", Rule::Unreadable),
            ("rm -rf ^*.o(D)", Rule::Unreadable),
            ("rm -rf .#git(D)", Rule::Unreadable),
            ("rm -rf (.|)git(D)", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_qualifier_stays_on_a_command_that_turns_its_words_into_a_script() {
    // `eval`, `watch` and `trap` run the words after zsh has expanded the
    // pattern with its qualifier, so the `rm` inside is handed `.git`.
    check(
        Shell::Posix,
        &posix(),
        &[
            // A pattern that cannot match a hidden name stays as safe as it was.
            "eval rm -rf *.o(D)",
            "watch rm -f *.o(D)",
            "trap rm\\ -f\\ *.o(D) EXIT",
            // The qualifier is for its own command, and not for the next.
            "eval echo *.o(D); rm -rf *git",
            "watch echo *.o(D); rm -rf *git",
            // A script that is only a string has no qualifier.
            "eval 'rm -rf *.o'",
            "eval echo hi",
        ],
        &[
            ("eval rm -rf *git(D)", Rule::Delete),
            ("eval rm -rf -- *git(D)", Rule::Delete),
            ("eval 'rm -rf' *git(D)", Rule::Delete),
            ("eval echo hi\\; rm -rf *git(D)", Rule::Delete),
            ("command eval rm -rf *git(D)", Rule::Delete),
            ("builtin eval rm -rf *git(D)", Rule::Delete),
            ("noglob eval rm -rf *git(D)", Rule::Delete),
            ("time eval rm -rf *git(D)", Rule::Delete),
            ("x=$(eval rm -rf *git(D))", Rule::Delete),
            ("watch rm -rf *git(D)", Rule::Delete),
            ("watch -n 1 rm -rf *git(D)", Rule::Delete),
            ("trap rm\\ -rf\\ *git(D) EXIT", Rule::Delete),
            // The same, with the option for the whole line.
            ("setopt globdots; eval rm -rf *git", Rule::Delete),
            ("setopt globdots; watch rm -rf *git", Rule::Delete),
        ],
    );
}

#[test]
fn a_posix_class_in_a_bracket_matches_a_hidden_name() {
    // `[[:alpha:]]` is one letter, `[[:punct:]]` one punctuation character
    // (a dot is one): with the qualifier, or `dotglob`, they match `.git`.
    check(
        Shell::Posix,
        &posix(),
        &[
            // A class that does not take what the pattern needs there.
            "rm -rf *[[:digit:]]it(D)",
            "rm -rf *g[[:digit:]]t(D)",
            "rm -rf [[:alpha:]]git(D)",
            "rm -rf *[![:alpha:]]it(D)",
            "rm -rf *[[:upper:]]it(D)",
            "rm -rf *[[:space:]]it(D)",
            "rm -rf *[[:alpha:]].o(D)",
            "shopt -s dotglob; rm -rf *[[:digit:]]it",
            "shopt -s dotglob; rm -rf [[:alpha:]]git",
            // The dot is hidden unless the option is on.
            "rm -rf *[[:alpha:]]it",
            "rm -rf [[:punct:]]git",
            "rm -rf [.[:alpha:]]git",
        ],
        &[
            ("rm -rf *[[:alpha:]]it(D)", Rule::Delete),
            ("rm -rf ?[[:alpha:]]it(D)", Rule::Delete),
            ("rm -rf [[:punct:]]git(D)", Rule::Delete),
            ("rm -rf [.[:alpha:]]git(D)", Rule::Delete),
            ("rm -rf [[:punct:][:alpha:]]git(D)", Rule::Delete),
            ("rm -rf *g[[:alpha:]]t(D)", Rule::Delete),
            ("rm -rf *[[:alpha:]]*(D)", Rule::Delete),
            ("rm -rf [[:punct:]]*(D)", Rule::Delete),
            ("rm -rf *[[:lower:]]it(D)", Rule::Delete),
            ("rm -rf *[[:alnum:]]it(D)", Rule::Delete),
            ("rm -rf *[[:graph:]]it(D)", Rule::Delete),
            ("rm -rf [![:alpha:]]git(D)", Rule::Delete),
            ("rm -rf [![:digit:]]git(D)", Rule::Delete),
            ("rm -rf [[:alpha:][:punct:]]git(D)", Rule::Delete),
            // Not read exactly, so taken as any character.
            ("rm -rf *[[:nosuch:]]it(D)", Rule::Delete),
            ("rm -rf [[=a=]]*(D)", Rule::Delete),
            ("rm -rf [[.-.]]git(D)", Rule::Delete),
            ("rm -rf [a-[.z.]]git(D)", Rule::Delete),
            // With the option for the whole line.
            ("shopt -s dotglob; rm -rf *[[:alpha:]]it", Rule::Delete),
            ("shopt -s dotglob; rm -rf [[:punct:]]git", Rule::Delete),
            ("shopt -s dotglob; rm -rf [.[:alpha:]]git", Rule::Delete),
            ("setopt globdots; rm -rf *[[:alpha:]]it", Rule::Delete),
        ],
    );
}

#[test]
fn an_arithmetic_chain_that_assigns_globignore_turns_hidden_names_on() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The variable is read, or compared, and not assigned to.
            "(( x = GLOBIGNORE )); rm -rf *git",
            "(( x = y = GLOBIGNORE )); rm -rf *git",
            "(( x = GLOBIGNORE == 1 )); rm -rf *git",
            "(( x = XGLOBIGNORE = 1 )); rm -rf *git",
            "x=$(( x = GLOBIGNORE )); rm -rf *git",
            "(( x = GLOBIGNORE = 1 )); rm -f *.o",
        ],
        &[
            ("(( x = GLOBIGNORE = 1 )); rm -rf *git", Rule::Delete),
            ("$(( x = GLOBIGNORE = 1 )); rm -rf *git", Rule::Delete),
            ("echo $(( x = GLOBIGNORE = 1 )); rm -rf *git", Rule::Delete),
            ("(( x = y = GLOBIGNORE = 1 )); rm -rf *git", Rule::Delete),
            ("(( GLOBIGNORE = x = 1 )); rm -rf *git", Rule::Delete),
            ("(( x += GLOBIGNORE += 1 )); rm -rf *git", Rule::Delete),
            ("(( x = (GLOBIGNORE = 1) )); rm -rf *git", Rule::Delete),
        ],
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn a_long_run_of_posix_class_openers_in_a_word_is_read_in_a_bound() {
    // A bracket whose only `]`s close `[:a:]`-style elements has no end, and
    // each `[` after it must not scan to the end of the word again: a run of
    // them read in minutes before.
    let runs = [
        "[[:a:]".repeat(10_600),
        "[[.x.]".repeat(10_600),
        "[[=x=]".repeat(10_600),
        "[[:alpha:]".repeat(6_300),
        "[[::]".repeat(12_700),
    ];
    for run in runs {
        // `mv` takes a part of the run (the work per word is high in the
        // debug build); the others take the whole of it.
        let short = &run[..12_000];
        for line in [
            format!("mv {short} x"),
            format!("rm -rf {run}"),
            format!("rm -rf **/{run}(D)"),
            format!("shopt -s dotglob; rm -rf **/{run}"),
        ] {
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            let started = std::time::Instant::now();
            let assessment = milo_guards_shell::classify(&line, Shell::Posix, &posix());
            let took = started.elapsed();
            // The read is linear: well under two seconds in the debug build.
            // The quadratic one took ten seconds for the `mv` line alone in
            // a release build, and minutes at the full length.
            assert!(
                took < std::time::Duration::from_secs(6),
                "took {took:?} for a line of {} bytes: {}",
                line.len(),
                &line[..line.len().min(40)]
            );
            drop(assessment);
        }
    }
}

#[test]
fn a_bracket_with_a_collating_element_is_also_read_as_zsh_does() {
    // zsh has no `[.x.]` or `[=x=]`: `[` and `.` are members and the first
    // `]` closes the bracket, so `[[.x.]*git` is one class and `*git`, and
    // with `globdots` or `(D)` it matches `.git`. Bash reads a plain `[` for
    // it. A line that can be read by zsh is judged by zsh's reading too.
    check(
        Shell::Posix,
        &posix(),
        &[
            // The dot is hidden unless an option or the qualifier is on.
            "rm -rf [[.x.]*git",
            "rm -rf [[=.=]*git",
            // Neither reading matches `.git`.
            "setopt globdots; rm -f [[.x.]*.o",
            "rm -f [[.x.]*.o(D)",
            "setopt globdots; rm -f [[=x=]*.o",
        ],
        &[
            ("setopt globdots; rm -rf [[.x.]*git", Rule::Delete),
            ("setopt globdots; rm -rf [[.x.]git", Rule::Delete),
            ("setopt globdots; rm -rf [a[.x.]git", Rule::Delete),
            ("setopt globdots; rm -rf [[=.=]*git", Rule::Delete),
            ("set -o globdots; rm -rf [[.x.]*git", Rule::Delete),
            ("zsh -o globdots -c 'rm -rf [[.x.]*git'", Rule::Delete),
            ("zsh -c 'setopt globdots; rm -rf [[.x.]*git'", Rule::Delete),
            // The qualifier exists only in zsh.
            ("rm -rf [[.x.]*git(D)", Rule::Delete),
            ("rm -rf [[=.=]*git(D)", Rule::Delete),
            ("rm -rf [[.x.]git(D)", Rule::Delete),
            ("rm -rf [a[.x.]git(D)", Rule::Delete),
            ("mv [[.x.]*git(D) /tmp/x", Rule::Delete),
        ],
    );
}
