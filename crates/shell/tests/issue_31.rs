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
