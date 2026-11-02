//! A signal to process 0 goes to every process in the caller's own group, the
//! program that ran the line included, and one to a negative id goes to a
//! whole group. `kill` judges both as stopping the system, in the shell and
//! in the inline process calls alike; an id it cannot read for sure is judged
//! the same way. An ordinary process, a job and signal 0 are unchanged.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn killing_process_zero_or_a_group_is_stopping_the_caller() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("kill -9 0", Rule::StopSystem),
            ("kill 0", Rule::StopSystem),
            ("kill -- -1234", Rule::StopSystem),
            ("kill -9 -- -1234", Rule::StopSystem),
            ("kill -s KILL 0", Rule::StopSystem),
            ("kill -n 9 0", Rule::StopSystem),
            ("kill -TERM 0", Rule::StopSystem),
            ("kill -SIGKILL 0", Rule::StopSystem),
            ("kill --signal=KILL 0", Rule::StopSystem),
            ("kill -s KILL -- -5", Rule::StopSystem),
            ("kill -1234", Rule::StopSystem),
            ("kill -9 -1", Rule::StopSystem),
            ("kill 4242 0", Rule::StopSystem),
            ("kill 00", Rule::StopSystem),
            ("kill +0", Rule::StopSystem),
            ("sudo kill -9 0", Rule::StopSystem),
            ("trap 'kill 0' INT", Rule::StopSystem),
            ("bash -c 'kill -9 0'", Rule::StopSystem),
            ("xargs kill", Rule::StopSystem),
            ("kill $pid", Rule::StopSystem),
            ("kill -9 $(pgrep node)", Rule::StopSystem),
            ("kill 99999999999999999999", Rule::StopSystem),
            ("kill 4294967296", Rule::StopSystem),
            ("kill '*'", Rule::StopSystem),
        ],
    );
}

#[test]
fn killing_an_ordinary_process_or_a_job_is_unchanged() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill 1234",
            "kill 4242",
            "kill -9 4242",
            "kill -TERM 4242",
            "kill -s KILL 4242",
            "kill %1",
            "kill -9 %1",
            "kill -0 4242",
            "kill -0 0",
            "kill -0 $pid",
            "kill -s 0 $pid",
            "kill -l",
            "kill -L",
            "kill $!",
            "kill \"$!\"",
            "kill $$",
            "kill $PPID",
        ],
        &[
            ("kill 1", Rule::StopSystem),
            ("kill -9 -1", Rule::StopSystem),
        ],
    );
}

#[test]
fn the_inline_process_calls_are_judged_the_same_way() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("python3 -c 'import os; os.kill(0, 9)'", Rule::StopSystem),
            ("python3 -c 'import os; os.killpg(0, 9)'", Rule::StopSystem),
            (
                "python3 -c 'import os; os.kill(-1234, 9)'",
                Rule::StopSystem,
            ),
            ("node -e 'process.kill(0, 9)'", Rule::StopSystem),
            ("node -e 'process.kill(-1234, 9)'", Rule::StopSystem),
            ("deno eval 'Deno.kill(0, \"SIGKILL\")'", Rule::StopSystem),
        ],
    );
}
