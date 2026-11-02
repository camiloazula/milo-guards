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
            ("kill -- -$$", Rule::StopSystem),
            ("kill -9 -- -$$", Rule::StopSystem),
            ("kill -$$", Rule::StopSystem),
            ("kill -9 -$$", Rule::StopSystem),
            ("kill -TERM -$$", Rule::StopSystem),
            ("kill -s TERM -$$", Rule::StopSystem),
            ("sh -c 'kill -- -$$'", Rule::StopSystem),
            ("bash -c 'kill -9 -$$'", Rule::StopSystem),
            ("trap 'kill -- -$$' EXIT", Rule::StopSystem),
            ("trap 'kill -TERM -$$' EXIT", Rule::StopSystem),
            ("set -m; kill -- -$$", Rule::StopSystem),
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
            "kill -0 -9 0",
            "kill -0 -1234",
            "kill -0 -- -1",
            "kill -s 0 -- -1",
            "kill -s 0 -$$ -1",
            "kill -0 -$$ 1",
            "kill -l -s 9 -1",
            "kill -l",
            "kill -L",
            "kill $!",
            "kill \"$!\"",
            "kill $$",
        ],
        &[
            ("kill 1", Rule::StopSystem),
            ("kill -9 -1", Rule::StopSystem),
            ("kill $PPID", Rule::StopSystem),
            ("kill -9 $PPID", Rule::StopSystem),
            ("kill -9 \"$PPID\"", Rule::StopSystem),
            ("kill -9 ${PPID}", Rule::StopSystem),
        ],
    );
}

#[test]
fn a_signal_0_read_first_does_not_hide_a_later_signal_option() {
    // The shell keeps reading signal options after the first, the last one
    // winning, so these send a real signal.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("kill -s 0 -s KILL -1", Rule::StopSystem),
            ("kill -s 0 -s KILL 1", Rule::StopSystem),
            ("kill -s 0 -s KILL -- -1", Rule::StopSystem),
            ("kill -s 0 -sKILL -1", Rule::StopSystem),
            ("kill -n 0 -n 9 -1", Rule::StopSystem),
            ("kill -0 -s KILL -1", Rule::StopSystem),
            ("kill -0 -s KILL 1", Rule::StopSystem),
            ("kill -s 0 -s KILL 0", Rule::StopSystem),
            ("kill -n 0 -n 9 0", Rule::StopSystem),
            ("kill -0 -s KILL 0", Rule::StopSystem),
            ("kill -0 -sKILL 0", Rule::StopSystem),
            ("kill -0 -n 9 0", Rule::StopSystem),
            ("kill -0 -n9 0", Rule::StopSystem),
            ("kill -00 -s 9 0", Rule::StopSystem),
            ("kill -s 0 -s 9 -- -1234", Rule::StopSystem),
            ("kill -s 0 -s $SIG 0", Rule::StopSystem),
        ],
    );
}

#[test]
fn a_listing_option_counts_only_as_the_first_word() {
    // The shells and the BSD program read only the first word as a listing
    // option; later it is an id they skip (zsh warns and goes on), so the ids
    // after it are still killed.
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill -l",
            "kill -L",
            "kill --list",
            "kill -l 9",
            "kill -l -s 9 -1",
        ],
        &[
            ("kill -9 -l -1", Rule::StopSystem),
            ("kill -s 9 -l -1", Rule::StopSystem),
            ("kill -9 -L -1", Rule::StopSystem),
            ("kill -9 --list -1", Rule::StopSystem),
            ("kill -s KILL --list -- -1", Rule::StopSystem),
            ("kill -9 -l 0", Rule::StopSystem),
            ("kill -TERM -l -1234", Rule::StopSystem),
            ("sudo kill -9 -l -1", Rule::StopSystem),
        ],
    );
}

#[test]
fn a_long_option_after_signal_0_may_send_a_real_signal() {
    // `--signal` is read anywhere among the options, the last one winning.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("kill -0 --signal 9 -1", Rule::StopSystem),
            ("kill -0 --signal=KILL -1", Rule::StopSystem),
            ("kill -0 --timeout 1000 KILL -1", Rule::StopSystem),
            ("sudo kill -0 --signal KILL -1", Rule::StopSystem),
        ],
    );
}

#[test]
fn an_unknown_word_among_the_options_after_signal_0_is_not_signal_0() {
    // An expansion may hold `-s` and a name, read as an option.
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill -0 $pid",
            "kill -0 \"$pid\"",
            "kill -0 \"$(cat app.pid)\"",
            "kill -s 0 $pid",
        ],
        &[
            ("kill -0 $X KILL -1", Rule::StopSystem),
            ("kill -0 \"$S\" -1", Rule::StopSystem),
            ("kill -s 0 $more -- -1", Rule::StopSystem),
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
