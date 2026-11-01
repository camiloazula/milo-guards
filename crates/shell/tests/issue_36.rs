//! zsh's precommand modifiers and `coproc` run the command after them, so
//! that command is judged like one that stands alone.

mod common;

use common::{check, check_effect, posix};
use milo_guards_shell::{Effect, Rule, Shell};

#[test]
fn a_modifier_or_coproc_does_not_hide_the_command_it_runs() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "noglob ls *.txt",
            "nocorrect ls -la",
            "- ls",
            "coproc cat",
            "coproc { ls; }",
            "coproc NAME { ls *.txt; }",
            "noglob git status",
            "coproc cat < notes.txt",
            "coproc",
            "noglob",
            "coproc NAME cat",
        ],
        &[
            ("noglob rm -rf ~", Rule::Delete),
            ("nocorrect rm -rf ~", Rule::Delete),
            ("- rm -rf ~", Rule::Delete),
            ("noglob nocorrect rm -rf ~", Rule::Delete),
            ("noglob - rm -rf ~", Rule::Delete),
            ("coproc rm -rf ~", Rule::Delete),
            ("coproc { rm -rf ~; }", Rule::Delete),
            ("coproc NAME { rm -rf ~; }", Rule::Delete),
            ("coproc {\n rm -rf ~\n}", Rule::Delete),
            ("coproc NAME { cd ~; rm -rf x; }", Rule::Delete),
            ("coproc { rm -rf ~; } 2>&1", Rule::Delete),
            ("coproc ( rm -rf ~ )", Rule::Delete),
            ("sudo noglob rm -rf ~", Rule::Delete),
            ("coproc sudo rm -rf ~", Rule::Elevated),
            ("noglob rm -rf ~ && ls", Rule::Delete),
            ("echo hi | coproc rm -rf ~", Rule::Delete),
            ("coproc { $CMD; }", Rule::Unknown),
            ("noglob $CMD", Rule::Unknown),
        ],
    );
}

/// The loop, conditional and function forms are cut up by the grammar with
/// the body behind a program named `do`, `then` or `{`: not read.
#[test]
fn coproc_of_a_compound_command_is_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("coproc while true; do rm -rf ~; done", Rule::Unreadable),
            (
                "coproc NAME while true; do rm -rf ~; done",
                Rule::Unreadable,
            ),
            ("coproc until false; do rm -rf ~; done", Rule::Unreadable),
            ("coproc if true; then rm -rf ~; fi", Rule::Unreadable),
            ("coproc for i in 1; do rm -rf ~; done", Rule::Unreadable),
            (
                "coproc NAME for i in 1; do rm -rf ~; done",
                Rule::Unreadable,
            ),
            ("coproc case x in x) rm -rf ~;; esac", Rule::Unreadable),
            ("coproc function f { rm -rf ~; }", Rule::Unreadable),
        ],
    );
}

#[test]
fn what_they_run_decides_the_effect() {
    let paths = posix();
    check_effect(
        Shell::Posix,
        &paths,
        Effect::ReadsOnly,
        &["noglob ls *.txt", "nocorrect ls", "- ls", "coproc cat"],
    );
    check_effect(
        Shell::Posix,
        &paths,
        Effect::Changes,
        &[
            "noglob rm -rf ~",
            "- rm -rf ~",
            "coproc rm -rf ~",
            "coproc { rm -rf ~; }",
        ],
    );
    check_effect(Shell::Posix, &paths, Effect::Unknown, &["noglob $CMD"]);
}
