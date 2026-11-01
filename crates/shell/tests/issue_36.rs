//! zsh's precommand modifiers and `coproc` run the command after them, so
//! that command is judged like one that stands alone.

mod common;

use common::{check, check_effect, posix};
use milo_guards_shell::{Effect, Reach, Rule, Shell};

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
        Effect::ReadsOnly(Reach::Workspace),
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

/// The group's commands are read where the shell runs them: past the name,
/// the `{` words, `NAME=value` words and `!`, and a loop, conditional or
/// function inside the group is as unreadable as one after a bare `coproc`.
#[test]
fn coproc_reads_the_program_inside_a_group() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "coproc { { ls; }; }",
            "coproc NAME { { ls; }; }",
            "coproc { FOO=1 ls; }",
            "coproc { ! ls; }",
            "coproc NAME { ! ls; }",
            "coproc FOO=1 ls",
            "coproc { > out; ls; }",
        ],
        &[
            (
                "coproc NAME { while true; do rm -rf ~; done; }",
                Rule::Unreadable,
            ),
            (
                "coproc NAME { if true; then rm -rf ~; fi; }",
                Rule::Unreadable,
            ),
            (
                "coproc NAME { for i in 1; do rm -rf ~; done; }",
                Rule::Unreadable,
            ),
            (
                "coproc { { while true; do rm -rf ~; done; }; }",
                Rule::Unreadable,
            ),
            (
                "coproc { ! while true; do rm -rf ~; done; }",
                Rule::Unreadable,
            ),
            ("coproc { { rm -rf ~; }; }", Rule::Delete),
            ("coproc NAME { { rm -rf ~; }; }", Rule::Delete),
            ("coproc { { { rm -rf ~; }; }; }", Rule::Delete),
        ],
    );
}

/// What stands before the command in a simple command or a group is read
/// past, as it is without `coproc`.
#[test]
fn coproc_reads_past_assignments_and_a_bang() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("coproc FOO=1 rm -rf ~", Rule::Delete),
            ("coproc A=1 B=2 rm -rf ~", Rule::Delete),
            ("coproc PATH=/x rm -rf ~", Rule::Delete),
            ("coproc FOO+=1 rm -rf ~", Rule::Delete),
            ("coproc FOO=1 { rm -rf ~; }", Rule::Delete),
            ("coproc ! rm -rf ~", Rule::Delete),
            ("coproc { FOO=1 rm -rf ~; }", Rule::Delete),
            ("coproc { ! rm -rf ~; }", Rule::Delete),
            ("coproc { FOO=1 BAR=2 ! rm -rf ~; }", Rule::Delete),
            ("coproc { FOO=1 { rm -rf ~; }; }", Rule::Delete),
            ("coproc NAME { ! rm -rf ~; }", Rule::Delete),
            ("coproc NAME { FOO=1 rm -rf ~; }", Rule::Delete),
            ("coproc FOO=1 sudo rm -rf ~", Rule::Elevated),
            ("coproc $X=1 rm -rf ~", Rule::Unknown),
            ("coproc GLOBIGNORE=x bash -c 'rm -rf *git'", Rule::Delete),
        ],
    );
}

/// The grammar takes the words after a redirect's target for more targets,
/// so a command that follows a redirect in a `coproc` is not among the
/// arguments: it cannot be read.
#[test]
fn coproc_command_after_a_redirect_is_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("coproc { 2>/dev/null rm -rf ~; }", Rule::Unreadable),
            ("coproc { > out rm -rf ~; }", Rule::Unreadable),
            ("coproc { < in rm -rf ~; }", Rule::Unreadable),
            ("coproc { 2>&1 rm -rf ~; }", Rule::Unreadable),
            ("coproc NAME { 2>/dev/null rm -rf ~; }", Rule::Unreadable),
            ("coproc NAME { > out rm -rf ~; }", Rule::Unreadable),
            ("coproc > out rm -rf ~", Rule::Unreadable),
            ("coproc 2>/dev/null rm -rf ~", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_coproc_assignment_is_a_variable_set_for_effect() {
    let paths = posix();
    check_effect(
        Shell::Posix,
        &paths,
        Effect::Unknown,
        &[
            "coproc PATH=/x ls",
            "coproc FOO=1 ls",
            "coproc NAME { PATH=/x ls; }",
        ],
    );
    check_effect(
        Shell::Posix,
        &paths,
        Effect::ReadsOnly(Reach::Workspace),
        &["coproc LANG=C ls", "env LANG=C ls"],
    );
    check_effect(
        Shell::Posix,
        &paths,
        Effect::Changes,
        &["coproc LANG=C rm -rf ~", "coproc { { rm -rf ~; }; }"],
    );
}

/// `noglob`, `nocorrect` and `-` are zsh's modifiers: in bash and sh they
/// are not found, so the builtin after them never runs and bash's flag
/// stays on. zsh's own flag does go off.
#[test]
fn a_zsh_modifier_turns_zshs_flag_off_and_never_bashs() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "setopt globdots; noglob unsetopt globdots; rm -rf *git",
            "setopt globdots; nocorrect unsetopt globdots; rm -rf *git",
            "setopt globdots; - unsetopt globdots; rm -rf *git",
            "setopt globdots; time noglob unsetopt globdots; rm -rf *git",
            "setopt globdots; builtin noglob unsetopt globdots; rm -rf *git",
            "shopt -s dotglob; command shopt -u dotglob; rm -rf *git",
        ],
        &[
            (
                "setopt globdots; noglob command unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; command unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; nocorrect command unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; command noglob unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; noglob time unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; nocorrect time unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; - time unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "shopt -s dotglob; noglob shopt -u dotglob; rm -rf *git",
                Rule::Delete,
            ),
            (
                "shopt -s dotglob; nocorrect shopt -u dotglob; rm -rf *git",
                Rule::Delete,
            ),
            (
                "shopt -s dotglob; - shopt -u dotglob; rm -rf *git",
                Rule::Delete,
            ),
            (
                "shopt -s dotglob; noglob command shopt -u dotglob; rm -rf *git",
                Rule::Delete,
            ),
        ],
    );
}
