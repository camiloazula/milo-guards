//! zsh's precommand modifiers and `coproc` run the command after them, so
//! that command is judged like one that stands alone, and decides the
//! line's effect. A modifier turns zsh's own flags off, never bash's.

mod common;

use common::{check, check_effect, posix};
use milo_guards_shell::{Effect, Reach, Rule, Shell};

/// The command after a modifier or `coproc` is read where the shell runs it:
/// past the name, the `{` words, `NAME=value` words and `!`. The loop,
/// conditional and function forms are cut up by the grammar with the body
/// behind a program named `do`, `then` or `{`, zsh reads a `{` stuck to a
/// word as a group where the grammar reads `{rm` as a program, and the
/// grammar takes the words after a redirect's target for more targets: none
/// of these can be read.
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
            // The program inside a group.
            "coproc { { ls; }; }",
            "coproc NAME { { ls; }; }",
            "coproc { FOO=1 ls; }",
            "coproc { ! ls; }",
            "coproc NAME { ! ls; }",
            "coproc FOO=1 ls",
            "coproc { > out; ls; }",
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
            // A compound command after `coproc`.
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
            // The program inside a group, and a compound command there.
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
            // Braces stuck to a word.
            ("coproc {rm -rf ~;}", Rule::Unreadable),
            ("coproc {{rm -rf ~;};}", Rule::Unreadable),
            ("coproc NAME {rm -rf ~;}", Rule::Unreadable),
            ("coproc { {rm -rf ~;}; }", Rule::Delete),
            ("coproc {ls;}", Rule::Unreadable),
            // Assignments and a bang before the command, as without `coproc`.
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
            // A command after a redirect.
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

/// What they run decides the effect; an assignment in front of the command
/// is a variable set, as it is without `coproc`.
#[test]
fn what_they_run_decides_the_effect() {
    let paths = posix();
    check_effect(
        Shell::Posix,
        &paths,
        Effect::ReadsOnly(Reach::Workspace),
        &[
            "noglob ls *.txt",
            "nocorrect ls",
            "- ls",
            "coproc cat",
            "coproc LANG=C ls",
        ],
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
            "coproc LANG=C rm -rf ~",
            "coproc { { rm -rf ~; }; }",
        ],
    );
    check_effect(
        Shell::Posix,
        &paths,
        Effect::Unknown,
        &[
            "noglob $CMD",
            "coproc PATH=/x ls",
            "coproc FOO=1 ls",
            "coproc NAME { PATH=/x ls; }",
        ],
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
            "setopt globdots; time nocorrect unsetopt globdots; rm -rf *git",
            "setopt globdots; nocorrect nocorrect unsetopt globdots; rm -rf *git",
            "setopt globdots; noglob - unsetopt globdots; rm -rf *git",
            "setopt globdots; - noglob unsetopt globdots; rm -rf *git",
            "setopt globdots; builtin - unsetopt globdots; rm -rf *git",
        ],
        &[
            // `nocorrect` is a reserved word: after any wrapper but a leading
            // `time` or `nocorrect` zsh does not find it and the flag stays on.
            (
                "setopt globdots; noglob nocorrect unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; - nocorrect unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; builtin nocorrect unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; builtin - nocorrect unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
            (
                "setopt globdots; time builtin nocorrect unsetopt globdots; rm -rf *git",
                Rule::Delete,
            ),
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
