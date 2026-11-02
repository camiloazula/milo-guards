//! In PowerShell the grammar reads `>`, `>>`, `2>` to `6>`, `*>` and their
//! doubled forms as redirect operators, but not `1>`, `7>`, or a `>` glued to
//! its word (`x>f`): those come out as words. They are redirects all the
//! same, so each writes its file, and a word that might be one and cannot be
//! told apart makes the line unknown.

mod common;

use common::{check, check_effect, windows};
use milo_guards_shell::{Effect, Rule, Shell};

#[test]
fn a_redirect_the_grammar_reads_as_a_word_writes_its_file() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Inside the workspace, with and without the stream number.
            "echo x > out.txt",
            "echo x 1> out.txt",
            "echo x 1>out.txt",
            "echo x 1>> out.txt",
            "echo x 1>>out.txt",
            "echo x>out.txt",
            "echo x>>out.txt",
            "echo x 2> err.txt 1> out.txt",
            "echo x 1> out.txt 2> err.txt",
            "Write-Output x 1> out.txt",
            "Set-Location sub 1> out.txt",
            "Get-Content a>out.txt",
            // The null device and the null value write nothing.
            "echo x 1> $null",
            "echo x 1>$null",
            "echo x 2>$null",
            "echo x 1> NUL",
            // A merge, a string and a comment are no redirect.
            "echo x 2>&1",
            "echo x 1>&2",
            "echo \"x>..\\y.txt\"",
            "echo 'x>..\\y.txt'",
            "echo \"a\",\"b>..\\y.txt\"",
            // `Set-Location sub` has moved by the time the next command runs.
            "Set-Location sub; echo x 1> ..\\x.txt",
        ],
        &[
            ("echo x 1> ..\\x.txt", Rule::Overwrite),
            ("Write-Output x 1> ..\\x.txt", Rule::Overwrite),
            ("echo x>..\\x.txt", Rule::Overwrite),
            ("Set-Location sub 1> ..\\x.txt", Rule::Overwrite),
            // Every stream the shell has, and the ones it does not.
            ("echo x 2> ..\\x.txt", Rule::Overwrite),
            ("echo x 3> ..\\x.txt", Rule::Overwrite),
            ("echo x 4> ..\\x.txt", Rule::Overwrite),
            ("echo x 5> ..\\x.txt", Rule::Overwrite),
            ("echo x 6> ..\\x.txt", Rule::Overwrite),
            ("echo x *> ..\\x.txt", Rule::Overwrite),
            ("echo x 7> ..\\x.txt", Rule::Overwrite),
            ("echo x 0> ..\\x.txt", Rule::Overwrite),
            ("echo x 12> ..\\x.txt", Rule::Overwrite),
            // Appending.
            ("echo x 1>> ..\\x.txt", Rule::Overwrite),
            ("echo x 2>> ..\\x.txt", Rule::Overwrite),
            ("echo x *>> ..\\x.txt", Rule::Overwrite),
            ("echo x>>..\\x.txt", Rule::Overwrite),
            // Glued to the file.
            ("echo x 1>..\\x.txt", Rule::Overwrite),
            ("echo x 2>..\\x.txt", Rule::Overwrite),
            ("echo x *>..\\x.txt", Rule::Overwrite),
            ("echo x 1>>..\\x.txt", Rule::Overwrite),
            ("echo x >..\\x.txt", Rule::Overwrite),
            ("echo x1>..\\x.txt", Rule::Overwrite),
            ("Get-Content a>..\\x.txt", Rule::Overwrite),
            ("echo \"x\" 1>..\\x.txt", Rule::Overwrite),
            // The file is another kind of word.
            ("echo x 1> \"..\\x.txt\"", Rule::Overwrite),
            ("echo x 1> '..\\x.txt'", Rule::Overwrite),
            ("echo x 1> C:\\Windows\\x.txt", Rule::Overwrite),
            ("echo x 1>C:\\Windows\\x.txt", Rule::Overwrite),
            ("echo x 1> ~\\x.txt", Rule::Overwrite),
            ("echo x 1>~\\x.txt", Rule::Overwrite),
            ("echo x 1>$HOME", Rule::Overwrite),
            ("echo x 1>$env:USERPROFILE\\x.txt", Rule::Overwrite),
            ("echo x 1> $env:USERPROFILE\\x.txt", Rule::Overwrite),
            // Among more redirects, pipes and moves.
            ("echo x 1> out.txt 2>..\\err.txt", Rule::Overwrite),
            ("echo x 1> ..\\x.txt 1> out.txt", Rule::Overwrite),
            (
                "Get-Content f 1> ..\\x.txt | Set-Content g",
                Rule::Overwrite,
            ),
            ("Set-Location ..; echo x 1> x.txt", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_word_that_may_be_a_redirect_and_cannot_be_told_apart_is_unknown() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            // No file after the operator, or two operators in one word.
            ("echo x 1>", Rule::Unknown),
            ("echo x a>b>c", Rule::Unknown),
            ("echo x 1>..\\a>b", Rule::Unknown),
            // A quote or an escape in the word hides where the file starts.
            ("echo x 1>\"..\\x.txt\"", Rule::Unknown),
            ("echo x 1>'..\\x.txt'", Rule::Unknown),
            ("echo x 1>..\\x`.txt", Rule::Unknown),
            ("echo x\"a\">..\\x.txt", Rule::Unknown),
            // The name of the command.
            ("echo>..\\x.txt", Rule::Unknown),
        ],
    );
}

#[test]
fn a_redirect_in_a_word_is_never_reads_only() {
    check_effect(
        Shell::PowerShell,
        &windows(),
        Effect::Changes,
        &[
            "echo x 1> out.txt",
            "echo x 1> ..\\x.txt",
            "echo x>..\\x.txt",
            "Set-Location sub 1> ..\\x.txt",
            "Write-Output x 1> ..\\x.txt",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows(),
        Effect::Unknown,
        &["echo x 1>", "echo x a>b>c"],
    );
}
