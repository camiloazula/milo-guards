//! The shell ends a here-document only at a line that is exactly its
//! delimiter (for `<<-`, after leading tabs). The grammar also ends it at a
//! line only near the delimiter: ` PY`, `PY `, `PY #...`, `PY ;...`. Then the
//! guard judges the rest as shell commands while the program reads it as its
//! input, so such a line is Unreadable, not guessed at.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_here_document_line_near_its_delimiter_is_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A leading space.
            (
                "python3 - <<'PY'\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<PY\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<-'PY'\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\ntry:\n pass\nexcept NameError:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // A trailing space, a comment, a `;`, a tab after the word.
            (
                "python3 - <<'PY'\nimport shutil\nPY \nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY #x\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY ;x\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY\t\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // The delimiter in quotes ends the body for neither the grammar
            // nor the shell, but is refused all the same (one simple rule).
            (
                "python3 - <<'PY'\nimport shutil\n'PY'\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\n\"PY\"\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // `<<-` strips tabs only: a space in front is near.
            (
                "python3 - <<-'PY'\nimport shutil\n\t PY\nshutil.rmtree('/home/me')\n\tPY",
                Rule::Unreadable,
            ),
            // Every reader of a here-document.
            (
                "bash <<'EOF'\necho a\n EOF\nrm -rf /home/me\nEOF",
                Rule::Unreadable,
            ),
            (
                "sh -s <<'EOF'\necho a\nEOF \nrm -rf /home/me\nEOF",
                Rule::Unreadable,
            ),
            (
                "node <<'EOF'\nlet a = 1\n EOF\nrequire('fs').rmSync('/home/me')\nEOF",
                Rule::Unreadable,
            ),
            (
                "psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // A reader that is not special still gets the same answer.
            ("cat <<'EOF'\nx\n EOF\nrm -rf /home/me\nEOF", Rule::Unreadable),
        ],
    );
}

/// The commonest way an agent writes a here-document is inside `"$(…)"`
/// (`git commit -m "$(cat <<'EOF' …)"`), so the same line in double quotes, or
/// in a backtick in double quotes, is as unreadable as outside them.
#[test]
fn a_here_document_in_a_double_quoted_substitution_is_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "x=\"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // The end line with a trailing space or a comment.
            (
                "echo \"$(psql <<'EOF'\nselect 1;\nEOF \ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(psql <<'EOF'\nselect 1;\nEOF #\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // An unquoted delimiter, and `<<-`.
            (
                "echo \"$(psql <<EOF\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(psql <<-EOF\n\tselect 1;\n EOF\n\tdrop table t;\n\tEOF\n)\"",
                Rule::Unreadable,
            ),
            // A backtick in double quotes.
            (
                "echo \"`psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n`\"",
                Rule::Unreadable,
            ),
            (
                "x=\"`psql <<'EOF'\nselect 1;\nEOF \ndrop table t;\nEOF\n`\"",
                Rule::Unreadable,
            ),
            // Other readers.
            (
                "echo \"$(mysql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(sqlite3 db <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(bash <<'EOF'\necho a\n EOF\nrm -rf /home/me\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // In a substitution in a substitution, in a subshell, in a pipe,
            // with words around it.
            (
                "echo \"$(echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\")\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$( (psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n) )\"",
                Rule::Unreadable,
            ),
            (
                "echo \"a\" \"$(psql <<'EOF' | cat\nselect 1;\n EOF\ndrop table t;\nEOF\n)\" \"b\"",
                Rule::Unreadable,
            ),
            (
                "echo \"`echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"`\"",
                Rule::Unreadable,
            ),
            // The same line outside the quotes.
            (
                "echo $(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)",
                Rule::Unreadable,
            ),
        ],
    );
}

#[test]
fn a_here_document_in_a_double_quoted_substitution_that_ends_exactly_reads_as_before() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"",
            "x=\"$(cat <<'EOF'\nx\nEOF\n)\"",
            "echo \"$(cat <<EOF\nx\nEOF\n)\"",
            "echo \"`cat <<'EOF'\nx\nEOF\n`\"",
            "echo \"$(cat <<-EOF\n\tx\n\tEOF\n)\"",
            "echo \"$(psql <<'EOF'\nselect 1;\nEOF\n)\" && echo done",
            // A line that holds a different word is body.
            "echo \"$(sqlite3 db <<'EOF'\nselect 1;\nPY\nEOF\n)\" \"$(echo ')')\"",
        ],
        &[],
    );
}

#[test]
fn a_here_document_that_ends_exactly_reads_as_before() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cat <<'EOF'\nx\nEOF",
            "cat <<EOF\nx\nEOF",
            "cat <<-EOF\n\tx\n\tEOF",
            "cat <<-EOF\n\t\tx\n\t\tEOF",
            // A line that only holds the delimiter's letters is body.
            "cat <<'EOF'\nXEOF\nEOF",
            "cat <<'EOF'\nthe EOF marker\nEOF",
            // A command after the end is read as a command.
            "cat <<'EOF'\nx\nEOF\necho done",
        ],
        &[],
    );
}
