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
            // Other quoting of the delimiter.
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
