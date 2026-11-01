//! Everyday lines that hold a lot of `<<` or `&`, which the counts that
//! guard the grammars' time must not take for tangled ones.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

/// Source with a stream operator on each line, written into a file by a
/// here-document or a PowerShell here-string.
fn cpp_lines() -> String {
    let mut lines = String::new();
    for n in 1..=130 {
        lines.extend(["std::cout << \"line ", &n.to_string(), "\" << std::endl;\n"]);
    }
    lines
}

#[test]
fn a_file_of_stream_operators_written_by_a_here_document_is_safe() {
    // Each line of the body holds two `<<`, none of them a here-document;
    // 130 of them are more than the limit on here-documents, counted over
    // the text.
    let heredoc = format!("cat > main.cpp <<'EOF'\n{}EOF\n", cpp_lines());
    // And a body with a delimiter of another shape, or an indented one.
    let tabbed = format!("cat > main.cpp <<-EOF\n{}\tEOF\n", cpp_lines());
    let quoted = format!("cat > main.cpp <<\"END\"\n{}END\n", cpp_lines());
    // Three hundred, each closed: here-documents after a command, on lines
    // of their own, are read in linear time, so any number of them are fine.
    let closed = "cat <<EOF\nx\nEOF\n".repeat(300);
    let many = "cat <<EOF\nx\nEOF\n".repeat(4_000);
    // And here-strings, of any number.
    let strings = "cat <<< a; ".repeat(1_000);
    check(
        Shell::Posix,
        &posix(),
        &[&heredoc, &tabbed, &quoted, &closed, &many, &strings],
        &[],
    );
}

#[test]
fn a_file_of_stream_operators_written_by_a_here_string_is_safe_in_powershell() {
    // PowerShell has no here-documents: `<<` in the text of a here-string is
    // text.
    let here_string = format!("Set-Content main.cpp @'\n{}'@\n", cpp_lines());
    check(Shell::PowerShell, &windows(), &[&here_string], &[]);
}

#[test]
fn too_many_here_documents_started_on_one_line_are_not_read() {
    // The grammar takes time that grows with the square of how many wait for
    // the end of the line, closed or not.
    let waiting = "cat <<EOF; ".repeat(300) + "\nEOF\n";
    let continued = "cat <<EOF; \\\n".repeat(300) + "\nEOF\n";
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&waiting, Rule::Unreadable), (&continued, Rule::Unreadable)],
    );
}

#[test]
fn a_long_chain_in_cmd_is_not_read_and_one_that_reads_is() {
    // `&` and `|` are counted before parsing: past the grammar's own depth a
    // chain is unreadable anyway, so a shorter one is read as before.
    let long = "echo x & ".repeat(5_000);
    let longer_pipeline = "echo x | ".repeat(5_000) + "cat";
    let short = "echo x & ".repeat(300) + "echo y";
    let shorter_pipeline = "echo x | ".repeat(300) + "cat";
    let both = "echo x & echo y | ".repeat(150) + "echo z";
    check(
        Shell::Cmd,
        &windows(),
        &[&short, &shorter_pipeline, &both],
        &[
            (&long, Rule::Unreadable),
            (&longer_pipeline, Rule::Unreadable),
        ],
    );
}
