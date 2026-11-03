//! The builder of nested inline code: a line whose Python runs a line, for
//! the test of code nested past the limit the reader reads to.

/// `python3 -c` of Python that runs `line` with `os.system`: the line is
/// quoted as a Python string, and that as a double-quoted shell word.
pub fn nest(line: &str) -> String {
    let python = format!(
        "import os; os.system('{}')",
        line.replace('\\', "\\\\").replace('\'', "\\'")
    );
    let word = python
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$");
    format!("python3 -c \"{word}\"")
}
