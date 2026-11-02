//! The builders of inline-code rows: a line that hands an interpreter its
//! code, and the checks that a row is risky for one of a few rules.

use milo_guards_shell::{Rule, Shell};

use super::{classify, posix};

/// `python3 -c 'CODE'`, where `\n` in the code is a line break and the code
/// writes its strings in double quotes.
pub fn py(code: &str) -> String {
    format!("python3 -c '{}'", code.replace("\\n", "\n"))
}

/// `PROGRAM -e 'CODE'` (node, bun), the code written with double quotes.
pub fn js(program: &str, code: &str) -> String {
    format!("{program} -e '{code}'")
}

/// `python3 -c "CODE" /home/me/.ssh/id_rsa`: the key is only an argument.
pub fn python(code: &str) -> String {
    format!("python3 -c \"{code}\" /home/me/.ssh/id_rsa")
}

/// `node -e "CODE" /home/me/.ssh/id_rsa`.
pub fn node(code: &str) -> String {
    format!("node -e \"{code}\" /home/me/.ssh/id_rsa")
}

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

/// Each row as an owned line.
pub fn lines(rows: &[&str]) -> Vec<String> {
    rows.iter().map(ToString::to_string).collect()
}

/// The rows of `lines` that `classify` calls safe, or that name none of
/// `rules` (any one will do).
pub fn not_risky_as(lines: &[String], rules: &[Rule]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let assessment = classify(line, Shell::Posix, &posix());
            let found = assessment
                .findings()
                .iter()
                .any(|finding| rules.contains(&finding.rule));
            (!found).then(|| format!("{line}\n    got {:?}", assessment.findings()))
        })
        .collect()
}

/// Every row of `lines` names one of `rules`.
pub fn assert_risky_as(lines: &[String], rules: &[Rule]) {
    let wrong = not_risky_as(lines, rules);
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every row is `unknown`: code the guard does not read fully.
pub fn assert_unknown(rows: &[&str]) {
    let rows: Vec<String> = rows.iter().map(ToString::to_string).collect();
    assert_risky_as(&rows, &[Rule::Unknown]);
}

/// A row that names either rule is right.
pub const UNKNOWN_OR_SECRET: [Rule; 2] = [Rule::Unknown, Rule::ReadSecret];
