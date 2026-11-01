//! The shell guard and the file guard give the same answer for the same file.
//!
//! An agent refused a key on the file API can read it through the shell, so
//! `cat <path>` must be `read_secret` exactly when a read of `<path>` is, for
//! every path the file guard's own tables name, on a POSIX machine, a Mac and
//! a Windows one (in PowerShell and in cmd). The paths are the string
//! literals of the file guard's test tables, read from their source, so a
//! row added there is held against the shell as soon as it lands.

#![cfg(all(feature = "shell", feature = "file"))]
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use milo_local_guards::file::{self, Access};
use milo_local_guards::shell::{self, Shell};
use milo_local_guards::Paths;

/// The test tables of the file guard.
const TABLES: [&str; 3] = ["posix.rs", "windows.rs", "protected.rs"];

/// The most a path may have in it for a table's row to be one worth a line.
const LONGEST: usize = 300;

fn source(table: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../file/tests")
        .join(table);
    fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Every string literal in Rust source `text`, with escapes resolved:
/// plain, raw (`r"…"`, `r#"…"#`) and across a line's end; comments and
/// character literals are skipped.
fn literals(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match c {
            '/' if chars.get(at + 1) == Some(&'/') => {
                while chars.get(at).is_some_and(|&c| c != '\n') {
                    at += 1;
                }
            }
            '/' if chars.get(at + 1) == Some(&'*') => {
                at += 2;
                while at < chars.len() && !(chars[at] == '*' && chars.get(at + 1) == Some(&'/')) {
                    at += 1;
                }
                at += 2;
            }
            // A character literal (`'"'`, `'\''`) is not the start of a string.
            '\'' => {
                at += if chars.get(at + 1) == Some(&'\\') {
                    // `'\n'`, `'\''`, `'\u{..}'`: to the closing quote.
                    let close = (at + 3..chars.len()).find(|&i| chars[i] == '\'');
                    close.map_or(1, |close| close + 1 - at)
                } else if chars.get(at + 2) == Some(&'\'') {
                    3
                } else {
                    1
                };
            }
            'r' if matches!(chars.get(at + 1), Some('"' | '#'))
                && at
                    .checked_sub(1)
                    .is_none_or(|before| !is_name(chars[before])) =>
            {
                let hashes = chars[at + 1..].iter().take_while(|&&c| c == '#').count();
                let open = at + 1 + hashes;
                if chars.get(open) != Some(&'"') {
                    at += 1;
                    continue;
                }
                let mut end = open + 1;
                let closing: Vec<char> = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                while end < chars.len() && chars[end..].get(..closing.len()) != Some(&closing[..]) {
                    end += 1;
                }
                found.push(chars[open + 1..end.min(chars.len())].iter().collect());
                at = end + closing.len();
            }
            '"' => {
                let mut value = String::new();
                at += 1;
                while let Some(&c) = chars.get(at) {
                    at += 1;
                    match c {
                        '"' => break,
                        '\\' => match chars.get(at).copied() {
                            Some('n') => {
                                value.push('\n');
                                at += 1;
                            }
                            Some('r') => {
                                value.push('\r');
                                at += 1;
                            }
                            Some('t') => {
                                value.push('\t');
                                at += 1;
                            }
                            Some('0') => {
                                value.push('\0');
                                at += 1;
                            }
                            Some('u') if chars.get(at + 1) == Some(&'{') => {
                                let close = (at..chars.len()).find(|&i| chars[i] == '}');
                                if let Some(close) = close {
                                    let hex: String = chars[at + 2..close].iter().collect();
                                    if let Some(c) =
                                        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                                    {
                                        value.push(c);
                                    }
                                    at = close + 1;
                                }
                            }
                            Some('\n') => {
                                at += 1;
                                while chars.get(at).is_some_and(|c| c.is_whitespace()) {
                                    at += 1;
                                }
                            }
                            Some(other) => {
                                value.push(other);
                                at += 1;
                            }
                            None => {}
                        },
                        other => value.push(other),
                    }
                }
                found.push(value);
            }
            _ => at += 1,
        }
    }
    found
}

fn is_name(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The paths of the file guard's tables: each literal that is a path a line
/// can name whole.
fn paths_of_the_tables() -> Result<BTreeSet<String>, String> {
    let mut found = BTreeSet::new();
    for table in TABLES {
        found.extend(literals(&source(table)?).into_iter().filter(|path| {
            !path.is_empty()
                && path.len() <= LONGEST
                && !path.chars().any(char::is_control)
                && !path.starts_with(char::is_whitespace)
        }));
    }
    Ok(found)
}

/// Whether `read_secret` is among the file guard's findings for a read of
/// `path`; `None` when the path is not one literal path the shell could be
/// given (a wildcard, a variable, `~user`: the file guard calls it
/// unreadable).
fn file_says(path: &str, paths: &Paths) -> Option<bool> {
    let assessment = file::judge(Access::Read, path, paths);
    let found: Vec<_> = assessment.findings().iter().map(|f| f.rule).collect();
    if found.contains(&file::Rule::Unreadable) {
        return None;
    }
    Some(found.contains(&file::Rule::ReadSecret))
}

fn shell_says(line: &str, shell: Shell, paths: &Paths) -> bool {
    shell::classify(line, shell, paths)
        .findings()
        .iter()
        .any(|finding| finding.rule == shell::Rule::ReadSecret)
}

/// The lines that read `path` in `shell`, in every form that names it whole:
/// quoted as the shell reads it as written, as a `<` redirect's source (cmd
/// and POSIX), and, where the path starts at the home directory, spelled with
/// the variable that names it (`$HOME`, `%USERPROFILE%`). A path a form cannot
/// carry is left out of that form, never out of the others:
///
/// - cmd cannot carry `"`: no Windows name has one, so there is nothing to
///   judge;
/// - cmd cannot carry `%`: it expands `%name%` even in quotes, so the word is a
///   variable and not this file;
/// - cmd cannot carry `^`: the guard reads a caret as cmd's escape, which cmd
///   does not do inside quotes (a known gap, kept visible by the skip);
/// - a word spelled with `$HOME` cannot carry `$`, a backtick, `"` or `\`
///   (POSIX), which are not plain text in it, nor, bare in PowerShell, a space
///   or one of `;|&(){},'"<>@#`, which end the word.
fn lines(path: &str, shell: Shell, home: &str) -> Vec<String> {
    let mut lines = Vec::new();
    // The path with the home directory spelled as a variable, when it starts
    // there (whole parts, without case on Windows).
    let under = |variable: &str| {
        let rest = path.get(home.len()..)?;
        let same = path.get(..home.len()).is_some_and(|head| {
            if home.starts_with('/') {
                head == home
            } else {
                head.eq_ignore_ascii_case(home)
            }
        });
        (same && (rest.is_empty() || rest.starts_with(['/', '\\'])))
            .then(|| format!("{variable}{rest}"))
    };
    match shell {
        Shell::Posix => {
            let quoted = format!("'{}'", path.replace('\'', "'\\''"));
            lines.push(format!("cat {quoted}"));
            lines.push(format!("cat < {quoted}"));
            lines.push(format!("base64 <{quoted}"));
            if let Some(spelled) =
                under("$HOME").filter(|text| !text.contains(['"', '$', '`', '\\', '!', '\n']))
            {
                lines.push(format!("cat \"{spelled}\""));
                lines.push(format!("cat < \"{spelled}\""));
            }
        }
        Shell::PowerShell => {
            let quoted = format!("'{}'", path.replace('\'', "''"));
            lines.push(format!("Get-Content -LiteralPath {quoted}"));
            lines.push(format!("Get-Content {quoted}"));
            lines.push(format!("Get-Content -Path {quoted} -Raw"));
            if let Some(spelled) = under("$HOME") {
                if !spelled.contains([
                    ' ', ';', '|', '&', '(', ')', '{', '}', ',', '\'', '"', '<', '>', '@', '#',
                    '$', '`',
                ]) {
                    lines.push(format!("Get-Content {spelled}"));
                    lines.push(format!("Get-Content -Path {spelled}"));
                }
            }
        }
        Shell::Cmd if !path.contains(['"', '%', '^']) => {
            lines.push(format!("type \"{path}\""));
            lines.push(format!("more < \"{path}\""));
            lines.push(format!("more <\"{path}\""));
            lines.push(format!("sort < \"{path}\""));
            lines.push(format!("findstr x 0< \"{path}\""));
            if !path.contains([' ', '&', '|', '<', '>', '(', ')', ',', ';', '=']) {
                lines.push(format!("more < {path}"));
            }
            if let Some(spelled) = under("%USERPROFILE%") {
                lines.push(format!("type \"{spelled}\""));
                lines.push(format!("more < \"{spelled}\""));
            }
        }
        _ => {}
    }
    lines
}

#[test]
fn the_shell_and_the_file_guard_agree_on_every_path_of_the_file_guards_tables() {
    let tables = paths_of_the_tables().expect("the file guard's tables are readable");
    let posix = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
    let mac = Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"]);
    let windows = Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    );
    let (mut wrong, mut judged, mut secrets) = (Vec::new(), 0_usize, 0_usize);
    for path in &tables {
        for (paths, shells) in [
            (&posix, &[Shell::Posix][..]),
            (&mac, &[Shell::Posix][..]),
            (&windows, &[Shell::PowerShell, Shell::Cmd][..]),
        ] {
            let Some(expected) = file_says(path, paths) else {
                continue;
            };
            let home = paths.home.to_string_lossy();
            for &shell in shells {
                for line in lines(path, shell, &home) {
                    judged += 1;
                    secrets += usize::from(expected);
                    let got = shell_says(&line, shell, paths);
                    if got != expected {
                        wrong.push(format!(
                            "{shell:?} on {home}: the file guard says read_secret = {expected}, \
                             the shell says {got}: {line}"
                        ));
                    }
                }
            }
        }
    }
    // The tables are read, and name keys: not an empty scan that agrees on
    // nothing.
    assert!(judged > 10_000, "only {judged} lines were judged");
    assert!(secrets > 2_000, "only {secrets} of them were secrets");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_literals_of_a_source_are_read_as_rust_reads_them() {
    let text = r##"
        // "not a literal"
        let a = "plain \\ and \" and \u{212a}";
        let b = r"raw \d";
        let c = r#"with "quotes" inside"#;
        let d = '"';
        let e = '\'';
        let f = "joined \
                 lines";
        /* "nor this" */
        let g = (1, "x");
    "##;
    assert_eq!(
        literals(text),
        [
            "plain \\ and \" and \u{212a}",
            "raw \\d",
            "with \"quotes\" inside",
            "joined lines",
            "x",
        ]
    );
}
