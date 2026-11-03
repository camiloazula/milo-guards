//! The case files: plain text, one case to a line, that a guard's tests read
//! instead of tables written in Rust. This module reads the format every
//! guard shares; each guard's `tests/common` says what the words of a case
//! mean for it and checks the cases. CONTRIBUTING.md describes the format.
//!
//! A line of a case file is one of:
//!
//! - blank, or a comment (its first character is `#`): skipped;
//! - words, then ` | ` and the text the case is about (a command line, a
//!   path): a case;
//! - words alone: a declaration, such as a named set of paths.
//!
//! Words are separated by spaces. A word is bare (`posix`, `safe`) or a field
//! (`finds=delete`, `reason="deletes your home directory"`); a field's value is
//! quoted when it holds a space. A text runs from one space after the `|` to
//! the end of the line. A text and a value hold any character: a backslash
//! starts one of the escapes `\\`, `\n`, `\t`, `\r`, `\s` (a space), `\u{HEX}`
//! and, in a quoted value, `\"`. A raw control character, a raw tab, a
//! carriage return, a space at the start or the end of a text, and a space at
//! the end of a line are refused, so what a case holds is what its line
//! shows.
//!
//! Every guard's tests include this file by its path; it uses only `std`.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    clippy::disallowed_types,
    reason = "a test reads its case files from the crate's `tests/cases`"
)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::Hash;
use std::path::{Path, PathBuf};

/// One line of a case file that is not blank or a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    /// The words before the `|`, in order.
    pub words: Vec<Word>,
    /// The text after the `|`, decoded; `None` for a declaration.
    pub text: Option<String>,
}

/// A word of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Word {
    /// A word with no `=`: `posix`, `safe`.
    Bare(String),
    /// `name=value`, the value decoded.
    Field(String, String),
}

/// Where the crate that runs the test keeps its case files.
pub fn folder() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases")
}

/// The file of the cases named `name`: `tests/cases/NAME.cases`.
pub fn file(name: &str) -> PathBuf {
    folder().join(format!("{name}.cases"))
}

/// The names of every case file in [`folder`], sorted.
pub fn names() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(folder()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
        .filter_map(|path| Some(path.file_stem()?.to_str()?.to_string()))
        .collect();
    names.sort();
    names
}

/// The records of the case file named `name`, or every reason it is refused:
/// a file that is not there is refused too.
pub fn read(name: &str) -> Result<Vec<Record>, Vec<String>> {
    let shown = format!("tests/cases/{name}.cases");
    match std::fs::read_to_string(file(name)) {
        Ok(source) => parse(&shown, &source),
        Err(error) => Err(vec![format!("{shown}: no case file ({error})")]),
    }
}

/// The records of `source`, the text of the file `file`, or every line that
/// is refused, each named by its file and line.
pub fn parse(file: &str, source: &str) -> Result<Vec<Record>, Vec<String>> {
    let mut records = Vec::new();
    let mut refused = Vec::new();
    for (index, line) in source.split('\n').enumerate() {
        let at = format!("{file}:{}", index + 1);
        match record(line) {
            Ok(Some((words, text))) => records.push(Record { at, words, text }),
            Ok(None) => {}
            Err(why) => refused.push(format!("{at}: {why}")),
        }
    }
    if refused.is_empty() {
        Ok(records)
    } else {
        Err(refused)
    }
}

type Parsed = (Vec<Word>, Option<String>);

/// The words and text of one line, `None` when it is blank or a comment.
fn record(line: &str) -> Result<Option<Parsed>, String> {
    if let Some(c) = line.chars().find(|c| c.is_control()) {
        return Err(format!(
            "a raw {} (write it as an escape)",
            c.escape_debug()
        ));
    }
    if line.ends_with(' ') {
        return Err("a space at the end of the line (write `\\s` in a text)".to_string());
    }
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if line.starts_with(' ') {
        return Err("a space at the start of the line".to_string());
    }
    let mut words = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            return Ok(Some((words, None)));
        }
        if rest == "|" {
            return Ok(Some((words, Some(String::new()))));
        }
        if let Some(text) = rest.strip_prefix("| ") {
            if text.starts_with(' ') {
                return Err("a space at the start of the text (write it as `\\s`)".to_string());
            }
            return Ok(Some((words, Some(decode(text, false)?))));
        }
        let (word, after) = take_word(rest)?;
        words.push(word);
        rest = after;
    }
}

/// The first word of `text`, and what follows it.
fn take_word(text: &str) -> Result<(Word, &str), String> {
    let end = text.find(' ').unwrap_or(text.len());
    let Some((name, value)) = text.split_once('=').filter(|(name, _)| name.len() < end) else {
        let word = &text[..end];
        if word.contains(['"', '\\', '|']) {
            return Err(format!("a malformed word `{word}`"));
        }
        return Ok((Word::Bare(word.to_string()), &text[end..]));
    };
    if name.is_empty() || name.contains(['"', '\\', '|']) {
        return Err(format!("a malformed field name `{name}`"));
    }
    if let Some(quoted) = value.strip_prefix('"') {
        let close = closing_quote(quoted)
            .ok_or_else(|| format!("the value of `{name}` has no closing quote"))?;
        let after = &quoted[close + 1..];
        if !(after.is_empty() || after.starts_with(' ')) {
            return Err(format!("a space must follow the quoted value of `{name}`"));
        }
        let value = decode(&quoted[..close], true)?;
        return Ok((Word::Field(name.to_string(), value), after));
    }
    let end = value.find(' ').unwrap_or(value.len());
    let raw = &value[..end];
    if raw.contains(['"', '|']) {
        return Err(format!("the value of `{name}` must be quoted: `{raw}`"));
    }
    let value_text = decode(raw, false)?;
    Ok((Word::Field(name.to_string(), value_text), &value[end..]))
}

/// The byte index of the quote that closes a quoted value, past escapes.
fn closing_quote(text: &str) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match (escaped, c) {
            (true, _) => escaped = false,
            (false, '\\') => escaped = true,
            (false, '"') => return Some(at),
            _ => {}
        }
    }
    None
}

/// `text` with its escapes read: `\\`, `\n`, `\t`, `\r`, `\s`, `\u{HEX}`, and
/// `\"` when `quoted`. Any other backslash is refused.
pub fn decode(text: &str, quoted: bool) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('s') => out.push(' '),
            Some('"') if quoted => out.push('"'),
            Some('u') => {
                let rest = chars.as_str();
                let hex = rest
                    .strip_prefix('{')
                    .and_then(|rest| rest.split_once('}'))
                    .map(|(hex, _)| hex)
                    .filter(|hex| (1..=6).contains(&hex.len()))
                    .ok_or("`\\u` must be `\\u{HEX}`, one to six digits")?;
                let c = u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| format!("`\\u{{{hex}}}` is not a character"))?;
                out.push(c);
                chars = rest[hex.len() + 2..].chars();
            }
            Some(other) => {
                return Err(format!(
                    "an unknown escape `\\{other}` (a backslash is `\\\\`)"
                ))
            }
            None => return Err("a backslash at the end (a backslash is `\\\\`)".to_string()),
        }
    }
    Ok(out)
}

/// `text` as a case file writes it after the `|`: a backslash doubled, a
/// line break, tab or carriage return as its escape, a space at either end as
/// `\s`, and any other control or invisible character as `\u{HEX}`.
/// [`decode`] gives `text` back.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let last = text.chars().count().saturating_sub(1);
    for (at, c) in text.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            ' ' if at == 0 || at == last => out.push_str("\\s"),
            ' ' => out.push(' '),
            c if c.is_control() || c.is_whitespace() || invisible(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// A character that shows as nothing, or as a space that is not one.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}'
    )
}

/// The cases that repeat an earlier one: each `(at, key)` whose key an
/// earlier item has, named with where the first one is.
pub fn repeated<K: Eq + Hash>(items: impl IntoIterator<Item = (String, K)>) -> Vec<String> {
    let mut seen: HashMap<K, String> = HashMap::new();
    let mut repeats = Vec::new();
    for (at, key) in items {
        match seen.get(&key) {
            Some(first) => repeats.push(format!("{at}: repeats the case at {first}")),
            None => {
                seen.insert(key, at);
            }
        }
    }
    repeats
}
