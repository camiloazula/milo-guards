//! The case-file format (CONTRIBUTING.md, "Case files"), read as far as this
//! tool needs it: the words before ` | ` and the line after it, with its
//! escapes. It is a reader of its own, not the guards' shared one (which
//! lives in a crate's test folder and is no dependency a package can name),
//! and it is strict: a line it does not understand is refused, never
//! guessed at, so a change to the format fails `tests/case_files.rs`, which
//! reads every real case file with it, rather than changing what is read.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::Hash;

/// One line of a case file that is not blank or a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Where it is: `FILE:LINE`.
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

/// The words and text of one line; `None` when it is blank or a comment.
/// The words are read one by one, and the text starts at the first `| ` (or
/// a last `|`, an empty text) that stands where a word would, so a quoted
/// value may hold a ` | `.
fn record(line: &str) -> Result<Option<Parsed>, String> {
    if line.chars().any(char::is_control) {
        return Err("a raw control character".to_string());
    }
    if line.ends_with(' ') {
        return Err("a space at the end of the line".to_string());
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
                return Err("a space at the start of the text".to_string());
            }
            return Ok(Some((words, Some(decode(text, false)?))));
        }
        let (word, after) = take_word(rest)?;
        words.push(word);
        rest = after;
    }
}

/// The first word of `text`, bare or `name=value` with the value quoted
/// when it holds a space, and what follows it.
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
        let mut close = None;
        let mut escaped = false;
        for (at, c) in quoted.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    close = Some(at);
                    break;
                }
                _ => {}
            }
        }
        let close = close.ok_or_else(|| format!("the value of `{name}` has no closing quote"))?;
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
        return Err(format!("a malformed value of `{name}`"));
    }
    Ok((
        Word::Field(name.to_string(), decode(raw, false)?),
        &value[end..],
    ))
}

/// `text` with its escapes read: `\\`, `\n`, `\t`, `\r`, `\s`, `\u{HEX}`,
/// and in a quoted value `\"`. Any other is refused.
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
                let rest: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let hex = rest
                    .strip_prefix('{')
                    .ok_or("a `\\u` escape without its `{HEX}`")?;
                let value = u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| format!("no character `\\u{{{hex}}}`"))?;
                out.push(value);
            }
            other => return Err(format!("an unknown escape `\\{}`", other.unwrap_or(' '))),
        }
    }
    Ok(out)
}

/// `text` as a case file writes it, on one line: what [`decode`] reads back.
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

/// The first word of a case, `KIND[@PATHS]`, as its two parts.
pub fn head(words: &[Word]) -> Option<(&str, Option<&str>)> {
    let Some(Word::Bare(first)) = words.first() else {
        return None;
    };
    match first.split_once('@') {
        Some((kind, paths)) if kind.is_empty() || paths.is_empty() => None,
        Some((kind, paths)) => Some((kind, Some(paths))),
        None => Some((first.as_str(), None)),
    }
}

/// The items that repeat an earlier one: each `(at, key)` whose key an
/// earlier item has, named with where the first one is.
pub fn repeated<K: Eq + Hash>(items: impl IntoIterator<Item = (String, K)>) -> Vec<String> {
    let mut seen: HashMap<K, String> = HashMap::new();
    let mut repeats = Vec::new();
    for (at, key) in items {
        match seen.get(&key) {
            Some(first) => repeats.push(format!("{at}: repeats the one at {first}")),
            None => {
                seen.insert(key, at);
            }
        }
    }
    repeats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_is_its_words_and_its_line() {
        let source = "# comment\n\nposix@home finds=delete reason=\"deletes your \\\"home\\\"\" | rm -rf ~ | x\\n\\s\\u{0}\nparts a=1 b";
        let records = parse("f.cases", source).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].at, "f.cases:3");
        assert_eq!(
            records[0].words,
            [
                Word::Bare("posix@home".into()),
                Word::Field("finds".into(), "delete".into()),
                Word::Field("reason".into(), "deletes your \"home\"".into()),
            ]
        );
        assert_eq!(records[0].text.as_deref(), Some("rm -rf ~ | x\n \u{0}"));
        assert_eq!(head(&records[0].words), Some(("posix", Some("home"))));
        assert_eq!(records[1].text, None);
        assert_eq!(head(&[Word::Bare("x@".into())]), None);
        assert_eq!(head(&[]), None);
    }

    #[test]
    fn what_it_does_not_understand_is_refused() {
        for line in [
            " posix safe | x",
            "posix safe | x ",
            "posix safe |  x",
            "posix safe | \\q",
            "posix safe | \\u{110000}",
            "posix safe | \\u0",
            "posix sa\"fe | x",
            "posix reason=\"x | y",
            "posix =x | y",
            "posix safe | a\tb",
        ] {
            assert!(parse("f", line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn a_line_is_written_as_it_is_read() {
        for text in [" a b ", "x\n\ty\\z", "\u{0}\u{200b}\u{a0}", "plain"] {
            assert_eq!(decode(&encode(text), false).as_deref(), Ok(text));
        }
        assert_eq!(encode(" a "), "\\sa\\s");
        assert_eq!(
            repeated([("a".to_string(), 1), ("b".to_string(), 1)]).len(),
            1
        );
    }
}
