//! A password, a secret or a token written down as the value of a name:
//! `password=hunter22`, `"api_key": "…"`, `export TOKEN=…`.
//!
//! This is the one detector that reads a name, so it is the one where code
//! is easy to mistake for a secret (`password: String`, `token = self.token`,
//! `let secret = get_secret();`). It judges the value it reads.
//!
//! **Where a value ends is decided on the text as it was written**, with the
//! quoting and the separators that text uses; reading escapes is for
//! recognising a secret, never for ending one. `%26`, `%20`, `"` and a
//! JSON `\"` inside a value are part of it:
//!
//! - a value in quotes ends at its closing quote, read with the escaping of
//!   the formats that write one: `\"` and `\'` (JSON, shell, code), `''`
//!   (YAML, SQL);
//! - a value in a string written `\"…\"` ends at the closing `\"`;
//! - any other value ends at white space or the end of the line, and at the
//!   closer of the bracket or quote the name sits in (`(a=b)`, `"a=b"`), and
//!   at the format's own separator: `&` before another `name=` of a query,
//!   `;` before another `Name=` of a connection string. `|`, `,`, `(` and
//!   a backtick do not end it.
//!
//! The text is scanned once from front to back: after a value has been read,
//! accepted or not, the scan goes on after it, so no byte is read again.
//!
//! The value is judged by what it is:
//!
//! - the name must end in a word that names a secret (`password`, `secret`,
//!   `token`, `api_key`, …); `tokens`, `max_tokens` and `password_hash` do
//!   not;
//! - a value that is no value is not a secret: empty, shorter than six
//!   characters, a reference to a variable or a template field, a stand-in
//!   ([`text::is_placeholder`]), a call, an index, or a chain of names; the
//!   value of a cursor of pagination (`next_page_token`); a quoted word of
//!   a locale file (`"password": "Contraseña"`); a quoted value of under
//!   eight characters after `token` or `api_key`;
//! - a quoted value has no space in it; an unquoted one is a secret when the
//!   name is tied to it (`password=value`, as an environment file, a query
//!   or a connection string write it), when it has a digit in it
//!   (`password: hunter22`), which a word of code does not, or when it ends
//!   in `=` (base64 padding).
//!
//! The span is the value, without its quotes, so a caller that scrubs it
//! keeps the name.

use std::sync::OnceLock;

use regex::Regex;

use crate::mask::Mask;
use crate::reading::Reading;
use crate::scan::Hit;
use crate::{text, Rule};

/// A name, and the operator after it, up to the value.
const KEY: &str = r#"([A-Za-z_][A-Za-z0-9_.\-]{0,79})\\?["']?[ \t]*(?::=|=>|==|[:=])[ \t]*"#;

/// What a lowercase text must hold for any name here to be a secret's.
const NEEDLES: [&str; 8] = [
    "pass",
    "pwd",
    "secret",
    "token",
    "key",
    "credential",
    "auth",
    "private",
];

/// The shortest value read as a secret.
const MIN_VALUE: usize = 6;

/// How far past a separator a name and its `=` are looked for.
const LOOKAHEAD: usize = 40;

fn key() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(KEY).ok()).as_ref()
}

/// Adds a hit for each secret written as the value of a name in the text.
pub(crate) fn scan(reading: &Reading<'_>, lower: &str, out: &mut Vec<Hit>) {
    if !NEEDLES.iter().any(|needle| lower.contains(needle)) {
        return;
    }
    let Some(regex) = key() else {
        return;
    };
    let read = reading.text();
    let written = reading.written();
    let mut at = 0;
    // Built when a name is first tied to a value.
    let mut lines: Option<LineIndex> = None;
    while let Some(captures) = regex.captures_at(read, at) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            break;
        };
        // A name that is not a secret's has its value read as the text goes
        // on: a name written inside it is still found.
        at = whole.end();
        let Some(word) = secret_word(name.as_str()) else {
            continue;
        };
        if is_cursor(name.as_str()) {
            continue;
        }
        let gap = read.get(name.end()..whole.end()).unwrap_or_default();
        let tied = !gap.contains([' ', '\t']) && gap.trim_matches(['"', '\'', '\\']) == "=";
        // A key of data is written in quotes: `"password": "…"`.
        let key_quoted = gap.trim_start_matches('\\').starts_with(['"', '\'']);
        let from = reading.written_point(whole.end());
        let name_at = reading.written_point(name.start());
        let name_end = reading.written_point(name.end());
        let Some(value) = read_value(written, from, enclosure(written, name_at, name_end)) else {
            continue;
        };
        // Whatever is decided, the scan goes on after the value.
        at = at.max(reading.read_point(value.after));
        let raw = written.get(value.start..value.end).unwrap_or_default();
        let env_file = tied
            && lines
                .get_or_insert_with(|| LineIndex::new(written))
                .is_env_line(written, name_at);
        // A word of a locale file under a key of data, not a password.
        let label = value.quoted && key_quoted && is_label(raw);
        if !label && accept(word, raw, value.quoted, tied, env_file) {
            out.push(Hit {
                rule: Rule::GenericSecret,
                reason: "holds a password or secret",
                start: reading.read_point(value.start),
                end: reading.read_point(value.end),
                mask: Mask::Length,
            });
        }
    }
}

/// What closes the string or the bracket a name is written in.
#[derive(Clone, Copy)]
struct Enclosure {
    /// The closing character.
    closer: char,
    /// Whether the opening one was written `\"`: the closer is `\"` too.
    escaped: bool,
}

/// The quote or bracket a name sits in: the character just before it, unless
/// that character is the name's own opening quote (`"password": …`).
fn enclosure(written: &str, name_at: usize, name_end: usize) -> Option<Enclosure> {
    let before = text::before(written, name_at)?;
    let closer = match before {
        '"' | '\'' | '`' => before,
        '(' => ')',
        '[' => ']',
        '{' => '}',
        _ => return None,
    };
    let escaped = text::before(written, name_at - before.len_utf8()) == Some('\\');
    let after = written.get(name_end..)?;
    let after = after.strip_prefix('\\').unwrap_or(after);
    if closer == before && after.starts_with(before) {
        return None;
    }
    Some(Enclosure { closer, escaped })
}

/// The value after an operator: where it is, whether it was quoted, and
/// where reading resumes. Offsets are in the written text.
struct Value {
    start: usize,
    end: usize,
    after: usize,
    quoted: bool,
}

fn read_value(written: &str, from: usize, enclosure: Option<Enclosure>) -> Option<Value> {
    let rest = written.get(from..)?;
    let mut chars = rest.chars();
    let first = chars.next()?;
    // A quote, or a quote written `\"` because the whole is inside a string.
    let (quote, opening) = match (first, chars.next()) {
        ('"' | '\'', _) => (Some(first), 1),
        ('\\', Some(second @ ('"' | '\''))) => (Some(second), 2),
        _ => (None, 0),
    };
    if let Some(quote) = quote {
        if let Some((length, after)) = read_quoted(rest.get(opening..)?, quote, opening == 2) {
            return Some(Value {
                start: from + opening,
                end: from + opening + length,
                after: from + opening + after,
                quoted: true,
            });
        }
        // A quote that never closes is not one: the value is what follows.
        return read_unquoted(written, from + opening, enclosure);
    }
    // The braces of a connection string quote a value that holds `;`:
    // `Pwd={a;b}`, with `}}` for a brace of the value. `{{` and `{%` are the
    // marks of a template.
    if first == '{' && !rest.starts_with("{{") && !rest.starts_with("{%") {
        if let Some((length, after)) = read_braced(rest.get(1..)?) {
            return Some(Value {
                start: from + 1,
                end: from + 1 + length,
                after: from + 1 + after,
                quoted: true,
            });
        }
    }
    read_unquoted(written, from, enclosure)
}

/// The length of a value in braces and of it with the closing brace.
fn read_braced(inner: &str) -> Option<(usize, usize)> {
    let mut chars = inner.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '\n' | '\r' => return None,
            '}' if chars.peek().is_some_and(|(_, next)| *next == '}') => {
                chars.next();
            }
            '}' => return Some((at, at + 1)),
            _ => {}
        }
    }
    None
}

/// The length of a value in quotes, and the length of it with its closing
/// quote: `inner` is what follows the opening one.
fn read_quoted(inner: &str, quote: char, escaped: bool) -> Option<(usize, usize)> {
    let mut chars = inner.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '\n' | '\r' => return None,
            // The closing `\"` of a string written `\"…\"` takes its
            // backslash with it; any other backslash escapes what follows.
            '\\' if escaped && chars.peek().is_some_and(|(_, next)| *next == quote) => {
                return Some((at, at + 1 + quote.len_utf8()));
            }
            '\\' => {
                chars.next();
            }
            c if c == quote => {
                // `''` inside `'…'` is one quote of the value.
                if quote == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                    chars.next();
                    continue;
                }
                return Some((at, at + quote.len_utf8()));
            }
            _ => {}
        }
    }
    None
}

fn read_unquoted(written: &str, from: usize, enclosure: Option<Enclosure>) -> Option<Value> {
    let rest = written.get(from..)?;
    let bytes = rest.as_bytes();
    let closer = enclosure.map(|e| e.closer);
    // A quote that closes the string the name is in, as a string escapes it:
    // `\"` and `''` are part of the value, a bare `"` or `'` is the end.
    let is_quote = closer.is_some_and(|c| matches!(c, '"' | '\''));
    let escaping = is_quote && !enclosure.is_some_and(|e| e.escaped);
    let mut length = 0;
    let mut backslashes = 0;
    while let Some(&byte) = bytes.get(length) {
        let at_closer = closer.is_some_and(|c| u32::from(byte) == u32::from(c));
        if at_closer && escaping {
            if backslashes % 2 == 1 {
                backslashes = 0;
                length += 1;
                continue;
            }
            if byte == b'\'' && bytes.get(length + 1) == Some(&b'\'') {
                length += 2;
                continue;
            }
        }
        let ends = match byte {
            b' ' | b'\t' | b'\r' | b'\n' => true,
            b'&' => names_a_pair(bytes, length + 1, true),
            b';' => names_a_pair(bytes, length + 1, false),
            _ => at_closer,
        };
        if ends {
            break;
        }
        backslashes = if byte == b'\\' { backslashes + 1 } else { 0 };
        length += 1;
    }
    // The escaped closer of `\"…\"` takes its backslash with it.
    let at_closer =
        closer.is_some_and(|c| u32::from(bytes.get(length).copied().unwrap_or(0)) == u32::from(c));
    let escaped = enclosure.is_some_and(|e| e.escaped) && at_closer;
    let end = if escaped && length > 0 && bytes.get(length - 1) == Some(&b'\\') {
        length - 1
    } else {
        length
    };
    Some(Value {
        start: from,
        end: from + end,
        after: from + length,
        quoted: false,
    })
}

/// Whether what follows a `&` or a `;` is another pair of a query or of a
/// connection string: a name, and `=` within a few characters. A name of a
/// connection string may have spaces (`User Id=`); one of a query may not.
fn names_a_pair(bytes: &[u8], from: usize, query: bool) -> bool {
    for &byte in bytes.iter().skip(from).take(LOOKAHEAD) {
        match byte {
            b'=' => return true,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' => {}
            b'%' | b'[' | b']' if query => {}
            b' ' if !query => {}
            _ => return false,
        }
    }
    false
}

/// The word a name ends in if it names a secret: what its value may not
/// repeat. `None` for any other name.
fn secret_word(name: &str) -> Option<&'static str> {
    const ENDINGS: [&str; 13] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "secretkey",
        "privatekey",
        "authkey",
        "credential",
        "credentials",
        "pwd",
    ];
    let lower = name.to_ascii_lowercase();
    let squeezed = text::squeezed(name);
    if let Some(ending) = ENDINGS.iter().find(|ending| squeezed.ends_with(**ending)) {
        return Some(ending);
    }
    // `pass` alone is also the end of `bypass` and `compass`.
    let whole = lower == "pass"
        || ["_pass", "-pass", ".pass"]
            .iter()
            .any(|ending| lower.ends_with(ending));
    whole.then_some("pass")
}

/// Where each line of the written text begins, and where its first
/// character that is not blank is, found in one pass: a hit asks which line
/// it is on by bisection, so a long line costs nothing per hit.
struct LineIndex {
    /// For each line: where it starts, and where its content does.
    lines: Vec<(usize, usize)>,
}

impl LineIndex {
    fn new(written: &str) -> Self {
        let bytes = written.as_bytes();
        let mut lines = Vec::new();
        let mut start = 0;
        loop {
            let blanks = bytes
                .get(start..)
                .unwrap_or_default()
                .iter()
                .take_while(|b| matches!(b, b' ' | b'\t'))
                .count();
            lines.push((start, start + blanks));
            let Some(newline) = bytes
                .get(start + blanks..)
                .and_then(|rest| rest.iter().position(|b| *b == b'\n'))
            else {
                break;
            };
            start += blanks + newline + 1;
        }
        Self { lines }
    }

    /// Whether the name at `at` begins its line, or follows `export` on it: a
    /// line of an environment file or a shell script that only sets it.
    fn is_env_line(&self, written: &str, at: usize) -> bool {
        let line = self.lines.partition_point(|(start, _)| *start <= at);
        let Some((_, content)) = line.checked_sub(1).and_then(|last| self.lines.get(last)) else {
            return false;
        };
        let before = written
            .get(*content..at)
            .unwrap_or_default()
            .trim_end_matches([' ', '\t']);
        matches!(before, "" | "export" | "declare -x")
    }
}

/// Whether a name is that of a cursor of pagination (`next_page_token`,
/// `nextToken`, `continuation_token`): an opaque text the server gives back
/// to ask for the next page, which opens no door.
fn is_cursor(name: &str) -> bool {
    const ENDINGS: [&str; 5] = [
        "pagetoken",
        "nexttoken",
        "continuationtoken",
        "paginationtoken",
        "cursortoken",
    ];
    let squeezed = text::squeezed(name);
    ENDINGS.iter().any(|ending| squeezed.ends_with(ending))
}

/// The most letters of a word that is a label and not a password.
const LABEL_LETTERS: usize = 24;

/// Whether `value` is one word of a language, as a locale file writes the
/// text of a label: letters only, the first a capital and the rest lower
/// case (`Contraseña`, `Confirmar`), and one `?` or `!` at its end
/// (`Forgot?`). A password of letters in any other case is not one.
fn is_label(value: &str) -> bool {
    let word = value.strip_suffix(['?', '!']).unwrap_or(value);
    let mut chars = word.chars();
    chars.next().is_some_and(char::is_uppercase)
        && chars.all(char::is_lowercase)
        && word.chars().count() <= LABEL_LETTERS
}

/// The names of a machine's key, whose value is never as short as a word:
/// `token = "abc123"` is a test, not a token.
fn is_machine_word(word: &str) -> bool {
    matches!(word, "token" | "apikey")
}

/// The shortest quoted value read as the value of a machine's key.
const MIN_MACHINE_VALUE: usize = 8;

/// Whether the value read after a name that ends in `word` is a secret.
/// `raw` is the value as it was written.
fn accept(word: &str, raw: &str, quoted: bool, tied: bool, env_file: bool) -> bool {
    let decoded = Reading::new(raw);
    let whole = decoded.text();
    // What closes a statement or a list is not part of the word before it.
    let value = if quoted {
        whole
    } else {
        whole.trim_end_matches([',', ';', ':', '.', ')', '"', '\'', '`'])
    };
    if value.chars().count() < MIN_VALUE
        || text::is_reference(value)
        || text::is_placeholder(
            value,
            &text::Standin {
                word: Some(word),
                quoted,
                address: false,
                env_file,
            },
        )
    {
        return false;
    }
    if quoted {
        let machine_short = is_machine_word(word) && value.chars().count() < MIN_MACHINE_VALUE;
        return !raw.contains([' ', '\t']) && !machine_short;
    }
    if value.contains(['[', ']']) || is_call(whole) || is_chain_of_names(value) {
        return false;
    }
    // Base64 ends in `=` when it is padded: a Kubernetes secret is written so.
    tied || value.ends_with('=') || value.bytes().any(|b| b.is_ascii_digit())
}

/// Whether `value` is a call (`get_token()`, `env::var("X")?;`): names, a
/// `(`, and either nothing more than a `)` that closes it or no `)` at all.
/// `F4ke(Pass9)word` has a `)` in the middle and is a word.
fn is_call(value: &str) -> bool {
    value.split_once('(').is_some_and(|(head, tail)| {
        head.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':'))
            && (!tail.contains(')')
                || tail
                    .trim_end_matches([';', ',', '?', '.', ':'])
                    .ends_with(')'))
    })
}

/// Whether `value` is names joined by dots or colons (`self.token`,
/// `config::TOKEN`): a reading of another value, not a value.
fn is_chain_of_names(value: &str) -> bool {
    value.contains(['.', ':'])
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '.' | ':'))
}
