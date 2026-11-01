//! A password, a secret or a token written down as the value of a name:
//! `password=hunter22`, `"api_key": "…"`, `export TOKEN=…`.
//!
//! This is the one detector that reads a name, so it is the one where code
//! is easy to mistake for a secret (`password: String`, `token = self.token`,
//! `let secret = get_secret();`). It judges the value it reads:
//!
//! - the name must end in a word that names a secret (`password`, `secret`,
//!   `token`, `api_key`, …); `tokens`, `max_tokens` and `password_hash` do
//!   not;
//! - the value is the text after `=`, `:`, `:=`, `==` or `=>`: a string in
//!   quotes, or a word up to a space, a quote or a separator (`,` `;` `&`
//!   `|` `(` `)`);
//! - a value that is no value is not a secret: empty, shorter than six
//!   characters, a reference to a variable or a template field, a mask, a
//!   label (`"password": "Password"`), a call, or a chain of names;
//! - a quoted value has no space in it; an unquoted one is a secret when the
//!   name is tied to it (`password=value`, as an environment file, a query
//!   or a connection string write it), or when it has a digit in it
//!   (`password: hunter22`), which a word of code does not.
//!
//! The span is the value, without its quotes, so a caller that scrubs it
//! keeps the name.

use std::sync::OnceLock;

use regex::Regex;

use crate::mask::Mask;
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

/// Words a quoted value is when it is the label of a field and no secret.
const LABELS: [&str; 17] = [
    "string",
    "str",
    "null",
    "none",
    "nil",
    "undefined",
    "true",
    "false",
    "required",
    "optional",
    "password",
    "secret",
    "token",
    "example",
    "redacted",
    "hidden",
    "masked",
];

fn key() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(KEY).ok()).as_ref()
}

/// Adds a hit for each secret written as the value of a name in `text`.
pub(crate) fn scan(text: &str, lower: &str, out: &mut Vec<Hit>) {
    if !NEEDLES.iter().any(|needle| lower.contains(needle)) {
        return;
    }
    let Some(regex) = key() else {
        return;
    };
    let mut at = 0;
    while let Some(captures) = regex.captures_at(text, at) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            break;
        };
        // Whatever is decided, the next search starts inside the value, so a
        // name written within a value is still read.
        at = whole.end();
        if !is_secret_name(name.as_str()) {
            continue;
        }
        let gap = text.get(name.end()..whole.end()).unwrap_or_default();
        let tied = !gap.contains([' ', '\t']) && gap.trim_matches(['"', '\'', '\\']) == "=";
        let Some(value) = read_value(text, whole.end()) else {
            continue;
        };
        let word = text.get(value.start..value.end).unwrap_or_default();
        let call = !value.quoted && text::after(text, value.end) == Some('(');
        if accept(name.as_str(), word, value.quoted, tied) && !call {
            out.push(Hit {
                rule: Rule::GenericSecret,
                reason: "holds a password or secret",
                start: value.start,
                end: value.end,
                mask: Mask::Length,
            });
            at = value.after;
        }
    }
}

/// The value after an operator: where it is, whether it was quoted, and
/// where reading resumes.
struct Value {
    start: usize,
    end: usize,
    after: usize,
    quoted: bool,
}

fn read_value(text: &str, from: usize) -> Option<Value> {
    let rest = text.get(from..)?;
    let mut chars = rest.chars();
    let first = chars.next()?;
    // A quote, or a quote written `\"` because the whole is inside a string.
    let (quote, opening) = match (first, chars.next()) {
        ('"' | '\'', _) => (Some(first), 1),
        ('\\', Some(second @ ('"' | '\''))) => (Some(second), 2),
        _ => (None, 0),
    };
    if let Some(quote) = quote {
        let escaped = opening == 2;
        let inner = rest.get(opening..)?;
        let close = inner.find([quote, '\n', '\r'])?;
        if !inner[close..].starts_with(quote) {
            return None;
        }
        // The closing `\"` of an escaped value takes its backslash with it.
        let length = if escaped {
            inner.get(..close)?.strip_suffix('\\')?.len()
        } else {
            close
        };
        return Some(Value {
            start: from + opening,
            end: from + opening + length,
            after: from + opening + close + 1,
            quoted: true,
        });
    }
    let length = rest
        .find([
            ' ', '\t', '\r', '\n', '"', '\'', '`', ',', ';', '&', '|', '(', ')',
        ])
        .unwrap_or(rest.len());
    Some(Value {
        start: from,
        end: from + length,
        after: from + length,
        quoted: false,
    })
}

/// Whether `name` ends in a word that names a secret.
fn is_secret_name(name: &str) -> bool {
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
    let squeezed: String = lower
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .collect();
    ENDINGS.iter().any(|ending| squeezed.ends_with(ending))
        // `pass` alone is also the end of `bypass` and `compass`.
        || lower == "pass"
        || ["_pass", "-pass", ".pass"]
            .iter()
            .any(|ending| lower.ends_with(ending))
}

/// Whether the value read after `name` is a secret.
fn accept(name: &str, value: &str, quoted: bool, tied: bool) -> bool {
    if value.chars().count() < MIN_VALUE || text::is_reference(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let squeezed: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .collect();
    // `password=password`, `"token": "Token"`: the name said twice.
    if LABELS.contains(&lower.as_str()) || lower == squeezed {
        return false;
    }
    // The values AWS's documentation shows end in EXAMPLE or EXAMPLEKEY.
    if lower.starts_with("your_")
        || lower.starts_with("your-")
        || value.ends_with("EXAMPLE")
        || value.ends_with("EXAMPLEKEY")
    {
        return false;
    }
    if quoted {
        return !value.contains([' ', '\t']);
    }
    if value.contains(['[', ']']) || is_chain_of_names(value) {
        return false;
    }
    // Base64 ends in `=` when it is padded: a Kubernetes secret is written so.
    tied || value.ends_with('=') || value.bytes().any(|b| b.is_ascii_digit())
}

/// Whether `value` is names joined by dots or colons (`self.token`,
/// `config::TOKEN`): a reading of another value, not a value.
fn is_chain_of_names(value: &str) -> bool {
    value.contains(['.', ':'])
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '.' | ':'))
}
