//! The options `zip` reads from its environment before its own: Info-ZIP's
//! `zip` reads `ZIPOPT`, and `ZIP` when `ZIPOPT` holds no word. A value the
//! line gives either one is noted once, where it is set: an assignment
//! replaces the one before it, and a prefix assignment or a wrapper's
//! (`ZIPOPT=-m zip …`, `env ZIP=-m zip …`) covers only its own command, which
//! the walk sees to by putting the noted values back after the command.

use std::rc::Rc;

use crate::unit::Arg;

/// The most words of a value split into options. Real values hold a
/// handful; past it, the value is not split and the options are only known
/// when it runs, so that each `zip` call costs no more than this.
const MAX_WORDS: usize = 64;

/// The longest value split into options, in bytes, for the same reason.
const MAX_LEN: usize = 1024;

/// What `zip` reads in front of its own options, when the line sets them.
#[derive(Debug, Clone, Default)]
pub(crate) struct ZipEnv {
    /// `ZIPOPT`'s value, when the line sets it.
    zipopt: Option<Value>,
    /// `ZIP`'s value, when the line sets it.
    zip: Option<Value>,
}

/// One variable's value.
#[derive(Debug, Clone)]
enum Value {
    /// Its words, split as `zip` splits them, once, and the text they were
    /// split from.
    Words(Rc<[String]>, Rc<str>),
    /// Only known when it runs: the text as written.
    Unknown(String),
    /// Longer than the guard splits.
    TooLong,
}

/// What reading the options found: the words, and a reason for each value
/// that holds options only known when it runs, with the text as written.
pub(crate) struct Read {
    pub(crate) words: Vec<Arg>,
    pub(crate) problems: Vec<(&'static str, Option<String>)>,
}

impl ZipEnv {
    /// Whether the line set neither variable.
    pub(crate) fn is_empty(&self) -> bool {
        self.zipopt.is_none() && self.zip.is_none()
    }

    /// Note `value` as what the variable `name` holds now, when it is
    /// `ZIPOPT` or `ZIP` (in any case, when `fold`: cmd and PowerShell read
    /// the names of variables so); whether it is one.
    pub(crate) fn set(&mut self, name: &str, value: &Arg, fold: bool) -> bool {
        let Some(slot) = self.slot(name, fold) else {
            return false;
        };
        *slot = Some(match value {
            Arg::Known(text) => split(text),
            other => Value::Unknown(other.text().to_string()),
        });
        true
    }

    /// `ZIPOPT+=value`: `value` added to the end of what the line gave the
    /// variable, or its whole value when the line gave none.
    pub(crate) fn append(&mut self, name: &str, value: &Arg) -> bool {
        let Some(slot) = self.slot(name, false) else {
            return false;
        };
        *slot = Some(match (slot.take(), value) {
            (None, Arg::Known(text)) => split(text),
            (Some(Value::Words(_, before)), Arg::Known(text)) => {
                if before.len() + text.len() > MAX_LEN {
                    Value::TooLong
                } else {
                    split(&format!("{before}{text}"))
                }
            }
            (Some(Value::TooLong), Arg::Known(_)) => Value::TooLong,
            (Some(unknown @ Value::Unknown(_)), Arg::Known(_)) => unknown,
            (_, other) => Value::Unknown(other.text().to_string()),
        });
        true
    }

    /// `export ZIPOPT` (`declare -x`) of a value set another way: the one the
    /// line gave stays, and with none the value is only known when it runs
    /// (`read`, `printf -v`). Whether `name` is one of the variables.
    pub(crate) fn export(&mut self, name: &str, source: &str) -> bool {
        let Some(slot) = self.slot(name, false) else {
            return false;
        };
        if slot.is_none() {
            *slot = Some(Value::Unknown(source.to_string()));
        }
        true
    }

    fn slot(&mut self, name: &str, fold: bool) -> Option<&mut Option<Value>> {
        let is = |full: &str| {
            if fold {
                name.eq_ignore_ascii_case(full)
            } else {
                name == full
            }
        };
        if is("ZIPOPT") {
            Some(&mut self.zipopt)
        } else if is("ZIP") {
            Some(&mut self.zip)
        } else {
            None
        }
    }

    /// The options `zip` reads before its own. `ZIP` counts unless the line
    /// gives `ZIPOPT` words it knows: with none, or a value only known when
    /// it runs, which may be empty, `zip` may read `ZIP` instead.
    pub(crate) fn read(&self) -> Read {
        let mut read = Read {
            words: Vec::new(),
            problems: Vec::new(),
        };
        let mut add = |value: &Value| match value {
            Value::Words(words, _) => read
                .words
                .extend(words.iter().map(|word| Arg::Known(word.clone()))),
            Value::Unknown(text) => read.problems.push((
                "gives zip options only known when it runs",
                Some(text.clone()),
            )),
            Value::TooLong => read
                .problems
                .push(("gives zip options too long to read", None)),
        };
        let mut known = false;
        if let Some(value) = &self.zipopt {
            known = matches!(value, Value::Words(words, _) if !words.is_empty());
            add(value);
        }
        if !known {
            if let Some(value) = &self.zip {
                add(value);
            }
        }
        read
    }
}

/// `text` split as `zip` splits it (`envargs`): at white space, where a word
/// that starts with `"` runs to the next `"` and is read without the quotes.
fn split(text: &str) -> Value {
    if text.len() > MAX_LEN {
        return Value::TooLong;
    }
    let mut words = Vec::new();
    let mut rest = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    while !rest.is_empty() {
        if words.len() == MAX_WORDS {
            return Value::TooLong;
        }
        let (word, after) = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
            None => rest
                .split_once(|c: char| c.is_ascii_whitespace())
                .unwrap_or((rest, "")),
        };
        words.push(word.to_string());
        rest = after.trim_start_matches(|c: char| c.is_ascii_whitespace());
    }
    Value::Words(words.into(), text.into())
}

#[cfg(test)]
mod tests {
    use super::{split, Value};

    fn words(text: &str) -> Vec<String> {
        match split(text) {
            Value::Words(words, _) => words.to_vec(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_value_is_split_as_zip_splits_it() {
        assert_eq!(words(" -q  -m "), ["-q", "-m"]);
        assert_eq!(words("\"-m\""), ["-m"]);
        assert_eq!(words("-q \"-x a b\" -m"), ["-q", "-x a b", "-m"]);
        assert_eq!(words("\"-m"), ["-m"]);
        assert!(words("  ").is_empty());
        assert!(matches!(split(&"-q ".repeat(65)), Value::TooLong));
        assert!(matches!(split(&"q".repeat(1025)), Value::TooLong));
    }
}
