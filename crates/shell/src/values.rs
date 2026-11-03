//! What a POSIX line sets its variables to, for the places where bash reads a
//! value again and runs what it holds: arithmetic (`$((x))`, `((x))`, `let`,
//! the arithmetic tests of `[[ … ]]`, an array subscript, a variable with the
//! integer attribute) reads a value as an expression and expands a subscript
//! in it (`a[$(cmd)]`), `${!x}` names a variable by the value, subscript and
//! all, and `${x@P}` expands the value as a prompt, command substitution
//! included.
//!
//! A value the line gives in text is read as the code it holds, where the
//! read is; a value only known when it runs is `unknown` there. A variable
//! the line never sets is the caller's environment, and is not judged.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::startup;
use crate::unit::{self, Split};
use crate::{Rule, Shell};

/// The most distinct values kept for one variable: past it the variable is
/// only known when it runs.
const MOST_VALUES: usize = 16;

/// The most distinct variables one value may name: past it the variable is
/// only known when it runs.
const MOST_NAMES: usize = 256;

/// The most variables a read follows through the values that name each other
/// (`x=y; y='a[$(cmd)]'; echo $((x))`): past it the read is `unknown`.
const MOST_FOLLOWED: usize = 64;

/// The reason of a read the guard cannot follow.
const UNKNOWN: &str = "may run code a variable holds that is only known when it runs";

/// The reason of arithmetic that reads a command's output as an expression.
pub(crate) const OUTPUT: &str = "may run code in a command's output that arithmetic reads";

/// The name the values of every positional parameter are kept under too, as
/// `$@` and `$*` read them all.
pub(crate) const POSITIONAL: &str = "@";

/// One value the line gives a variable.
#[derive(Debug, Clone)]
pub(crate) enum Value {
    /// The text, as the variable holds it.
    Text(String),
    /// A value only known when it runs, as written.
    Unknown(String),
}

/// What the line sets one variable to, read once when it is set.
#[derive(Debug, Default)]
struct Entry {
    /// The texts it is set to, to tell a value seen before.
    texts: Vec<String>,
    /// A value only known when it runs, as written.
    unknown: Option<String>,
    /// The values that hold code: `$(`, a backtick or `${`.
    codes: Vec<String>,
    /// The values that hold code once a prompt's escapes are decoded.
    prompts: Vec<String>,
    /// The variables its values name, as an expression reads them.
    names: Vec<String>,
    /// The variables named in a subscript of its values (`a[i]`), which
    /// `${!x}` reads as an expression.
    indexes: Vec<String>,
}

/// What a read by arithmetic of one variable runs: every variable the value
/// names is read too.
#[derive(Debug, Default)]
struct Followed {
    unknown: Option<String>,
    codes: Vec<String>,
}

/// The values of the variables a line sets, kept for the whole line and the
/// scripts nested in it (`x=…; eval 'echo $((x))'`).
#[derive(Debug, Default)]
pub(crate) struct Values {
    set: HashMap<String, Entry>,
    /// The variables given the integer attribute (`declare -i n`): an
    /// assignment to one reads its value as arithmetic.
    integers: HashSet<String>,
    /// The arrays declared associative (`declare -A m`), whose keys are
    /// text, not arithmetic.
    associative: HashSet<String>,
    /// The variables declared a reference to another (`declare -n r`): a
    /// read of one reads the variable its value names, subscript and all.
    references: HashSet<String>,
    /// Whether the line shifts the positional parameters, so that each may
    /// hold the value of any other.
    pub(crate) shifted: bool,
    /// What a read by arithmetic of a variable runs, worked out once.
    followed: HashMap<String, Rc<Followed>>,
}

impl Values {
    /// Note that the line sets `name` to `value`.
    pub(crate) fn add(&mut self, name: &str, value: Value) {
        self.followed.clear();
        let entry = self.set.entry(name.to_string()).or_default();
        let text = match value {
            Value::Unknown(written) => {
                entry.unknown.get_or_insert(written);
                return;
            }
            Value::Text(text) => text,
        };
        if entry.texts.contains(&text) {
            return;
        }
        if entry.texts.len() >= MOST_VALUES {
            entry.unknown.get_or_insert(text);
            return;
        }
        if holds_code(&text) {
            entry.codes.push(text.clone());
        }
        let prompt = startup::prompt(&text);
        if startup::runs(&prompt.text) || prompt.undecoded && prompt.text.contains(['$', '(', '`'])
        {
            entry.prompts.push(prompt.text.into_owned());
        }
        for (list, found) in [
            (&mut entry.names, names(&text)),
            (&mut entry.indexes, index_names(&text)),
        ] {
            for name in found {
                if list.len() >= MOST_NAMES {
                    entry.unknown.get_or_insert(text.clone());
                    break;
                }
                if !list.contains(&name) {
                    list.push(name);
                }
            }
        }
        entry.texts.push(text);
    }

    /// The texts the line set `name` to so far, and whether one is only
    /// known when it runs: what `name+=…` appends to.
    pub(crate) fn texts(&self, name: &str) -> (Vec<String>, bool) {
        self.set.get(name).map_or((Vec::new(), false), |entry| {
            (entry.texts.clone(), entry.unknown.is_some())
        })
    }

    /// Note that the line gives `name` the integer attribute.
    pub(crate) fn integer(&mut self, name: &str) {
        self.integers.insert(name.to_string());
    }

    /// Whether the line gives `name` the integer attribute anywhere.
    pub(crate) fn is_integer(&self, name: &str) -> bool {
        self.integers.contains(name)
    }

    /// Note that the line declares `name` an associative array.
    pub(crate) fn associative(&mut self, name: &str) {
        self.associative.insert(name.to_string());
    }

    /// Whether the line declares `name` an associative array anywhere.
    pub(crate) fn is_associative(&self, name: &str) -> bool {
        self.associative.contains(name)
    }

    /// Note that the line declares `name` a reference to another variable.
    pub(crate) fn reference(&mut self, name: &str) {
        self.references.insert(name.to_string());
    }

    /// Whether the line declares `name` a reference anywhere.
    pub(crate) fn is_reference(&self, name: &str) -> bool {
        self.references.contains(name)
    }

    /// After the whole line is read: a shift moves every positional
    /// parameter's value to another, so each is only known when it runs.
    pub(crate) fn settle(&mut self) {
        if !self.shifted {
            return;
        }
        let positional: Vec<String> = self
            .set
            .keys()
            .filter(|name| {
                name.as_str() == POSITIONAL || name.bytes().all(|byte| byte.is_ascii_digit())
            })
            .cloned()
            .collect();
        for name in positional {
            self.add(&name, Value::Unknown("shift".to_string()));
        }
    }

    /// The variables the values of `name` name, as `${!name}` reads them
    /// (`a[i]` names `a` and `i`), and whether one of its values is only
    /// known when it runs. Nothing for a variable the line does not set.
    pub(crate) fn named_by(&self, name: &str) -> (Vec<String>, bool) {
        self.set.get(name).map_or((Vec::new(), false), |entry| {
            (entry.names.clone(), entry.unknown.is_some())
        })
    }

    /// What a read by arithmetic of `name` runs, following the variables its
    /// values name.
    fn follow(&mut self, name: &str) -> Rc<Followed> {
        if let Some(found) = self.followed.get(name) {
            return Rc::clone(found);
        }
        let mut followed = Followed::default();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut next = vec![name];
        while let Some(at) = next.pop() {
            if !seen.insert(at) {
                continue;
            }
            if seen.len() > MOST_FOLLOWED {
                followed.unknown.get_or_insert_with(|| name.to_string());
                break;
            }
            let Some(entry) = self.set.get(at) else {
                continue;
            };
            if let Some(unknown) = &entry.unknown {
                followed.unknown.get_or_insert_with(|| unknown.clone());
            }
            for code in &entry.codes {
                if !followed.codes.contains(code) {
                    followed.codes.push(code.clone());
                }
            }
            next.extend(entry.names.iter().map(String::as_str));
        }
        let followed = Rc::new(followed);
        self.followed.insert(name.to_string(), Rc::clone(&followed));
        followed
    }
}

/// Whether `text`, a value, holds code a read of it may run: `$(`, a
/// backtick, or a `${…}`, which may set or expand another value as code.
pub(crate) fn holds_code(text: &str) -> bool {
    text.contains("$(") || text.contains("${") || text.contains('`')
}

/// The variables `text`, an arithmetic expression, names: each name that
/// does not start a number (`0x1f`, `16#ff`) and is not assigned to (`x=1`,
/// but `x==1` and `x+=1` read it). Read loosely: a name in a quote or a
/// substitution counts too, which only follows more values.
pub(crate) fn names(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found: Vec<String> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        if !(bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'#' | b'@')) {
            at += 1;
            continue;
        }
        while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
            at += 1;
        }
        let word = &text[start..at];
        // A number in any base (`16#ff`, `0x1f`) is a number, all of it.
        if bytes[start].is_ascii_digit() || matches!(bytes[start], b'#' | b'@') {
            while at < bytes.len()
                && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'#' | b'@'))
            {
                at += 1;
            }
            at = at.max(start + 1);
            continue;
        }
        let rest = text[at..].trim_start();
        let assigned = rest.starts_with('=') && !rest.starts_with("==");
        if !assigned && seen.insert(word) {
            found.push(word.to_string());
        }
    }
    found
}

/// The variables named inside the brackets of `text` (`a[i+1]` names `i`).
fn index_names(text: &str) -> Vec<String> {
    let mut depth = 0_usize;
    let mut inside = String::new();
    for c in text.chars() {
        match c {
            '[' => {
                depth += 1;
                inside.push(' ');
            }
            ']' => {
                depth = depth.saturating_sub(1);
                inside.push(' ');
            }
            _ if depth > 0 => inside.push(c),
            _ => {}
        }
    }
    names(&inside)
}

/// Read `text`, a value bash expands again, as the script its `$(…)`,
/// backticks and `${…}` are, where the read runs.
fn run(split: &mut Split, text: &str, depth: usize) {
    if let Some(quoted) = startup::quote(text) {
        unit::script(split, &quoted, Shell::Posix, depth + 1);
    } else {
        split.problem(
            Rule::Unreadable,
            "may run code a variable holds that the guard cannot read to its end",
            Some(text),
        );
    }
}

/// Arithmetic reads the variables `names` at `site`: each value is an
/// expression, and the code in it runs.
pub(crate) fn arithmetic(split: &mut Split, names: &[String], site: &str, depth: usize) {
    let mut said = false;
    for name in names {
        let followed = split.values.follow(name);
        if followed.unknown.is_some() && !said {
            said = true;
            split.problem(Rule::Unknown, UNKNOWN, Some(site));
        }
        for code in &followed.codes {
            run(split, code, depth);
        }
    }
}

/// `${!name}` reads the variable the value of `name` names, with its
/// subscript read as arithmetic.
pub(crate) fn indirect(split: &mut Split, name: &str, site: &str, depth: usize) {
    let Some(entry) = split.values.set.get(name) else {
        return;
    };
    let unknown = entry.unknown.is_some();
    let codes = entry.codes.clone();
    let indexes = entry.indexes.clone();
    if unknown {
        split.problem(Rule::Unknown, UNKNOWN, Some(site));
    }
    for code in &codes {
        run(split, code, depth);
    }
    arithmetic(split, &indexes, site, depth);
}

/// A read of a reference, `r` after `declare -n r=value`: the variable the
/// value names is read, and its subscript is read as arithmetic.
pub(crate) fn referenced(split: &mut Split, value: &Value, depth: usize) {
    match value {
        Value::Text(text) => {
            if holds_code(text) {
                run(split, text, depth);
            }
            arithmetic(split, &index_names(text), text, depth);
        }
        Value::Unknown(written) => split.problem(Rule::Unknown, UNKNOWN, Some(written)),
    }
}

/// `${name@P}` expands the value of `name` as a prompt: its escapes decoded,
/// then its expansions and command substitutions.
pub(crate) fn prompt(split: &mut Split, name: &str, site: &str, depth: usize) {
    let Some(entry) = split.values.set.get(name) else {
        return;
    };
    let unknown = entry.unknown.is_some();
    let prompts = entry.prompts.clone();
    if unknown {
        split.problem(Rule::Unknown, UNKNOWN, Some(site));
    }
    for code in &prompts {
        run(split, code, depth);
    }
}

/// `text`, an expression the line writes out where arithmetic reads it (the
/// value of a variable with the integer attribute): the code in it runs, and
/// the variables it names are read.
pub(crate) fn expression(split: &mut Split, text: &str, depth: usize) {
    if holds_code(text) {
        run(split, text, depth);
    }
    arithmetic(split, &names(text), text, depth);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_read_as_an_expression_reads_them() {
        assert_eq!(names("x + y1*2"), ["x", "y1"]);
        assert_eq!(names("0x1f + 16#ff + 2#101"), Vec::<String>::new());
        assert_eq!(names("x = y"), ["y"]);
        assert_eq!(names("x == y"), ["x", "y"]);
        assert_eq!(names("x += 1"), ["x"]);
        assert_eq!(names("a[i]"), ["a", "i"]);
        assert_eq!(names("x x"), ["x"]);
    }

    #[test]
    fn a_subscript_names_its_variables() {
        assert_eq!(index_names("a[i+1]"), ["i"]);
        assert_eq!(index_names("a"), Vec::<String>::new());
        assert_eq!(index_names("a[b[j]]"), ["b", "j"]);
    }

    #[test]
    fn a_value_is_followed_through_the_names_it_holds() {
        let mut values = Values::default();
        values.add("x", Value::Text("y".to_string()));
        values.add("y", Value::Text("a[$(cmd)]".to_string()));
        values.add("z", Value::Text("3".to_string()));
        values.add("w", Value::Unknown("$1".to_string()));
        assert_eq!(values.follow("x").codes, ["a[$(cmd)]"]);
        assert!(values.follow("z").codes.is_empty());
        assert!(values.follow("z").unknown.is_none());
        assert!(values.follow("w").unknown.is_some());
        assert!(values.follow("unset").unknown.is_none());
    }

    #[test]
    fn a_cycle_of_names_ends() {
        let mut values = Values::default();
        values.add("x", Value::Text("y".to_string()));
        values.add("y", Value::Text("x".to_string()));
        assert!(values.follow("x").codes.is_empty());
    }

    #[test]
    fn too_many_values_are_only_known_when_they_run() {
        let mut values = Values::default();
        for at in 0..=MOST_VALUES {
            values.add("x", Value::Text(at.to_string()));
        }
        assert!(values.follow("x").unknown.is_some());
    }
}
