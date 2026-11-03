//! The walk's side of [`crate::values`]: the values a line gives its
//! variables, read from the tree before the walk, and the places the walk
//! finds that read a value again as code (arithmetic, `${!x}`, `${x@P}`), or
//! read quoted text as code where the grammar does not (single quotes in a
//! `${…}` word inside double quotes, an escaped backtick inside backticks).

use tree_sitter::Node;

use super::{backtick_codes, Walker, OPAQUE};
use crate::unit::{self, Arg};
use crate::values::{self, Value};
use crate::{startup, Rule, Shell};

/// The tests of `[[ … ]]` that read both sides as arithmetic.
const ARITHMETIC_TESTS: [&str; 6] = ["-eq", "-ne", "-lt", "-le", "-gt", "-ge"];

/// The kinds of node whose text runs, or names a value, only when it runs.
const EXPANDING: [&str; 4] = [
    "simple_expansion",
    "expansion",
    "command_substitution",
    "process_substitution",
];

impl Walker<'_> {
    /// Note the value `node` gives a variable, if it gives one: an
    /// assignment (also after `declare` and the like, and `+=`), the words of
    /// a `for` loop, a `${x:=v}`, and a value only known when it runs from
    /// `read`, `mapfile`, `printf -v` and `getopts`. Every node of the line
    /// is handed here before the walk, and which value reaches a read is not
    /// worked out: every value counts.
    pub(super) fn note_value(&mut self, node: Node<'_>) {
        match node.kind() {
            "variable_assignment" => self.note_assignment(node),
            "for_statement" => self.note_loop(node),
            "declaration_command" => self.note_declaration(node),
            "command" => self.note_read(node),
            "expansion" => self.note_default(node),
            _ => {}
        }
    }

    /// The name an assignment sets, without a subscript: `a[i]=x` sets `a`.
    fn assigned_name(&self, name: Node<'_>) -> String {
        let name = match name.kind() {
            "subscript" => name.child_by_field_name("name").unwrap_or(name),
            _ => name,
        };
        unit::text(&name, self.source).to_string()
    }

    fn note_assignment(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.assigned_name(name);
        let mut cursor = node.walk();
        let appends = node
            .children(&mut cursor)
            .any(|child| !child.is_named() && unit::text(&child, self.source) == "+=");
        let found: Vec<Value> = match node.child_by_field_name("value") {
            None => vec![Value::Text(String::new())],
            Some(array) if array.kind() == "array" => {
                let mut cursor = array.walk();
                array
                    .named_children(&mut cursor)
                    .map(|element| self.value(element))
                    .collect()
            }
            Some(value) => vec![self.value(value)],
        };
        for value in found {
            let value = if appends {
                Self::appended(&self.split.values.texts(&name), value)
            } else {
                value
            };
            self.split.values.add(&name, value);
        }
    }

    /// `name+=value`: the value is what it held, then this. Pieces may join
    /// into a `$(` none of them holds (`x='$'; x+='(cmd)'`), so a `$` or a
    /// backtick in any piece makes it only known when it runs.
    fn appended((texts, unknown): &(Vec<String>, bool), value: Value) -> Value {
        let Value::Text(added) = value else {
            return value;
        };
        let joined: String = texts
            .iter()
            .map(String::as_str)
            .chain([added.as_str()])
            .collect();
        if *unknown || joined.contains(['$', '`']) {
            Value::Unknown(joined)
        } else {
            Value::Text(joined)
        }
    }

    /// The value `node`, the right side of an assignment, gives: its text,
    /// with an arithmetic expansion taken as the number it is, or only known
    /// when it runs when anything else in it expands.
    fn value(&self, node: Node<'_>) -> Value {
        let written = unit::text(&node, self.source);
        let mut expands = false;
        let mut stack = vec![node];
        while let Some(at) = stack.pop() {
            if at.kind() == "arithmetic_expansion" {
                continue;
            }
            expands |= EXPANDING.contains(&at.kind());
            let mut cursor = at.walk();
            stack.extend(at.named_children(&mut cursor));
        }
        if expands {
            return Value::Unknown(written.to_string());
        }
        match node.kind() {
            "arithmetic_expansion" => Value::Text("0".to_string()),
            "raw_string" | "string" | "concatenation" | "word" | "number" => match self.arg(node) {
                Arg::Known(text) => Value::Text(text),
                Arg::Template { text, .. } => Value::Text(text.replace(OPAQUE, "0")),
                Arg::Unknown(_) | Arg::Input | Arg::Null => Value::Unknown(written.to_string()),
            },
            _ => Value::Unknown(written.to_string()),
        }
    }

    /// `for x in a b c`: each word, or a value only known when it runs for a
    /// word that expands or matches names (`*.txt`), and for a loop over the
    /// arguments (`for x; do`).
    fn note_loop(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("variable") else {
            return;
        };
        let name = unit::text(&name, self.source).to_string();
        let mut cursor = node.walk();
        let words: Vec<Node<'_>> = node.children_by_field_name("value", &mut cursor).collect();
        if words.is_empty() {
            self.split.values.add(
                &name,
                Value::Unknown(unit::text(&node, self.source).to_string()),
            );
        }
        for word in words {
            let value = match self.value(word) {
                Value::Text(text)
                    if word.kind() != "raw_string" && text.contains(['*', '?', '[']) =>
                {
                    Value::Unknown(text)
                }
                value => value,
            };
            self.split.values.add(&name, value);
        }
    }

    /// `declare -i n`, `local -i n=…`: the variables given the integer
    /// attribute, and a quoted assignment (`export "x=…"`), which the grammar
    /// reads as a string.
    fn note_declaration(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let integer = children.iter().any(|child| {
            let text = unit::text(child, self.source);
            text.starts_with('-') && !text.starts_with("--") && text.contains('i')
        });
        for child in children {
            match child.kind() {
                "variable_assignment" | "variable_name" => {
                    let name = child.child_by_field_name("name").unwrap_or(child);
                    let name = self.assigned_name(name);
                    if integer {
                        self.split.values.integer(&name);
                    }
                }
                _ => {
                    let Some((name, value)) = startup::word(&self.arg(child)) else {
                        continue;
                    };
                    let name = name.split('[').next().unwrap_or_default().to_string();
                    let value = match value {
                        Arg::Known(text) => Value::Text(text),
                        other => Value::Unknown(other.text().to_string()),
                    };
                    if integer {
                        self.split.values.integer(&name);
                    }
                    self.split.values.add(&name, value);
                }
            }
        }
    }

    /// `read x`, `mapfile x`, `printf -v x …`, `getopts o x`: a value only
    /// known when it runs.
    fn note_read(&mut self, node: Node<'_>) {
        let Some(program) = node.child_by_field_name("name") else {
            return;
        };
        let program = unit::text(&program, self.source);
        if !matches!(
            program,
            "read" | "mapfile" | "readarray" | "printf" | "getopts"
        ) {
            return;
        }
        let mut cursor = node.walk();
        let args: Vec<String> = node
            .children_by_field_name("argument", &mut cursor)
            .map(|arg| unit::text(&arg, self.source).to_string())
            .collect();
        let names: Vec<&str> = match program {
            "read" | "mapfile" | "readarray" => args
                .iter()
                .map(String::as_str)
                .filter(|arg| !arg.starts_with('-'))
                .collect(),
            "printf" => args
                .iter()
                .enumerate()
                .filter_map(|(at, arg)| match arg.as_str() {
                    "-v" => args.get(at + 1).map(String::as_str),
                    _ => arg.strip_prefix("-v").filter(|name| !name.is_empty()),
                })
                .collect(),
            "getopts" => args.get(1).map(String::as_str).into_iter().collect(),
            _ => Vec::new(),
        };
        let written = unit::text(&node, self.source);
        for name in names {
            let name = name.split('[').next().unwrap_or_default();
            self.split
                .values
                .add(name, Value::Unknown(written.to_string()));
        }
    }

    /// `${x:=v}` and `${x=v}` set `x` to `v` when it has no value: a word
    /// written out plainly, or a value only known when it runs.
    fn note_default(&mut self, node: Node<'_>) {
        let Some((name, rest)) = Self::parts(unit::text(&node, self.source)) else {
            return;
        };
        if name.bang {
            return;
        }
        let Some(word) = rest.strip_prefix(":=").or_else(|| rest.strip_prefix('=')) else {
            return;
        };
        let value = if word.contains(['\'', '"', '\\', '$', '`']) {
            Value::Unknown(word.to_string())
        } else {
            Value::Text(word.to_string())
        };
        self.split.values.add(name.name, value);
    }

    /// The variables an arithmetic expression at `node` reads. A subscript
    /// reads its array, and its index is read where the walk reaches it; a
    /// substitution and a nested `$((…))` are read where the walk reaches
    /// them; `${#x}` is a length and reads no value as code.
    pub(super) fn arithmetic_names(&self, node: Node<'_>) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![node];
        while let Some(at) = stack.pop() {
            let text = unit::text(&at, self.source);
            match at.kind() {
                "command_substitution" | "process_substitution" => continue,
                "arithmetic_expansion" if at.id() != node.id() => continue,
                "expansion" if text.starts_with("${#") || text.starts_with("${!") => continue,
                "subscript" => {
                    if let Some(name) = at.child_by_field_name("name") {
                        found.push(unit::text(&name, self.source).to_string());
                    }
                    continue;
                }
                "variable_name" => {
                    found.push(text.to_string());
                    continue;
                }
                "word" | "number" | "string_content" | "raw_string" => {
                    found.extend(values::names(text));
                    continue;
                }
                // `x = 1` and `i=0` (in a `for ((…))`) set `x`, not read it.
                "variable_assignment" => {
                    stack.extend(at.child_by_field_name("value"));
                    continue;
                }
                "binary_expression" => {
                    let mut cursor = at.walk();
                    let plain = at
                        .children(&mut cursor)
                        .any(|child| !child.is_named() && unit::text(&child, self.source) == "=");
                    if plain {
                        stack.extend(at.child_by_field_name("right"));
                        continue;
                    }
                }
                _ => {}
            }
            let mut cursor = at.walk();
            stack.extend(at.named_children(&mut cursor));
        }
        found
    }

    /// Read the variables arithmetic at `node` names: the code their values
    /// hold runs here.
    pub(super) fn arithmetic(&mut self, node: Node<'_>) {
        let names = self.arithmetic_names(node);
        if !names.is_empty() {
            let site = unit::text(&node, self.source);
            values::arithmetic(self.split, &names, site, self.depth);
        }
    }

    /// `(( … ))`, which the grammar holds as a compound statement as it does
    /// `{ …; }`.
    pub(super) fn is_arithmetic_command(&self, node: Node<'_>) -> bool {
        node.child(0)
            .is_some_and(|open| !open.is_named() && unit::text(&open, self.source) == "((")
    }

    /// `for ((init; test; step))`: the three expressions, not the body.
    pub(super) fn arithmetic_for(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let parts: Vec<Node<'_>> = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "do_group" && child.kind() != "compound_statement")
            .collect();
        for part in parts {
            self.arithmetic(part);
        }
    }

    /// An array's subscript, outside arithmetic or in it: the index is an
    /// expression (`${a[i]}`, `a[i]=1`), unless it is `@` or `*`.
    pub(super) fn subscript(&mut self, node: Node<'_>) {
        let Some(index) = node.child_by_field_name("index") else {
            return;
        };
        if !matches!(unit::text(&index, self.source), "@" | "*") {
            self.arithmetic(index);
        }
    }

    /// `[[ a -eq b ]]` and the other arithmetic tests read both sides as
    /// expressions. `[ … ]` and `test` read numbers only.
    pub(super) fn arithmetic_tests(&mut self, node: Node<'_>) {
        if !unit::text(&node, self.source).starts_with("[[") {
            return;
        }
        let mut sides = Vec::new();
        let mut stack = vec![node];
        while let Some(at) = stack.pop() {
            if matches!(at.kind(), "command_substitution" | "process_substitution") {
                continue;
            }
            let mut cursor = at.walk();
            let arithmetic = at.kind() == "binary_expression"
                && at.children(&mut cursor).any(|child| {
                    child.kind() == "test_operator"
                        && ARITHMETIC_TESTS.contains(&unit::text(&child, self.source))
                });
            if arithmetic {
                sides.extend(at.child_by_field_name("left"));
                sides.extend(at.child_by_field_name("right"));
            } else {
                let mut cursor = at.walk();
                stack.extend(at.named_children(&mut cursor));
            }
        }
        for side in sides {
            self.arithmetic(side);
        }
    }

    /// `let x+1 …`: each word is an expression.
    pub(super) fn let_words(&mut self, command: Node<'_>) {
        let is_let = command
            .child_by_field_name("name")
            .is_some_and(|name| unit::text(&name, self.source) == "let");
        if !is_let {
            return;
        }
        let mut cursor = command.walk();
        let words: Vec<Node<'_>> = command
            .children_by_field_name("argument", &mut cursor)
            .collect();
        for word in words {
            self.arithmetic(word);
        }
    }

    /// `name=value` where the line gave `name` the integer attribute: the
    /// value is read as arithmetic.
    pub(super) fn integer_assignment(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        if !self.split.values.is_integer(&self.assigned_name(name)) {
            return;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        let site = unit::text(&node, self.source);
        match self.value(value) {
            Value::Text(text) => values::expression(self.split, &text, self.depth),
            Value::Unknown(_) => self.split.problem(
                Rule::Unknown,
                "may run code in a value only known when it runs",
                Some(site),
            ),
        }
    }

    /// A `${…}` that reads a value again: `${!x}` (but not `${!x@}`,
    /// `${!x*}` or `${!a[@]}`, which list names and keys), `${x@P}`, and the
    /// offset and length of `${x:i:j}`, which are expressions. Inside double
    /// quotes, single quotes in its word are text, so what they hold is read
    /// as the inside of double quotes.
    pub(super) fn expansion(&mut self, node: Node<'_>) {
        let site = unit::text(&node, self.source);
        if let Some((name, rest)) = Self::parts(site) {
            let listing = matches!(rest, "@" | "*")
                || matches!(name.index, Some("@" | "*")) && rest.is_empty();
            if name.bang && !listing {
                values::indirect(self.split, name.name, site, self.depth);
            }
            if !name.bang && rest == "@P" {
                values::prompt(self.split, name.name, site, self.depth);
            }
            let offset = rest
                .strip_prefix(':')
                .filter(|offset| !offset.starts_with(['-', '=', '?', '+']));
            if let (false, Some(offset)) = (name.bang, offset) {
                values::arithmetic(self.split, &values::names(offset), site, self.depth);
            }
        }
        if self.in_double_quotes(node) {
            let mut quoted = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "concatenation" {
                    let mut inner = child.walk();
                    quoted.extend(child.named_children(&mut inner));
                } else {
                    quoted.push(child);
                }
            }
            for part in quoted {
                let text = unit::text(&part, self.source);
                let inner = match part.kind() {
                    "raw_string" => text.strip_prefix('\''),
                    "ansi_c_string" => text.strip_prefix("$'"),
                    _ => None,
                }
                .and_then(|inner| inner.strip_suffix('\''));
                if let Some(inner) = inner.filter(|inner| inner.contains(['$', '`'])) {
                    self.quoted_text(inner);
                }
            }
        }
    }

    /// Read `text`, written in single quotes the shell takes as text, as the
    /// inside of double quotes: its `$(…)`, backticks and `${…}` run.
    fn quoted_text(&mut self, text: &str) {
        if let Some(quoted) = startup::quote(text) {
            unit::script(self.split, &quoted, Shell::Posix, self.depth + 1);
        } else {
            self.split.problem(
                Rule::Unreadable,
                "has quoted text that runs code the guard cannot read to its end",
                Some(text),
            );
        }
    }

    /// Whether `node`, a `${…}`, is inside double quotes (or the body of a
    /// here-document, read the same way), and not inside a substitution in
    /// them.
    fn in_double_quotes(&self, node: Node<'_>) -> bool {
        let mut up = node.parent();
        while let Some(parent) = up {
            match parent.kind() {
                "string" | "heredoc_body" => return true,
                "expansion" | "concatenation" => up = parent.parent(),
                _ => return false,
            }
        }
        false
    }

    /// A backtick substitution whose text holds a backslash before a
    /// backtick, a `$`, a backslash or a `"`: the shell takes the backslash
    /// off before it reads the code, so an escaped backtick inside starts a
    /// substitution of its own, which the grammar reads as words. The code is
    /// read as the shell reads it, each reading the shells differ on; `false`
    /// when there is no such escape, and the grammar's reading holds.
    pub(super) fn escaped_backticks(&mut self, node: Node<'_>) -> bool {
        let text = unit::text(&node, self.source);
        let Some(inner) = text
            .strip_prefix('`')
            .and_then(|inner| inner.strip_suffix('`'))
        else {
            return false;
        };
        if !inner.contains('\\') {
            return false;
        }
        match backtick_codes(text, &[], false) {
            Some(codes) if codes.len() == 1 && codes[0] == inner => false,
            Some(codes) => {
                for code in codes {
                    unit::script(self.split, &code, Shell::Posix, self.depth + 1);
                }
                true
            }
            None => {
                self.split.problem(
                    Rule::Unreadable,
                    "has a backtick substitution that cannot be read",
                    Some(text),
                );
                true
            }
        }
    }

    /// The name a `${…}` reads, and what follows it: `${!x[i]:-y}` is `x`
    /// with `!` and the index `i`, then `:-y`. `None` for a `${…}` the guard
    /// does not take apart (a length, a special parameter).
    fn parts(text: &str) -> Option<(Named<'_>, &str)> {
        let inner = text.strip_prefix("${")?.strip_suffix('}')?;
        let (bang, inner) = match inner.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, inner),
        };
        let end = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let (name, rest) = inner.split_at(end);
        if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let (index, rest) = match rest.strip_prefix('[') {
            Some(subscript) => {
                let (index, rest) = subscript.split_once(']')?;
                (Some(index), rest)
            }
            None => (None, rest),
        };
        Some((Named { name, bang, index }, rest))
    }
}

/// The variable a `${…}` names.
struct Named<'a> {
    name: &'a str,
    /// Whether it is `${!…}`.
    bang: bool,
    index: Option<&'a str>,
}
