//! The walk's side of [`crate::values`]: the values a line gives its
//! variables, read from the tree before the walk, and the places the walk
//! finds that read a value again as code (arithmetic, `${!x}`, `${x@P}`, a
//! subscript in a variable's name), or read quoted text as code where the
//! grammar does not (single quotes in a `${…}` word inside double quotes, an
//! escaped backtick inside backticks).

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

/// The special parameters whose value is always a number: the status, the
/// count of arguments, and process ids.
const NUMBERS: [&str; 4] = ["?", "#", "$", "!"];

/// The variables bash gives a number each time they are read, as long as the
/// line does not unset or declare them, which takes that away.
const COUNTERS: [&str; 9] = [
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "EPOCHSECONDS",
    "LINENO",
    "BASHPID",
    "PPID",
    "UID",
    "EUID",
];

/// The builtins that set the variables they are given by name, and read a
/// subscript in the name as arithmetic.
const SETTERS: [&str; 5] = ["read", "mapfile", "readarray", "printf", "getopts"];

/// The builtins that declare variables.
const DECLARERS: [&str; 5] = ["declare", "typeset", "local", "export", "readonly"];

/// The attributes a `declare` gives the variables it names.
#[derive(Default, Clone, Copy)]
struct Attributes {
    /// `-i`: each value is read as arithmetic.
    integer: bool,
    /// `-A`: the keys of the array are text.
    associative: bool,
    /// `-n`: the value names another variable.
    reference: bool,
}

impl Attributes {
    /// The attributes the option words `words` of `program`, one of
    /// [`DECLARERS`], give. `export -n` takes the export away, and gives no
    /// reference.
    fn of<'w>(program: &str, words: impl IntoIterator<Item = &'w str>) -> Self {
        let mut found = Self::default();
        for word in words {
            if word.starts_with('-') && !word.starts_with("--") {
                found.integer |= word.contains('i');
                found.associative |= word.contains('A');
                found.reference |= word.contains('n') && program != "export";
            }
        }
        found
    }
}

impl Walker<'_> {
    /// Note the value `node` gives a variable, if it gives one: an
    /// assignment (also after `declare` and the like, and `+=`), the words of
    /// a `for` loop, a `${x:=v}`, the positional parameters `set --` and a
    /// call of a function the line defines give, and a value only known when
    /// it runs from `read`, `mapfile`, `printf -v` and `getopts`. Every node
    /// of the line is handed here before the walk, and which value reaches a
    /// read is not worked out: every value counts.
    pub(super) fn note_value(&mut self, node: Node<'_>) {
        match node.kind() {
            "variable_assignment" => self.note_assignment(node),
            "for_statement" => self.note_loop(node),
            "declaration_command" => self.note_declaration(node),
            "command" => self.note_command(node),
            "expansion" => self.note_default(node),
            "function_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let name = unit::text(&name, self.source).to_string();
                    self.functions.insert(name);
                }
            }
            _ => {}
        }
    }

    /// After every node was noted: what a `shift` does to the positional
    /// parameters.
    pub(super) fn noted(&mut self) {
        self.split.values.settle();
    }

    /// Note that `node` gives `name` the value `value`: kept for every read
    /// of `name`, and for the walk to read again where `node` runs, when
    /// `name` has the integer attribute or is a reference.
    fn record(&mut self, node: Node<'_>, name: &str, value: Value) {
        self.split.values.add(name, value.clone());
        self.sets
            .entry(node.id())
            .or_default()
            .push((name.to_string(), value));
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
                    .map(|element| match self.value(element) {
                        // `[k]=v`: the value is `v`.
                        Value::Text(text) => match text
                            .strip_prefix('[')
                            .and_then(|keyed| keyed.split_once("]="))
                        {
                            Some((_, value)) => Value::Text(value.to_string()),
                            None => Value::Text(text),
                        },
                        unknown @ Value::Unknown(_) => unknown,
                    })
                    .collect()
            }
            // The grammar may end a word early, before a backslash it reads
            // apart (`x=a[\$\(rm\ x\)]`): what the shell reads is more.
            Some(value) if !self.ends_word(value) => {
                vec![Value::Unknown(unit::text(&value, self.source).to_string())]
            }
            Some(value) => vec![self.value(value)],
        };
        for value in found {
            let value = if appends {
                Self::appended(&self.split.values.texts(&name), value)
            } else {
                value
            };
            self.record(node, &name, value);
        }
    }

    /// Whether the word `node` ends where the shell ends it: at the end of
    /// the line, or before a blank or an operator.
    fn ends_word(&self, node: Node<'_>) -> bool {
        self.source
            .get(node.end_byte()..)
            .and_then(|rest| rest.chars().next())
            .is_none_or(|next| {
                next.is_whitespace()
                    || matches!(next, ';' | '&' | '|' | '(' | ')' | '<' | '>' | '`')
            })
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
    /// with an arithmetic expansion and a parameter that is always a number
    /// (`$?`, `$#`, `${#a[@]}`, `$RANDOM`) taken as a number, or only known
    /// when it runs when anything else in it expands. An unquoted backslash
    /// before a `$` or a backtick is only known when it runs too.
    fn value(&self, node: Node<'_>) -> Value {
        let written = unit::text(&node, self.source);
        if self.is_number(node) {
            return Value::Text("0".to_string());
        }
        let mut expands = false;
        let mut stack = vec![node];
        while let Some(at) = stack.pop() {
            if at.kind() == "arithmetic_expansion" || self.is_number(at) {
                continue;
            }
            expands |= EXPANDING.contains(&at.kind());
            let mut cursor = at.walk();
            stack.extend(at.named_children(&mut cursor));
        }
        if expands {
            return Value::Unknown(written.to_string());
        }
        // The grammar may read a word with such a backslash apart
        // (`a[\$\(rm\ x\)]`), so its text is not what the shell reads.
        let escaped = matches!(node.kind(), "word" | "concatenation")
            && (written.contains("\\$") || written.contains("\\`"));
        if escaped {
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

    /// Whether `node` is a parameter whose value is always a number, alone or
    /// alone in double quotes: `$?`, `$#`, `$$`, `$!`, a length (`${#x}`,
    /// `${#a[@]}`), or a counter such as `$RANDOM` that the line names
    /// nowhere but in a read of it.
    fn is_number(&self, node: Node<'_>) -> bool {
        let node = match node.kind() {
            "string" if node.named_child_count() == 1 => match node.named_child(0) {
                Some(inner) => inner,
                None => return false,
            },
            _ => node,
        };
        if !matches!(node.kind(), "simple_expansion" | "expansion") {
            return false;
        }
        let text = unit::text(&node, self.source);
        let Some(inner) = text
            .strip_prefix("${")
            .and_then(|inner| inner.strip_suffix('}'))
            .or_else(|| text.strip_prefix('$'))
        else {
            return false;
        };
        NUMBERS.contains(&inner)
            || text.starts_with("${#")
                && inner[1..].bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'[' | b']' | b'@' | b'*')
                })
            || COUNTERS.contains(&inner) && self.only_read(inner)
    }

    /// Whether the line names `name` only where it reads it (`$name`,
    /// `${name}`): not where it unsets, declares or sets it.
    fn only_read(&self, name: &str) -> bool {
        let all = self.source.matches(name).count();
        let read = self.source.matches(&format!("${name}")).count()
            + self.source.matches(&format!("${{{name}}}")).count();
        all == read
    }

    /// `for x in a b c`: each word, or a value only known when it runs for a
    /// word that expands or matches names (`*.txt`), and for a loop over the
    /// arguments (`for x; do`). A range of numbers (`{1..5}`) is numbers.
    fn note_loop(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("variable") else {
            return;
        };
        let name = unit::text(&name, self.source).to_string();
        let mut cursor = node.walk();
        let words: Vec<Node<'_>> = node.children_by_field_name("value", &mut cursor).collect();
        if words.is_empty() {
            let written = unit::text(&node, self.source).to_string();
            self.record(node, &name, Value::Unknown(written));
        }
        for word in words {
            let value = if word.kind() == "brace_expression" {
                let mut cursor = word.walk();
                let numbers = word
                    .named_children(&mut cursor)
                    .all(|part| part.kind() == "number");
                if numbers {
                    Value::Text("0".to_string())
                } else {
                    Value::Unknown(unit::text(&word, self.source).to_string())
                }
            } else {
                match self.value(word) {
                    Value::Text(text)
                        if word.kind() != "raw_string" && text.contains(['*', '?', '[']) =>
                    {
                        Value::Unknown(text)
                    }
                    value => value,
                }
            };
            self.record(node, &name, value);
        }
    }

    /// `declare -i n`, `local -A m`, `declare -n r=…`: the attributes of the
    /// variables named, and a quoted assignment (`export "x=…"`), which the
    /// grammar reads as a string.
    fn note_declaration(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let program = node
            .child(0)
            .map_or("", |keyword| unit::text(&keyword, self.source));
        let attributes = Attributes::of(
            program,
            children.iter().map(|child| unit::text(child, self.source)),
        );
        for child in children {
            match child.kind() {
                "variable_assignment" | "variable_name" => {
                    let name = child.child_by_field_name("name").unwrap_or(child);
                    let name = self.assigned_name(name);
                    self.attribute(&name, attributes);
                }
                _ => {
                    let arg = self.arg(child);
                    self.declared_word(child, &arg, attributes);
                }
            }
        }
    }

    /// Give `name` the attributes `attributes` say.
    fn attribute(&mut self, name: &str, attributes: Attributes) {
        if attributes.integer {
            self.split.values.integer(name);
        }
        if attributes.associative {
            self.split.values.associative(name);
        }
        if attributes.reference {
            self.split.values.reference(name);
        }
    }

    /// A word `declare` reads that is not a plain assignment to the grammar:
    /// `"x=…"`, or every word of a `declare` behind `builtin` or `command`.
    fn declared_word(&mut self, node: Node<'_>, arg: &Arg, attributes: Attributes) {
        if let Some(name) = arg.known().filter(|word| !word.starts_with(['-', '+'])) {
            let name = name.split('[').next().unwrap_or_default().to_string();
            if !name.contains('=') {
                self.attribute(&name, attributes);
            }
        }
        let Some((name, value)) = startup::word(arg) else {
            return;
        };
        let name = name.split('[').next().unwrap_or_default().to_string();
        let value = match value {
            Arg::Known(text) => Value::Text(text),
            other => Value::Unknown(other.text().to_string()),
        };
        self.attribute(&name, attributes);
        self.record(node, &name, value);
    }

    /// The program `command` runs once `builtin` and `command` are taken off
    /// and its name is read as the shell reads it (`\let`, `'let'`), and the
    /// words it is given. `None` when the name is only known when it runs, or
    /// for `command -v`, which only says what the program is.
    fn program<'t>(&self, command: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        let name = command.child_by_field_name("name")?;
        let mut program = self.arg(name).known()?.to_string();
        let mut cursor = command.walk();
        let args: Vec<Node<'t>> = command
            .children_by_field_name("argument", &mut cursor)
            .collect();
        let mut at = 0;
        while matches!(program.as_str(), "builtin" | "command") {
            if program == "command" {
                while let Some(flag) = args
                    .get(at)
                    .map(|arg| self.arg(*arg))
                    .filter(|arg| arg.known().is_some_and(|word| word.starts_with('-')))
                {
                    if flag.text().contains(['v', 'V']) {
                        return None;
                    }
                    at += 1;
                }
            }
            program = self.arg(*args.get(at)?).known()?.to_string();
            at += 1;
        }
        Some((program, args.get(at..).unwrap_or_default().to_vec()))
    }

    /// The names `program`, one of [`SETTERS`], sets from its words `args`,
    /// as written: `read x`, `mapfile x`, `printf -v x …`, `getopts o x`.
    fn set_names(&self, program: &str, args: &[Node<'_>]) -> Vec<String> {
        let words: Vec<String> = args
            .iter()
            .map(|arg| match self.arg(*arg) {
                Arg::Known(text) => text,
                _ => unit::text(arg, self.source).to_string(),
            })
            .collect();
        match program {
            "read" | "mapfile" | "readarray" => words
                .into_iter()
                .filter(|word| !word.starts_with('-'))
                .collect(),
            "printf" => words
                .iter()
                .enumerate()
                .filter_map(|(at, word)| match word.as_str() {
                    "-v" => words.get(at + 1).cloned(),
                    _ => word
                        .strip_prefix("-v")
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                })
                .collect(),
            "getopts" => words.get(1).cloned().into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// A command that sets variables: `read x` and the other [`SETTERS`]
    /// give a value only known when it runs; `declare` behind `builtin` or
    /// `command` declares as `declare` does; `set -- a b` and a call of a
    /// function the line defines give the positional parameters; `shift`
    /// moves them.
    fn note_command(&mut self, node: Node<'_>) {
        let Some((program, args)) = self.program(node) else {
            return;
        };
        let written = unit::text(&node, self.source).to_string();
        if SETTERS.contains(&program.as_str()) {
            for name in self.set_names(&program, &args) {
                let name = name.split('[').next().unwrap_or_default().to_string();
                self.record(node, &name, Value::Unknown(written.clone()));
            }
        } else if DECLARERS.contains(&program.as_str()) {
            let words: Vec<Arg> = args.iter().map(|arg| self.arg(*arg)).collect();
            let attributes = Attributes::of(&program, words.iter().filter_map(Arg::known));
            for word in &words {
                self.declared_word(node, word, attributes);
            }
        } else if program == "shift" {
            self.split.values.shifted = true;
        } else if program == "set" {
            let mut at = 0;
            let mut given = false;
            while let Some(arg) = args.get(at) {
                let word = self.arg(*arg);
                let word = word.known().unwrap_or_default();
                if word == "--" || word == "-" {
                    at += 1;
                    given = true;
                    break;
                }
                if word.len() > 1 && word.starts_with(['-', '+']) {
                    at += if word.contains('o') { 2 } else { 1 };
                    continue;
                }
                given = true;
                break;
            }
            if given {
                self.positional(node, args.get(at..).unwrap_or_default());
            }
        } else if self.functions.contains(&program) {
            self.positional(node, &args);
        }
    }

    /// The positional parameters `words` give, from `$1` on, each also under
    /// [`values::POSITIONAL`] for `$@` and `$*`.
    fn positional(&mut self, node: Node<'_>, words: &[Node<'_>]) {
        for (at, word) in words.iter().enumerate() {
            let value = self.value(*word);
            self.record(node, &(at + 1).to_string(), value.clone());
            self.record(node, values::POSITIONAL, value);
        }
    }

    /// `${x:=v}` and `${x=v}` set `x` to `v` when it has no value: a word
    /// written out plainly, or a value only known when it runs.
    fn note_default(&mut self, node: Node<'_>) {
        let Some((name, rest)) = Self::parts(unit::text(&node, self.source)) else {
            return;
        };
        if name.bang || name.special {
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
        self.record(node, name.name, value);
    }

    /// Before the walk reads `node`: the places it reads a value again as
    /// code. `true` when `node` was read here whole, and the walk is to skip
    /// it. Kept out of the walk's own frame, which recurses for each level of
    /// the tree, so that a line nested near the limit still fits the stack.
    #[inline(never)]
    pub(super) fn reads_again(&mut self, node: Node<'_>) -> bool {
        self.set_here(node);
        match node.kind() {
            "variable_assignment" => self.array_keys(node),
            "command" => {
                // The assignments in front of a command are not walked as
                // nodes of their own.
                let mut cursor = node.walk();
                let prefixes: Vec<Node<'_>> = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "variable_assignment")
                    .collect();
                for prefix in prefixes {
                    self.set_here(prefix);
                    self.array_keys(prefix);
                }
                self.command_reads(node);
            }
            "declaration_command" => {
                let mut cursor = node.walk();
                let words: Vec<Node<'_>> = node
                    .named_children(&mut cursor)
                    .filter(|child| !matches!(child.kind(), "variable_assignment" | "word"))
                    .collect();
                for word in words {
                    let arg = self.arg(word);
                    let site = unit::text(&word, self.source);
                    if let Some((name, _)) = arg.known().and_then(|text| text.split_once('=')) {
                        self.name_index(&Arg::Known(name.to_string()), site);
                    }
                }
            }
            "expansion" => self.expansion(node),
            "arithmetic_expansion" => self.arithmetic(node),
            "compound_statement" if self.is_arithmetic_command(node) => self.arithmetic(node),
            "subscript" => self.subscript(node),
            "c_style_for_statement" => self.arithmetic_for(node),
            "test_command" => {
                self.arithmetic_tests(node);
                self.tested_names(node);
            }
            "unset_command" => self.unset_names(node),
            "command_substitution" => {
                self.misread_arithmetic(node);
                return self.escaped_backticks(node);
            }
            _ => {}
        }
        false
    }

    /// The values `node` gives variables, read where it runs: a value given
    /// to a variable with the integer attribute is read as arithmetic, and
    /// one given to a reference names the variable a read of it reads.
    fn set_here(&mut self, node: Node<'_>) {
        let Some(sets) = self.sets.remove(&node.id()) else {
            return;
        };
        for (name, value) in sets {
            if self.split.values.is_integer(&name) {
                match &value {
                    Value::Text(text) => values::expression(self.split, text, self.depth),
                    Value::Unknown(written) => self.split.problem(
                        Rule::Unknown,
                        "may run code in a value only known when it runs",
                        Some(written),
                    ),
                }
            }
            if self.split.values.is_reference(&name) {
                values::referenced(self.split, &value, self.depth);
            }
        }
    }

    /// `a=([k]=v)`, `declare -a a=([k]=v)`: the key of each element of an
    /// indexed array is arithmetic. An associative array's keys are text.
    fn array_keys(&mut self, assignment: Node<'_>) {
        let (Some(name), Some(array)) = (
            assignment.child_by_field_name("name"),
            assignment.child_by_field_name("value"),
        ) else {
            return;
        };
        if array.kind() != "array" || self.split.values.is_associative(&self.assigned_name(name)) {
            return;
        }
        let mut cursor = array.walk();
        let keys: Vec<&str> = array
            .named_children(&mut cursor)
            .filter_map(|element| {
                unit::text(&element, self.source)
                    .strip_prefix('[')
                    .and_then(|keyed| keyed.split_once("]="))
                    .map(|(key, _)| key)
            })
            .collect();
        for key in keys {
            self.written_expression(key, key);
        }
    }

    /// `text`, an expression as the line writes it (quotes and expansions
    /// and all), read as arithmetic: plain text is read as the code it holds
    /// and the variables it names; one that expands reads the variables it
    /// names, and the output of a substitution in it is only known when it
    /// runs.
    fn written_expression(&mut self, text: &str, site: &str) {
        if text.contains(['$', '`', '\'', '"', '\\']) {
            if text.contains("$(") || text.contains('`') {
                self.split
                    .problem(Rule::Unknown, values::OUTPUT, Some(site));
            }
            values::arithmetic(self.split, &values::names(text), site, self.depth);
        } else {
            values::expression(self.split, text, self.depth);
        }
    }

    /// `name`, a variable named by a word a builtin reads it from (`read
    /// 'a[i]'`, `unset 'a[i]'`, `[[ -v a[i] ]]`): its subscript is
    /// arithmetic.
    fn name_index(&mut self, name: &Arg, site: &str) {
        let (text, known) = match name {
            Arg::Known(text) => (text.as_str(), true),
            other => (other.text(), false),
        };
        let Some(index) = text
            .split_once('[')
            .and_then(|(_, rest)| rest.strip_suffix(']'))
        else {
            return;
        };
        if matches!(index, "@" | "*") {
            return;
        }
        if known {
            values::expression(self.split, index, self.depth);
        } else {
            self.written_expression(index, site);
        }
    }

    /// What a command reads again: each word of `let` is an expression, and
    /// a subscript in a name that `read`, `printf -v`, `getopts`, `declare`
    /// behind a wrapper, or `test -v` reads is arithmetic.
    fn command_reads(&mut self, command: Node<'_>) {
        let Some((program, args)) = self.program(command) else {
            return;
        };
        let site = unit::text(&command, self.source);
        if program == "let" {
            for word in args {
                match self.arg(word) {
                    Arg::Known(text) => values::expression(self.split, &text, self.depth),
                    _ => self.arithmetic(word),
                }
            }
        } else if SETTERS.contains(&program.as_str()) {
            for name in self.set_names(&program, &args) {
                self.name_index(&Arg::Known(name), site);
            }
        } else if DECLARERS.contains(&program.as_str()) {
            for word in args {
                if let Some((name, _)) =
                    self.arg(word).known().and_then(|text| text.split_once('='))
                {
                    self.name_index(&Arg::Known(name.to_string()), site);
                }
            }
        } else if matches!(program.as_str(), "test" | "[") {
            let mut words = args.iter();
            while let Some(word) = words.next() {
                if self.arg(*word).known() == Some("-v") {
                    if let Some(name) = words.next() {
                        let name = self.arg(*name);
                        self.name_index(&name, site);
                    }
                }
            }
        }
    }

    /// `[[ -v a[i] ]]`: the subscript of the name tested is arithmetic.
    fn tested_names(&mut self, test: Node<'_>) {
        let mut names = Vec::new();
        unit::for_each_node(test, |node| {
            if node.kind() != "unary_expression" {
                return;
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor);
            let tests_set = children.next().is_some_and(|operator| {
                operator.kind() == "test_operator" && unit::text(&operator, self.source) == "-v"
            });
            if tests_set {
                names.extend(children.next());
            }
        });
        for name in names {
            let arg = self.arg(name);
            self.name_index(&arg, unit::text(&name, self.source));
        }
    }

    /// `unset 'a[i]'`: the subscript of an element unset is arithmetic.
    /// `unset -f` removes functions.
    fn unset_names(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let words: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let functions = words.iter().any(|word| {
            let text = unit::text(word, self.source);
            text.starts_with('-') && !text.starts_with("--") && text.contains('f')
        });
        if functions {
            return;
        }
        for word in words {
            let arg = self.arg(word);
            self.name_index(&arg, unit::text(&word, self.source));
        }
    }

    /// `$((x))` in the body of a here-document, which the grammar reads as a
    /// command substitution of a subshell: it is arithmetic, and is read as
    /// arithmetic as well as the command the grammar found.
    fn misread_arithmetic(&mut self, node: Node<'_>) {
        let text = unit::text(&node, self.source);
        let Some(inner) = text
            .strip_prefix("$((")
            .and_then(|inner| inner.strip_suffix("))"))
        else {
            return;
        };
        self.written_expression(inner, text);
    }

    /// The variables an arithmetic expression at `node` reads, and whether
    /// it reads the output of a command (`$(( $(cat f) ))`), which is only
    /// known when it runs. A subscript reads its array, and its index is
    /// read where the walk reaches it; a nested `$((…))` is read where the
    /// walk reaches it; `${#x}` is a length and reads no value as code;
    /// `${!x}` reads the variables the values of `x` name; `$@` and `$*`
    /// read every positional parameter.
    pub(super) fn arithmetic_names(&self, node: Node<'_>) -> (Vec<String>, bool) {
        let mut found = Vec::new();
        let mut output = false;
        let mut stack = vec![node];
        while let Some(at) = stack.pop() {
            let text = unit::text(&at, self.source);
            match at.kind() {
                "command_substitution" => {
                    output = true;
                    continue;
                }
                "process_substitution" => continue,
                "arithmetic_expansion" if at.id() != node.id() => continue,
                "expansion" if text.starts_with("${#") => continue,
                "expansion" if text.starts_with("${!") => {
                    if let Some((name, rest)) = Self::parts(text) {
                        if !Self::listing(&name, rest) {
                            let (named, _) = self.split.values.named_by(name.name);
                            found.push(name.name.to_string());
                            found.extend(named);
                        }
                    }
                    continue;
                }
                "special_variable_name" => {
                    if matches!(text, "@" | "*") {
                        found.push(values::POSITIONAL.to_string());
                    }
                    continue;
                }
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
        (found, output)
    }

    /// Read the variables arithmetic at `node` names: the code their values
    /// hold runs here.
    pub(super) fn arithmetic(&mut self, node: Node<'_>) {
        let (names, output) = self.arithmetic_names(node);
        let site = unit::text(&node, self.source);
        if output {
            self.split
                .problem(Rule::Unknown, values::OUTPUT, Some(site));
        }
        if !names.is_empty() {
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

    /// Whether a `${!…}` lists names or keys (`${!x@}`, `${!x*}`,
    /// `${!a[@]}`) rather than reading the variable a value names.
    fn listing(name: &Named<'_>, rest: &str) -> bool {
        matches!(rest, "@" | "*") || matches!(name.index, Some("@" | "*")) && rest.is_empty()
    }

    /// A `${…}` that reads a value again: `${!x}` (but not the listings of
    /// [`Self::listing`]), `${x@P}` and `${!x@P}`, and the offset and length
    /// of `${x:i:j}`, `${@:i:j}` and `${1:i}`, which are expressions. Inside
    /// double quotes, single quotes in its word are text, so what they hold
    /// is read as the inside of double quotes.
    pub(super) fn expansion(&mut self, node: Node<'_>) {
        let site = unit::text(&node, self.source);
        if let Some((name, rest)) = Self::parts(site) {
            let listing = Self::listing(&name, rest);
            if name.bang && !listing && !name.special {
                values::indirect(self.split, name.name, site, self.depth);
            }
            if rest == "@P" && !name.special {
                if name.bang {
                    let (named, _) = self.split.values.named_by(name.name);
                    for named in named {
                        values::prompt(self.split, &named, site, self.depth);
                    }
                } else {
                    values::prompt(self.split, name.name, site, self.depth);
                }
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
                if let Some(inner) = inner.filter(|inner| Self::expands_in_quotes(inner)) {
                    self.quoted_text(inner);
                }
            }
        }
    }

    /// Whether `text`, read as the inside of double quotes, holds a `$` or a
    /// backtick the shell expands: one a backslash escapes is text.
    fn expands_in_quotes(text: &str) -> bool {
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '$' | '`' => return true,
                _ => {}
            }
        }
        false
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
    /// with `!` and the index `i`, then `:-y`. A special or positional
    /// parameter (`${@:1}`, `${1:x}`) is a name too, marked special. `None`
    /// for a `${…}` the guard does not take apart (a length).
    fn parts(text: &str) -> Option<(Named<'_>, &str)> {
        let inner = text.strip_prefix("${")?.strip_suffix('}')?;
        if inner.starts_with('#') && inner.len() > 1 {
            return None;
        }
        let (bang, inner) = match inner.strip_prefix('!') {
            Some(rest) if !rest.is_empty() => (true, rest),
            _ => (false, inner),
        };
        let digits = inner
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(inner.len());
        let end = if digits > 0 {
            digits
        } else if inner.starts_with(['@', '*', '#', '?', '$', '!', '-']) {
            1
        } else {
            inner
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(inner.len())
        };
        let (name, rest) = inner.split_at(end);
        if name.is_empty() {
            return None;
        }
        let special = !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
        let (index, rest) = match rest.strip_prefix('[') {
            Some(subscript) if !special => {
                let (index, rest) = subscript.split_once(']')?;
                (Some(index), rest)
            }
            _ => (None, rest),
        };
        Some((
            Named {
                name,
                bang,
                special,
                index,
            },
            rest,
        ))
    }
}

/// The variable a `${…}` names.
struct Named<'a> {
    name: &'a str,
    /// Whether it is `${!…}`.
    bang: bool,
    /// Whether it is a special or positional parameter (`@`, `*`, `1`).
    special: bool,
    index: Option<&'a str>,
}
