//! The default parameter values a PowerShell line sets in
//! `$PSDefaultParameterValues`. PowerShell gives each cmdlet whose name a
//! key's `Cmdlet:Parameter` matches that parameter with the value, when the
//! command does not name it: `$PSDefaultParameterValues['Remove-Item:Path']
//! = '~'; Remove-Item -Recurse` deletes the home directory. A block written
//! out as a value is read where its command runs (see `blocks.rs`); here a
//! value of any kind is given to the cmdlets as an argument, so their rules
//! judge it as if the line wrote it.
//!
//! The defaults belong to the session: text `Invoke-Expression` runs takes
//! the ones the line set before it and may add more, while the text a new
//! process runs (`powershell -c '…'`) starts with none (see
//! [`crate::unit::Split::powershell_defaults`]). A block written out, a
//! job's among them, is read where it stands, with the line's.

use std::collections::{HashMap, HashSet};

use milo_guards_core::spelling::glob;
use milo_guards_core::Flavour;
use tree_sitter::Node;

use super::{
    blocks, canonical, is_cmdlet, session_drive, variables, Param, Params, Session, Walker,
};
use crate::unit::{self, Arg};
use crate::Rule;

/// The variable, as [`variables::root_is`] names it.
const VARIABLE: &str = "psdefaultparametervalues";

/// How many entries are read before the line is taken to set defaults the
/// guard cannot follow: each cmdlet is given every entry its key matches,
/// so the work a line can make stays bounded.
const MOST: usize = 16;

/// How many arguments default values give the cmdlets of a whole line, the
/// texts it runs in the same session among them: a line pays for each
/// command in length, but not for what a default gives it. Past this, the
/// line is unknown and nothing more is given.
const MOST_GIVEN: usize = 1024;

/// The parameters of `Get-Variable`, `Set-Variable` and `New-Variable`.
const VARIABLE_CMDLET: [Param; 13] = [
    Param::value("name", &[]),
    Param::value("value", &[]),
    Param::value("include", &[]),
    Param::value("exclude", &[]),
    Param::value("description", &[]),
    Param::value("option", &[]),
    Param::value("scope", &[]),
    Param::value("visibility", &[]),
    Param::switch("valueonly", &[]),
    Param::switch("passthru", &[]),
    Param::switch("force", &[]),
    Param::switch("whatif", &["wi"]),
    Param::switch("confirm", &["cf"]),
];

/// One entry the line sets.
#[derive(Debug, Clone)]
struct Entry {
    /// The cmdlet part of its key, in lower case, a wildcard pattern; `None`
    /// when the key is only known when it runs, which may name any cmdlet.
    cmdlet: Option<String>,
    /// The parameter part, in lower case; `None` when the key is only known
    /// when it runs or the part holds a wildcard.
    parameter: Option<String>,
    /// The value, as an argument: text the line writes out, or only known
    /// when it runs (a variable, an expression, a block, whose result is the
    /// value).
    value: Arg,
    /// Whether the value is a script block written out, which the cmdlet
    /// takes as one (it is read where the value is set).
    block: bool,
}

/// The default parameter values a line sets, read once before its commands
/// are judged: they hold wherever on the line they are set, as a command
/// before the assignment may run after it (a loop, a function, a trap).
#[derive(Debug, Default)]
pub(crate) struct Defaults {
    entries: Vec<Entry>,
    /// Whether the line may set defaults the guard does not read: the whole
    /// table set to a value only known when it runs, a method only known
    /// when it runs, the variable reached in any other way (`$d =
    /// $PSDefaultParameterValues`), a variable or item cmdlet that may get,
    /// set or make it by its name (`Set-Variable PSDefaultParameterValues
    /// …`, `Get-Variable PSDefaultP*`, `Get-Item Variable:PSDefaultP*`, a
    /// name only known when it runs), a method given its name as text, or
    /// more entries than are read. Every cmdlet's paths are then only known
    /// when it runs.
    unread: bool,
}

/// Whether `pattern`, a variable's name as a cmdlet is given it (in any
/// case, with a scope, or a wildcard pattern), may name the table.
fn names_table(pattern: &str) -> bool {
    let lower = pattern.trim_matches(['\'', '"']).to_ascii_lowercase();
    let name = ["global:", "script:", "local:", "private:"]
        .iter()
        .find_map(|scope| lower.strip_prefix(scope))
        .unwrap_or(&lower);
    if name.contains(['*', '?', '[']) {
        glob::matches(name, VARIABLE, Flavour::Windows, true)
    } else {
        name == VARIABLE
    }
}

/// Whether `key` gets, sets or makes a variable by its name: `Get-Variable`,
/// `Set-Variable` and `New-Variable`, by name or alias.
fn by_name(key: &str) -> bool {
    matches!(
        key,
        "get-variable" | "gv" | "set-variable" | "set" | "sv" | "new-variable" | "nv"
    )
}

/// Whether `text` holds `word`, in any case.
fn holds(text: &str, word: &str) -> bool {
    text.as_bytes()
        .windows(word.len())
        .any(|window| window.eq_ignore_ascii_case(word.as_bytes()))
}

/// Whether the command `node` is a statement of the line's own, alone in its
/// pipeline: what it gets is printed, and nothing can call a method on it.
fn printed(node: Node<'_>) -> bool {
    let mut node = node;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "pipeline" | "pipeline_chain" if parent.named_child_count() == 1 => node = parent,
            "statement_list" => return parent.parent().is_some_and(|top| top.parent().is_none()),
            _ => return false,
        }
    }
    false
}

/// The nodes a chain of members, items and calls is made of, down to the
/// variable it starts at, as [`variables::root_is`] walks it.
fn chain(kind: &str) -> bool {
    matches!(
        kind,
        "left_assignment_expression"
            | "member_access"
            | "element_access"
            | "invokation_expression"
            | "parenthesized_expression"
    ) || blocks::WRAPPERS.contains(&kind)
}

impl Walker<'_> {
    /// Read the defaults the tree under `root` sets (see [`Defaults`]), and
    /// add them to the session's.
    pub(super) fn read_defaults(&mut self, root: Node<'_>) {
        let mut unread = false;
        let mut assignments = Vec::new();
        let mut calls = Vec::new();
        let mut uses = Vec::new();
        let mut commands = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "assignment_expression" => assignments.push(node),
            "variable" => uses.push(node),
            "command" => commands.push(node),
            "invokation_expression" => calls.push(node),
            _ => {}
        });
        // The variable each chain starts at, when it is this one: worked out
        // from the variable up, once for each node, so that a long chain is
        // not walked down again from each of its calls. A line that never
        // uses the variable has no chain to walk.
        let mut starts: HashMap<usize, Node<'_>> = uses
            .iter()
            .filter(|node| variables::root_is(**node, self.source, VARIABLE))
            .map(|node| (node.id(), *node))
            .collect();
        let mut chains = Vec::new();
        if !starts.is_empty() {
            unit::for_each_node(root, |node| {
                if chain(node.kind()) {
                    chains.push(node);
                }
            });
        }
        for node in chains.iter().rev() {
            let first = node.named_child(0);
            let wrapper = blocks::WRAPPERS.contains(&node.kind());
            if wrapper && node.named_child_count() != 1 {
                continue;
            }
            if let Some(start) = first.and_then(|first| starts.get(&first.id()).copied()) {
                starts.insert(node.id(), start);
            }
        }
        // The uses of the variable read as an entry or the table set.
        let mut read = HashSet::new();
        let mut start = |node: Node<'_>| {
            let found = starts.get(&node.id()).copied();
            if let Some(variable) = found {
                read.insert(variable.id());
            }
            found.is_some()
        };
        let mut pairs = Vec::new();
        for node in assignments {
            let Some(left) = node.named_child(0) else {
                continue;
            };
            if !start(left) {
                continue;
            }
            let Some(value) = node.child_by_field_name("value") else {
                unread = true;
                continue;
            };
            // `+=` and the like make a value of what was there and this.
            let plain = self
                .source
                .get(left.end_byte()..value.start_byte())
                .is_some_and(|between| between.trim() == "=");
            // `$PSDefaultParameterValues['Remove-Item:Path'] = '~'`
            if let Some(key) = blocks::assigned_key(left) {
                pairs.push((Some(key), value, plain));
                continue;
            }
            // `$PSDefaultParameterValues = @{ 'Remove-Item:Path' = '~' }`
            let table = blocks::unwrap(value);
            if table.kind() != "hash_literal_expression" {
                unread = true;
                continue;
            }
            let Some(body) = table.named_child(0) else {
                continue;
            };
            let mut cursor = body.walk();
            for entry in body.named_children(&mut cursor) {
                let mut cursor = entry.walk();
                let parts: Vec<Node<'_>> = entry.named_children(&mut cursor).collect();
                let key = parts.first().and_then(|key| key.named_child(0));
                let value = parts
                    .last()
                    .filter(|value| value.kind() != "key_expression");
                match (entry.kind(), value) {
                    ("hash_entry", Some(value)) => pairs.push((key, *value, true)),
                    _ => unread = true,
                }
            }
        }
        for node in calls {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            let Some(object) = children.first() else {
                continue;
            };
            if !start(*object) {
                // A method given the variable's name as text may get or set
                // it (`$ExecutionContext.SessionState.PSVariable.Set(…)`).
                unread |= self.names_table_in(&children);
                continue;
            }
            let method = children
                .iter()
                .find(|child| child.kind() == "member_name")
                .and_then(|member| blocks::called(*member, self.source));
            match method.as_deref() {
                // A method only known when it runs may add one.
                None => unread = true,
                // `.Add(key, value)`, `.set_Item(key, value)`
                Some("add" | "set_item") => {
                    let values = children
                        .iter()
                        .find(|child| child.kind() == "argument_list")
                        .and_then(|list| list.named_child(0));
                    let Some(values) = values else {
                        continue;
                    };
                    let mut cursor = values.walk();
                    let mut values = values.named_children(&mut cursor);
                    match (values.next(), values.next()) {
                        (Some(key), Some(value)) => pairs.push((Some(key), value, true)),
                        _ => unread = true,
                    }
                }
                // `.Remove(key)`, `.Clear()` and the reads set none.
                Some(_) => {}
            }
        }
        // The variable reached any other way may be the table, set under
        // another name.
        if uses.into_iter().any(|node| {
            !read.contains(&node.id()) && variables::root_is(node, self.source, VARIABLE)
        }) {
            unread = true;
        }
        for command in commands {
            unread |= self.reaches_table(command);
        }
        let mut entries = Vec::new();
        let had = self.split.powershell_defaults.entries.len();
        for (key, value, plain) in pairs {
            if had + entries.len() >= MOST {
                unread = true;
                break;
            }
            let block = plain && blocks::written(value);
            let value = if plain {
                self.default_value(value)
            } else {
                Arg::Unknown(unit::text(&value, self.source).to_string())
            };
            let key = key.and_then(|key| blocks::plain_text(blocks::unwrap(key), self.source));
            let (cmdlet, parameter) = match key {
                Some(key) => {
                    // A key without a parameter (`Disabled`) gives none.
                    let Some((cmdlet, parameter)) = key.split_once(':') else {
                        continue;
                    };
                    let parameter = parameter.trim();
                    let plain = !parameter.is_empty() && !parameter.contains(['*', '?', '[', ']']);
                    (
                        Some(cmdlet.trim().to_string()),
                        plain.then(|| parameter.to_string()),
                    )
                }
                None => (None, None),
            };
            entries.push(Entry {
                cmdlet,
                parameter,
                value,
                block,
            });
        }
        let defaults = &mut self.split.powershell_defaults;
        defaults.entries.extend(entries);
        defaults.unread |= unread;
        // A cmdlet may then take a parameter the line does not write for it
        // (`'Stop-EC2Instance:Terminate'`).
        self.split.defaults |= unread;
    }

    /// Whether any argument of a method call is text that names the table.
    fn names_table_in(&self, children: &[Node<'_>]) -> bool {
        let Some(list) = children
            .iter()
            .find(|child| child.kind() == "argument_list")
            .and_then(|list| list.named_child(0))
        else {
            return false;
        };
        let mut found = false;
        let mut cursor = list.walk();
        for value in list.named_children(&mut cursor) {
            let value = blocks::unwrap(value);
            found |= blocks::plain_text(value, self.source).is_some_and(|text| names_table(&text));
        }
        found
    }

    /// Whether the command `node` may get, set or make the table by its
    /// name: `Get-Variable`, `Set-Variable` and `New-Variable` (by name or
    /// alias, or a name the line makes stand for one) given its name, a
    /// wildcard that matches it, or a name only known when it runs (and
    /// `Get-Variable` given no name, which gets every variable), or any
    /// cmdlet given a path on the `Variable:` drive that may name it (the
    /// drive itself among them). What a cmdlet that gets only prints, alone
    /// as a statement of the line, sets nothing.
    fn reaches_table(&mut self, node: Node<'_>) -> bool {
        // A program that is no cmdlet reaches no variable of the session.
        let keys: Vec<String> = self
            .session_keys(node)
            .iter()
            .map(|key| canonical(key).to_string())
            .filter(|key| by_name(key) || is_cmdlet(key))
            .collect();
        if keys.is_empty() {
            return false;
        }
        // Only a command whose words may name a variable has its arguments
        // read: a word on the `Variable:` drive, or `-OutVariable` and
        // `-PipelineVariable` by any of their names (backticks taken off,
        // as PowerShell does). A block among them holds commands of its own.
        let words = node
            .child_by_field_name("command_elements")
            .is_some_and(|elements| {
                let mut cursor = elements.walk();
                let found = elements.named_children(&mut cursor).any(|element| {
                    let word = matches!(element.kind(), "generic_token" | "command_parameter");
                    if !word
                        && (element.kind() == "command_argument_sep" || blocks::written(element))
                    {
                        return false;
                    }
                    let text = unit::text(&element, self.source);
                    let bare;
                    let text = if text.contains('`') {
                        bare = text.replace('`', "");
                        bare.as_str()
                    } else {
                        text
                    };
                    ["variable", "-ov", "-outv", "-pv", "-pi"]
                        .iter()
                        .any(|word| holds(text, word))
                });
                found
            });
        let printed = printed(node);
        let mut reaches = false;
        for key in keys {
            let by_name = by_name(&key);
            let gets = key.starts_with("get-") || key == "gv";
            // A location cmdlet goes to the drive, which reaches nothing
            // itself: a plain name after it may (below).
            let location = super::names_location(&key);
            if (gets && printed) || location || !(by_name || words || self.variable_location) {
                continue;
            }
            let args = self.plain_args(node, Some(&key));
            let key = key.as_str();
            let names = |arg: &Arg| arg.known().is_none_or(names_table);
            reaches |= by_name && {
                let params = Params::cmdlet(&args, &VARIABLE_CMDLET);
                let mut given = params.values(&["name"]);
                if gets {
                    given.extend(params.values(&["include"]));
                    given.extend(params.positional.iter().copied());
                } else if given.is_empty() {
                    given.extend(params.positional.first().copied());
                }
                (gets && given.is_empty()) || given.into_iter().any(names)
            };
            // `Get-Item Variable:PSDefaultP*`, `New-Item -Path Variable:
            // -Name …`, and a path only known when it runs that starts on
            // the drive.
            reaches |= args.iter().any(|arg| {
                if let Some(text) = arg.known() {
                    return session_drive(text).is_some_and(|(drive, name)| {
                        drive == Session::Variables && (name.is_empty() || names_table(&name))
                    });
                }
                let text = arg.text().trim_start_matches(['"', '\'']);
                text.get(..9)
                    .is_some_and(|head| head.eq_ignore_ascii_case("variable:"))
            });
            // `cd Variable:; Set-Item PSDefaultParameterValues …`.
            reaches |= self.variable_location
                && args.iter().any(|arg| {
                    arg.known()
                        .is_some_and(|text| !text.starts_with('-') && names_table(text))
                });
            // `-OutVariable PSDefaultParameterValues`.
            reaches |= super::variables_set(key, &args)
                .iter()
                .any(|name| names_table(name));
        }
        reaches
    }

    /// A value as an argument: text written out, or only known when it
    /// runs.
    fn default_value(&self, node: Node<'_>) -> Arg {
        match self.environment_value(node) {
            Arg::Null => Arg::Unknown(unit::text(&node, self.source).to_string()),
            value => value,
        }
    }

    /// A value given to a variable: text written out, `$null`, or only
    /// known when it runs.
    pub(super) fn environment_value(&self, node: Node<'_>) -> Arg {
        let mut value = node;
        while value.kind() != "string_literal" && value.named_child_count() == 1 {
            match value.named_child(0) {
                Some(only) => value = only,
                None => break,
            }
        }
        match self.expr(value) {
            known @ Arg::Known(_) if value.kind() == "string_literal" => known,
            Arg::Null => Arg::Null,
            _ => Arg::Unknown(unit::text(&node, self.source).to_string()),
        }
    }

    /// Give the cmdlet `key` the defaults the session sets for it, after
    /// its own `args`: a parameter by name (`-Path:` and the value), unless
    /// the command names that parameter itself, and a value whose parameter
    /// is only known when it runs as an argument by position. A session
    /// that may set defaults the guard does not read gives it an argument
    /// only known when it runs. A program that is no cmdlet takes no
    /// defaults. Past [`MOST_GIVEN`] arguments on the line, the line is
    /// unknown and none is given.
    pub(super) fn give_defaults(
        &mut self,
        key: &str,
        args: &mut Vec<Arg>,
        shapes: &mut Vec<blocks::Shape>,
    ) {
        let defaults = &self.split.powershell_defaults;
        if (defaults.entries.is_empty() && !defaults.unread)
            || self.split.defaults_given > MOST_GIVEN
        {
            return;
        }
        let name = canonical(key);
        if !is_cmdlet(name) {
            return;
        }
        let named = |parameter: &str| {
            args.iter().any(|arg| {
                arg.known().is_some_and(|word| {
                    word.strip_prefix('-').is_some_and(|word| {
                        word.trim_end_matches(':').eq_ignore_ascii_case(parameter)
                    })
                })
            })
        };
        let shape = |block: bool, value: &Arg| blocks::Shape {
            block,
            plain: block || value.known().is_some(),
            ..blocks::Shape::default()
        };
        let mut given = Vec::new();
        for entry in &defaults.entries {
            let matches = entry
                .cmdlet
                .as_deref()
                .is_none_or(|cmdlet| glob::matches(cmdlet, name, Flavour::Windows, true));
            if !matches {
                continue;
            }
            match entry.parameter.as_deref() {
                Some(parameter) if named(parameter) => {}
                Some(parameter) => {
                    let flag = Arg::Known(format!("-{parameter}:"));
                    given.push((shape(false, &flag), flag));
                    given.push((shape(entry.block, &entry.value), entry.value.clone()));
                }
                None => given.push((shape(entry.block, &entry.value), entry.value.clone())),
            }
        }
        if defaults.unread {
            given.push((
                blocks::Shape::default(),
                Arg::Unknown(format!("${VARIABLE}")),
            ));
        }
        self.split.defaults_given += given.len();
        if self.split.defaults_given > MOST_GIVEN {
            self.split.problem(
                Rule::Unknown,
                "gives default parameter values to more commands than the guard reads",
                None,
            );
            return;
        }
        for (shape, arg) in given {
            args.push(arg);
            shapes.push(shape);
        }
    }
}
