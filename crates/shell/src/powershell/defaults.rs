//! The default parameter values a PowerShell line sets in
//! `$PSDefaultParameterValues`. PowerShell gives each cmdlet whose name a
//! key's `Cmdlet:Parameter` matches that parameter with the value, when the
//! command does not name it: `$PSDefaultParameterValues['Remove-Item:Path']
//! = '~'; Remove-Item -Recurse` deletes the home directory. A block written
//! out as a value is read where its command runs (see `blocks.rs`); here a
//! value of any kind is given to the cmdlets as an argument, so their rules
//! judge it as if the line wrote it.

use std::collections::{HashMap, HashSet};

use milo_guards_core::spelling::glob;
use milo_guards_core::Flavour;
use tree_sitter::Node;

use super::{blocks, canonical, is_cmdlet, variables, Walker};
use crate::unit::{self, Arg};

/// The variable, as [`variables::root_is`] names it.
const VARIABLE: &str = "psdefaultparametervalues";

/// How many entries are read before the line is taken to set defaults the
/// guard cannot follow: each cmdlet is given every entry its key matches,
/// so the work a line can make stays bounded.
const MOST: usize = 16;

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
}

/// The default parameter values a line sets, read once before its commands
/// are judged: they hold wherever on the line they are set, as a command
/// before the assignment may run after it (a loop, a function, a trap).
#[derive(Debug, Default)]
pub(super) struct Defaults {
    entries: Vec<Entry>,
    /// Whether the line may set defaults the guard does not read: the whole
    /// table set to a value only known when it runs, a method only known
    /// when it runs, the variable reached in any other way (`$d =
    /// $PSDefaultParameterValues`) or named as text (`Set-Variable
    /// PSDefaultParameterValues …`), or more entries than are read. Every
    /// cmdlet's paths are then only known when it runs.
    unread: bool,
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
    /// Read the defaults the tree under `root` sets (see [`Defaults`]).
    pub(super) fn read_defaults(&mut self, root: Node<'_>) {
        let mut assignments = Vec::new();
        let mut calls = Vec::new();
        let mut uses = Vec::new();
        let mut chains = Vec::new();
        unit::for_each_node(root, |node| {
            let kind = node.kind();
            match kind {
                "assignment_expression" => assignments.push(node),
                "variable" => uses.push(node),
                "generic_token" | "string_literal" => {
                    let text = unit::text(&node, self.source).as_bytes();
                    if text
                        .windows(VARIABLE.len())
                        .any(|window| window.eq_ignore_ascii_case(VARIABLE.as_bytes()))
                    {
                        self.defaults.unread = true;
                    }
                }
                _ => {}
            }
            if kind == "invokation_expression" {
                calls.push(node);
            }
            if chain(kind) {
                chains.push(node);
            }
        });
        // The variable each chain starts at, when it is this one: worked out
        // from the variable up, once for each node, so that a long chain is
        // not walked down again from each of its calls.
        let mut starts: HashMap<usize, Node<'_>> = uses
            .iter()
            .filter(|node| variables::root_is(**node, self.source, VARIABLE))
            .map(|node| (node.id(), *node))
            .collect();
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
                self.defaults.unread = true;
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
                self.defaults.unread = true;
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
                    _ => self.defaults.unread = true,
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
                continue;
            }
            let method = children
                .iter()
                .find(|child| child.kind() == "member_name")
                .and_then(|member| blocks::called(*member, self.source));
            match method.as_deref() {
                // A method only known when it runs may add one.
                None => self.defaults.unread = true,
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
                        _ => self.defaults.unread = true,
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
            self.defaults.unread = true;
        }
        for (key, value, plain) in pairs {
            if self.defaults.entries.len() >= MOST {
                self.defaults.unread = true;
                break;
            }
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
            self.defaults.entries.push(Entry {
                cmdlet,
                parameter,
                value,
            });
        }
    }

    /// A value as an argument: text written out, or only known when it
    /// runs.
    fn default_value(&self, node: Node<'_>) -> Arg {
        let mut value = node;
        while value.kind() != "string_literal" && value.named_child_count() == 1 {
            match value.named_child(0) {
                Some(only) => value = only,
                None => break,
            }
        }
        match self.expr(value) {
            known @ Arg::Known(_) if value.kind() == "string_literal" => known,
            _ => Arg::Unknown(unit::text(&node, self.source).to_string()),
        }
    }

    /// Give the cmdlet `key` the defaults the line sets for it, after its
    /// own `args`: a parameter by name (`-Path:` and the value), unless the
    /// command names that parameter itself, and a value whose parameter is
    /// only known when it runs as an argument by position. A line that may
    /// set defaults the guard does not read gives it an argument only known
    /// when it runs. A program that is no cmdlet takes no defaults.
    pub(super) fn give_defaults(
        &self,
        key: &str,
        args: &mut Vec<Arg>,
        shapes: &mut Vec<blocks::Shape>,
    ) {
        let defaults = &self.defaults;
        if defaults.entries.is_empty() && !defaults.unread {
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
                    given.push(Arg::Known(format!("-{parameter}:")));
                    given.push(entry.value.clone());
                }
                None => given.push(entry.value.clone()),
            }
        }
        if defaults.unread {
            given.push(Arg::Unknown(format!("${VARIABLE}")));
        }
        for arg in given {
            args.push(arg);
            shapes.push(blocks::Shape::default());
        }
    }
}
