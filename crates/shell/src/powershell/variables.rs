//! What a PowerShell line sets its variables to, where the line shows it for
//! certain: `$sb = { Get-ChildItem }; Invoke-Command $sb` runs the block the
//! line wrote out, and `$new = 'b'; $s -replace 'a', $new` replaces with
//! text. A variable is read only when the line sets it once, at its top
//! level, before the use, and nothing else on the line may set it; any
//! other is only known when it runs.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::blocks;
use crate::unit;

/// What a variable holds, when the line shows it for certain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Held {
    /// A script block written out, which the walk reads where it is
    /// written.
    Block,
    /// Text, a number, or a list or table of them: never a script block.
    Inert,
}

/// A variable the line sets once, to a value it shows.
struct Value {
    held: Held,
    /// Where the assignment ends: a use before it sees what the variable
    /// held before the line.
    after: usize,
    /// The assignment, for the walk to read its block as one that runs
    /// later.
    assignment: usize,
}

/// The variables of a line, read before its commands are judged.
#[derive(Default)]
pub(super) struct Variables {
    known: HashMap<String, Value>,
    /// The assignments of a block to a variable a later part of the line
    /// uses: the block runs where the variable is used, not where it is
    /// written.
    used_blocks: HashSet<usize>,
    /// The variables the line sets to something reached from
    /// `$ExecutionContext` (`$ic = $ExecutionContext.InvokeCommand`), in
    /// any assignment.
    session: HashSet<String>,
}

/// The variables PowerShell sets itself, or that hold the session's state:
/// what the line assigns to them may not be what they hold when used.
const AUTOMATIC: [&str; 44] = [
    "_",
    "$",
    "?",
    "^",
    "args",
    "consolefilename",
    "enabledexperimentalfeatures",
    "error",
    "event",
    "eventargs",
    "eventsubscriber",
    "executioncontext",
    "false",
    "foreach",
    "home",
    "host",
    "input",
    "iscoreclr",
    "islinux",
    "ismacos",
    "iswindows",
    "lastexitcode",
    "matches",
    "myinvocation",
    "nestedpromptlevel",
    "null",
    "pid",
    "profile",
    "psboundparameters",
    "pscmdlet",
    "pscommandpath",
    "psculture",
    "psdebugcontext",
    "psdefaultparametervalues",
    "pshome",
    "psitem",
    "psscriptroot",
    "pssenderinfo",
    "psuiculture",
    "psversiontable",
    "pwd",
    "sender",
    "shellid",
    "this",
];

/// The commands that set a variable by its name, or run text as code that
/// may set one, or give a command another name (`Set-Alias x Set-Variable`):
/// on a line with one, no variable is read.
const SETTERS: [&str; 17] = [
    "set-variable",
    "set",
    "sv",
    "new-variable",
    "nv",
    "clear-variable",
    "clv",
    "remove-variable",
    "rv",
    "get-variable",
    "gv",
    "invoke-expression",
    "set-alias",
    "new-alias",
    "import-alias",
    "remove-alias",
    "new-psdrive",
];

/// The common parameters that store a command's output or errors in a
/// variable they name (`-OutVariable sb`), with their aliases.
const STORES: [&str; 5] = [
    "outvariable",
    "errorvariable",
    "warningvariable",
    "informationvariable",
    "pipelinevariable",
];
const STORE_ALIASES: [&str; 5] = ["ov", "ev", "wv", "iv", "pv"];

/// How deep a value is read for text and blocks: a table in a table in a
/// list. A deeper one is only known when it runs.
const MAX_DEPTH: usize = 16;

impl Variables {
    /// Read the variables the line under `root` sets.
    pub(super) fn read(root: Node<'_>, source: &str) -> Self {
        // A line with no variable sets none.
        if !source
            .get(root.byte_range())
            .unwrap_or_default()
            .contains('$')
        {
            return Self::default();
        }
        let mut sets: HashMap<String, usize> = HashMap::new();
        // The last place each variable is used, read or set.
        let mut last_use: HashMap<String, usize> = HashMap::new();
        let mut candidates: Vec<(String, Value)> = Vec::new();
        let mut session = HashSet::new();
        let mut all = true;
        // Each node with whether it is on the left of an assignment or
        // declares a parameter.
        let mut stack: Vec<(Node<'_>, bool)> = vec![(root, false)];
        while let Some((node, set)) = stack.pop() {
            let set = set
                || matches!(
                    node.kind(),
                    "left_assignment_expression" | "script_parameter"
                );
            match node.kind() {
                "variable" => {
                    let name = normal(unit::text(&node, source));
                    if set {
                        *sets.entry(name.clone()).or_default() += 1;
                    }
                    let at = last_use.entry(name).or_default();
                    *at = (*at).max(node.start_byte());
                }
                "foreach_statement" => {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if child.kind() == "variable" {
                            *sets.entry(normal(unit::text(&child, source))).or_default() += 2;
                        }
                    }
                }
                "assignment_expression" => {
                    if let Some((name, value)) = candidate(node, source) {
                        candidates.push((name, value));
                    }
                    if let Some(name) = single(node, source) {
                        if node
                            .child_by_field_name("value")
                            .is_some_and(|value| from_session(value, source, &HashSet::new()))
                        {
                            session.insert(name);
                        }
                    }
                }
                "command" => all &= !sets_variables(node, source),
                // `data sb { … }` sets `$sb`.
                "data_statement" => all = false,
                "type_spec" => {
                    let spec = unit::text(&node, source).to_ascii_lowercase();
                    all &= spec != "ref" && !spec.contains("psreference");
                }
                "member_name" => {
                    all &= !unit::text(&node, source).eq_ignore_ascii_case("psvariable");
                }
                "generic_token" | "string_literal" => {
                    // A path on the `Variable:` or `Alias:` drive.
                    let text = unit::text(&node, source).to_ascii_lowercase();
                    all &= !text.contains("variable:") && !text.contains("alias:");
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((child, set));
            }
        }
        let mut variables = Self {
            session,
            ..Self::default()
        };
        if !all {
            return variables;
        }
        for (name, value) in candidates {
            if sets.get(&name) != Some(&1) || AUTOMATIC.contains(&name.as_str()) {
                continue;
            }
            if value.held == Held::Block && last_use.get(&name).is_some_and(|at| *at >= value.after)
            {
                variables.used_blocks.insert(value.assignment);
            }
            variables.known.insert(name, value);
        }
        variables
    }

    /// What the variable `node` is (however the grammar wraps it) holds
    /// where it is used, when the line shows it.
    pub(super) fn held(&self, node: Node<'_>, source: &str) -> Option<Held> {
        let node = blocks::unwrap(node);
        if node.kind() != "variable" {
            return None;
        }
        let text = unit::text(&node, source);
        // A scope written out may name another variable than the one the
        // line set.
        if text.contains(':') {
            return None;
        }
        let value = self.known.get(&normal(text))?;
        (node.start_byte() >= value.after).then_some(value.held)
    }

    /// Whether the assignment `node` gives a variable a block that a later
    /// part of the line runs through it.
    pub(super) fn runs_later(&self, node: Node<'_>) -> bool {
        self.used_blocks.contains(&node.id())
    }

    /// Whether `node` (however the grammar wraps it) is a value that cannot
    /// be a script block known only when it runs: text, a number, a word, a
    /// block written out, a list or table of them, or a variable the line
    /// sets to one of them.
    pub(super) fn inert(&self, node: Node<'_>, source: &str) -> bool {
        inert(node, source, Some(self), 0)
    }

    /// Whether `node` is reached from `$ExecutionContext`, or from a
    /// variable the line sets to something that is.
    pub(super) fn reaches_session(&self, node: Node<'_>, source: &str) -> bool {
        // The chain starts with its variable: a chain of any other is not
        // walked down, so a long one costs one look.
        let Some((name, scoped)) = leading(unit::text(&node, source)) else {
            return false;
        };
        (name == "executioncontext" || (!scoped && self.session.contains(&name)))
            && from_session(node, source, &self.session)
    }
}

/// A variable's name as PowerShell looks it up: without `$`, `@` or braces,
/// in lower case, and without a scope that names the line's own variables
/// (`$global:x`, `${script:x}`, `$variable:x`). `$using:x` is another.
fn normal(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let name = lower.trim_start_matches(['$', '@']);
    let name = name
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(name);
    let name = ["global:", "local:", "script:", "private:", "variable:"]
        .iter()
        .find_map(|scope| name.strip_prefix(scope))
        .unwrap_or(name);
    name.to_string()
}

/// The variable a chain of members, items and calls starts at
/// (`$PSDefaultParameterValues['x']`), as [`normal`] names it, when it is
/// `name`.
pub(super) fn root_is(node: Node<'_>, source: &str, name: &str) -> bool {
    leading(unit::text(&node, source)).is_some_and(|(leading, _)| leading == name)
        && root(node, source).as_deref() == Some(name)
}

/// The variable the text of a chain starts with, as [`normal`] names it,
/// and whether it is written with a scope. Only a quick look, which
/// [`root`] makes sure of.
fn leading(text: &str) -> Option<(String, bool)> {
    let rest = text
        .trim_start_matches(['(', ' ', '\t'])
        .strip_prefix('$')?;
    let name = if rest.starts_with('{') {
        let end = rest.find('}')?;
        rest.get(..=end)?
    } else {
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(rest.len());
        rest.get(..end)?
    };
    Some((normal(name), name.contains(':')))
}

/// The variable a chain of members, items and calls starts at, as
/// [`normal`] names it.
fn root(node: Node<'_>, source: &str) -> Option<String> {
    let mut node = node;
    for _ in 0..unit::MAX_TREE_DEPTH {
        if node.kind() == "left_assignment_expression" {
            node = node.named_child(0)?;
            continue;
        }
        node = blocks::unwrap(node);
        match node.kind() {
            "member_access"
            | "element_access"
            | "invokation_expression"
            | "parenthesized_expression" => {
                node = node.named_child(0)?;
            }
            "variable" => return Some(normal(unit::text(&node, source))),
            _ => return None,
        }
    }
    None
}

/// The one variable an assignment sets, when its left side is a variable
/// alone (`$x = …`, not `$x.y = …` or `$a, $b = …`).
fn single(node: Node<'_>, source: &str) -> Option<String> {
    let left = node.named_child(0)?;
    let mut target = left;
    if target.kind() == "left_assignment_expression" {
        target = target.named_child(0)?;
    }
    let target = blocks::unwrap(target);
    (target.kind() == "variable").then(|| normal(unit::text(&target, source)))
}

/// A variable the assignment `node` sets for certain: a plain `=` to a
/// variable alone, a statement of its own at the top of the line (not in a
/// branch, a loop, a block or a chain, which may not run it), to a block
/// written out or to an inert value.
fn candidate(node: Node<'_>, source: &str) -> Option<(String, Value)> {
    let pipeline = node.parent()?;
    let statements = pipeline.parent()?;
    if pipeline.kind() != "pipeline"
        || pipeline.named_child_count() != 1
        || statements.kind() != "statement_list"
        || statements.parent()?.kind() != "program"
    {
        return None;
    }
    let mut cursor = node.walk();
    let operator = node
        .children(&mut cursor)
        .find(|child| child.kind() == "assignement_operator")?;
    if unit::text(&operator, source) != "=" {
        return None;
    }
    let name = single(node, source)?;
    let value = node.child_by_field_name("value")?;
    let held = if blocks::written(value) {
        Held::Block
    } else if inert(value, source, None, 0) {
        Held::Inert
    } else {
        return None;
    };
    Some((
        name,
        Value {
            held,
            after: node.end_byte(),
            assignment: node.id(),
        },
    ))
}

/// Whether a command may set a variable the guard does not see set: one of
/// [`SETTERS`], or a parameter that stores into a variable it names.
fn sets_variables(node: Node<'_>, source: &str) -> bool {
    // The name as PowerShell finds the command: in any case, without its
    // quotes and escapes (`& 'Set-Variable'`), and without the module it is
    // taken from (`Microsoft.PowerShell.Utility\Set-Variable`).
    let name = node.child_by_field_name("command_name").map(|name| {
        let text = unit::text(&name, source)
            .to_ascii_lowercase()
            .replace(['`', '\'', '"'], "");
        text.rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string()
    });
    if name
        .as_deref()
        .is_some_and(|name| SETTERS.contains(&super::canonical(name)))
    {
        return true;
    }
    let Some(elements) = node.child_by_field_name("command_elements") else {
        return false;
    };
    let mut cursor = elements.walk();
    let stores = elements
        .named_children(&mut cursor)
        .filter(|element| element.kind() == "command_parameter")
        .any(|element| {
            let name = unit::text(&element, source)
                .trim_start_matches('-')
                .trim_end_matches(':')
                .to_ascii_lowercase();
            !name.is_empty()
                && (STORE_ALIASES.contains(&name.as_str())
                    || STORES.iter().any(|full| full.starts_with(&name)))
        });
    stores
}

/// Whether `node` is a value that cannot be a script block known only when
/// it runs (see [`Variables::inert`]); `variables` reads the variables the
/// line sets, when given.
fn inert(node: Node<'_>, source: &str, variables: Option<&Variables>, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let node = blocks::unwrap(node);
    match node.kind() {
        "string_literal"
        | "integer_literal"
        | "real_literal"
        | "generic_token"
        | "script_block_expression" => true,
        "variable" => {
            matches!(
                normal(unit::text(&node, source)).as_str(),
                "true" | "false" | "null"
            ) || variables.is_some_and(|variables| variables.held(node, source).is_some())
        }
        "array_literal_expression" => {
            let mut cursor = node.walk();
            let all = node
                .named_children(&mut cursor)
                .all(|item| inert(item, source, variables, depth + 1));
            all
        }
        "hash_literal_expression" => {
            let Some(body) = node.named_child(0) else {
                // `@{}`
                return true;
            };
            let mut cursor = body.walk();
            let all = body.named_children(&mut cursor).all(|entry| {
                let mut cursor = entry.walk();
                let value = entry.named_children(&mut cursor).last();
                entry.kind() == "hash_entry"
                    && value.is_some_and(|value| {
                        value.kind() != "key_expression"
                            && inert(value, source, variables, depth + 1)
                    })
            });
            all
        }
        _ => false,
    }
}

/// Whether `node` is a chain of members, items and calls that starts at
/// `$ExecutionContext` or at a variable in `session`.
fn from_session(node: Node<'_>, source: &str, session: &HashSet<String>) -> bool {
    let mut node = blocks::unwrap(node);
    for _ in 0..unit::MAX_TREE_DEPTH {
        match node.kind() {
            "member_access" | "element_access" | "invokation_expression" => {
                let Some(object) = node.named_child(0) else {
                    return false;
                };
                node = blocks::unwrap(object);
            }
            "parenthesized_expression" => {
                let Some(inner) = node.named_child(0) else {
                    return false;
                };
                node = blocks::unwrap(inner);
            }
            "variable" => {
                let text = unit::text(&node, source);
                let name = normal(text);
                return name == "executioncontext"
                    || (!text.contains(':') && session.contains(&name));
            }
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::normal;

    #[test]
    fn a_name_is_read_without_its_scope_and_case() {
        assert_eq!(normal("$SB"), "sb");
        assert_eq!(normal("${sb}"), "sb");
        assert_eq!(normal("$global:Sb"), "sb");
        assert_eq!(normal("${script:sb}"), "sb");
        assert_eq!(normal("$variable:sb"), "sb");
        assert_eq!(normal("@sb"), "sb");
        assert_eq!(normal("$using:sb"), "using:sb");
    }
}
