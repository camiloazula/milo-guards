//! What a PowerShell line sets its variables to, where the line shows it for
//! certain: `$sb = { Get-ChildItem }; Invoke-Command $sb` runs the block the
//! line wrote out, and `$new = 'b'; $s -replace 'a', $new` replaces with
//! text. A variable is read only when the line sets it once, at its top
//! level, before the use, and nothing else on the line may set it; any
//! other is only known when it runs. A table or a list is read only when
//! nothing on the line may change it in place.

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
    /// A table or a list, which a method, an item or a member set on it
    /// changes in place without an assignment to the variable.
    collection: bool,
    /// Where the assignment ends: a use before it sees what the variable
    /// held before the line.
    after: usize,
    /// The assignment, for the walk to read its block as one that runs
    /// later.
    assignment: usize,
    /// A table written out whose every key is a name and every value text
    /// with nothing in it only known when it runs (`@{ Path = 'x' }`): the
    /// parameters a splat of it binds, as names and values.
    table: Option<Vec<(String, String)>>,
}

/// The variables of a line, read before its commands are judged.
#[derive(Default)]
pub(super) struct Variables {
    known: HashMap<String, Value>,
    /// The assignments of a block to a variable a later part of the line
    /// uses: the block runs where the variable is used, not where it is
    /// written.
    used_blocks: HashSet<usize>,
    /// The variables the line sets to something that may reach the session
    /// (`$ic = $ExecutionContext.InvokeCommand`, `$ec = (Get-Variable
    /// ExecutionContext).Value`, `$a = $ic`), in any assignment.
    session: HashSet<String>,
    /// What [`Variables::reaches_session`] found from each link of a chain,
    /// by node id and whether the links above it were obscure.
    reached: std::cell::RefCell<HashMap<(usize, bool), bool>>,
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
const SETTERS: [&str; 20] = [
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
    // `Tee-Object -Variable sb`, `tee -var sb`.
    "tee-object",
    // `-BindingVariable sb`.
    "import-localizeddata",
    // Changes a list it is given in place.
    "update-list",
];

/// The cmdlets that change an item or its content, on any drive: on the
/// `Variable:` drive they set a variable (`Set-Item Variable:sb $x`,
/// `Rename-Item Variable:x sb`). One whose path is not written out, or is
/// piped to it, may name that drive.
const ITEM_SETTERS: [&str; 7] = [
    "set-item",
    "new-item",
    "rename-item",
    "copy-item",
    "move-item",
    "set-content",
    "add-content",
];

/// The members that set a variable by its name or reach the variables of a
/// scope (`$ExecutionContext.SessionState.PSVariable.Set('sb', $x)`,
/// `(Get-PSCallStack)[0].GetFrameVariables()`,
/// `$Host.Runspace.SessionStateProxy.SetVariable('sb', $x)`), or set the
/// value of what holds one (`(Get-Variable sb).set_Value($x)`, and by
/// reflection `SetValue`): on a line that names one, no variable is read.
/// So does a line that sets a member named `Value`.
const VARIABLE_MEMBERS: [&str; 5] = [
    "psvariable",
    "getframevariables",
    "setvariable",
    "set_value",
    "setvalue",
];

/// The members that lead to the state of the session from wherever they are
/// reached (`$ExecutionContext.InvokeCommand`, `$PSCmdlet.SessionState`,
/// `$Host.Runspace.SessionStateProxy`): its hooks, variables and commands.
const SESSION_MEMBERS: [&str; 3] = ["invokecommand", "sessionstate", "sessionstateproxy"];

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

/// How many entries a table written out may have for a splat of it to bind
/// them (see [`table`]): a splat that binds parameters holds a handful, and
/// a line that splats a big table many times must not bind each entry each
/// time.
const MAX_SPLATTED: usize = 16;

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
        // What may reach the session: the variables set from it for certain,
        // and for each variable, the ones the line sets from it.
        let mut seeds: Vec<String> = Vec::new();
        let mut from: HashMap<String, Vec<String>> = HashMap::new();
        // The variables whose members, items or methods the line reaches, and
        // whether anything on the line may change a table or a list in place.
        let mut reached: HashSet<String> = HashSet::new();
        let mut changes = false;
        // Each splat, by name, with where it is and whether it names a scope.
        let mut splats: Vec<(String, usize, bool)> = Vec::new();
        // The variables the line reads other than by a splat (`f $p`), which
        // a command given one may change, and whether it runs code that may
        // set its variables where the guard does not read it (`. ./x.ps1`,
        // `Import-Module`).
        let mut given: HashSet<String> = HashSet::new();
        let mut unread = false;
        // The stages of pipelines after the first, which their input goes to.
        let mut piped: HashSet<usize> = HashSet::new();
        let top = top_level(root);
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
                    let text = unit::text(&node, source);
                    // A splat may hold `-OutVariable sb`, unless it is a
                    // table the line writes out (see below).
                    if text.starts_with('@') {
                        splats.push((normal(text), node.start_byte(), text.contains(':')));
                    } else if !set {
                        given.insert(normal(text));
                    }
                    let name = normal(text);
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
                    if let Some((name, value)) = candidate(node, source, &top) {
                        candidates.push((name, value));
                    }
                    if let (Some(name), Some(value)) =
                        (single(node, source), node.child_by_field_name("value"))
                    {
                        let (direct, names) = session_parts(value, source);
                        if direct {
                            seeds.push(name.clone());
                        }
                        for other in names {
                            from.entry(other).or_default().push(name.clone());
                        }
                    }
                }
                "pipeline_chain" => {
                    let mut cursor = node.walk();
                    piped.extend(
                        node.named_children(&mut cursor)
                            .skip(1)
                            .map(|stage| stage.id()),
                    );
                }
                "command" => {
                    all &= !sets_variables(node, source, piped.contains(&node.id()));
                    unread |= node.child(0).is_some_and(|first| {
                        first.kind() == "command_invokation_operator"
                            && unit::text(&first, source) == "."
                    }) || command_name(node, source).is_some_and(|name| {
                        matches!(super::canonical(&name), "import-module" | "ipmo")
                    });
                    // `$h | % Add e $b` calls a method of each item.
                    changes |= calls_members(node, source);
                }
                // `data sb { … }` sets `$sb`; a trap may run before an
                // assignment the line makes ahead of it.
                "data_statement" | "trap_statement" => all = false,
                "type_spec" => {
                    let spec = unit::text(&node, source).to_ascii_lowercase();
                    all &= spec != "ref" && !spec.contains("psreference");
                }
                "member_name" => {
                    all &= blocks::called(node, source).is_some_and(|name| {
                        !(VARIABLE_MEMBERS.contains(&name.as_str()) || (set && name == "value"))
                    });
                }
                "generic_token" | "string_literal" => {
                    // A path on the `Variable:` or `Alias:` drive, and a
                    // member `ForEach-Object` is given by name.
                    let text = unit::text(&node, source).to_ascii_lowercase();
                    let bare = blocks::bare(&text);
                    all &= !text.contains("variable:")
                        && !text.contains("alias:")
                        && !VARIABLE_MEMBERS.contains(&bare.as_str())
                        && bare != "value";
                }
                "member_access" | "element_access" | "invokation_expression" => {
                    // `$h.Add(…)`, `$h['e'] = …`, `$t.e = …`: a method may
                    // change what it is called on, and a member or item set
                    // changes a table or list another variable may hold.
                    changes |= node.kind() == "invokation_expression" || set;
                    if let Some(object) = node.named_child(0) {
                        let object = unwrap_parens(object);
                        if object.kind() == "variable" {
                            reached.insert(normal(unit::text(&object, source)));
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((child, set));
            }
        }
        let mut variables = Self {
            session: closure(seeds, &from),
            ..Self::default()
        };
        // A splat binds only the parameters its table holds when the line
        // sets it once, before the splat, to a table it writes out, that
        // nothing changes in place, no command is given and no code the
        // guard does not read may reach, and none of them stores into a
        // variable.
        let tables: HashMap<&str, &Value> = candidates
            .iter()
            .map(|(name, value)| (name.as_str(), value))
            .collect();
        all &= splats.iter().all(|(name, at, scoped)| {
            !scoped
                && !unread
                && !given.contains(name)
                && sets.get(name) == Some(&1)
                && !changes
                && !reached.contains(name)
                && tables.get(name.as_str()).is_some_and(|value| {
                    *at >= value.after
                        && value.table.as_ref().is_some_and(|table| {
                            table.iter().all(|(key, _)| {
                                let key = key.to_ascii_lowercase();
                                !STORE_ALIASES.contains(&key.as_str())
                                    && !STORES.iter().any(|full| full.starts_with(&key))
                            })
                        })
                })
        });
        if !all {
            return variables;
        }
        for (name, value) in candidates {
            if sets.get(&name) != Some(&1) || AUTOMATIC.contains(&name.as_str()) {
                continue;
            }
            if value.collection && (changes || reached.contains(&name)) {
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

    /// The parameters the splat `node` (however the grammar wraps it)
    /// binds, as names and values, when it splats a table the line writes
    /// out (see [`Value::table`]).
    pub(super) fn splat(&self, node: Node<'_>, source: &str) -> Option<&[(String, String)]> {
        let node = blocks::unwrap(node);
        let text = unit::text(&node, source);
        if node.kind() != "variable" || !text.starts_with('@') || text.contains(':') {
            return None;
        }
        let value = self.known.get(&normal(text))?;
        (node.start_byte() >= value.after)
            .then_some(value.table.as_deref())
            .flatten()
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

    /// Whether a chain of members, items and calls (`$x.$h`, `….psobject
    /// .Properties[…].Value`) reaches a member of the session by a way the
    /// guard cannot name: a name only known when it runs, an item, the
    /// result of a call, or the object's own view of its members (`psobject`
    /// and the like), above a member that leads to the session
    /// (`InvokeCommand`, `SessionState`, `SessionStateProxy`), whatever the
    /// chain starts at, or anywhere above `$ExecutionContext`, `(Get-Variable
    /// ExecutionContext)` or a variable the line sets to what may reach the
    /// session. Such a member may be a hook, or a method that runs code.
    ///
    /// What each link gives, with whether the links above it were obscure,
    /// is kept for the line: every call in a chain asks it of the chain
    /// before it, so read again at each, a chain of calls took time that
    /// grows with its square, up to the depth a tree may have.
    pub(super) fn reaches_session(&self, node: Node<'_>, source: &str) -> bool {
        let mut node = blocks::unwrap(node);
        let mut obscure = false;
        // The answer at each link is the answer at the next, so every link
        // passed keeps the one found.
        let mut passed = Vec::new();
        let found = 'found: {
            for _ in 0..unit::MAX_TREE_DEPTH {
                if let Some(&known) = self.reached.borrow().get(&(node.id(), obscure)) {
                    break 'found known;
                }
                passed.push((node.id(), obscure));
                match node.kind() {
                    "member_access" | "invokation_expression" => {
                        let name =
                            member_name(node).and_then(|member| blocks::called(member, source));
                        match name {
                            Some(name) if SESSION_MEMBERS.contains(&name.as_str()) && obscure => {
                                break 'found true;
                            }
                            Some(name)
                                if node.kind() == "member_access"
                                    && !matches!(
                                        name.as_str(),
                                        "psobject" | "psbase" | "psadapted" | "psextended"
                                    ) => {}
                            _ => obscure = true,
                        }
                    }
                    "element_access" => obscure = true,
                    "parenthesized_expression" => {}
                    "command" => break 'found obscure && reads_session(node, source),
                    "variable" => {
                        let text = unit::text(&node, source);
                        let name = normal(text);
                        break 'found obscure
                            && (name == "executioncontext"
                                || (!text.contains(':') && self.session.contains(&name)));
                    }
                    _ => break 'found false,
                }
                let Some(object) = node.named_child(0) else {
                    break 'found false;
                };
                node = blocks::unwrap(object);
            }
            true
        };
        self.reached
            .borrow_mut()
            .extend(passed.into_iter().map(|key| (key, found)));
        found
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
    starts_as(node, source, name) && root(node, source).as_deref() == Some(name)
}

/// Whether the text of `node` starts with the variable `name`: the quick
/// look of [`root_is`], before the chain is walked.
pub(super) fn starts_as(node: Node<'_>, source: &str, name: &str) -> bool {
    leading(unit::text(&node, source)).is_some_and(|(leading, _)| leading == name)
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
        match root_link(node, source) {
            Ok(next) => node = next,
            Err(found) => return found,
        }
    }
    None
}

/// One link of the chain [`root`] walks down: the next link, or what the
/// chain starts at when `node` is the last.
pub(super) fn root_link<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Result<Node<'tree>, Option<String>> {
    if node.kind() == "left_assignment_expression" {
        return node.named_child(0).ok_or(None);
    }
    let node = blocks::unwrap(node);
    match node.kind() {
        "member_access"
        | "element_access"
        | "invokation_expression"
        | "parenthesized_expression" => node.named_child(0).ok_or(None),
        "variable" => Err(Some(normal(unit::text(&node, source)))),
        _ => Err(None),
    }
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
/// `top` holds the assignments that are statements of their own at the top
/// of the line (see [`top_level`]).
fn candidate(node: Node<'_>, source: &str, top: &HashSet<usize>) -> Option<(String, Value)> {
    if !top.contains(&node.id()) {
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
    let collection = matches!(
        blocks::unwrap(value).kind(),
        "array_literal_expression" | "hash_literal_expression"
    );
    Some((
        name,
        Value {
            held,
            collection,
            after: node.end_byte(),
            assignment: node.id(),
            table: table(value, source),
        },
    ))
}

/// The parameters a table written out binds when it is splatted (`@{ Path
/// = 'x'; Value = "y" }`): each key a name, once, and each value text with
/// nothing in it only known when it runs that does not start with `-`,
/// and at most [`MAX_SPLATTED`] of them, so the parameters every splat of
/// it binds stay few. `None` for anything else.
fn table(value: Node<'_>, source: &str) -> Option<Vec<(String, String)>> {
    let value = blocks::unwrap(value);
    if value.kind() != "hash_literal_expression" {
        return None;
    }
    let Some(body) = value.named_child(0) else {
        return Some(Vec::new());
    };
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut cursor = body.walk();
    for entry in body.named_children(&mut cursor) {
        if entry.kind() != "hash_entry" || entry.named_child_count() != 2 {
            return None;
        }
        let key = entry.named_child(0)?;
        let key = blocks::unwrap(
            key.named_child(0)
                .filter(|_| key.kind() == "key_expression")?,
        );
        let key = match key.kind() {
            "simple_name" => unit::text(&key, source).to_string(),
            _ => literal_text(key, source)?,
        };
        let named = key.starts_with(|c: char| c.is_ascii_alphabetic())
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let text = literal_text(entry.named_child(1)?, source)?;
        if !named
            || text.starts_with('-')
            || entries
                .iter()
                .any(|(known, _)| known.eq_ignore_ascii_case(&key))
        {
            return None;
        }
        entries.push((key, text));
        if entries.len() > MAX_SPLATTED {
            return None;
        }
    }
    Some(entries)
}

/// The text a string written out holds, when nothing in it is only known
/// when it runs: `'x'` or `"x"` with no `$`, backtick or quote of any kind
/// inside.
fn literal_text(node: Node<'_>, source: &str) -> Option<String> {
    let node = blocks::unwrap(node);
    if node.kind() != "string_literal" {
        return None;
    }
    let text = unit::text(&node, source);
    let inner = text
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
        .or_else(|| {
            text.strip_prefix('"')
                .and_then(|text| text.strip_suffix('"'))
        })?;
    let quotes = [
        '\'', '"', '$', '`', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}', '\u{201c}',
        '\u{201d}', '\u{201e}',
    ];
    (!inner.contains(quotes)).then(|| inner.to_string())
}

/// The assignments that are statements of their own at the top of the line
/// under `root`, found from the top down: a node's parent is found by a walk
/// from the root, which on a deep line would cost its depth for each.
fn top_level(root: Node<'_>) -> HashSet<usize> {
    let mut top = HashSet::new();
    let mut cursor = root.walk();
    for statements in root.named_children(&mut cursor) {
        if statements.kind() != "statement_list" {
            continue;
        }
        let mut cursor = statements.walk();
        for pipeline in statements.named_children(&mut cursor) {
            if pipeline.kind() != "pipeline" || pipeline.named_child_count() != 1 {
                continue;
            }
            if let Some(assignment) = pipeline
                .named_child(0)
                .filter(|only| only.kind() == "assignment_expression")
            {
                top.insert(assignment.id());
            }
        }
    }
    top
}

/// Whether a command may set a variable the guard does not see set: one of
/// [`SETTERS`], one whose name is only known when it runs, one of
/// [`ITEM_SETTERS`] whose path is not written out or may be piped to it, or
/// a parameter that stores into a variable it names. `piped` says it is not
/// the first stage of its pipeline.
fn sets_variables(node: Node<'_>, source: &str, piped: bool) -> bool {
    let Some(name) = command_name(node, source) else {
        // `& { … }` runs the block written out, which the pass reads.
        return !node
            .child_by_field_name("command_name")
            .is_some_and(super::names_block);
    };
    let name = super::canonical(&name);
    if SETTERS.contains(&name) {
        return true;
    }
    let elements = node.child_by_field_name("command_elements");
    if ITEM_SETTERS.contains(&name) {
        // What it is piped may be a path.
        let unwritten = elements.is_some_and(|elements| {
            let mut cursor = elements.walk();
            let unwritten = elements
                .named_children(&mut cursor)
                .any(|element| !written_out(element, source, 0));
            unwritten
        });
        if piped || unwritten {
            return true;
        }
    }
    let Some(elements) = elements else {
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

/// What an assigned value says of the session: whether it may reach it for
/// certain (it names `$ExecutionContext`, a member that leads to the session
/// or `Get-Variable`), and the other variables it names, which may hold
/// what does. An assignment nested in it (`$a = $b = …`) is read on its own,
/// and gives the variable it sets: the walk does not go into one, so a line
/// is read once whatever its assignments.
fn session_parts(value: Node<'_>, source: &str) -> (bool, Vec<String>) {
    let mut direct = false;
    let mut names = Vec::new();
    unit::for_each_node_until(value, |node| match node.kind() {
        "assignment_expression" => {
            let mut cursor = node.walk();
            let left = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "left_assignment_expression");
            if let Some(left) = left {
                unit::for_each_node(left, |inner| {
                    if inner.kind() == "variable" {
                        names.push(normal(unit::text(&inner, source)));
                    }
                });
            }
            false
        }
        "variable" => {
            let text = unit::text(&node, source);
            let name = normal(text);
            if name == "executioncontext" {
                direct = true;
            } else if !text.contains(':') {
                names.push(name);
            }
            false
        }
        "member_name" => {
            direct |= blocks::called(node, source)
                .is_some_and(|name| SESSION_MEMBERS.contains(&name.as_str()));
            true
        }
        "command" => {
            direct |= reads_session(node, source);
            true
        }
        _ => true,
    });
    (direct, names)
}

/// The variables that may reach the session: `seeds`, and each the line
/// sets from one of them (`from` maps a variable to the ones set from it).
fn closure(seeds: Vec<String>, from: &HashMap<String, Vec<String>>) -> HashSet<String> {
    let mut session: HashSet<String> = HashSet::new();
    let mut queue = seeds;
    while let Some(name) = queue.pop() {
        if !session.insert(name.clone()) {
            continue;
        }
        if let Some(next) = from.get(&name) {
            queue.extend(next.iter().filter(|next| !session.contains(*next)).cloned());
        }
    }
    session
}

/// Whether a command is `Get-Variable`, which may give the session's
/// `$ExecutionContext` by name (`Get-Variable ExecutionContext -ValueOnly`,
/// `gv Exec*`).
fn reads_session(command: Node<'_>, source: &str) -> bool {
    matches!(
        command_name(command, source).as_deref(),
        Some("get-variable" | "gv")
    )
}

/// Whether a command is `ForEach-Object` given no script block, which calls a
/// member of each item by its name (`$h | % Add e $b`) or runs a block only
/// known when it runs.
fn calls_members(command: Node<'_>, source: &str) -> bool {
    if command_name(command, source)
        .as_deref()
        .map(super::canonical)
        != Some("foreach-object")
    {
        return false;
    }
    let Some(elements) = command.child_by_field_name("command_elements") else {
        return true;
    };
    let mut cursor = elements.walk();
    let block = elements
        .named_children(&mut cursor)
        .any(|element| blocks::written(element));
    !block
}

/// The name a command is run by, as PowerShell finds it: in lower case,
/// without its quotes and escapes (`& 'Set-Variable'`), and without the
/// module it is taken from (`Microsoft.PowerShell.Utility\Set-Variable`).
/// `None` for a name only known when it runs (`& $c`, `& ('Set-' + 'Variable')`)
/// and a block (`& { … }`).
fn command_name(command: Node<'_>, source: &str) -> Option<String> {
    let name = command.child_by_field_name("command_name")?;
    let text = unit::text(&name, source)
        .to_ascii_lowercase()
        .replace(['`', '\'', '"'], "");
    if text.contains(['$', '(', '{', '@']) {
        return None;
    }
    Some(
        text.rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string(),
    )
}

/// The name of the member a member access or call ends in.
fn member_name(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let name = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "member_name")
        .last();
    name
}

/// What an expression holds inside the brackets around it (`($h)`).
fn unwrap_parens(node: Node<'_>) -> Node<'_> {
    let mut node = blocks::unwrap(node);
    for _ in 0..unit::MAX_TREE_DEPTH {
        if node.kind() != "parenthesized_expression" {
            break;
        }
        match node.named_child(0) {
            Some(inner) => node = blocks::unwrap(inner),
            None => break,
        }
    }
    node
}

/// Whether an argument is written out: a word, a parameter, text with
/// nothing in it only known when it runs, or a list of them.
fn written_out(node: Node<'_>, source: &str, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let node = blocks::unwrap(node);
    match node.kind() {
        "generic_token" | "command_parameter" | "command_argument_sep" => true,
        // A splat is held to a table the line writes out once the line is
        // read (see [`Variables::read`]).
        "variable" => unit::text(&node, source).starts_with('@'),
        "string_literal" => match node.named_child(0) {
            Some(part) if part.kind() == "verbatim_string_characters" => true,
            Some(part) if part.kind() == "expandable_string_literal" => {
                part.named_child_count() == 0
            }
            _ => false,
        },
        "array_literal_expression" => {
            let mut cursor = node.walk();
            let all = node
                .named_children(&mut cursor)
                .all(|item| written_out(item, source, depth + 1));
            all
        }
        _ => false,
    }
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
