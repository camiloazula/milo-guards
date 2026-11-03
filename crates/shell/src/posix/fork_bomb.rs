//! Fork bombs: the functions a line defines that start copies of themselves
//! without end, alone (`:(){ :|:& };:`) or through each other (`f() { g & };
//! g() { f & }`).
//!
//! Each function's body is read for the calls it makes to the functions the
//! line defines, and where each call stands: whether it starts a process of
//! its own, whether a recursion through it may end with the values it passes
//! on, and whether it runs more than once. `eval`'s words are read as a line
//! of their own, standing where the `eval` does. The functions that call each
//! other in a cycle are judged together: they start copies without end when
//! one of their calls starts a process and they start two or more copies
//! each time round, or one copy with no such condition on the way.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use tree_sitter::Node;

use super::Walker;
use crate::launch::{self, Launch};
use crate::unit::{self, Arg};
use crate::Rule;

/// Where a command stands in a function's body.
#[derive(Clone, Default)]
struct Scope {
    /// It starts a process of its own: in the background, as a stage of a
    /// pipeline, in a subshell or a substitution, or through `coproc`.
    forks: bool,
    /// It runs only when a condition that reads a value known when it runs
    /// holds (`[ -d "$d" ] && …`, `case $1 in …`).
    conditional: bool,
    /// It may run more than once each time the function runs: in a `while`
    /// or `until` loop, a `select`, a `for ((…))`, or a loop over two or more
    /// words or a brace list.
    many: bool,
    /// The loops over a word known only when it runs, or over the arguments,
    /// it is in: innermost first.
    loops: Option<Rc<Loop>>,
}

/// A loop over a word known only when it runs (`for d in "$1"/*`, `for i in
/// $(seq 2)`) or over the arguments (`for x; do`, `for x in "$@"`): it runs
/// its body as many times as that word gives names.
struct Loop {
    variable: String,
    over_arguments: bool,
    outer: Option<Rc<Loop>>,
}

/// A call from one function the line defines to another, or to itself, and
/// where it stands.
struct Call {
    from: usize,
    to: usize,
    /// It starts a process of its own.
    forks: bool,
    /// A recursion through it may end with the values it passes on.
    guarded: bool,
    /// It may start more than one copy each time the function runs.
    many: bool,
}

/// What a command runs, of what the scan follows.
enum Called<'t> {
    /// A function the line defines, by its index, with the arguments it is
    /// given.
    Function {
        to: usize,
        forks: bool,
        args: Vec<Node<'t>>,
    },
    /// A line `eval` runs, joined from its arguments.
    Eval { line: String, forks: bool },
}

impl Walker<'_> {
    /// After the line is read: each set of functions that start copies of
    /// themselves without end is `stop_system`, however the line calls them,
    /// even when it only defines them.
    pub(super) fn fork_bombs(&mut self, root: Node<'_>) {
        let definitions = definitions(root);
        if definitions.is_empty() {
            return;
        }
        // One function to a name, in the order the line first defines them:
        // a name defined twice has the calls of both bodies.
        let mut names: Vec<&str> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for (name, _) in &definitions {
            let name = unit::text(name, self.source);
            index.entry(name).or_insert_with(|| {
                names.push(name);
                names.len() - 1
            });
        }
        let varies = varying(root, self.source);
        let mut calls = Vec::new();
        for (name, body) in &definitions {
            let Some(&from) = index.get(unit::text(name, self.source)) else {
                continue;
            };
            self.calls_in(*body, Scope::default(), from, &index, &varies, &mut calls);
        }
        let mut graph = vec![Vec::new(); names.len()];
        for call in &calls {
            if let Some(out) = graph.get_mut(call.from) {
                out.push(call.to);
            }
        }
        let component = components(&graph);
        let count = component.iter().max().map_or(0, |last| last + 1);
        // For each cycle: whether a call in it starts a process, whether a
        // function in it starts two or more copies, and whether a call in it
        // is guarded.
        let mut forks = vec![false; count];
        let mut guarded = vec![false; count];
        let mut copies = vec![0_usize; names.len()];
        let mut cyclic = vec![false; count];
        for call in &calls {
            let (Some(&from), Some(&to)) = (component.get(call.from), component.get(call.to))
            else {
                continue;
            };
            if from != to {
                continue;
            }
            if let Some(cycle) = cyclic.get_mut(from) {
                *cycle = true;
            }
            if let Some(forks) = forks.get_mut(from) {
                *forks |= call.forks;
            }
            if let Some(guarded) = guarded.get_mut(from) {
                *guarded |= call.guarded;
            }
            if let Some(copies) = copies.get_mut(call.from) {
                *copies += if call.many { 2 } else { 1 };
            }
        }
        let mut branches = vec![false; count];
        for (function, &made) in copies.iter().enumerate() {
            if made >= 2 {
                if let Some(branch) = component.get(function).and_then(|c| branches.get_mut(*c)) {
                    *branch = true;
                }
            }
        }
        let mut reported = vec![false; count];
        for (function, name) in names.iter().enumerate() {
            let Some(&cycle) = component.get(function) else {
                continue;
            };
            let at = |list: &[bool]| list.get(cycle).copied().unwrap_or(false);
            let bomb = at(&cyclic) && at(&forks) && (at(&branches) || !at(&guarded));
            if bomb && !at(&reported) {
                if let Some(seen) = reported.get_mut(cycle) {
                    *seen = true;
                }
                self.split.problem(
                    Rule::StopSystem,
                    "starts copies of itself without end",
                    Some(name),
                );
            }
        }
    }

    /// The calls `body`, standing at `outer` in the body of the function
    /// `from`, makes to the functions in `index`; `varies` holds the nodes of
    /// its tree that read a value known when it runs. A function defined
    /// inside is read on its own, so its commands are not read again here:
    /// each node is read once, and each carries down where it stands, so the
    /// scan never climbs back up.
    fn calls_in(
        &mut self,
        body: Node<'_>,
        outer: Scope,
        from: usize,
        index: &HashMap<&str, usize>,
        varies: &HashSet<usize>,
        calls: &mut Vec<Call>,
    ) {
        let mut stack = vec![(body, outer)];
        let mut cursor = body.walk();
        while let Some((node, scope)) = stack.pop() {
            if node.kind() == "command" {
                match self.called(node, index) {
                    Some(Called::Function { to, forks, args }) => {
                        calls.push(self.placed(&scope, from, to, forks, &args, varies));
                    }
                    // What `eval` runs stands where the `eval` does.
                    Some(Called::Eval { line, forks }) => {
                        let mut scope = scope.clone();
                        scope.forks |= forks;
                        self.eval_calls(&line, scope, from, index, calls);
                    }
                    None => {}
                }
            }
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            let inner = Inner::of(node, &children, varies, self.source);
            for (at, child) in children.iter().enumerate() {
                if !child.is_named() || child.kind() == "function_definition" {
                    continue;
                }
                let mut scope = inner.scope(&scope, node, *child);
                scope.forks |= children.get(at + 1).is_some_and(|next| next.kind() == "&");
                stack.push((*child, scope));
            }
        }
    }

    /// The calls in `line`, which `eval` runs at `scope`: read as a line of
    /// its own, each command at its own place in it.
    fn eval_calls(
        &mut self,
        line: &str,
        scope: Scope,
        from: usize,
        index: &HashMap<&str, usize>,
        calls: &mut Vec<Call>,
    ) {
        // The walk reads the same line, and says when it is too deep or too
        // long to read.
        if self.depth >= unit::MAX_DEPTH || line.len() > unit::MAX_LEN {
            return;
        }
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_bash::LANGUAGE.into();
        let Some(tree) = parser
            .set_language(&language)
            .ok()
            .and_then(|()| parser.parse(line, None))
        else {
            return;
        };
        let root = tree.root_node();
        let varies = varying(root, line);
        let mut walker = Walker {
            source: line,
            marks: &[],
            depth: self.depth + 1,
            split: &mut *self.split,
            redirected: None,
            lost: None,
            last_command: 0..0,
            tail_of: Vec::new(),
            tail: None,
            unstaged: None,
            sets: HashMap::new(),
            functions: HashSet::new(),
        };
        walker.calls_in(root, scope, from, index, &varies, calls);
    }

    /// A call to `to` from `from` with `args`, standing at `scope`: guarded
    /// when a condition holds it and it passes on a value known when it runs,
    /// or when, in each loop over a word known when it runs, it passes on
    /// the loop's variable (`walk "$d"`); in such a loop it starts many
    /// copies otherwise, or when the loop is over the arguments and it passes
    /// two or more words, which may grow with each copy.
    fn placed(
        &self,
        scope: &Scope,
        from: usize,
        to: usize,
        forks: bool,
        args: &[Node<'_>],
        varies: &HashSet<usize>,
    ) -> Call {
        let mut many = scope.many;
        let mut guarded = scope.conditional && args.iter().any(|arg| varies.contains(&arg.id()));
        if scope.loops.is_some() {
            let read = variables(args, self.source);
            let mut each = true;
            let mut at = scope.loops.as_deref();
            while let Some(lp) = at {
                if !read.contains(lp.variable.as_str()) || (lp.over_arguments && args.len() >= 2) {
                    each = false;
                    break;
                }
                at = lp.outer.as_deref();
            }
            if each {
                guarded = true;
            } else {
                many = true;
            }
        }
        Call {
            from,
            to,
            forks: scope.forks || forks,
            guarded,
            many,
        }
    }

    /// What `command` runs of what the scan follows: a function in `index`
    /// by its name (`f`, `\f`, `"f"`), behind zsh's `noglob`, `nocorrect`
    /// and `-`, or started by `coproc` (`coproc f`, `coproc { f; }`, which
    /// starts a process of its own); or the line `eval` runs, also behind
    /// `builtin` and `command`, which skip functions but not `eval`.
    fn called<'t>(&self, command: Node<'t>, index: &HashMap<&str, usize>) -> Option<Called<'t>> {
        let mut cursor = command.walk();
        let words: Vec<Node<'t>> = command
            .child_by_field_name("name")
            .into_iter()
            .chain(command.children_by_field_name("argument", &mut cursor))
            .collect();
        let args: Vec<Arg> = words.iter().map(|word| self.arg(*word)).collect();
        let mut at = 0;
        let mut functions = true;
        let mut forks = false;
        // Each wrapper takes at least its own word off, so this ends.
        while let Some(word) = args.get(at).and_then(Arg::known) {
            if functions {
                if let Some(&to) = index.get(word) {
                    let args = words.get(at + 1..).unwrap_or_default().to_vec();
                    return Some(Called::Function { to, forks, args });
                }
            }
            let rest = args.get(at + 1..).unwrap_or_default();
            match word {
                "eval" => {
                    let rest = match rest.first().and_then(Arg::known) {
                        Some("--") => rest.get(1..).unwrap_or_default(),
                        _ => rest,
                    };
                    let line = launch::join(rest);
                    return line.known().map(|line| Called::Eval {
                        line: line.to_string(),
                        forks,
                    });
                }
                "builtin" | "command" => {
                    // `command -v f` only says what `f` is.
                    if word == "command"
                        && rest
                            .iter()
                            .map_while(Arg::known)
                            .take_while(|flag| flag.starts_with('-') && *flag != "--")
                            .any(|flag| flag.contains(['v', 'V']))
                    {
                        return None;
                    }
                    functions = false;
                    at += 1 + launch::after_options(rest, &[])?;
                }
                "noglob" | "nocorrect" | "-" if functions => at += 1,
                "coproc" if functions => {
                    let Launch::Runs(start) = launch::coproc(rest) else {
                        return None;
                    };
                    forks = true;
                    at += 1 + start;
                }
                _ => return None,
            }
        }
        None
    }
}

/// What the children of a compound node are: for each kind that changes how
/// often, or on what, what it holds runs.
struct Inner {
    /// The ids of the children that are its condition, run before the rest.
    condition: HashSet<usize>,
    /// Whether the condition reads a value known when it runs.
    varies: bool,
    /// Whether the rest may run more than once.
    many: bool,
    /// For a loop over a word known when it runs, or over the arguments:
    /// its variable, and whether it is over the arguments.
    over: Option<(String, bool)>,
}

impl Inner {
    fn of(node: Node<'_>, children: &[Node<'_>], varies: &HashSet<usize>, source: &str) -> Self {
        let mut cursor = node.walk();
        let reads = |nodes: &[Node<'_>]| nodes.iter().any(|node| varies.contains(&node.id()));
        let mut inner = Self {
            condition: HashSet::new(),
            varies: false,
            many: false,
            over: None,
        };
        match node.kind() {
            "if_statement" => {
                let condition: Vec<Node<'_>> = node
                    .children_by_field_name("condition", &mut cursor)
                    .collect();
                inner.varies = reads(&condition);
                inner.condition = condition.iter().map(Node::id).collect();
            }
            // A `while` or `until` loop may run its body and its condition
            // again and again, whatever the condition reads.
            "while_statement" | "c_style_for_statement" => inner.many = true,
            // The commands before `then` are the condition of an `elif`.
            "elif_clause" => {
                let then = children
                    .iter()
                    .position(|child| child.kind() == "then")
                    .unwrap_or(children.len());
                let condition = children.get(..then).unwrap_or_default();
                inner.varies = reads(condition);
                inner.condition = condition.iter().map(Node::id).collect();
            }
            "case_statement" => {
                let value: Vec<Node<'_>> =
                    node.children_by_field_name("value", &mut cursor).collect();
                inner.varies = reads(&value);
                inner.condition = value.iter().map(Node::id).collect();
            }
            // `for x in a b` runs once for each word, so more than once for
            // two or more words or a brace list, which may stand for many;
            // `select` until the user stops it. A word known only when it
            // runs, or the arguments (`for x; do`, `for x in "$@"`), give as
            // many names as they hold.
            "for_statement" => {
                let values: Vec<Node<'_>> =
                    node.children_by_field_name("value", &mut cursor).collect();
                inner.many = values.len() >= 2
                    || values.iter().any(|value| brace_list(*value, source))
                    || children.first().is_some_and(|word| word.kind() == "select");
                if !inner.many && (values.is_empty() || reads(&values)) {
                    let variable = node
                        .child_by_field_name("variable")
                        .map(|name| unit::text(&name, source).to_string())
                        .unwrap_or_default();
                    let over_arguments =
                        values.is_empty() || values.iter().any(|value| arguments(*value, source));
                    inner.over = Some((variable, over_arguments));
                }
                inner.condition = values.iter().map(Node::id).collect();
            }
            // The right side of `&&` and `||` runs on what the left gave.
            "list" => {
                let named: Vec<Node<'_>> =
                    children.iter().filter(|c| c.is_named()).copied().collect();
                let left = named
                    .get(..named.len().saturating_sub(1))
                    .unwrap_or_default();
                inner.varies = reads(left);
                inner.condition = left.iter().map(Node::id).collect();
            }
            _ => {}
        }
        inner
    }

    /// Where `child`, a child of `node`, stands, inside `outer`.
    fn scope(&self, outer: &Scope, node: Node<'_>, child: Node<'_>) -> Scope {
        let mut scope = outer.clone();
        match node.kind() {
            // Each stage of a pipeline of two or more runs as a process.
            "pipeline" => scope.forks |= node.named_child_count() > 1,
            "subshell" | "command_substitution" | "process_substitution" => scope.forks = true,
            "list" | "if_statement" | "elif_clause" | "case_statement" => {
                if !self.condition.contains(&child.id()) {
                    scope.conditional |= self.varies;
                }
            }
            "for_statement" => {
                if !self.condition.contains(&child.id()) {
                    scope.many |= self.many;
                    if let Some((variable, over_arguments)) = &self.over {
                        scope.loops = Some(enter(outer.loops.as_ref(), variable, *over_arguments));
                    }
                }
            }
            "while_statement" | "c_style_for_statement" => scope.many |= self.many,
            _ => {}
        }
        scope
    }
}

/// The loops `outer` with one over `variable` inside them. A loop whose
/// variable an outer one already asks for, as strictly, asks nothing more,
/// so a call is checked against each variable at most twice however deep
/// the loops nest.
fn enter(outer: Option<&Rc<Loop>>, variable: &str, over_arguments: bool) -> Rc<Loop> {
    let mut at = outer.map(Rc::as_ref);
    while let Some(lp) = at {
        if lp.variable == variable && (lp.over_arguments || !over_arguments) {
            if let Some(outer) = outer {
                return Rc::clone(outer);
            }
        }
        at = lp.outer.as_deref();
    }
    Rc::new(Loop {
        variable: variable.to_string(),
        over_arguments,
        outer: outer.cloned(),
    })
}

/// Whether `value`, a word a `for` loops over, is a brace list: a range
/// (`{1..3}`), or a `{`, a `,` and a `}` the grammar leaves as bare words of
/// one word (`{a,b}`, `x{a,"b"}`), not quoted.
fn brace_list(value: Node<'_>, source: &str) -> bool {
    let mut found = false;
    unit::for_each_node(value, |node| match node.kind() {
        "brace_expression" => found = true,
        "concatenation" => {
            let mut cursor = node.walk();
            let mut open = false;
            let mut comma = false;
            for part in node.named_children(&mut cursor) {
                if part.kind() != "word" {
                    continue;
                }
                let word = unit::text(&part, source);
                if word == "{" {
                    open = true;
                } else if open && word.starts_with('}') && comma {
                    found = true;
                } else if open && word.contains(',') {
                    comma = true;
                }
            }
        }
        _ => {}
    });
    found
}

/// Whether `value`, a word a `for` loops over, holds the arguments: `$@`,
/// `$*`, quoted or not.
fn arguments(value: Node<'_>, source: &str) -> bool {
    let mut found = false;
    unit::for_each_node(value, |node| {
        found |= node.kind() == "special_variable_name"
            && matches!(unit::text(&node, source), "@" | "*");
    });
    found
}

/// The names of the variables `args` read.
fn variables<'s>(args: &[Node<'_>], source: &'s str) -> HashSet<&'s str> {
    let mut read = HashSet::new();
    for arg in args {
        unit::for_each_node(*arg, |node| {
            if node.kind() == "variable_name" {
                read.insert(unit::text(&node, source));
            }
        });
    }
    read
}

/// The function definitions in the tree under `root`, inside others
/// included, each as its name and body.
fn definitions(root: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    let mut found = Vec::new();
    unit::for_each_node(root, |node| {
        if node.kind() == "function_definition" {
            if let (Some(name), Some(body)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("body"),
            ) {
                found.push((name, body));
            }
        }
    });
    found
}

/// The ids of the nodes under `root` that hold a value only known when the
/// line runs: an expansion, a substitution, or a word with a wildcard. Each
/// node is read once, its children before it.
fn varying(root: Node<'_>, source: &str) -> HashSet<usize> {
    let mut varies = HashSet::new();
    let mut cursor = root.walk();
    let mut stack = vec![(root, false)];
    while let Some((node, done)) = stack.pop() {
        if done {
            let own = matches!(
                node.kind(),
                "simple_expansion" | "expansion" | "command_substitution" | "process_substitution"
            ) || (node.kind() == "word"
                && unit::text(&node, source).contains(['*', '?', '[']));
            if own
                || node
                    .children(&mut cursor)
                    .any(|child| varies.contains(&child.id()))
            {
                varies.insert(node.id());
            }
        } else {
            stack.push((node, true));
            stack.extend(node.children(&mut cursor).map(|child| (child, false)));
        }
    }
    varies
}

/// The strongly connected components of `graph`, as a component number for
/// each node (Kosaraju's, without recursion).
fn components(graph: &[Vec<usize>]) -> Vec<usize> {
    let count = graph.len();
    let mut seen = vec![false; count];
    let mut order = Vec::with_capacity(count);
    for start in 0..count {
        if seen.get(start).copied().unwrap_or(true) {
            continue;
        }
        if let Some(mark) = seen.get_mut(start) {
            *mark = true;
        }
        let mut stack = vec![(start, 0_usize)];
        while let Some((node, next)) = stack.last_mut() {
            let to = graph.get(*node).and_then(|out| out.get(*next)).copied();
            if let Some(to) = to {
                *next += 1;
                if let Some(mark) = seen.get_mut(to).filter(|mark| !**mark) {
                    *mark = true;
                    stack.push((to, 0));
                }
            } else {
                order.push(*node);
                stack.pop();
            }
        }
    }
    let mut reverse = vec![Vec::new(); count];
    for (from, out) in graph.iter().enumerate() {
        for &to in out {
            if let Some(into) = reverse.get_mut(to) {
                into.push(from);
            }
        }
    }
    let mut component = vec![usize::MAX; count];
    let mut next = 0;
    for &start in order.iter().rev() {
        if component.get(start).is_some_and(|&c| c != usize::MAX) {
            continue;
        }
        if let Some(c) = component.get_mut(start) {
            *c = next;
        }
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            for &from in reverse.get(node).map_or(&[][..], Vec::as_slice) {
                if let Some(c) = component.get_mut(from).filter(|c| **c == usize::MAX) {
                    *c = next;
                    stack.push(from);
                }
            }
        }
        next += 1;
    }
    component
}

#[cfg(test)]
mod tests {
    use super::components;

    #[test]
    fn components_join_the_nodes_of_a_cycle() {
        let graph = vec![vec![1], vec![0, 2], vec![], vec![3]];
        let component = components(&graph);
        assert_eq!(component.first(), component.get(1));
        assert_ne!(component.first(), component.get(2));
        assert_ne!(component.get(3), component.get(2));
        assert_eq!(component.len(), 4);
    }
}
