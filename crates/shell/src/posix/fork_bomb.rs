//! Fork bombs: the functions a line defines that start copies of themselves
//! without end, alone (`:(){ :|:& };:`) or through each other (`f() { g & };
//! g() { f & }`).
//!
//! Each function's body is read for the calls it makes to the functions the
//! line defines, and where each call stands: whether it starts a process of
//! its own, whether it runs only on a condition that reads a value known when
//! it runs, and whether it runs more than once. The functions that call each
//! other in a cycle are judged together: they start copies without end when
//! one of their calls starts a process and they start two or more copies
//! each time round, or one copy with no such condition on the way.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::Walker;
use crate::launch::{self, Launch};
use crate::unit;
use crate::Rule;

/// Where a call stands in a function's body.
#[derive(Clone, Copy, Default)]
struct Scope {
    /// It starts a process of its own: in the background, as a stage of a
    /// pipeline, in a subshell or a substitution, or through `coproc`.
    forks: bool,
    /// It runs only when a condition that reads a value known when it runs
    /// holds (`[ -d "$d" ] && …`, `case $1 in …`), or once for each name of
    /// one word known when it runs (`for d in "$1"/*`): a recursion through it
    /// may end with those values.
    guarded: bool,
    /// It may run more than once each time the function runs: in a loop over
    /// two or more words or a brace list, or in a loop whose condition reads
    /// no such value (`while true`, `for ((;;))`).
    many: bool,
}

/// A call from one function the line defines to another, or to itself.
struct Call {
    from: usize,
    to: usize,
    scope: Scope,
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
            self.calls_in(*body, from, &index, &varies, &mut calls);
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
                *forks |= call.scope.forks;
            }
            if let Some(guarded) = guarded.get_mut(from) {
                *guarded |= call.scope.guarded;
            }
            if let Some(copies) = copies.get_mut(call.from) {
                *copies += if call.scope.many { 2 } else { 1 };
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

    /// The calls `body`, the body of the function `from`, makes to the
    /// functions in `index`. A function defined inside is read on its own,
    /// so its commands are not read again here: each node is read once, and
    /// each carries down where it stands, so the scan never climbs back up.
    fn calls_in(
        &self,
        body: Node<'_>,
        from: usize,
        index: &HashMap<&str, usize>,
        varies: &HashSet<usize>,
        calls: &mut Vec<Call>,
    ) {
        let mut stack = vec![(body, Scope::default())];
        let mut cursor = body.walk();
        while let Some((node, scope)) = stack.pop() {
            if node.kind() == "command" {
                if let Some(to) = self.called(node, index) {
                    let forks = scope.forks || to.1;
                    calls.push(Call {
                        from,
                        to: to.0,
                        scope: Scope { forks, ..scope },
                    });
                }
            }
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            let inner = Inner::of(node, &children, varies, self.source);
            for (at, child) in children.iter().enumerate() {
                if !child.is_named() || child.kind() == "function_definition" {
                    continue;
                }
                let mut scope = inner.scope(scope, node, *child);
                scope.forks |= children.get(at + 1).is_some_and(|next| next.kind() == "&");
                stack.push((*child, scope));
            }
        }
    }

    /// The function `command` calls, by its index, and whether the call
    /// starts a process of its own: the command's name (`f`, `\f`, `"f"`),
    /// the name `eval` is given first (`eval f`), or the command `coproc`
    /// starts (`coproc f`, `coproc { f; }`).
    fn called(&self, command: Node<'_>, index: &HashMap<&str, usize>) -> Option<(usize, bool)> {
        let name = command.child_by_field_name("name")?;
        let name = self.arg(name);
        let name = name.known()?;
        if let Some(&to) = index.get(name) {
            return Some((to, false));
        }
        let mut cursor = command.walk();
        let args: Vec<unit::Arg> = command
            .children_by_field_name("argument", &mut cursor)
            .map(|arg| self.arg(arg))
            .collect();
        match name {
            "eval" => {
                let first = args.first()?.known()?.split_whitespace().next()?;
                index.get(first).map(|&to| (to, false))
            }
            "coproc" => {
                let Launch::Runs(at) = launch::coproc(&args) else {
                    return None;
                };
                let program = args.get(at)?.known()?;
                index.get(program).map(|&to| (to, true))
            }
            _ => None,
        }
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
}

impl Inner {
    fn of(node: Node<'_>, children: &[Node<'_>], varies: &HashSet<usize>, source: &str) -> Self {
        let mut cursor = node.walk();
        let reads = |nodes: &[Node<'_>]| nodes.iter().any(|node| varies.contains(&node.id()));
        let mut inner = Self {
            condition: HashSet::new(),
            varies: false,
            many: false,
        };
        match node.kind() {
            "if_statement" | "while_statement" => {
                let condition: Vec<Node<'_>> = node
                    .children_by_field_name("condition", &mut cursor)
                    .collect();
                inner.varies = reads(&condition);
                // A loop runs its condition again each time round too.
                if node.kind() == "while_statement" {
                    inner.many = !inner.varies;
                } else {
                    inner.condition = condition.iter().map(Node::id).collect();
                }
            }
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
            // `for x; do` runs once for each argument; `for x in a b` once
            // for each word, so more than once for two or more words or a
            // brace list, which may stand for many.
            "for_statement" => {
                let values: Vec<Node<'_>> =
                    node.children_by_field_name("value", &mut cursor).collect();
                inner.many = values.len() >= 2
                    || values.iter().any(|value| {
                        value.kind() == "brace_expression"
                            || unit::text(value, source).contains('{')
                    });
                inner.varies = !inner.many && (values.is_empty() || reads(&values));
                inner.condition = values.iter().map(Node::id).collect();
            }
            "c_style_for_statement" => inner.many = true,
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
    fn scope(&self, outer: Scope, node: Node<'_>, child: Node<'_>) -> Scope {
        let mut scope = outer;
        match node.kind() {
            // Each stage of a pipeline of two or more runs as a process.
            "pipeline" => scope.forks |= node.named_child_count() > 1,
            "subshell" | "command_substitution" | "process_substitution" => scope.forks = true,
            "list" | "if_statement" | "elif_clause" | "case_statement" | "for_statement" => {
                if !self.condition.contains(&child.id()) {
                    scope.guarded |= self.varies;
                    scope.many |= self.many;
                }
            }
            "while_statement" | "c_style_for_statement" => {
                scope.guarded |= self.varies;
                scope.many |= self.many;
            }
            _ => {}
        }
        scope
    }
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
