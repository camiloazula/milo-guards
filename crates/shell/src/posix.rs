//! Splitting a POSIX shell line (`sh`, `bash`, `zsh`) with tree-sitter-bash.

use tree_sitter::Node;

use crate::dotglob;
use crate::launch;
use crate::unit::{self, Arg, Flag, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    let text = join_continuations(text);
    let text = text.as_str();
    let language = tree_sitter_bash::LANGUAGE.into();
    let Some(tree) = unit::parse(split, text, &language) else {
        return;
    };
    for name in assigned(tree.root_node(), text) {
        split.reassign(&name);
    }
    if split.kept.on {
        environment(split, tree.root_node(), text);
    }
    Walker {
        source: text,
        depth,
        split,
    }
    .walk(tree.root_node(), None, 0);
}

/// `text` with each backslash-newline taken out, as the shell does before
/// it reads a line (`r\<newline>m` is `rm`), except inside single quotes,
/// comments and here-document bodies, where it stays. A body is copied as it
/// is, so a quote in it (`don't`) cannot leave the rest of the line looking
/// quoted.
fn join_continuations(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut joined = String::with_capacity(text.len());
    let (mut single, mut double) = (false, false);
    // Here-documents opened on the current line, read from the next one:
    // each delimiter, and whether `<<-` lets it be indented with tabs.
    let mut bodies: Vec<(String, bool)> = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        if single {
            joined.push(c);
            single = c != '\'';
            continue;
        }
        match c {
            '\\' => match chars.get(at) {
                Some('\n') => at += 1,
                Some(&next) => {
                    joined.push(c);
                    joined.push(next);
                    at += 1;
                }
                None => joined.push(c),
            },
            '\'' if !double => {
                single = true;
                joined.push(c);
            }
            '"' => {
                double = !double;
                joined.push(c);
            }
            '#' if !double
                && joined
                    .chars()
                    .last()
                    .is_none_or(|before| before.is_whitespace() || ";&|()<>".contains(before)) =>
            {
                joined.push(c);
                while let Some(&next) = chars.get(at).filter(|next| **next != '\n') {
                    joined.push(next);
                    at += 1;
                }
            }
            // `<<WORD` (not `<<<`): a here-document whose body starts on
            // the next line.
            '<' if !double
                && chars.get(at) == Some(&'<')
                && chars.get(at + 1) != Some(&'<')
                && at.checked_sub(2).and_then(|before| chars.get(before)) != Some(&'<') =>
            {
                joined.push_str("<<");
                at += 1;
                let tabs = chars.get(at) == Some(&'-');
                if tabs {
                    joined.push('-');
                    at += 1;
                }
                while let Some(&space) = chars.get(at).filter(|c| **c == ' ' || **c == '\t') {
                    joined.push(space);
                    at += 1;
                }
                let mut word = String::new();
                while let Some(&next) = chars.get(at) {
                    if next.is_whitespace() || ";&|<>()".contains(next) {
                        break;
                    }
                    joined.push(next);
                    if !matches!(next, '\'' | '"' | '\\') {
                        word.push(next);
                    }
                    at += 1;
                }
                if !word.is_empty() {
                    bodies.push((word, tabs));
                }
            }
            '\n' if !double && !bodies.is_empty() => {
                joined.push('\n');
                for (delimiter, tabs) in std::mem::take(&mut bodies) {
                    while at < chars.len() {
                        let start = at;
                        while chars.get(at).is_some_and(|c| *c != '\n') {
                            at += 1;
                        }
                        let line: String = chars[start..at].iter().collect();
                        joined.push_str(&line);
                        if at < chars.len() {
                            joined.push('\n');
                            at += 1;
                        }
                        let content = if tabs {
                            line.trim_start_matches('\t')
                        } else {
                            line.as_str()
                        };
                        if content == delimiter {
                            break;
                        }
                    }
                }
            }
            _ => joined.push(c),
        }
    }
    joined
}

/// Whether `node` is a here-document's redirect that holds the rest of its
/// pipeline: `<<EOF | nc host 1`.
fn piped_heredoc(node: Node<'_>) -> bool {
    node.kind() == "heredoc_redirect" && {
        let mut cursor = node.walk();
        let found = node
            .named_children(&mut cursor)
            .any(|part| part.kind() == "pipeline");
        found
    }
}

/// The variables the line sets anywhere: assignments (also after `export`
/// or `local`), `for` variables, `unset` and `read`.
fn assigned(root: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    unit::for_each_node(root, |node| match node.kind() {
        "variable_assignment" => names.extend(
            node.child_by_field_name("name")
                .map(|name| unit::text(&name, source).to_string()),
        ),
        "for_statement" => names.extend(
            node.child_by_field_name("variable")
                .map(|name| unit::text(&name, source).to_string()),
        ),
        "unset_command" => {
            let mut cursor = node.walk();
            names.extend(
                node.named_children(&mut cursor)
                    .map(|name| unit::text(&name, source).to_string()),
            );
        }
        "command"
            if node
                .child_by_field_name("name")
                .is_some_and(|name| unit::text(&name, source) == "read") =>
        {
            let mut cursor = node.walk();
            names.extend(
                node.children_by_field_name("argument", &mut cursor)
                    .map(|arg| unit::text(&arg, source).to_string())
                    .filter(|arg| !arg.starts_with('-')),
            );
        }
        _ => {}
    });
    names
}

/// The variables the line sets or unsets, for `effect`: assignments (also
/// in front of a command, and after `export` or `local`, quoted or not),
/// `unset`, and the variable of a `for` loop, which is kept apart.
fn environment(split: &mut Split, root: Node<'_>, source: &str) {
    unit::for_each_node(root, |node| match node.kind() {
        "variable_assignment" => {
            if let Some(name) = node.child_by_field_name("name") {
                split.set(unit::text(&name, source));
            }
        }
        // `export "PATH=."`: a quoted assignment is a string, not an
        // assignment node.
        "declaration_command" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "variable_assignment" {
                    let text = unit::text(&child, source).trim_matches(['"', '\'']);
                    if let Some((name, _)) = text.split_once('=') {
                        split.set(name);
                    }
                }
            }
        }
        "unset_command" => {
            let mut cursor = node.walk();
            for name in node.named_children(&mut cursor) {
                let name = unit::text(&name, source);
                if !name.starts_with('-') {
                    split.set(name);
                }
            }
        }
        "for_statement" => {
            if let Some(name) = node.child_by_field_name("variable") {
                split.loop_variable(unit::text(&name, source));
            }
        }
        _ => {}
    });
}

/// Whether `body` may set `name`, or define a function, which runs later: an
/// assignment, `unset`, a loop of the same name, an arithmetic assignment or
/// increment, `${name:=…}`, or a declaration that mentions it.
fn reassigns(body: Node<'_>, name: &str, source: &str) -> bool {
    let mut found = false;
    let set = format!("${{{name}");
    unit::for_each_node(body, |node| {
        let text = unit::text(&node, source);
        found |= match node.kind() {
            "function_definition" => true,
            "variable_assignment" => node
                .child_by_field_name("name")
                .is_some_and(|assigned| unit::text(&assigned, source) == name),
            "unset_command" => text.split_whitespace().any(|word| word == name),
            "for_statement" => node
                .child_by_field_name("variable")
                .is_some_and(|inner| unit::text(&inner, source) == name),
            "binary_expression" => {
                node.child_by_field_name("left")
                    .is_some_and(|left| unit::text(&left, source) == name)
                    && node.children(&mut node.walk()).any(|part| {
                        !part.is_named() && {
                            let operator = unit::text(&part, source);
                            operator.ends_with('=')
                                && !matches!(operator, "==" | "!=" | "<=" | ">=")
                        }
                    })
            }
            "postfix_expression" | "unary_expression" => {
                text.contains(name) && (text.contains("++") || text.contains("--"))
            }
            "expansion" => text
                .strip_prefix(set.as_str())
                .is_some_and(|rest| rest.starts_with(":=") || rest.starts_with('=')),
            "declaration_command" => text.contains(name),
            _ => false,
        };
    });
    found
}

/// What stands for an expansion in a template: a variable the guard cannot
/// name, so a script read from the template finds a value known only when it
/// runs where the expansion was.
pub(crate) const OPAQUE: &str = "$__v";

/// Whether `command`, a `coproc`, has a redirect in front of the command it
/// starts (`coproc { 2>/dev/null rm -rf ~; }`, `coproc > out rm -rf ~`). The
/// grammar takes the words after the redirect's target for more targets, so
/// the command is not among the arguments and cannot be read.
fn words_lost_after_redirect(command: Node<'_>) -> bool {
    let Some(parent) = command
        .parent()
        .filter(|parent| parent.kind() == "redirected_statement")
        .filter(|parent| {
            parent
                .child_by_field_name("body")
                .is_some_and(|body| body.id() == command.id())
        })
    else {
        return false;
    };
    let mut cursor = parent.walk();
    let lost = parent
        .children_by_field_name("redirect", &mut cursor)
        .any(|redirect| {
            let mut cursor = redirect.walk();
            redirect
                .children_by_field_name("destination", &mut cursor)
                .count()
                > 1
        });
    lost
}

struct Walker<'a> {
    source: &'a str,
    depth: usize,
    split: &'a mut Split,
}

impl Walker<'_> {
    fn walk(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        self.walk_in(node, stage, level, false);
    }

    /// Walk `node`; `background` says it is followed by `&`, so it runs in a
    /// subshell and a change it makes is not certain to reach the rest of the
    /// line.
    fn walk_in(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize, background: bool) {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return;
        }
        self.split.branches += usize::from(background);
        self.node(node, stage, level);
        self.split.branches -= usize::from(background);
    }

    fn node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        match node.kind() {
            // The assignments in front of a command are that command's, which
            // `command` reads; what they hold is still walked.
            "command" => self.command_node(node, stage, level),
            // `cmd < f`, `cmd > f`, `cmd <<EOF`.
            "redirected_statement" => self.redirected(node, stage, level),
            // `GLOBIGNORE=x` on a line of its own, or after `export`: the
            // shell has it from here on.
            "variable_assignment" => {
                self.assignment(node);
                self.assigned(node, level);
            }
            // The right side of `&&` and `||` may not run.
            "list" => {
                let mut cursor = node.walk();
                for (at, child) in node.named_children(&mut cursor).enumerate() {
                    self.split.branches += usize::from(at > 0);
                    self.walk(child, stage, level + 1);
                    self.split.branches -= usize::from(at > 0);
                }
            }
            // `unset GLOBIGNORE` turns bash's option off as `shopt -u` does;
            // `unset -f GLOBIGNORE` removes a function, not the variable.
            "unset_command" => {
                let mut cursor = node.walk();
                let names: Vec<&str> = node
                    .named_children(&mut cursor)
                    .map(|name| unit::text(&name, self.source))
                    .collect();
                let function = names.iter().any(|name| {
                    name.starts_with('-') && !name.starts_with("--") && name.contains('f')
                });
                if !function && names.contains(&dotglob::GLOBIGNORE) {
                    self.split.show(Flag::Bash, stage.is_none());
                }
                self.children(node, stage, level);
            }
            // `export "GLOBIGNORE=x"`, `declare 'GLOBIGNORE=x'`: a quoted
            // assignment is a string, not an assignment node.
            "declaration_command" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() != "variable_assignment" && self.arg_hides(child) {
                        self.split.hide();
                    }
                }
                self.declared(node, stage);
                self.children(node, stage, level);
            }
            // `(( GLOBIGNORE=1 ))`
            "binary_expression" => {
                let mut cursor = node.walk();
                let operator = node
                    .children(&mut cursor)
                    .find(|child| !child.is_named())
                    .map(|child| unit::text(&child, self.source));
                let assigns = operator.is_some_and(|operator| {
                    operator.ends_with('=') && !matches!(operator, "==" | "!=" | "<=" | ">=")
                });
                let left = node.child_by_field_name("left");
                if assigns
                    && left
                        .is_some_and(|left| unit::text(&left, self.source) == dotglob::GLOBIGNORE)
                {
                    self.split.hide();
                }
                self.children(node, stage, level);
            }
            // What may not run, may run more than once, or runs when the
            // line calls it. A function body or a loop may run after the
            // line has turned the option on, which the walk's end settles.
            "if_statement"
            | "case_statement"
            | "while_statement"
            | "for_statement"
            | "c_style_for_statement"
            | "function_definition" => {
                let body = !matches!(node.kind(), "if_statement" | "case_statement");
                if node.kind() == "for_statement"
                    && node
                        .child_by_field_name("variable")
                        .is_some_and(|name| unit::text(&name, self.source) == dotglob::GLOBIGNORE)
                {
                    self.split.hide();
                }
                if let Some(name) = node
                    .child_by_field_name("name")
                    .filter(|_| node.kind() == "function_definition")
                {
                    self.split.define_function(unit::text(&name, self.source));
                }
                self.split.branches += 1;
                self.split.bodies += usize::from(body);
                let start = (self.split.units.len(), self.split.reads.len());
                self.children(node, stage, level);
                if node.kind() == "for_statement" {
                    self.bind_loop(node, start);
                }
                self.split.bodies -= usize::from(body);
                self.split.branches -= 1;
            }
            "pipeline" => {
                let pipeline = self.split.pipeline(stage);
                self.pipeline_in(node, pipeline, 0, level);
            }
            "file_redirect" => {
                self.redirect(node);
                self.children(node, None, level);
            }
            // The grammar reads `$(…)` in a here-document's body but not a
            // backtick substitution, which the shell runs when the delimiter
            // is not quoted: `effect` cannot say what the line does then.
            "heredoc_redirect" => {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
                let quoted = children.iter().any(|child| {
                    child.kind() == "heredoc_start"
                        && unit::text(child, self.source).contains(['\'', '"', '\\'])
                });
                let backtick = children.iter().any(|child| {
                    child.kind() == "heredoc_body" && unit::text(child, self.source).contains('`')
                });
                if backtick && !quoted && self.split.kept.on {
                    self.split.opaque();
                }
                self.children(node, stage, level);
            }
            // `[[ 'a[$(cmd)]' -eq 0 ]]`: the shell evaluates an arithmetic
            // operand, subscript and all, so a quoted `$(…)` runs.
            "test_command" => {
                let mut hidden = false;
                unit::for_each_node(node, |inner| {
                    hidden |= inner.kind() == "raw_string" && {
                        let text = unit::text(&inner, self.source);
                        text.contains("$(") || text.contains('`')
                    };
                });
                if hidden {
                    self.split.problem(
                        Rule::Unknown,
                        "may run a command hidden in a test's arithmetic",
                        Some(unit::text(&node, self.source)),
                    );
                }
                self.children(node, stage, level);
            }
            // A subshell's `cd` does not move the rest of the line.
            "subshell" | "command_substitution" | "process_substitution" => {
                self.substituted(node);
                let outer = self.split.dir_snapshot();
                let hidden = self.split.hidden_snapshot();
                self.children(node, stage, level);
                self.split.restore_dir(outer);
                self.split.restore_hidden(hidden);
            }
            _ => self.children(node, stage, level),
        }
    }

    /// The stages of `node`, numbered from `first` in `pipeline`, and the
    /// number after the last. A child that is itself a pipeline (the grammar
    /// nests the rest of a pipeline that follows a here-document) is part of
    /// the same pipeline, its stages numbered on from the ones before it.
    fn pipeline_in(
        &mut self,
        node: Node<'_>,
        pipeline: usize,
        first: usize,
        level: usize,
    ) -> usize {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return first;
        }
        let mut next = first;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "pipeline" {
                next = self.pipeline_in(child, pipeline, next, level + 1);
            } else {
                let stage = Stage {
                    pipeline,
                    index: next,
                };
                self.walk(child, Some(stage), level + 1);
                next += 1;
            }
        }
        next
    }

    /// A `for` over words written out (no expansion in the list), whose body
    /// does not set the variable and defines no function: `effect` and the
    /// rule about reading a key read each body unit and each `<` redirect in
    /// it with every word in place of the variable.
    fn bind_loop(&mut self, node: Node<'_>, start: (usize, usize)) {
        let (Some(variable), Some(body)) = (
            node.child_by_field_name("variable"),
            node.child_by_field_name("body"),
        ) else {
            return;
        };
        let mut cursor = node.walk();
        let words: Vec<Arg> = node
            .children_by_field_name("value", &mut cursor)
            .map(|word| self.arg(word))
            .collect();
        if words.is_empty() || words.iter().any(|word| word.known().is_none()) {
            return;
        }
        let name = unit::text(&variable, self.source);
        if reassigns(body, name, self.source) {
            return;
        }
        let words = words
            .iter()
            .filter_map(Arg::known)
            .map(str::to_string)
            .collect();
        self.split.bind(name, words, start);
    }

    fn children(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let mut cursor = node.walk();
        let all: Vec<Node<'_>> = node.children(&mut cursor).collect();
        for (at, child) in all.iter().enumerate() {
            if child.is_named() {
                let background = all.get(at + 1).is_some_and(|next| next.kind() == "&");
                self.walk_in(*child, stage, level + 1, background);
            }
        }
    }

    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let program = self.arg(name);
        let mut cursor = node.walk();
        let nodes: Vec<Node<'_>> = node
            .children_by_field_name("argument", &mut cursor)
            .collect();
        let mut args = Vec::with_capacity(nodes.len());
        let mut nodes = nodes.into_iter().peekable();
        while let Some(arg) = nodes.next() {
            // `$"text"` is a locale-translated string: its `$` comes apart
            // from the string, and the word is only known when it runs.
            let translated = !arg.is_named()
                && unit::text(&arg, self.source) == "$"
                && nodes
                    .peek()
                    .is_some_and(|next| next.start_byte() == arg.end_byte());
            if let (true, Some(string)) = (translated, nodes.peek().copied()) {
                nodes.next();
                let word = self
                    .source
                    .get(arg.start_byte()..string.end_byte())
                    .unwrap_or_default();
                args.push(Arg::Unknown(word.to_string()));
            } else {
                args.push(self.arg(arg));
            }
        }
        // `read GLOBIGNORE`, `printf -v GLOBIGNORE`, `printf -vGLOBIGNORE`,
        // `let GLOBIGNORE=1`: set by a command whose value the line does not
        // show or reads as an assignment.
        let names = |at: usize| args.get(at).and_then(Arg::known) == Some(dotglob::GLOBIGNORE);
        let sets = match program.known() {
            Some("read" | "mapfile" | "readarray") => (0..args.len()).any(names),
            Some("printf") => {
                args.iter().any(|arg| {
                    arg.known().and_then(|word| word.strip_prefix("-v"))
                        == Some(dotglob::GLOBIGNORE)
                }) || args
                    .iter()
                    .enumerate()
                    .any(|(at, arg)| arg.known() == Some("-v") && names(at + 1))
            }
            Some("let") => args.iter().any(dotglob::assigns_hiding),
            _ => false,
        };
        if sets {
            self.split.hide();
        }
        // `GLOBIGNORE=x bash -c '…'`: the shell it starts has the option.
        let mut cursor = node.walk();
        let prefixed = node
            .children(&mut cursor)
            .filter(|child| child.kind() == "variable_assignment")
            .any(|assignment| self.sets_hiding(assignment));
        // In front of a call to a function the line defines, it is set while
        // the body runs.
        if prefixed
            && program
                .known()
                .is_some_and(|name| self.split.defines_function(name))
        {
            self.split.hide_functions();
        }
        if program.known() == Some("coproc") && words_lost_after_redirect(node) {
            self.split.problem(
                Rule::Unreadable,
                "starts a command after a redirect that cannot be read",
                Some(unit::text(&node, self.source)),
            );
        }
        let outer = self.split.scope_hidden(prefixed);
        launch::add(
            self.split,
            Unit::new(Shell::Posix, program, args, stage),
            self.depth,
        );
        self.split.unscope_hidden(outer);
    }

    /// Whether `assignment` gives a variable a value that turns the option
    /// on: `GLOBIGNORE` not empty, `BASHOPTS` with `dotglob`.
    fn sets_hiding(&self, assignment: Node<'_>) -> bool {
        assignment.child_by_field_name("name").is_some_and(|name| {
            dotglob::hides(
                unit::text(&name, self.source),
                assignment
                    .child_by_field_name("value")
                    .map(|value| self.arg(value))
                    .as_ref(),
            )
        })
    }

    /// Whether `node`, an argument of `export` or `declare`, is a quoted
    /// assignment that turns the option on.
    fn arg_hides(&self, node: Node<'_>) -> bool {
        dotglob::assigns_hiding(&self.arg(node))
    }

    fn assignment(&mut self, node: Node<'_>) {
        if self.sets_hiding(node) {
            self.split.hide();
        }
    }

    /// A command and what it holds. What its substitutions run is handed to
    /// it, and a redirect in front of it (`< f cat`) feeds it.
    fn command_node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let first = self.split.units.len();
        self.command(node, stage);
        let own = first..self.split.units.len();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_assignment" {
                self.children(child, None, level + 1);
            } else {
                self.walk(child, None, level + 1);
            }
        }
        self.split
            .nest(own.clone(), own.end..self.split.units.len());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some((target, input)) = self.file_redirect(child) {
                self.split.redirect(own.clone(), target, input);
            } else if let Some(text) = self.fed_text(child) {
                self.split.feed(own.clone(), text);
            }
        }
    }

    /// A statement with redirects: they belong to its body, whose input and
    /// output they are, and what runs in a here-document is handed to it.
    fn redirected(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let body = node.child_by_field_name("body").map(|body| body.id());
        let mut cursor = node.walk();
        let all: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // In `cat <<EOF | nc host 1` the grammar holds the rest of the
        // pipeline in the here-document's redirect: the body is its first
        // stage. It starts its own pipeline whatever stage the statement is
        // in, as a `pipeline` node does inside a group that is a stage.
        let pipeline = all
            .iter()
            .any(|child| piped_heredoc(*child))
            .then(|| self.split.pipeline(stage));
        let mut own = 0..0;
        let mut after = Vec::new();
        // The stages the body takes in that pipeline: the here-document's
        // own come after them.
        let mut next = 1;
        for child in &all {
            let first = self.split.units.len();
            if Some(child.id()) == body {
                match pipeline {
                    // `echo hi | cat .env <<EOF | nc host 1`: the body is
                    // itself a pipeline, whose stages come first.
                    Some(pipeline) if child.kind() == "pipeline" => {
                        next = self.pipeline_in(*child, pipeline, 0, level + 1);
                    }
                    Some(pipeline) => {
                        self.walk(*child, Some(Stage { pipeline, index: 0 }), level + 1);
                    }
                    None => self.walk(*child, stage, level + 1),
                }
                own = first..self.split.units.len();
            } else if let (Some(pipeline), true) = (pipeline, piped_heredoc(*child)) {
                // What the redirect's own parts run is handed to the body,
                // and what the rest of the pipeline runs is not.
                let mut inside = Vec::new();
                let mut cursor = child.walk();
                for part in child.named_children(&mut cursor) {
                    let first = self.split.units.len();
                    if part.kind() == "pipeline" {
                        self.pipeline_in(part, pipeline, next, level + 1);
                    } else {
                        self.walk(part, None, level + 1);
                        inside.push(first..self.split.units.len());
                    }
                }
                after.push((*child, inside));
            } else {
                self.walk(*child, stage, level + 1);
                let whole = first..self.split.units.len();
                after.push((*child, std::iter::once(whole).collect()));
            }
        }
        for (child, inside) in after {
            if let Some((target, input)) = self.file_redirect(child) {
                self.split.redirect(own.clone(), target, input);
            } else if let Some(text) = self.fed_text(child) {
                self.split.feed(own.clone(), text);
            }
            for inside in inside {
                self.split.nest(own.clone(), inside);
            }
        }
    }

    /// `name=value`: what runs in the value is what the variable holds.
    fn assigned(&mut self, node: Node<'_>, level: usize) {
        let first = self.split.units.len();
        self.children(node, None, level);
        if let Some(name) = node.child_by_field_name("name") {
            let name = unit::text(&name, self.source);
            let name = name.split('[').next().unwrap_or(name);
            let value = node
                .child_by_field_name("value")
                .map(|value| unit::text(&value, self.source))
                .unwrap_or_default();
            self.split
                .assign(name, first..self.split.units.len(), value);
        }
    }

    /// `export -p` and `declare -x` print the environment: they are programs
    /// the line runs like any other.
    fn declared(&mut self, node: Node<'_>, stage: Option<Stage>) {
        let Some(keyword) = node.child(0).filter(|keyword| !keyword.is_named()) else {
            return;
        };
        let mut cursor = node.walk();
        let args = node
            .named_children(&mut cursor)
            .map(|child| match child.kind() {
                "variable_assignment" => Arg::Unknown(unit::text(&child, self.source).to_string()),
                _ => self.arg(child),
            })
            .collect();
        let program = Arg::Known(unit::text(&keyword, self.source).to_string());
        self.split
            .push(Unit::new(Shell::Posix, program, args, stage));
    }

    /// `$(<file)` prints the file, as `cat file` does.
    fn substituted(&mut self, node: Node<'_>) {
        if node.kind() != "command_substitution" {
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some((target, true)) = self.file_redirect(child) {
                let cat = Arg::Known("cat".to_string());
                self.split
                    .push(Unit::new(Shell::Posix, cat, vec![target], None));
            }
        }
    }

    /// The file a redirect names, and whether it feeds input (`<`) rather
    /// than taking output; `None` for any other node, or a descriptor.
    fn file_redirect(&self, node: Node<'_>) -> Option<(Arg, bool)> {
        if node.kind() != "file_redirect" {
            return None;
        }
        let mut cursor = node.walk();
        let operator = node
            .children(&mut cursor)
            .find(|child| !child.is_named())
            .map(|child| unit::text(&child, self.source));
        if operator == Some("<&") {
            return None;
        }
        let destination = node.child_by_field_name("destination")?;
        Some((self.arg(destination), matches!(operator, Some("<" | "<>"))))
    }

    /// The text a here-string or an unquoted here-document feeds when it
    /// holds an expansion, as the source writes it: `<<< "$k"`, `<<EOF` with
    /// `$k` in its body. What a substitution in it runs is a unit of its own.
    fn fed_text(&self, node: Node<'_>) -> Option<Arg> {
        let mut cursor = node.walk();
        let text = match node.kind() {
            "herestring_redirect" => {
                let arg = self.arg(node.named_children(&mut cursor).next()?);
                return arg.is_unknown().then_some(arg);
            }
            "heredoc_redirect" => {
                let body = node
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "heredoc_body")?;
                let mut cursor = body.walk();
                body.named_children(&mut cursor)
                    .filter(|part| matches!(part.kind(), "simple_expansion" | "expansion"))
                    .map(|part| unit::text(&part, self.source))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            _ => return None,
        };
        (!text.is_empty()).then_some(Arg::Unknown(text))
    }

    /// A redirect that writes: `>`, `>>`, `&>`, `>|`, `<>`, and `>&` to a
    /// file rather than a descriptor.
    fn redirect(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let operator = node
            .children(&mut cursor)
            .find(|child| !child.is_named())
            .map(|child| unit::text(&child, self.source));
        let Some(destination) = node.child_by_field_name("destination") else {
            return;
        };
        let target = self.arg(destination);
        // `effect` judges where a read comes from: bash opens
        // `/dev/tcp/HOST/PORT` itself, so a read from it is a connection.
        if operator == Some("<") {
            self.split.read(Shell::Posix, target.clone());
        }
        let writes = match operator {
            Some(">" | ">>" | "&>" | "&>>" | ">|" | "<>") => true,
            Some(">&" | "&>&") => !target
                .known()
                .is_some_and(|text| text == "-" || text.chars().all(|c| c.is_ascii_digit())),
            _ => false,
        };
        if writes {
            self.split.write(Shell::Posix, target);
        }
    }

    /// An argument's value, where its spelling gives it.
    fn arg(&self, node: Node<'_>) -> Arg {
        let source = unit::text(&node, self.source);
        match node.kind() {
            "word" | "number" => {
                let value = unescape(source);
                // `~` is `$HOME`: once the line sets `HOME`, it is unknown.
                if value.starts_with('~') && self.split.reassigned("HOME") {
                    Arg::Unknown(source.to_string())
                } else {
                    Arg::Known(value)
                }
            }
            "raw_string" => Arg::Known(
                source
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
                    .unwrap_or(source)
                    .to_string(),
            ),
            "string" => self.string(node),
            // `'rm -rf '"$d"`: known text and expansions side by side. A
            // value only when every part is; otherwise a template, which a
            // script can still be read from.
            "concatenation" => {
                let mut value = String::new();
                let mut template = String::new();
                let mut partial = false;
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match self.arg(part) {
                        Arg::Known(text) => {
                            value.push_str(&text);
                            template.push_str(&text);
                        }
                        Arg::Template { text, .. } => {
                            partial = true;
                            template.push_str(&text);
                        }
                        Arg::Unknown(_) | Arg::Input | Arg::Null
                            if matches!(
                                part.kind(),
                                "simple_expansion" | "expansion" | "command_substitution"
                            ) =>
                        {
                            partial = true;
                            template.push_str(OPAQUE);
                        }
                        Arg::Unknown(_) | Arg::Input | Arg::Null => {
                            return Arg::Unknown(source.to_string())
                        }
                    }
                }
                if partial {
                    Arg::Template {
                        text: template,
                        source: source.to_string(),
                    }
                } else {
                    Arg::Known(value)
                }
            }
            "simple_expansion" | "expansion" => self.variable(source),
            "command_name" => match node.named_child(0) {
                Some(child) => self.arg(child),
                None => Arg::Unknown(source.to_string()),
            },
            _ => Arg::Unknown(source.to_string()),
        }
    }

    /// A double-quoted string: its text with the variables the guard can name
    /// put in. Anything else expanded inside makes it a template: the text
    /// with each such expansion replaced by an opaque variable, which is not
    /// a value but can be read as a script. The expansion's own source is not
    /// kept: a `$(…)` in it is read where it stands, and reading it again in
    /// the script would double the work at each level of nesting.
    fn string(&self, node: Node<'_>) -> Arg {
        let source = unit::text(&node, self.source);
        let start = node.start_byte() + 1;
        let end = node.end_byte().saturating_sub(1).max(start);
        let mut value = String::new();
        let mut template = String::new();
        let mut partial = false;
        let mut at = start;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let gap = unescape_quoted(self.source.get(at..child.start_byte()).unwrap_or_default());
            value.push_str(&gap);
            template.push_str(&gap);
            let written = unit::text(&child, self.source);
            match child.kind() {
                "string_content" => {
                    let text = unescape_quoted(written);
                    value.push_str(&text);
                    template.push_str(&text);
                }
                "simple_expansion" | "expansion" => match self.variable(written) {
                    Arg::Known(text) => {
                        value.push_str(&text);
                        template.push_str(&text);
                    }
                    Arg::Unknown(_) | Arg::Template { .. } | Arg::Input | Arg::Null => {
                        partial = true;
                        template.push_str(OPAQUE);
                    }
                },
                _ => {
                    partial = true;
                    template.push_str(OPAQUE);
                }
            }
            at = child.end_byte();
        }
        let rest = unescape_quoted(self.source.get(at..end).unwrap_or_default());
        value.push_str(&rest);
        template.push_str(&rest);
        if partial {
            Arg::Template {
                text: template,
                source: source.to_string(),
            }
        } else {
            Arg::Known(value)
        }
    }

    /// `$HOME`, `${HOME}`, `$PWD` and `$TMPDIR` as paths the resolver reads,
    /// unless the line sets them; any other variable is only known when it
    /// runs.
    fn variable(&self, source: &str) -> Arg {
        let name = source
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
            .or_else(|| source.strip_prefix('$'))
            .filter(|name| !self.split.reassigned(name));
        match name {
            Some("HOME") => Arg::Known("~".to_string()),
            Some("PWD") => Arg::Known(".".to_string()),
            Some("TMPDIR") => Arg::Known("/tmp".to_string()),
            _ => Arg::Unknown(source.to_string()),
        }
    }
}

/// A bare word as the program receives it: a backslash keeps the next
/// character (`\rm` is `rm`).
fn unescape(word: &str) -> String {
    let mut value = String::with_capacity(word.len());
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                value.push(next);
            }
        } else {
            value.push(c);
        }
    }
    value
}

/// Text inside double quotes: a backslash only escapes `"`, `\`, `$` and
/// `` ` ``.
fn unescape_quoted(text: &str) -> String {
    let mut value = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && chars
                .peek()
                .is_some_and(|next| matches!(next, '"' | '\\' | '$' | '`'))
        {
            if let Some(next) = chars.next() {
                value.push(next);
            }
        } else {
            value.push(c);
        }
    }
    value
}
