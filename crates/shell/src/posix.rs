//! Splitting a POSIX shell line (`sh`, `bash`, `zsh`) with tree-sitter-bash.

use tree_sitter::{Node, TreeCursor};

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

/// What stands for an expansion in a template: a variable the guard cannot
/// name, so a script read from the template finds a value known only when it
/// runs where the expansion was.
pub(crate) const OPAQUE: &str = "$__v";

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
            "command" => {
                self.command(node, stage);
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "variable_assignment" {
                        self.children(child, None, level + 1);
                    } else {
                        self.walk(child, None, level + 1);
                    }
                }
            }
            // `GLOBIGNORE=x` on a line of its own, or after `export`: the
            // shell has it from here on.
            "variable_assignment" => {
                self.assignment(node);
                self.children(node, None, level);
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
                    let name = unit::text(&name, self.source);
                    self.split.define_function(name);
                    self.fork_bomb(node, name);
                }
                self.split.branches += 1;
                self.split.bodies += usize::from(body);
                self.children(node, stage, level);
                self.split.bodies -= usize::from(body);
                self.split.branches -= 1;
            }
            "pipeline" => {
                let pipeline = self.split.pipeline();
                let mut cursor = node.walk();
                for (index, child) in node.named_children(&mut cursor).enumerate() {
                    self.walk(child, Some(Stage { pipeline, index }), level + 1);
                }
            }
            "file_redirect" => {
                self.redirect(node);
                self.children(node, None, level);
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
                let outer = self.split.dir_snapshot();
                let hidden = self.split.hidden_snapshot();
                self.children(node, stage, level);
                self.split.restore_dir(outer);
                self.split.restore_hidden(hidden);
            }
            _ => self.children(node, stage, level),
        }
    }

    /// A function that starts itself in the background, or as one side of a
    /// pipeline, starts copies of itself without end: `:(){ :|:& };:`.
    fn fork_bomb(&mut self, function: Node<'_>, name: &str) {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        // A function defined inside is judged when the walk reaches it, so
        // its commands are not read again here: each node is read once. Each
        // level of the walk says whether what it holds runs apart, so the
        // scan never climbs back up: it is linear in the nodes.
        let mut cursor = body.walk();
        let mut stack = vec![Level::of(body, false, &mut cursor)];
        let mut bomb = false;
        while let Some(level) = stack.last_mut() {
            let Some(&inner) = level.children.get(level.at) else {
                stack.pop();
                continue;
            };
            let apart = level.apart
                || level.staged
                || level
                    .children
                    .get(level.at + 1)
                    .is_some_and(|next| next.kind() == "&");
            level.at += 1;
            if inner.kind() == "function_definition" {
                continue;
            }
            if apart
                && inner.kind() == "command"
                && inner
                    .child_by_field_name("name")
                    .is_some_and(|called| self.arg(called).known() == Some(name))
            {
                bomb = true;
                break;
            }
            stack.push(Level::of(inner, apart, &mut cursor));
        }
        if bomb {
            self.split.problem(
                Rule::StopSystem,
                "starts copies of itself without end",
                Some(name),
            );
        }
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
                        Arg::Unknown(_) | Arg::Input
                            if matches!(
                                part.kind(),
                                "simple_expansion" | "expansion" | "command_substitution"
                            ) =>
                        {
                            partial = true;
                            template.push_str(OPAQUE);
                        }
                        Arg::Unknown(_) | Arg::Input => return Arg::Unknown(source.to_string()),
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
                    Arg::Unknown(_) | Arg::Template { .. } | Arg::Input => {
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

/// One node of the fork-bomb scan, with its children still to read.
struct Level<'t> {
    children: Vec<Node<'t>>,
    /// The next child to read.
    at: usize,
    /// Whether the node, or one it is inside (up to the function's body), is
    /// followed by `&` or is a stage of a pipeline: what it holds runs as a
    /// process of its own.
    apart: bool,
    /// Whether the children are the stages of a pipeline of more than one.
    staged: bool,
}

impl<'t> Level<'t> {
    fn of(node: Node<'t>, apart: bool, cursor: &mut TreeCursor<'t>) -> Self {
        Self {
            children: node.children(cursor).collect(),
            at: 0,
            apart,
            staged: node.kind() == "pipeline" && node.named_child_count() > 1,
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
