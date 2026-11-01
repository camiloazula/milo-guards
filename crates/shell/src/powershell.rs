//! Splitting a PowerShell line with tree-sitter-powershell, PowerShell's
//! aliases, and how a cmdlet's parameters are read.

use std::borrow::Cow;

use tree_sitter::Node;

use crate::launch;
use crate::unit::{self, Arg, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    let language = tree_sitter_powershell::LANGUAGE.into();
    let Some(first) = unit::parse(split, text, &language) else {
        return;
    };
    // A line the grammar cannot read stays unreadable, whatever else is found
    // in it. When it holds a word that is a variable and a path
    // (`$HOME\.ssh\id_rsa`), which the grammar fails on, it is also read again
    // with those words quoted, so the rules see the paths.
    let fixed;
    let (text, tree) = if first.root_node().has_error() {
        if let Cow::Owned(rewritten) = variable_paths(text) {
            fixed = rewritten;
            let Some(again) = unit::parse(split, &fixed, &language) else {
                return;
            };
            (fixed.as_str(), again)
        } else {
            (text, first)
        }
    } else {
        (text, first)
    };
    // `$env:TEMP = $HOME`: a variable the line sets no longer names its
    // usual place.
    let mut names = Vec::new();
    unit::for_each_node(tree.root_node(), |node| {
        if node.kind() == "assignment_expression" {
            if let Some(left) = node.named_child(0) {
                let left = unit::text(&left, text).trim();
                let name = left
                    .strip_prefix("${")
                    .and_then(|rest| rest.strip_suffix('}'))
                    .or_else(|| left.strip_prefix('$'))
                    .unwrap_or(left);
                names.push(name.to_string());
            }
        }
    });
    for name in names {
        split.reassign(&name);
        split.set(&name);
    }
    // `foreach ($c in …)`: the variable holds one item of what it walks.
    unit::for_each_node(tree.root_node(), |node| {
        if node.kind() == "foreach_statement" {
            let mut cursor = node.walk();
            let variable = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "variable");
            if let Some(variable) = variable {
                let name = unit::text(&variable, text).trim();
                let name = name
                    .strip_prefix("${")
                    .and_then(|rest| rest.strip_suffix('}'))
                    .or_else(|| name.strip_prefix('$'))
                    .unwrap_or(name);
                split.loop_variable(name);
            }
        }
    });
    Walker {
        source: text,
        depth,
        split,
        item: None,
    }
    .walk(tree.root_node(), None, 0);
}

/// The cmdlets that register a script block to run when an event happens:
/// the block is read where it is written, and runs later.
const EVENTS: [&str; 4] = [
    "register-engineevent",
    "register-objectevent",
    "register-wmievent",
    "register-cimindicationevent",
];

/// Whether `node` is a script block written out, however it is wrapped by
/// the grammar (`{ … }` is an array of one unary expression of the block).
fn is_script_block(node: Node<'_>) -> bool {
    let mut node = node;
    loop {
        match node.kind() {
            "script_block_expression" => return true,
            "array_literal_expression" | "unary_expression" if node.named_child_count() == 1 => {
                match node.named_child(0) {
                    Some(only) => node = only,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}

/// Whether `node` is a splat (`@args`), however the grammar wraps it.
fn is_splat(node: Node<'_>, source: &str) -> bool {
    let mut node = node;
    loop {
        match node.kind() {
            "variable" => return unit::text(&node, source).starts_with('@'),
            "array_literal_expression" | "unary_expression" if node.named_child_count() == 1 => {
                match node.named_child(0) {
                    Some(only) => node = only,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}

/// The cmdlet an alias stands for, in lower case; any other name as given.
pub(crate) fn canonical(name: &str) -> &str {
    match name {
        "rm" | "ri" | "del" | "erase" | "rd" | "rmdir" => "remove-item",
        "cp" | "copy" | "cpi" => "copy-item",
        "mv" | "move" | "mi" => "move-item",
        "sc" => "set-content",
        "ni" => "new-item",
        "ren" | "rni" => "rename-item",
        "sp" => "set-itemproperty",
        "rp" => "remove-itemproperty",
        "ac" => "add-content",
        "clc" => "clear-content",
        "gci" | "ls" | "dir" => "get-childitem",
        "gi" => "get-item",
        "iwr" | "curl" | "wget" => "invoke-webrequest",
        "irm" => "invoke-restmethod",
        "iex" => "invoke-expression",
        "icm" => "invoke-command",
        "start" | "saps" => "start-process",
        "kill" | "spps" => "stop-process",
        "%" | "foreach" => "foreach-object",
        "tee" => "tee-object",
        "cd" | "sl" | "chdir" => "set-location",
        "pushd" => "push-location",
        "popd" => "pop-location",
        "?" | "where" => "where-object",
        name => name,
    }
}

/// What `$null` is as a word: the device. In a longer word it is nothing.
const NULL: &str = "$null";

struct Walker<'a> {
    source: &'a str,
    depth: usize,
    split: &'a mut Split,
    /// Inside a `ForEach-Object` block: the stage whose input `$_` is.
    item: Option<Stage>,
}

impl Walker<'_> {
    fn walk(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return;
        }
        match node.kind() {
            "pipeline_chain" => {
                let pipeline = self.split.pipeline(stage.or(self.item));
                let mut cursor = node.walk();
                let stages: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                for (index, child) in stages.iter().enumerate() {
                    // A value that is piped on (`'DROP TABLE t' | psql`) is
                    // a stage that says it, as `Write-Output` would.
                    if child.kind() == "logical_expression" && index + 1 < stages.len() {
                        self.value_stage(*child, Stage { pipeline, index });
                    }
                    // The first command in a `ForEach-Object` block reads
                    // `$_` from the stage the block is.
                    let stage = match (index, self.item) {
                        (0, Some(item)) => item,
                        _ => Stage { pipeline, index },
                    };
                    self.walk(*child, Some(stage), level + 1);
                }
            }
            "command" => {
                let first = self.split.units.len();
                let key = self.command(node, stage);
                let own = first..self.split.units.len();
                let outer = self.item;
                // The block of `ForEach-Object` and `Where-Object` runs once
                // for each item of its input.
                let each = matches!(key.as_deref(), Some("foreach-object" | "where-object"));
                if each {
                    self.item = stage;
                    self.split.repeats += 1;
                }
                // The block of an event runs later, in this session.
                let later = key
                    .as_deref()
                    .is_some_and(|key| EVENTS.contains(&key))
                    .then(|| self.split.begin_later());
                self.children(node, None, level);
                if let Some(began) = later {
                    self.split.end_later(began, false);
                }
                self.item = outer;
                if each {
                    self.split.repeats -= 1;
                }
                // What a sub-expression in its arguments runs is handed to it.
                self.split
                    .nest(own.clone(), own.end..self.split.units.len());
            }
            // `trap { … }`: its block runs on a terminating error, later.
            "trap_statement" => {
                let began = self.split.begin_later();
                self.children(node, stage, level);
                self.split.end_later(began, false);
            }
            // A loop, or a function that is called more than once, runs
            // what it holds again with other values.
            "foreach_statement" | "for_statement" | "while_statement" | "do_statement"
            | "function_statement" => {
                self.split.repeats += 1;
                self.children(node, stage, level);
                self.split.repeats -= 1;
            }
            "redirection" => {
                self.redirect(node);
                self.children(node, None, level);
            }
            "invokation_expression" => {
                // A method call is no unit, and the rules know only some of
                // them: `effect` cannot say what it does.
                self.split.opaque();
                self.dotnet(node);
                self.children(node, stage, level);
            }
            _ => self.children(node, stage, level),
        }
    }

    /// A stage that is an expression and not a command: it says its value
    /// to the next stage, as `Write-Output value` does. A string says its
    /// text; a variable or anything computed says what is only known when it
    /// runs.
    fn value_stage(&mut self, node: Node<'_>, stage: Stage) {
        let mut node = node;
        // The chain of expressions a value is wrapped in, one child each.
        while matches!(
            node.kind(),
            "logical_expression"
                | "bitwise_expression"
                | "comparison_expression"
                | "additive_expression"
                | "multiplicative_expression"
                | "format_expression"
                | "range_expression"
        ) {
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor);
            match (children.next(), children.next()) {
                (Some(only), None) => node = only,
                _ => break,
            }
        }
        let value = self.expr(node);
        let program = Arg::Known("Write-Output".to_string());
        self.split.push(Unit::new(
            Shell::PowerShell,
            program,
            vec![value],
            Some(stage),
        ));
    }

    fn children(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk(child, stage, level + 1);
        }
    }

    /// The unit `node` runs; its key, for the walk to know a
    /// `ForEach-Object` block.
    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) -> Option<String> {
        let name = node.child_by_field_name("command_name")?;
        let program = self.name(name);
        let mut args = Vec::new();
        if let Some(elements) = node.child_by_field_name("command_elements") {
            let mut cursor = elements.walk();
            for element in elements.named_children(&mut cursor) {
                // `--%` passes the rest verbatim, but only up to a `|`: the
                // grammar runs it to the end of the line, so what follows the
                // pipe is read again as the next command.
                let source = unit::text(&element, self.source);
                if source.starts_with("--%") {
                    if let Some((_, rest)) = source.split_once('|') {
                        unit::script(self.split, rest, Shell::PowerShell, self.depth + 1);
                    }
                    continue;
                }
                match element.kind() {
                    "command_argument_sep" => {
                        if unit::text(&element, self.source).contains(':') {
                            if let Some(Arg::Known(param)) = args.last_mut() {
                                if param.starts_with('-') && !param.ends_with(':') {
                                    param.push(':');
                                }
                            }
                        }
                    }
                    "redirection" | "comment" => {}
                    "array_literal_expression" => {
                        let mut items = element.walk();
                        for item in element.named_children(&mut items) {
                            args.push(self.expr(item));
                        }
                    }
                    _ => args.push(self.expr(element)),
                }
            }
        }
        // Inside a `ForEach-Object` block, a command takes its place in the
        // pipeline the block is a stage of.
        let stage = stage.or(self.item);
        let unit = Unit::new(Shell::PowerShell, program, args, stage);
        let key = unit.key();
        // A block known only when it runs (`-Action $block`, an action given
        // by position or in a splat) is a script the guard cannot read, run
        // by the event.
        if let Some(key) = key.as_deref().filter(|key| EVENTS.contains(key)) {
            if self.action_unread(node, key) {
                self.split.problem(
                    Rule::Unknown,
                    "runs an event action only known when it runs",
                    Some(unit::text(&node, self.source)),
                );
            }
        }
        launch::add(self.split, unit, self.depth);
        key
    }

    /// Whether the action of a `Register-*Event` command is not a script
    /// block written out, which the walk reads where it stands. The action is
    /// the `-Action` parameter or, by position, the last of the parameters
    /// the command's names leave to be given by position (the docs' order:
    /// `Register-EngineEvent` takes its source then its action;
    /// `Register-ObjectEvent` the object, its event, the source, then the
    /// action; the others a class or query, the source, then the action). A
    /// splat (`@p`) may hold any of them.
    fn action_unread(&self, node: Node<'_>, key: &str) -> bool {
        let Some(elements) = node.child_by_field_name("command_elements") else {
            return false;
        };
        let slots: &[&[&str]] = match key {
            "register-engineevent" => &[&["sourceidentifier"], &["action"]],
            "register-objectevent" => &[
                &["inputobject"],
                &["eventname"],
                &["sourceidentifier"],
                &["action"],
            ],
            "register-wmievent" => &[&["class", "query"], &["sourceidentifier"], &["action"]],
            _ => &[&["classname", "query"], &["sourceidentifier"], &["action"]],
        };
        let mut bound = vec![false; slots.len()];
        // Parameters that take a value but are not given by position.
        let named = [
            "messagedata",
            "maxtriggercount",
            "namespace",
            "computername",
            "credential",
            "timeout",
            "operationtimeoutsec",
            "cimsession",
            "querydialect",
        ];
        let mut named_action = None;
        let mut positional = Vec::new();
        // What the next value belongs to: `Some(true)` the action,
        // `Some(false)` another parameter.
        let mut takes: Option<bool> = None;
        let mut cursor = elements.walk();
        for element in elements.named_children(&mut cursor) {
            match element.kind() {
                "command_argument_sep" | "comment" | "redirection" => continue,
                "command_parameter" => {
                    let name = unit::text(&element, self.source)
                        .trim_start_matches('-')
                        .to_ascii_lowercase();
                    let slot = slots
                        .iter()
                        .position(|names| names.iter().any(|full| full.starts_with(&name)));
                    takes = match slot {
                        _ if name.is_empty() => None,
                        Some(slot) if slot + 1 == slots.len() => Some(true),
                        Some(slot) => {
                            bound[slot] = true;
                            Some(false)
                        }
                        None if named.iter().any(|full| full.starts_with(&name)) => Some(false),
                        None => None,
                    };
                    continue;
                }
                _ => {}
            }
            if is_splat(element, self.source) {
                return true;
            }
            match takes.take() {
                Some(true) => named_action = Some(is_script_block(element)),
                Some(false) => {}
                None => positional.push(is_script_block(element)),
            }
        }
        if let Some(block) = named_action {
            return !block;
        }
        let place = bound.iter().filter(|bound| !**bound).count() - 1;
        positional.get(place).is_some_and(|block| !block)
    }

    fn name(&self, node: Node<'_>) -> Arg {
        let source = unit::text(&node, self.source);
        match node.kind() {
            "command_name" => Arg::Known(unescape(source)),
            "command_name_expr" | "path_command_name" => {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                match children.as_slice() {
                    [] => Arg::Known(unescape(source)),
                    [only] => self.name(*only),
                    _ => Arg::Unknown(source.to_string()),
                }
            }
            _ => self.expr(node),
        }
    }

    /// A value: a token, a string, a variable the guard can name; anything
    /// computed is only known when it runs.
    fn expr(&self, node: Node<'_>) -> Arg {
        let source = unit::text(&node, self.source);
        match node.kind() {
            "generic_token" | "command_parameter" => Arg::Known(unescape(source)),
            "integer_literal"
            | "decimal_integer_literal"
            | "hexadecimal_integer_literal"
            | "real_literal" => Arg::Known(source.to_string()),
            "unary_expression" | "array_literal_expression" => {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                match children.as_slice() {
                    [only] => self.expr(*only),
                    _ => Arg::Unknown(source.to_string()),
                }
            }
            "string_literal" => self.string(node),
            "variable" => self.variable(source),
            "member_access" => match node.named_child(0) {
                Some(object)
                    if object.kind() == "variable"
                        && self.is_item(unit::text(&object, self.source)) =>
                {
                    Arg::Input
                }
                _ => Arg::Unknown(source.to_string()),
            },
            _ => Arg::Unknown(source.to_string()),
        }
    }

    fn string(&self, node: Node<'_>) -> Arg {
        let source = unit::text(&node, self.source);
        let Some(literal) = node.named_child(0) else {
            return Arg::Unknown(source.to_string());
        };
        let text = unit::text(&literal, self.source);
        match literal.kind() {
            "verbatim_string_characters" => Arg::Known(
                text.strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
                    .unwrap_or(text)
                    .replace("''", "'"),
            ),
            "expandable_string_literal" | "expandable_here_string_literal" => {
                // `"…"` or `@"` … `"@`.
                let here = literal.kind() == "expandable_here_string_literal";
                let quotes = if here { 2 } else { 1 };
                let start = literal.start_byte() + quotes;
                let end = literal.end_byte().saturating_sub(quotes).max(start);
                let mut value = String::new();
                let mut nulls = false;
                let mut splits = Vec::new();
                let mut at = start;
                let mut cursor = literal.walk();
                for child in literal.named_children(&mut cursor) {
                    let (before, made) = unescape_expandable(
                        self.source.get(at..child.start_byte()).unwrap_or_default(),
                    );
                    splits.extend(made);
                    value.push_str(&before);
                    if child.kind() != "variable" {
                        return Arg::Unknown(source.to_string());
                    }
                    match self.variable(unit::text(&child, self.source)) {
                        // Inside a string `$null` is the empty string, so
                        // `"$null\Windows"` is `\Windows`.
                        Arg::Known(text) if text == NULL => nulls = true,
                        Arg::Known(text) => value.push_str(&text),
                        Arg::Unknown(_) | Arg::Template { .. } | Arg::Input => {
                            return Arg::Unknown(source.to_string())
                        }
                    }
                    at = child.end_byte();
                }
                let (rest, made) =
                    unescape_expandable(self.source.get(at..end).unwrap_or_default());
                splits.extend(made);
                value.push_str(&rest);
                // A string of nothing but `$null` is still the device.
                if nulls && value.is_empty() {
                    return Arg::Known(NULL.to_string());
                }
                let value = if here {
                    // The lines between the two markers.
                    value.trim_matches(['\r', '\n']).to_string()
                } else {
                    value.replace("\"\"", "\"")
                };
                // The value is the string as an argument; only a script read
                // from it is not what it says (see `Split::note_splitting`).
                self.split.note_splitting(&splits);
                Arg::Known(value)
            }
            "verbatim_here_string_characters" => Arg::Known(
                text.trim_start_matches("@'")
                    .trim_end_matches("'@")
                    .trim_matches(['\r', '\n'])
                    .to_string(),
            ),
            _ => Arg::Unknown(source.to_string()),
        }
    }

    fn is_item(&self, source: &str) -> bool {
        self.item.is_some() && matches!(source.to_ascii_lowercase().as_str(), "$_" | "$psitem")
    }

    /// The variables that name a known place, as paths the resolver reads;
    /// `$_` inside a `ForEach-Object` block is the pipeline's input.
    fn variable(&self, source: &str) -> Arg {
        if self.is_item(source) {
            return Arg::Input;
        }
        let lower = source.to_ascii_lowercase();
        let name = lower
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
            .or_else(|| lower.strip_prefix('$'))
            .unwrap_or_default();
        if self.split.reassigned(name) {
            return Arg::Unknown(source.to_string());
        }
        let Some(value) = place_variable(name) else {
            return Arg::Unknown(source.to_string());
        };
        Arg::Known(value.to_string())
    }

    /// A .NET method call that changes files or the system
    /// (`[IO.Directory]::Delete(…)`, `(Get-Item ~).Delete()`): its arguments
    /// are expressions the guard does not resolve, so the call is risky
    /// wherever it points.
    fn dotnet(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let Some(member) = children.iter().find(|child| child.kind() == "member_name") else {
            return;
        };
        let method = unit::text(member, self.source).to_ascii_lowercase();
        let object = children
            .first()
            .map(|object| unit::text(object, self.source).to_ascii_lowercase())
            .unwrap_or_default();
        // A type that touches the file system, registry or network: only
        // then is a generic method (`Copy`, `Open`, `Replace`) a file write,
        // not a string or list method.
        let file_like = [
            "file",
            "directory",
            "io.",
            "path",
            "registrykey",
            "webclient",
            "stream",
        ]
        .iter()
        .any(|kind| object.contains(kind));
        let (rule, reason) = match method.as_str() {
            "invoke" | "invokereturnasis" | "invokewithcontext" => {
                (Rule::Unknown, "invokes code the guard does not read")
            }
            "delete" | "moveto" | "deletesubkey" | "deletesubkeytree" | "deletevalue" => {
                (Rule::Delete, "calls .NET to delete or move files")
            }
            "move" if file_like => (Rule::Delete, "calls .NET to delete or move files"),
            "writealltext" | "writeallbytes" | "writealllines" | "appendalltext"
            | "appendalllines" | "createtext" | "appendtext" | "appendallbytes"
            | "downloadfile" => (Rule::Overwrite, "calls .NET to write files"),
            "copy" | "open" | "openwrite" | "create" | "createnew" | "opentext" | "replace"
                if file_like =>
            {
                (Rule::Overwrite, "calls .NET to write or open files")
            }
            "setaccesscontrol" if file_like => {
                (Rule::Permissions, "calls .NET to change permissions")
            }
            "setenvironmentvariable" => (
                Rule::SystemSettings,
                "calls .NET to change environment variables",
            ),
            "start" if object.contains("process") => {
                (Rule::Unknown, "calls .NET to start a program")
            }
            _ => return,
        };
        self.split
            .problem(rule, reason, Some(unit::text(&node, self.source)));
    }

    /// A redirect to a file: `>`, `>>`, `2>`, `*>`. A merge (`2>&1`) writes
    /// nothing.
    fn redirect(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let writes = children
            .iter()
            .any(|child| child.kind() == "file_redirection_operator");
        let Some(file) = children
            .iter()
            .find(|child| child.kind() == "redirected_file_name")
        else {
            return;
        };
        if !writes {
            return;
        }
        let mut cursor = file.walk();
        let target = file
            .named_children(&mut cursor)
            .find(|child| child.kind() != "command_argument_sep")
            .map_or_else(
                || Arg::Unknown(unit::text(file, self.source).to_string()),
                |value| self.expr(value),
            );
        self.split.write(Shell::PowerShell, target);
    }
}

/// PowerShell's escape character is the backtick: `` `$ `` is `$`.
fn unescape(text: &str) -> String {
    let mut value = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '`' {
            if let Some(next) = chars.next() {
                value.push(next);
            }
        } else {
            value.push(c);
        }
    }
    value
}

/// What a backtick makes of the text in an expandable string or here-string:
/// `` `n `` is a line break, `` `t `` a tab, `` `u{1F600} `` a character; any
/// other character after it is itself (`` `$ ``, `` `" ``). The second value
/// holds each character a `` `u{…} `` made that PowerShell reads as more than
/// a character once the text is run as code (a space that is not an ASCII one,
/// a dash or a quote that looks like another): as an argument the string is
/// the text it holds, but read again as a script it is not the words it runs
/// as.
fn unescape_expandable(text: &str) -> (String, Vec<char>) {
    let mut splits = Vec::new();
    let mut value = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '`' {
            value.push(c);
            continue;
        }
        let Some(next) = chars.next() else { break };
        match next {
            '0' => value.push('\0'),
            'a' => value.push('\x07'),
            'b' => value.push('\x08'),
            'e' => value.push('\x1b'),
            'f' => value.push('\x0c'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            'v' => value.push('\x0b'),
            'u' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut digits = String::new();
                while let Some(digit) = chars.next_if(char::is_ascii_hexdigit) {
                    digits.push(digit);
                }
                let closed = chars.next_if_eq(&'}').is_some();
                let decoded = u32::from_str_radix(&digits, 16)
                    .ok()
                    .filter(|_| closed)
                    .and_then(char::from_u32);
                if let Some(decoded) = decoded {
                    if splits_words(decoded) {
                        splits.push(decoded);
                    }
                    value.push(decoded);
                } else {
                    // Not a character: PowerShell does not run the line.
                    value.push_str("`u{");
                    value.push_str(&digits);
                    if closed {
                        value.push('}');
                    }
                }
            }
            other => value.push(other),
        }
    }
    (value, splits)
}

/// Whether PowerShell reads `c`, run as code, as something other than the
/// character it is: a space that is not an ASCII one (U+00A0, U+0085,
/// U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) splits
/// words, a dash (U+2013 to U+2015) starts a parameter, and a typographic
/// quote (U+2018 to U+201E) opens or closes a string. The guard's own read of
/// a nested line does not know them, so a script with one in it is not read.
fn splits_words(c: char) -> bool {
    (!c.is_ascii() && c.is_whitespace())
        || matches!(c, '\u{2013}'..='\u{2015}' | '\u{2018}'..='\u{201e}')
}

/// Switch parameters (they take no value) that the rules meet.
const SWITCHES: [&str; 17] = [
    "recurse",
    "force",
    "whatif",
    "confirm",
    "verbose",
    "debug",
    "passthru",
    "nonewline",
    "append",
    "noclobber",
    "wait",
    "container",
    "nonewwindow",
    "asjob",
    "usebasicparsing",
    "noprofile",
    "nologo",
];

/// Parameters that take a value, which a prefix also names.
const VALUES: [&str; 45] = [
    "path",
    "literalpath",
    "destination",
    "filepath",
    "argumentlist",
    "verb",
    "value",
    "filter",
    "include",
    "exclude",
    "encoding",
    "name",
    "id",
    "command",
    "scriptblock",
    "executionpolicy",
    "scope",
    "computername",
    "credential",
    "uri",
    "outfile",
    "workingdirectory",
    "itemtype",
    "stream",
    "width",
    // The common parameters and their aliases: a value is never an operand.
    "erroraction",
    "ea",
    "warningaction",
    "wa",
    "informationaction",
    "infa",
    "errorvariable",
    "ev",
    "warningvariable",
    "wv",
    "informationvariable",
    "iv",
    "outvariable",
    "ov",
    "outbuffer",
    "ob",
    "pipelinevariable",
    "pv",
    "progressaction",
    "proga",
];

/// A cmdlet's arguments read as PowerShell reads them.
#[derive(Debug, Default)]
pub(crate) struct Params<'a> {
    /// Each parameter given (lower case, without `-`), with its value.
    pub(crate) named: Vec<(String, Option<&'a Arg>)>,
    /// The arguments no parameter takes.
    pub(crate) positional: Vec<&'a Arg>,
}

impl<'a> Params<'a> {
    pub(crate) fn read(args: &'a [Arg]) -> Self {
        let mut params = Self::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(name) = parameter(arg) else {
                params.positional.push(arg);
                continue;
            };
            let colon = name.ends_with(':');
            let name = name.trim_end_matches(':').to_ascii_lowercase();
            // A value is taken only by a parameter that names a value one
            // and no switch: an unknown or ambiguous one (`-rf` to a native
            // `rm`, `-f`) leaves the next argument where a rule sees it.
            let takes_value = colon
                || VALUES.contains(&name.as_str())
                || (VALUES.iter().any(|full| full.starts_with(&name))
                    && !SWITCHES.iter().any(|full| full.starts_with(&name)));
            let value = if takes_value
                && iter
                    .peek()
                    .is_some_and(|next| parameter(next).is_none() || colon)
            {
                iter.next()
            } else {
                None
            };
            params.named.push((name, value));
        }
        params
    }

    /// The values of the parameters that abbreviate one of `fulls`.
    pub(crate) fn values(&self, fulls: &[&str]) -> Vec<&'a Arg> {
        self.named
            .iter()
            .filter(|(name, _)| fulls.iter().any(|full| full.starts_with(name.as_str())))
            .filter_map(|(_, value)| *value)
            .collect()
    }
}

/// A parameter's name with its `-`, when `arg` is one.
fn parameter(arg: &Arg) -> Option<&str> {
    let text = arg.known()?;
    let name = text.strip_prefix('-')?;
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        .then_some(name)
}

/// `text` with each bare word that is a variable followed by a path
/// (`$HOME\.ssh\id_rsa`, `$env:USERPROFILE/.aws`) put in double quotes, which
/// is what PowerShell reads it as: an expandable string. The grammar reads
/// such a word as a member access and loses the path, so without this a
/// line that names a key through a variable cannot be read.
///
/// Only a word of plain path characters after a name is wrapped, and only
/// where a word can begin (after white space, `(`, `,` or the `:` of
/// `-Path:`). Text the scan cannot follow with certainty (a here-string, a
/// subexpression in a string) leaves the whole line as written.
fn variable_paths(text: &str) -> Cow<'_, str> {
    if !text.contains(['\\', '/']) || !text.contains('$') {
        return Cow::Borrowed(text);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 8);
    let mut changed = false;
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        let previous = at.checked_sub(1).and_then(|before| chars.get(before));
        match c {
            // A here-string: its end is not one this scan reads.
            '@' if matches!(chars.get(at + 1), Some('\'' | '"')) => {
                return Cow::Borrowed(text);
            }
            '\'' => {
                let Some(end) = single_quoted(&chars, at) else {
                    return Cow::Borrowed(text);
                };
                out.extend(&chars[at..end]);
                at = end;
            }
            '"' => {
                let Some(end) = double_quoted(&chars, at) else {
                    return Cow::Borrowed(text);
                };
                out.extend(&chars[at..end]);
                at = end;
            }
            '`' => {
                out.push(c);
                out.extend(chars.get(at + 1));
                at += 2;
            }
            '<' if chars.get(at + 1) == Some(&'#') => {
                // A block comment runs to `#>`.
                let Some(end) = (at + 2..chars.len().saturating_sub(1))
                    .find(|&i| chars[i] == '#' && chars[i + 1] == '>')
                else {
                    return Cow::Borrowed(text);
                };
                out.extend(&chars[at..end + 2]);
                at = end + 2;
            }
            '#' if previous.is_none_or(|p| p.is_whitespace() || matches!(p, ';' | '(' | '{')) => {
                // A line comment runs to the end of the line.
                let end = (at..chars.len())
                    .find(|&i| chars[i] == '\n')
                    .unwrap_or(chars.len());
                out.extend(&chars[at..end]);
                at = end;
            }
            '$' if previous.is_none_or(|p| p.is_whitespace() || matches!(p, '(' | ',' | ':')) => {
                if let Some(end) = variable_word(&chars, at) {
                    out.push('"');
                    out.extend(&chars[at..end]);
                    out.push('"');
                    changed = true;
                    at = end;
                } else {
                    out.push(c);
                    at += 1;
                }
            }
            _ => {
                out.push(c);
                at += 1;
            }
        }
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(text)
    }
}

/// Where the single-quoted string that opens at `at` ends (after its closing
/// quote); `''` inside is a quote.
fn single_quoted(chars: &[char], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while let Some(&c) = chars.get(i) {
        if c == '\'' {
            if chars.get(i + 1) == Some(&'\'') {
                i += 2;
                continue;
            }
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// Where the double-quoted string that opens at `at` ends. A backtick
/// escapes, `""` is a quote; a `$(` inside is a subexpression with quotes of
/// its own, which is not followed, so the scan gives up on it.
fn double_quoted(chars: &[char], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while let Some(&c) = chars.get(i) {
        match c {
            '`' => i += 2,
            '$' if chars.get(i + 1) == Some(&'(') => return None,
            '"' => {
                if chars.get(i + 1) == Some(&'"') {
                    i += 2;
                } else {
                    return Some(i + 1);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Where a word of the form `$name\path` that begins at `at` ends, when it is
/// one: a variable name (`$HOME`, `$env:USERPROFILE`, `${HOME}`), a `\` or
/// `/` right after it, and plain path characters up to a character that ends
/// a word. `None` for anything else: a variable alone, a member access, a
/// word with another expansion, a quote or a backtick in it.
fn variable_word(chars: &[char], at: usize) -> Option<usize> {
    let mut i = at + 1;
    if chars.get(i) == Some(&'{') {
        let close = (i + 1..chars.len()).find(|&j| chars[j] == '}')?;
        if chars[i + 1..close]
            .iter()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | ':')))
        {
            return None;
        }
        i = close + 1;
    } else {
        let start = i;
        while chars
            .get(i)
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':'))
        {
            i += 1;
        }
        if i == start || chars[start..i].ends_with(&[':']) {
            return None;
        }
    }
    if !matches!(chars.get(i), Some('\\' | '/')) {
        return None;
    }
    while let Some(&c) = chars.get(i) {
        if c.is_whitespace() || matches!(c, ';' | '|' | '&' | ')' | '}' | ',') {
            break;
        }
        // A backtick escapes the next character, a space included.
        if c == '`' {
            if chars
                .get(i + 1)
                .is_some_and(|next| !matches!(next, '\n' | '\r'))
            {
                i += 2;
                continue;
            }
            return None;
        }
        if matches!(c, '$' | '\'' | '"' | '(' | '{' | '<' | '>' | '@') {
            return None;
        }
        i += 1;
    }
    Some(i)
}

/// The place a variable names, by its lower-case name without `$`: the home
/// directory, the working directory, the folders `env:` names.
fn place_variable(name: &str) -> Option<&'static str> {
    Some(match name {
        "home" | "env:userprofile" | "env:home" => "~",
        "pwd" => ".",
        "env:temp" | "env:tmp" => "~\\AppData\\Local\\Temp",
        "env:appdata" => "~\\AppData\\Roaming",
        "env:localappdata" => "~\\AppData\\Local",
        "env:systemroot" | "env:windir" => "C:\\Windows",
        "env:programfiles" => "C:\\Program Files",
        "env:programdata" => "C:\\ProgramData",
        "null" => "$null",
        _ => return None,
    })
}

/// The path a bare word that is a variable and a path names (`$HOME\.ssh\x`,
/// which the grammar reads as something it cannot see into), when the variable
/// is one the guard names and the line does not set: the place and the rest.
pub(crate) fn bare_path(source: &str, split: &Split) -> Option<String> {
    let chars: Vec<char> = source.chars().collect();
    if variable_word(&chars, 0)? != chars.len() {
        return None;
    }
    let end = source
        .find(['\\', '/'])
        .filter(|end| source[..*end].starts_with('$'))?;
    let lower = source[..end].to_ascii_lowercase();
    let name = lower
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| lower.strip_prefix('$'))?;
    if split.reassigned(name) {
        return None;
    }
    Some(format!("{}{}", place_variable(name)?, &source[end..]))
}

#[cfg(test)]
mod tests {
    use super::VALUES;

    /// The parameters `classify` reads a value for, as they were when `Reach`
    /// landed. A name added to the shared list swallows the argument after it,
    /// which can be the target of a delete (`Remove-Item -Depth ~ -Recurse`), so
    /// a cmdlet's own value parameters belong to its reader (`Get-ChildItem
    /// -Depth` is in `effect`), and this list changes only with a row for each
    /// name in `tests/windows.rs`.
    const PINNED: [&str; 45] = [
        "path",
        "literalpath",
        "destination",
        "filepath",
        "argumentlist",
        "verb",
        "value",
        "filter",
        "include",
        "exclude",
        "encoding",
        "name",
        "id",
        "command",
        "scriptblock",
        "executionpolicy",
        "scope",
        "computername",
        "credential",
        "uri",
        "outfile",
        "workingdirectory",
        "itemtype",
        "stream",
        "width",
        // The common parameters and their aliases: a value is never an operand.
        "erroraction",
        "ea",
        "warningaction",
        "wa",
        "informationaction",
        "infa",
        "errorvariable",
        "ev",
        "warningvariable",
        "wv",
        "informationvariable",
        "iv",
        "outvariable",
        "ov",
        "outbuffer",
        "ob",
        "pipelinevariable",
        "pv",
        "progressaction",
        "proga",
    ];

    #[test]
    fn the_shared_value_parameters_are_the_pinned_list() {
        assert_eq!(VALUES, PINNED);
    }
}
