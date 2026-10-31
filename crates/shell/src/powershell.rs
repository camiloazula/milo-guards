//! Splitting a PowerShell line with tree-sitter-powershell, PowerShell's
//! aliases, and how a cmdlet's parameters are read.

use tree_sitter::Node;

use crate::detect::DOWNLOADERS;
use crate::launch;
use crate::unit::{self, Arg, Between, Listing, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    let language = tree_sitter_powershell::LANGUAGE.into();
    let Some(tree) = unit::parse(split, text, &language) else {
        return;
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
    }
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
        "gps" | "ps" => "get-process",
        "%" | "foreach" => "foreach-object",
        "tee" => "tee-object",
        "cd" | "sl" | "chdir" => "set-location",
        "pushd" => "push-location",
        "popd" => "pop-location",
        "?" | "where" => "where-object",
        name => name,
    }
}

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
                let pipeline = self.split.pipeline();
                let mut cursor = node.walk();
                for (index, child) in node.named_children(&mut cursor).enumerate() {
                    // The first command in a `ForEach-Object` block reads
                    // `$_` from the stage the block is.
                    let stage = match (index, self.item) {
                        (0, Some(item)) => item,
                        _ => Stage { pipeline, index },
                    };
                    self.walk(child, Some(stage), level + 1);
                }
            }
            "command" => {
                let key = self.command(node, stage);
                let outer = self.item;
                if matches!(key.as_deref(), Some("foreach-object" | "where-object")) {
                    self.item = stage;
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
            }
            // `trap { … }`: its block runs on a terminating error, later.
            "trap_statement" => {
                let began = self.split.begin_later();
                self.children(node, stage, level);
                self.split.end_later(began, false);
            }
            "redirection" => {
                self.redirect(node);
                self.children(node, None, level);
            }
            "invokation_expression" => {
                self.dotnet(node);
                self.children(node, stage, level);
            }
            _ => self.children(node, stage, level),
        }
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
        // Whether an argument is a download, as `iex (iwr url)` runs one.
        let mut downloads = false;
        let program_key = program
            .known()
            .map(|program| unit::key(program, Shell::PowerShell));
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
                downloads |= self.downloads(element);
                match element.kind() {
                    "command_argument_sep" => {
                        if unit::text(&element, self.source).contains(':') {
                            attach_colon(&mut args);
                        }
                    }
                    "redirection" | "comment" => {}
                    "array_literal_expression" => {
                        let mut items = element.walk();
                        for item in element.named_children(&mut items) {
                            args.extend(self.element_args(item, program_key.as_deref()));
                        }
                    }
                    _ => args.extend(self.element_args(element, program_key.as_deref())),
                }
            }
        }
        // Inside a `ForEach-Object` block, a command takes its place in the
        // pipeline the block is a stage of.
        let stage = stage.or(self.item);
        let mut unit = Unit::new(Shell::PowerShell, program, args, stage);
        let key = unit.key();
        unit.downloaded = downloads && key.as_deref() == Some("invoke-expression");
        // The processes a `Stop-Process` is handed by a listing in its own
        // arguments: `-InputObject (Get-Process)`.
        if key.as_deref() == Some("stop-process") {
            if let Some(elements) = node.child_by_field_name("command_elements") {
                unit.listings = self.listings(elements);
            }
        }
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

    /// The arguments an element stands for: one, or three when it is the
    /// block of a `Where-Object` that only compares a process's name
    /// (`{ $_.ProcessName -eq 'node' }`), read as `ProcessName -eq node`.
    fn element_args(&self, element: Node<'_>, program: Option<&str>) -> Vec<Arg> {
        if program == Some("where-object") && is_script_block(element) {
            if let Some(filter) = self.name_filter(element) {
                return filter.to_vec();
            }
        }
        vec![self.expr(element)]
    }

    /// `{ $_.Name -eq 'x' }`: the property, the operator and the value of a
    /// block that is only a comparison of a process's name, with `-eq` or
    /// `-like` (and their case-sensitive and -insensitive spellings).
    fn name_filter(&self, block: Node<'_>) -> Option<[Arg; 3]> {
        // The block's one statement, through the grammar's layers.
        let mut node = block;
        for kind in [
            "script_block_expression",
            "script_block",
            "script_block_body",
            "statement_list",
        ] {
            while node.kind() != kind {
                node = only_child(node)?;
            }
            node = only_child(node)?;
        }
        while node.kind() != "comparison_expression" {
            node = only_child(node)?;
        }
        let mut cursor = node.walk();
        let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let [left, operator, right] = parts.as_slice() else {
            return None;
        };
        let operator = unit::text(operator, self.source).to_ascii_lowercase();
        if !matches!(
            operator.as_str(),
            "-eq" | "-ieq" | "-ceq" | "-like" | "-ilike" | "-clike"
        ) {
            return None;
        }
        let mut member = *left;
        while member.kind() != "member_access" {
            member = only_child(member)?;
        }
        let mut cursor = member.walk();
        let parts: Vec<Node<'_>> = member.named_children(&mut cursor).collect();
        let [item, property] = parts.as_slice() else {
            return None;
        };
        if item.kind() != "variable"
            || !matches!(
                unit::text(item, self.source).to_ascii_lowercase().as_str(),
                "$_" | "$psitem"
            )
            || property.kind() != "member_name"
        {
            return None;
        }
        let property = unit::text(property, self.source).to_ascii_lowercase();
        if !matches!(property.as_str(), "name" | "processname") {
            return None;
        }
        let mut value = *right;
        while value.kind() != "string_literal" {
            value = only_child(value)?;
        }
        let Arg::Known(value) = self.expr(value) else {
            return None;
        };
        Some([
            Arg::Known(property),
            Arg::Known(operator),
            Arg::Known(value),
        ])
    }

    /// The arguments of a command as its rules read them, with no side
    /// effects.
    fn plain_args(&self, command: Node<'_>, program: Option<&str>) -> Vec<Arg> {
        let mut args = Vec::new();
        let Some(elements) = command.child_by_field_name("command_elements") else {
            return args;
        };
        let mut cursor = elements.walk();
        for element in elements.named_children(&mut cursor) {
            match element.kind() {
                "command_argument_sep" => {
                    if unit::text(&element, self.source).contains(':') {
                        attach_colon(&mut args);
                    }
                }
                "redirection" | "comment" => {}
                "array_literal_expression" => {
                    let mut items = element.walk();
                    for item in element.named_children(&mut items) {
                        args.extend(self.element_args(item, program));
                    }
                }
                _ => args.extend(self.element_args(element, program)),
            }
        }
        args
    }

    /// The key of a command node's program, when it is written out.
    fn command_key(&self, command: Node<'_>) -> Option<String> {
        let name = command.child_by_field_name("command_name")?;
        let name = self.name(name);
        name.known()
            .map(|program| unit::key(program, Shell::PowerShell))
    }

    /// Every `Get-Process` written under `node`, with what follows it.
    fn listings(&self, node: Node<'_>) -> Vec<Listing> {
        let mut commands = Vec::new();
        unit::for_each_node(node, |inner| {
            if inner.kind() == "command"
                && self.command_key(inner).as_deref() == Some("get-process")
            {
                commands.push(inner);
            }
        });
        commands
            .into_iter()
            .map(|command| self.listing(command, node))
            .collect()
    }

    /// One `Get-Process` under `top`: its arguments, the stages after it in
    /// its pipeline, and anything else around it that picks from what it
    /// lists (`(Get-Process).Where{…}`).
    fn listing(&self, command: Node<'_>, top: Node<'_>) -> Listing {
        let mut between = Vec::new();
        let mut up = command.parent();
        if let Some(chain) = up.filter(|parent| parent.kind() == "pipeline_chain") {
            let mut cursor = chain.walk();
            let mut after = false;
            for stage in chain.named_children(&mut cursor) {
                if stage.id() == command.id() {
                    after = true;
                } else if after {
                    between.push(self.stage(stage));
                } else {
                    between.push(Between::Other);
                }
            }
            up = chain.parent();
        }
        while let Some(parent) = up.filter(|parent| parent.id() != top.id()) {
            if !matches!(
                parent.kind(),
                "pipeline"
                    | "pipeline_chain"
                    | "parenthesized_expression"
                    | "sub_expression"
                    | "statement_list"
                    | "member_access"
                    | "array_literal_expression"
                    | "unary_expression"
            ) {
                between.push(Between::Other);
                break;
            }
            up = parent.parent();
        }
        Listing {
            args: self.plain_args(command, Some("get-process")),
            between,
        }
    }

    /// A stage that follows a listing.
    fn stage(&self, stage: Node<'_>) -> Between {
        if stage.kind() != "command" {
            return Between::Other;
        }
        match self.command_key(stage).as_deref() {
            Some("where-object") => Between::Where(self.plain_args(stage, Some("where-object"))),
            Some("select-object" | "select") => {
                Between::select(&self.plain_args(stage, Some("select-object")))
            }
            Some("sort-object" | "sort") => Between::Narrows,
            _ => Between::Other,
        }
    }

    /// Whether the code under `node` downloads: a download cmdlet or a .NET
    /// call such as `(New-Object Net.WebClient).DownloadString(…)`.
    fn downloads(&self, node: Node<'_>) -> bool {
        let mut found = false;
        unit::for_each_node(node, |inner| match inner.kind() {
            "command" => {
                if let Some(Arg::Known(name)) = inner
                    .child_by_field_name("command_name")
                    .map(|name| self.name(name))
                {
                    found |= DOWNLOADERS.contains(&unit::key(&name, Shell::PowerShell).as_str());
                }
            }
            // `(…).DownloadString('url')`, which the grammar reads as a member
            // and its call, or a member alone when it is an argument.
            "invokation_expression" | "member_access" => {
                let mut cursor = inner.walk();
                let member = inner
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "member_name")
                    .map(|member| unit::text(&member, self.source).to_ascii_lowercase());
                // `GetString` decodes bytes (`Encoding.GetString`) and
                // downloads nothing; `HttpClient.GetStringAsync` does.
                found |= member.is_some_and(|member| {
                    member.starts_with("download") || member == "getstringasync"
                });
            }
            _ => {}
        });
        found
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
            "expandable_string_literal" => {
                let start = literal.start_byte() + 1;
                let end = literal.end_byte().saturating_sub(1).max(start);
                let mut value = String::new();
                let mut at = start;
                let mut cursor = literal.walk();
                for child in literal.named_children(&mut cursor) {
                    value.push_str(&unescape(
                        self.source.get(at..child.start_byte()).unwrap_or_default(),
                    ));
                    if child.kind() != "variable" {
                        return Arg::Unknown(source.to_string());
                    }
                    match self.variable(unit::text(&child, self.source)) {
                        Arg::Known(text) => value.push_str(&text),
                        Arg::Unknown(_) | Arg::Template { .. } | Arg::Input => {
                            return Arg::Unknown(source.to_string())
                        }
                    }
                    at = child.end_byte();
                }
                value.push_str(&unescape(self.source.get(at..end).unwrap_or_default()));
                Arg::Known(value.replace("\"\"", "\""))
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
        let value = match name {
            "home" | "env:userprofile" | "env:home" => "~",
            "pwd" => ".",
            "env:temp" | "env:tmp" => "~\\AppData\\Local\\Temp",
            "env:appdata" => "~\\AppData\\Roaming",
            "env:localappdata" => "~\\AppData\\Local",
            "env:systemroot" | "env:windir" => "C:\\Windows",
            "env:programfiles" => "C:\\Program Files",
            "env:programdata" => "C:\\ProgramData",
            "null" => "$null",
            _ => return Arg::Unknown(source.to_string()),
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

/// The one named child of `node`, when it has just one.
fn only_child(node: Node<'_>) -> Option<Node<'_>> {
    (node.named_child_count() == 1)
        .then(|| node.named_child(0))
        .flatten()
}

/// A colon right after a parameter (`-Name:value`) binds the next argument
/// to it: the parameter ends in `:`.
fn attach_colon(args: &mut [Arg]) {
    if let Some(Arg::Known(param)) = args.last_mut() {
        if param.starts_with('-') && !param.ends_with(':') {
            param.push(':');
        }
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
const VALUES: [&str; 26] = [
    "path",
    "literalpath",
    "destination",
    "destinationpath",
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

    /// One cmdlet's arguments, read by its own parameters: each name given
    /// is resolved to the parameter it names (its name or alias, or a prefix
    /// of one), and only a parameter that takes a value takes the next
    /// argument. A name that fits several is read as the first of them in
    /// `own`, then the common parameters, so a cmdlet's own parameters win
    /// and what the cmdlet might take as a value is not left for a rule to
    /// see as something else. A name that fits none takes no value.
    pub(crate) fn cmdlet(args: &'a [Arg], own: &[Param]) -> Self {
        let mut params = Self::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(name) = parameter(arg) else {
                params.positional.push(arg);
                continue;
            };
            let colon = name.ends_with(':');
            let typed = name.trim_end_matches(':').to_ascii_lowercase();
            let found = Param::resolve(&typed, own);
            let takes_value = colon || found.is_some_and(|param| param.value);
            let value = if takes_value
                && iter
                    .peek()
                    .is_some_and(|next| parameter(next).is_none() || colon)
            {
                iter.next()
            } else {
                None
            };
            let name = found.map_or(typed, |param| param.name.to_string());
            params.named.push((name, value));
        }
        params
    }

    /// Whether any of the parameters `fulls` was given, by a name that
    /// [`Params::cmdlet`] resolved to it.
    pub(crate) fn has(&self, fulls: &[&str]) -> bool {
        self.named
            .iter()
            .any(|(name, _)| fulls.contains(&name.as_str()))
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

/// A cmdlet's parameter, for [`Params::cmdlet`].
pub(crate) struct Param {
    /// Its name, in lower case.
    pub(crate) name: &'static str,
    /// The other names it answers to.
    pub(crate) aliases: &'static [&'static str],
    /// Whether it takes a value, or is a switch.
    pub(crate) value: bool,
}

impl Param {
    pub(crate) const fn value(name: &'static str, aliases: &'static [&'static str]) -> Self {
        Self {
            name,
            aliases,
            value: true,
        }
    }

    pub(crate) const fn switch(name: &'static str, aliases: &'static [&'static str]) -> Self {
        Self {
            name,
            aliases,
            value: false,
        }
    }

    /// Whether `typed` is a prefix of the parameter's name or an alias.
    fn starts_with(&self, typed: &str) -> bool {
        self.name.starts_with(typed) || self.aliases.iter().any(|alias| alias.starts_with(typed))
    }

    /// The parameter `typed` names: an exact name or alias first, then a
    /// prefix of one, the first that fits.
    fn resolve<'p>(typed: &str, own: &'p [Param]) -> Option<&'p Param> {
        if typed.is_empty() {
            return None;
        }
        let all = || own.iter().chain(COMMON.iter());
        all()
            .find(|param| param.name == typed || param.aliases.contains(&typed))
            .or_else(|| all().find(|param| param.starts_with(typed)))
    }
}

/// The parameters every cmdlet takes.
const COMMON: [Param; 12] = [
    Param::switch("verbose", &["vb"]),
    Param::switch("debug", &["db"]),
    Param::value("erroraction", &["ea"]),
    Param::value("warningaction", &["wa"]),
    Param::value("informationaction", &["infa", "ia"]),
    Param::value("progressaction", &["proga"]),
    Param::value("errorvariable", &["ev"]),
    Param::value("warningvariable", &["wv"]),
    Param::value("informationvariable", &["iv"]),
    Param::value("outvariable", &["ov"]),
    Param::value("outbuffer", &["ob"]),
    Param::value("pipelinevariable", &["pv"]),
];

/// A parameter's name with its `-`, when `arg` is one.
fn parameter(arg: &Arg) -> Option<&str> {
    let text = arg.known()?;
    let name = text.strip_prefix('-')?;
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        .then_some(name)
}
