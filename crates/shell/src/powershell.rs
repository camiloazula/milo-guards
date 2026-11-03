//! Splitting a PowerShell line with tree-sitter-powershell, PowerShell's
//! aliases, and how a cmdlet's parameters are read.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::Range;

use tree_sitter::Node;

mod blocks;
pub(crate) mod native;
mod spelling;

use crate::detect::DOWNLOADERS;
use crate::launch;
use crate::unit::{self, Arg, Between, Listing, OpensFrom, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    let language = tree_sitter_powershell::LANGUAGE.into();
    // A space, quote or dash PowerShell reads as an ASCII one is written as
    // that one, which is all the grammar knows.
    let ascii = spelling::ascii(text);
    let text = ascii.as_ref();
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
    let mut walker = Walker {
        source: text,
        depth,
        split,
        item: None,
        holds: HashSet::new(),
    };
    walker.mark_listings(tree.root_node());
    walker.walk(tree.root_node(), None, 0);
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

/// Whether a command's name is a script block written out (`& { … }`,
/// `. ({ … })`), however the grammar wraps it: its commands are read where
/// they stand.
fn names_block(node: Node<'_>) -> bool {
    let mut node = node;
    loop {
        if node.kind() == "script_block_expression" {
            return true;
        }
        if node.named_child_count() != 1 {
            return false;
        }
        match node.named_child(0) {
            Some(only) => node = only,
            None => return false,
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
        "ren" | "rni" => "rename-item",
        "si" => "set-item",
        "cli" => "clear-item",
        "clp" => "clear-itemproperty",
        "rnp" => "rename-itemproperty",
        "cpp" => "copy-itemproperty",
        "mp" => "move-itemproperty",
        "mv" | "move" | "mi" => "move-item",
        "sc" => "set-content",
        "ni" => "new-item",
        "ndr" | "mount" => "new-psdrive",
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
        "sajb" => "start-job",
        "sbp" => "set-psbreakpoint",
        "start" | "saps" => "start-process",
        "kill" | "spps" => "stop-process",
        "gps" | "ps" => "get-process",
        "icim" => "invoke-cimmethod",
        "iwmi" => "invoke-wmimethod",
        "%" | "foreach" => "foreach-object",
        "tee" => "tee-object",
        "cd" | "sl" | "chdir" => "set-location",
        "pushd" => "push-location",
        "popd" => "pop-location",
        "?" | "where" => "where-object",
        name => name,
    }
}

/// How a value uses `$_` (see [`Walker::item_use`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemUse {
    Absent,
    Own,
    Other,
}

/// Where the redirects of one command are opened from (see
/// [`Walker::command_children`]).
struct Redirects {
    /// The command's own units.
    own: Range<usize>,
    /// The units of the command before this index have been read for a move.
    seen: usize,
    /// Whether an argument that came before has moved the line.
    moved: bool,
    /// Whether the last word was a redirect operator alone (`1>`), so that
    /// the next argument is the file it writes.
    pending: bool,
    /// For `Start-Job`, the script blocks it is given, read after the rest of
    /// the command in the job's own process (see [`Walker::job`]); `None`
    /// for any other command.
    job: Option<Vec<usize>>,
}

/// What a bare word (a generic token) holds of a redirect. The grammar reads
/// only `>`, `>>`, `2>` to `6>`, `*>` and their doubled forms as operators;
/// a `1>`, a `7>` or a `>` glued to its word (`x>f`) is lexed as part of a
/// word, which PowerShell reads as a redirect.
#[derive(Debug, PartialEq, Eq)]
enum Bare<'t> {
    /// No `>` in it.
    Plain,
    /// A redirect: `word` is what comes before the operator and stays an
    /// argument (`x` in `x>f`, nothing for `1>f` or `*>f`), `target` the
    /// file glued to it, or empty when the next argument is the file.
    Redirect { word: &'t str, target: &'t str },
    /// A `>` the guard cannot place: in a quote or after an escape, or more
    /// than one in the word (`a>b>c`).
    Unclear,
}

/// Where the first `>` of a word is, read outside its quotes.
enum Arrow {
    /// At this byte, outside every quote.
    At(usize),
    /// Every `>` is text, in a closed quote (`--format="%an <%ae>"`).
    Quoted,
    /// A `>` the guard cannot place: in a quote that is not closed or that
    /// holds `$(` or a backtick, or after an escape.
    Unclear,
}

/// Find the first `>` of a word that is outside its quotes. PowerShell reads
/// one inside a closed `'...'` or `"..."` as text.
fn first_arrow(text: &str) -> Arrow {
    let mut quote: Option<(char, usize)> = None;
    for (index, c) in text.char_indices() {
        match quote {
            Some((open, start)) if c == open => {
                let inside = &text[start..index];
                if open == '"' && (inside.contains("$(") || inside.contains('`')) {
                    return Arrow::Unclear;
                }
                quote = None;
            }
            Some(_) => {}
            None => match c {
                '>' => return Arrow::At(index),
                '\'' | '"' => quote = Some((c, index + 1)),
                '`' => return Arrow::Unclear,
                _ => {}
            },
        }
    }
    if quote.is_some() {
        Arrow::Unclear
    } else {
        Arrow::Quoted
    }
}

/// Read the redirect in the text of a bare word.
fn bare_redirect(text: &str) -> Bare<'_> {
    if !text.contains('>') {
        return Bare::Plain;
    }
    let at = match first_arrow(text) {
        Arrow::At(at) => at,
        Arrow::Quoted => return Bare::Plain,
        Arrow::Unclear => return Bare::Unclear,
    };
    let (head, rest) = text.split_at(at);
    let target = rest
        .strip_prefix(">>")
        .or_else(|| rest.strip_prefix('>'))
        .unwrap_or_default();
    if head.contains(['`', '"', '\'', '$']) || target.contains(['>', '`', '"', '\'']) {
        return Bare::Unclear;
    }
    // A stream number or `*` before the operator is part of it.
    let word = if matches!(head, "1" | "2" | "3" | "4" | "5" | "6" | "*") {
        ""
    } else {
        head
    };
    Bare::Redirect { word, target }
}

struct Walker<'a> {
    source: &'a str,
    depth: usize,
    split: &'a mut Split,
    /// Inside a `ForEach-Object` block: the stage whose input `$_` is.
    item: Option<Stage>,
    /// The nodes with a `Get-Process` somewhere below them, worked out once
    /// for the whole tree so that each `Stop-Process` reads only the nodes
    /// that lead to a listing.
    holds: HashSet<usize>,
}

impl Walker<'_> {
    fn walk(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return;
        }
        match node.kind() {
            // `a && b`, `a || b`: the right side may not run, and the right
            // side of `||` runs only when the left failed, so a `cd` on the
            // left may not have moved the line.
            "pipeline" => {
                let list = self.split.list_start();
                let mut cursor = node.walk();
                let mut at = 0;
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "pipeline_chain_tail" {
                        if unit::text(&child, self.source) == "||" {
                            self.split.list_or(&list);
                        }
                        continue;
                    }
                    // A `cd` on the right side runs only when the left let
                    // it: when it did not, the line may still be where that
                    // side began, or where the chain did.
                    if at > 0 {
                        let link = self.split.link_start();
                        self.walk(child, stage, level + 1);
                        self.split.link_end(&list, link);
                    } else {
                        self.walk(child, stage, level + 1);
                    }
                    at += 1;
                }
                self.split.list_end(list);
            }
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
                // The block of an event, and a breakpoint's action, runs
                // later, in this session.
                let later = key
                    .as_deref()
                    .is_some_and(|key| EVENTS.contains(&key) || key == "set-psbreakpoint")
                    .then(|| self.split.begin_later());
                let job = key.as_deref() == Some("start-job");
                // A thread job and a `-Parallel` block run in a runspace of
                // their own, whose location stacks are empty.
                let stacks = self
                    .own_runspace(key.as_deref(), own.clone())
                    .then(|| self.split.take_locations());
                self.command_children(node, own.clone(), level, job);
                if let Some(stacks) = stacks {
                    self.split.restore_locations(stacks);
                }
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
                // A function named as a location cmdlet stands in for it.
                if node.kind() == "function_statement" && self.names_location(node) {
                    self.split.lose_locations();
                }
                self.split.repeats += 1;
                self.children(node, stage, level);
                self.split.repeats -= 1;
            }
            // What a condition guards, or a `try` may stop short of, may not
            // run.
            "if_statement" | "switch_statement" | "try_statement" => {
                self.split.branches += 1;
                self.children(node, stage, level);
                self.split.branches -= 1;
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
                // A hook's block, set by its method, runs later.
                let later = blocks::sets_hook(node, self.source).then(|| self.split.begin_later());
                self.children(node, stage, level);
                if let Some(began) = later {
                    self.split.end_later(began, false);
                }
            }
            "assignment_expression" => {
                blocks::hook(self.split, node, self.source);
                self.env_assignment(node);
                // `[Environment]::CurrentDirectory = …` moves the process,
                // whose folder a .NET call and a program the session starts
                // may take: where the line is, is only known when it runs.
                if blocks::assigned_member(node, self.source).as_deref() == Some("currentdirectory")
                {
                    self.moves_unknown(node);
                }
                // A hook's block runs later, when a command is looked up.
                let later = blocks::assigned_member(node, self.source)
                    .is_some_and(|name| blocks::HOOKS.contains(&name.as_str()))
                    .then(|| self.split.begin_later());
                self.children(node, stage, level);
                if let Some(began) = later {
                    self.split.end_later(began, false);
                }
            }
            _ => self.children(node, stage, level),
        }
    }

    /// `$env:TF_CLI_ARGS = '-destroy'`: terraform reads the value as
    /// arguments of its command, in any later line that runs it. A value
    /// that is not a plain `=` of a string written out (`+=`, a variable) is
    /// only known when it runs.
    fn env_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.named_child(0) else {
            return;
        };
        let text = unit::text(&left, self.source).trim();
        let name = text
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
            .or_else(|| text.strip_prefix('$'))
            .unwrap_or(text);
        let Some(name) = name
            .get(..4)
            .filter(|head| head.eq_ignore_ascii_case("env:"))
            .and_then(|_| name.get(4..))
            .and_then(unit::tf_cli_args_folded)
        else {
            return;
        };
        let right = node.child_by_field_name("value");
        let plain = right.is_some_and(|right| {
            self.source
                .get(left.end_byte()..right.start_byte())
                .is_some_and(|between| between.trim() == "=")
        });
        let value = match right {
            Some(mut right) if plain => {
                while right.kind() != "string_literal" && right.named_child_count() == 1 {
                    match right.named_child(0) {
                        Some(only) => right = only,
                        None => break,
                    }
                }
                match self.expr(right) {
                    known @ Arg::Known(_) if right.kind() == "string_literal" => known,
                    _ => Arg::Unknown(unit::text(&node, self.source).to_string()),
                }
            }
            _ => Arg::Unknown(unit::text(&node, self.source).to_string()),
        };
        self.split.tf_cli_args.push((name, value));
    }

    /// `Set-Item env:TF_CLI_ARGS …`, `New-Item -Path Env:\TF_CLI_ARGS_apply
    /// …`: a variable terraform reads as arguments, set to a value the guard
    /// does not read, so a later `terraform apply` is only known when it
    /// runs. A wildcard in the name may match one.
    fn env_item(&mut self, key: &str, args: &[Arg]) {
        if !matches!(key, "set-item" | "new-item" | "set-content" | "add-content") {
            return;
        }
        for arg in args {
            let Some(text) = arg.known() else { continue };
            let lower = text.trim_matches(['"', '\'']).to_ascii_lowercase();
            let Some(rest) = lower
                .strip_prefix("env:")
                .or_else(|| lower.split_once(":env:").map(|(_, rest)| rest))
            else {
                continue;
            };
            let rest = rest.trim_start_matches(['\\', '/']);
            let name = unit::tf_cli_args_folded(rest).or_else(|| {
                rest.contains(['*', '?', '['])
                    .then(|| "TF_CLI_ARGS".to_string())
            });
            if let Some(name) = name {
                self.split
                    .tf_cli_args
                    .push((name, Arg::Unknown(text.to_string())));
            }
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
        // Taken once: asking each child for the one after it walks the
        // children from the first again.
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for (at, &child) in children.iter().enumerate() {
            // A pipeline followed by `&` runs as a job of its own: a `cd` in
            // it does not move the session.
            let job = children
                .get(at + 1)
                .is_some_and(|next| next.kind() == "background_operator");
            self.split.branches += usize::from(job);
            self.walk(child, stage, level + 1);
            self.split.branches -= usize::from(job);
        }
    }

    /// What a command holds, `own` being its own units. A redirect on a
    /// command that moves the line (`Set-Location sub > f`) is opened before
    /// it runs: from where it starts. Only the redirects are placed so: a
    /// sub-expression in an argument is walked from where the line is, and a
    /// redirect that follows one that moved the line is opened where the line
    /// has gone to, as the session ran the argument before opening the file.
    fn command_children(&mut self, node: Node<'_>, own: Range<usize>, level: usize, job: bool) {
        let folder = job.then(|| self.job_folder(own.clone()));
        let mut state = Redirects {
            seen: own.end,
            own,
            moved: false,
            pending: false,
            job: job.then(Vec::new),
        };
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "command_elements" {
                let mut inner = child.walk();
                for element in child.named_children(&mut inner) {
                    self.command_child(element, level + 2, &mut state);
                }
            } else {
                self.command_child(child, level + 1, &mut state);
            }
        }
        // `echo x 1>` with no file after it.
        if state.pending {
            self.unclear_redirect(node);
        }
        if let (Some(blocks), Some(folder)) = (state.job, folder) {
            self.job(node, &blocks, folder.as_ref(), level);
        }
    }

    /// The folder a `Start-Job` among `own` starts its job in: its
    /// `-WorkingDirectory`, or where the line is when it names none.
    fn job_folder(&self, own: Range<usize>) -> Option<Arg> {
        let unit = self
            .split
            .units
            .get(own)?
            .iter()
            .find(|unit| unit.key().as_deref() == Some("start-job"))?;
        Params::read(&unit.args)
            .values(&["workingdirectory"])
            .first()
            .map(|folder| (*folder).clone())
    }

    /// The script blocks of a `Start-Job`, the descendants of `node` with
    /// the ids in `blocks`: they run in a process of its own, which starts
    /// in `folder` when one is given, so a `cd` in them does not move the
    /// line. They are read after the rest of the command, as the session
    /// runs its arguments before the job starts, and together, in the order
    /// they are written; when one of several moves, which runs first (an
    /// `-InitializationScript` runs before the block) is not read, and every
    /// path in them is only known when it runs.
    fn job(&mut self, node: Node<'_>, blocks: &[usize], folder: Option<&Arg>, level: usize) {
        let mut found = Vec::new();
        unit::for_each_node(node, |inner| {
            if blocks.contains(&inner.id()) {
                found.push(inner);
            }
        });
        let outer = self.split.dir_snapshot();
        let began = self.split.begin_later();
        self.split.apart += 1;
        // Its location stacks are its own, and empty.
        self.split.take_locations();
        if let Some(folder) = folder {
            self.split.enter(folder, Shell::PowerShell);
        }
        for block in &found {
            self.walk(*block, None, level + 1);
        }
        self.split.apart -= 1;
        if found.len() > 1 && self.split.moved_so_far() != began.moved() {
            self.split.unplace(began);
        }
        self.split.restore_dir(outer);
    }

    /// Whether a command among `own` named `key` runs its blocks in a
    /// runspace of its own: `Start-ThreadJob`, and `ForEach-Object
    /// -Parallel`.
    fn own_runspace(&self, key: Option<&str>, own: Range<usize>) -> bool {
        match key {
            Some("start-threadjob") => true,
            Some("foreach-object") => self.split.units.get(own).is_some_and(|units| {
                units
                    .iter()
                    .filter(|unit| unit.key().as_deref() == Some("foreach-object"))
                    .flat_map(|unit| &unit.args)
                    .filter_map(parameter)
                    .map(|name| name.trim_end_matches(':').to_ascii_lowercase())
                    .any(|name| name.len() > 1 && "parallel".starts_with(&name))
            }),
            _ => false,
        }
    }

    /// Whether a function definition is named as a location cmdlet
    /// (`function Pop-Location { }`, `function global:popd { }`).
    fn names_location(&self, node: Node<'_>) -> bool {
        let mut cursor = node.walk();
        let name = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "function_name");
        name.is_some_and(|name| names_location(unit::text(&name, self.source)))
    }

    /// A move of the session (or of its process) to a place the guard cannot
    /// read: the line is then only known to be somewhere when it runs. It is
    /// added as a `Set-Location` there, which the walk follows as it does any.
    fn moves_unknown(&mut self, node: Node<'_>) {
        let target = Arg::Unknown(unit::text(&node, self.source).to_string());
        self.location_unit("Set-Location", vec![target]);
    }

    /// Add a location cmdlet a .NET call stands for, with `args`.
    fn location_unit(&mut self, cmdlet: &str, args: Vec<Arg>) {
        let unit = Unit::new(
            Shell::PowerShell,
            Arg::Known(cmdlet.to_string()),
            args,
            None,
        );
        launch::add(self.split, unit, self.depth);
    }

    /// A call of a method of the session's paths (`$ExecutionContext
    /// .SessionState.Path`), or of the process's folder
    /// (`[IO.Directory]::SetCurrentDirectory`), that moves the line or keeps
    /// its location stacks: it is the location cmdlet it stands for, with the
    /// string it is given when that is written out. Called on another object
    /// (a variable that may hold the paths), the place, or the stack, is only
    /// known when it runs. True when `method` is one of them.
    fn location_call(
        &mut self,
        method: &str,
        object: &str,
        node: Node<'_>,
        children: &[Node<'_>],
    ) -> bool {
        if matches!(method, "setcurrentdirectory" | "set_currentdirectory") {
            self.moves_unknown(node);
            return true;
        }
        if !matches!(
            method,
            "setlocation" | "poplocation" | "pushcurrentlocation" | "setdefaultlocationstack"
        ) {
            return false;
        }
        let call = unit::text(&node, self.source);
        let paths = object.ends_with("sessionstate.path");
        // The string given first, when one is given.
        let given = blocks::first_argument(children).map(|_| {
            match blocks::first_string(children).map(|string| self.string(string)) {
                Some(Arg::Known(text)) if paths && !text.starts_with('-') => Arg::Known(text),
                _ => Arg::Unknown(call.to_string()),
            }
        });
        let stack = |given: Option<Arg>| {
            given.map_or_else(Vec::new, |name| {
                vec![Arg::Known("-StackName".to_string()), name]
            })
        };
        match method {
            "setlocation" => {
                let target = given.unwrap_or_else(|| Arg::Unknown(call.to_string()));
                self.location_unit("Set-Location", vec![target]);
            }
            // On another object the stack is not known: popping from it
            // leaves every stack unknown, and the line only known.
            _ if !paths => {
                let unknown = Some(Arg::Unknown(call.to_string()));
                self.location_unit("Pop-Location", stack(unknown));
            }
            "poplocation" => self.location_unit("Pop-Location", stack(given)),
            "pushcurrentlocation" => self.location_unit("Push-Location", stack(given)),
            _ => self.location_unit(
                "Set-Location",
                stack(Some(
                    given.unwrap_or_else(|| Arg::Unknown(call.to_string())),
                )),
            ),
        }
        true
    }

    /// A word that may be a redirect, which the guard cannot place.
    fn unclear_redirect(&mut self, node: Node<'_>) {
        self.split.problem(
            Rule::Unknown,
            "has a word that may be a redirect the guard cannot read",
            Some(unit::text(&node, self.source)),
        );
    }

    /// One part of a command (see [`Self::command_children`]).
    fn command_child(&mut self, child: Node<'_>, level: usize, state: &mut Redirects) {
        let kind = child.kind();
        let text = unit::text(&child, self.source);
        // A parameter after a `1>` (`1> --hard`) may or may not be the file
        // it writes: the guard keeps it an argument and cannot place the
        // redirect.
        if state.pending && kind == "command_parameter" {
            state.pending = false;
            self.unclear_redirect(child);
        }
        // The file a `1>` is followed by.
        let target = state.pending && !matches!(kind, "command_argument_sep" | "comment");
        let bare = match kind {
            "generic_token" | "command_parameter" if !target => bare_redirect(text),
            // A name or a list that holds a `>` (`echo>f`, `x>a,b`).
            // Also after `&` or `.`, where the name is wrapped in a
            // `command_name_expr`.
            "command_name" | "command_name_expr" if !target && text.contains('>') => Bare::Unclear,
            "array_literal_expression" if !target => {
                let mut arrow = false;
                unit::for_each_node(child, |inner| {
                    arrow |= inner.kind() == "generic_token"
                        && unit::text(&inner, self.source).contains('>');
                });
                if arrow {
                    Bare::Unclear
                } else {
                    Bare::Plain
                }
            }
            _ => Bare::Plain,
        };
        if bare == Bare::Unclear {
            self.unclear_redirect(child);
        }
        if kind != "redirection" && !target && !matches!(bare, Bare::Redirect { .. }) {
            // A job's block is read once the rest of the command is.
            if let Some(blocks) = state.job.as_mut().filter(|_| is_script_block(child)) {
                blocks.push(child.id());
                return;
            }
            self.walk(child, None, level);
            return;
        }
        // The units of the arguments walked since the last redirect: each
        // is read once, however many redirects there are.
        let len = self.split.units.len();
        state.moved |= self.split.moves_in(state.seen..len);
        state.seen = len;
        let from = if state.moved {
            OpensFrom::Line
        } else {
            self.split.starts_in(state.own.clone(), true)
        };
        let outer = self.split.open_from(from);
        match bare {
            Bare::Redirect { target: "", .. } => state.pending = true,
            Bare::Redirect { target, .. } => {
                let file = self.glued_target(target);
                self.split.write(Shell::PowerShell, file);
            }
            _ if target => {
                state.pending = false;
                let file = self.expr(child);
                self.split.write(Shell::PowerShell, file);
                self.walk(child, None, level);
            }
            _ => self.walk(child, None, level),
        }
        self.split.open_from(outer);
    }

    /// The file glued to a redirect operator (`..\x.txt` in `1>..\x.txt`):
    /// a variable by itself is read as one, and anything else with a `$` in
    /// it is only known when it runs.
    fn glued_target(&self, text: &str) -> Arg {
        if !text.contains('$') {
            Arg::Known(unescape(text))
        } else if text
            .strip_prefix('$')
            .is_some_and(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            self.variable(text)
        } else {
            Arg::Unknown(text.to_string())
        }
    }

    /// The unit `node` runs; its key, for the walk to know a
    /// `ForEach-Object` block.
    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) -> Option<String> {
        let name = node.child_by_field_name("command_name")?;
        let program = self.name(name);
        let mut args = Vec::new();
        let mut shapes = Vec::new();
        // Whether an argument is a download, as `iex (iwr url)` runs one.
        let mut downloads = false;
        let program_key = program
            .known()
            .map(|program| unit::key(program, Shell::PowerShell));
        // Whether the last word was a redirect operator alone (`1>`).
        let mut file_next = false;
        let native = !program_key.as_deref().is_some_and(is_cmdlet);
        if let Some(elements) = node.child_by_field_name("command_elements") {
            let mut cursor = elements.walk();
            for element in elements.named_children(&mut cursor) {
                // `--%` passes the rest verbatim, but only up to a `|`: the
                // grammar runs it to the end of the line, so what follows the
                // pipe is read again as the next command.
                let source = unit::text(&element, self.source);
                if let Some(verbatim) = source.strip_prefix("--%") {
                    let (own, rest) = verbatim
                        .split_once('|')
                        .map_or((verbatim, None), |(own, rest)| (own, Some(rest)));
                    // The words are handed on as written but for `%NAME%`,
                    // which PowerShell puts the environment variable in, and
                    // the program splits them by its own rules. `cmd` puts
                    // the variables in itself, and is read so.
                    let key = program_key.as_deref().unwrap_or_default();
                    for word in native::words(key, &args, own) {
                        args.push(if key == "cmd" {
                            Arg::Known(word)
                        } else {
                            self.environment(&word)
                        });
                        shapes.push(blocks::Shape::default());
                    }
                    if let Some(rest) = rest {
                        unit::script(self.split, rest, Shell::PowerShell, self.depth + 1);
                    }
                    continue;
                }
                // A native program is not handed `$null` at all: the
                // arguments after it move up (`git $null push` is `git
                // push`). A cmdlet binds it, and a string that holds it is a
                // value.
                if native && self.is_null(element) {
                    continue;
                }
                // A `1>` word and the file after it are a redirect, not
                // arguments (see `command_child`).
                // A parameter is not taken for the file (see `command_child`):
                // it stays an argument.
                if file_next && element.kind() == "command_parameter" {
                    file_next = false;
                } else if file_next && !matches!(element.kind(), "command_argument_sep" | "comment")
                {
                    file_next = false;
                    continue;
                }
                if matches!(element.kind(), "generic_token" | "command_parameter") {
                    if let Bare::Redirect { word, target } = bare_redirect(source) {
                        if !word.is_empty() {
                            args.push(Arg::Known(unescape(word)));
                            shapes.push(blocks::Shape::default());
                        }
                        file_next = target.is_empty();
                        continue;
                    }
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
                        for (index, item) in element.named_children(&mut items).enumerate() {
                            self.push_element(
                                &mut args,
                                &mut shapes,
                                item,
                                program_key.as_deref(),
                                index > 0,
                            );
                        }
                    }
                    _ => self.push_element(
                        &mut args,
                        &mut shapes,
                        element,
                        program_key.as_deref(),
                        false,
                    ),
                }
            }
        }
        // Whether a `ForEach-Object` calls a method that stops a process on
        // each item (`% Kill`).
        let mut stops = false;
        if let Some(program) = program.known() {
            let key = unit::key(program, Shell::PowerShell);
            stops = blocks::check(
                self.split,
                &key,
                &args,
                &shapes,
                unit::text(&node, self.source),
                self.depth,
            );
        }
        // Inside a `ForEach-Object` block, a command takes its place in the
        // pipeline the block is a stage of.
        let stage = stage.or(self.item);
        let mut unit = Unit::new(Shell::PowerShell, program, args, stage);
        let key = unit.key();
        if let Some(key) = key.as_deref() {
            self.env_item(key, &unit.args);
        }
        unit.downloaded = downloads && key.as_deref() == Some("invoke-expression");
        // A block or a script run by a name only known when it runs (`& $b`)
        // may move the session; one written out (`& { … }`) is read.
        unit.relocates = key.is_none() && !names_block(name);
        // The processes a `Stop-Process` is handed by a listing in its own
        // arguments: `-InputObject (Get-Process)`.
        if key.as_deref() == Some("stop-process") {
            if let Some(elements) = node.child_by_field_name("command_elements") {
                unit.listings = self.listings(elements);
                unit.unread_item = self.item.is_some() && self.unread_item(elements);
                unit.listed = shapes.iter().map(|shape| shape.listing).collect();
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
        // `Start-Process -RedirectStandardOutput f` writes the program's
        // output to `f`, as a redirect does.
        if key.as_deref() == Some("start-process") {
            let params = Params::start_process(&unit.args);
            let files: Vec<Arg> = params
                .values(&["redirectstandardoutput", "redirectstandarderror"])
                .into_iter()
                .cloned()
                .collect();
            for file in files {
                self.split.write(Shell::PowerShell, file);
            }
        }
        let at = unit.stage;
        launch::add(self.split, unit, self.depth);
        if stops {
            // `ForEach-Object Kill` stops each process it is handed, as a
            // `Stop-Process` that is given them does.
            self.stop_unit(vec![Arg::Input], Vec::new(), Vec::new(), at);
        }
        key
    }

    /// Add the `Stop-Process` a method that stops a process stands for
    /// (`(Get-Process node).Kill()`, `$_.Terminate()`, `% Kill`): it is
    /// judged as one given the same processes, by its `args`, which of them
    /// hold a `Get-Process` listing (`listed`) and what the listings are.
    fn stop_unit(
        &mut self,
        args: Vec<Arg>,
        listed: Vec<bool>,
        listings: Vec<Listing>,
        stage: Option<Stage>,
    ) {
        let mut unit = Unit::new(
            Shell::PowerShell,
            Arg::Known("Stop-Process".to_string()),
            args,
            stage,
        );
        unit.listed = listed;
        unit.listings = listings;
        launch::add(self.split, unit, self.depth);
    }

    /// A call of a method that stops a process (see [`blocks::stops_process`])
    /// on the first of `children`, the object. It is judged as a
    /// `Stop-Process` of that object: the processes a `Get-Process` listing
    /// gives, the item of a `ForEach-Object` block, or a process picked by
    /// an id written out (`[Process]::GetProcessById(1234)`); an object
    /// the guard cannot trace to one of those is any process.
    fn stop_call(&mut self, node: Node<'_>, children: &[Node<'_>]) {
        let Some(object) = children.first() else {
            return;
        };
        let text = unit::text(object, self.source);
        if object.kind() == "variable" && self.is_item(text) {
            self.stop_unit(vec![Arg::Input], Vec::new(), Vec::new(), self.item);
        } else if self.holds.contains(&object.id()) {
            let listings = self.listings(node);
            self.stop_unit(
                vec![Arg::Unknown(text.to_string())],
                vec![true],
                listings,
                None,
            );
        } else if let Some(id) = process_by_id(text) {
            self.stop_unit(vec![Arg::Known(id)], vec![false], Vec::new(), None);
        } else {
            self.stop_unit(
                vec![Arg::Unknown(text.to_string())],
                vec![false],
                Vec::new(),
                None,
            );
        }
    }

    /// Add what an element stands for to `args`, and one shape to `shapes` for
    /// each argument, so the two stay in step: the element's own shape goes
    /// with the first argument, and any more it stands for (the three of a
    /// `Where-Object` name filter) are plain.
    fn push_element(
        &self,
        args: &mut Vec<Arg>,
        shapes: &mut Vec<blocks::Shape>,
        element: Node<'_>,
        program: Option<&str>,
        joined: bool,
    ) {
        let made = self.element_args(element, program);
        for (at, arg) in made.into_iter().enumerate() {
            shapes.push(if at == 0 {
                self.shape(element, joined)
            } else {
                blocks::Shape::default()
            });
            args.push(arg);
        }
    }

    /// The arguments an element stands for: one, or three when it is the
    /// block of a `Where-Object` that only compares a process's name
    /// (`{ $_.ProcessName -eq 'node' }`), read as `ProcessName -eq node`.
    fn element_args(&self, element: Node<'_>, program: Option<&str>) -> Vec<Arg> {
        // A value a `Stop-Process` in a block builds on `$_`: the item, when
        // it unwraps to the item or one of the process's own members, and
        // only known when it runs for anything else.
        if program == Some("stop-process") && self.item.is_some() {
            match self.item_use(element) {
                ItemUse::Absent => {}
                ItemUse::Own => return vec![Arg::Input],
                ItemUse::Other => {
                    return vec![Arg::Unknown(unit::text(&element, self.source).to_string())]
                }
            }
        }
        if program == Some("where-object") && is_script_block(element) {
            if let Some(filter) = self.name_filter(element) {
                return filter.to_vec();
            }
        }
        // `Start-Process psql -ArgumentList @('-c', '…')`: an array of
        // strings is its items, as a comma list is.
        if program == Some("start-process") {
            let mut array = element;
            while array.kind() == "unary_expression" && array.named_child_count() == 1 {
                match array.named_child(0) {
                    Some(inner) => array = inner,
                    None => break,
                }
            }
            if array.kind() == "array_expression" {
                if let Some(items) = self.literal_array(array) {
                    return items;
                }
            }
        }
        vec![self.expr(element)]
    }

    /// The items of `@( … )` when each is a string whose value is known
    /// (`@('-c', 'SELECT 1')`); `None` for anything else in it.
    fn literal_array(&self, array: Node<'_>) -> Option<Vec<Arg>> {
        let mut items = Vec::new();
        let mut plain = true;
        unit::for_each_node(array, |node| {
            if !node.is_named() || node.id() == array.id() {
                return;
            }
            match node.kind() {
                "string_literal" => items.push(self.expr(node)),
                "statement_list"
                | "pipeline"
                | "pipeline_chain"
                | "logical_expression"
                | "bitwise_expression"
                | "comparison_expression"
                | "additive_expression"
                | "multiplicative_expression"
                | "format_expression"
                | "range_expression"
                | "array_literal_expression"
                | "unary_expression"
                | "verbatim_string_characters"
                | "expandable_string_literal" => {}
                _ => plain = false,
            }
        });
        (plain && items.iter().all(|item| matches!(item, Arg::Known(_)))).then_some(items)
    }

    /// How a value uses `$_`, the item of a `ForEach-Object` block: not at
    /// all; as the item or one of the process's own members (`.Id`, `.Name`,
    /// `.ProcessName`), through any parentheses, `$( )`, `@( )`, cast or
    /// string that holds nothing else; or as anything else (`$_.Parent`,
    /// `$_ + 1`, a call), which is not the processes the pipeline hands on.
    fn item_use(&self, node: Node<'_>) -> ItemUse {
        let mut holds = false;
        unit::for_each_node(node, |inner| {
            holds |= inner.kind() == "variable" && self.is_item(unit::text(&inner, self.source));
        });
        if !holds {
            return ItemUse::Absent;
        }
        let mut node = node;
        loop {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            let next = match (node.kind(), children.as_slice()) {
                ("variable", _) => {
                    return if self.is_item(unit::text(&node, self.source)) {
                        ItemUse::Own
                    } else {
                        ItemUse::Other
                    };
                }
                ("member_access", [object, member]) => {
                    let own = object.kind() == "variable"
                        && self.is_item(unit::text(object, self.source))
                        && member.kind() == "member_name"
                        && ["id", "name", "processname"]
                            .iter()
                            .any(|own| unit::text(member, self.source).eq_ignore_ascii_case(own));
                    return if own { ItemUse::Own } else { ItemUse::Other };
                }
                // `"$_"` and `"$($_.Id)"`: a string that is one expansion.
                ("string_literal", [literal]) if literal.kind() == "expandable_string_literal" => {
                    match literal
                        .named_children(&mut literal.walk())
                        .collect::<Vec<_>>()
                        .as_slice()
                    {
                        [only]
                            if only.start_byte() == literal.start_byte() + 1
                                && only.end_byte() + 1 == literal.end_byte() =>
                        {
                            *only
                        }
                        _ => return ItemUse::Other,
                    }
                }
                // `[int]$_.Id`: a cast of the value, which the grammar holds
                // in an operator's layer (`-not $_.Id` is one too, and not a
                // cast).
                ("expression_with_unary_operator", [cast]) if cast.kind() == "cast_expression" => {
                    *cast
                }
                // `[int]$_.Id`: a cast of the value.
                ("cast_expression", [kind, value]) if kind.kind() == "type_literal" => *value,
                (
                    "parenthesized_expression"
                    | "sub_expression"
                    | "array_expression"
                    | "statement_list"
                    | "pipeline"
                    | "pipeline_chain"
                    | "unary_expression"
                    | "array_literal_expression"
                    | "logical_expression"
                    | "bitwise_expression"
                    | "comparison_expression"
                    | "additive_expression"
                    | "multiplicative_expression"
                    | "format_expression"
                    | "range_expression",
                    [only],
                ) => *only,
                _ => return ItemUse::Other,
            };
            node = next;
        }
    }

    /// Whether any value given to a `Stop-Process` (`elements`, its
    /// arguments) is built on `$_` into something that is not the item.
    fn unread_item(&self, elements: Node<'_>) -> bool {
        let mut cursor = elements.walk();
        let other = elements.named_children(&mut cursor).any(|element| {
            if element.kind() == "array_literal_expression" {
                let mut items = element.walk();
                let other = element
                    .named_children(&mut items)
                    .any(|item| self.item_use(item) == ItemUse::Other);
                other
            } else {
                self.item_use(element) == ItemUse::Other
            }
        });
        other
    }

    /// `{ $_.Name -eq 'x' }`: the property, the operator and the value of a
    /// block that is only a comparison of a process's name, with `-eq`,
    /// `-like` or `-match` (and their case-sensitive and -insensitive
    /// spellings).
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
            "-eq"
                | "-ieq"
                | "-ceq"
                | "-like"
                | "-ilike"
                | "-clike"
                | "-match"
                | "-imatch"
                | "-cmatch"
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

    /// Mark every node that has a `Get-Process` below it. Each climb stops at
    /// a node already marked, so the marking is linear in the tree; the path
    /// is kept by the walk, because asking a node for its parent costs the
    /// depth of the tree.
    fn mark_listings(&mut self, root: Node<'_>) {
        let mut holds = HashSet::new();
        let mut path: Vec<usize> = Vec::new();
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            if node.kind() == "command" && self.command_key(node).as_deref() == Some("get-process")
            {
                for id in path.iter().rev() {
                    if !holds.insert(*id) {
                        break;
                    }
                }
            }
            if cursor.goto_first_child() {
                path.push(node.id());
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    self.holds = holds;
                    return;
                }
                path.pop();
            }
        }
    }

    /// The `Get-Process` listings a `Stop-Process`'s arguments (`elements`)
    /// hand it: each one that nothing but a pipeline, parentheses and the
    /// members `Id`, `Name` and `ProcessName` lie between it and the
    /// arguments, with what follows it in its pipeline. A listing anywhere
    /// else is one more listing, `Between::Other`, however many there are:
    /// the walk goes in one pass, never below a command, and reads only the
    /// nodes that lead to a `Get-Process`.
    fn listings(&self, elements: Node<'_>) -> Vec<Listing> {
        let mut found = Vec::new();
        let mut other = false;
        let mut stack: Vec<(Node<'_>, Node<'_>)> = Vec::new();
        self.push_towards_listings(elements, &mut stack);
        while let Some((node, parent)) = stack.pop() {
            if node.kind() == "command" {
                if self.command_key(node).as_deref() == Some("get-process") {
                    match self.listing(node, parent) {
                        Some(listing) => found.push(listing),
                        None => other = true,
                    }
                }
                // A `Get-Process` below a command (in its arguments, or in
                // a block it runs) is not what this `Stop-Process` is handed.
                other |= self.holds.contains(&node.id());
            } else if self.passes(node)
                // The list of the arguments themselves (`-Id $a, $b`): each
                // of them is read as an argument of its own.
                || (node.kind() == "array_literal_expression" && parent.id() == elements.id())
            {
                self.push_towards_listings(node, &mut stack);
            } else {
                // It holds a listing, which it may change.
                other = true;
            }
        }
        if other {
            found.push(Listing {
                args: Vec::new(),
                between: vec![Between::Other],
            });
        }
        found
    }

    /// Push the children of `node` that can lead to a listing, each with
    /// `node`, the last first so that they are read in order.
    fn push_towards_listings<'tree>(
        &self,
        node: Node<'tree>,
        stack: &mut Vec<(Node<'tree>, Node<'tree>)>,
    ) {
        let mut cursor = node.walk();
        let from = stack.len();
        for child in node.named_children(&mut cursor) {
            if self.holds.contains(&child.id()) || child.kind() == "command" {
                stack.push((child, node));
            }
        }
        stack[from..].reverse();
    }

    /// Whether a node between a `Get-Process` and the arguments of the
    /// `Stop-Process` hands on the processes the listing gives: a pipeline,
    /// parentheses, and a member that is a process's own (`.Id`, `.Name`,
    /// `.ProcessName`), not one that leads to others (`.Parent`, `.Threads`).
    fn passes(&self, node: Node<'_>) -> bool {
        match node.kind() {
            "pipeline_chain" => true,
            // Wrappers that hold the listing and nothing else: one with a
            // second part (`(Get-Process node), $x`, `$(Get-Process node; $x)`)
            // hands on that part too, which the listing says nothing of.
            "pipeline"
            | "parenthesized_expression"
            | "sub_expression"
            | "statement_list"
            | "array_literal_expression"
            | "unary_expression" => node.named_child_count() == 1,
            // The grammar wraps an expression in a layer for each operator
            // that binds looser; one with no operand but its own is only
            // that wrapping (`((Get-Process node).Id)`).
            "logical_expression"
            | "bitwise_expression"
            | "comparison_expression"
            | "additive_expression"
            | "multiplicative_expression"
            | "format_expression"
            | "range_expression" => node.named_child_count() == 1,
            "member_access" => {
                let mut cursor = node.walk();
                let member = node
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "member_name")
                    .map(|member| unit::text(&member, self.source));
                member.is_some_and(|member| {
                    ["id", "name", "processname"]
                        .iter()
                        .any(|own| member.eq_ignore_ascii_case(own))
                })
            }
            _ => false,
        }
    }

    /// One `Get-Process` that starts at the arguments: its own arguments and
    /// the stages after it in its pipeline. None when something comes before
    /// it in the pipeline, which may hand it other processes.
    fn listing(&self, command: Node<'_>, parent: Node<'_>) -> Option<Listing> {
        let mut between = Vec::new();
        if parent.kind() == "pipeline_chain" {
            let mut cursor = parent.walk();
            let mut stages = parent.named_children(&mut cursor);
            if stages.next()?.id() != command.id() {
                return None;
            }
            between = stages.map(|stage| self.stage(stage)).collect();
        }
        Some(Listing {
            args: self.plain_args(command, Some("get-process")),
            between,
        })
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

    /// What the grammar says of an argument: a block written out, a splat,
    /// and whether it follows a comma.
    fn shape(&self, node: Node<'_>, joined: bool) -> blocks::Shape {
        blocks::Shape {
            block: is_script_block(node),
            splat: is_splat(node, self.source),
            joined,
            listing: self.holds.contains(&node.id()),
        }
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
                        Arg::Null => nulls = true,
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
                // A string of nothing but `$null` is still the null value.
                if nulls && value.is_empty() {
                    return Arg::Null;
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

    /// A word after `--%` with each `%NAME%` in it put in: a variable that
    /// names a known place is that place, and any other (or one the line
    /// sets) is only known when it runs. A `%` with no name after it is
    /// text.
    fn environment(&self, word: &str) -> Arg {
        let mut value = String::with_capacity(word.len());
        let mut rest = word;
        while let Some(at) = rest.find('%') {
            value.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some(end) = after.find('%').filter(|&end| end > 0) else {
                value.push('%');
                rest = after;
                continue;
            };
            let name = &after[..end];
            match crate::cmd::place(name) {
                Some(place) if !self.split.reassigned(&format!("env:{name}")) => {
                    value.push_str(place);
                }
                _ => return Arg::Unknown(word.to_string()),
            }
            rest = &after[end + 1..];
        }
        value.push_str(rest);
        Arg::Known(value)
    }

    /// Whether `node` gives a native program nothing: the variable `$null`
    /// (in any case, or as `${null}`), not in a string; an empty `$()` or
    /// `@()`; a pipeline that ends in `Out-Null`; or one of these in
    /// parentheses or a subexpression (`(Out-Null)`, `$($null)`).
    fn is_null(&self, node: Node<'_>) -> bool {
        let mut node = node;
        for _ in 0..unit::MAX_TREE_DEPTH {
            match node.kind() {
                "array_literal_expression"
                | "unary_expression"
                | "parenthesized_expression"
                | "statement_list"
                | "pipeline"
                | "logical_expression"
                | "bitwise_expression"
                | "comparison_expression"
                | "additive_expression"
                | "multiplicative_expression"
                | "format_expression"
                | "range_expression" => match only_child(node) {
                    Some(only) => node = only,
                    None => return false,
                },
                "sub_expression" | "array_expression" => match only_child(node) {
                    Some(only) => node = only,
                    None => return node.named_child_count() == 0,
                },
                // A pipeline gives what its last stage does.
                "pipeline_chain" => {
                    let count = node.named_child_count();
                    match node
                        .named_child(u32::try_from(count.saturating_sub(1)).unwrap_or(u32::MAX))
                    {
                        Some(last) if last.kind() == "command" => {
                            return self.command_key(last).as_deref() == Some("out-null")
                        }
                        Some(only) if count == 1 => node = only,
                        _ => return false,
                    }
                }
                "command" => return self.command_key(node).as_deref() == Some("out-null"),
                "variable" => {
                    return matches!(self.variable(unit::text(&node, self.source)), Arg::Null)
                }
                _ => return false,
            }
        }
        false
    }

    fn is_item(&self, source: &str) -> bool {
        self.item.is_some()
            && matches!(
                source.to_ascii_lowercase().as_str(),
                "$_" | "$psitem" | "${_}" | "${psitem}"
            )
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
        if name == "null" {
            return Arg::Null;
        }
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
        // A name only known when it runs (`.$m(…)`, `."Invoke$x"(…)`,
        // `.($m)(…)`) may be any method, `InvokeScript` and `Delete` among
        // them: the call is risky wherever it points.
        let Some(method) = blocks::called(*member, self.source) else {
            self.split.problem(
                Rule::Unknown,
                "calls a method only known when it runs",
                Some(unit::text(&node, self.source)),
            );
            return;
        };
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
        blocks::hook_call(self.split, &method, &children, node, self.source);
        if self.location_call(&method, &object, node, &children) {
            return;
        }
        // A method that stops a process, called on it (`.Kill()`). The
        // array's `.ForEach('Kill')` is a line the grammar does not read.
        if blocks::stops_process(&method) {
            self.stop_call(node, &children);
            return;
        }
        // Code built from text, or run from it: the guard reads the text
        // when it is written out, and the call is risky wherever it points.
        if matches!(
            method.as_str(),
            "newscriptblock" | "invokescript" | "expandstring"
        ) || (method == "create" && object.contains("scriptblock"))
        {
            self.split.problem(
                Rule::Unknown,
                "builds or runs code the guard does not read",
                Some(unit::text(&node, self.source)),
            );
            if let Some(Arg::Known(code)) = blocks::first_string(&children).map(|n| self.string(n))
            {
                unit::script(self.split, &code, Shell::PowerShell, self.depth + 1);
            }
            return;
        }
        // `[Environment]::SetEnvironmentVariable('TF_CLI_ARGS', …)`: a name
        // terraform reads as arguments, or one only known when it runs, set
        // to a value the guard does not read.
        if method == "setenvironmentvariable" {
            let name = match blocks::first_string(&children).map(|name| self.string(name)) {
                Some(Arg::Known(name)) => unit::tf_cli_args_folded(&name),
                _ => Some("TF_CLI_ARGS".to_string()),
            };
            if let Some(name) = name {
                self.split.tf_cli_args.push((
                    name,
                    Arg::Unknown(unit::text(&node, self.source).to_string()),
                ));
            }
        }
        let Some((rule, reason)) = dotnet_rule(&method, &object, file_like) else {
            return;
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

/// The id in `[System.Diagnostics.Process]::GetProcessById(1234)`, when the
/// text is exactly that call (or the same with the namespace left out) and
/// the id is written out in digits.
fn process_by_id(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let id = [
        "[system.diagnostics.process]::getprocessbyid(",
        "[diagnostics.process]::getprocessbyid(",
        "[process]::getprocessbyid(",
    ]
    .iter()
    .find_map(|call| lower.strip_prefix(call))?
    .strip_suffix(')')?;
    (!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())).then(|| id.to_string())
}

/// What a .NET method does to files or the system, by its lower-case name:
/// `object` is the lower-case text it is called on, and `file_like` whether
/// that is a type that touches the file system, registry or network. Also what
/// `ForEach-Object` calls when it is given the method's name.
fn dotnet_rule(method: &str, object: &str, file_like: bool) -> Option<(Rule, &'static str)> {
    Some(match method {
        "invoke" | "invokereturnasis" | "invokewithcontext" => {
            (Rule::Unknown, "invokes code the guard does not read")
        }
        "delete" | "moveto" | "deletesubkey" | "deletesubkeytree" | "deletevalue" => {
            (Rule::Delete, "calls .NET to delete or move files")
        }
        "move" if file_like => (Rule::Delete, "calls .NET to delete or move files"),
        "writealltext" | "writeallbytes" | "writealllines" | "appendalltext" | "appendalllines"
        | "createtext" | "appendtext" | "appendallbytes" | "downloadfile" => {
            (Rule::Overwrite, "calls .NET to write files")
        }
        "copy" | "open" | "openwrite" | "create" | "createnew" | "opentext" | "replace"
            if file_like =>
        {
            (Rule::Overwrite, "calls .NET to write or open files")
        }
        "setaccesscontrol" if file_like => (Rule::Permissions, "calls .NET to change permissions"),
        "setenvironmentvariable" => (
            Rule::SystemSettings,
            "calls .NET to change environment variables",
        ),
        "start" if object.contains("process") => (Rule::Unknown, "calls .NET to start a program"),
        _ => return None,
    })
}

/// Whether the program `key` names (lower case, an alias read as its
/// cmdlet) is a cmdlet: a name of an approved verb, a dash and a noun, or a
/// built-in `-Object` cmdlet (`ForEach-Object`, `Tee-Object`). Any other is
/// taken for a native program.
fn is_cmdlet(key: &str) -> bool {
    key.split_once('-')
        .is_some_and(|(verb, noun)| !noun.is_empty() && (VERBS.contains(&verb) || noun == "object"))
}

/// PowerShell's approved verbs (`Get-Verb`), in lower case.
const VERBS: [&str; 100] = [
    "add",
    "approve",
    "assert",
    "backup",
    "block",
    "build",
    "checkpoint",
    "clear",
    "close",
    "compare",
    "complete",
    "compress",
    "confirm",
    "connect",
    "convert",
    "convertfrom",
    "convertto",
    "copy",
    "debug",
    "deny",
    "deploy",
    "disable",
    "disconnect",
    "dismount",
    "edit",
    "enable",
    "enter",
    "exit",
    "expand",
    "export",
    "find",
    "format",
    "get",
    "grant",
    "group",
    "hide",
    "import",
    "initialize",
    "install",
    "invoke",
    "join",
    "limit",
    "lock",
    "measure",
    "merge",
    "mount",
    "move",
    "new",
    "open",
    "optimize",
    "out",
    "ping",
    "pop",
    "protect",
    "publish",
    "push",
    "read",
    "receive",
    "redo",
    "register",
    "remove",
    "rename",
    "repair",
    "request",
    "reset",
    "resize",
    "resolve",
    "restart",
    "restore",
    "resume",
    "revoke",
    "save",
    "search",
    "select",
    "send",
    "set",
    "show",
    "skip",
    "split",
    "start",
    "step",
    "stop",
    "submit",
    "suspend",
    "switch",
    "sync",
    "test",
    "trace",
    "unblock",
    "undo",
    "uninstall",
    "unlock",
    "unprotect",
    "unpublish",
    "unregister",
    "update",
    "use",
    "wait",
    "watch",
    "write",
];

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
const VALUES: [&str; 46] = [
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

/// The value parameters of a listing (`Get-ChildItem`, `Get-Item`) alone.
const LISTING_VALUES: [&str; 2] = ["attributes", "depth"];

/// The value parameters of the `-ItemProperty` cmdlets alone.
const PROPERTY_VALUES: [&str; 2] = ["type", "propertytype"];

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
        Self::read_with(args, &[], &[])
    }

    /// `Get-ChildItem`'s arguments: its switch aliases that a prefix of a
    /// value parameter would swallow the folder for (`-s`, the alias of
    /// `-Recurse`, reads as a prefix of `-Scope`; `-ar`, the alias of
    /// `-ReadOnly`, of `-ArgumentList`; `-Name` and its prefixes are
    /// `Get-ChildItem`'s switch, not the item's `-Name`; `-File` is its
    /// switch, while for `Tee-Object`, `Out-File` or `Start-Process` its
    /// prefixes are the value parameters `-FilePath` and `-Filter`) are read
    /// as switches,
    /// and `-Attributes` and `-Depth` take a value.
    pub(crate) fn read_listing(args: &'a [Arg]) -> Self {
        Self::read_with(
            args,
            &["s", "ar", "n", "na", "nam", "name", "file"],
            &LISTING_VALUES,
        )
    }

    /// The arguments of `Get-Item`, which lists with the value parameters of
    /// a listing but has none of its switch aliases.
    pub(crate) fn read_item_listing(args: &'a [Arg]) -> Self {
        Self::read_with(args, &[], &LISTING_VALUES)
    }

    /// The arguments of an `-ItemProperty` cmdlet, whose `-Type` (an alias of
    /// `-PropertyType`) and `-PropertyType` take a value.
    pub(crate) fn read_property(args: &'a [Arg]) -> Self {
        Self::read_with(args, &[], &PROPERTY_VALUES)
    }

    /// Reads `args`, with the parameters named in `switches` (lower case,
    /// exactly) read as switches though a prefix of a value parameter, and
    /// those in `own` read as taking a value: a cmdlet's own value
    /// parameters are not added to the shared list, where one would swallow
    /// the path of every other cmdlet (`Remove-Item -Depth ~ -Recurse`).
    fn read_with(args: &'a [Arg], switches: &[&str], own: &[&str]) -> Self {
        let mut params = Self::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(name) = parameter(arg) else {
                params.positional.push(arg);
                continue;
            };
            let colon = name.ends_with(':');
            let name = name.trim_end_matches(':').to_ascii_lowercase();
            // `-LP` and `-PSPath` (and what abbreviates the second) are
            // aliases of `-LiteralPath`: the item cmdlets read them so.
            let name = if name == "lp" || (name.len() > 1 && "pspath".starts_with(&name)) {
                "literalpath".to_string()
            } else {
                name
            };
            // A value is taken only by a parameter that names a value one
            // and no switch: an unknown or ambiguous one (`-rf` to a native
            // `rm`, `-f`) leaves the next argument where a rule sees it.
            // The common parameters take one too (`-ErrorAction 0`), or its
            // value would be read as the path; `-Args` is left out, as it
            // is a cmdlet's own.
            let fulls = || {
                VALUES
                    .iter()
                    .chain(own.iter())
                    .chain(blocks::SHARED_VALUES.iter().filter(|full| **full != "args"))
            };
            let takes_value = colon
                || (!switches.contains(&name.as_str())
                    && (fulls().any(|full| *full == name)
                        || (fulls().any(|full| full.starts_with(&name))
                            && !SWITCHES.iter().any(|full| full.starts_with(&name)))));
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

    /// Whether a parameter was given with no value that may be a value
    /// parameter: a bare `-n` (`-Name`, read as a switch as it also starts
    /// `-NoNewline`) leaves its value among the positionals.
    pub(crate) fn unclear(&self) -> bool {
        let names = |fulls: &[&str], name: &str| fulls.iter().any(|full| full.starts_with(name));
        self.named.iter().any(|(name, value)| {
            let switch = names(&SWITCHES, name) && !names(&VALUES, name);
            value.is_none() && !name.is_empty() && !switch
        })
    }

    /// One cmdlet's arguments, read by its own parameters: each name given
    /// is resolved to the parameter it names (its name or alias, or a prefix
    /// of one), and only a parameter that takes a value takes the next
    /// argument. A name that fits several is read as the first of them in
    /// `own`, then the common parameters, so a cmdlet's own parameters win
    /// and what the cmdlet might take as a value is not left for a rule to
    /// see as something else. A name that fits none takes no value.
    pub(crate) fn cmdlet(args: &'a [Arg], own: &[Param]) -> Self {
        Self::bind(args, own, false)
    }

    /// `Start-Process`'s arguments (see [`START_PROCESS`]), read as
    /// [`Params::cmdlet`] reads them, but a parameter that takes a value
    /// takes the next argument whatever it is: a quoted string that starts
    /// with a dash (`-ArgumentList '-c x'`) is its value, and a parameter
    /// there is an error that stops the command.
    pub(crate) fn start_process(args: &'a [Arg]) -> Self {
        Self::bind(args, &START_PROCESS, true)
    }

    fn bind(args: &'a [Arg], own: &[Param], strict: bool) -> Self {
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
                    .is_some_and(|next| parameter(next).is_none() || colon || strict)
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

/// `Start-Process`'s parameters: every one that takes a value takes it, so
/// none is left where the program is read from (`-WindowStyle Hidden cmd`).
pub(crate) const START_PROCESS: [Param; 17] = [
    Param::value("filepath", &["pspath", "path"]),
    Param::value("argumentlist", &["args"]),
    Param::value("credential", &["runas"]),
    Param::value("workingdirectory", &[]),
    Param::value("verb", &[]),
    Param::value("windowstyle", &[]),
    Param::value("redirectstandardoutput", &["rso"]),
    Param::value("redirectstandarderror", &["rse"]),
    Param::value("redirectstandardinput", &["rsi"]),
    Param::value("environment", &[]),
    Param::switch("loaduserprofile", &["lup"]),
    Param::switch("nonewwindow", &["nnw"]),
    Param::switch("passthru", &[]),
    Param::switch("wait", &[]),
    Param::switch("usenewenvironment", &[]),
    Param::switch("whatif", &["wi"]),
    Param::switch("confirm", &["cf"]),
];

/// The parameters of `Set-Location`, `Push-Location` and `Pop-Location`:
/// `-StackName` takes a value, which is not the folder.
pub(crate) const LOCATION: [Param; 4] = [
    Param::value("path", &[]),
    Param::value("literalpath", &["pspath", "lp"]),
    Param::value("stackname", &[]),
    Param::switch("passthru", &[]),
];

/// Whether every argument of the location cmdlet `key` binds, so that it
/// runs: each parameter is its own or a common one, named once, and not a
/// prefix of more than one; a value parameter has its value; and it is given
/// no more folders than it takes (`Pop-Location` none, `Push-Location` one,
/// `Set-Location -StackName` none). One that does not bind stops the cmdlet
/// before it does anything, and the next statement still runs. A splat
/// (`@a`) may hold any of them, so it is not known to bind.
pub(crate) fn location_binds(args: &[Arg], key: &str) -> bool {
    // `Pop-Location` takes no folder: only `-StackName` and `-PassThru`.
    let own = if key == "pop-location" {
        &LOCATION[2..]
    } else {
        &LOCATION[..]
    };
    let all = || own.iter().chain(COMMON.iter());
    let mut seen: Vec<&str> = Vec::new();
    let mut folders = 0;
    let mut ended = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg.text().starts_with('@') && arg.is_unknown() {
            return false;
        }
        if !ended && arg.known() == Some("--") {
            ended = true;
            continue;
        }
        let Some(name) = parameter(arg).filter(|_| !ended) else {
            folders += 1;
            continue;
        };
        let colon = name.ends_with(':');
        let typed = name.trim_end_matches(':').to_ascii_lowercase();
        let exact =
            all().find(|param| param.name == typed || param.aliases.contains(&typed.as_str()));
        let mut prefixed = all().filter(|param| param.starts_with(&typed));
        let found = exact.or(match (prefixed.next(), prefixed.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        });
        let Some(param) = found else {
            return false;
        };
        if seen.contains(&param.name) {
            return false;
        }
        seen.push(param.name);
        if matches!(param.name, "path" | "literalpath") {
            folders += 1;
        }
        let value = if colon {
            iter.next()
        } else if param.value {
            iter.next_if(|next| parameter(next).is_none())
        } else {
            Some(arg)
        };
        if value.is_none() {
            return false;
        }
    }
    let most = usize::from(
        key == "push-location" || (key == "set-location" && !seen.contains(&"stackname")),
    );
    folders <= most
}

/// Whether a function or an alias named `name` stands in for a location
/// cmdlet (`Pop-Location`, `popd`, `global:cd`), which then may not run.
pub(crate) fn names_location(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let bare = ["global:", "script:", "local:", "private:"]
        .iter()
        .find_map(|scope| lower.strip_prefix(scope))
        .unwrap_or(&lower);
    matches!(
        canonical(bare),
        "set-location" | "push-location" | "pop-location"
    )
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

/// A parameter's name with its `-`, when `arg` is one. A word with white
/// space in it is a string, never a parameter (`'-c "x"'`).
fn parameter(arg: &Arg) -> Option<&str> {
    let text = arg.known()?;
    let name = text.strip_prefix('-')?;
    (name.starts_with(|c: char| c.is_ascii_alphabetic()) && !name.contains(char::is_whitespace))
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
    /// name in `tests/cases/windows.cases`.
    const PINNED: [&str; 46] = [
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
