//! Splitting a Windows command prompt line (`cmd.exe`) with
//! tree-sitter-batch.

use std::ops::Range;

use tree_sitter::Node;

use crate::launch;
use crate::unit::{self, Arg, OpensFrom, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    // The grammar ends every statement at a line break.
    let text = if text.ends_with('\n') {
        text.to_string()
    } else {
        format!("{text}\n")
    };
    let language = tree_sitter_batch::LANGUAGE.into();
    let Some(tree) = unit::parse(split, &text, &language) else {
        return;
    };
    assigned(split, tree.root_node(), &text);
    Walker {
        source: &text,
        depth,
        split,
    }
    .walk(tree.root_node(), None, 0);
}

/// `set TEMP=…`: a variable the line sets no longer names its usual place.
fn assigned(split: &mut Split, root: Node<'_>, text: &str) {
    let mut names = Vec::new();
    unit::for_each_node(root, |node| {
        if node.kind() == "variable_name"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "variable_assignment")
        {
            names.push(unit::text(&node, text).to_string());
        }
    });
    for name in names {
        split.reassign(&name);
        split.set(&name);
    }
}

struct Walker<'a> {
    source: &'a str,
    depth: usize,
    split: &'a mut Split,
}

impl Walker<'_> {
    fn walk(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return;
        }
        match node.kind() {
            "cmd" | "call_stmt" => {
                if !self.statement(node, stage, level) {
                    self.command(node, stage);
                    self.children(node, None, level);
                }
            }
            "pipe_stmt" => {
                let pipeline = self.split.pipeline(stage);
                self.pipe_in(node, pipeline, 0, level);
            }
            // The right side of `&&` and `||` may not run, and the right
            // side of `||` runs only when the left failed: a `cd` on the
            // left may not have moved the line.
            "cond_exec" => {
                let mut cursor = node.walk();
                let list = self.split.list_start();
                let mut at = 0;
                let mut exit = None;
                for child in node.children(&mut cursor) {
                    // When the right side of `||` ends cmd (`cd s || exit`),
                    // the rest of the line runs only where the left side
                    // took it.
                    if child.kind() == "||" {
                        if stage.is_none()
                            && child
                                .next_named_sibling()
                                .is_some_and(|right| self.exits(right))
                        {
                            exit = Some(self.split.exits_after());
                        }
                        self.split.list_or(&list);
                    }
                    if !child.is_named() {
                        continue;
                    }
                    // A `cd` on the right side runs only when the left let
                    // it: when it did not, the line may still be where that
                    // side began, or where the list did.
                    if at > 0 {
                        let link = self.split.link_start();
                        self.walk(child, stage, level + 1);
                        self.split.link_end(&list, link);
                        if let Some(exit) = exit.take() {
                            self.split.exited(exit);
                        }
                    } else {
                        self.split.list_head(child.kind() == "cond_exec");
                        self.walk(child, stage, level + 1);
                        self.split.list_head(false);
                    }
                    at += 1;
                }
                self.split.list_end(list);
            }
            // `cmd < f`, `cmd > f`, `< f cmd`: a file redirected onto the
            // command's input feeds the units it runs.
            "redirect_stmt" => {
                let mut cursor = node.walk();
                let mut inputs = Vec::new();
                let mut own: Option<Range<usize>> = None;
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                for child in children
                    .iter()
                    .filter(|child| child.kind() != "redirection")
                {
                    let first = self.split.units.len();
                    self.walk(*child, stage, level + 1);
                    let range = first..self.split.units.len();
                    own = Some(own.map_or(range.clone(), |own| own.start..range.end));
                }
                // The shell opens a redirect before the command runs, so a
                // command that moves the line (`cd sub > f`) is redirected
                // from the folder it starts in.
                let from = own
                    .clone()
                    .map_or(OpensFrom::Line, |own| self.split.starts_in(own, true));
                let before = self.split.open_from(from);
                for child in children
                    .iter()
                    .filter(|child| child.kind() == "redirection")
                {
                    inputs.extend(self.redirect(*child));
                }
                self.split.open_from(before);
                if let Some(own) = own {
                    for target in inputs {
                        self.split.redirect(own.clone(), target, true);
                    }
                }
            }
            "redirection" => {
                self.redirect(node);
            }
            "variable_assignment" => {
                self.assignment(node);
                self.children(node, stage, level);
            }
            "comment" => self.comment(node),
            // `for %%i in (…) do …`: what it does runs once for each item.
            "for_stmt" => {
                self.split.repeats += 1;
                self.children(node, stage, level);
                self.split.repeats -= 1;
            }
            // What a condition guards may not run.
            "if_stmt" => {
                self.split.branches += 1;
                self.children(node, stage, level);
                self.split.branches -= 1;
            }
            _ => self.children(node, stage, level),
        }
    }

    /// The grammar reads an `if` or a `for` only at the start of a line:
    /// after `&&`, `||` or `|` (`ver && if exist q rd /s /q C:\x`) it is a
    /// command named `if` whose condition and body are its arguments. Nor
    /// does it read a `call`, `if` or `for` spelled with carets (`ca^ll`,
    /// `i^f`), which cmd takes off first, or a `call` that a `call` runs
    /// (`call call rd …`, a `call` of the program `call`). cmd reads each as
    /// the statement it is, so the command's text (from the second `call`,
    /// in the last case) is split again on its own, the carets of its first
    /// word taken off, where the grammar reads it as one. Returns whether it
    /// was. An `if` or a `for` with no carets that already starts the text
    /// it was split from is not split again: the grammar would read it the
    /// same way. The text split again counts against the line's budget of
    /// nested text, so a command that holds another such command, and so
    /// on, cannot make the line be read again and again.
    fn statement(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) -> bool {
        let call = node.kind() == "call_stmt";
        let Some((word, _)) = parts(node) else {
            return false;
        };
        let Some(range) = span(&word) else {
            return false;
        };
        let raw = self.source.get(range.clone()).unwrap_or_default();
        let bare = unescape(raw);
        let is =
            |text: &str, names: &[&str]| names.iter().any(|name| name.eq_ignore_ascii_case(text));
        let spelled = !raw.contains('"')
            && if call {
                is(&bare, &["call"])
            } else {
                raw.contains('^') && is(&bare, &["call", "if", "for"])
            };
        let name = word
            .first()
            .filter(|name| name.kind() == "command_name")
            .map(|name| unit::text(name, self.source))
            .unwrap_or_default();
        let later = !call && node.start_byte() != 0 && is(name, &["if", "for"]);
        if !spelled && !later {
            return false;
        }
        let from = if call { range.start } else { node.start_byte() };
        let text = if spelled {
            let before = self.source.get(from..range.start).unwrap_or_default();
            let after = self
                .source
                .get(range.end..node.end_byte())
                .unwrap_or_default();
            format!("{before}{bare}{after}\n")
        } else {
            let command = self.source.get(from..node.end_byte()).unwrap_or_default();
            format!("{command}\n")
        };
        if !unit::read_again(
            self.split,
            &text,
            "reads too many of its commands again to judge",
        ) {
            return true;
        }
        let language = tree_sitter_batch::LANGUAGE.into();
        if let Some(tree) = unit::parse(self.split, &text, &language) {
            assigned(self.split, tree.root_node(), &text);
            Walker {
                source: &text,
                depth: self.depth,
                split: self.split,
            }
            .walk(tree.root_node(), stage, level + 1);
        }
        true
    }

    /// The stages of `node`, numbered from `first` in `pipeline`, and the
    /// number after the last. The grammar nests `a | b | c` as
    /// `(a | b) | c`: the inner pipe is part of the same pipeline.
    fn pipe_in(&mut self, node: Node<'_>, pipeline: usize, first: usize, level: usize) -> usize {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return first;
        }
        let mut next = first;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "pipe_stmt" {
                next = self.pipe_in(child, pipeline, next, level + 1);
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

    fn children(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk(child, stage, level + 1);
        }
    }

    /// The grammar also reads an unmatched quote, `<#` or `%#` as a comment
    /// running to the end of the line, though cmd still runs what the
    /// comment holds. A comment that is not a `rem` or `::` and holds a
    /// command separator or a redirect cannot be read.
    fn comment(&mut self, node: Node<'_>) {
        let text = unit::text(&node, self.source);
        let head = text
            .trim_start()
            .trim_start_matches('@')
            .to_ascii_lowercase();
        let remark = head == "rem"
            || head.starts_with("rem ")
            || head.starts_with("rem\t")
            || head.starts_with("::");
        if !remark && text.contains(['&', '|', '<', '>']) {
            self.split
                .problem(Rule::Unreadable, "cannot be read in full", None);
        }
    }

    /// Whether `node`, the right side of an `||`, ends cmd: `exit` (with
    /// `/b` too, which outside a batch file ends cmd), alone or last in a
    /// `( … )` block, which runs in cmd itself. Not `exit /?`, which only
    /// prints its help, nor any argument with `/?` in it (`exit /b/?`).
    fn exits(&self, node: Node<'_>) -> bool {
        let mut node = node;
        loop {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor);
            match node.kind() {
                "exit_stmt" => return true,
                "cmd" => {
                    let mut name = false;
                    let mut help = false;
                    for child in children {
                        match child.kind() {
                            "command_name" => {
                                name = unit::text(&child, self.source).eq_ignore_ascii_case("exit");
                            }
                            "argument_list" => {
                                let mut cursor = child.walk();
                                help = child.named_children(&mut cursor).any(|argument| {
                                    unit::text(&argument, self.source).contains("/?")
                                });
                            }
                            _ => {}
                        }
                    }
                    return name && !help;
                }
                "parenthesized" | "command_sep" => match children.last() {
                    Some(last) => node = last,
                    None => return false,
                },
                _ => return false,
            }
        }
    }

    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) {
        let Some((word, after)) = parts(node) else {
            return;
        };
        let (args, spans) = self.args(&after);
        let units: Vec<Unit> = self
            .word(&word)
            .into_iter()
            .map(|reading| self.unit(reading, args.clone(), spans.clone(), &after, stage))
            .collect();
        launch::add_readings(self.split, units, self.depth);
    }

    /// The unit of `reading`, the program and what is left of its word, and
    /// then `args`, the arguments after the word, made of the grammar's
    /// `pieces`; `spans` are where each argument is in the source.
    fn unit(
        &self,
        reading: Reading,
        mut args: Vec<Arg>,
        mut spans: Vec<Range<usize>>,
        pieces: &[Node<'_>],
        stage: Option<Stage>,
    ) -> Unit {
        let Reading { program, first } = reading;
        // `start "title" program …`: cmd takes a first quoted argument as
        // the window's title, which the values here no longer show.
        let title =
            first.is_empty() && pieces.first().is_some_and(|first| first.kind() == "string");
        for (at, (first, span)) in first.into_iter().enumerate() {
            args.insert(at, first);
            spans.insert(at, span);
        }
        let key = program
            .known()
            .map(|program| unit::key(program, Shell::Cmd));
        if matches!(key.as_deref(), Some("cd" | "chdir" | "pushd")) {
            self.one_folder(&mut args, &spans);
        }
        if program
            .known()
            .is_some_and(|program| program.eq_ignore_ascii_case("start"))
            && args.len() >= 2
            && title
        {
            args.remove(0);
        }
        Unit::new(Shell::Cmd, program, args, stage)
    }

    /// How cmd reads a command's first word, made of the touching `pieces`:
    /// each program it may name, with what is left of the word as its first
    /// arguments.
    ///
    /// cmd ends the name at the first `,`, `;` or `=` outside quotes, as it
    /// does at a space, and skips them before the name: `shutdown,/s` is
    /// `shutdown /s`. The name is then read by [`Self::name`].
    fn word(&self, pieces: &[Node<'_>]) -> Vec<Reading> {
        let Some(range) = span(pieces) else {
            return vec![Reading::program(Arg::Unknown(String::new()))];
        };
        let whole = self.source.get(range.clone()).unwrap_or_default();
        let raw = whole.trim_start_matches(DELIMITERS);
        let start = range.start + (whole.len() - raw.len());
        if raw.is_empty() {
            return vec![Reading::program(Arg::Unknown(whole.to_string()))];
        }
        let (name, rest) = match find_unquoted(raw, |c| DELIMITERS.contains(&c)) {
            Some(end) => {
                let after = raw[end..].trim_start_matches(DELIMITERS);
                let from = start + (raw.len() - after.len());
                let rest = (!after.is_empty()).then(|| (self.known(after), from..range.end));
                (&raw[..end], rest)
            }
            None => (raw, None),
        };
        let mut readings = self.name(name, start);
        if let Some(rest) = rest {
            for reading in &mut readings {
                reading.first.push(rest.clone());
            }
        }
        readings
    }

    /// How cmd reads a command's name, `raw`, which is at `start` in the
    /// source.
    ///
    /// A name in quotes is a program's path. Otherwise cmd looks for one
    /// of its built-in commands at the start of the name, with the carets
    /// taken off (`r^d` is `rd`): the whole name, or the part before the
    /// first `+`, `/`, `[`, `]` or `(` (`rd/s`, `echo(x`), or the part
    /// before the first `.`, `\` or `:` (`echo.x`, `cd..`, `cd\x`). The
    /// rest of the name is the built-in's first argument; `echo` drops the
    /// one character after its name. In the last case cmd runs the file the
    /// name names instead when there is one, which only the disk can say: a
    /// name that names a program (`dir.bat`,
    /// `echo\..\..\Windows\System32\shutdown.exe`) is read both ways. A name
    /// that starts with no built-in is the path of a program (see
    /// [`Self::path`]).
    fn name(&self, raw: &str, start: usize) -> Vec<Reading> {
        if raw.contains('"') {
            return self.path(raw, start);
        }
        // Each character as cmd reads it, carets taken off, and where it is
        // in `raw`.
        let mut chars = Vec::new();
        let mut iter = raw.char_indices();
        while let Some((at, c)) = iter.next() {
            if c == '^' {
                if let Some(next) = iter.next() {
                    chars.push(next);
                }
            } else {
                chars.push((at, c));
            }
        }
        let text: String = chars.iter().map(|(_, c)| *c).collect();
        let prefix = |end: usize| -> String { chars[..end].iter().map(|(_, c)| *c).collect() };
        let find = |set: &[char]| chars.iter().position(|(_, c)| set.contains(c));
        let built_in = if is_built_in(&text) {
            Some((chars.len(), false))
        } else {
            find(&['+', '/', '[', ']', ',', ';', '=', '('])
                .filter(|end| is_built_in(&prefix(*end)))
                .map(|end| (end, false))
                .or_else(|| {
                    find(&['.', '\\', ':'])
                        .filter(|end| is_built_in(&prefix(*end)))
                        .map(|end| (end, true))
                })
        };
        let Some((end, maybe_file)) = built_in else {
            return self.path(raw, start);
        };
        let name = prefix(end);
        // `echo.x` says `x`.
        let skip = usize::from(name.eq_ignore_ascii_case("echo"));
        let first = chars
            .get(end + skip)
            .map(|(at, _)| (self.known(&raw[*at..]), start + at..start + raw.len()));
        let mut readings = vec![Reading {
            program: Arg::Known(name),
            first: first.into_iter().collect(),
        }];
        if maybe_file {
            readings.extend(
                self.path(raw, start)
                    .into_iter()
                    .filter(|reading| reading.program.known().is_some_and(names_program)),
            );
        }
        readings
    }

    /// The programs a name that starts with no built-in, `raw` at `start`
    /// in the source, may run: a path, with the variables put in and the
    /// quotes taken off, judged by its last part (`C:\Windows\System32\cmd.exe`
    /// is `cmd`). A `/` outside the quotes ends the name (`cmd/c`,
    /// `"C:\x\cmd.exe"/c`) and starts the first argument, unless it follows
    /// a drive (`C:/Windows/System32/shutdown.exe` is `shutdown`). After a
    /// folder in a name with no quotes (`C:\Windows/System32/shutdown.exe`)
    /// it may be either, so both are read. A bare drive (`D:`) is the
    /// program `D` given `:`, as the grammar reads it.
    fn path(&self, raw: &str, start: usize) -> Vec<Reading> {
        let end = start + raw.len();
        let whole = self.known(raw);
        if let Some(drive) = whole.known().filter(|text| is_drive(text)) {
            return vec![Reading {
                program: Arg::Known(drive[..1].to_string()),
                first: vec![(Arg::Known(":".to_string()), end.saturating_sub(1)..end)],
            }];
        }
        let whole = Reading::program(whole);
        let Some(at) = find_unquoted(raw, |c| c == '/').filter(|at| *at > 0) else {
            return vec![whole];
        };
        let before = self.known(&raw[..at]);
        if before.known().is_some_and(is_drive) {
            return vec![whole];
        }
        let folder = !raw[..at].contains('"')
            && (raw[..at].contains(['\\', ':'])
                || before
                    .known()
                    .is_some_and(|text| text.contains(['\\', ':'])));
        let cut = Reading {
            program: before,
            first: vec![(self.known(&raw[at..]), start + at..end)],
        };
        if folder {
            vec![cut, whole]
        } else {
            vec![cut]
        }
    }

    /// `text` with the quotes taken off and the variables that name a known
    /// place put in, or only known when it runs.
    fn known(&self, text: &str) -> Arg {
        expand(&text.replace('"', ""), self.split)
            .map_or_else(|| Arg::Unknown(text.to_string()), Arg::Known)
    }

    /// The arguments of a list. cmd splits arguments at spaces only, so the
    /// pieces the grammar gives that touch (`%USERPROFILE%` and `\x`) are
    /// one argument.
    fn args(&self, pieces: &[Node<'_>]) -> (Vec<Arg>, Vec<Range<usize>>) {
        let mut args = Vec::new();
        let mut spans = Vec::new();
        let mut group: Vec<Node<'_>> = Vec::new();
        for &piece in pieces {
            if group
                .last()
                .is_some_and(|last| last.end_byte() != piece.start_byte())
            {
                args.push(self.value(&group));
                spans.extend(span(&group));
                group.clear();
            }
            group.push(piece);
        }
        if !group.is_empty() {
            args.push(self.value(&group));
            spans.extend(span(&group));
        }
        (args, spans)
    }

    /// The operands of a cmd `cd` (`chdir`, `pushd`) written with more than
    /// one word (`cd My Folder`) as the one folder cmd reads: the words
    /// joined as written, the spaces between them kept and none after the
    /// last. A word known only when it runs, or a later `/d`, which cmd may
    /// read as the switch, leaves the folder known only when it runs. The
    /// operands are the `args` from the first that is no switch; `spans` are
    /// where each is in the source.
    fn one_folder(&self, args: &mut Vec<Arg>, spans: &[Range<usize>]) {
        let first = args
            .iter()
            .position(|arg| !arg.known().is_some_and(unit::is_switch));
        let Some(first) = first.filter(|first| first + 1 < args.len()) else {
            return;
        };
        let (Some(start), Some(end)) = (spans.get(first), spans.last()) else {
            return;
        };
        let written = self
            .source
            .get(start.start..end.end)
            .unwrap_or_default()
            .to_string();
        let mut joined = Some(String::new());
        for (at, arg) in args.iter().enumerate().skip(first) {
            let gap = at
                .checked_sub(1)
                .filter(|before| *before >= first)
                .and_then(|before| {
                    self.source
                        .get(spans.get(before)?.end..spans.get(at)?.start)
                })
                .unwrap_or_default();
            joined = match (joined, arg.known()) {
                (Some(mut text), Some(word))
                    if !(at > first && word.eq_ignore_ascii_case("/d")) =>
                {
                    text.push_str(gap);
                    text.push_str(word);
                    Some(text)
                }
                _ => None,
            };
        }
        args.truncate(first);
        args.push(joined.map_or_else(|| Arg::Unknown(written), Arg::Known));
    }

    /// One argument made of touching pieces.
    fn value(&self, pieces: &[Node<'_>]) -> Arg {
        let source = match (pieces.first(), pieces.last()) {
            (Some(first), Some(last)) => self
                .source
                .get(first.start_byte()..last.end_byte())
                .unwrap_or_default(),
            _ => "",
        };
        let mut value = String::new();
        for piece in pieces {
            let text = unit::text(piece, self.source);
            let text = match piece.kind() {
                "string" => text
                    .strip_prefix('"')
                    .map_or(text, |inner| inner.strip_suffix('"').unwrap_or(inner)),
                "command_name" | "command_option" | "argument_value" | "variable_reference"
                | "redirect_target" => text,
                _ => return Arg::Unknown(source.to_string()),
            };
            match expand(text, self.split) {
                Some(text) => value.push_str(&text),
                None => return Arg::Unknown(source.to_string()),
            }
        }
        Arg::Known(value)
    }

    /// A redirect's target with its quotes taken off, as cmd takes them off
    /// before it opens the file: `< "C:\Users\me\.ssh\id_rsa"` reads the
    /// file the unquoted word names.
    fn quoted_value(&self, target: Node<'_>) -> Arg {
        // The grammar ends the target at a space inside the quotes; cmd ends it
        // at the closing quote.
        let rest = self.source.get(target.start_byte()..).unwrap_or_default();
        let source = match rest.strip_prefix('"').and_then(|inner| inner.find('"')) {
            Some(close) => &rest[..close + 2],
            None => unit::text(&target, self.source),
        };
        let unquoted = source.replace('"', "");
        match expand(&unquoted, self.split) {
            Some(text) => Arg::Known(text),
            None => Arg::Unknown(source.to_string()),
        }
    }

    /// A redirect that writes to a file: `>`, `>>`, `2>`. A duplication
    /// (`2>&1`) writes nothing. Returns the files it reads (`<`), and notes each read.
    fn redirect(&mut self, node: Node<'_>) -> Vec<Arg> {
        let mut cursor = node.walk();
        let mut operator = None;
        let mut inputs = Vec::new();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "redirect_op" => operator = Some(unit::text(&child, self.source)),
                "redirect_target" => {
                    let target_text = unit::text(&child, self.source);
                    let duplicates = operator.is_some_and(|op| op.ends_with('&'));
                    let writes = operator.is_some_and(|op| op.contains('>') && !duplicates);
                    if writes && !target_text.starts_with('&') {
                        self.split.write(Shell::Cmd, self.value(&[child]));
                    }
                    // `<` and `0<`.
                    if operator.is_some_and(|op| {
                        op.trim_start_matches(|c: char| c.is_ascii_digit()) == "<"
                    }) {
                        self.split.read(Shell::Cmd, self.quoted_value(child));
                    }
                    if !duplicates && operator.is_some_and(|op| op.contains('<')) {
                        inputs.push(self.value(&[child]));
                    }
                }
                _ => {}
            }
        }
        inputs
    }

    /// The grammar reads `set X=1 && del y` as one assignment whose value
    /// is everything after `=`; cmd ends the value at an unquoted `&` or
    /// `|`. What follows is split again, so nothing hides in a value.
    fn assignment(&mut self, node: Node<'_>) {
        let text = unit::text(&node, self.source);
        if let Some(at) = unquoted_operator(text) {
            let rest = text[at..].trim_start_matches(['&', '|', ' ', '\t']);
            if !rest.is_empty() {
                unit::script(self.split, rest, Shell::Cmd, self.depth + 1);
            }
        }
    }
}

/// The characters that end a command's name as a space does.
const DELIMITERS: &[char] = &[',', ';', '='];

/// The pieces of a command's first word and the pieces after it. The
/// grammar ends a command's name where cmd does not
/// (`C:\Windows\System32\cmd.exe` is `C` given `:\Windows…`, `r^d` is `r`
/// given `^d`): the name and the pieces that touch it are the word.
fn parts(node: Node<'_>) -> Option<(Vec<Node<'_>>, Vec<Node<'_>>)> {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
    // `call %X%` names its program with a variable: the first piece is
    // the program whatever its kind, so no command goes unread.
    let name = children
        .iter()
        .find(|child| child.kind() == "command_name")
        .or_else(|| {
            children
                .iter()
                .find(|child| child.kind() != "argument_list")
        })?;
    let pieces: Vec<Node<'_>> = children
        .iter()
        .find(|child| child.kind() == "argument_list")
        .map(|list| {
            let mut cursor = list.walk();
            list.named_children(&mut cursor).collect()
        })
        .unwrap_or_default();
    let mut word = vec![*name];
    for piece in &pieces {
        if word
            .last()
            .is_some_and(|last| last.end_byte() == piece.start_byte())
        {
            word.push(*piece);
        } else {
            break;
        }
    }
    let after = pieces.get(word.len() - 1..).unwrap_or_default().to_vec();
    Some((word, after))
}

/// Where the first character of `text` that `stop` takes is, outside
/// double quotes and `%…%` (cmd puts a variable's value in before it reads
/// the word) and not escaped with `^`.
fn find_unquoted(text: &str, stop: impl Fn(char) -> bool) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    let mut skip = 0;
    for (at, c) in text.char_indices() {
        if at < skip {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '^' => escaped = true,
            '%' => {
                if let Some(close) = text[at + 1..].find('%') {
                    skip = at + close + 2;
                }
            }
            _ if stop(c) => return Some(at),
            _ => {}
        }
    }
    None
}

/// An argument and where it is in the source.
type Placed = (Arg, Range<usize>);

/// One way cmd may read a command's first word (see [`Walker::word`]).
struct Reading {
    /// The program it names.
    program: Arg,
    /// What is left of the word, the program's first arguments, and where
    /// each is in the source.
    first: Vec<Placed>,
}

impl Reading {
    fn program(program: Arg) -> Self {
        Self {
            program,
            first: Vec::new(),
        }
    }
}

/// cmd's built-in commands: the ones it finds at the start of a longer word
/// (`echo.`, `cd..`, `rd/s`).
const BUILT_INS: &[&str] = &[
    "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "dpath",
    "echo", "endlocal", "erase", "exit", "for", "ftype", "goto", "if", "keys", "md", "mkdir",
    "mklink", "move", "path", "pause", "popd", "prompt", "pushd", "rd", "rem", "ren", "rename",
    "rmdir", "set", "setlocal", "shift", "start", "time", "title", "type", "ver", "verify", "vol",
];

fn is_built_in(name: &str) -> bool {
    BUILT_INS
        .iter()
        .any(|built_in| built_in.eq_ignore_ascii_case(name))
}

/// Whether `text` is a drive: a letter and a colon.
fn is_drive(text: &str) -> bool {
    matches!(text.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic())
}

/// Whether `path` names a program: it ends in an extension cmd runs.
pub(crate) fn names_program(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".exe", ".com", ".bat", ".cmd"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

/// The bytes of the source that the touching `pieces` cover.
fn span(pieces: &[Node<'_>]) -> Option<Range<usize>> {
    Some(pieces.first()?.start_byte()..pieces.last()?.end_byte())
}

/// Where the first `&` or `|` outside double quotes and not escaped with
/// `^` is.
fn unquoted_operator(text: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '^' => escaped = true,
            '"' => quoted = !quoted,
            '&' | '|' if !quoted => return Some(at),
            _ => {}
        }
    }
    None
}

/// `text` with cmd's escapes taken off (`^&` is `&`) and the variables that
/// name a known place put in; `None` when any other variable (`%X%`, `%%f`,
/// `!X!`), or one the line sets, makes it known only when it runs.
fn expand(text: &str, split: &Split) -> Option<String> {
    let text = unescape(text);
    if text.matches('!').count() >= 2 {
        return None;
    }
    let mut value = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        value.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find('%')?;
        let name = &after[..end];
        if split.reassigned(name) {
            return None;
        }
        value.push_str(place(name)?);
        rest = &after[end + 1..];
    }
    value.push_str(rest);
    Some(value)
}

/// The variables that name a known place, as paths the resolver reads.
fn place(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "userprofile" => "~",
        "cd" => ".",
        "temp" | "tmp" => "~\\AppData\\Local\\Temp",
        "appdata" => "~\\AppData\\Roaming",
        "localappdata" => "~\\AppData\\Local",
        "systemroot" | "windir" => "C:\\Windows",
        "systemdrive" => "C:",
        "programfiles" => "C:\\Program Files",
        "programfiles(x86)" => "C:\\Program Files (x86)",
        "programdata" => "C:\\ProgramData",
        _ => return None,
    })
}

/// cmd's escape character is `^`: `^&` is `&`.
fn unescape(text: &str) -> String {
    let mut value = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '^' {
            if let Some(next) = chars.next() {
                value.push(next);
            }
        } else {
            value.push(c);
        }
    }
    value
}
