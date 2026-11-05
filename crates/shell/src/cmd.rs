//! Splitting a Windows command prompt line (`cmd.exe`) with
//! tree-sitter-batch.

use std::ops::Range;

use tree_sitter::Node;

use crate::launch;
use crate::path;
use crate::powershell::native;
use crate::startup;
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
    let Some(tree) = unit::parse(split, &text, &language, unit::Recovery::Cheap) else {
        return;
    };
    assigned(split, tree.root_node(), &text);
    let mut walker = Walker {
        source: &text,
        depth,
        input: false,
        tail: false,
        loops: Vec::new(),
        split,
    };
    walker.walk(tree.root_node(), None, 0);
    walker.close_loops();
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
    /// Whether the commands being walked have a file redirected onto their
    /// input (`python < x.py`, `(python) < x.py`).
    input: bool,
    /// The `for` loops whose command goes on past where the grammar ends
    /// it, each with the node it ends with (see [`Walker::open_loop`]):
    /// `None` for one that ends with the statement this text was split
    /// from.
    loops: Vec<Option<usize>>,
    /// Whether the text is the rest of a longer statement, split again on
    /// its own (see [`Self::statement`]).
    tail: bool,
    split: &'a mut Split,
}

impl Walker<'_> {
    fn walk(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        if level > unit::MAX_TREE_DEPTH {
            self.split
                .problem(Rule::Unreadable, "nests too deeply to read", None);
            return;
        }
        // The right side of an `&&` after a statement runs when it
        // succeeded, whatever a `cd` before it did (see
        // [`Split::statement`]).
        if matches!(
            node.kind(),
            "pipe_stmt"
                | "cond_exec"
                | "redirect_stmt"
                | "variable_assignment"
                | "for_stmt"
                | "if_stmt"
        ) {
            self.split.statement();
        }
        match node.kind() {
            "cmd" | "call_stmt" => self.command_node(node, stage, level),
            "pipe_stmt" => {
                let pipeline = self.split.pipeline(stage);
                self.pipe_in(node, pipeline, 0, level);
            }
            // The right side of `&&` and `||` may not run, and the right
            // side of `||` runs only when the left failed: a `cd` on the
            // left may not have moved the line.
            "cond_exec" => self.cond_node(node, stage, level),
            // `cmd < f`, `cmd > f`, `< f cmd`: a file redirected onto the
            // command's input feeds the units it runs.
            "redirect_stmt" => self.redirected_node(node, stage, level),
            "redirection" => {
                self.redirect(node);
            }
            "variable_assignment" => {
                self.assignment(node);
                self.children(node, stage, level);
            }
            "comment" => self.comment(node, level),
            // `for %%i in (…) do …`: what it does runs once for each item.
            "for_stmt" => self.for_node(node, stage, level),
            // What a condition guards may not run.
            "if_stmt" => {
                self.split.branches += 1;
                self.children(node, stage, level);
                self.split.branches -= 1;
            }
            _ => self.children(node, stage, level),
        }
        while self.loops.last() == Some(&Some(node.id())) {
            self.loops.pop();
            self.end_loop();
        }
    }

    /// A command, or a `call`. An arm of [`Self::walk`], kept out of its frame,
    /// which nests as deep as the tree.
    #[inline(never)]
    fn command_node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        if !self.statement(node, stage, level) {
            self.command(node, stage);
            self.children(node, None, level);
        }
    }

    /// Commands joined by `&&` and `||`. An arm of [`Self::walk`], kept out of
    /// its frame, which nests as deep as the tree.
    #[inline(never)]
    fn cond_node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
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

    /// A redirected statement. An arm of [`Self::walk`], kept out of its frame,
    /// which nests as deep as the tree.
    #[inline(never)]
    fn redirected_node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let mut cursor = node.walk();
        let mut inputs = Vec::new();
        let mut own: Option<Range<usize>> = None;
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // What the commands read from their input is the file: an
        // interpreter runs it (`python < x.py`).
        let outer = self.input;
        self.input |= children
            .iter()
            .any(|child| child.kind() == "redirection" && self.reads_input(*child));
        for child in children
            .iter()
            .filter(|child| child.kind() != "redirection")
        {
            let first = self.split.units.len();
            self.walk(*child, stage, level + 1);
            let range = first..self.split.units.len();
            own = Some(own.map_or(range.clone(), |own| own.start..range.end));
        }
        self.input = outer;
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

    /// A `for` loop. An arm of [`Self::walk`], kept out of its frame, which
    /// nests as deep as the tree.
    #[inline(never)]
    fn for_node(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        self.split.repeats += 1;
        self.split.begin_body();
        self.children(node, stage, level);
        self.open_loop(node);
    }

    /// Note that the `for` loop `node` has been read as far as the grammar
    /// takes it. cmd reads the whole rest of the statement after `do` as
    /// its command, past `&`, `&&` and `||` (`for %%i in (1 2) do rd /s /q
    /// build & cd ..` runs the `cd` on each pass), where the grammar ends it
    /// at the first: the loop ends with the list it is the start of, or,
    /// when the text is the rest of a longer statement (see
    /// [`Self::tail`]), with that statement.
    fn open_loop(&mut self, node: Node<'_>) {
        let mut end = None;
        let mut at = node;
        while let Some(parent) = at
            .parent()
            .filter(|parent| matches!(parent.kind(), "command_sep" | "cond_exec"))
        {
            end = Some(parent.id());
            at = parent;
        }
        match end {
            Some(end) => self.loops.push(Some(end)),
            None if self.tail && at.end_byte() + 1 >= self.source.len() => {
                self.loops.push(None);
            }
            None => self.end_loop(),
        }
    }

    /// Note that a `for` loop's command has been read to its end.
    fn end_loop(&mut self) {
        self.split.end_body(None);
        self.split.repeats -= 1;
    }

    /// End every loop still open once the line is read.
    fn close_loops(&mut self) {
        while self.loops.pop().is_some() {
            self.end_loop();
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
    /// word taken off, where the grammar reads it as one; a `,`, `;` or `=`
    /// ends that word as a space does (`ca^ll,rd` is `call rd`). Returns
    /// whether it was. An `if` or a `for` with no carets that already starts the text
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
        // cmd skips the `,`, `;` and `=` before the name and ends it at the
        // first one after, as at a space (see `Self::word`): `ca^ll,,rd` is
        // `call rd`.
        let whole = self.source.get(range.clone()).unwrap_or_default();
        let raw = whole.trim_start_matches(DELIMITERS);
        let (raw, rest) = match find_unquoted(raw, |c| DELIMITERS.contains(&c)) {
            Some(end) => (&raw[..end], raw[end..].trim_start_matches(DELIMITERS)),
            None => (raw, ""),
        };
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
            let rest = if rest.is_empty() {
                String::new()
            } else {
                format!(" {rest}")
            };
            format!("{before}{bare}{rest}{after}\n")
        } else {
            let command = self.source.get(from..node.end_byte()).unwrap_or_default();
            format!("{command}\n")
        };
        self.read_again(node, &text, stage, level);
        true
    }

    /// Split `text`, the text of `node` as cmd reads it, again on its own,
    /// as the rest of the statement `node` ends. The text split again
    /// counts against the line's budget of nested text.
    fn read_again(&mut self, node: Node<'_>, text: &str, stage: Option<Stage>, level: usize) {
        if !unit::read_again(
            self.split,
            text,
            "reads too many of its commands again to judge",
        ) {
            return;
        }
        let language = tree_sitter_batch::LANGUAGE.into();
        if let Some(tree) = unit::parse(self.split, text, &language, unit::Recovery::Cheap) {
            assigned(self.split, tree.root_node(), text);
            let mut walker = Walker {
                source: text,
                depth: self.depth,
                input: self.input,
                tail: true,
                loops: Vec::new(),
                split: self.split,
            };
            walker.walk(tree.root_node(), stage, level + 1);
            // A loop whose command goes on to the end of the text goes on
            // with the statement it was split from.
            let open = walker.loops.len();
            for _ in 0..open {
                self.open_loop(node);
            }
        }
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

    /// A comment the grammar reads. cmd skips only two kinds: the `rem`
    /// command (`rem`, `@rem`, in any case, then a space, a tab or the end
    /// of the line), which skips the rest of the line, `&` and `|` and all,
    /// and `::` at the start of a statement, a label that never runs. The
    /// grammar reads more as a comment running to the end of the line, all
    /// text cmd runs: `<#` and `%#…#%` (a redirect and a variable to cmd),
    /// a `:` that `::` does not start, a `::` after a label in a `( … )`
    /// block (cmd runs the line after a label there as a command), and any
    /// line with `'VBS` after a space or a tab (a marker for files that are
    /// also Visual Basic scripts; to cmd, one more argument). A line with
    /// `'VBS` is read again with a caret before each `'VBS` outside quotes,
    /// which cmd takes off, so the grammar reads the command it is (see
    /// [`vbs_read`]); any other is unreadable. After `goto`'s label the
    /// comment is words `goto` ignores, but cmd still ends the statement at
    /// a `&`, `|` or redirect in them: such words cannot be read.
    fn comment(&mut self, node: Node<'_>, level: usize) {
        let text = unit::text(&node, self.source);
        if node
            .parent()
            .is_some_and(|parent| parent.kind() == "goto_stmt")
        {
            if text.contains(['&', '|', '<', '>']) {
                self.split
                    .problem(Rule::Unreadable, "cannot be read in full", None);
            }
            return;
        }
        if is_rem(text) || (text.starts_with("::") && !after_label(node, self.source)) {
            return;
        }
        match vbs_read(text) {
            Some(again) => self.read_again(node, &format!("{again}\n"), None, level),
            None => self
                .split
                .problem(Rule::Unreadable, "cannot be read in full", None),
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

    /// A command as the program its first word names. A `call`, `if` or
    /// `for` read here is one [`Self::statement`] did not read as the
    /// statement it is, spelled in a way it does not know (`call^,rd`): what
    /// it runs cannot be read. A `call` of a label (`call:sub`) runs no
    /// program.
    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) {
        let Some((word, after)) = parts(node) else {
            return;
        };
        let (args, spans) = self.args(&after);
        let mut readings = self.word(&word);
        // `call.bat`, `for.exe`: the built-in cmd may read before the dot.
        let mut called = Vec::new();
        readings.retain(|reading| {
            if !reading.before_dot {
                return true;
            }
            match reading
                .program
                .known()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("call") => match self.called(reading) {
                    Some(more) => {
                        called.extend(more);
                        false
                    }
                    None => true,
                },
                Some("for") => !self.bad_for(reading, &args),
                _ => true,
            }
        });
        readings.extend(called);
        let statement = readings.iter().any(|reading| {
            let name = reading.program.known().map(str::to_ascii_lowercase);
            match name.as_deref() {
                Some("if" | "for") => true,
                Some("call") => !reading
                    .first
                    .first()
                    .and_then(|(first, _)| first.known())
                    .is_some_and(|first| first.starts_with(':')),
                _ => false,
            }
        });
        if statement {
            self.split.problem(
                Rule::Unreadable,
                "runs a call, if or for that cannot be read",
                None,
            );
        }
        let mut units = Vec::new();
        for reading in readings {
            let raw = raw_arguments(&reading, &after).and_then(|range| self.source.get(range));
            let mut unit = self.unit(reading, args.clone(), spans.clone(), &after, stage);
            if let Some(raw) = raw {
                self.own_split(&mut unit, raw);
            }
            units.push(unit);
        }
        launch::add_readings(self.split, units, self.depth);
    }

    /// What a `call` that cmd may read before a `.`, `\` or `:` of its
    /// word runs (`call.bat x`): the program the rest of the word names,
    /// read with the character that ends the built-in's name (`.bat`, or
    /// `\..\Windows\System32\shutdown.exe`, a path) and without it, as
    /// `echo.` drops it (`bat`, or a built-in: `call.rd /s /q C:\x` runs
    /// `rd`). `None` when the rest is not known or is that character alone.
    fn called(&self, reading: &Reading) -> Option<Vec<Reading>> {
        let (first, span) = reading.first.first()?;
        first.known()?;
        let word = self.source.get(span.clone())?;
        let mut chars = word.char_indices();
        chars.next();
        let (at, _) = chars.next()?;
        let mut readings = self.path(word, span.start);
        readings.extend(self.name(&word[at..], span.start + at));
        Some(readings)
    }

    /// Whether a `for` that cmd may read before a `.`, `\` or `:` of its
    /// word (`for.exe`) is one it refuses: the word after the name, read
    /// with the character that ends the name or without it, starts neither
    /// a loop variable (`%`) nor an option (`/`), so cmd reports a syntax
    /// error and runs nothing for it. The rest of the word must be one
    /// piece the line shows whole: a word with a part only known when it
    /// runs, or quoted or expanded apart (`for.;%i in (1) do …`), may start a
    /// loop variable after the delimiters, and so keeps the built-in reading.
    fn bad_for(&self, reading: &Reading, args: &[Arg]) -> bool {
        let [(first, _)] = reading.first.as_slice() else {
            return false;
        };
        let Some(first) = first.known() else {
            return false;
        };
        let dropped = first.get(1..).unwrap_or_default();
        let next = if dropped.trim_start_matches(DELIMITERS).is_empty() {
            match args.first() {
                Some(arg) => arg.known(),
                None => Some(""),
            }
        } else {
            Some(dropped.trim_start_matches(DELIMITERS))
        };
        let starts_loop = |text: &str| text.starts_with(['%', '/', '^', '!']);
        next.is_some_and(|next| !starts_loop(next)) && !starts_loop(first)
    }

    /// The arguments of a program that splits its own command line, as
    /// it reads them: cmd hands every program it starts, all but its own
    /// built-in commands, the text after its name as written, carets outside
    /// quotes and variables apart (`raw`), and the program splits it. A
    /// program does so by the C runtime's rules, where `\"` is a quote and a
    /// quote does not end a word (`bash -c "echo \"hi\"; rm -rf ~"` hands
    /// bash `echo "hi"; rm -rf ~`), and so does a runner or a wrapper that
    /// starts another (`uv run bash -c …`, `wsl …`, `git submodule foreach
    /// …`). `start` hands the program it starts the same text, after a title
    /// in quotes. `cmd` runs the text after `/c` as it is, quotes and all
    /// (`cmd /c bash -c "rm -rf ~"`), by its own rule for the quotes around
    /// it. A word with a variable that is only known when it runs is unknown.
    fn own_split(&self, unit: &mut Unit, raw: &str) {
        let Some(key) = unit.key() else {
            return;
        };
        let Some(program) = unit.program.known() else {
            return;
        };
        let start = program.eq_ignore_ascii_case("start");
        if is_built_in(program) && !start {
            return;
        }
        let text = uncaret(raw);
        // Each word, and the text it was written as: a word only known when
        // it runs keeps its quotes (`docker rm -f "%IDS%"` is one name).
        let words = if key == "cmd" {
            native::words("cmd", &[], &text)
                .into_iter()
                .map(|word| (word.clone(), word))
                .collect()
        } else {
            let mut words = native::argv_written(&text);
            // `start "title" program …`: the title is no argument (see
            // `Self::unit`).
            if start && text.trim_start().starts_with('"') && words.len() >= 2 {
                words.remove(0);
            }
            words
        };
        unit.args = words
            .into_iter()
            .map(|(word, written)| {
                expand_variables(&word, self.split).map_or(Arg::Unknown(written), Arg::Known)
            })
            .collect();
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
        let Reading { program, first, .. } = reading;
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
        let mut unit = Unit::new(Shell::Cmd, program, args, stage);
        if self.input {
            unit.stdin = Some(Arg::Unknown("<input>".to_string()));
        }
        unit
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
            before_dot: maybe_file,
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
                before_dot: false,
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
            before_dot: false,
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

    /// Whether the redirects of `node` hand the command an input: a file
    /// (`<`, `0<`) or another handle (`0<&3`, `<&3`, `0>&3`), whose content
    /// the line does not show. The null device holds nothing to read
    /// (`python < NUL`), and handle 0 made a copy of itself (`0<&0`) is the
    /// input the command had, so neither is one. Every redirect counts, not
    /// only the first: `python < NUL < x.py` reads `x.py`.
    fn reads_input(&self, node: Node<'_>) -> bool {
        let mut cursor = node.walk();
        let mut reads = false;
        let mut input = false;
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "redirect_op" => {
                    reads = unit::text(&child, self.source)
                        .trim_start_matches(|c: char| c.is_ascii_digit())
                        .starts_with('<');
                }
                "redirect_target" if reads => {
                    let target = self.quoted_value(child);
                    input |= !target
                        .known()
                        .is_some_and(|target| path::null_device(target, Shell::Cmd));
                    reads = false;
                }
                "fd_redirect" => input |= self.duplicates_input(child),
                _ => {}
            }
        }
        input
    }

    /// Whether the handle duplication `node` (`N<&M`, `N>&M`) makes the
    /// input, handle 0, a copy of another handle. cmd reads both operators
    /// as a copy of handle `M` into handle `N`; `N` is 0 for `<&` and 1 for
    /// `>&` when it is not written. `M` may be a variable (`0<&%h%`), read
    /// as cmd expands it; one only known when it runs may be any handle.
    fn duplicates_input(&self, node: Node<'_>) -> bool {
        let text = unit::text(&node, self.source);
        let Some((handle, rest)) = text.split_once('&') else {
            return true;
        };
        let into = match handle.strip_suffix(['<', '>']) {
            Some("") if handle.ends_with('<') => "0",
            Some("") => "1",
            Some(digit) => digit,
            None => return true,
        };
        if into != "0" {
            return false;
        }
        let mut cursor = node.walk();
        let source = match node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "variable_reference")
        {
            Some(variable) => self.value(&[variable]),
            None => Arg::Known(rest.to_string()),
        };
        source.known().is_none_or(|source| source.trim() != "0")
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
        self.tf_cli_args(node);
        let text = unit::text(&node, self.source);
        if let Some(at) = unquoted_operator(text) {
            let rest = text[at..].trim_start_matches(['&', '|', ' ', '\t']);
            if !rest.is_empty() {
                unit::script(self.split, rest, Shell::Cmd, self.depth + 1);
            }
        }
    }
}

impl Walker<'_> {
    /// `set TF_CLI_ARGS=-destroy`, `set "TF_CLI_ARGS_apply=-destroy"`:
    /// terraform reads the value as arguments of its command, in any later
    /// command that runs it, as `zip` reads `ZIPOPT` (and `ZIP`) as options. cmd reads the names of variables in any case.
    /// The value ends at an unquoted `&` or `|`; one with a switch (`set /p`
    /// reads it from the input) or a variable cmd expands later (`!X!`) is
    /// only known when it runs. `set /a` gives a number, which holds no
    /// flag.
    fn tf_cli_args(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // `set /p NAME=prompt`: the grammar holds the name a level down.
        if let Some(prompt) = children
            .iter()
            .find(|child| child.kind() == "prompt_assignment")
            .copied()
        {
            let mut cursor = prompt.walk();
            children.extend(prompt.named_children(&mut cursor));
        }
        let source = unit::text(&node, self.source);
        // `set /a BASH_ENV=1`: a number, which still names a file a bash the
        // line starts runs first.
        if let Some(sum) = children
            .iter()
            .find(|child| child.kind() == "arithmetic_assignment")
        {
            let text = unit::text(sum, self.source);
            for name in arithmetic_names(text) {
                if startup::named_file(name) {
                    startup::environment(self.split, Some(name), Arg::Unknown(source.to_string()));
                }
            }
            return;
        }
        // `set %n%=x.sh`: a name only known when it runs may be `BASH_ENV`.
        if children
            .iter()
            .any(|child| child.kind() == "variable_reference")
        {
            startup::environment(self.split, None, Arg::Unknown(source.to_string()));
        }
        let Some(written_name) = children
            .iter()
            .find(|child| child.kind() == "variable_name")
            .map(|name| unit::text(name, self.source).trim())
        else {
            return;
        };
        let zip =
            written_name.eq_ignore_ascii_case("ZIPOPT") || written_name.eq_ignore_ascii_case("ZIP");
        let node_options = written_name.eq_ignore_ascii_case("NODE_OPTIONS");
        let terraform = unit::argument_variable(written_name);
        let startup = startup::named_file(written_name);
        if !zip && !node_options && terraform.is_none() && !startup {
            return;
        }
        let plain = children.iter().all(|child| {
            matches!(
                child.kind(),
                "set_keyword" | "variable_name" | "assignment_value" | "quoted_assignment_value"
            )
        });
        let written = children
            .iter()
            .find(|child| matches!(child.kind(), "assignment_value" | "quoted_assignment_value"))
            .map_or("", |value| {
                let text = unit::text(value, self.source);
                if value.kind() == "quoted_assignment_value" {
                    text
                } else {
                    unquoted_operator(text).map_or(text, |at| &text[..at])
                }
            });
        let value = if plain && !written.contains('!') {
            expand(written.trim_matches('"').trim(), self.split)
        } else {
            None
        };
        let value = value.map_or_else(|| Arg::Unknown(source.to_string()), Arg::Known);
        // `set BASH_ENV=x.sh`: a bash the line starts runs the file first.
        if startup {
            startup::environment(self.split, Some(written_name), value);
            return;
        }
        match terraform {
            Some(name) => self.split.note_argument_variable(name, value),
            // `set NODE_OPTIONS=--require ./x.js`: every node a later
            // command starts loads it first.
            None if node_options => self.split.node_options.push(value),
            None => {
                self.split.zip_env.set(written_name, &value, true);
            }
        }
    }
}

/// The names `set /a` gives a value to (`set /a a=1, BASH_ENV+=2`): before
/// each `=` of an assignment, or of an operator and `=`, in each part
/// between commas, without the quotes and the switch it is written with. A
/// name with `%` or `!` in it is only known when it runs, and may be any.
fn arithmetic_names(text: &str) -> Vec<&str> {
    let text = text.trim_start();
    let text = text
        .get(..2)
        .filter(|head| head.eq_ignore_ascii_case("/a"))
        .map_or(text, |_| &text[2..]);
    text.split(',')
        .filter_map(|part| {
            let (name, _) = part.split_once('=')?;
            let name = name
                .trim_end_matches(['+', '-', '*', '/', '%', '&', '|', '^', '<', '>'])
                .trim()
                .trim_matches(['"', '(', ' ']);
            Some(if name.contains(['%', '!']) {
                "BASH_ENV"
            } else {
                name
            })
        })
        .collect()
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

/// Whether `text`, a comment the grammar reads, is the `rem` command:
/// `rem`, with or without an `@`, in any case, then a space, a tab or the
/// end of the line, as the grammar reads one.
fn is_rem(text: &str) -> bool {
    let rest = text.strip_prefix('@').unwrap_or(text);
    rest.get(..3)
        .is_some_and(|head| head.eq_ignore_ascii_case("rem"))
        && matches!(rest.as_bytes().get(3), None | Some(b' ' | b'\t'))
}

/// Whether `node`, a comment, follows a label in a `( … )` block: cmd runs
/// the line after a label there as a command, even one that starts with
/// `::`.
fn after_label(node: Node<'_>, source: &str) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "parenthesized")
        && node.prev_named_sibling().is_some_and(|before| {
            before.kind() == "label"
                || (before.kind() == "comment" && unit::text(&before, source).starts_with(':'))
        })
}

/// The text cmd runs for `text`, a comment the grammar reads, with a caret
/// before each `'VBS` outside double quotes, so the grammar no longer reads
/// a comment for it. cmd takes the caret off: `rd /s /q C:\ ^'VBS` runs as
/// `rd /s /q C:\ 'VBS` does. In quotes a caret stays, so a `'VBS` there
/// that the grammar may read a comment for (after a space or a tab, or at
/// the start) cannot be read: `None`, as for a comment with no `'VBS`
/// outside quotes to put a caret before.
fn vbs_read(text: &str) -> Option<String> {
    let mut read = String::with_capacity(text.len() + 16);
    let mut quoted = false;
    let mut escaped = false;
    let mut changed = false;
    let mut previous = None;
    for (at, c) in text.char_indices() {
        if !escaped && c == '\'' && text[at..].starts_with("'VBS") {
            if !quoted {
                read.push('^');
                changed = true;
            } else if matches!(previous, None | Some(' ' | '\t')) {
                return None;
            }
        }
        read.push(c);
        if escaped {
            escaped = false;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == '^' && !quoted {
            escaped = true;
        }
        previous = Some(c);
    }
    changed.then_some(read)
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
    /// Whether the program is a built-in found before a `.`, `\` or `:` of
    /// the word (`call.bat`, `for.exe`), which cmd may read as the file the
    /// word names instead.
    before_dot: bool,
}

impl Reading {
    fn program(program: Arg) -> Self {
        Self {
            program,
            first: Vec::new(),
            before_dot: false,
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

pub(crate) fn is_built_in(name: &str) -> bool {
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
/// `!X!`), or one the line sets (or the PowerShell line that starts this
/// cmd), makes it known only when it runs.
fn expand(text: &str, split: &Split) -> Option<String> {
    expand_variables(&unescape(text), split)
}

/// `text` with the variables that name a known place put in (see
/// [`expand`]), its carets left as they are.
fn expand_variables(text: &str, split: &Split) -> Option<String> {
    if text.matches('!').count() >= 2 {
        return None;
    }
    let mut value = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        value.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find('%')?;
        let name = &after[..end];
        // A PowerShell line that starts this cmd may have changed it
        // (`$env:TEMP = …`, `Set-Item Env:TEMP …`): cmd is handed the
        // session's environment.
        if split.reassigned(name) || split.reassigned(&format!("env:{name}")) {
            return None;
        }
        value.push_str(place(name)?);
        rest = &after[end + 1..];
    }
    value.push_str(rest);
    Some(value)
}

/// The variables that name a known place, as paths the resolver reads.
pub(crate) fn place(name: &str) -> Option<&'static str> {
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

/// Where the arguments after a command's name are in the source, as one
/// stretch: what is left of the first word, then the `after` pieces.
fn raw_arguments(reading: &Reading, after: &[Node<'_>]) -> Option<Range<usize>> {
    let start = reading
        .first
        .first()
        .map(|(_, range)| range.start)
        .or_else(|| after.first().map(Node::start_byte))?;
    let end = after
        .last()
        .map(Node::end_byte)
        .or_else(|| reading.first.last().map(|(_, range)| range.end))?;
    (start <= end).then_some(start..end)
}

/// `text` as cmd hands it to a program: the carets outside double quotes
/// taken off (`^"` is a quote cmd does not read as one, but the program
/// does), the ones inside kept.
fn uncaret(text: &str) -> String {
    let mut value = String::with_capacity(text.len());
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' if !quoted => {
                if let Some(next) = chars.next() {
                    value.push(next);
                }
            }
            '"' => {
                quoted = !quoted;
                value.push(c);
            }
            _ => value.push(c),
        }
    }
    value
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
