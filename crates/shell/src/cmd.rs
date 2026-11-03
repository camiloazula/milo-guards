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
                for child in node.children(&mut cursor) {
                    if child.kind() == "||" {
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
    /// command named `if` whose condition and body are its arguments. cmd
    /// reads it as the statement it is, so the command's text is split again
    /// on its own, where the grammar reads it as one. Returns whether it was.
    /// A command that already starts the text it was split from is not split
    /// again: the grammar would read it the same way.
    fn statement(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) -> bool {
        let mut cursor = node.walk();
        let keyword = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "command_name")
            .is_some_and(|name| {
                let name = unit::text(&name, self.source);
                name.eq_ignore_ascii_case("if") || name.eq_ignore_ascii_case("for")
            });
        if !keyword || node.kind() != "cmd" || node.start_byte() == 0 {
            return false;
        }
        let text = format!("{}\n", unit::text(&node, self.source));
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

    fn command(&mut self, node: Node<'_>, stage: Option<Stage>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // `call %X%` names its program with a variable: the first piece is
        // the program whatever its kind, so no command goes unread.
        let Some(name) = children
            .iter()
            .find(|child| child.kind() == "command_name")
            .or_else(|| {
                children
                    .iter()
                    .find(|child| child.kind() != "argument_list")
            })
        else {
            return;
        };
        let pieces: Vec<Node<'_>> = children
            .iter()
            .find(|child| child.kind() == "argument_list")
            .map(|list| {
                let mut cursor = list.walk();
                list.named_children(&mut cursor).collect()
            })
            .unwrap_or_default();
        // The grammar ends a command's name where cmd does not
        // (`C:\Windows\System32\cmd.exe` is `C` given `:\Windows…`, `r^d` is
        // `r` given `^d`): the pieces that touch the name are its word.
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
        let after = &pieces[word.len() - 1..];
        let (args, spans) = self.args(after);
        let read = self.word(&word);
        let file = read.file.map(|(program, first)| {
            self.unit(program, first, args.clone(), spans.clone(), after, stage)
        });
        let unit = self.unit(read.program, read.first, args, spans, after, stage);
        match file {
            Some(file) => launch::add_either(self.split, unit, file, self.depth),
            None => launch::add(self.split, unit, self.depth),
        }
    }

    /// The unit of `program` given what is left of its word, `first`, and
    /// then `args`, the arguments after the word, made of the grammar's
    /// `pieces`; `spans` are where each argument is in the source.
    fn unit(
        &self,
        program: Arg,
        first: Option<Placed>,
        mut args: Vec<Arg>,
        mut spans: Vec<Range<usize>>,
        pieces: &[Node<'_>],
        stage: Option<Stage>,
    ) -> Unit {
        // `start "title" program …`: cmd takes a first quoted argument as
        // the window's title, which the values here no longer show.
        let title = first.is_none() && pieces.first().is_some_and(|first| first.kind() == "string");
        if let Some((first, span)) = first {
            args.insert(0, first);
            spans.insert(0, span);
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
    /// the program it names and what is left of it, the first argument.
    ///
    /// A word in quotes names a program's path. Otherwise cmd looks for one
    /// of its built-in commands at the start of the word, with the carets
    /// taken off (`r^d` is `rd`): the whole word, or the part before the
    /// first `+`, `/`, `[`, `]`, `,`, `;`, `=` or `(` (`rd/s`, `echo(x`), or
    /// the part before the first `.`, `\` or `:` (`echo.x`, `cd..`,
    /// `cd\x`). The rest of the word is the built-in's first argument;
    /// `echo` drops the one character after its name. In the last case cmd
    /// runs the file the word names instead when there is one, which only
    /// the disk can say: a word that names a program (`dir.bat`,
    /// `echo\..\..\Windows\System32\shutdown.exe`) is read both ways.
    /// A word that starts with no built-in is the path of a program,
    /// judged by its last part (`C:\Windows\System32\cmd.exe` is `cmd`).
    fn word(&self, pieces: &[Node<'_>]) -> Word {
        let Some(range) = span(pieces) else {
            return Word::program(Arg::Unknown(String::new()));
        };
        let raw = self.source.get(range.clone()).unwrap_or_default();
        if raw.contains('"') {
            let (program, first) = match self.value(pieces) {
                Arg::Known(text) => cut(text, range),
                unknown => (unknown, None),
            };
            return Word {
                program,
                first,
                file: None,
            };
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
            let (program, first) = self.path(raw, range.start);
            return Word {
                program,
                first,
                file: None,
            };
        };
        let name = prefix(end);
        // `echo.x` says `x`.
        let skip = usize::from(name.eq_ignore_ascii_case("echo"));
        let first = chars.get(end + skip).map(|(at, _)| {
            let rest = &raw[*at..];
            let value =
                expand(rest, self.split).map_or_else(|| Arg::Unknown(rest.to_string()), Arg::Known);
            (value, range.start + at..range.end)
        });
        let file = if maybe_file {
            let (program, first) = self.path(raw, range.start);
            program
                .known()
                .is_some_and(names_program)
                .then_some((program, first))
        } else {
            None
        };
        Word {
            program: Arg::Known(name),
            first,
            file,
        }
    }

    /// The program a word that starts with no built-in names, with what is
    /// left of it (see [`cut`]); `start` is where the word is in the source.
    fn path(&self, raw: &str, start: usize) -> (Arg, Option<Placed>) {
        match expand(raw, self.split) {
            Some(text) => cut(text, start..start + raw.len()),
            None => (Arg::Unknown(raw.to_string()), None),
        }
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

/// The program a word that starts with no built-in names, read from its
/// `text` with the variables put in and the quotes taken off: a path, and,
/// when a `/` that does not follow a drive (`C:/Windows`) ends the name
/// (`cmd/c`), the rest of the word as the first argument. A bare drive (`D:`)
/// is the program `D` given `:`, as the grammar reads it. `span` is where the
/// word is in the source.
fn cut(text: String, span: Range<usize>) -> (Arg, Option<Placed>) {
    if is_drive(&text) {
        let colon = span.end.saturating_sub(1)..span.end;
        return (
            Arg::Known(text[..1].to_string()),
            Some((Arg::Known(":".to_string()), colon)),
        );
    }
    match text.find('/') {
        Some(at) if at > 0 && !is_drive(&text[..at]) => (
            Arg::Known(text[..at].to_string()),
            Some((Arg::Known(text[at..].to_string()), span)),
        ),
        _ => (Arg::Known(text), None),
    }
}

/// An argument and where it is in the source.
type Placed = (Arg, Range<usize>);

/// How cmd reads a command's first word (see [`Walker::word`]).
struct Word {
    /// The program it names.
    program: Arg,
    /// What is left of the word, the program's first argument, and where
    /// it is in the source.
    first: Option<Placed>,
    /// The word read as the path of a program, with what is left of it,
    /// when cmd may run that file instead of the built-in.
    file: Option<(Arg, Option<Placed>)>,
}

impl Word {
    fn program(program: Arg) -> Self {
        Self {
            program,
            first: None,
            file: None,
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
fn names_program(path: &str) -> bool {
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
