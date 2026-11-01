//! Splitting a Windows command prompt line (`cmd.exe`) with
//! tree-sitter-batch.

use tree_sitter::Node;

use crate::launch;
use crate::unit::{self, Arg, Origin, Split, Stage, Unit};
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
    // `set TEMP=…`: a variable the line sets no longer names its usual
    // place.
    let mut names = Vec::new();
    unit::for_each_node(tree.root_node(), |node| {
        if node.kind() == "variable_name"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "variable_assignment")
        {
            names.push(unit::text(&node, &text).to_string());
        }
    });
    for name in names {
        split.reassign(&name);
    }
    Walker {
        source: &text,
        depth,
        split,
    }
    .walk(tree.root_node(), None, 0);
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
                self.command(node, stage);
                self.children(node, None, level);
            }
            "pipe_stmt" => {
                let pipeline = self.split.pipeline();
                let mut cursor = node.walk();
                for (index, child) in node.named_children(&mut cursor).enumerate() {
                    self.walk(child, Some(Stage { pipeline, index }), level + 1);
                }
            }
            "redirection" => self.redirect(node),
            "variable_assignment" => {
                self.assignment(node);
                self.children(node, stage, level);
            }
            "comment" => self.comment(node),
            _ => self.children(node, stage, level),
        }
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
        let program = self.value(&[*name]);
        let list = children
            .iter()
            .find(|child| child.kind() == "argument_list")
            .copied();
        let (mut args, mut origins) = list.map(|list| self.args(list)).unwrap_or_default();
        // `start "title" program …`: cmd takes a first quoted argument as
        // the window's title, which the values here no longer show.
        if program
            .known()
            .is_some_and(|program| program.eq_ignore_ascii_case("start"))
            && args.len() >= 2
            && list
                .and_then(|list| list.named_child(0))
                .is_some_and(|first| first.kind() == "string")
        {
            args.remove(0);
            origins.remove(0);
        }
        launch::add(
            self.split,
            Unit::new(Shell::Cmd, program, args, stage).with_origins(origins),
            self.depth,
        );
    }

    /// The arguments of a list. cmd splits arguments at spaces only, so the
    /// pieces the grammar gives that touch (`%USERPROFILE%` and `\x`) are
    /// one argument.
    fn args(&self, list: Node<'_>) -> (Vec<Arg>, Vec<Origin>) {
        let mut cursor = list.walk();
        let pieces: Vec<Node<'_>> = list.named_children(&mut cursor).collect();
        let mut args = Vec::new();
        let mut origins = Vec::new();
        let mut group: Vec<Node<'_>> = Vec::new();
        for piece in pieces {
            if group
                .last()
                .is_some_and(|last| last.end_byte() != piece.start_byte())
            {
                let (arg, origin) = self.value_from(&group);
                args.push(arg);
                origins.push(origin);
                group.clear();
            }
            group.push(piece);
        }
        if !group.is_empty() {
            let (arg, origin) = self.value_from(&group);
            args.push(arg);
            origins.push(origin);
        }
        (args, origins)
    }

    /// One argument made of touching pieces.
    fn value(&self, pieces: &[Node<'_>]) -> Arg {
        self.value_from(pieces).0
    }

    /// One argument made of touching pieces, and where its value came from:
    /// from a system folder's variable anywhere in it, else from a variable
    /// under home at its very start.
    fn value_from(&self, pieces: &[Node<'_>]) -> (Arg, Origin) {
        let source = match (pieces.first(), pieces.last()) {
            (Some(first), Some(last)) => self
                .source
                .get(first.start_byte()..last.end_byte())
                .unwrap_or_default(),
            _ => "",
        };
        let unknown = || (Arg::Unknown(source.to_string()), Origin::Typed);
        let mut value = String::new();
        let mut origin = Origin::Typed;
        for piece in pieces {
            let text = unit::text(piece, self.source);
            let text = match piece.kind() {
                "string" => text
                    .strip_prefix('"')
                    .map_or(text, |inner| inner.strip_suffix('"').unwrap_or(inner)),
                "command_name" | "command_option" | "argument_value" | "variable_reference"
                | "redirect_target" => text,
                _ => return unknown(),
            };
            let Some((text, from)) = expand(text, self.split) else {
                return unknown();
            };
            origin = match (origin, from) {
                (Origin::System, _) | (_, Origin::System) => Origin::System,
                // Only a variable at the start of the whole value puts it
                // under home.
                (Origin::Typed, Origin::Home) if value.is_empty() => Origin::Home,
                (kept, _) => kept,
            };
            value.push_str(&text);
        }
        (Arg::Known(value), origin)
    }

    /// A redirect that writes to a file: `>`, `>>`, `2>`. A duplication
    /// (`2>&1`) writes nothing.
    fn redirect(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let operator = children
            .iter()
            .find(|child| child.kind() == "redirect_op")
            .map(|op| unit::text(op, self.source));
        let Some(target) = children
            .iter()
            .find(|child| child.kind() == "redirect_target")
        else {
            return;
        };
        let writes = operator.is_some_and(|op| op.contains('>') && !op.ends_with('&'));
        let target_text = unit::text(target, self.source);
        if writes && !target_text.starts_with('&') {
            self.split.write(Shell::Cmd, self.value(&[*target]));
        }
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
/// name a known place put in, and where the value came from: [`Origin::Home`]
/// when it starts with a variable under home, [`Origin::System`] when it
/// holds a system folder's variable; `None` when any other variable (`%X%`,
/// `%%f`, `!X!`), or one the line sets, makes it known only when it runs.
fn expand(text: &str, split: &Split) -> Option<(String, Origin)> {
    let text = unescape(text);
    if text.matches('!').count() >= 2 {
        return None;
    }
    let mut value = String::with_capacity(text.len());
    let mut origin = Origin::Typed;
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        value.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find('%')?;
        let name = &after[..end];
        if split.reassigned(name) {
            return None;
        }
        let (path, from) = place(name)?;
        origin = match (origin, from) {
            (Origin::System, _) | (_, Origin::System) => Origin::System,
            (Origin::Typed, Origin::Home) if value.is_empty() => Origin::Home,
            (kept, _) => kept,
        };
        value.push_str(path);
        rest = &after[end + 1..];
    }
    value.push_str(rest);
    Some((value, origin))
}

/// The variables that name a known place, as paths the resolver reads, and
/// what kind of place: under home (on home's drive), a system folder (whose
/// drive is a guess, as Windows may not be on `C:`), or neither.
fn place(name: &str) -> Option<(&'static str, Origin)> {
    Some(match name.to_ascii_lowercase().as_str() {
        "userprofile" => ("~", Origin::Home),
        "cd" => (".", Origin::Typed),
        "temp" | "tmp" => ("~\\AppData\\Local\\Temp", Origin::Home),
        "appdata" => ("~\\AppData\\Roaming", Origin::Home),
        "localappdata" => ("~\\AppData\\Local", Origin::Home),
        "systemroot" | "windir" => ("C:\\Windows", Origin::System),
        "systemdrive" => ("C:", Origin::System),
        "programfiles" => ("C:\\Program Files", Origin::System),
        "programfiles(x86)" => ("C:\\Program Files (x86)", Origin::System),
        "programdata" => ("C:\\ProgramData", Origin::System),
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
