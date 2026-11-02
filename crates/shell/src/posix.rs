//! Splitting a POSIX shell line (`sh`, `bash`, `zsh`) with tree-sitter-bash.

use std::ops::Range;
use std::rc::Rc;

use tree_sitter::{Node, TreeCursor};

use crate::dotglob;
use crate::launch;
use crate::startup;
use crate::unit::{self, Arg, Flag, Split, Stage, Unit};
use crate::{Rule, Shell};

pub(crate) fn split(split: &mut Split, text: &str, depth: usize) {
    let (text, marks, near, open) = join_continuations(text);
    let text = text.as_str();
    // The grammar ends such a here-document at the near line, where the shell
    // does not: what the program reads is not what the guard reads.
    if near {
        split.problem(
            Rule::Unreadable,
            "has a here-document line that is only near its delimiter",
            None,
        );
    }
    let language = tree_sitter_bash::LANGUAGE.into();
    let Some(tree) = unit::parse(split, text, &language) else {
        return;
    };
    // The grammar may read quotes that never close, and then says so; if it
    // does not, the scan above has misread the text, and what follows its
    // stopping place was not joined.
    if open && !tree.root_node().has_error() {
        split.problem(
            Rule::Unreadable,
            "has quotes or a substitution that never close",
            None,
        );
    }
    let (names, looped) = assigned(tree.root_node(), text);
    for name in names {
        split.reassign(&name);
    }
    for name in looped {
        split.loop_variable(&name);
    }
    if split.kept.on {
        environment(split, tree.root_node(), text);
    }
    Walker {
        source: text,
        marks: &marks,
        depth,
        split,
        redirected: None,
        last_command: 0..0,
    }
    .walk(tree.root_node(), None, 0);
}

/// Whether a character may stand in a zsh glob qualifier the guard reads:
/// the file tests and flags, digits for `m`, `u` and the like, `^` to
/// negate, `-` to follow links, `,` to separate. Not `e` (runs a string),
/// `+` (runs a function), `P` (adds a string it holds as a word before each
/// match: `*(DP./usr.)` is `/usr` and every name), `:` (a modifier), `[` (a
/// subscript) or anything that can hold a substitution.
fn qualifier_char(c: char) -> bool {
    (c.is_ascii_alphanumeric() && !"eP".contains(c)) || ".^/@=%*,-".contains(c)
}

/// How many characters of `rest`, the text after a `(`, make a zsh glob
/// qualifier that holds `D` (`*git(D)`, `*(.D)`), the `)` included. `word` is
/// the text in front of the `(`, back to the last space: it must end a word,
/// so not a space or what makes `$(`, `<(`, `>(`, `((`, `a=(`, `+(` and `!(`
/// something else. The `)` must end the word too.
///
/// A word that holds `^`, `#`, or a `~` that does not start it is left as it
/// is: with `extendedglob` they are operators, and `^x(D)`, `*git~x(D)` and
/// `.#git(D)` match `.git`, which a guard that reads them as plain text
/// would not see.
fn qualifier(word: &str, rest: &[char]) -> Option<usize> {
    word.chars()
        .last()
        .filter(|c| !c.is_whitespace() && !"$<>=(;&|{}`!+@)".contains(*c))?;
    if word.contains(['^', '#']) || word.char_indices().any(|(at, c)| c == '~' && at > 0) {
        return None;
    }
    let end = rest.iter().position(|c| *c == ')')?;
    let body = &rest[..end];
    let ends = rest
        .get(end + 1)
        .is_none_or(|next| next.is_whitespace() || ";&|)<>".contains(*next));
    (ends && body.contains(&'D') && body.iter().all(|c| qualifier_char(*c))).then_some(end + 1)
}

/// `text` with each backslash-newline taken out, as the shell does before
/// it reads a line (`r\<newline>m` is `rm`), except inside single quotes,
/// comments and the bodies of here-documents with a quoted delimiter, where
/// it stays. Such a body is copied as it is, so a quote in it (`don't`)
/// cannot leave the rest of the line looking quoted. The body of an unquoted
/// delimiter is fed to the shell as the inside of a double-quoted word: a
/// backslash-newline in it is joined, before the body is expanded. A line that
/// took one in and is, or is near, the delimiter (joined, or in any piece) is
/// refused: bash, sh and zsh compare the joined line, dash and ksh do not, so
/// they disagree on where the body ends. With `<<-` the tabs of the line that
/// goes on stay, as in every shell.
///
/// It also takes out zsh's `(D)` glob qualifier (see [`qualifier`]), which
/// the grammar cannot read: `rm -rf *git(D)` becomes `rm -rf *git`. Each is
/// given back as the offset in the new text where it was, the end of its
/// word, for [`Walker::qualified`].
fn join_continuations(text: &str) -> (String, Vec<usize>, bool, bool) {
    let chars: Vec<char> = text.chars().collect();
    let mut marks = Vec::new();
    // Whether a body has a line only near its delimiter (see
    // [`near_delimiter`]).
    let mut near = false;
    // Whether quotes or a substitution never close: a shell refuses such
    // text, so the scan has misread it, and what follows was not joined.
    let mut open = false;
    let mut joined = String::with_capacity(text.len());
    let (mut single, mut double) = (false, false);
    // Whether the open single quotes are `$'…'`, where a backslash escapes the
    // next character, so `\'` does not end them.
    let mut ansi = false;
    // The `$(…)`, `$((…))`, `((…))` and backticks open at this point, each
    // with whether it sits in double quotes: inside one the quoting starts
    // afresh, so a here-document in `"$(psql <<'EOF' …)"` is a here-document.
    let mut subs: Vec<(Sub, bool)> = Vec::new();
    // Here-documents opened on the current line, read from the next one:
    // each delimiter, whether `<<-` lets it be indented with tabs, and
    // whether the word had a quote or a backslash (a body fed as it is).
    let mut bodies: Vec<(String, bool, bool)> = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        if single {
            joined.push(c);
            if ansi && c == '\\' {
                if let Some(&next) = chars.get(at) {
                    joined.push(next);
                    at += 1;
                }
            } else {
                single = c != '\'';
            }
            continue;
        }
        let in_brace = matches!(subs.last(), Some((Sub::Brace, _)));
        // zsh's `(D)` glob qualifier at the end of a word.
        if c == '(' && !double {
            let rest = chars.get(at..).unwrap_or_default();
            let word = joined.rsplit(char::is_whitespace).next().unwrap_or("");
            if let Some(length) = qualifier(word, rest) {
                at += length;
                marks.push(joined.len());
                continue;
            }
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
                ansi = ansi_quote(&joined);
                joined.push(c);
            }
            '"' => {
                double = !double;
                joined.push(c);
            }
            // Arithmetic, `$((…))`: a `<<` in it is a shift.
            '$' if chars.get(at) == Some(&'(') && chars.get(at + 1) == Some(&'(') => {
                joined.push_str("$((");
                at += 2;
                subs.push((Sub::Arith(2), double));
                double = false;
            }
            // A substitution: outside the quotes of the line around it.
            '$' if chars.get(at) == Some(&'(') => {
                joined.push_str("$(");
                at += 1;
                subs.push((Sub::Paren(1), double));
                double = false;
            }
            // A `${…}`: a parenthesis in it (`${x/(/y}`, `${x%(*}`) is text,
            // not the end of the substitution around it. The quotes in it
            // are the ones of the word around it, so it ends at a `}` in the
            // same state.
            '$' if chars.get(at) == Some(&'{') => {
                joined.push_str("${");
                at += 1;
                subs.push((Sub::Brace, double));
            }
            '}' if matches!(subs.last(), Some((Sub::Brace, outer)) if *outer == double) => {
                joined.push(c);
                subs.pop();
            }
            // Arithmetic, `((…))`, unless already in some.
            '(' if !double
                && !in_brace
                && chars.get(at) == Some(&'(')
                && !matches!(subs.last(), Some((Sub::Arith(_), _))) =>
            {
                joined.push_str("((");
                at += 1;
                subs.push((Sub::Arith(2), double));
            }
            '`' => {
                joined.push(c);
                if let Some(&(Sub::Backtick, outer)) = subs.last() {
                    subs.pop();
                    double = outer;
                } else {
                    subs.push((Sub::Backtick, double));
                    double = false;
                }
            }
            '(' if !double && !in_brace => {
                if let Some((Sub::Paren(depth) | Sub::Arith(depth), _)) = subs.last_mut() {
                    *depth += 1;
                }
                joined.push(c);
            }
            ')' if !double && !in_brace => {
                joined.push(c);
                if let Some((Sub::Paren(depth) | Sub::Arith(depth), outer)) = subs.last_mut() {
                    *depth = depth.saturating_sub(1);
                    if *depth == 0 {
                        double = *outer;
                        subs.pop();
                    }
                }
            }
            '#' if !double
                && !in_brace
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
            // A `<<` in arithmetic is a shift (`$((1<<2))`), but the shell
            // reads `$((cat <<EOF` and the like as a subshell with a
            // here-document: a word and the end of the line after it could be
            // either, and is not guessed at.
            '<' if !double
                && !in_brace
                && chars.get(at) == Some(&'<')
                && matches!(subs.last(), Some((Sub::Arith(_), _))) =>
            {
                near |= ends_like_heredoc_start(chars.get(at + 1..).unwrap_or_default());
                joined.push(c);
            }
            // `<<WORD` (not `<<<`): a here-document whose body starts on
            // the next line.
            '<' if !double
                && !in_brace
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
                // The word: a quoted part is read through its closing quote
                // (`<<'E;F'` is `E;F`), the rest stops at a space or an
                // operator.
                let mut word = String::new();
                let mut quoted = false;
                while let Some(&next) = chars.get(at) {
                    if next.is_whitespace() || ";&|<>()".contains(next) {
                        break;
                    }
                    joined.push(next);
                    at += 1;
                    quoted |= matches!(next, '\\' | '\'' | '"');
                    match next {
                        '\\' => {
                            if let Some(&escaped) = chars.get(at).filter(|c| **c != '\n') {
                                joined.push(escaped);
                                word.push(escaped);
                                at += 1;
                            }
                        }
                        '\'' | '"' => {
                            let mut closed = false;
                            while let Some(&inner) = chars.get(at) {
                                joined.push(inner);
                                at += 1;
                                if inner == next {
                                    closed = true;
                                    break;
                                }
                                if inner == '\\' && next == '"' {
                                    if let Some(&escaped) = chars.get(at) {
                                        joined.push(escaped);
                                        word.push(escaped);
                                        at += 1;
                                    }
                                    continue;
                                }
                                word.push(inner);
                            }
                            // A quote that never closes is not a word the
                            // shell would take.
                            open |= !closed;
                        }
                        _ => word.push(next),
                    }
                }
                if !word.is_empty() {
                    bodies.push((word, tabs, quoted));
                }
            }
            '\n' if !double && !bodies.is_empty() => {
                joined.push('\n');
                for (delimiter, tabs, quoted) in std::mem::take(&mut bodies) {
                    while at < chars.len() {
                        let mut line = String::new();
                        // Where in `line` each backslash-newline was taken
                        // out: the pieces of the physical lines.
                        let mut cuts: Vec<usize> = Vec::new();
                        while let Some(&c) = chars.get(at).filter(|c| **c != '\n') {
                            at += 1;
                            if c != '\\' || quoted {
                                line.push(c);
                            } else if let Some(&next) = chars.get(at) {
                                // An unquoted body: a backslash-newline is
                                // joined, any other escape (`\\`) is kept
                                // whole, so `\\<newline>` is not one. The
                                // tabs of the line that goes on stay, also
                                // with `<<-`: shells keep them.
                                at += 1;
                                if next == '\n' {
                                    cuts.push(line.len());
                                } else {
                                    line.push(c);
                                    line.push(next);
                                }
                            } else {
                                line.push(c);
                            }
                        }
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
                        // A line that took in a backslash-newline: bash, sh
                        // and zsh join it before they compare it with the
                        // delimiter, dash and ksh do not (and then end the
                        // body at a piece that is the delimiter). If the
                        // joined line or any piece is, or is near, the
                        // delimiter, the shells disagree on where the body
                        // ends, so the line is refused.
                        if !cuts.is_empty() {
                            let mut start = 0;
                            let mut pieces = Vec::new();
                            for cut in cuts.iter().copied().chain([line.len()]) {
                                pieces.push(line.get(start..cut).unwrap_or_default());
                                start = cut;
                            }
                            near |= near_delimiter(content, &delimiter)
                                || pieces.iter().any(|piece| near_delimiter(piece, &delimiter));
                        }
                        if content == delimiter {
                            break;
                        }
                        near |= near_delimiter(content, &delimiter);
                    }
                }
            }
            _ => joined.push(c),
        }
    }
    open |= single || double || !subs.is_empty();
    (joined, marks, near, open)
}

/// An open `$(…)`, `$((…))` or `((…))` (with the depth of the parentheses in
/// it) or backtick, see [`join_continuations`].
#[derive(Clone, Copy)]
enum Sub {
    Paren(usize),
    Arith(usize),
    Backtick,
    /// A `${…}`, in which a parenthesis is not counted.
    Brace,
}

/// Whether the quote that follows `before` opens `$'…'`: a `$` that is not
/// escaped and does not pair with another (`$$'` is the process id and a plain
/// quote). A backslash in `$'…'` escapes the next character.
fn ansi_quote(before: &str) -> bool {
    let dollars = before.chars().rev().take_while(|c| *c == '$').count();
    let rest = &before[..before.len() - dollars];
    let slashes = rest.chars().rev().take_while(|c| *c == '\\').count();
    let unescaped = if slashes % 2 == 1 {
        dollars.saturating_sub(1)
    } else {
        dollars
    };
    unescaped % 2 == 1
}

/// Whether `rest`, the text after a `<<` in arithmetic, has the look of a
/// here-document's start: an optional `-`, one word, then the end of the line.
fn ends_like_heredoc_start(rest: &[char]) -> bool {
    let mut rest = rest.iter().peekable();
    rest.next_if(|c| **c == '-');
    while rest.next_if(|c| **c == ' ' || **c == '\t').is_some() {}
    let mut word = 0;
    while rest
        .next_if(|c| !c.is_whitespace() && !";&|<>()".contains(**c))
        .is_some()
    {
        word += 1;
    }
    while rest.next_if(|c| **c == ' ' || **c == '\t').is_some() {}
    word > 0 && rest.next() == Some(&'\n')
}

/// Whether a line of a here-document's body is only near its delimiter: the
/// shell ends the body at a line that is exactly the delimiter (for `<<-`,
/// after its leading tabs), but the grammar also ends it at ` EOF`, `EOF `,
/// `EOF #…` and `EOF ;…`. The line's first word, without spaces, quotes and
/// backslashes, is the delimiter while the line is not. A line that is the
/// delimiter in quotes or with a backslash (`'EOF'`) ends the body for
/// neither the grammar nor the shell, but is refused too: it is no body
/// anyone writes, and one rule is simpler than two.
fn near_delimiter(line: &str, delimiter: &str) -> bool {
    let word = line
        .trim_start()
        .split(|c: char| c.is_whitespace() || ";&|()<>#".contains(c))
        .next()
        .unwrap_or_default();
    word.replace(['\'', '"', '\\'], "") == delimiter
}

/// The command a redirect after `node` belongs to, when `node` is a list, a
/// pipeline or a negated command: the grammar puts the redirect on the whole
/// of it, and the shell on the last command (`a && b < f` redirects `b`).
/// `None` when `node` is not one of those, or ends in something else than a
/// plain command.
fn last_simple(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(node.kind(), "list" | "pipeline" | "negated_command") {
        return None;
    }
    let mut last = node;
    while matches!(last.kind(), "list" | "pipeline" | "negated_command") {
        let mut cursor = last.walk();
        last = last
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "comment")
            .last()?;
    }
    (last.kind() == "command").then_some(last)
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

/// How many words of `rest`, the text after a command, are a lone `-` that
/// the grammar leaves out: those that stand between the command and a
/// here-document (`<<`, not the here-string `<<<`).
fn dashes_before_heredoc(rest: &str) -> usize {
    let mut rest = rest.trim_start_matches([' ', '\t']);
    let mut found = 0;
    while let Some(after) = rest.strip_prefix('-') {
        if !after.starts_with([' ', '\t', '<']) {
            return 0;
        }
        found += 1;
        rest = after.trim_start_matches([' ', '\t']);
    }
    if found > 0 && rest.starts_with("<<") && !rest.starts_with("<<<") {
        found
    } else {
        0
    }
}

/// The variables the line sets anywhere (assignments, also after `export`
/// or `local`, `for` variables, `unset` and `read`), and among them the ones
/// a `for` loop or a `read` sets: each of those holds one item of what the
/// loop walks or the input it reads. One walk of the tree finds both.
fn assigned(root: Node<'_>, source: &str) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut looped = Vec::new();
    unit::for_each_node(root, |node| match node.kind() {
        "variable_assignment" => names.extend(
            node.child_by_field_name("name")
                .map(|name| unit::text(&name, source).to_string()),
        ),
        "unset_command" => {
            let mut cursor = node.walk();
            names.extend(
                node.named_children(&mut cursor)
                    .map(|name| unit::text(&name, source).to_string()),
            );
        }
        _ => {
            let found = loop_variables(node, source);
            names.extend(found.iter().cloned());
            looped.extend(found);
        }
    });
    (names, looped)
}

/// The variable of a `for` statement, or the names a `read` is given.
fn loop_variables(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "for_statement" => node
            .child_by_field_name("variable")
            .map(|name| unit::text(&name, source).to_string())
            .into_iter()
            .collect(),
        "command"
            if node
                .child_by_field_name("name")
                .is_some_and(|name| unit::text(&name, source) == "read") =>
        {
            let mut cursor = node.walk();
            node.children_by_field_name("argument", &mut cursor)
                .map(|arg| unit::text(&arg, source).to_string())
                .filter(|arg| !arg.starts_with('-'))
                .collect()
        }
        _ => Vec::new(),
    }
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
                split.kept_loop(unit::text(&name, source));
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
    /// Where `source` had a `(D)` glob qualifier taken out (see
    /// [`join_continuations`]).
    marks: &'a [usize],
    depth: usize,
    split: &'a mut Split,
    /// The redirects of the statement being walked, for its body command.
    redirected: Option<Redirected>,
    /// The units of the command walked last (not what its arguments run):
    /// read right after a statement's body, it is the body's last command.
    last_command: Range<usize>,
}

/// The redirects of a statement whose body is a command: the node id of
/// that command, what redirects its input, and where the redirects start.
struct Redirected {
    body: usize,
    inputs: Vec<Option<Arg>>,
    from: usize,
}

impl Walker<'_> {
    /// Whether `node` is, or ends with, a word that had a `(D)` glob
    /// qualifier: its wildcards can match a leading dot.
    fn qualified(&self, node: Node<'_>) -> bool {
        self.marks
            .iter()
            .any(|mark| (node.start_byte()..=node.end_byte()).contains(mark))
    }

    /// Whether `node`, a `${…}`, gives its variable a value when it has
    /// none: `${X:=v}`, `${X=v}`, `${X[1]:=v}`. Whether it had one is not
    /// known, so the variable is taken as set.
    fn assigns_default(&self, node: Node<'_>) -> bool {
        let Some(inner) = unit::text(&node, self.source)
            .strip_prefix("${")
            .and_then(|inner| inner.strip_suffix('}'))
        else {
            return false;
        };
        let rest = inner.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let rest = match rest.strip_prefix('[') {
            Some(subscript) => subscript.split_once(']').map_or("", |(_, rest)| rest),
            None => rest,
        };
        rest.len() < inner.len() && (rest.starts_with('=') || rest.starts_with(":="))
    }

    /// Whether `node` is in arithmetic, `(( ))` or `$(( ))`, where `=`, `++`
    /// and `--` set a variable, and not in a `[` or `[[` test, where `=` is a
    /// comparison.
    fn in_arithmetic(node: Node<'_>) -> bool {
        let mut up = node.parent();
        while let Some(parent) = up {
            match parent.kind() {
                "arithmetic_expansion" | "c_style_for_statement" | "compound_statement" => {
                    return true
                }
                "binary_expression"
                | "unary_expression"
                | "postfix_expression"
                | "parenthesized_expression"
                | "ternary_expression" => {}
                _ => return false,
            }
            up = parent.parent();
        }
        false
    }

    /// Whether `node`, a `${…}`, assigns `GLOBIGNORE` a value that is not
    /// empty: `${GLOBIGNORE:=x}` when it is unset or empty, `${GLOBIGNORE=x}`
    /// when it is unset. Whether it was is not known, so the assignment is
    /// taken as made.
    fn assigns_ignore(&self, node: Node<'_>) -> bool {
        let text = unit::text(&node, self.source);
        let Some(inner) = text
            .strip_prefix("${")
            .and_then(|inner| inner.strip_suffix('}'))
            .and_then(|inner| inner.strip_prefix(dotglob::GLOBIGNORE))
        else {
            return false;
        };
        // `GLOBIGNORE[0]`: an element of it is set, and the first is read.
        let inner = match inner.strip_prefix('[') {
            Some(subscript) => subscript.split_once(']').map_or("", |(_, rest)| rest),
            None => inner,
        };
        let value = inner.strip_prefix(":=").or_else(|| inner.strip_prefix('='));
        value.is_some_and(|value| {
            dotglob::assigns_hiding(&Arg::Unknown(format!("{}={value}", dotglob::GLOBIGNORE)))
        })
    }

    /// The operands of a chain of assignments in `(( ))`, in order, as the
    /// text each is written in: `x = y = 1` is `x`, `y` and `1`, however the
    /// parse nests it. Anything else is one operand.
    fn chain_operands<'t>(&self, node: Node<'t>, out: &mut Vec<Node<'t>>) {
        let assigning = node.kind() == "binary_expression" && {
            let mut cursor = node.walk();
            let found = node
                .children(&mut cursor)
                .find(|child| !child.is_named())
                .map(|child| unit::text(&child, self.source));
            found.is_some_and(|operator| {
                operator.ends_with('=') && !matches!(operator, "==" | "!=" | "<=" | ">=")
            })
        };
        match (
            assigning,
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            (true, Some(left), Some(right)) => {
                self.chain_operands(left, out);
                self.chain_operands(right, out);
            }
            _ => out.push(node),
        }
    }

    /// Whether `node`, an assignment in `(( ))`, gives `GLOBIGNORE` a value
    /// at any place of a chain: `GLOBIGNORE = 1`, `x = GLOBIGNORE = 1`. Every
    /// operand but the last is assigned to; the last is the value.
    fn assigns_in_chain(&self, node: Node<'_>) -> bool {
        let mut operands = Vec::new();
        self.chain_operands(node, &mut operands);
        operands.split_last().is_some_and(|(_, targets)| {
            targets
                .iter()
                .any(|target| unit::text(target, self.source).trim() == dotglob::GLOBIGNORE)
        })
    }

    /// Whether `node` or anything in it assigns `GLOBIGNORE` with a `${…}`:
    /// the shell expands the words of a command before it expands the
    /// command's own wildcards, so `rm -rf ${GLOBIGNORE:=x}*git` has it set
    /// when `*git` is read.
    fn holds_ignore_assignment(&self, node: Node<'_>) -> bool {
        let mut found = false;
        unit::for_each_node(node, |inner| {
            found |= inner.kind() == "expansion" && self.assigns_ignore(inner);
        });
        found
    }

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
            // The redirects of a command are for its input too: a
            // here-document it reads its code from.
            "redirected_statement" => {
                let outer = self.redirected.take();
                self.redirected = self.redirects(node);
                self.redirected(node, stage, level);
                self.redirected = outer;
            }
            // `GLOBIGNORE=x` on a line of its own, or after `export`: the
            // shell has it from here on.
            "variable_assignment" => {
                self.split.assigned_earlier = true;
                self.assignment(node);
                self.assigned(node, level);
            }
            // The right side of `&&` and `||` may not run.
            "list" => {
                let mut cursor = node.walk();
                let before = self.split.moved_so_far();
                let mut at = 0;
                for child in node.children(&mut cursor) {
                    // The right side of `||` only runs when the left failed:
                    // a `cd` on the left may not have moved the line.
                    if child.kind() == "||" {
                        self.split.may_not_have_moved(before);
                    }
                    if !child.is_named() {
                        continue;
                    }
                    self.split.branches += usize::from(at > 0);
                    self.walk(child, stage, level + 1);
                    self.split.branches -= usize::from(at > 0);
                    at += 1;
                }
            }
            // `unset GLOBIGNORE` turns bash's option off as `shopt -u` does;
            // `unset -f GLOBIGNORE` removes a function, not the variable.
            "unset_command" => {
                self.split.assigned_earlier = true;
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
                    if child.kind() != "variable_assignment" {
                        self.exported_options(child);
                        let text = unit::text(&child, self.source);
                        let written = startup::Written {
                            expanded: text.contains(['$', '`']),
                            pwd: text.contains("PWD"),
                        };
                        self.startup_words(&[self.arg(child)], written);
                    }
                }
                self.declaration(node, stage);
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
                if assigns && self.assigns_in_chain(node) {
                    self.split.hide();
                }
                // `((PATH=1))` sets a variable the interpreter after it may
                // be given.
                self.split.assigned_earlier |= assigns && Self::in_arithmetic(node);
                self.children(node, stage, level);
            }
            // `: ${GLOBIGNORE:=x}`: the expansion sets it.
            "expansion" => {
                if self.assigns_ignore(node) {
                    self.split.hide();
                }
                self.split.assigned_earlier |= self.assigns_default(node);
                self.children(node, stage, level);
            }
            // `(( GLOBIGNORE++ ))`, `(( --GLOBIGNORE ))`: an empty variable
            // becomes 1 or -1.
            "postfix_expression" | "unary_expression" => {
                let text = unit::text(&node, self.source);
                let bare = text.replace("++", "").replace("--", "");
                if bare.len() < text.len() && bare.trim() == dotglob::GLOBIGNORE {
                    self.split.hide();
                }
                self.split.assigned_earlier |= bare.len() < text.len() && Self::in_arithmetic(node);
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
                // `for f in *git(D); do rm -rf "$f"; done`: the body works
                // on names the qualifier let a wildcard match.
                let mut cursor = node.walk();
                if node.kind() == "for_statement"
                    && node
                        .children_by_field_name("value", &mut cursor)
                        .any(|word| self.qualified(word))
                {
                    self.split.hide_functions();
                }
                if let Some(name) = node
                    .child_by_field_name("name")
                    .filter(|_| node.kind() == "function_definition")
                {
                    let name = unit::text(&name, self.source);
                    self.split.define_function(name);
                    self.fork_bomb(node, name);
                }
                // The variable of `for` and `select` is set for the body
                // (`for PATH in /x; do …`).
                self.split.assigned_earlier |= node.kind() == "for_statement";
                self.split.branches += 1;
                self.split.bodies += usize::from(body);
                self.split.repeats += usize::from(body);
                let start = (self.split.units.len(), self.split.reads.len());
                self.children(node, stage, level);
                if node.kind() == "for_statement" {
                    self.bind_loop(node, start);
                }
                // A function defined here may stand for a program of the same
                // name (`node() { NODE_OPTIONS=… command node "$@"; }`) from
                // here on.
                self.split.assigned_earlier |= node.kind() == "function_definition";
                self.split.repeats -= usize::from(body);
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
            "heredoc_redirect" => self.walk_heredoc(node, stage, level, None),
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
        // `rm -rf ${GLOBIGNORE:=x}*git`: set while the words are expanded,
        // before the wildcard is.
        if self.holds_ignore_assignment(node) {
            self.split.hide();
        }
        let program = self.arg(name);
        let mut cursor = node.walk();
        let nodes: Vec<Node<'_>> = node
            .children_by_field_name("argument", &mut cursor)
            .collect();
        // `rm -rf *git(D)`: the qualifier is for this command's wildcards.
        let qualified = nodes.iter().any(|arg| self.qualified(*arg));
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
        // The grammar leaves a `-` that is the last word before a
        // here-document out of the tree (`cat a - <<EOF` has the argument
        // `a` only): it is an argument all the same.
        let lost = dashes_before_heredoc(self.source.get(node.end_byte()..).unwrap_or_default());
        args.extend(std::iter::repeat_n(Arg::Known("-".to_string()), lost));
        // A here-document or here-string is the program's input. tree-sitter
        // drops a lone `-` before the redirect (`python3 - <<'PY'`), which
        // names that input, so it is put back when the lines above did not.
        let mut stdin = None;
        if let Some((input, from)) = self.input(node) {
            let gap = self.source.get(node.start_byte()..from).unwrap_or_default();
            if lost == 0
                && gap.split_whitespace().any(|word| word == "-")
                && !args.iter().any(|arg| arg.known() == Some("-"))
            {
                args.push(Arg::Known("-".to_string()));
            }
            stdin = Some(input);
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
            Some("let") => args
                .iter()
                .any(|arg| dotglob::assigns_hiding(arg) || dotglob::arithmetic_hides(arg)),
            _ => false,
        };
        if sets {
            self.split.hide();
        }
        if program
            .known()
            .is_some_and(|name| startup::read_into(name, &args))
        {
            self.split.problem(
                Rule::Unknown,
                "sets a variable the shell runs later to a value only known when it runs",
                Some(program.text()),
            );
        }
        // `BASH_ENV=f bash -c '…'`: the shell it starts runs `f` first.
        let mut cursor = node.walk();
        let assignments: Vec<Node<'_>> = node
            .children(&mut cursor)
            .filter(|child| child.kind() == "variable_assignment")
            .collect();
        let mut startup = Rc::default();
        // In front of a special builtin the assignment outlives it: it stays
        // set, and exported, for the rest of the line (POSIX mode, and an
        // `EXIT` or `RETURN` trap that runs with it still set). It is read
        // as the line-level statement it then is.
        let outlives = program
            .known()
            .is_some_and(|name| startup::SPECIAL.contains(&name));
        for assignment in &assignments {
            if let Some(file) = self.startup(*assignment) {
                if outlives {
                    self.split.add_startup(file);
                } else if !startup::push(&mut startup, file) {
                    self.split.startup_overflow();
                }
            }
        }
        self.declared(program.known(), &args);
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
        // `NODE_OPTIONS=… node -e …`: node reads the value as its options.
        // The same for `PYTHONPATH=… python3 -c …`.
        let options = self.split.node_options.len();
        let paths = self.split.python_path.len();
        let mut cursor = node.walk();
        let assignments: Vec<Node<'_>> = node
            .children(&mut cursor)
            .filter(|child| child.kind() == "variable_assignment")
            .collect();
        // Inline code is not read whole by a program given an environment.
        let environed = assignments.len();
        self.split.environment += environed;
        for assignment in assignments {
            self.node_options(assignment);
        }
        let before = self.split.qualify(qualified);
        let mut unit = Unit::new(Shell::Posix, program, args, stage);
        unit.stdin = stdin;
        unit.startup = startup;
        launch::add(self.split, unit, self.depth);
        self.split.environment -= environed;
        self.split.restore_qualified(before);
        self.split.node_options.truncate(options);
        self.split.python_path.truncate(paths);
        self.split.unscope_hidden(outer);
    }

    /// What redirects the input of the command at `node`: a here-document or
    /// here-string gives its text, and any other redirect of the input (a
    /// file, a second one) an unknown, since which one the program reads is
    /// not worth working out. The byte where the redirects start comes too.
    /// `None` when the input is not redirected, or the command is part of a
    /// pipeline, where the tree does not say which command a here-document
    /// is for.
    fn input(&self, node: Node<'_>) -> Option<(Arg, usize)> {
        // A here-string is a redirect of the command itself; the others are
        // the redirected statement's, whose body the command is.
        let mut inputs = Vec::new();
        let mut from = usize::MAX;
        let mut cursor = node.walk();
        for redirect in node.children_by_field_name("redirect", &mut cursor) {
            from = from.min(redirect.start_byte());
            self.inputs(redirect, &mut inputs);
        }
        if let Some(redirected) = self.redirected.as_ref().filter(|r| r.body == node.id()) {
            inputs.extend(redirected.inputs.iter().cloned());
            from = from.min(redirected.from);
        }
        let input = match inputs.len() {
            0 => return None,
            1 => inputs.pop().flatten(),
            _ => None,
        };
        Some((
            input.unwrap_or_else(|| Arg::Unknown("<input>".to_string())),
            from,
        ))
    }

    /// What the redirects of a redirected statement are for its body, when
    /// the body is a command; asking the tree for a node's parent walks it
    /// from the top, which a long line would pay for at each command.
    fn redirects(&self, statement: Node<'_>) -> Option<Redirected> {
        let body = statement
            .child_by_field_name("body")
            .filter(|body| body.kind() == "command")?;
        let mut inputs = Vec::new();
        let mut from = usize::MAX;
        let mut cursor = statement.walk();
        for redirect in statement.children_by_field_name("redirect", &mut cursor) {
            from = from.min(redirect.start_byte());
            self.inputs(redirect, &mut inputs);
        }
        Some(Redirected {
            body: body.id(),
            inputs,
            from,
        })
    }

    /// The redirects of the input at `redirect`, also the ones the tree
    /// nests inside a here-document: each is its text when it is one, and
    /// `None` when the program reads something else.
    fn inputs(&self, redirect: Node<'_>, inputs: &mut Vec<Option<Arg>>) {
        let on_input = redirect
            .child_by_field_name("descriptor")
            .is_none_or(|descriptor| unit::text(&descriptor, self.source) == "0");
        let mut cursor = redirect.walk();
        match redirect.kind() {
            "heredoc_redirect" => {
                if on_input {
                    inputs.push(self.heredoc(redirect));
                }
                for child in redirect.named_children(&mut cursor) {
                    if matches!(child.kind(), "file_redirect" | "herestring_redirect") {
                        self.inputs(child, inputs);
                    }
                }
            }
            "herestring_redirect" if on_input => {
                let text = redirect
                    .named_children(&mut cursor)
                    .find(|child| child.kind() != "file_descriptor");
                inputs.push(text.and_then(|text| match self.arg(text) {
                    Arg::Known(text) => Some(Arg::Known(format!("{text}\n"))),
                    _ => None,
                }));
            }
            "file_redirect" if on_input => {
                let operator = redirect
                    .children(&mut cursor)
                    .find(|child| !child.is_named())
                    .map(|child| unit::text(&child, self.source));
                if operator.is_some_and(|operator| operator.starts_with('<')) {
                    inputs.push(None);
                }
            }
            _ => {}
        }
    }

    /// The text of a here-document, when it is plain text: the delimiter is
    /// quoted, or the body has nothing the shell would expand. `<<-` takes
    /// the tabs off the front of each line.
    fn heredoc(&self, redirect: Node<'_>) -> Option<Arg> {
        let mut cursor = redirect.walk();
        let children: Vec<Node<'_>> = redirect.named_children(&mut cursor).collect();
        let start = children
            .iter()
            .find(|child| child.kind() == "heredoc_start")?;
        let body = children
            .iter()
            .find(|child| child.kind() == "heredoc_body")?;
        let delimiter = unit::text(start, self.source);
        let body = unit::text(body, self.source);
        let quoted = delimiter.contains(['\'', '"', '\\']);
        if !quoted && body.contains(['$', '`', '\\']) {
            return None;
        }
        let strips = redirect
            .children(&mut cursor)
            .any(|child| !child.is_named() && unit::text(&child, self.source) == "<<-");
        let text = if strips {
            body.lines()
                .map(|line| line.trim_start_matches('\t'))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            body.to_string()
        };
        Some(Arg::Known(text))
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

    /// `export "NODE_OPTIONS=x"` (a quoted assignment is a string), and
    /// `export NODE_OPTIONS` of a value the line set another way: what node
    /// gets then is not read.
    fn exported_options(&mut self, node: Node<'_>) {
        let word = self.arg(node);
        let source = unit::text(&node, self.source).trim_matches(['"', '\'']);
        match word.known() {
            Some(text) => {
                if let Some(value) = text.strip_prefix("NODE_OPTIONS=") {
                    self.split.node_options.push(Arg::Known(value.to_string()));
                } else if text == "NODE_OPTIONS" {
                    self.split.node_options.push(Arg::Unknown(text.to_string()));
                } else if let Some(value) = text.strip_prefix("PYTHONPATH=") {
                    self.split.python_path.push(Arg::Known(value.to_string()));
                } else if text == "PYTHONPATH" {
                    self.split.python_path.push(Arg::Unknown(text.to_string()));
                }
            }
            None if source.starts_with("NODE_OPTIONS") => {
                self.split
                    .node_options
                    .push(Arg::Unknown(source.to_string()));
            }
            None if source.starts_with("PYTHONPATH") => {
                self.split
                    .python_path
                    .push(Arg::Unknown(source.to_string()));
            }
            None => {}
        }
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
        // Set on a line of its own, or after `export`: the programs after it
        // have it, so it stays for the rest of the line.
        self.node_options(node);
        // `BASH_ENV=f` on a line of its own, or after `export`, is the
        // file every shell started from here on runs.
        if let Some(file) = self.startup(node) {
            self.split.add_startup(file);
        }
    }

    /// Note the value `assignment` gives `NODE_OPTIONS` or `PYTHONPATH`,
    /// when it is one of those variables'.
    fn node_options(&mut self, assignment: Node<'_>) {
        let Some(name) = assignment.child_by_field_name("name") else {
            return;
        };
        let name = unit::text(&name, self.source);
        if name != "NODE_OPTIONS" && name != "PYTHONPATH" {
            return;
        }
        let value = assignment
            .child_by_field_name("value")
            .map_or_else(|| Arg::Known(String::new()), |value| self.arg(value));
        if name == "PYTHONPATH" {
            self.split.python_path.push(value);
        } else {
            self.split.node_options.push(value);
        }
    }

    /// `builtin export PS4=…`, `command declare PS4=…`: the same
    /// assignments as `export` itself makes, behind the builtins that
    /// run it.
    fn declared(&mut self, program: Option<&str>, args: &[Arg]) {
        let mut at = 0;
        let mut name = program;
        while matches!(name, Some("builtin" | "command")) {
            if name == Some("command") {
                while let Some(flags) = args
                    .get(at)
                    .and_then(Arg::known)
                    .filter(|word| word.starts_with('-'))
                {
                    // `command -v export …` only says what `export` is.
                    if flags.contains(['v', 'V']) {
                        return;
                    }
                    at += 1;
                }
            }
            name = args.get(at).and_then(Arg::known);
            at += 1;
        }
        if program != name
            && matches!(
                name,
                Some("export" | "declare" | "typeset" | "local" | "readonly")
            )
        {
            // The words are values already, so the line can no longer say
            // whether `$PWD` was one of them: it is taken as if it was.
            let written = startup::Written {
                expanded: true,
                pwd: true,
            };
            self.startup_words(&args[at..], written);
        }
    }

    /// The `NAME=value` words of `words`, read as assignments that set a
    /// variable the shell runs later.
    fn startup_words(&mut self, words: &[Arg], written: startup::Written) {
        for word in words {
            if let Some((name, value)) = startup::word(word) {
                if let Some(file) = startup::read(self.split, &name, &value, self.depth, written) {
                    self.split.add_startup(file);
                }
            }
        }
    }

    /// Read the assignment `node` for a variable the shell runs later (see
    /// [`startup`]): the file it names when it is `BASH_ENV`.
    fn startup(&mut self, node: Node<'_>) -> Option<startup::Startup> {
        let source = self.source;
        let name = startup::variable(unit::text(&node.child_by_field_name("name")?, source));
        if !startup::VARIABLES.contains(&name) {
            return None;
        }
        let written = node.child_by_field_name("value")?;
        let text = unit::text(&written, source);
        let how = startup::Written {
            expanded: text.contains(['$', '`']),
            pwd: text.contains("PWD"),
        };
        let value = self.arg(written);
        startup::read(self.split, name, &value, self.depth, how)
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
            } else if child.kind() == "file_redirect" {
                self.walk_redirect(child, None, level, own.clone());
            } else {
                self.walk(child, None, level + 1);
            }
        }
        self.split
            .nest(own.clone(), own.end..self.split.units.len());
        self.last_command = own.clone();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some((target, input)) = self.file_redirect(child) {
                self.split.redirect(own.clone(), target, input);
            } else if let Some(text) = self.fed_text(child) {
                self.split.feed(own.clone(), text);
            }
            if let Some(text) = self.fed_literal(child) {
                self.split.text_fed(own.clone(), text);
            }
        }
    }

    /// Walk `redirect`, a redirect of a file on a command whose own units are
    /// `own`. The shell opens the file before the command runs, so when the
    /// command moves the line (`cd sub < f`) the file is read from the folder
    /// the command starts in, not the one it goes to.
    fn walk_redirect(
        &mut self,
        redirect: Node<'_>,
        stage: Option<Stage>,
        level: usize,
        own: Range<usize>,
    ) {
        let from = self.split.starts_in(own);
        let outer = self.split.open_from(from);
        self.walk(redirect, stage, level + 1);
        self.split.open_from(outer);
    }

    /// A here-document's redirect. The grammar holds the redirects written
    /// after its start (`<<EOF < f`) inside it: when `own` is the units of the
    /// command it belongs to, they are placed like any redirect of that
    /// command.
    fn walk_heredoc(
        &mut self,
        node: Node<'_>,
        stage: Option<Stage>,
        level: usize,
        own: Option<Range<usize>>,
    ) {
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
        for (at, child) in children.iter().enumerate() {
            if !child.is_named() {
                continue;
            }
            match &own {
                Some(own) if child.kind() == "file_redirect" => {
                    self.walk_redirect(*child, stage, level, own.clone());
                }
                _ => {
                    let background = children.get(at + 1).is_some_and(|next| next.kind() == "&");
                    self.walk_in(*child, stage, level + 1, background);
                }
            }
        }
    }

    /// A statement with redirects: they belong to its body, whose input and
    /// output they are, and what runs in a here-document is handed to it.
    fn redirected(&mut self, node: Node<'_>, stage: Option<Stage>, level: usize) {
        let body = node.child_by_field_name("body").map(|body| body.id());
        let simple = node
            .child_by_field_name("body")
            .is_some_and(|body| body.kind() == "command");
        // A redirect after a list, a pipeline or a negation is on its last
        // command: `a && cd sub < f` opens `f` from where the `cd` starts.
        let chained = node
            .child_by_field_name("body")
            .and_then(last_simple)
            .is_some();
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
        // The units the redirects are opened before: a plain command's own,
        // or the last command of a list, pipeline or negation.
        let mut placed = 0..0;
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
                if chained {
                    placed = self.last_command.clone();
                }
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
                if child.kind() == "file_redirect" {
                    // Only a plain command's redirect is opened before the
                    // unit that moves the line runs: what a group holds is
                    // not read that way.
                    let on = if simple { own.clone() } else { placed.clone() };
                    self.walk_redirect(*child, stage, level, on);
                } else if child.kind() == "heredoc_redirect" {
                    let on = if simple { own.clone() } else { placed.clone() };
                    self.walk_heredoc(*child, stage, level, Some(on));
                } else {
                    self.walk(*child, stage, level + 1);
                }
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
            if let Some(text) = self.fed_literal(child) {
                self.split.text_fed(own.clone(), text);
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
    fn declaration(&mut self, node: Node<'_>, stage: Option<Stage>) {
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

    /// The text a here-string or a here-document feeds, as written, whether
    /// or not it holds an expansion (a template when it does): the
    /// statements a database client reads from its input.
    fn fed_literal(&self, node: Node<'_>) -> Option<Arg> {
        let mut cursor = node.walk();
        match node.kind() {
            "herestring_redirect" => Some(self.arg(node.named_children(&mut cursor).next()?)),
            "heredoc_redirect" => {
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                let kind = |kind: &str| children.iter().find(|child| child.kind() == kind);
                let body = kind("heredoc_body");
                let opened = kind("heredoc_start").map(|start| start.end_position().row);
                // A first line that starts with a backslash is read as
                // arguments of the redirect, not as the start of the body;
                // the body is what is on the lines after the one that
                // opens it.
                let mut arguments = node.walk();
                let lost: Vec<Node<'_>> = node
                    .children_by_field_name("argument", &mut arguments)
                    .filter(|argument| {
                        opened.is_some_and(|row| argument.start_position().row > row)
                    })
                    .collect();
                let from = lost
                    .iter()
                    .map(Node::start_byte)
                    .chain(body.map(Node::start_byte))
                    .min();
                let end = kind("heredoc_end")
                    .map(Node::start_byte)
                    .or_else(|| body.map(Node::end_byte));
                let (Some(from), Some(end)) = (from, end) else {
                    return Some(Arg::Known(String::new()));
                };
                // From the start of its line.
                let from = self
                    .source
                    .get(..from)
                    .and_then(|before| before.rfind('\n'))
                    .map_or(0, |newline| newline + 1);
                let raw = self.source.get(from..end).unwrap_or_default();
                // The delimiter is quoted when any part of it is: `'EOF'`,
                // `"EOF"`, `\EOF`.
                let quoted = kind("heredoc_start").is_some_and(|start| {
                    unit::text(start, self.source).contains(['\'', '"', '\\'])
                });
                let strips = node
                    .children(&mut cursor)
                    .find(|child| !child.is_named())
                    .is_some_and(|operator| unit::text(&operator, self.source) == "<<-");
                Some(heredoc_fed(raw, strips, quoted))
            }
            _ => None,
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
        let before = self.split.qualify(self.qualified(destination));
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
        self.split.restore_qualified(before);
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
    /// unless the line sets them (or moves, for `$PWD`, to a name that may
    /// hold code); any other variable is only known when it runs.
    fn variable(&self, source: &str) -> Arg {
        let name = source
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
            .or_else(|| source.strip_prefix('$'))
            .filter(|name| !self.split.reassigned(name));
        match name {
            Some("HOME") => Arg::Known("~".to_string()),
            // After a `cd` to a name the line chose that may hold code
            // (`d$(rm -rf ~)`, or one only known when it runs), `$PWD` is
            // that name: text a `PS4` or `BASH_ENV` expands again.
            Some("PWD") if self.split.pwd_is_plain() => Arg::Known(".".to_string()),
            Some("TMPDIR") => Arg::Known("/tmp".to_string()),
            _ => Arg::Unknown(source.to_string()),
        }
    }
}

/// The text a here-document feeds, from the lines of its body as written.
/// `<<-` takes the tabs off the front of each line, whatever the delimiter.
/// With a quoted delimiter the body is fed as it is. With an unquoted one the
/// shell reads it as the inside of a double-quoted word, without the quotes:
/// a backslash before a newline joins the lines, and before `$`, a backtick
/// or a backslash it goes and leaves the character; any other backslash
/// stays. What is left of `$` or a backtick is an expansion, so the text is a
/// template (`$$` is the shell's process id, and tree-sitter does not read it
/// as an expansion). A body with both an escaped and an expanding `$` or
/// backtick is known only when it runs: a template reads each `$` it holds as
/// an expansion, and would take a character the client gets as it is for one.
fn heredoc_fed(raw: &str, strips: bool, quoted: bool) -> Arg {
    let lines: String = if strips {
        raw.split_inclusive('\n')
            .map(|line| line.trim_start_matches('\t'))
            .collect()
    } else {
        raw.to_string()
    };
    if quoted {
        return Arg::Known(lines);
    }
    let mut text = String::with_capacity(lines.len());
    let (mut escaped, mut expands) = (false, false);
    let mut chars = lines.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek().copied()) {
            ('\\', Some('\n')) => {
                chars.next();
            }
            ('\\', Some(next @ ('$' | '`' | '\\'))) => {
                chars.next();
                text.push(next);
                escaped |= next != '\\';
            }
            ('$' | '`', _) => {
                expands = true;
                text.push(c);
            }
            _ => text.push(c),
        }
    }
    match (escaped, expands) {
        (true, true) => Arg::Unknown(raw.to_string()),
        (false, true) => Arg::Template {
            text,
            source: raw.to_string(),
        },
        (_, false) => Arg::Known(text),
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
