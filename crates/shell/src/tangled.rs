//! The counts taken before a script is parsed: shapes a grammar takes too
//! long over, or that are too deep to read whatever it makes of them, found
//! by counting bytes.
//!
//! Text the shell surely reads as a literal is not counted, since nothing in
//! it is a command: in a POSIX shell a single-quoted string (`'…'`, `$'…'`)
//! and the body of a here-document whose delimiter is quoted (`<<'EOF'`), or
//! is a plain name and whose body holds no `$(`, backquote or backslash; in
//! cmd a string quoted on one line. Each is found by a walk that keeps track
//! of double quotes, escapes, comments and brackets: a command substitution
//! (`$( … )`), in a double-quoted string or not, is walked as code up to the
//! `)` that closes it, and a `<<` in arithmetic (`(( … ))`, `$(( … ))`,
//! `$[ … ]`) is a shift, not a here-document. The walk stops skipping for
//! the rest of the text at anything it cannot follow for sure (a backquote
//! in double quotes, a quote or a here-document that is not closed, a
//! here-document delimiter with an expansion, a `case` inside brackets,
//! whose patterns close with a `)` that opened nothing): there it counts
//! everything, so a mistake can only count more. The walk is one pass over
//! the text.

use crate::unit::MAX_TREE_DEPTH;
use crate::Shell;

/// The most here-documents a POSIX script may start on one line before it is
/// not read: the bash grammar holds each until the line ends and takes time
/// that grows with the square of how many are waiting (a second, at the
/// length limit), and no real script starts this many on a line. Here-
/// documents on lines of their own that follow a command (`cat <<A` and a
/// line break, repeated) cost no more than the text does, and here-strings
/// (`<<<`) are not here-documents.
const MAX_HEREDOCS: usize = 256;

/// The most `&`, and the most `|`, a cmd line may hold before it is not
/// read: cmd's grammar nests a chain one level for each, so a line past
/// the depth the walk goes is unreadable whatever else it holds, and its
/// grammar takes time that grows with the square of the chain to find that
/// out (seconds, at the length limit).
const MAX_CMD_SEPARATORS: usize = MAX_TREE_DEPTH;

/// The most pipes (`|`, not `||`) one POSIX pipeline may hold outside
/// quotes before the line is not read: the bash grammar takes time that
/// grows with the square of the stages of a pipeline that ends in an error
/// (`a|` repeated to the length limit takes 20 to 30 seconds in a release
/// build), and no real pipeline has this many stages. A pipeline ends at `;`,
/// `&`, `&&`, `||` and a line break that does not follow a `|`, so a line
/// may hold many short ones (a script of 450 `grep x f | wc -l`); a list in
/// brackets (`( … )`, `$( … )`, `{ … }`) is part of the pipeline around it,
/// whose pipes it adds to. A `|` in a double-quoted string or a comment is
/// text (a table in a pull request's body) and is not counted.
const MAX_PIPES: usize = MAX_TREE_DEPTH;

/// Whether the grammar of `shell` would take too long over `text`, and why,
/// found by counting bytes without parsing, outside the literals the module
/// comment names:
///
/// - more brackets opened, with none closed in between, than a parse tree
///   is walked deep: the line is unreadable whatever the grammar makes of
///   it, and the grammars take seconds to find that out at the length limit
///   (see [`Openers`]);
/// - in cmd, more `&`, or more `|`, than [`MAX_CMD_SEPARATORS`] (`&&` and
///   `||` count once);
/// - in a POSIX shell, more here-documents started on one line (a `\` before
///   the line break continues it) than [`MAX_HEREDOCS`], and more pipes in
///   one pipeline, outside double quotes, than [`MAX_PIPES`].
pub(crate) fn too_tangled(text: &str, shell: Shell) -> Option<&'static str> {
    let counted = match shell {
        Shell::Posix => posix(text.as_bytes()),
        Shell::Cmd => cmd(text.as_bytes()),
        Shell::PowerShell => Counted::raw(text.as_bytes()),
    };
    let bytes = counted.bytes.as_slice();
    let mut openers = Openers::default();
    let mut heredocs = 0_usize;
    let (mut ands, mut pipes) = (0_usize, 0_usize);
    let mut pipelines = Pipelines {
        command: true,
        last: b'\n',
        ..Pipelines::default()
    };
    // How many `<` in a row end just before `at`, and whether the `&` or `|`
    // just before it was the second of a pair.
    let (mut run, mut paired) = (0_usize, false);
    // A line break after the text settles a run of `<` at its end.
    for (at, byte) in bytes
        .iter()
        .copied()
        .chain(std::iter::once(b'\n'))
        .enumerate()
    {
        if shell == Shell::Posix && counted.code(at) && pipelines.too_many(bytes, at) {
            return Some("chains too many commands to read");
        }
        if byte == b'<' {
            run += 1;
            continue;
        }
        // `<<EOF` starts a here-document, `<<<` a here-string; more than
        // three in a row is noise, which counts.
        if shell == Shell::Posix && (run == 2 || run >= 4) {
            heredocs += 1;
            if heredocs > MAX_HEREDOCS {
                return Some("starts too many here-documents to read");
            }
        }
        run = 0;
        if openers.too_deep(bytes, at, shell) {
            return Some("nests too deeply to read");
        }
        match byte {
            b'\n' if at == 0 || bytes[at - 1] != b'\\' => heredocs = 0,
            b'&' | b'|' if shell == Shell::Cmd => {
                // The second of two the same is part of `&&` or `||`.
                let second = !paired && at >= 1 && bytes[at - 1] == byte;
                paired = second;
                if !second {
                    let count = if byte == b'&' { &mut ands } else { &mut pipes };
                    *count += 1;
                    if *count > MAX_CMD_SEPARATORS {
                        return Some("chains too many commands to read");
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// The brackets a script opens and has not closed, counted byte by byte,
/// each kind apart, so a closer counts off only the kind it closes: `(` in
/// every shell; `${` in a POSIX shell, where a `{` elsewhere is a word as
/// often as a group; `{` and `[` in PowerShell, which open a block, a hash
/// table, a variable's name (`${…}`), a type or an index. To find a line
/// of them unreadable, cmd's grammar takes time that grows with the square
/// of the depth, PowerShell's lexer reads on to the next `}` at each `${`,
/// and the grammars recover from an error at each, up to a second at the
/// length limit; the count reads the line once.
#[derive(Default)]
struct Openers {
    parens: usize,
    braces: usize,
    squares: usize,
}

impl Openers {
    /// Count the byte at `at`; whether more are open now than a parse tree
    /// is walked deep.
    fn too_deep(&mut self, bytes: &[u8], at: usize, shell: Shell) -> bool {
        let count = match bytes.get(at) {
            Some(b'(' | b')') => &mut self.parens,
            Some(b'{') if shell == Shell::PowerShell => &mut self.braces,
            Some(b'{') if shell == Shell::Posix && at > 0 && bytes[at - 1] == b'$' => {
                &mut self.braces
            }
            // Only a `${` is counted in a POSIX shell, but any `}` may
            // close it.
            Some(b'}') if shell != Shell::Cmd => &mut self.braces,
            Some(b'[' | b']') if shell == Shell::PowerShell => &mut self.squares,
            _ => return false,
        };
        if matches!(bytes.get(at), Some(b')' | b'}' | b']')) {
            *count = count.saturating_sub(1);
            return false;
        }
        *count += 1;
        self.parens + self.braces + self.squares > MAX_TREE_DEPTH
    }
}

/// The pipes of each POSIX pipeline, counted byte by byte over the code
/// (see [`MAX_PIPES`]).
#[derive(Default)]
struct Pipelines {
    /// The pipes of the pipeline the count is in.
    piped: usize,
    /// The pipes of the pipeline a separator just ended: a `|` right after
    /// it is an error the grammar reads as going on with that pipeline.
    held: Option<usize>,
    /// The brackets and compound commands open, innermost last, each with
    /// the pipes counted when it opened: a list in it ends a pipeline only
    /// back to there.
    open: Vec<(Group, usize)>,
    /// Whether a word that starts now is in command position, where a
    /// reserved word is one.
    command: bool,
    /// The last byte of code before this one that is not a blank.
    last: u8,
}

/// A bracket or compound command a pipeline may go on around.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Paren,
    Brace,
    Test,
    If,
    Loop,
    Case,
}

impl Pipelines {
    /// Count the byte of code at `at`; whether the pipeline it is in now
    /// has too many pipes. A line break is the last byte.
    fn too_many(&mut self, bytes: &[u8], at: usize) -> bool {
        let byte = bytes.get(at).copied().unwrap_or(b'\n');
        if matches!(byte, b' ' | b'\t') {
            return false;
        }
        let before = at.checked_sub(1).and_then(|at| bytes.get(at)).copied();
        let after = bytes.get(at + 1).copied();
        let last = std::mem::replace(&mut self.last, byte);
        let separator = match byte {
            // `||` is a list, not a pipe.
            b'|' if before == Some(b'|') || after == Some(b'|') => true,
            b'|' => {
                if let Some(held) = self.held.take() {
                    self.piped = self.piped.max(held);
                }
                self.piped += 1;
                self.command = true;
                return self.piped > MAX_PIPES;
            }
            // `|&`, `>&`, `<&` and `&>` are not lists.
            b'&' => !matches!(before, Some(b'|' | b'<' | b'>')) && after != Some(b'>'),
            b';' => true,
            // A line break after a `|` goes on with the pipeline, and one
            // after a backslash joins the lines.
            b'\n' => last != b'|' && before != Some(b'\\'),
            _ => false,
        };
        if separator {
            let base = self.open.last().map_or(0, |(_, base)| *base);
            self.held = Some(self.held.map_or(self.piped, |held| held.max(self.piped)));
            self.piped = base;
            self.command = true;
            return false;
        }
        if matches!(byte, b'&' | b'\n' | b'<' | b'>') {
            return false;
        }
        self.held = None;
        match byte {
            b'(' => {
                self.opened(Group::Paren);
                self.command = true;
            }
            // In a `case`, a `)` that opened nothing ends a pattern.
            b')' if self.open.last().map(|(group, _)| *group) == Some(Group::Case) => {
                self.command = true;
            }
            b')' => {
                self.closed(Group::Paren);
                self.command = false;
            }
            _ if before.is_none_or(breaks_word) => {
                let word = &bytes[at..];
                let word = &word[..word
                    .iter()
                    .position(|byte| breaks_word(*byte))
                    .unwrap_or(word.len())];
                self.word(word);
            }
            _ => {}
        }
        false
    }

    /// Read a word, which may be a reserved one.
    fn word(&mut self, word: &[u8]) {
        let command = std::mem::replace(&mut self.command, false);
        if !command {
            if word == b"]]" {
                self.closed(Group::Test);
            }
            return;
        }
        match word {
            b"if" => self.opened(Group::If),
            b"while" | b"until" => self.opened(Group::Loop),
            b"for" | b"select" => {
                self.opened(Group::Loop);
                return;
            }
            b"case" => {
                self.opened(Group::Case);
                return;
            }
            b"{" => self.opened(Group::Brace),
            b"[[" => {
                self.opened(Group::Test);
                return;
            }
            b"then" | b"else" | b"elif" | b"do" | b"!" | b"time" => {}
            b"fi" => return self.closed(Group::If),
            b"done" => return self.closed(Group::Loop),
            b"esac" => return self.closed(Group::Case),
            b"}" => return self.closed(Group::Brace),
            _ => return,
        }
        self.command = true;
    }

    fn opened(&mut self, group: Group) {
        self.open.push((group, self.piped));
    }

    /// Close `group` if it is the innermost open; a word or bracket that
    /// closes another is an error, and closes nothing.
    fn closed(&mut self, group: Group) {
        if self.open.last().map(|(open, _)| *open) == Some(group) {
            self.open.pop();
        }
    }
}

/// A text as the counts read it.
struct Counted {
    /// The bytes counted: the text, with each literal skipped left as one
    /// `x` (so the words beside it stay apart), and each here-document body
    /// skipped left out.
    bytes: Vec<u8>,
    /// What each byte is.
    kinds: Vec<Kind>,
}

/// What a byte of a POSIX script is, to the count of pipes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Code,
    /// In a double-quoted string, where a `|` is text.
    Text,
    /// In a comment.
    Comment,
}

impl Counted {
    fn raw(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            kinds: vec![Kind::Code; bytes.len()],
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            kinds: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, byte: u8, kind: Kind) {
        self.bytes.push(byte);
        self.kinds.push(kind);
    }

    fn extend(&mut self, bytes: &[u8], kind: Kind) {
        self.bytes.extend_from_slice(bytes);
        self.kinds.resize(self.bytes.len(), kind);
    }

    /// Whether the byte at `at` is code.
    fn code(&self, at: usize) -> bool {
        self.kinds.get(at) == Some(&Kind::Code)
    }

    /// Everything from `at` on counted, and the walk over: what comes next
    /// cannot be followed for sure.
    fn rest(mut self, bytes: &[u8], at: usize) -> Self {
        self.extend(bytes.get(at..).unwrap_or_default(), Kind::Code);
        self
    }
}

/// A bracket the POSIX walk is in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bracket {
    /// `(`: a subshell, a function's `()`, a pattern.
    Plain,
    /// `$(`; `string` says it is in a double-quoted string, which goes on
    /// after the `)`.
    Substitution { string: bool },
    /// The outer `(` of `((` or `$((`.
    Arithmetic,
    /// `$[`, and a `[` in it.
    Square,
}

/// The brackets a POSIX walk is in, innermost last.
#[derive(Default)]
struct Brackets {
    open: Vec<Bracket>,
    /// How many of them are arithmetic, where `<<` is a shift.
    arithmetic: usize,
}

impl Brackets {
    fn push(&mut self, bracket: Bracket) {
        if matches!(bracket, Bracket::Arithmetic | Bracket::Square) {
            self.arithmetic += 1;
        }
        self.open.push(bracket);
    }

    /// Close the innermost bracket on `byte` (`)` or `]`), if it is one
    /// that byte closes.
    fn close(&mut self, byte: u8) -> Option<Bracket> {
        let last = *self.open.last()?;
        if (byte == b']') != (last == Bracket::Square) {
            return None;
        }
        self.open.pop();
        if matches!(last, Bracket::Arithmetic | Bracket::Square) {
            self.arithmetic -= 1;
        }
        Some(last)
    }

    /// Open `$(` at `at` (just past the `$`), or `$((`; `string` says it is
    /// in a double-quoted string. Where the walk goes on.
    fn substitution(
        &mut self,
        counted: &mut Counted,
        bytes: &[u8],
        at: usize,
        string: bool,
    ) -> usize {
        self.push(Bracket::Substitution { string });
        counted.push(b'(', Kind::Code);
        if bytes.get(at + 1) == Some(&b'(') {
            self.push(Bracket::Arithmetic);
            counted.push(b'(', Kind::Code);
            return at + 2;
        }
        at + 1
    }
}

/// What a POSIX script's counts read (see the module comment).
fn posix(bytes: &[u8]) -> Counted {
    let mut counted = Counted::with_capacity(bytes.len());
    let mut at = 0;
    let (mut double, mut comment, mut dollar) = (false, false, false);
    let mut waiting: Vec<Heredoc> = Vec::new();
    let mut brackets = Brackets::default();
    while let Some(&byte) = bytes.get(at) {
        if comment && byte != b'\n' {
            counted.push(byte, Kind::Comment);
            at += 1;
            continue;
        }
        comment = false;
        if double {
            match byte {
                b'\\' => {
                    counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), Kind::Text);
                    at += 2;
                }
                b'"' => {
                    counted.push(byte, Kind::Text);
                    double = false;
                    at += 1;
                }
                // A backquote's substitution in a string holds quotes and
                // backslashes of its own.
                b'`' => return counted.rest(bytes, at),
                // A `$(` in a string is code up to its `)`, and the string
                // goes on after it.
                b'$' if bytes.get(at + 1) == Some(&b'(') => {
                    counted.push(byte, Kind::Code);
                    at = brackets.substitution(&mut counted, bytes, at + 1, true);
                    double = false;
                }
                _ => {
                    counted.push(byte, Kind::Text);
                    at += 1;
                }
            }
            continue;
        }
        let after_dollar = std::mem::replace(&mut dollar, false);
        match byte {
            b'\\' => {
                counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), Kind::Code);
                at += 2;
            }
            b'\'' => match single_closed(bytes, at + 1, after_dollar) {
                Some(end) => {
                    counted.push(b'x', Kind::Code);
                    at = end + 1;
                }
                None => return counted.rest(bytes, at),
            },
            b'"' => {
                counted.push(byte, Kind::Text);
                double = true;
                at += 1;
            }
            b'#' if at == 0 || breaks_word(bytes[at - 1]) => {
                counted.push(byte, Kind::Comment);
                comment = true;
                at += 1;
            }
            b'(' if after_dollar => at = brackets.substitution(&mut counted, bytes, at, false),
            b'(' => {
                let arithmetic = bytes.get(at + 1) == Some(&b'(');
                brackets.push(if arithmetic {
                    Bracket::Arithmetic
                } else {
                    Bracket::Plain
                });
                counted.push(byte, Kind::Code);
                at += 1;
            }
            b'[' if after_dollar || brackets.open.last() == Some(&Bracket::Square) => {
                brackets.push(Bracket::Square);
                counted.push(byte, Kind::Code);
                at += 1;
            }
            b')' | b']' => {
                if brackets.close(byte) == Some(Bracket::Substitution { string: true }) {
                    double = true;
                }
                counted.push(byte, Kind::Code);
                at += 1;
            }
            // A `case` pattern closes with a `)` that opened nothing, which
            // in brackets would close the wrong one.
            b'c' if !brackets.open.is_empty()
                && (at == 0 || breaks_word(bytes[at - 1]))
                && bytes[at..].starts_with(b"case")
                && bytes.get(at + 4).is_none_or(|byte| breaks_word(*byte)) =>
            {
                return counted.rest(bytes, at);
            }
            b'<' => {
                let run = bytes[at..].iter().take_while(|byte| **byte == b'<').count();
                counted.extend(&bytes[at..at + run], Kind::Code);
                at += run;
                // In arithmetic, `<<` is a shift.
                if run == 2 && brackets.arithmetic == 0 {
                    let Some((heredoc, end)) = heredoc(bytes, at) else {
                        return counted.rest(bytes, at);
                    };
                    counted.extend(&bytes[at..end], Kind::Code);
                    at = end;
                    waiting.push(heredoc);
                }
            }
            b'\n' => {
                counted.push(byte, Kind::Code);
                at += 1;
                // The bodies of the here-documents the line started follow
                // it, in order.
                for heredoc in waiting.drain(..) {
                    let Some(end) = heredoc.body_end(bytes, at) else {
                        return counted.rest(bytes, at);
                    };
                    if !heredoc.literal(&bytes[at..end]) {
                        counted.extend(&bytes[at..end], Kind::Code);
                    }
                    at = end;
                }
            }
            _ => {
                counted.push(byte, Kind::Code);
                dollar = byte == b'$';
                at += 1;
            }
        }
    }
    counted
}

/// Where the single-quoted string whose text starts at `from` closes; `ansi`
/// says it is a `$'…'` string, in which a backslash escapes the next byte.
fn single_closed(bytes: &[u8], from: usize, ansi: bool) -> Option<usize> {
    let mut at = from;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\'' => return Some(at),
            b'\\' if ansi => at += 2,
            _ => at += 1,
        }
    }
    None
}

/// Whether `byte` ends a word, so a `#` after it starts a comment.
fn breaks_word(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
    )
}

/// A here-document a line started, waiting for its body.
struct Heredoc {
    /// The delimiter, its quotes taken off.
    word: Vec<u8>,
    /// Whether the delimiter was quoted, which makes the body a literal.
    quoted: bool,
    /// `<<-`: tabs before the closing delimiter are taken off.
    tabs: bool,
}

impl Heredoc {
    /// The end of the body that starts at `from`, just past the line that
    /// closes it; `None` when no line does.
    fn body_end(&self, bytes: &[u8], from: usize) -> Option<usize> {
        let mut start = from;
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |at| start + at);
            let mut line = &bytes[start..end];
            while self.tabs && line.first() == Some(&b'\t') {
                line = &line[1..];
            }
            if line == self.word.as_slice() {
                return Some((end + 1).min(bytes.len()));
            }
            start = end + 1;
        }
        None
    }

    /// Whether `body` is a literal to the shell: the delimiter was quoted, or
    /// is a plain name (not the operand of a shift in arithmetic) and the body
    /// expands nothing that runs and joins no lines.
    fn literal(&self, body: &[u8]) -> bool {
        self.quoted
            || (self
                .word
                .first()
                .is_some_and(|first| first.is_ascii_alphabetic() || *first == b'_')
                && self
                    .word
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                && !body.contains(&b'`')
                && !body.contains(&b'\\')
                && !body.windows(2).any(|pair| pair == b"$("))
    }
}

/// The here-document whose delimiter follows `<<` at `at`, and where the
/// delimiter ends; `None` for one the walk cannot follow (no delimiter, or
/// one with an expansion in it).
fn heredoc(bytes: &[u8], mut at: usize) -> Option<(Heredoc, usize)> {
    let tabs = bytes.get(at) == Some(&b'-');
    at += usize::from(tabs);
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    let (mut word, mut quoted) = (Vec::new(), false);
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\'' => {
                let end = single_closed(bytes, at + 1, false)?;
                word.extend_from_slice(&bytes[at + 1..end]);
                quoted = true;
                at = end + 1;
            }
            b'"' => {
                at += 1;
                loop {
                    match *bytes.get(at)? {
                        b'"' => break,
                        b'$' | b'`' => return None,
                        b'\\' => {
                            word.push(*bytes.get(at + 1)?);
                            at += 2;
                        }
                        other => {
                            word.push(other);
                            at += 1;
                        }
                    }
                }
                quoted = true;
                at += 1;
            }
            b'\\' => {
                word.push(*bytes.get(at + 1)?);
                quoted = true;
                at += 2;
            }
            b'$' | b'`' => return None,
            byte if breaks_word(byte) => break,
            byte => {
                word.push(byte);
                at += 1;
            }
        }
    }
    (!word.is_empty()).then_some((Heredoc { word, quoted, tabs }, at))
}

/// What a cmd script's counts read: a string closed on its line is a
/// literal; `^` escapes the byte after it, a `"` too.
fn cmd(bytes: &[u8]) -> Counted {
    let mut counted = Counted::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'^' => {
                counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), Kind::Code);
                at += 2;
            }
            b'"' => {
                let close = bytes[at + 1..]
                    .iter()
                    .position(|byte| matches!(byte, b'"' | b'\n'))
                    .map(|end| at + 1 + end)
                    .filter(|end| bytes[*end] == b'"');
                if let Some(end) = close {
                    counted.push(b'x', Kind::Code);
                    at = end + 1;
                } else {
                    counted.push(byte, Kind::Code);
                    at += 1;
                }
            }
            _ => {
                counted.push(byte, Kind::Code);
                at += 1;
            }
        }
    }
    counted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str, shell: Shell) -> String {
        let counted = match shell {
            Shell::Posix => posix(text.as_bytes()),
            _ => cmd(text.as_bytes()),
        };
        String::from_utf8_lossy(&counted.bytes).into_owned()
    }

    #[test]
    fn literals_are_skipped_and_what_cannot_be_followed_is_counted() {
        for (text, counted) in [
            ("echo 'a(b' c", "echo x c"),
            ("echo $'a\\'(' c", "echo $x c"),
            ("echo \\'(( c", "echo \\'(( c"),
            ("echo \"it's\" '('", "echo \"it's\" x"),
            ("echo 'open (", "echo 'open ("),
            // A comment's quote starts nothing.
            ("# it's\necho ((", "# it's\necho (("),
            ("a#'b' 'c'", "a#x x"),
            // Bodies: quoted, plain, and those that may run something.
            ("cat <<'E'\n(((\nE\necho", "cat <<'E'\necho"),
            ("cat <<\"E\" >x\n(((\nE\n", "cat <<\"E\" >x\n"),
            ("cat <<-\\E\n(\n\tE\n'('", "cat <<-\\E\nx"),
            ("cat <<E\na(b\nE\n", "cat <<E\n"),
            ("cat <<E\n$(a)\nE\n", "cat <<E\n$(a)\nE\n"),
            ("cat <<E\na \\\nE\n", "cat <<E\na \\\nE\n"),
            ("cat <<'E'\n(\n", "cat <<'E'\n(\n"),
            ("echo $((1<<2))\n'('", "echo $((1<<2))\nx"),
            ("cat <<$x\n'('\n$x\n", "cat <<$x\n'('\n$x\n"),
            ("cat <<'A' <<B\na\nA\n(\nB\n'('", "cat <<'A' <<B\nx"),
            // A substitution is walked to its `)`, in a string or not; a
            // backquote in a string ends the walk.
            ("echo \"$(echo ')')\" '('", "echo \"$(echo x)\" x"),
            (
                "echo \"a $(b \"$(c)\" ')') d\" '('",
                "echo \"a $(b \"$(c)\" x) d\" x",
            ),
            (
                "git commit -m \"$(cat <<'EOF'\n| a | (b |\nEOF\n)\" '('",
                "git commit -m \"$(cat <<'EOF'\n)\" x",
            ),
            ("echo $(cat <<'E'\n(\nE\n) '('", "echo $(cat <<'E'\n) x"),
            ("echo \"$((1<<2))\" '('", "echo \"$((1<<2))\" x"),
            ("echo \"`a`\" '('", "echo \"`a`\" '('"),
            // A `case` in brackets ends the walk: its `)` opened nothing.
            (
                "x=\"$(case a in a) ;; esac)\" '('",
                "x=\"$(case a in a) ;; esac)\" '('",
            ),
            // In arithmetic, `<<` is a shift and starts no here-document.
            ("((x=1<<y))\n'('\ny\n", "((x=1<<y))\nx\ny\n"),
            ("echo $((1<<y))\n'('\ny\n", "echo $((1<<y))\nx\ny\n"),
            ("echo $[1<<y]\n'('\ny\n", "echo $[1<<y]\nx\ny\n"),
            ("echo $[a[1]<<y]\n'('\ny\n", "echo $[a[1]<<y]\nx\ny\n"),
            ("((x=1)); cat <<y\n'('\ny\n", "((x=1)); cat <<y\n"),
        ] {
            assert_eq!(read(text, Shell::Posix), counted, "{text:?}");
        }
        for (text, counted) in [
            ("echo \"a & b\" & c", "echo x & c"),
            ("echo ^\"a & b\" & c", "echo ^\"a & b\" & c"),
            ("echo \"a &\nb\"", "echo \"a &\nb\""),
        ] {
            assert_eq!(read(text, Shell::Cmd), counted, "{text:?}");
        }
    }

    #[test]
    fn a_pair_in_cmd_counts_once() {
        for separator in ["& ", "| ", "&& ", "|| "] {
            let line = |n| format!("echo {}", separator.repeat(n));
            assert!(too_tangled(&line(400), Shell::Cmd).is_none(), "{separator}");
            assert!(too_tangled(&line(401), Shell::Cmd).is_some(), "{separator}");
        }
    }

    #[test]
    fn a_pipe_in_double_quotes_is_text() {
        let pipes = |text: &str| too_tangled(text, Shell::Posix);
        assert!(pipes(&format!("echo \"{}\"", "| a ".repeat(1_000))).is_none());
        assert!(pipes(&format!("echo a # {}", "| a ".repeat(1_000))).is_none());
        assert!(pipes(&"a | ".repeat(401)).is_some());
        assert!(pipes(&"a | ".repeat(400)).is_none());
        assert!(pipes(&"a || ".repeat(1_000)).is_none());
    }

    #[test]
    fn pipes_are_counted_in_each_pipeline() {
        let pipes = |text: &str| too_tangled(text, Shell::Posix).is_some();
        // A pipeline ends at a list's separators and a line break.
        for separator in ["; ", "& ", "&& ", "|| ", "\n"] {
            let line = format!("a{}", format!(" | a{separator}a").repeat(1_000));
            assert!(!pipes(&line), "{separator:?}");
        }
        // It goes on past a line break after a `|`, a backslash and line
        // break, `|&` and a redirect of a descriptor.
        for stage in [
            "a |\n",
            "a | # b\n",
            "a \\\n| ",
            "a |& ",
            "a 2>&1 | ",
            "a &>x | ",
            "a >&2 | ",
        ] {
            assert!(pipes(&stage.repeat(401)), "{stage:?}");
            assert!(!pipes(&stage.repeat(400)), "{stage:?}");
        }
        // A list in brackets ends a pipeline only inside them: what it
        // pipes adds to the pipeline around it.
        for stage in [
            "a | (b; c) | ",
            "a | { b; } | ",
            "a | $(b; c) | ",
            "a | (b | c; d) | ",
        ] {
            assert!(pipes(&stage.repeat(201)), "{stage:?}");
        }
        assert!(!pipes(&"(a | b; c | d); ".repeat(1_000)));
    }
}
