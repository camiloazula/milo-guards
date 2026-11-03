//! The counts taken before a script is parsed: shapes a grammar takes too
//! long over, or that are too deep to read whatever it makes of them, found
//! by counting bytes.
//!
//! Text the shell surely reads as a literal is not counted, since nothing in
//! it is a command: in a POSIX shell a single-quoted string (`'…'`, `$'…'`)
//! and the body of a here-document whose delimiter is quoted (`<<'EOF'`), or
//! is a plain name and whose body holds no `$(`, backquote or backslash; in
//! cmd a string quoted on one line. Each is found by a walk that keeps track
//! of double quotes, escapes and comments, and stops skipping for the rest
//! of the text at anything it cannot follow for sure (a substitution inside
//! double quotes, a quote or a here-document that is not closed, a
//! here-document delimiter with an expansion): there it counts everything,
//! so a mistake can only count more. The walk is one pass over the text.

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

/// The most pipes (`|`, not `||`) a POSIX script may hold outside quotes
/// before it is not read: the bash grammar takes time that grows with the
/// square of the stages of a pipeline that ends in an error (`a|` repeated
/// to the length limit takes 20 to 30 seconds in a release build), and no
/// real line pipes this many times. A `|` in a double-quoted string is text
/// (a table in a pull request's body) and is not counted.
const MAX_PIPES: usize = MAX_TREE_DEPTH;

/// Whether the grammar of `shell` would take too long over `text`, and why,
/// found by counting bytes without parsing, outside the literals the module
/// comment names:
///
/// - more `(` opened (`{` and `[` are not counted), with none closed in
///   between, than a parse tree is walked deep (the line is unreadable
///   whatever the grammar makes of it, and cmd's takes seconds to find that
///   out at the length limit);
/// - in cmd, more `&`, or more `|`, than [`MAX_CMD_SEPARATORS`] (`&&` and
///   `||` count once);
/// - in a POSIX shell, more here-documents started on one line (a `\` before
///   the line break continues it) than [`MAX_HEREDOCS`], and more pipes
///   outside double quotes than [`MAX_PIPES`].
pub(crate) fn too_tangled(text: &str, shell: Shell) -> Option<&'static str> {
    let counted = match shell {
        Shell::Posix => posix(text.as_bytes()),
        Shell::Cmd => cmd(text.as_bytes()),
        Shell::PowerShell => Counted::raw(text.as_bytes()),
    };
    let bytes = counted.bytes.as_slice();
    let (mut open, mut heredocs, mut piped) = (0_usize, 0_usize, 0_usize);
    let (mut ands, mut pipes) = (0_usize, 0_usize);
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
        match byte {
            b'(' => {
                open += 1;
                if open > MAX_TREE_DEPTH {
                    return Some("nests too deeply to read");
                }
            }
            b')' => open = open.saturating_sub(1),
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
            b'|' if shell == Shell::Posix => {
                // `||` is a list, not a pipe.
                let alone = (at == 0 || bytes[at - 1] != b'|') && bytes.get(at + 1) != Some(&b'|');
                if alone && !counted.quoted.get(at).copied().unwrap_or(false) {
                    piped += 1;
                    if piped > MAX_PIPES {
                        return Some("chains too many commands to read");
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// A text as the counts read it.
struct Counted {
    /// The bytes counted: the text, with each literal skipped left as one
    /// `x` (so the words beside it stay apart), and each here-document body
    /// skipped left out.
    bytes: Vec<u8>,
    /// For each byte, whether it is in a double-quoted string, where a `|`
    /// is text.
    quoted: Vec<bool>,
}

impl Counted {
    fn raw(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            quoted: vec![false; bytes.len()],
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            quoted: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, byte: u8, quoted: bool) {
        self.bytes.push(byte);
        self.quoted.push(quoted);
    }

    fn extend(&mut self, bytes: &[u8], quoted: bool) {
        self.bytes.extend_from_slice(bytes);
        self.quoted.resize(self.bytes.len(), quoted);
    }

    /// Everything from `at` on counted, and the walk over: what comes next
    /// cannot be followed for sure.
    fn rest(mut self, bytes: &[u8], at: usize) -> Self {
        self.extend(bytes.get(at..).unwrap_or_default(), false);
        self
    }
}

/// What a POSIX script's counts read (see the module comment).
fn posix(bytes: &[u8]) -> Counted {
    let mut counted = Counted::with_capacity(bytes.len());
    let mut at = 0;
    let (mut double, mut comment, mut dollar) = (false, false, false);
    let mut waiting: Vec<Heredoc> = Vec::new();
    while let Some(&byte) = bytes.get(at) {
        if comment && byte != b'\n' {
            counted.push(byte, false);
            at += 1;
            continue;
        }
        comment = false;
        if double {
            match byte {
                b'\\' => {
                    counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), true);
                    at += 2;
                }
                b'"' => {
                    counted.push(byte, true);
                    double = false;
                    at += 1;
                }
                // A substitution in a string holds quotes of its own.
                b'`' => return counted.rest(bytes, at),
                b'$' if bytes.get(at + 1) == Some(&b'(') => return counted.rest(bytes, at),
                _ => {
                    counted.push(byte, true);
                    at += 1;
                }
            }
            continue;
        }
        let after_dollar = std::mem::replace(&mut dollar, false);
        match byte {
            b'\\' => {
                counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), false);
                at += 2;
            }
            b'\'' => match single_closed(bytes, at + 1, after_dollar) {
                Some(end) => {
                    counted.push(b'x', false);
                    at = end + 1;
                }
                None => return counted.rest(bytes, at),
            },
            b'"' => {
                counted.push(byte, true);
                double = true;
                at += 1;
            }
            b'#' if at == 0 || breaks_word(bytes[at - 1]) => {
                counted.push(byte, false);
                comment = true;
                at += 1;
            }
            b'<' => {
                let run = bytes[at..].iter().take_while(|byte| **byte == b'<').count();
                counted.extend(&bytes[at..at + run], false);
                at += run;
                if run == 2 {
                    let Some((heredoc, end)) = heredoc(bytes, at) else {
                        return counted.rest(bytes, at);
                    };
                    counted.extend(&bytes[at..end], false);
                    at = end;
                    waiting.push(heredoc);
                }
            }
            b'\n' => {
                counted.push(byte, false);
                at += 1;
                // The bodies of the here-documents the line started follow
                // it, in order.
                for heredoc in waiting.drain(..) {
                    let Some(end) = heredoc.body_end(bytes, at) else {
                        return counted.rest(bytes, at);
                    };
                    if !heredoc.literal(&bytes[at..end]) {
                        counted.extend(&bytes[at..end], false);
                    }
                    at = end;
                }
            }
            _ => {
                counted.push(byte, false);
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
                counted.extend(bytes.get(at..at + 2).unwrap_or(&bytes[at..]), false);
                at += 2;
            }
            b'"' => {
                let close = bytes[at + 1..]
                    .iter()
                    .position(|byte| matches!(byte, b'"' | b'\n'))
                    .map(|end| at + 1 + end)
                    .filter(|end| bytes[*end] == b'"');
                if let Some(end) = close {
                    counted.push(b'x', false);
                    at = end + 1;
                } else {
                    counted.push(byte, false);
                    at += 1;
                }
            }
            _ => {
                counted.push(byte, false);
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
            ("echo $((1<<2))\n'('", "echo $((1<<2))\n'('"),
            ("cat <<$x\n'('\n$x\n", "cat <<$x\n'('\n$x\n"),
            ("cat <<'A' <<B\na\nA\n(\nB\n'('", "cat <<'A' <<B\nx"),
            // In double quotes, a substitution ends the walk.
            ("echo \"$(echo ')')\" '('", "echo \"$(echo ')')\" '('"),
            ("echo \"`a`\" '('", "echo \"`a`\" '('"),
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
        assert!(pipes(&"a | ".repeat(401)).is_some());
        assert!(pipes(&"a | ".repeat(400)).is_none());
        assert!(pipes(&"a || ".repeat(1_000)).is_none());
    }
}
