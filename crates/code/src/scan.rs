//! What the reader reads of code before it hands it to a grammar: a scan of
//! its text, in one pass with a stack of its own (no recursion), that says
//! how deep its brackets nest and counts the marks of the shapes a grammar
//! reads two ways at a cost no count of the parse sees. It only ever refuses
//! code: code it passes is parsed and read as before.

use crate::unit::MAX_TREE_DEPTH;

/// What a scan found in code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Scanned {
    /// The most openers left unclosed at once (see [`python`] and
    /// [`javascript`]), counted up to one past [`MAX_TREE_DEPTH`].
    pub(crate) depth: usize,
    /// The marks of a costly shape: in Python the stars where Python allows
    /// none, in JavaScript an `await` read before a `/`.
    pub(crate) marks: usize,
    /// The spaces the grammar passes over that the scan only reads as such
    /// by what the grammar's own rule says (see [`odd_space`]), outside a
    /// string or a comment: past [`MAX_ODD_SPACES`] the scan is not sure
    /// enough of what it read, and the code is not read.
    pub(crate) odd: usize,
    /// Backticks outside a string or a comment, in Python: no Python 3
    /// reads one, and tree-sitter-python takes one for a string's quote.
    pub(crate) backticks: usize,
    /// The same depth and marks counted on the bytes alone, with no
    /// reading of strings, comments, escapes or regular expressions (see
    /// [`raw_depth`], [`raw_stars`] and [`raw_awaits`]): no misreading of
    /// one can hide what they count, and code past their bounds is not read
    /// whatever the scan above found.
    pub(crate) raw_depth: usize,
    pub(crate) raw_marks: usize,
}

/// How many stars after an operator (see [`raw_stars`]) Python may hold,
/// counted on its bytes alone, before it is not read. Strings and comments
/// count too (`c == '*'`, a list in a docstring): real code holds at most a
/// few dozen, and the costly shapes one for each few bytes, whose cost
/// grows with the square of the run (256 of them cost a few milliseconds).
pub(crate) const MAX_RAW_STARS: usize = 256;

/// Whether the character of `code` at byte `at` may be part of a name: an
/// ASCII letter or digit, `_`, `$` (for JavaScript), or a letter or digit
/// of Unicode, and the joiners a name may hold. Anything else is not.
fn raw_name_at(code: &str, at: usize) -> bool {
    let text = code.as_bytes();
    match text.get(at) {
        Some(&b) if b < 0x80 => b.is_ascii_alphanumeric() || b == b'_' || b == b'$',
        Some(_) => code
            .get(at..)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_alphanumeric() || matches!(c, '\u{200c}' | '\u{200d}')),
        None => false,
    }
}

/// The most brackets (`(`, `[` and `{`) left open at once on the bytes of
/// `text`, strings, comments and all, each closer closing one opener of any
/// kind, and never below none.
pub(crate) fn raw_depth(text: &[u8]) -> usize {
    let mut depth: usize = 0;
    let mut most = 0;
    for &byte in text {
        match byte {
            b'(' | b'[' | b'{' => {
                depth += 1;
                most = most.max(depth);
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    most
}

/// How many stars (`*` or `**`) of Python `code` stand after an operator, on
/// its bytes alone, counted up to one past [`MAX_RAW_STARS`]. Between the
/// operator and the star every byte that is not part of a name, an operator
/// or a bracket is passed over (spaces of any kind, line ends, a NUL, a
/// backslash, quotes), so no reading of a string, an escape or a comment can
/// hide one. An operator is `+ - * / % @ & | ^ ~ < > !`, `==`, `!=`, `<=`,
/// `>=` and `:=`, or a keyword of [`STARLESS_KEYWORDS`]; an assignment,
/// plain or augmented, may unpack, and a bracket, a comma or a colon may
/// stand before a star, and those are not counted.
pub(crate) fn raw_stars(code: &str) -> usize {
    let text = code.as_bytes();
    let mut count = 0;
    let mut at = 0;
    while at < text.len() && count <= MAX_RAW_STARS {
        if text[at] != b'*' || (at > 0 && text[at - 1] == b'*') {
            at += 1;
            continue;
        }
        // Back over what is passed over.
        let mut back = at;
        let before = loop {
            let Some(c) = code.get(..back).and_then(|head| head.chars().next_back()) else {
                break None;
            };
            let passed = c.is_whitespace()
                || matches!(c, '\0' | '\\' | '\'' | '"' | '`')
                || (!c.is_ascii() && !c.is_alphanumeric());
            if !passed {
                break Some(back - c.len_utf8());
            }
            back -= c.len_utf8();
        };
        let counted = before.is_some_and(|j| match text[j] {
            b'=' => {
                let one = j.checked_sub(1).map(|i| text[i]);
                let two = j.checked_sub(2).map(|i| text[i]);
                match one {
                    Some(b'=' | b'!' | b':') => true,
                    Some(b'<') => two != Some(b'<'),
                    Some(b'>') => two != Some(b'>'),
                    _ => false,
                }
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'@' | b'&' | b'|' | b'^' | b'~' | b'<' | b'>'
            | b'!' => true,
            byte if byte.is_ascii_alphanumeric() || byte == b'_' => {
                let mut start = j;
                while start > 0
                    && (text[start - 1].is_ascii_alphanumeric() || text[start - 1] == b'_')
                {
                    start -= 1;
                }
                let starts_word = start == 0 || !raw_name_at(code, start - 1);
                starts_word && STARLESS_KEYWORDS.contains(&&text[start..=j])
            }
            _ => false,
        });
        if counted {
            count += 1;
        }
        at += 1;
    }
    count
}

/// How many times the word `await` (not part of a longer name, wherever it
/// stands: after a `.` or `...` too) is followed in JavaScript `code`, past
/// anything that is not part of a name, by a `/`, on its bytes alone,
/// counted up to one past [`MAX_AWAITED_SLASHES`]: so no reading of a comment,
/// a string, a regular expression or a space can hide one.
pub(crate) fn raw_awaits(code: &str) -> usize {
    let text = code.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(found) = text[from..].windows(5).position(|w| w == b"await") {
        let at = from + found;
        from = at + 5;
        let before = code.get(..at).and_then(|head| head.chars().next_back());
        if before.is_some_and(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '$')
                || (!c.is_ascii() && c.is_alphanumeric())
        }) || raw_name_at(code, from)
        {
            continue;
        }
        let mut next = from;
        while next < text.len() && text[next] != b'/' && !raw_name_at(code, next) {
            next += 1;
        }
        if text.get(next) == Some(&b'/') {
            count += 1;
            if count > MAX_AWAITED_SLASHES {
                break;
            }
        }
        from = from.max(next);
    }
    count
}

/// How many spaces of [`odd_space`] code may hold outside its strings and
/// comments before it is not read. Real code holds none there (a byte-order
/// mark at the start is no such space).
pub(crate) const MAX_ODD_SPACES: usize = 4;

/// Whether `c` is a space other than an ASCII space, tab, line feed,
/// carriage return or form feed that a grammar passes over: Unicode's white
/// space (U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F,
/// U+205F, U+3000), the vertical tab, and U+200B, U+2060 and U+FEFF, which
/// both grammars' rules for what they pass over name.
pub(crate) fn odd_space(c: char) -> bool {
    !matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')
        && (c.is_whitespace() || matches!(c, '\u{200b}' | '\u{2060}' | '\u{feff}'))
}

/// The character of `code` at byte `at`, when it is not ASCII.
fn wide(code: &str, at: usize) -> Option<char> {
    code.get(at..)?.chars().next().filter(|c| !c.is_ascii())
}

/// The bytes of the space of [`odd_space`] at `at` in `code`, if one is
/// there.
fn odd_at(code: &str, at: usize) -> Option<usize> {
    if code.as_bytes().get(at) == Some(&0x0b) {
        return Some(1);
    }
    wide(code, at).filter(|&c| odd_space(c)).map(char::len_utf8)
}

/// How many stars where Python allows none (see [`python`]) code may hold
/// before it is not parsed. Valid Python holds none: of the real files
/// measured, the most one held is noted in the crate's design page. Every
/// costly shape of code tree-sitter-python reads two ways at once found
/// holds one in each few bytes.
pub(crate) const MAX_STARS_AFTER_OPERATORS: usize = 4;

/// How many times an `await` may come before a `/` in JavaScript (see
/// [`javascript`]) before the code is not read. tree-sitter-javascript
/// reads such an `await` both as a name divided and as the keyword before
/// a regular expression, and inside brackets, a template's field or a
/// ternary left open the two ways merge at each one over a stack that
/// grows with the code, in time that grows with its square and recursion
/// as deep as the stack.
/// Real code divides an awaited value as `(await x) / y`, and an `await`
/// directly before a regular expression is rare.
pub(crate) const MAX_AWAITED_SLASHES: usize = 4;

/// The keywords after which a starred expression is never Python: those
/// that take an expression as an operand or a condition (`in`, `for`,
/// `return`, `yield`, `lambda`, `import` and `except` may take one).
const STARLESS_KEYWORDS: [&[u8]; 12] = [
    b"not", b"and", b"or", b"is", b"if", b"elif", b"else", b"while", b"with", b"assert", b"del",
    b"await",
];

/// What a frame of a scan's stack is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// An opening bracket of code: `(`, `[` or `{`, and whether the `(`
    /// is the head of a JavaScript `if`, `while`, `for` or `with`.
    Bracket(u8, bool),
    /// The text of a Python string, by its quote, whether it has three,
    /// and whether it is a format string (an `f` or `t` prefix).
    Text {
        quote: u8,
        triple: bool,
        format: bool,
    },
    /// The code of a replacement field of a Python format string, or of a
    /// `${…}` of a JavaScript template.
    Field,
    /// The format specification of a Python replacement field (after its
    /// `:`), text that may hold fields of its own.
    Spec,
    /// The text of a JavaScript template.
    Template,
    /// A JSX tag, to its `>` or `/>`.
    Tag,
    /// The children of a JSX element, to its closing tag.
    Children,
}

impl Frame {
    /// Whether the frame is a level of the grammar's nesting.
    fn nests(self) -> bool {
        !matches!(self, Self::Spec | Self::Tag)
    }
}

/// A scan's stack, and the most levels it nested.
#[derive(Default)]
struct Stack {
    frames: Vec<Frame>,
    levels: usize,
    most: usize,
}

impl Stack {
    fn push(&mut self, frame: Frame) {
        self.frames.push(frame);
        if frame.nests() {
            self.levels += 1;
            self.most = self.most.max(self.levels);
        }
    }

    fn pop(&mut self) -> Option<Frame> {
        let frame = self.frames.pop()?;
        if frame.nests() {
            self.levels -= 1;
        }
        Some(frame)
    }

    fn top(&self) -> Option<Frame> {
        self.frames.last().copied()
    }

    /// Whether the scan has seen enough to refuse the code.
    fn too_deep(&self) -> bool {
        self.most > MAX_TREE_DEPTH
    }
}

/// Whether `byte` may be part of a name.
fn name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// What a scan of Python `code` finds.
///
/// Its depth counts the brackets of code left open, and each string and
/// replacement field of a format string a field holds, as Python's own
/// tokenizer reads them: a string ends at its quote (in a raw string too, a
/// backslash keeps the character after it from ending it), a format string's
/// fields are code (`{{` is text), and a comment runs to the end of its
/// line.
///
/// Its marks are the stars (`*`, not `**`) that stand directly after an
/// operator (`+ - * / % @ & | ^ ~ < > ! =`, and `**`, but not after an
/// assignment, plain or augmented, which may unpack) or after a keyword of
/// [`STARLESS_KEYWORDS`]: `+*a`, `a == *b`, `not *a`, `@*a`. A starred
/// expression stands after an opening bracket, a comma, a colon, an
/// assignment (`x = *a, b`, `x += *a,`) or `in`, `for`, `return`, `yield`,
/// `lambda`, `import` or `except`, and those are not counted, nor is a star
/// in a string or a comment (but one in a replacement field is).
pub(crate) fn python(code: &str) -> Scanned {
    let text = code.as_bytes();
    let operator = |byte: u8| b"+-*/%@&|^~<>=!".contains(&byte);
    let mut stack = Stack::default();
    let mut marks = 0;
    let mut at = 0;
    // The last byte of code that is no space, the word it ends, if any,
    // and whether the last `=` was an assignment, not `==` or `<=`.
    let mut last = b'\n';
    let mut word: &[u8] = b"";
    let mut word_end = 0;
    let mut assigned = false;
    let mut odd = 0;
    let mut backticks = 0;
    while at < text.len()
        && !stack.too_deep()
        && marks <= MAX_STARS_AFTER_OPERATORS
        && odd <= MAX_ODD_SPACES
        && backticks == 0
    {
        let byte = text[at];
        match stack.top() {
            Some(Frame::Text {
                quote,
                triple,
                format,
            }) => {
                if byte == b'\\' {
                    // A backslash keeps the character after it from ending
                    // the string, raw or not; a `{` after it still opens a
                    // field.
                    let next = text.get(at + 1).copied();
                    at += if matches!(next, Some(b'\\' | b'\'' | b'"' | b'\n' | b'\r')) {
                        2
                    } else {
                        1
                    };
                    continue;
                }
                if byte == quote && (!triple || text[at..].starts_with(&[quote; 3])) {
                    stack.pop();
                    at += if triple { 3 } else { 1 };
                    last = b'"';
                    word = b"";
                    continue;
                }
                if !triple && byte == b'\n' {
                    stack.pop();
                } else if format && byte == b'{' {
                    if text.get(at + 1) == Some(&b'{') {
                        at += 1;
                    } else {
                        stack.push(Frame::Field);
                        last = b'{';
                        word = b"";
                    }
                }
                at += 1;
                continue;
            }
            Some(Frame::Spec) => {
                match byte {
                    b'{' => {
                        stack.push(Frame::Field);
                        last = b'{';
                        word = b"";
                    }
                    b'}' => {
                        // The end of the field the specification is of.
                        stack.pop();
                        stack.pop();
                    }
                    b'\n' | b'\'' | b'"' => {
                        // The string ends in it: its field and the string
                        // end with it.
                        stack.pop();
                        stack.pop();
                        continue;
                    }
                    _ => {}
                }
                at += 1;
                continue;
            }
            _ => {}
        }
        if byte == b'#' {
            while at < text.len() && text[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if let Some(len) = odd_at(code, at) {
            // A space the grammar passes over, as it does any space; not a
            // byte-order mark that starts the code.
            if at > 0 || text[at] != 0xef {
                odd += 1;
            }
            at += len;
            continue;
        }
        if byte == b'`' {
            backticks += 1;
            at += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            // As tree-sitter-python reads a string's start: any run of the
            // letters `f`, `t`, `r`, `b` and `u`, in any case, directly
            // before its quote, and a format string if `f` or `t` is among
            // them.
            let prefixed =
                last == b'a' && word_end == at && word.iter().all(|b| b"ftrbuFTRBU".contains(b));
            let format = prefixed && word.iter().any(|b| b"ftFT".contains(b));
            let triple = text[at..].starts_with(&[byte; 3]);
            stack.push(Frame::Text {
                quote: byte,
                triple,
                format,
            });
            at += if triple { 3 } else { 1 };
            continue;
        }
        if name_byte(byte) {
            let start = at;
            while at < text.len() && name_byte(text[at]) && odd_at(code, at).is_none() {
                at += 1;
            }
            word = &text[start..at];
            word_end = at;
            last = b'a';
            continue;
        }
        match byte {
            b'*' if text.get(at + 1) == Some(&b'*') => {
                last = b'*';
                word = b"";
                at += 2;
                continue;
            }
            b'*' => {
                let after_operator = operator(last) && !(last == b'=' && assigned);
                if after_operator || STARLESS_KEYWORDS.contains(&word) {
                    marks += 1;
                }
            }
            b'(' | b'[' | b'{' => stack.push(Frame::Bracket(byte, false)),
            b')' | b']' | b'}' => match stack.top() {
                Some(Frame::Bracket(open, _)) if open == opening(byte) => {
                    stack.pop();
                }
                Some(Frame::Field) if byte == b'}' => {
                    stack.pop();
                }
                _ => {}
            },
            b':' if stack.top() == Some(Frame::Field) => stack.push(Frame::Spec),
            b'!' if stack.top() == Some(Frame::Field) && text.get(at + 1) != Some(&b'=') => {
                // A conversion (`!r`): its letter, then `:` or `}`.
                at += 2;
                continue;
            }
            _ => {}
        }
        if !byte.is_ascii_whitespace() && byte != b'\\' {
            if byte == b'=' {
                let before = at.checked_sub(1).map(|i| text[i]);
                let twice = |b: u8| at >= 2 && text[at - 2] == b;
                assigned = text.get(at + 1) != Some(&b'=')
                    && match before {
                        Some(b'=' | b'!' | b':') => false,
                        Some(b'<') => twice(b'<'),
                        Some(b'>') => twice(b'>'),
                        _ => true,
                    };
            }
            last = byte;
            word = b"";
        }
        at += 1;
    }
    Scanned {
        depth: stack.most,
        marks,
        odd,
        backticks,
        raw_depth: raw_depth(text),
        raw_marks: raw_stars(code),
    }
}

/// The opening bracket a closing one closes.
fn opening(close: u8) -> u8 {
    match close {
        b')' => b'(',
        b']' => b'[',
        _ => b'{',
    }
}

/// What may come next in JavaScript, by what came last: a value (a `/` is
/// a division), an operand (a `/` starts a regular expression), or either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Next {
    Operator,
    #[default]
    Operand,
    Either,
}

/// The keywords after which JavaScript reads an operand: a `/` after one
/// starts a regular expression.
const OPERAND_KEYWORDS: [&[u8]; 14] = [
    b"return",
    b"typeof",
    b"instanceof",
    b"in",
    b"new",
    b"delete",
    b"void",
    b"throw",
    b"case",
    b"do",
    b"else",
    b"extends",
    b"export",
    b"default",
];

/// The names that are keywords in some places and names in others: a `/`
/// after one may be either.
const EITHER_KEYWORDS: [&[u8]; 4] = [b"await", b"yield", b"of", b"let"];

/// The keywords whose `(` opens the head of a statement: a `/` after its
/// `)` starts a regular expression.
const HEAD_KEYWORDS: [&[u8]; 4] = [b"if", b"while", b"for", b"with"];

/// Whether `text` at `at` ends a line, as JavaScript ends one: `\n`, `\r`,
/// U+2028 or U+2029.
fn line_end(text: &[u8], at: usize) -> bool {
    matches!(text[at], b'\n' | b'\r')
        || text[at..].starts_with("\u{2028}".as_bytes())
        || text[at..].starts_with("\u{2029}".as_bytes())
}

/// Where the white space and comments at `at` in JavaScript `code` end, and
/// how many spaces of [`odd_space`] were among them, outside the comments.
fn blank(code: &str, at: usize) -> (usize, usize) {
    let text = code.as_bytes();
    let mut odd = 0;
    let mut end = at;
    while end < text.len() {
        if text[end..].starts_with(b"//") {
            while end < text.len() && !line_end(text, end) {
                end += 1;
            }
        } else if text[end..].starts_with(b"/*") {
            end = text[end + 2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .map_or(text.len(), |found| end + 2 + found + 2);
        } else if text[end].is_ascii_whitespace() {
            end += 1;
        } else if let Some(len) = odd_at(code, end) {
            if end > 0 || text[end] != 0xef {
                odd += 1;
            }
            end += len;
        } else {
            break;
        }
    }
    (end, odd)
}

/// What a scan of JavaScript `code` finds.
///
/// Its marks are the times an `await` stands before a `/` (see
/// [`raw_awaits`]), counted on the bytes alone.
///
/// Its depth counts the brackets of code left open, and each template and
/// `${…}` field. Strings, comments, templates' text, regular expressions
/// and the text of JSX are passed over, and each JSX element and `{…}` in
/// one counts. Where it cannot tell a regular expression from a division (a
/// `/` after a `}`, or after `await`, `yield`, `of` or `let`), or JSX from a
/// `<` (at the start of a line after a value), it only counts more: to the
/// end of the line every opener counts, no closer closes and nothing is
/// passed over; and to the end of the code if that line holds a template, a
/// block comment, a backslash or a `<`, which a line's end may not end. The
/// depth counted on the bytes alone ([`raw_depth`]) holds where this reads
/// the text otherwise than the grammar does.
pub(crate) fn javascript(code: &str) -> Scanned {
    let text = code.as_bytes();
    let marks = raw_awaits(code);
    let mut stack = Stack::default();
    let mut next = Next::Operand;
    // Whether the scan is unsure of what the text is, to the end of the
    // line or to the end of the code.
    let mut unsure = false;
    let mut unsure_to_end = false;
    // Whether the last word was a keyword whose `(` heads a statement, and
    // whether a `.` came last (a member's name is no keyword).
    let mut head = false;
    let mut member = false;
    let mut odd = 0;
    let mut at = 0;
    if text.starts_with(b"#!") {
        while at < text.len() && !line_end(text, at) {
            at += 1;
        }
    }
    while at < text.len() && !stack.too_deep() && odd <= MAX_ODD_SPACES {
        let byte = text[at];
        if unsure {
            if let Some(len) = odd_at(code, at) {
                odd += 1;
                at += len;
                continue;
            }
            if line_end(text, at) && !unsure_to_end {
                unsure = false;
                next = Next::Either;
            } else {
                match byte {
                    b'(' | b'[' | b'{' => stack.push(Frame::Bracket(byte, false)),
                    b'`' | b'\\' | b'<' => unsure_to_end = true,
                    b'/' if text.get(at + 1) == Some(&b'*') => unsure_to_end = true,
                    _ => {}
                }
            }
            at += 1;
            continue;
        }
        if stack.top() == Some(Frame::Tag) {
            let (blank_end, spaces) = blank(code, at);
            if blank_end > at {
                // A tag may hold comments: none of it ends the tag.
                odd += spaces;
                at = blank_end;
                continue;
            }
            match byte {
                b'<' => stack.push(Frame::Tag),
                b'/' if text.get(at + 1) == Some(&b'>') => {
                    stack.pop();
                    at += 1;
                    if stack.top() != Some(Frame::Children) {
                        next = Next::Operator;
                    }
                }
                b'>' => {
                    stack.pop();
                    stack.push(Frame::Children);
                }
                b'{' => {
                    stack.push(Frame::Field);
                    next = Next::Operand;
                }
                b'"' | b'\'' => {
                    at += 1;
                    while at < text.len() && text[at] != byte {
                        at += 1;
                    }
                }
                _ => {}
            }
            at += 1;
            continue;
        }
        if stack.top() == Some(Frame::Children) {
            match byte {
                b'{' => {
                    stack.push(Frame::Field);
                    next = Next::Operand;
                }
                b'<' if text.get(at + 1) == Some(&b'/') => {
                    while at < text.len() && text[at] != b'>' {
                        at += 1;
                    }
                    stack.pop();
                    if stack.top() != Some(Frame::Children) {
                        next = Next::Operator;
                    }
                }
                b'<' => stack.push(Frame::Tag),
                _ => {}
            }
            at += 1;
            continue;
        }
        if stack.top() == Some(Frame::Template) {
            match byte {
                b'\\' => at += 1,
                b'`' => {
                    stack.pop();
                    next = Next::Operator;
                }
                b'$' if text.get(at + 1) == Some(&b'{') => {
                    stack.push(Frame::Field);
                    next = Next::Operand;
                    at += 1;
                }
                _ => {}
            }
            at += 1;
            continue;
        }
        let (blank_end, spaces) = blank(code, at);
        if blank_end > at {
            odd += spaces;
            // A line's end after a value may end a statement, after which
            // a `/` starts a regular expression; or not, when the next line
            // goes on with it: either.
            if next == Next::Operator && (at..blank_end).any(|i| line_end(text, i)) {
                next = Next::Either;
            }
            at = blank_end;
            continue;
        }
        if name_byte(byte) || byte == b'$' || byte == b'#' || byte == b'\\' {
            let start = at;
            while at < text.len()
                && (name_byte(text[at]) || matches!(text[at], b'$' | b'#'))
                && odd_at(code, at).is_none()
            {
                at += 1;
            }
            if text.get(at) == Some(&b'\\') || start == at {
                // An escape in a name (`aw\u0061it`): a name, never a
                // keyword.
                at = (at + 1).min(text.len());
                next = Next::Operator;
                member = false;
                head = false;
                continue;
            }
            let word = &text[start..at];
            // `for await (…)` heads a statement too.
            head = !member && (HEAD_KEYWORDS.contains(&word) || (head && word == b"await"));
            next = if member || byte.is_ascii_digit() {
                Next::Operator
            } else if OPERAND_KEYWORDS.contains(&word) {
                Next::Operand
            } else if EITHER_KEYWORDS.contains(&word) {
                Next::Either
            } else {
                Next::Operator
            };
            member = false;
            if byte.is_ascii_digit() && matches!(text.get(at), Some(b'.')) {
                // The fraction of a number: `1.5`, `1.e3`.
                at += 1;
                while at < text.len() && (name_byte(text[at]) || text[at] == b'.') {
                    at += 1;
                }
            }
            continue;
        }
        if text[at..].starts_with(b"<!--") || text[at..].starts_with(b"-->") {
            match next {
                // Where an operand goes, an HTML-like comment, to the end
                // of the line, as tree-sitter-javascript reads one.
                Next::Operand => {
                    while at < text.len() && !line_end(text, at) {
                        at += 1;
                    }
                    continue;
                }
                // After a value, `<`, `!`, `--` or `--`, `>`.
                Next::Operator => {}
                Next::Either => {
                    unsure = true;
                    unsure_to_end = true;
                    continue;
                }
            }
        }
        let was_head = head;
        head = false;
        member = false;
        match byte {
            b'\'' | b'"' => {
                at += 1;
                while at < text.len() && !matches!(text[at], b'\n' | b'\r') && text[at] != byte {
                    if text[at] == b'\\' {
                        at += 1;
                    }
                    at += 1;
                }
                next = Next::Operator;
            }
            b'`' => {
                stack.push(Frame::Template);
                next = Next::Operand;
            }
            b'/' => match next {
                Next::Operand => {
                    at += 1;
                    let mut class = false;
                    while at < text.len() && !line_end(text, at) {
                        match text[at] {
                            b'\\' => at += 1,
                            b'[' => class = true,
                            b']' => class = false,
                            b'/' if !class => break,
                            _ => {}
                        }
                        at += 1;
                    }
                    next = Next::Operator;
                }
                Next::Operator => next = Next::Operand,
                Next::Either => {
                    unsure = true;
                    continue;
                }
            },
            b'(' => {
                stack.push(Frame::Bracket(b'(', was_head));
                next = Next::Operand;
            }
            b'[' | b'{' => {
                stack.push(Frame::Bracket(byte, false));
                next = Next::Operand;
            }
            b')' | b']' | b'}' => {
                next = match stack.top() {
                    Some(Frame::Bracket(open, heads)) if open == opening(byte) => {
                        stack.pop();
                        if heads {
                            Next::Operand
                        } else if byte == b'}' {
                            // A block, after which a `/` starts a regular
                            // expression, or an object, after which it
                            // divides.
                            Next::Either
                        } else {
                            Next::Operator
                        }
                    }
                    Some(Frame::Field) if byte == b'}' => {
                        stack.pop();
                        Next::Operator
                    }
                    _ => Next::Operator,
                };
            }
            b'?' if text.get(at + 1) == Some(&b'?') => {
                at += 1;
                next = Next::Operand;
            }
            b'?' if text.get(at + 1) == Some(&b'.')
                && !text.get(at + 2).is_some_and(u8::is_ascii_digit) =>
            {
                at += 1;
                member = true;
                next = Next::Operator;
            }
            b'?' | b':' | b',' | b';' => next = Next::Operand,
            b'.' if text[at..].starts_with(b"...") => {
                at += 2;
                next = Next::Operand;
            }
            b'.' if text.get(at + 1).is_some_and(u8::is_ascii_digit) => {
                at += 1;
                while at < text.len() && name_byte(text[at]) {
                    at += 1;
                }
                next = Next::Operator;
                continue;
            }
            b'.' => {
                member = true;
                next = Next::Operator;
            }
            b'+' | b'-' if text.get(at + 1) == Some(&byte) => {
                // `++` and `--` after a value leave a value.
                at += 1;
                if next != Next::Operator {
                    next = Next::Operand;
                }
            }
            b'<' if text.get(at + 1) == Some(&b'<') => {
                at += 1;
                next = Next::Operand;
            }
            b'<' if next != Next::Operator
                && text.get(at + 1).is_some_and(|&b| {
                    b.is_ascii_alphabetic() || b"_$>".contains(&b) || b >= 0x80
                }) =>
            {
                if next == Next::Operand {
                    // A JSX element: its tag, then its children.
                    stack.push(Frame::Tag);
                } else {
                    // JSX, or a `<` that goes on from the line before.
                    unsure = true;
                    unsure_to_end = true;
                    continue;
                }
            }
            _ => next = Next::Operand,
        }
        at += 1;
    }
    Scanned {
        depth: stack.most,
        marks,
        odd,
        backticks: 0,
        raw_depth: raw_depth(text),
        raw_marks: marks,
    }
}

#[cfg(feature = "ruby")]
mod ruby;
#[cfg(feature = "ruby")]
pub(crate) use ruby::{ruby, ruby_refusal};
#[cfg(all(feature = "ruby", feature = "testing"))]
pub(crate) use ruby::{ruby_raw, Raw};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_depth_counts_brackets_and_fields_of_code() {
        assert_eq!(python("f(a[b], {c: (d)})").depth, 3);
        assert_eq!(python("'((((' + \"[[\" # (((\n").depth, 1);
        assert_eq!(python("f'{a[(b)]}'").depth, 4);
        assert_eq!(python("f'{{((('").depth, 1);
        assert_eq!(python(r"r'\\' + '('").depth, 1);
        assert_eq!(python("x = f'{a:{b}>{c}}'").depth, 3);
        assert_eq!(python(&"(".repeat(500)).depth, MAX_TREE_DEPTH + 1);
    }

    #[test]
    fn python_strings_end_where_python_ends_them() {
        // In a raw string, a backslash keeps the quote after it.
        assert_eq!(python(r#"q = r"\"" ; h = "- *a* - *b*""#).marks, 0);
        assert_eq!(python(r"q = r'\'' + *a").marks, 1);
        assert_eq!(python("h = f\"{'{'} - *a* - *b*\"").marks, 0);
        assert_eq!(python("h = f\"{d[\"k\"]} - *a* - *b*\"").marks, 0);
        assert_eq!(python("h = f'{a + *b}'").marks, 1);
        assert_eq!(python("h = f'{a!r:*>10}'").marks, 0);
        assert_eq!(python("parts += *'ab',\nx <<= *a,\nx == *a").marks, 1);
        assert_eq!(python("x <= *a").marks, 1);
        assert_eq!(python("ifx'+*a'").marks, 0);
    }

    #[test]
    fn javascript_depth_counts_what_is_left_open() {
        assert_eq!(javascript("f(a[b], {c: (d)})").depth, 3);
        assert_eq!(javascript("'((((' + \"[[\" // (((\n/* ((( */").depth, 0);
        assert_eq!(javascript("`a${b(`${c}`)}d`").depth, 5);
        assert_eq!(javascript("x = /(((/.test(y)").depth, 1);
        assert_eq!(javascript("x = (a) / (b) / (c)").depth, 1);
        assert_eq!(javascript("if (a) /(((/.test(b)").depth, 1);
        assert_eq!(javascript("a ? b : c ? d : e ? f : g").depth, 0);
        assert_eq!(javascript("f(a ? b : c, d ? e : f)").depth, 1);
        assert_eq!(javascript("a?.b ?? c?.[d]").depth, 1);
        // Where a `/` may be either, every opener to the line's end counts.
        assert_eq!(javascript("{}\n/(((/.test(a)").depth, 4);
        assert_eq!(javascript("x = <a b={(c)}>((((<d/>{[e]}</a>; (((").depth, 3);
        assert_eq!(javascript("x = y\n<a>((((</a>; (((").depth, 7);
        assert_eq!(javascript("x = a << 4 | b <c; (((").depth, 3);
    }

    #[test]
    fn python_reads_spaces_and_prefixes_as_its_grammar_does() {
        // A space the grammar passes over is a space, and counted.
        for space in [
            "\u{200b}", "\u{2060}", "\u{feff}", "\u{a0}", "\x0b", "\u{3000}",
        ] {
            let scanned = python(&format!("x = a +{space}*b"));
            assert_eq!((scanned.marks, scanned.odd), (1, 1), "{space:?}");
        }
        assert_eq!(python("\u{feff}x = 1").odd, 0);
        assert_eq!(python("s = 'a\u{a0}b' # \u{a0}").odd, 0);
        // Any run of prefix letters makes a string, a format string with
        // `f` or `t` among them.
        assert_eq!(
            python("h = fu'{a + *b}' + ff'{a + *b}' + Rt'{a + *b}'").marks,
            3
        );
        assert_eq!(python("h = ub'{a + *b}' + bu'*a'").marks, 0);
        // A backtick outside a string.
        assert_eq!(python("x = `'''`\n+*a").backticks, 1);
        assert_eq!(python("x = '`'").backticks, 0);
    }

    #[test]
    fn javascript_reads_spaces_and_comments_as_its_grammar_does() {
        for space in [
            "\u{200b}", "\u{2060}", "\u{feff}", "\u{a0}", "\u{3000}", "\u{2028}",
        ] {
            let scanned = javascript(&format!("(await{space}/a/)"));
            assert_eq!((scanned.marks, scanned.odd), (1, 1), "{space:?}");
        }
        assert_eq!(javascript("(await\u{200c}/a/)").marks, 0);
        assert_eq!(javascript("s = 'a\u{a0}b' // \u{a0}").odd, 0);
        // HTML-like comments where an operand goes, and comments in a tag.
        assert_eq!(javascript("<!-- `\n(((").depth, 3);
        assert_eq!(javascript("x;\n--> `\n(((").depth, 3);
        assert_eq!(javascript("x-->0; (((").depth, 3);
        assert_eq!(javascript("x = <a /* > */ b/>;\n(((").depth, 3);
        assert_eq!(javascript("x = <a b=<c/> // >\n />;\n(((").depth, 3);
    }

    #[test]
    fn javascript_counts_await_before_a_slash() {
        // On the bytes alone: past anything but a name, wherever the
        // `await` stands, and a comment's or a string's too.
        assert_eq!(javascript("(await /a/)").marks, 1);
        assert_eq!(
            javascript("await /* c */ /a/; await\n/b/; x.await / 2; f(...await /a/)").marks,
            4
        );
        assert_eq!(javascript("await // c\n'await /'").marks, 2);
        assert_eq!(
            javascript("(await x) / y; awaited / 2; await\u{200c}/").marks,
            0
        );
        assert_eq!(
            javascript(&"(await /".repeat(10)).marks,
            MAX_AWAITED_SLASHES + 1
        );
    }

    #[test]
    fn raw_counts_see_through_strings_comments_and_escapes() {
        // Stars after an operator, whatever stands between them but a name.
        for (code, count) in [
            ("+*a+*a", 2),
            ("+\\\0*a", 1),
            ("x = f\"\\N{\"\"\"}\"\n+*a +*a", 2),
            ("x = f\"{a:\"}\"\"\"\n+*a", 1),
            ("f\"{lambda: +*a}\"", 1),
            ("not\u{200b}*a; c == '*'; x != *a", 3),
            (
                "print(*a); x = [*a, *b]; x += *a,; f(a, *b); a ** b; x <<= *a,",
                0,
            ),
        ] {
            assert_eq!(python(code).raw_marks, count, "{code:?}");
        }
        // Brackets, strings and comments alike, each closer closing one.
        assert_eq!(python("'(((' # [[\n)").raw_depth, 5);
        assert_eq!(javascript("f(a)[b]{c} ))) (").raw_depth, 1);
        // The scan of the text, misread by an escape, counts none of it.
        let blinded = "x = f\"\\N{\"\"\"}\"\n".to_string() + &"(".repeat(500);
        assert!(python(&blinded).depth < 4);
        assert_eq!(python(&blinded).raw_depth, 500);
    }

    #[test]
    fn python_names_end_at_an_odd_space() {
        assert_eq!(python("not\u{200b}*a").marks, 1);
    }
}
