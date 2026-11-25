//! The scan of Ruby code before its parse (see [`ruby`]), behind the
//! crate's `ruby` feature.

use super::{name_byte, opening, raw_depth, Next, Scanned};
use crate::unit::MAX_TREE_DEPTH;

/// The most Ruby literals (strings, symbols, regular expressions, command
/// strings, `%` literals) open at once, one inside a `#{…}` field of the
/// other, before the code is not read. tree-sitter-ruby's scanner keeps
/// them in a state of 1 KB, five bytes each: past some 200 of them it keeps
/// none, and reads what follows as code. Real code opens three or four.
pub(crate) const MAX_RUBY_LITERALS: usize = 64;

/// How deep a Ruby `%` literal may nest its own delimiter (`%q(((…)))`)
/// before the code is not read: tree-sitter-ruby's scanner keeps the count
/// in a byte, which comes back to nothing past 255.
pub(crate) const MAX_RUBY_NESTING: usize = 200;

/// The longest word a Ruby heredoc may end at (`<<~WORD`) before the code
/// is not read: tree-sitter-ruby's scanner keeps its length in a byte, and
/// one longer than it holds makes it fail an assertion, which aborts the
/// process. Real code ends heredocs at a word of a few letters.
pub(crate) const MAX_HEREDOC_WORD: usize = 64;

/// The most Ruby heredocs open at once (started and not ended) before the
/// code is not read: their words share the scanner's 1 KB of state with the
/// literals.
pub(crate) const MAX_HEREDOCS: usize = 8;

/// The Ruby keywords after which code reads an operand (a `/` starts a
/// regular expression, `<<WORD` a heredoc), and a line's `if`, `while`, …
/// opens a block rather than ending a statement.
const RUBY_OPERAND_KEYWORDS: [&[u8]; 24] = [
    b"alias", b"undef", b"and", b"begin", b"case", b"class", b"def", b"do", b"else", b"elsif",
    b"ensure", b"for", b"if", b"in", b"module", b"not", b"or", b"rescue", b"return", b"then",
    b"unless", b"until", b"when", b"while",
];

/// The Ruby keywords that open a block an `end` closes, wherever they stand.
const RUBY_BLOCKS: [&[u8]; 6] = [b"begin", b"case", b"class", b"def", b"module", b"do"];

/// The Ruby keywords that open a block an `end` closes at the start of an
/// expression, and end a statement after one (`x if y`); `while`, `until`
/// and `for` take a `do` of their own.
const RUBY_HEADED: [&[u8]; 5] = [b"if", b"unless", b"while", b"until", b"for"];

/// The bytes a Ruby operator method's name is made of (`def <=>`, `:[]=`).
const RUBY_OPERATOR_NAME: &[u8] = b"+-*/%<>=!~^&|[]`@";

/// What a frame of the Ruby scan's stack is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rb {
    /// An opening bracket of code.
    Bracket(u8),
    /// A block a keyword opened, to its `end`, and whether the head of a
    /// loop is still open (a `do` there is the loop's own).
    Block { head: bool },
    /// A literal: the byte that closes it, the one that opens it again
    /// inside it (a `%` literal's paired delimiter, or none), whether it
    /// reads `#{…}`, and how deep it nests its delimiter.
    Text {
        close: u8,
        open: u8,
        interp: bool,
        nest: usize,
    },
    /// The code of a `#{…}` field.
    Field,
    /// The body of a heredoc (by its place among the heredocs), and
    /// whether the scan is at the start of one of its lines.
    Heredoc(usize, bool),
}

/// A heredoc the Ruby scan met: its word, whether its end may be indented
/// (`<<-`, `<<~`) and whether it reads `#{…}`.
struct Heredoc {
    word: Vec<u8>,
    indent: bool,
    interp: bool,
}

/// The Ruby scan's state.
#[derive(Default)]
struct RubyScan {
    frames: Vec<Rb>,
    levels: usize,
    most: usize,
    literals: usize,
    /// The scanner's limits the code goes past (see [`ruby`]).
    marks: usize,
    heredocs: Vec<Heredoc>,
    /// The heredocs started on this line, whose bodies start at its end.
    pending: Vec<usize>,
    /// The heredocs whose bodies come after the one being read, in order:
    /// one body is open at a time, as the grammar reads them.
    queue: Vec<usize>,
    next: Next,
    /// Whether the last token was a name that may be a call given an
    /// argument after a space (`p /a/`, `puts <<A`).
    command: bool,
    /// Whether the scan is unsure of what the text is, to the end of the
    /// line or to the end of the code: every opener counts and no closer
    /// closes.
    unsure: bool,
    unsure_to_end: bool,
}

impl RubyScan {
    fn push(&mut self, frame: Rb) {
        if matches!(frame, Rb::Text { .. }) {
            self.literals += 1;
            if self.literals > MAX_RUBY_LITERALS {
                self.marks += 1;
            }
        }
        self.frames.push(frame);
        self.levels += 1;
        self.most = self.most.max(self.levels);
    }

    fn pop(&mut self) {
        if let Some(frame) = self.frames.pop() {
            self.levels -= 1;
            if matches!(frame, Rb::Text { .. }) {
                self.literals -= 1;
            }
        }
    }

    fn top(&self) -> Option<Rb> {
        self.frames.last().copied()
    }

    fn set_top(&mut self, frame: Rb) {
        if let Some(top) = self.frames.last_mut() {
            *top = frame;
        }
    }

    /// Be unsure from here: to the end of the code when the rest of the
    /// line may start what a line's end does not end (a literal, a heredoc,
    /// a line that goes on), or a heredoc's body is to come.
    fn doubt(&mut self, text: &[u8], at: usize) {
        self.unsure = true;
        let rest = text.get(at + 1..).unwrap_or_default();
        let rest = rest.split(|&b| b == b'\n').next().unwrap_or_default();
        if !self.pending.is_empty() || rest.iter().any(|b| b"\"'`%/\\?:".contains(b) || *b == b'<')
        {
            self.unsure_to_end = true;
        }
    }

    /// Whether the scan has seen enough to refuse the code.
    fn refused(&self) -> bool {
        self.most > MAX_TREE_DEPTH || self.marks > 0
    }
}

/// Where the name at `at` in Ruby `text` ends (letters, digits, `_` and any
/// byte past ASCII).
fn ruby_name_end(text: &[u8], at: usize) -> usize {
    let mut end = at;
    while end < text.len() && name_byte(text[end]) {
        end += 1;
    }
    end
}

/// The heredoc `<<` at `at` starts in Ruby `text`, if it is one: its word,
/// whether its end may be indented, whether it reads `#{…}`, and where the
/// start ends. `Err` for one the grammar's scanner cannot hold (a word not
/// in ASCII, too long, empty and quoted, or a quoted word a line's end
/// cuts).
fn ruby_heredoc(text: &[u8], at: usize) -> Option<Result<(Heredoc, usize), ()>> {
    let mut end = at + 2;
    let indent = matches!(text.get(end), Some(b'-' | b'~'));
    if indent {
        end += 1;
    }
    let quote = text.get(end).copied().filter(|b| b"'\"`".contains(b));
    let word = if let Some(quote) = quote {
        let start = end + 1;
        let close = text[start..]
            .iter()
            .position(|&b| b == quote || b == b'\n')
            .map(|found| start + found);
        let Some(close) = close.filter(|close| text[*close] == quote) else {
            return Some(Err(()));
        };
        end = close + 1;
        &text[start..close]
    } else {
        let start = end;
        end = ruby_name_end(text, start);
        if end == start {
            return None;
        }
        &text[start..end]
    };
    if word.is_empty() || word.len() > MAX_HEREDOC_WORD || !word.is_ascii() {
        return Some(Err(()));
    }
    let heredoc = Heredoc {
        word: word.to_vec(),
        indent,
        interp: quote != Some(b'\''),
    };
    Some(Ok((heredoc, end)))
}

/// The most `#{` Ruby code may hold, anywhere in its text: a literal opens
/// inside another only in a `#{…}` of it, so the scanner of tree-sitter-ruby
/// keeps at most one more literal than this at once, five bytes each of the
/// 1,024 its state is serialized in, however the context reads.
pub(crate) const MAX_RUBY_INTERPOLATIONS: usize = 150;

/// The most bytes the heredocs a Ruby text may start take in the scanner's
/// state, anywhere in it, each counted as the scanner writes it, four bytes
/// and its word: every `<<` and a word or a quoted word after it counts,
/// whether Ruby reads a heredoc there or not.
///
/// The scanner writes its state, when the parser asks for it, as a count of
/// literals, five bytes for each, a count of heredocs, and four bytes and the
/// word for each, into 1,024 bytes (`serialize` in `src/scanner.c`). It
/// gives up, writing nothing (the state is then lost, which is no harm but
/// a wrong reading of code with an error), when the literals alone take
/// 1,023 bytes or more (205 of them), and, before writing a heredoc, when
/// `size + 2 + word >= 1024`, though it then writes `4 + word` bytes: past
/// the buffer when `size + word` is 1,021, and the parser's
/// check of what it was given (`length <= 1024`) fails. With `L` literals
/// and heredocs of `H` bytes in all the state is `2 + 5L + H` bytes, so it
/// is written whole, and within 1,021 bytes, whatever the order, when
/// `2 + 5L + H <= 1,021` ([`MAX_RUBY_STATE`]): the first heredoc is written
/// at `size = 1 + 5L` with `size + 4 + word <= 2 + 5L + H <= 1,021`, so
/// `size + 2 + word < 1,024` always, and no byte is written past 1,021.
/// `H` is counted in the raw text, whatever its context, so it is never
/// less than the heredocs the scanner holds. `L`, the literals the scanner
/// holds, is at most the bytes that start one (`"`, `'`, a backtick, `/`
/// and `%`) in the text, [`MAX_RUBY_STATE`] being checked against that count
/// whenever the text starts a heredoc. It is that count and not the nesting
/// of `#{…}` (see [`MAX_RUBY_INTERPOLATIONS`]) that bounds the literals,
/// because where the parser has met an error it takes every token for valid,
/// and the scanner reads no literal's content but starts a literal at every
/// such byte: they are never closed. Without a heredoc `L` needs no bound,
/// for the state is then written whole (up to 204 literals) or not at all.
pub(crate) const MAX_RUBY_HEREDOC_BYTES: usize = 256;

/// The bytes of the scanner's state a text may take, as [`MAX_RUBY_HEREDOC_BYTES`]
/// has it: 1,024 less the three bytes the check and the writes of a heredoc
/// need past it.
pub(crate) const MAX_RUBY_STATE: usize = 1021;

/// Whether the byte is white space as Ruby's lexer reads it: a space, a tab,
/// a line end, a carriage return, a form feed and a vertical tab.
pub(crate) fn ruby_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Whether the escape whose letter is at `at` (the byte after a backslash)
/// is one Ruby reads with the character after it, a quote too (`\c`, `\C-`,
/// `\M-`), and that character is not a letter or a digit.
fn ruby_takes_next(text: &[u8], at: usize) -> bool {
    let after = |from: usize| text.get(from).is_some_and(u8::is_ascii_alphanumeric);
    let long = matches!(text.get(at), Some(b'C' | b'M')) && text.get(at + 1) == Some(&b'-');
    (text.get(at) == Some(&b'c') && !after(at + 1)) || (long && !after(at + 2))
}

/// Where the embedded document `=begin` starts at `at` (a line's start)
/// ends, or `None` when it ends at another place for tree-sitter-ruby than
/// for Ruby, or starts one Ruby does not. The grammar's comment is `=begin`, the rest of the line,
/// and then anything up to the first `=end` there is, wherever it stands (in
/// a line, after spaces and stars: `x=end`, `  =end`, `*=end`, `=endx`) and
/// the rest of that line. Ruby ends a document only at a line that starts
/// with `=end` and then has white space or ends, and starts one only at
/// `=begin` and white space or the end. Where the two ends differ, what is
/// between them is a string or a comment to the grammar and code to Ruby.
fn ruby_doc_end(text: &[u8], at: usize) -> Option<usize> {
    if !text.get(at + 6).is_none_or(|&b| ruby_space(b)) {
        return None;
    }
    let Some(newline) = text[at..].iter().position(|&b| b == b'\n') else {
        return Some(at + 6);
    };
    let body = at + newline + 1;
    let grammar = text[body..]
        .windows(4)
        .position(|word| word == b"=end")
        .map(|found| body + found);
    let mut ruby = None;
    let mut line = body;
    loop {
        if text[line..].starts_with(b"=end") && text.get(line + 4).is_none_or(|&b| ruby_space(b)) {
            ruby = Some(line);
            break;
        }
        match text[line..].iter().position(|&b| b == b'\n') {
            Some(found) => line += found + 1,
            None => break,
        }
    }
    // Both ends are the same, or neither is: a document to the end of the
    // code. What stands in it is read once, the next `=begin` in it is text.
    (grammar == ruby).then_some(ruby.map_or(text.len(), |end| end + 4))
}

/// What the raw text of Ruby code shows past what tree-sitter-ruby's scanner
/// holds, read with no context at all: so that no reading of where a
/// literal, a comment or a heredoc starts and ends can hide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Raw {
    /// A `<<`, `<<-` or `<<~` followed by a word the scanner cannot hold:
    /// unquoted and longer than [`MAX_HEREDOC_WORD`] or not in ASCII, or
    /// quoted and longer, not in ASCII, or across a line's end or the
    /// code's (a word longer than the scanner holds aborts the process).
    HeredocWord,
    /// More `#{` than [`MAX_RUBY_INTERPOLATIONS`].
    Interpolations,
    /// Heredocs, as many as the `<<` of the text may start, that take more
    /// than [`MAX_RUBY_HEREDOC_BYTES`] of the scanner's state, or that with
    /// the literals the text may start take more than [`MAX_RUBY_STATE`].
    Heredocs,
    /// A `\c`, `\C-` or `\M-` followed by anything but a letter or a digit:
    /// Ruby reads the character after it as part of the escape (a quote,
    /// a `#`, a backslash too), where the grammar reads the escape as two
    /// characters, so the two end a string, or start a field, elsewhere.
    Escape,
    /// An embedded document (`=begin`) the grammar ends elsewhere than Ruby
    /// (see [`ruby_doc_end`]).
    Doc,
    /// A `%` literal with a paired delimiter that may nest it past
    /// [`MAX_RUBY_NESTING`].
    Nesting,
}

/// See [`Raw`]: the first of them the raw `text` shows, if any.
pub(crate) fn ruby_raw(text: &[u8]) -> Option<Raw> {
    let word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80;
    let mut interpolations = 0;
    let mut heredoc_bytes = 0;
    // The bytes that start a literal in the scanner.
    let mut openers = 0;
    // Where the last embedded document read ends: the `=begin` in it are
    // its text.
    let mut doc_end = 0;
    // Whether the last byte may be a backslash that starts an escape, and
    // whether it may be one that does not.
    let mut escaping = false;
    let mut plain = true;
    // How many of each opener of a paired delimiter stand from each place
    // on, for a `%` literal that may run to the end of the code: counted
    // once, when one is met.
    let mut after: Vec<[usize; 4]> = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let byte = text[at];
        if byte == b'#' && text.get(at + 1) == Some(&b'{') {
            interpolations += 1;
            if interpolations > MAX_RUBY_INTERPOLATIONS {
                return Some(Raw::Interpolations);
            }
        }
        // Every `<<`, wherever it stands: in a literal, after a quote, a `#`
        // or a `.`, where Ruby starts no heredoc, the grammar may still read
        // one, as it does wherever the parser has met an error and takes any
        // token for valid (`''<<\`a` holds a heredoc's quoted word the
        // scanner cannot hold).
        if text[at..].starts_with(b"<<") {
            let mut start = at + 2;
            if matches!(text.get(start), Some(b'-' | b'~')) {
                start += 1;
            }
            match text.get(start).copied() {
                Some(quote @ (b'\'' | b'"' | b'`')) => {
                    let word = &text[start + 1..];
                    let end = word.iter().position(|&b| b == quote);
                    let held = end.is_some_and(|end| {
                        let word = &word[..end];
                        word.len() <= MAX_HEREDOC_WORD && word.is_ascii() && !word.contains(&b'\n')
                    });
                    if !held {
                        return Some(Raw::HeredocWord);
                    }
                    heredoc_bytes += 4 + end.unwrap_or_default();
                }
                Some(b) if word_byte(b) => {
                    let len = text[start..].iter().take_while(|&&b| word_byte(b)).count();
                    let word = &text[start..start + len];
                    if len > MAX_HEREDOC_WORD || !word.is_ascii() {
                        return Some(Raw::HeredocWord);
                    }
                    heredoc_bytes += 4 + len;
                }
                _ => {}
            }
        }
        if matches!(byte, b'"' | b'\'' | b'`' | b'/' | b'%') {
            openers += 1;
        }
        // The escapes Ruby reads with the character after them. `\C` and
        // `\M` with no `-` are an error in Ruby (nothing runs).
        // Which of the two readings of the backslashes so far the byte may
        // be in: after a backslash that starts an escape (`escaping`), or
        // not. A backslash after `#$` is also read as the global `$\`
        // interpolated, which ends no escape, to Ruby and to the scanner: both
        // readings are followed, so the escapes may pair up from any of the
        // backslashes of a run.
        if escaping && ruby_takes_next(text, at) {
            return Some(Raw::Escape);
        }
        let after_hash_dollar = at >= 2 && &text[at - 2..at] == b"#$";
        let (was_plain, was_escaping) = (plain, escaping);
        escaping = was_plain && byte == b'\\';
        plain = was_escaping || (was_plain && (byte != b'\\' || after_hash_dollar));
        if heredoc_bytes > MAX_RUBY_HEREDOC_BYTES
            || (heredoc_bytes > 0 && 2 + 5 * openers + heredoc_bytes > MAX_RUBY_STATE)
        {
            return Some(Raw::Heredocs);
        }
        // A `=begin` that does not start its line is a comment to the
        // grammar, though Ruby has an error there: not read.
        if byte == b'='
            && at >= doc_end
            && at > 0
            && text[at - 1] != b'\n'
            && text[at..].starts_with(b"=begin")
            && text.get(at + 6).is_none_or(|&b| ruby_space(b))
        {
            return Some(Raw::Doc);
        }
        if byte == b'=' && (at == 0 || text[at - 1] == b'\n') && text[at..].starts_with(b"=begin") {
            // A `=begin` the grammar may read past a space is refused
            // wherever it stands, in a document too; the end of a document
            // is looked for once.
            if !text.get(at + 6).is_none_or(|&b| ruby_space(b)) {
                return Some(Raw::Doc);
            }
            if at >= doc_end {
                match ruby_doc_end(text, at) {
                    Some(end) => doc_end = end,
                    None => return Some(Raw::Doc),
                }
            }
        }
        if byte == b'%' && ruby_raw_nesting(text, at, &mut after) {
            return Some(Raw::Nesting);
        }
        at += 1;
    }
    None
}

/// Whether the `%` at `at` may start a literal that nests its paired
/// delimiter past [`MAX_RUBY_NESTING`]: the openers counted from it to where
/// the delimiters close it, a backslash and the byte after it passed over
/// (the scanner reads no delimiter in an escape, and one the grammar reads
/// longer, `\u{…}`, holds an opener for each closer); and for one that
/// reads `#{…}`, whose code may hold a closer the scanner does not count,
/// every opener to the end of the code.
fn ruby_raw_nesting(text: &[u8], at: usize, after: &mut Vec<[usize; 4]>) -> bool {
    let mut start = at + 1;
    let kind = text.get(start).copied();
    if kind.is_some_and(|b| b"qQwWiIsrx".contains(&b)) {
        start += 1;
    }
    let Some(open) = text.get(start).copied() else {
        return false;
    };
    let (index, close) = match open {
        b'(' => (0, b')'),
        b'[' => (1, b']'),
        b'{' => (2, b'}'),
        b'<' => (3, b'>'),
        _ => return false,
    };
    let interp = !kind.is_some_and(|b| b"qwis".contains(&b));
    // The openers inside it, as the scanner counts its nesting.
    let (mut depth, mut opens) = (1_usize, 0_usize);
    let mut at = start + 1;
    while at < text.len() {
        let byte = text[at];
        // A `#{…}` field is code, whose closers the scanner does not count,
        // where this count, which does not read the field, may.
        if interp && byte == b'#' && text.get(at + 1) == Some(&b'{') {
            if after.is_empty() {
                *after = vec![[0; 4]; text.len() + 1];
                for from in (0..text.len()).rev() {
                    after[from] = after[from + 1];
                    if let Some(kind) = b"([{<".iter().position(|&o| o == text[from]) {
                        after[from][kind] += 1;
                    }
                }
            }
            return opens + after[at][index] > MAX_RUBY_NESTING;
        }
        if byte == b'\\' {
            at += 2;
            continue;
        }
        if byte == open {
            depth += 1;
            opens += 1;
            if opens > MAX_RUBY_NESTING {
                return true;
            }
        } else if byte == close {
            depth -= 1;
            if depth == 0 {
                return false;
            }
        }
        at += 1;
    }
    false
}

/// Why the scan refuses Ruby `code`, in words, when it does for what the
/// grammar's scanner or the grammar read otherwise than Ruby (not for the
/// depth of its openers, which the budget tells).
pub(crate) fn ruby_refusal(code: &str) -> Option<&'static str> {
    // Code the reader does not read for its length is not scanned.
    if code.len() > crate::unit::longest() {
        return Some("is longer than the reader reads");
    }
    if let Some(raw) = ruby_raw(code.as_bytes()) {
        return Some(match raw {
            Raw::HeredocWord => "has a heredoc word the grammar cannot hold",
            Raw::Interpolations | Raw::Heredocs | Raw::Nesting => {
                "has more than the grammar's scanner holds"
            }
            Raw::Doc => "has an embedded document the grammar ends before Ruby does",
            Raw::Escape => "has an escape Ruby reads longer than the grammar",
        });
    }
    (ruby(code).marks > 0).then_some("has more than the grammar's scanner holds")
}

/// What a scan of Ruby `code` finds.
///
/// Its depth counts the brackets of code left open, the blocks a keyword
/// opens to its `end` (`begin`, `do`, `def`, `class`, `module`, `case`, and
/// `if`, `unless`, `while`, `until` and `for` where they start an
/// expression, not where they end a statement), each literal, `#{…}` field
/// and heredoc body. Strings, symbols, regular expressions, command strings,
/// `%` literals, heredocs, character literals (`?(`) and comments are read
/// as tree-sitter-ruby reads them, its heredoc's end too.
///
/// Its marks are the limits of the grammar's scanner the code goes past,
/// past which the grammar reads other code than Ruby does or aborts: more
/// than [`MAX_RUBY_LITERALS`] literals open at once, a `%` literal that
/// nests its delimiter past [`MAX_RUBY_NESTING`], a heredoc word past
/// [`MAX_HEREDOC_WORD`] or not in ASCII (which the scanner cuts to bytes
/// and never finds again), and more than [`MAX_HEREDOCS`] heredocs open at
/// once.
///
/// Where the scan cannot tell what the text is (a `/`, `%`, `?`, `:` or
/// `<<` after a name and a space with no space after it, which may divide
/// or start a literal; a heredoc started in another's body; a line that
/// starts with a heredoc's word and goes on), it only counts more: to the
/// end of the line every opener counts and no closer closes, and to the end
/// of the code if the rest of that line may start a literal or a heredoc's
/// body is to come. There, each `#{` counts as a literal and each bracket
/// and `<` as a nesting of a `%` literal's delimiter.
pub(crate) fn ruby(code: &str) -> Scanned {
    let text = code.as_bytes();
    // What the raw text alone shows past the grammar's scanner, whatever the
    // context, refuses the code before the scan reads any context.
    if ruby_raw(text).is_some() {
        return Scanned {
            marks: 1,
            ..Scanned::default()
        };
    }
    let mut scan = RubyScan::default();
    let mut at = 0;
    let mut line_start = true;
    // Whether the last word was `def` (a method's name follows, which may
    // be an operator) or `class` (`class << self`), and whether a `.`, `&.`
    // or `::` came last (a member's name is no keyword).
    let mut after_def = false;
    let mut after_class = false;
    let mut member = false;
    // Whether the last word was `return`, after which `if` ends the
    // statement (`return if x`).
    let mut returned = false;
    // Whether the last token was a symbol: an operator's symbol after it is
    // one too (`alias :a :<<`).
    let mut symbol_last = false;
    // In doubt, the openers a `%` literal's delimiter may be, and the
    // heredocs this line may start.
    let mut doubtful_openers = 0;
    let mut doubtful_heredocs = 0;
    while at < text.len() && !scan.refused() {
        let byte = text[at];
        if scan.unsure {
            if byte == b'\n' {
                doubtful_heredocs = 0;
            }
            if byte == b'\n' && !scan.unsure_to_end {
                scan.unsure = false;
                scan.next = Next::Operand;
                scan.command = false;
                line_start = true;
                at += 1;
                continue;
            }
            match byte {
                b'(' | b'[' | b'{' | b'<' => {
                    if byte != b'<' {
                        scan.push(Rb::Bracket(byte));
                    } else if text.get(at + 1) == Some(&b'<') {
                        // A heredoc's word the scanner cannot hold is
                        // refused here too.
                        match ruby_heredoc(text, at) {
                            Some(Err(())) => scan.marks += 1,
                            Some(Ok(_)) => {
                                // The heredocs a line starts are open at once.
                                doubtful_heredocs += 1;
                                if doubtful_heredocs > MAX_HEREDOCS {
                                    scan.marks += 1;
                                }
                            }
                            None => {}
                        }
                    }
                    doubtful_openers += 1;
                    if doubtful_openers > MAX_RUBY_NESTING {
                        scan.marks += 1;
                    }
                }
                b'#' if text.get(at + 1) == Some(&b'{') => {
                    scan.push(Rb::Field);
                    scan.literals += 1;
                    if scan.literals > MAX_RUBY_LITERALS {
                        scan.marks += 1;
                    }
                    at += 1;
                }
                byte if name_byte(byte) => {
                    let end = ruby_name_end(text, at);
                    let word = &text[at..end];
                    if RUBY_BLOCKS.contains(&word) || RUBY_HEADED.contains(&word) {
                        scan.push(Rb::Block { head: false });
                    }
                    at = end;
                    continue;
                }
                _ => {}
            }
            at += 1;
            continue;
        }
        match scan.top() {
            Some(Rb::Text {
                close,
                open,
                interp,
                nest,
            }) => {
                if byte == b'\\' {
                    at += 1 + text.get(at + 1).map_or(0, |&b| utf8_len(b));
                    continue;
                }
                if interp && byte == b'#' && text.get(at + 1) == Some(&b'{') {
                    scan.push(Rb::Field);
                    scan.next = Next::Operand;
                    scan.command = false;
                    at += 2;
                    continue;
                }
                if open != 0 && byte == open {
                    if nest + 1 > MAX_RUBY_NESTING {
                        scan.marks += 1;
                    }
                    scan.set_top(Rb::Text {
                        close,
                        open,
                        interp,
                        nest: nest + 1,
                    });
                } else if byte == close {
                    if nest > 0 {
                        scan.set_top(Rb::Text {
                            close,
                            open,
                            interp,
                            nest: nest - 1,
                        });
                    } else {
                        scan.pop();
                        at += 1;
                        if close == b'/' {
                            // A regular expression's flags.
                            while at < text.len() && text[at].is_ascii_lowercase() {
                                at += 1;
                            }
                        }
                        scan.next = Next::Operator;
                        scan.command = false;
                        continue;
                    }
                } else if byte == b'\n' && !scan.pending.is_empty() {
                    // A heredoc's body starts at the end of a line that
                    // holds it inside a literal.
                    scan.doubt(text, at);
                    scan.unsure_to_end = true;
                    continue;
                }
                at += 1;
                continue;
            }
            Some(Rb::Heredoc(index, start)) => {
                let Some(heredoc) = scan.heredocs.get(index) else {
                    break;
                };
                let interp = heredoc.interp;
                if start {
                    // A line of the body: its end is read where the line
                    // starts, past spaces and tabs for `<<-` and `<<~`.
                    let mut from = at;
                    while from < text.len() && matches!(text[from], b' ' | b'\t') {
                        from += 1;
                    }
                    let ends = if from > at && !heredoc.indent {
                        End::Not
                    } else {
                        heredoc_end(text, from, &heredoc.word)
                    };
                    match ends {
                        End::Ends(end) => {
                            scan.pop();
                            at = end;
                            heredoc_ended(&mut scan);
                        }
                        End::Unsure => {
                            scan.doubt(text, at);
                            scan.unsure_to_end = true;
                        }
                        End::Not => scan.set_top(Rb::Heredoc(index, false)),
                    }
                    continue;
                }
                match byte {
                    b'\n' => {
                        scan.set_top(Rb::Heredoc(index, true));
                        at += 1;
                    }
                    b'\\' if interp => {
                        // An escape, as the grammar reads it; it reads the
                        // heredoc's end again after it.
                        if let Some(len) = ruby_escape(text, at) {
                            at += len;
                            restart_heredoc(&mut scan, text, &mut at);
                        } else {
                            scan.doubt(text, at);
                            scan.unsure_to_end = true;
                        }
                    }
                    b'#' if interp && text.get(at + 1) == Some(&b'{') => {
                        scan.push(Rb::Field);
                        scan.next = Next::Operand;
                        scan.command = false;
                        at += 2;
                    }
                    b'#' if interp && matches!(text.get(at + 1), Some(b'@' | b'$')) => {
                        scan.doubt(text, at);
                        scan.unsure_to_end = true;
                    }
                    _ => at += 1,
                }
                continue;
            }
            _ => {}
        }
        // Code.
        if line_start {
            line_start = false;
            if text[at..].starts_with(b"=begin") && text.get(at + 6).is_none_or(|&b| ruby_space(b))
            {
                // A comment to a line that starts with `=end`.
                let mut from = at;
                loop {
                    let Some(found) = text[from..].iter().position(|&b| b == b'\n') else {
                        at = text.len();
                        break;
                    };
                    from += found + 1;
                    if text[from..].starts_with(b"=end")
                        && text.get(from + 4).is_none_or(|&b| ruby_space(b))
                    {
                        at = text[from..]
                            .iter()
                            .position(|&b| b == b'\n')
                            .map_or(text.len(), |end| from + end);
                        break;
                    }
                }
                continue;
            }
            // `__END__` alone on its line, as Ruby ends the code there.
            let rest = text.get(at + 7..).unwrap_or_default();
            if text[at..].starts_with(b"__END__")
                && (rest.is_empty() || rest.starts_with(b"\n") || rest.starts_with(b"\r\n"))
            {
                break;
            }
        }
        match byte {
            b'\n' => {
                if let Some(Rb::Block { head: true }) = scan.top() {
                    scan.set_top(Rb::Block { head: false });
                }
                at += 1;
                line_start = true;
                returned = false;
                scan.next = Next::Operand;
                scan.command = false;
                if !scan.pending.is_empty() {
                    // The bodies of the heredocs the line started, one
                    // after the other, the first on top.
                    if scan
                        .frames
                        .iter()
                        .any(|frame| matches!(frame, Rb::Heredoc(..)))
                    {
                        scan.doubt(text, at);
                        scan.unsure_to_end = true;
                        continue;
                    }
                    let mut pending = std::mem::take(&mut scan.pending);
                    let first = pending.remove(0);
                    scan.queue = pending;
                    scan.push(Rb::Heredoc(first, true));
                }
                continue;
            }
            b' ' | b'\t' | b'\r' | 0x0b | 0x0c => {
                if scan.command {
                    scan.next = Next::Either;
                }
                at += 1;
                continue;
            }
            b'\\' if matches!(text.get(at + 1), Some(b'\n')) => {
                at += 2;
                continue;
            }
            b'#' => {
                while at < text.len() && text[at] != b'\n' {
                    at += 1;
                }
                continue;
            }
            _ => {}
        }
        let was_command = scan.command;
        scan.command = false;
        let was_return = std::mem::take(&mut returned);
        let was_symbol = std::mem::take(&mut symbol_last);
        // A method's name, which may be an operator (`def <=>`, `` def `
        // ``).
        if after_def && !name_byte(byte) && RUBY_OPERATOR_NAME.contains(&byte) {
            after_def = false;
            while at < text.len() && RUBY_OPERATOR_NAME.contains(&text[at]) {
                at += 1;
            }
            scan.next = Next::Operand;
            continue;
        }
        if name_byte(byte) || byte == b'@' || (byte == b'$' && text.get(at + 1).is_some()) {
            let start = at;
            if byte == b'$' {
                // A global, `$"` and `$'` among them.
                at += 1;
                if text.get(at) == Some(&b'-') {
                    at += 1;
                }
                if text.get(at).is_some_and(|&b| name_byte(b)) {
                    at = ruby_name_end(text, at);
                } else {
                    at += text.get(at).map_or(0, |&b| utf8_len(b));
                }
                scan.next = Next::Operator;
                scan.command = true;
                member = false;
                after_def = false;
                continue;
            }
            while at < text.len() && text[at] == b'@' {
                at += 1;
            }
            at = ruby_name_end(text, at);
            let word = &text[start..at];
            let digit = byte.is_ascii_digit();
            if digit {
                // A number, its fraction and exponent with it.
                while at + 1 < text.len() && text[at] == b'.' && text[at + 1].is_ascii_digit() {
                    at = ruby_name_end(text, at + 1);
                }
                scan.next = Next::Operator;
                member = false;
                after_def = false;
                continue;
            }
            // `empty?`, `save!`: a method's name, but `x != y`; a `?` before
            // what may start a literal is a name's or a conditional's.
            match text.get(at) {
                Some(b'!') if !matches!(text.get(at + 1), Some(b'=' | b'~')) => at += 1,
                Some(b'?') => match text.get(at + 1) {
                    None => at += 1,
                    Some(&b)
                        if b.is_ascii_whitespace() || name_byte(b) || b")]},;.(:{".contains(&b) =>
                    {
                        at += 1;
                    }
                    Some(_) => {
                        scan.doubt(text, at);
                        continue;
                    }
                },
                _ => {}
            }
            // A label (`key: value`) is no keyword.
            let label = text.get(at) == Some(&b':') && text.get(at + 1) != Some(&b':');
            let keyword = !member && !after_def && !label && byte != b'@';
            let was_def = after_def;
            member = false;
            after_def = false;
            after_class = false;
            if label {
                at += 1;
                scan.next = Next::Operand;
                continue;
            }
            if !keyword {
                // A method's name after `def` may be `self.name`.
                if was_def && text.get(at) == Some(&b'.') {
                    at += 1;
                    after_def = true;
                    continue;
                }
                scan.next = Next::Operator;
                scan.command = true;
                continue;
            }
            if word == b"end" {
                if let Some(Rb::Block { .. }) = scan.top() {
                    scan.pop();
                }
                scan.next = Next::Operator;
                continue;
            }
            if word == b"do" {
                match scan.top() {
                    Some(Rb::Block { head: true }) => scan.set_top(Rb::Block { head: false }),
                    _ => scan.push(Rb::Block { head: false }),
                }
            } else if RUBY_BLOCKS.contains(&word) {
                scan.push(Rb::Block { head: false });
            } else if RUBY_HEADED.contains(&word) && scan.next == Next::Operand && !was_return {
                let head = matches!(word, b"while" | b"until" | b"for");
                scan.push(Rb::Block { head });
            }
            after_def = word == b"def";
            after_class = word == b"class";
            returned = word == b"return";
            if RUBY_OPERAND_KEYWORDS.contains(&word) {
                scan.next = Next::Operand;
            } else if matches!(
                word,
                b"self" | b"nil" | b"true" | b"false" | b"__FILE__" | b"__LINE__" | b"__dir__"
            ) {
                scan.next = Next::Operator;
            } else {
                scan.next = Next::Operator;
                scan.command = true;
            }
            continue;
        }
        let after = text.get(at + 1).copied();
        // What may start a literal after a name and a space, with no space
        // after it, may be its argument or an operator.
        let either = scan.next == Next::Either && was_command;
        let spaced_after = after.is_none_or(|b| b.is_ascii_whitespace() || b == b'=');
        member = false;
        let class = std::mem::take(&mut after_class);
        after_def = false;
        match byte {
            b'"' | b'`' => {
                scan.push(Rb::Text {
                    close: byte,
                    open: 0,
                    interp: true,
                    nest: 0,
                });
            }
            b'\'' => scan.push(Rb::Text {
                close: byte,
                open: 0,
                interp: false,
                nest: 0,
            }),
            // After a name and a space, the grammar reads a `/` or a `%` with no
            // space after it as a literal's start, as Ruby reads a call's
            // argument (`p /a/`): where Ruby reads a division of a local
            // (`x = 1; x /2`) the grammar reads more as literal than Ruby does,
            // and this scan reads it as the grammar does.
            b'/' if scan.next == Next::Operand || (either && !spaced_after) => {
                scan.push(Rb::Text {
                    close: b'/',
                    open: 0,
                    interp: true,
                    nest: 0,
                });
            }
            b'%' if scan.next == Next::Operand || (either && !spaced_after) => {
                let mut kind = after;
                let mut delimiter_at = at + 1;
                if kind.is_some_and(|b| b"qQwWiIsrx".contains(&b)) {
                    delimiter_at += 1;
                } else {
                    kind = None;
                }
                let Some(delimiter) = text.get(delimiter_at).copied() else {
                    at += 1;
                    continue;
                };
                if delimiter.is_ascii_whitespace() || delimiter == b'=' {
                    scan.doubt(text, at);
                    scan.unsure_to_end = true;
                    continue;
                }
                if delimiter.is_ascii_alphanumeric() || delimiter >= 0x80 {
                    // No literal: an operator (or an error).
                    scan.next = Next::Operand;
                    at += 1;
                    continue;
                }
                let (open, close) = match delimiter {
                    b'(' => (b'(', b')'),
                    b'[' => (b'[', b']'),
                    b'{' => (b'{', b'}'),
                    b'<' => (b'<', b'>'),
                    other => (0, other),
                };
                let interp = !kind.is_some_and(|b| b"qwis".contains(&b));
                scan.push(Rb::Text {
                    close,
                    open,
                    interp,
                    nest: 0,
                });
                at = delimiter_at + 1;
                continue;
            }
            b'?' if scan.next == Next::Operand || (either && !spaced_after) => {
                if either || after.is_none_or(|b| b.is_ascii_whitespace()) {
                    if either {
                        scan.doubt(text, at);
                        continue;
                    }
                    scan.next = Next::Operand;
                    at += 1;
                    continue;
                }
                // A character literal: `?a`, `?(`, `?\n`.
                let mut end = at + 1;
                if after == Some(b'\\') {
                    let escaped = text.get(end + 1).copied();
                    if escaped.is_none_or(|b| b"uxCMc".contains(&b) || b.is_ascii_digit()) {
                        scan.doubt(text, at);
                        continue;
                    }
                    end += 1;
                }
                end += text.get(end).map_or(0, |&b| utf8_len(b));
                if text.get(end).is_some_and(|&b| name_byte(b)) {
                    scan.doubt(text, at);
                    continue;
                }
                at = end;
                scan.next = Next::Operator;
                continue;
            }
            b':' if after == Some(b':') => {
                at += 2;
                member = true;
                scan.next = Next::Operator;
                continue;
            }
            b':' if matches!(after, Some(b'"' | b'\'')) => {
                scan.push(Rb::Text {
                    close: after.unwrap_or(b'"'),
                    open: 0,
                    interp: after == Some(b'"'),
                    nest: 0,
                });
                at += 2;
                continue;
            }
            b':' if after.is_some_and(name_byte) => {
                // A symbol.
                at = ruby_name_end(text, at + 1);
                if matches!(text.get(at), Some(b'?' | b'!' | b'=')) {
                    at += 1;
                }
                scan.next = Next::Operator;
                symbol_last = true;
                continue;
            }
            b':' if after.is_some_and(|b| RUBY_OPERATOR_NAME.contains(&b)) => {
                // After a symbol (`alias :a :<<`) it is another, and after a name
                // and a space (`wont_be :<, 1`) the grammar reads it as a
                // call's argument.
                if scan.next != Next::Operand
                    && !was_symbol
                    && !either
                    && after.is_some_and(|b| b"/%?<`".contains(&b))
                {
                    scan.doubt(text, at);
                    continue;
                }
                // The symbol of an operator: `:/`, `:<=>`, `:[]=`.
                at += 1;
                while at < text.len() && RUBY_OPERATOR_NAME.contains(&text[at]) {
                    at += 1;
                }
                scan.next = Next::Operator;
                symbol_last = true;
                continue;
            }
            // After a name, spaced or not, the grammar reads `<<WORD` as a
            // heredoc (`x<<A`), after a value as a shift (`1<<A`).
            b'<' if after == Some(b'<')
                && !class
                && (scan.next == Next::Operand || was_command) =>
            {
                match ruby_heredoc(text, at) {
                    Some(Err(())) => {
                        scan.marks += 1;
                        continue;
                    }
                    Some(Ok((heredoc, end))) => {
                        let open = scan
                            .frames
                            .iter()
                            .filter(|frame| matches!(frame, Rb::Heredoc(..)))
                            .count();
                        if open > 0 {
                            // A heredoc started in another's body.
                            scan.doubt(text, at);
                            scan.unsure_to_end = true;
                            continue;
                        }
                        scan.heredocs.push(heredoc);
                        scan.pending.push(scan.heredocs.len() - 1);
                        if scan.pending.len() > MAX_HEREDOCS {
                            scan.marks += 1;
                        }
                        at = end;
                        scan.next = Next::Operator;
                        continue;
                    }
                    None => {
                        at += 2;
                        scan.next = Next::Operand;
                        continue;
                    }
                }
            }
            b'(' | b'[' | b'{' => {
                scan.push(Rb::Bracket(byte));
                scan.next = Next::Operand;
            }
            b')' | b']' => {
                if scan.top() == Some(Rb::Bracket(opening(byte))) {
                    scan.pop();
                }
                scan.next = Next::Operator;
            }
            b'}' => {
                match scan.top() {
                    Some(Rb::Field) => {
                        scan.pop();
                        at += 1;
                        if let Some(Rb::Heredoc(..)) = scan.top() {
                            // The grammar reads the heredoc's end again
                            // where the field ends.
                            restart_heredoc(&mut scan, text, &mut at);
                        }
                        continue;
                    }
                    Some(Rb::Bracket(b'{')) => scan.pop(),
                    _ => {}
                }
                scan.next = Next::Operator;
                scan.command = true;
            }
            b';' => {
                if let Some(Rb::Block { head: true }) = scan.top() {
                    scan.set_top(Rb::Block { head: false });
                }
                scan.next = Next::Operand;
            }
            b'.' if after == Some(b'.') => {
                at += 2;
                if text.get(at) == Some(&b'.') {
                    at += 1;
                }
                scan.next = Next::Operand;
                continue;
            }
            b'.' => {
                member = true;
                scan.next = Next::Operator;
            }
            b'&' if after == Some(b'.') => {
                member = true;
                at += 2;
                scan.next = Next::Operator;
                continue;
            }
            _ => scan.next = Next::Operand,
        }
        at += 1;
    }
    Scanned {
        depth: scan.most,
        marks: scan.marks,
        raw_depth: raw_depth(text),
        ..Scanned::default()
    }
}

/// How long the escape at `at` (its `\`) is, as tree-sitter-ruby's
/// `escape_sequence` reads it: `\` and one character but `u`, `x` and an
/// octal digit; `\x` and one or two hex digits; one to three octal digits;
/// `\u` and four hex digits, or hex digits and spaces in braces. `None` for
/// one it does not read.
fn ruby_escape(text: &[u8], at: usize) -> Option<usize> {
    let rest = text.get(at + 1..)?;
    let first = *rest.first()?;
    let run = |from: usize, most: usize, ok: fn(&u8) -> bool| {
        rest.iter()
            .skip(from)
            .take(most)
            .take_while(|b| ok(b))
            .count()
    };
    match first {
        b'x' => match run(1, 2, u8::is_ascii_hexdigit) {
            0 => None,
            n => Some(2 + n),
        },
        b'0'..=b'7' => Some(1 + run(0, 3, |b| (b'0'..=b'7').contains(b))),
        b'u' if run(1, 4, u8::is_ascii_hexdigit) == 4 => Some(6),
        b'u' if rest.get(1) == Some(&b'{') => {
            let inner = run(2, usize::MAX, |b| b.is_ascii_hexdigit() || *b == b' ');
            (inner > 0 && rest.get(2 + inner) == Some(&b'}')).then_some(3 + inner + 1)
        }
        b'u' => None,
        other => Some(1 + utf8_len(other)),
    }
}

/// How many bytes the UTF-8 character that starts with `byte` takes.
fn utf8_len(byte: u8) -> usize {
    match byte {
        0xf0.. => 4,
        0xe0.. => 3,
        0xc0.. => 2,
        _ => 1,
    }
}

/// Whether a heredoc ends at `at`, as tree-sitter-ruby's scanner ends one.
enum End {
    /// Its word, then spaces or tabs, then a line's end or the code's: the
    /// body ends where the word does.
    Ends(usize),
    /// Its word and then something else, which the grammar's scanner may
    /// read as its end too (its word again, a carriage return).
    Unsure,
    /// Not its word.
    Not,
}

/// Whether the heredoc whose word is `word` ends at `at` in `text`.
fn heredoc_end(text: &[u8], at: usize, word: &[u8]) -> End {
    if !text[at..].starts_with(word) {
        return End::Not;
    }
    let end = at + word.len();
    let mut after = end;
    while after < text.len() && matches!(text[after], b' ' | b'\t') {
        after += 1;
    }
    match text.get(after) {
        None | Some(b'\n') => End::Ends(end),
        Some(_) => End::Unsure,
    }
}

/// The heredoc on top of `scan` has ended: the next one's body starts on
/// the next line.
fn heredoc_ended(scan: &mut RubyScan) {
    if scan.queue.is_empty() {
        scan.next = Next::Operator;
    } else {
        let next = scan.queue.remove(0);
        scan.push(Rb::Heredoc(next, false));
    }
}

/// tree-sitter-ruby's scanner reads a heredoc's end again where it reads
/// its text again: after a `#{…}` field and after an escape. Where its word
/// stands there, the heredoc ends as the grammar ends it, or the scan is
/// unsure.
fn restart_heredoc(scan: &mut RubyScan, text: &[u8], at: &mut usize) {
    let Some(Rb::Heredoc(index, _)) = scan.top() else {
        return;
    };
    let Some(heredoc) = scan.heredocs.get(index) else {
        return;
    };
    let ends = heredoc_end(text, *at, &heredoc.word);
    match ends {
        End::Ends(end) => {
            scan.pop();
            *at = end;
            heredoc_ended(scan);
        }
        End::Unsure => {
            scan.doubt(text, *at);
            scan.unsure_to_end = true;
        }
        End::Not => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(code: &str) -> usize {
        ruby(code).depth
    }

    #[test]
    fn ruby_depth_counts_brackets_blocks_and_literals() {
        assert_eq!(depth("f(a[b], {c: (d)})"), 3);
        assert_eq!(depth("'((((' + \"[[\" # (((\n"), 1);
        assert_eq!(depth("x = \"a#{b(\"#{c}\")}d\""), 5);
        assert_eq!(depth("begin\n  a do\n    b\n  end\nend"), 2);
        assert_eq!(depth("if a\n  b\nend\nx if y\nreturn if z"), 1);
        assert_eq!(depth("while a do\n  b\nend"), 1);
        assert_eq!(depth("x = y.end + z.begin"), 0);
        assert_eq!(depth("def end; end"), 1);
        assert_eq!(depth("{ end: 1, if: 2 }"), 1);
        assert_eq!(depth("x = %q(((a)))"), 1);
        assert_eq!(depth("x = %w[a b] + %i<c>"), 1);
        assert_eq!(depth("x = ?( + ?)"), 0);
        assert_eq!(depth("x = $\" + $'"), 0);
        assert_eq!(depth("x = :\"((\" + :/"), 1);
        assert_eq!(depth("x = /((/ + 1 / (2)"), 1);
        assert_eq!(depth("=begin\n((((\n=end\nx"), 0);
        assert_eq!(depth("x\n__END__\n(((("), 0);
        assert_eq!(depth("def `(c); end"), 2);
        assert_eq!(depth("class << self\nend"), 1);
    }

    #[test]
    fn ruby_heredocs_are_read_as_the_grammar_reads_them() {
        // The body is text, to a line of its word, past spaces for `<<~`.
        assert_eq!(depth("x = <<A\n((((\nA\n"), 1);
        assert_eq!(depth("x = <<~A\n  ((((\n  A\n(("), 2);
        // A field in the body is code, and the word may end the body
        // right after it, as the grammar's scanner reads it.
        assert_eq!(depth("x = <<A\n#{(a)}\nA\n"), 3);
        assert_eq!(depth("x = <<A\n#{a}A\n(("), 2);
        // The bodies of a line's heredocs, one after the other.
        assert_eq!(depth("x = [<<A, <<B]\na\nA\n(b\nB\n((("), 3);
        // After a name the grammar reads `<<WORD` as a heredoc, after a
        // value as a shift.
        assert_eq!(depth("x<<A\n((((\nA\n"), 1);
        assert_eq!(depth("1<<A\n(("), 2);
    }

    #[test]
    fn ruby_marks_what_the_grammar_s_scanner_cannot_hold() {
        let marks = |code: &str| ruby(code).marks;
        assert_eq!(
            marks(&format!("x = <<{}\n", "A".repeat(MAX_HEREDOC_WORD))),
            0
        );
        assert_eq!(
            marks(&format!("x = <<{}\n", "A".repeat(MAX_HEREDOC_WORD + 1))),
            1
        );
        assert_eq!(marks("x = <<\"É\"\n"), 1);
        assert_eq!(marks("x = <<É\n"), 1);
        assert_eq!(marks("x = <<\"A\nA\"\n"), 1);
        let literals = |n: usize| format!("x = {}{}", "\"#{".repeat(n), "}\"".repeat(n));
        assert_eq!(marks(&literals(MAX_RUBY_LITERALS)), 0);
        assert_eq!(marks(&literals(MAX_RUBY_LITERALS + 1)), 1);
        let nesting = |n: usize| format!("x = %q({}{})", "(".repeat(n), ")".repeat(n));
        assert_eq!(marks(&nesting(MAX_RUBY_NESTING)), 0);
        assert_eq!(marks(&nesting(MAX_RUBY_NESTING + 1)), 1);
        let heredocs = |n: usize| format!("x = [{}]\n", vec!["<<A"; n].join(", "));
        assert_eq!(marks(&heredocs(MAX_HEREDOCS)), 0);
        assert_eq!(marks(&heredocs(MAX_HEREDOCS + 1)), 1);
    }

    #[test]
    fn ruby_raw_text_refuses_what_no_context_can_hold() {
        let raw = |code: &str| ruby_raw(code.as_bytes());
        let word = |n: usize| "A".repeat(n);
        // A heredoc's word, wherever it stands: in a comment, a string, past
        // `__END__`, after a space Ruby does not read as one.
        assert_eq!(raw(&format!("# <<{}", word(65))), Some(Raw::HeredocWord));
        assert_eq!(
            raw(&format!("x = 1\u{a0}<<{}", word(65))),
            Some(Raw::HeredocWord)
        );
        assert_eq!(raw(&format!("<<~{}", word(64))), None);
        assert_eq!(raw("<<-É"), Some(Raw::HeredocWord));
        assert_eq!(raw("<<'É'"), Some(Raw::HeredocWord));
        assert_eq!(raw("<<'A\nA'"), Some(Raw::HeredocWord));
        assert_eq!(raw("<<'A"), Some(Raw::HeredocWord));
        assert_eq!(raw("<<'A'"), None);
        // Right after a quote, a `#` or a method's `.` too: Ruby starts no
        // heredoc there, but the grammar, at an error, takes any token for
        // valid and the scanner reads one.
        assert_eq!(raw("x = \"<<\"\ny = 1 # \"\n"), Some(Raw::HeredocWord));
        assert_eq!(raw("''<<`a\nb`"), Some(Raw::HeredocWord));
        assert_eq!(raw(&format!("''<<{}", word(65))), Some(Raw::HeredocWord));
        assert_eq!(raw(&format!("x.<<{}", word(65))), Some(Raw::HeredocWord));
        assert_eq!(raw("x.<<\"a b\" + c\nd = \"e\""), None);
        assert_eq!(raw("x..<<\"a\nb\""), Some(Raw::HeredocWord));
        // Ruby reads `\c`, `\C-` and `\M-` with the character after them.
        for refused in [
            "\"\\c\"",
            "\"\\C-\"",
            "\"\\M-\"",
            "\"\\M-\\C-a\"",
            "\\c#",
            "\\c",
        ] {
            assert_eq!(raw(refused), Some(Raw::Escape), "{refused}");
        }
        for refused in ["\"#$\\\\c\"", "\"#$\\\\M-\"", "%Q(#$\\\\C-)"] {
            assert_eq!(raw(refused), Some(Raw::Escape), "{refused}");
        }
        for read in [
            "\"\\cA\"",
            "\"\\C-b\\M-1\"",
            "\"\\\\c\"",
            "'C:\\\\Cache'",
            "\"\\C\"",
            "'\\Camilo'",
        ] {
            assert_eq!(raw(read), None, "{read}");
        }
        // All the heredocs the text may start, in the scanner's state.
        let starts = |n: usize| "<<A ".repeat(n);
        assert_eq!(raw(&starts(MAX_RUBY_HEREDOC_BYTES / 5)), None);
        assert_eq!(
            raw(&starts(MAX_RUBY_HEREDOC_BYTES / 5 + 1)),
            Some(Raw::Heredocs)
        );
        // And with the literals a text may start (a quote, a backtick, a `/`
        // or a `%` each), where it starts a heredoc.
        let quoted = |n: usize| format!("x = <<A\nA\n{}", "'".repeat(n));
        let room = (MAX_RUBY_STATE - 2 - 5) / 5;
        assert_eq!(raw(&quoted(room)), None);
        assert_eq!(raw(&quoted(room + 1)), Some(Raw::Heredocs));
        assert_eq!(raw(&format!("x = a\n{}", "'".repeat(1_000))), None);
        assert_eq!(
            raw(&format!("{}x = <<A\nA\n", "/%`\"".repeat(60))),
            Some(Raw::Heredocs)
        );
        assert_eq!(raw(&format!("<<'{}' ", word(60)).repeat(4)), None);
        assert_eq!(
            raw(&format!("<<'{}' ", word(60)).repeat(5)),
            Some(Raw::Heredocs)
        );
        // `#{` beyond what the scanner holds in all.
        let fields = |n: usize| "\"#{a}\" ".repeat(n);
        assert_eq!(raw(&fields(MAX_RUBY_INTERPOLATIONS)), None);
        assert_eq!(
            raw(&fields(MAX_RUBY_INTERPOLATIONS + 1)),
            Some(Raw::Interpolations)
        );
        // A `%` literal's openers, to its close, or with a field to the end.
        let nesting = |n: usize| format!("%q({}{})", "(".repeat(n), ")".repeat(n));
        assert_eq!(raw(&nesting(MAX_RUBY_NESTING)), None);
        assert_eq!(raw(&nesting(MAX_RUBY_NESTING + 1)), Some(Raw::Nesting));
        let fielded = |n: usize| format!("%(#{{a}})\n{}", "f(x) ".repeat(n));
        assert_eq!(raw(&fielded(MAX_RUBY_NESTING)), None);
        assert_eq!(raw(&fielded(MAX_RUBY_NESTING + 1)), Some(Raw::Nesting));
        assert_eq!(raw(&format!("%r{{\\d}}\n{}", "{}".repeat(300))), None);
    }

    #[test]
    fn ruby_predicate_keys_and_operator_symbols_are_read_as_they_are() {
        // `success?: true` is a key, `alias :<< :push` and `wont_be :<, 1`
        // are symbols: nothing to be unsure of after them.
        assert_eq!(depth("double(success?: true)\n(a)"), 1);
        assert_eq!(depth("alias :<< :push\n(a)"), 1);
        assert_eq!(depth("wont_be :<, 1\n(a)"), 1);
        assert_eq!(depth("x.any?{ |y| y }\n(a)"), 1);
        // An escaped line end in a heredoc's body is read as the grammar
        // reads it, and the code after the body as code.
        assert_eq!(ruby("x = <<A\n  \"a\" \\\n  b\nA\n(a)(b)(c)").depth, 1);
    }

    #[test]
    fn ruby_where_the_scan_is_unsure_it_counts_more() {
        // `x ?a :b` may be a conditional or a character: to the end of the
        // line every opener counts and no closer closes.
        assert_eq!(depth("x ?a :b\n(a)"), 1);
        assert_eq!(depth("x ?( ) ( )\n()"), 3);
        // A line that may start a literal makes it so to the end of the
        // code.
        assert_eq!(depth("x ?\"a\n()()"), 2);
    }
}
