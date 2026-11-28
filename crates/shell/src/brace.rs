//! Brace expansion: the words a POSIX shell (bash, zsh and ksh) makes of a
//! word with a brace list or a sequence in it before it runs the program: a
//! list among a program's arguments can make an option and its value out of
//! one word.
//!
//! The walk of a line reads each argument of a command with it twice when it
//! has a list: as the line writes it (what the rules of a path operand have
//! always read, with [`braces`] and [`spelled_out`]), and as the words the
//! shell makes of it ([`spell`]), and every finding of either is the line's:
//! dash and ash expand nothing, so the line as written is a reading too.
//! PowerShell and cmd expand no braces, and are read as written only.
//!
//! A word is spelled out within bounds: at most [`MAX_LISTS`] lists in it,
//! [`MAX_BRACES`] words made of it, as many words as a command of its length
//! can hold, and [`MAX_SPELLED`] bytes for the line. Past one, a word is read
//! as each element of each of its lists alone, with every other list a `*`
//! and nothing ([`approximate`]), which takes no room; and a word too long
//! for that, with too many lists, or in a form the guard does not model, is
//! one only known when it runs, which the walk says in a finding of its own.

use crate::unit::{Arg, Split};

/// The most words one brace word is expanded into: a bigger one is read as
/// a word only known when the line runs (a path operand, as the folder before
/// its first list).
const MAX_BRACES: usize = 256;

/// The most brace lists in one word that are expanded.
const MAX_LISTS: usize = 12;

/// The most brace lists in one word that are read an element at a time.
const MAX_ALONE_LISTS: usize = 64;

/// The most bytes of words the expansions of one line make in all, so that
/// many words each made many ways are not read without end.
const MAX_SPELLED: usize = 256 * 1024;

/// The longest word whose lists are read one element at a time, when they
/// make too many words to spell out.
const MAX_APPROXIMATED: usize = 1024;

/// What stands for an empty quoted word (`''`, `""`), which is an argument,
/// in a word being spelled out: no character of the word is it.
const EMPTY: char = '\u{fdd0}';

/// What stands for an expansion that is only known when the line runs
/// (`$x`, `${x:-y}`), and for one that runs a command (`$(…)`, a backtick,
/// `<(…)`), in a word being spelled out.
const HOLE: char = '\u{fdd1}';
const HOLE_RUNS: char = '\u{fdd2}';

/// What the shell makes of a word as written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Spelled {
    /// A word with nothing to spell out: no brace list or sequence outside
    /// quotes, an escape and a `${…}`.
    Plain,
    /// The words it makes, in order, empty ones that were bare left out.
    Words(Vec<Made>),
    /// Each element of each of its lists alone, with the other lists any and
    /// nothing, not the words it makes: their order and the pairing of the
    /// words are lost, so the word is also one the guard does not spell out.
    Alone(Vec<Made>),
    /// A word that does have a list or a sequence, and cannot be read: too
    /// long to read one element at a time, or in a form the guard does not
    /// model (zsh's `{a-z}`, ksh's `{1..3%d}`).
    Unknown,
}

/// One word a brace word is spelled out into.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Made {
    /// What it is, with each expansion only known when the line runs as
    /// [`crate::posix::OPAQUE`].
    pub(crate) text: String,
    /// Whether it has such an expansion: it is a template, not a value.
    pub(crate) hole: bool,
    /// Whether one of them runs a command.
    pub(crate) runs: bool,
}

/// What a line has left to spell words out with: bytes and words.
#[derive(Clone, Copy)]
struct Room {
    bytes: usize,
    words: usize,
}

impl Room {
    /// Spend a word of `word`'s length; `None` when there is not the room.
    fn take(&mut self, word: &str) -> Option<()> {
        self.words = self.words.checked_sub(1)?;
        self.bytes = self.bytes.checked_sub(word.len())?;
        Some(())
    }
}

/// What the shell makes of `source`, a word as the line writes it, quotes and
/// all, in the words of a command.
pub(crate) fn spell(source: &str, split: &mut Split) -> Spelled {
    spell_as(source, split, false)
}

/// What the shell makes of `source` as each element of each of its lists
/// alone, with the other lists any: what is read when the words themselves are
/// not (a word zsh reads another way), with no room spent.
pub(crate) fn elements(source: &str, split: &mut Split) -> Spelled {
    spell_as(source, split, true)
}

fn spell_as(source: &str, split: &mut Split, alone: bool) -> Spelled {
    if !may_list(source) {
        return Spelled::Plain;
    }
    if source.contains([EMPTY, HOLE, HOLE_RUNS]) {
        return Spelled::Unknown;
    }
    let Some(scanned) = scan(source, split, true) else {
        return Spelled::Unknown;
    };
    let chars = &scanned.chars;
    let lists = chars.iter().filter(|(c, bare)| *bare && *c == '{').count();
    if lists == 0 {
        return Spelled::Plain;
    }
    if lists > MAX_ALONE_LISTS {
        return Spelled::Unknown;
    }
    if first_group(chars).is_none() {
        return if unformed(chars) {
            Spelled::Unknown
        } else {
            Spelled::Plain
        };
    }
    // A command makes as many words as one of its length can hold: a word is
    // at least a byte and a space.
    let full = Room {
        bytes: MAX_SPELLED.saturating_sub(split.spelled),
        words: (split.line_len / 2)
            .max(MAX_BRACES)
            .saturating_sub(split.spelled_words),
    };
    let mut room = full;
    let (mut found, mut listed) = (Vec::new(), false);
    let exact = !alone
        && lists <= MAX_LISTS
        && full.words > 0
        && full.bytes > 0
        && expand(chars, &mut found, &mut listed, &mut room).is_some();
    let words = if exact {
        split.spelled += full.bytes - room.bytes;
        split.spelled_words += full.words - room.words;
        found
    } else {
        // Each element alone, within what the line may spend on it: the
        // bytes it spells out, and as many words as a line of its length
        // holds.
        if chars.len() > MAX_APPROXIMATED || full.bytes == 0 {
            return Spelled::Unknown;
        }
        let most = (split.line_len)
            .max(MAX_BRACES)
            .saturating_sub(split.alone_words);
        let Some(words) = approximate(chars, MAX_BRACES.min(most)) else {
            return Spelled::Unknown;
        };
        let bytes: usize = words.iter().map(String::len).sum();
        split.alone_words += words.len();
        split.spelled += bytes.min(full.bytes);
        if bytes > full.bytes {
            split.spelled = MAX_SPELLED;
            return Spelled::Unknown;
        }
        // Their order is lost and so is what goes with what, unless the word
        // is one list, whose elements alone are the words it makes.
        let lone = lists == 1 && first_group(chars).is_some();
        let made = made_of(words);
        return if lone {
            Spelled::Words(made)
        } else {
            Spelled::Alone(made)
        };
    };
    Spelled::Words(made_of(words))
}

/// The words `words` are, as the walk reads a word: the empty ones a bare
/// element made left out.
fn made_of(words: Vec<String>) -> Vec<Made> {
    words
        .into_iter()
        .filter_map(|word| {
            let kept = word.contains(EMPTY);
            let (hole, runs) = (word.contains([HOLE, HOLE_RUNS]), word.contains(HOLE_RUNS));
            let mut text = String::with_capacity(word.len());
            for c in word.chars() {
                match c {
                    EMPTY => {}
                    HOLE | HOLE_RUNS => text.push_str(crate::posix::OPAQUE),
                    c => text.push(c),
                }
            }
            // An empty word the shell made of a bare element is no argument;
            // a quoted one (`''`) is.
            (!text.is_empty() || kept).then_some(Made { text, hole, runs })
        })
        .collect()
}

/// Whether `text` may hold a brace list or a sequence: a `{`, and a `,`, `..`
/// or `-` (`{a-z}`) somewhere. A cheap test that most words fail, before it is
/// read.
fn may_list(text: &str) -> bool {
    text.contains('{') && text.contains([',', '.', '-'])
}

/// Whether the bare braces of `chars`, none of which makes a list or a
/// sequence, are a form zsh with `BRACE_CCL` (`{a-z}`) or ksh93 (`{1..3%d}`)
/// reads as words: not modelled, so a word with one is not read.
fn unformed(chars: &[(char, bool)]) -> bool {
    let mut at = 0;
    while let Some(open) = chars
        .get(at..)
        .and_then(|rest| rest.iter().position(|&(c, bare)| bare && c == '{'))
        .map(|found| found + at)
    {
        let rest = chars.get(open + 1..).unwrap_or_default();
        if let Some(close) = rest
            .iter()
            .position(|&(c, bare)| bare && (c == '}' || c == '{'))
        {
            if rest.get(close).is_some_and(|&(c, _)| c == '}') {
                let inner = rest.get(..close).unwrap_or_default();
                let range = inner
                    .windows(3)
                    .any(|w| w[1] == ('-', true) && w[0].0 != '-' && w[2].0 != '-');
                let formatted = inner.iter().any(|&(c, bare)| bare && c == '%')
                    && inner.windows(2).any(|w| w[0].0 == '.' && w[1].0 == '.');
                if range || formatted {
                    return true;
                }
            }
        }
        at = open + 1;
    }
    false
}

/// A word read into characters, each with whether it is bare: not quoted and
/// not escaped.
struct Scanned {
    chars: Vec<(char, bool)>,
    /// It holds an ANSI-C string (`$'…'`), a value known when the line is
    /// read.
    ansi: bool,
    /// It holds an expansion the line gives no value for (`$x`, `${x:-y}`,
    /// `$(…)`, a backtick).
    opaque: bool,
    /// A quote opened before the first slash that is bare, in the prefix of
    /// a `~` the word starts with (`~''/x` and `''~` are no tilde).
    quoted_prefix: bool,
}

/// The variables a word may name that are a place the guard knows, and the
/// place: `$HOME`, `$PWD` and `$TMPDIR`, unless the line sets them.
fn known_variable(name: &str, split: &Split) -> Option<&'static str> {
    let value = match name {
        "HOME" => "~",
        "PWD" => ".",
        "TMPDIR" => "/tmp",
        _ => return None,
    };
    (!split.reassigned(name)).then_some(value)
}

/// Read `source` as the shell reads a word: quotes and escapes taken off as it
/// takes them, an ANSI-C string and the places a few variables name as their
/// values, and any other expansion left as written, not bare, with the word
/// marked. With `spelling`, an expansion is one [`HOLE`] and an empty quoted
/// word is an [`EMPTY`], for a word that is read as its words; without, the
/// word is read as a path operand reads it. `None` for a string that does not
/// close.
fn scan(source: &str, split: &Split, spelling: bool) -> Option<Scanned> {
    // Each character, and whether it is bare.
    let mut chars: Vec<(char, bool)> = Vec::with_capacity(source.len());
    let mut quote: Option<char> = None;
    let mut opened = 0;
    let (mut ansi, mut opaque) = (false, false);
    let mut quoted_prefix = false;
    let mut iter = source.chars().peekable();
    while let Some(c) = iter.next() {
        match (quote, c) {
            (None, '$') if iter.peek() == Some(&'\'') => {
                iter.next();
                ansi = true;
                quoted_prefix |= !chars.iter().any(|(c, bare)| *c == '/' && *bare);
                let decoded = ansi_c(&mut iter)?;
                if chars.is_empty() && decoded.first() == Some(&'~') {
                    chars.extend([('.', false), ('/', false)]);
                }
                if spelling && decoded.is_empty() {
                    chars.push((EMPTY, false));
                }
                chars.extend(decoded.into_iter().map(|c| (c, false)));
            }
            // `$HOME`, `$PWD` and `$TMPDIR` are the places the guard names,
            // as in a plain word, unless the line sets them.
            (None | Some('"'), '$') => {
                let mut probe = iter.clone();
                let value = variable_name(&mut probe).and_then(|name| known_variable(&name, split));
                if let Some(value) = value {
                    iter = probe;
                    chars.extend(value.chars().map(|c| (c, false)));
                } else {
                    opaque = true;
                    let mut region = vec![('$', false)];
                    skip_expansion(&mut iter, &mut region);
                    hole(&mut chars, region, spelling);
                }
            }
            (None, '\'' | '"') => {
                quoted_prefix |= !chars.iter().any(|(c, bare)| *c == '/' && *bare);
                quote = Some(c);
                opened = chars.len();
            }
            (Some(open), c) if c == open => {
                quote = None;
                if spelling && chars.len() == opened {
                    chars.push((EMPTY, false));
                }
            }
            (Some('\''), c) => chars.push((c, false)),
            (_, '`') => {
                opaque = true;
                let mut region = vec![('`', false)];
                for next in iter.by_ref() {
                    region.push((next, false));
                    if next == '`' {
                        break;
                    }
                }
                hole(&mut chars, region, spelling);
            }
            // `<(cmd)` and `>(cmd)` are the command's, not the word's.
            (None, '<' | '>') if iter.peek() == Some(&'(') => {
                opaque = true;
                let mut region = vec![(c, false)];
                skip_balanced(&mut iter, &mut region, '(', ')');
                hole(&mut chars, region, spelling);
            }
            (None, '\\') => chars.push((iter.next()?, false)),
            (Some(_), '\\') => {
                let next = iter.next()?;
                if !matches!(next, '"' | '\\' | '$' | '`') {
                    chars.push(('\\', false));
                }
                chars.push((next, false));
            }
            (Some(_), c) => chars.push((c, false)),
            (None, c) => chars.push((c, true)),
        }
    }
    Some(Scanned {
        chars,
        ansi,
        opaque,
        quoted_prefix,
    })
}

/// Put the expansion `region` in `chars`: as it is written, or, for a word
/// that is spelled out, as one character that says whether it runs a
/// command.
fn hole(chars: &mut Vec<(char, bool)>, region: Vec<(char, bool)>, spelling: bool) {
    if !spelling {
        chars.extend(region);
        return;
    }
    let text: String = region.iter().map(|(c, _)| c).collect();
    let runs = text.contains("$(") || text.contains(['`', '<', '>']);
    chars.push((if runs { HOLE_RUNS } else { HOLE }, false));
}

/// Take the rest of the expansion after a `$` that has been read off
/// `iter` into `chars`, none of it bare: `${…}` and `$(…)` up to their end,
/// and a name or a one-character parameter.
fn skip_expansion(
    iter: &mut std::iter::Peekable<std::str::Chars<'_>>,
    chars: &mut Vec<(char, bool)>,
) {
    match iter.peek() {
        Some('{') => skip_balanced(iter, chars, '{', '}'),
        Some('(') => skip_balanced(iter, chars, '(', ')'),
        Some(c) if c.is_ascii_alphanumeric() || *c == '_' => {
            while let Some(c) = iter.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                chars.push((c, false));
            }
        }
        Some(c) if matches!(c, '@' | '*' | '#' | '?' | '-' | '$' | '!') => {
            chars.push((*c, false));
            iter.next();
        }
        _ => {}
    }
}

/// Take the group `iter` is at, which starts with `open`, up to its `close`
/// (groups of the same two characters inside it, quoted text and escapes
/// are read as they stand) into `chars`, none of it bare; all that is left
/// if it does not close.
fn skip_balanced(
    iter: &mut std::iter::Peekable<std::str::Chars<'_>>,
    chars: &mut Vec<(char, bool)>,
    open: char,
    close: char,
) {
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    while let Some(c) = iter.next() {
        chars.push((c, false));
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (_, '\\') => {
                if let Some(next) = iter.next() {
                    chars.push((next, false));
                }
            }
            (None, '\'' | '"') => quote = Some(c),
            (Some(_), _) => {}
            (None, c) if c == open => depth += 1,
            (None, c) if c == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return;
                }
            }
            (None, _) => {}
        }
    }
}

/// The words a POSIX word as written stands for, when it has a brace list or
/// an ANSI-C string (`$'\x2f'etc`) in it: `~/.ssh/{id_rsa,x}` is `~/.ssh/id_rsa`
/// and `~/.ssh/x`. Quotes and backslashes are taken off as the shell takes
/// them; a brace that is quoted, escaped, or has no comma in it (`{a}`,
/// `{1..3}`) is text. `None` when the word has neither or holds an expansion
/// (`$x`, `` `cmd` ``); see [`spelled_out`] for a list that is too big.
///
/// An ANSI-C string is a value known when the line is read, so it is read; a
/// `~` it makes is a plain character, not the home directory.
pub(crate) fn braces(source: &str, split: &Split) -> Option<Vec<Arg>> {
    let mut scanned = scan(source, split, false)?;
    if scanned.opaque {
        return None;
    }
    // The shell expands a `~` only when it starts the word and nothing of
    // its prefix, the text up to the first slash it reads as one, is quoted
    // or escaped: otherwise it is a plain character, a name in the folder
    // the line is in.
    let chars = &mut scanned.chars;
    if chars.first() == Some(&('~', true)) {
        let prefix = chars
            .iter()
            .position(|(c, bare)| *c == '/' && *bare)
            .unwrap_or(chars.len());
        if scanned.quoted_prefix || chars[..prefix].iter().any(|(_, bare)| !bare) {
            chars.splice(0..0, [('.', false), ('/', false)]);
        }
    }
    let spelled = spelled_out(&scanned.chars).or_else(|| {
        scanned
            .ansi
            .then(|| vec![scanned.chars.iter().map(|(c, _)| c).collect::<String>()])
    });
    spelled.map(|found| found.into_iter().map(Arg::Known).collect())
}

/// The name of the variable after a `$` that has been read: `NAME` or
/// `{NAME}`; `None` for any other expansion (`$(…)`, `${X:-y}`, `$1`).
fn variable_name(iter: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let braced = iter.peek() == Some(&'{');
    if braced {
        iter.next();
    }
    let mut name = String::new();
    while let Some(&c) = iter.peek() {
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
            iter.next();
        } else {
            break;
        }
    }
    if braced && iter.next() != Some('}') {
        return None;
    }
    (!name.is_empty()).then_some(name)
}

/// The characters of an ANSI-C string (`$'…'`) whose opening quote has been
/// read, up to the closing one: `\n`, `\t`, `\xHH`, `\nnn`, `\uHHHH`, `\e` and
/// the rest as bash reads them. `None` when it does not close.
fn ansi_c(iter: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<Vec<char>> {
    let mut out = Vec::new();
    let mut ended = false;
    loop {
        let c = iter.next()?;
        if c == '\'' {
            return Some(out);
        }
        if ended {
            continue;
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        let e = iter.next()?;
        let number = |iter: &mut std::iter::Peekable<std::str::Chars<'_>>,
                      radix: u32,
                      most: usize,
                      first: Option<char>| {
            let mut value = first.and_then(|d| d.to_digit(radix)).unwrap_or(0);
            let mut count = usize::from(first.is_some());
            while count < most {
                match iter.peek().and_then(|d| d.to_digit(radix)) {
                    Some(digit) => {
                        value = value.saturating_mul(radix).saturating_add(digit);
                        iter.next();
                        count += 1;
                    }
                    None => break,
                }
            }
            (value, count)
        };
        let decoded = match e {
            'a' => Some('\x07'),
            'b' => Some('\x08'),
            'e' | 'E' => Some('\x1b'),
            'f' => Some('\x0c'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'v' => Some('\x0b'),
            '\\' | '\'' | '"' | '?' => Some(e),
            '0'..='7' => {
                let (value, _) = number(iter, 8, 3, Some(e));
                char::from_u32(value & 0xff)
            }
            'x' => {
                let (value, count) = number(iter, 16, 2, None);
                if count == 0 {
                    out.extend(['\\', 'x']);
                    continue;
                }
                char::from_u32(value)
            }
            'u' | 'U' => {
                let (value, count) = number(iter, 16, if e == 'u' { 4 } else { 8 }, None);
                if count == 0 {
                    out.extend(['\\', e]);
                    continue;
                }
                char::from_u32(value)
            }
            'c' => iter
                .next()
                .and_then(|x| char::from_u32(u32::from(x) & 0x1f)),
            other => {
                out.extend(['\\', other]);
                continue;
            }
        };
        match decoded {
            // A NUL ends the string, as bash reads it.
            Some('\0') => ended = true,
            Some(c) => out.push(c),
            None => return None,
        }
    }
}

/// The words the brace lists in `chars` stand for; `None` when there is no
/// list. A word with more lists than [`MAX_LISTS`] in it, or that stands for
/// more than [`MAX_BRACES`] words, is not spelled out, since it would make as
/// many words as the product of the lists' sizes and be read once for each:
/// it stands for the folder before its first list, where it ends in one
/// (`~/.ssh/{a,b}{a,b}…` lands in `~/.ssh/`).
pub(crate) fn spelled_out(chars: &[(char, bool)]) -> Option<Vec<String>> {
    let lists = chars.iter().filter(|(c, bare)| *bare && *c == '{').count();
    if lists == 0 {
        return None;
    }
    let mut found = Vec::new();
    let mut listed = false;
    if lists <= MAX_LISTS && expand_lists(chars, &mut found, &mut listed).is_some() {
        return listed.then_some(found);
    }
    let before: String = chars
        .iter()
        .take_while(|(c, bare)| !(*bare && *c == '{'))
        .map(|(c, _)| c)
        .collect();
    Some(if before.ends_with('/') {
        vec![before]
    } else {
        Vec::new()
    })
}

/// Expand the first bare brace list in `chars` and then each word it makes;
/// `None` once there are more than [`MAX_BRACES`] words.
fn expand_lists(chars: &[(char, bool)], found: &mut Vec<String>, listed: &mut bool) -> Option<()> {
    if let Some((open, close, commas)) = first_list(chars) {
        *listed = true;
        let mut start = open + 1;
        for &stop in commas.iter().chain(std::iter::once(&close)) {
            let mut word = chars[..open].to_vec();
            word.extend_from_slice(&chars[start..stop]);
            word.extend_from_slice(&chars[close + 1..]);
            expand_lists(&word, found, listed)?;
            start = stop + 1;
        }
        return Some(());
    }
    if found.len() >= MAX_BRACES {
        return None;
    }
    found.push(chars.iter().map(|(c, _)| c).collect());
    Some(())
}

/// The first bare `{` that closes with a bare comma between: where it opens,
/// where it closes, and the commas at its top level.
fn first_list(chars: &[(char, bool)]) -> Option<(usize, usize, Vec<usize>)> {
    for (open, _) in chars
        .iter()
        .enumerate()
        .filter(|(_, &(c, bare))| bare && c == '{')
    {
        let (mut depth, mut commas) = (0_usize, Vec::new());
        for (at, &(c, bare)) in chars.iter().enumerate().skip(open) {
            if !bare {
                continue;
            }
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if commas.is_empty() {
                            break;
                        }
                        return Some((open, at, commas));
                    }
                }
                ',' if depth == 1 => commas.push(at),
                _ => {}
            }
        }
    }
    None
}

/// Expand the first bare brace list or sequence in `chars` and then each
/// word it makes; `None` once there are more than [`MAX_BRACES`] words, or
/// more than `room` has.
fn expand(
    chars: &[(char, bool)],
    found: &mut Vec<String>,
    listed: &mut bool,
    room: &mut Room,
) -> Option<()> {
    if let Some((open, close, group)) = first_group(chars) {
        *listed = true;
        let most = room.words.min(MAX_BRACES);
        let mut each = |piece: &[(char, bool)], found: &mut Vec<String>| {
            let mut word = chars.get(..open).unwrap_or_default().to_vec();
            word.extend_from_slice(piece);
            word.extend_from_slice(chars.get(close + 1..).unwrap_or_default());
            expand(&word, found, listed, room)
        };
        match group {
            Group::List(commas) => {
                let mut start = open + 1;
                for &stop in commas.iter().chain(std::iter::once(&close)) {
                    each(chars.get(start..stop).unwrap_or_default(), found)?;
                    start = stop + 1;
                }
            }
            Group::Sequence(text) => {
                for made in Sequence::of(&text)?.words(most)? {
                    let piece: Vec<(char, bool)> = made.chars().map(|c| (c, false)).collect();
                    each(&piece, found)?;
                }
            }
        }
        return Some(());
    }
    if found.len() >= MAX_BRACES {
        return None;
    }
    let word: String = chars.iter().map(|(c, _)| c).collect();
    room.take(&word)?;
    found.push(word);
    Some(())
}

/// What the words of `chars` are, past what can be spelled out, as far as an
/// option or a path in one can be told: each element of each list or
/// sequence of it alone, with every other list a `*` (a sequence of more
/// than [`MAX_BRACES`] numbers is a `*` itself). `None` for more than
/// `most` words.
fn approximate(chars: &[(char, bool)], most: usize) -> Option<Vec<String>> {
    // The lists of the word that are not in another, and where.
    let mut groups = Vec::new();
    let mut at = 0;
    while let Some((open, close, group)) = chars.get(at..).and_then(first_group) {
        // Where the commas are, in `chars`, not in what is left of it.
        let group = match group {
            Group::List(commas) => Group::List(commas.iter().map(|comma| comma + at).collect()),
            sequence @ Group::Sequence(_) => sequence,
        };
        groups.push((at + open, at + close, group));
        at += close + 1;
    }
    let plain = |from: usize, to: usize| -> String {
        chars
            .get(from..to)
            .unwrap_or_default()
            .iter()
            .map(|(c, _)| c)
            .collect()
    };
    if groups.is_empty() {
        return Some(vec![plain(0, chars.len())]);
    }
    // Which of them may make nothing.
    let empty: Vec<bool> = groups
        .iter()
        .map(|(open, close, group)| match group {
            Group::List(commas) => {
                let mut start = open + 1;
                commas.iter().chain(std::iter::once(close)).any(|&stop| {
                    let none = start == stop;
                    start = stop + 1;
                    none
                })
            }
            Group::Sequence(_) => false,
        })
        .collect();
    let mut out = Vec::new();
    for (this, (open, close, group)) in groups.iter().enumerate() {
        // The word around the list, with each other list a `*`.
        // The word around the list, with each other list a `*`, and with each
        // other list nothing where it may be (it has an empty element: the
        // shell makes a word of the element alone when the others make
        // nothing).
        let (mut before, mut bare_before) = (String::new(), String::new());
        let mut from = 0;
        for (other, (o_open, o_close, _)) in groups.iter().enumerate().take(this) {
            before.push_str(&plain(from, *o_open));
            bare_before.push_str(&plain(from, *o_open));
            before.push('*');
            bare_before.push_str(if empty[other] { "" } else { "*" });
            from = o_close + 1;
        }
        before.push_str(&plain(from, *open));
        bare_before.push_str(&plain(from, *open));
        let (mut after, mut bare_after) = (String::new(), String::new());
        let mut from = close + 1;
        for (other, (o_open, o_close, _)) in groups.iter().enumerate().skip(this + 1) {
            after.push_str(&plain(from, *o_open));
            bare_after.push_str(&plain(from, *o_open));
            after.push('*');
            bare_after.push_str(if empty[other] { "" } else { "*" });
            from = o_close + 1;
        }
        after.push_str(&plain(from, chars.len()));
        bare_after.push_str(&plain(from, chars.len()));
        let elements: Vec<Vec<(char, bool)>> = match group {
            Group::List(commas) => {
                let mut start = open + 1;
                let mut each = Vec::new();
                for &stop in commas.iter().chain(std::iter::once(close)) {
                    each.push(chars.get(start..stop).unwrap_or_default().to_vec());
                    start = stop + 1;
                }
                each
            }
            // Numbers are any: a `*`; characters, as many as they are.
            Group::Sequence(text) => match Sequence::of(text) {
                Some(sequence)
                    if !sequence.numeric
                        && sequence.count() <= i128::try_from(MAX_BRACES).unwrap_or(0) =>
                {
                    sequence
                        .words(most)?
                        .iter()
                        .map(|word| word.chars().map(|c| (c, false)).collect())
                        .collect()
                }
                _ => vec![vec![('*', false)]],
            },
        };
        for element in &elements {
            for inner in approximate(element, most)? {
                out.push(format!("{before}{inner}{after}"));
                let bare = format!("{bare_before}{inner}{bare_after}");
                if out.last() != Some(&bare) {
                    out.push(bare);
                }
                if out.len() > most {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// What a brace is: a list, with where its commas are, or a sequence
/// expression, with what is between its braces.
enum Group {
    List(Vec<usize>),
    Sequence(String),
}

/// The first bare `{` that closes with a bare comma between, or a sequence
/// expression (`{1..3}`, `{a..c}`, `{1..9..2}`) inside: where it opens,
/// where it closes, and what it is.
fn first_group(chars: &[(char, bool)]) -> Option<(usize, usize, Group)> {
    for (open, _) in chars
        .iter()
        .enumerate()
        .filter(|(_, &(c, bare))| bare && c == '{')
    {
        let (mut depth, mut commas) = (0_usize, Vec::new());
        for (at, &(c, bare)) in chars.iter().enumerate().skip(open) {
            if !bare {
                continue;
            }
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if commas.is_empty() {
                            if let Some(text) = chars.get(open + 1..at).and_then(sequence_text) {
                                return Some((open, at, Group::Sequence(text)));
                            }
                            break;
                        }
                        return Some((open, at, Group::List(commas)));
                    }
                }
                ',' if depth == 1 => commas.push(at),
                _ => {}
            }
        }
    }
    None
}

/// What is between the braces of a sequence expression, when `inner` is one:
/// all of it bare, with no brace or comma, and two integers or two single
/// characters, and an integer step ([`crate::path::sequence`]).
fn sequence_text(inner: &[(char, bool)]) -> Option<String> {
    if inner
        .iter()
        .any(|&(c, bare)| !bare || matches!(c, '{' | '}' | ','))
    {
        return None;
    }
    let text: String = inner.iter().map(|(c, _)| c).collect();
    crate::path::sequence(&text).then_some(text)
}

/// What a sequence expression is: where it starts and ends, by what step, how
/// wide its numbers are padded, and whether they are numbers (or characters).
struct Sequence {
    start: i128,
    end: i128,
    step: i128,
    width: usize,
    numeric: bool,
}

impl Sequence {
    /// The sequence expression `text` (`1..3`, `a..e`, `01..10..3`, already
    /// known to be one); `None` for a number too big to read.
    fn of(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split("..").collect();
        let (from, to, step) = match parts.as_slice() {
            [from, to] => (*from, *to, 1),
            [from, to, step] => (*from, *to, step.parse::<i64>().ok()?.unsigned_abs().max(1)),
            _ => return None,
        };
        let numbers = |part: &str| {
            let digits = part.strip_prefix(['-', '+']).unwrap_or(part);
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        };
        let numeric = numbers(from) && numbers(to);
        let (start, end, width) = if numeric {
            // A leading zero pads every number to the longest of the two.
            let padded = |part: &str| {
                let digits = part.strip_prefix(['-', '+']).unwrap_or(part);
                digits.len() > 1 && digits.starts_with('0')
            };
            let width = if padded(from) || padded(to) {
                from.len().max(to.len())
            } else {
                0
            };
            (
                i128::from(from.parse::<i64>().ok()?),
                i128::from(to.parse::<i64>().ok()?),
                width,
            )
        } else {
            let mut each = [from, to].map(|part| part.chars().next().map(u32::from));
            (i128::from(each[0].take()?), i128::from(each[1].take()?), 0)
        };
        Some(Self {
            start,
            end,
            step: i128::from(step),
            width,
            numeric,
        })
    }

    /// How many words it makes.
    fn count(&self) -> i128 {
        (self.end - self.start).abs() / self.step + 1
    }

    /// The words it makes: `None` for more than `most`, which is known before
    /// any is made.
    fn words(&self, most: usize) -> Option<Vec<String>> {
        let count = self.count();
        if count > i128::try_from(most).ok()? {
            return None;
        }
        let width = self.width;
        let mut words = Vec::new();
        let mut at = self.start;
        for _ in 0..count {
            words.push(if self.numeric {
                format!("{at:0width$}")
            } else {
                char::from_u32(u32::try_from(at).ok()?)?.to_string()
            });
            at += if self.end >= self.start {
                self.step
            } else {
                -self.step
            };
        }
        Some(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spelled(source: &str) -> Spelled {
        spell(source, &mut Split::default())
    }

    /// The text of each word `source` is spelled into, or `None` when it is
    /// not spelled out.
    fn words(source: &str) -> Option<Vec<String>> {
        match spelled(source) {
            Spelled::Words(made) | Spelled::Alone(made) => {
                Some(made.into_iter().map(|word| word.text).collect())
            }
            Spelled::Plain | Spelled::Unknown => None,
        }
    }

    #[test]
    fn a_list_is_the_words_it_makes() {
        assert_eq!(words("a{b,c}d"), Some(vec!["abd".into(), "acd".into()]));
        assert_eq!(words("{-c,'x y'}"), Some(vec!["-c".into(), "x y".into()]));
        assert_eq!(words("{a,b}{1..2}").map(|w| w.len()), Some(4));
        assert_eq!(
            words("x{01..03}"),
            Some(vec!["x01".into(), "x02".into(), "x03".into()])
        );
        assert_eq!(
            words("{c..a}"),
            Some(vec!["c".into(), "b".into(), "a".into()])
        );
    }

    #[test]
    fn what_is_quoted_escaped_or_no_list_is_plain() {
        for source in [
            "'{a,b}'",
            "\"{a,b}\"",
            "\\{a,b}",
            "{a}",
            "{}",
            "${x,,}",
            "{a,b",
        ] {
            assert_eq!(spelled(source), Spelled::Plain, "{source}");
        }
    }

    #[test]
    fn an_empty_word_is_an_argument_only_when_it_is_quoted() {
        assert_eq!(words("{,a}"), Some(vec!["a".into()]));
        assert_eq!(words("{'',a}"), Some(vec![String::new(), "a".into()]));
        assert_eq!(words("{\"\",a}"), Some(vec![String::new(), "a".into()]));
        assert_eq!(words("{$'',a}"), Some(vec![String::new(), "a".into()]));
    }

    #[test]
    fn a_part_only_known_when_it_runs_makes_a_template_word() {
        let Spelled::Words(made) = spelled("~/.ssh/{$f,x,$(y)}") else {
            panic!("not spelled");
        };
        let each: Vec<(&str, bool, bool)> = made
            .iter()
            .map(|word| (word.text.as_str(), word.hole, word.runs))
            .collect();
        assert_eq!(
            each,
            [
                ("~/.ssh/$__v", true, false),
                ("~/.ssh/x", false, false),
                ("~/.ssh/$__v", true, true)
            ]
        );
    }

    #[test]
    fn a_list_past_the_bounds_is_each_element_alone_with_the_rest_any() {
        assert_eq!(
            words("id_rsa{,{1..300}}"),
            Some(vec!["id_rsa".into(), "id_rsa*".into()])
        );
        assert_eq!(
            words("{{1..300},-delete}"),
            Some(vec!["*".into(), "-delete".into()])
        );
        let letters = words("{,{a..z}{a..z}}").unwrap_or_default();
        assert!(letters.contains(&"a*".to_string()) && letters.contains(&"*z".to_string()));
        // Too long to be read so, and more lists than are read.
        let long = format!("{}{{a,b}}{{1..300}}", "y".repeat(MAX_APPROXIMATED));
        assert_eq!(spelled(&long), Spelled::Unknown);
        let each = words("{a,b}{c,d}{1..300}").unwrap_or_default();
        assert!(each.contains(&"*c*".to_string()) && !each.contains(&"c".to_string()));
        assert!(each.contains(&"b**".to_string()));
        let many = words(&format!("{{-delete,}}{}", "{,}".repeat(MAX_LISTS))).unwrap_or_default();
        assert!(many.contains(&"-delete".to_string()), "{many:?}");
    }

    #[test]
    fn nothing_for_a_list_that_cannot_make_nothing_and_never_an_absolute_word() {
        let each = words("{a..z}/{a..z}").unwrap_or_default();
        assert!(
            !each.is_empty() && each.iter().all(|word| !word.starts_with('/')),
            "{each:?}"
        );
        // A list with an empty element may make nothing.
        let each = words("x{,{a..z}}{1,{b..z}}{,y}").unwrap_or_default();
        assert!(each.contains(&"x*".to_string()), "{each:?}");
        // A list that may make nothing may open a word: a word of it is
        // absolute where it makes nothing.
        let each = words("{,x}/etc{,{1..300}}").unwrap_or_default();
        assert!(each.contains(&"/etc".to_string()), "{each:?}");
        // A word of one sequence is its numbers, any, and no more doubt.
        assert!(matches!(spelled("{1..300}"), Spelled::Words(_)));
        assert!(matches!(spelled("file{001..500}"), Spelled::Words(_)));
        assert!(matches!(spelled("{1..300}{a,b}"), Spelled::Alone(_)));
    }

    #[test]
    fn a_line_that_has_spelled_all_it_may_spells_no_more() {
        let mut split = Split::default();
        assert!(matches!(spell("{1..256}", &mut split), Spelled::Words(_)));
        assert_eq!(split.spelled_words, MAX_BRACES);
        // The rest is each element alone, which needs no room.
        let Spelled::Words(rest) = spell("{-x,y}", &mut split) else {
            panic!("not read");
        };
        assert_eq!(rest.len(), 2);
        assert_eq!(split.spelled_words, MAX_BRACES);
    }

    #[test]
    fn a_form_zsh_or_ksh_reads_as_words_is_not_read() {
        assert_eq!(spelled("{a-z}"), Spelled::Unknown);
        assert_eq!(spelled("{1..3%d}"), Spelled::Unknown);
        assert_eq!(spelled("{-c}"), Spelled::Plain);
        assert_eq!(spelled("{a--b}"), Spelled::Plain);
    }

    #[test]
    fn a_word_as_a_path_operand_reads_it_is_read_as_it_always_was() {
        let split = Split::default();
        let each = |source: &str| {
            braces(source, &split).map(|args| {
                args.iter()
                    .map(|arg| arg.text().to_string())
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            each("~/.ssh/{id_rsa,x}"),
            Some(vec!["~/.ssh/id_rsa".into(), "~/.ssh/x".into()])
        );
        // Sequences are not read, and a list past the bounds is the folder
        // before it.
        assert_eq!(each("~/.ssh/id_{1..3}"), None);
        assert_eq!(
            each(&format!("~/.ssh/{}", "{a,b}".repeat(9))),
            Some(vec!["~/.ssh/".into()])
        );
        assert_eq!(each("{a,$x}"), None);
    }
}
