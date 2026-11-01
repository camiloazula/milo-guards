//! Wildcard patterns in a path: which entries of a folder one can match.
//!
//! A part of a path holding `*`, `?` or `[` stands for the entries that
//! match it. The resolver judges a pattern by the folder before its first
//! wildcard; [`shape`] says how much of that folder the pattern takes, and
//! [`matches()`] tells whether one pattern part can match one name.

use crate::resolve::windows_name;
use crate::Flavour;

/// The characters that make a path part a pattern.
pub(crate) const WILDCARDS: [char; 3] = ['*', '?', '['];

/// Whether `text` holds a wildcard.
#[must_use]
pub fn has_wildcard(text: &str) -> bool {
    text.contains(WILDCARDS)
}

/// The hidden names the path model protects inside a workspace.
const PROTECTED: [&str; 1] = [".git"];

/// What a repository's `.git` folder holds at its top level: a pattern that
/// reaches one of these through `.git` takes the repository's history.
const GIT_ENTRIES: [&str; 18] = [
    "HEAD",
    "config",
    "index",
    "objects",
    "refs",
    "hooks",
    "info",
    "logs",
    "packed-refs",
    "modules",
    "lfs",
    "worktrees",
    "shallow",
    "ORIG_HEAD",
    "MERGE_HEAD",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
];

/// Files deeper in `.git` whose loss hurts as much (a branch's tip, the
/// repository's description, the last message, `stash`, which is the only
/// reference to every stash entry, a pack): a name search of
/// every folder that finds one of these takes history with it.
const GIT_FILES: [&str; 8] = [
    "description",
    "COMMIT_EDITMSG",
    "FETCH_HEAD",
    "stash",
    "main",
    "master",
    "pack-0.pack",
    "pack-0.idx",
];

/// Folders below the top level whose loss takes history with it: the packs
/// (`objects/pack`), every branch tip and its reflog (`refs/heads`,
/// `logs/refs/heads`), the tags, the remote-tracking branches and the default
/// remote, `origin`, which is as well known as `main`.
const GIT_FOLDERS: [&str; 5] = ["pack", "heads", "tags", "remotes", "origin"];

/// The hex digits an object's name is spelled with (lower case, as git writes
/// them; a Windows name compares without case).
const HEX: &str = "0123456789abcdef";

/// The digits of an 8.3 short name's `~n` tail.
const TAIL_DIGITS: &str = "123456789";

/// The 8.3 short names Windows gives the long names above on a drive that
/// creates them (the system drive does by default): cmd matches its wildcards
/// against these as well as the long names, which is why `*.pac` finds a pack.
/// A name of at most eight characters with an extension of at most three has
/// none.
const GIT_SHORT_NAMES: [&str; 12] = [
    "PACKED~1",
    "COMMIT~1",
    "DESCRI~1",
    "ORIG_H~1",
    "FETCH_~1",
    "MERGE_~1",
    "REBASE~1",
    "REBASE~2",
    "SEQUEN~1",
    "WORKTR~1",
    "PACK-0~1.PAC",
    "PACK-0~1.IDX",
];

/// Whether the name pattern `pattern` can match the name of something a
/// repository's `.git` holds: one of its top-level entries (`HEAD`, `config`,
/// `index`, `objects`, ...), a well-known file deeper in (`description`,
/// `COMMIT_EDITMSG`, a branch named `main` or `master`), a well-known folder
/// deeper in (`pack`, `heads`, `tags`, `remotes`, `origin`), or an object by
/// the shape of its name: a loose object's folder (two hex digits), its file
/// (thirty-eight) and a pack (`pack-` and forty hex digits, then `.pack` or
/// `.idx`).
///
/// It is for a search that goes into every folder below one (`del /s`, a
/// recursive `Get-ChildItem`), which finds `.git`'s own files whatever folder
/// they lie in. On Windows the pattern is read as cmd reads it, which is not
/// how PowerShell does:
/// - a trailing dot or space is not part of a name, so the pattern is read
///   both with and without it;
/// - a `.` followed by `*` or `?` also matches nothing, as cmd turns it into
///   a DOS dot (`main.*` finds `main`, as `dir foo.*` lists `foo`, and
///   `HEAD.*.*` finds `HEAD`);
/// - a run of `?` at the end of the pattern, or just before a `.`, can match
///   nothing (`HEAD?` finds `HEAD`, `main?.x` finds `main.x`);
/// - the 8.3 short names of the long ones are tried as well (`PACKED~1`,
///   `*.pac`, and the six hex digits and `~1` of a loose object's).
///
/// A hex-shaped name is judged by shape: the pattern is asked whether it can
/// match some string of that many hex digits, so `??`, `1*` and `*7*` are
/// told, and `bin`, `obj`, `*.tmp` and `*.log` are not. Only the names above
/// are tried: a pattern that matches a branch with some other name (`dev`) is
/// not told.
///
/// `flavour` is as for [`matches()`]; a name is matched with `hidden` on.
#[must_use]
pub fn can_match_git_entry(pattern: &str, flavour: Flavour) -> bool {
    let names = GIT_ENTRIES.iter().chain(&GIT_FILES).chain(&GIT_FOLDERS);
    if flavour != Flavour::Windows {
        return !pattern.is_empty()
            && (names
                .clone()
                .any(|name| matches(pattern, name, flavour, true))
                || can_match_shape(pattern, flavour, &hex_shapes(false)));
    }
    can_match_cmd(
        pattern,
        names.chain(&GIT_SHORT_NAMES),
        &hex_shapes(true),
        true,
    )
}

/// As [`can_match_git_entry`] on Windows, for PowerShell's own matching (an
/// `-Include`), where cmd's DOS wildcards (`<`, `>`, `"`) are plain
/// characters.
#[must_use]
pub fn can_match_git_entry_powershell(pattern: &str) -> bool {
    let names = GIT_ENTRIES.iter().chain(&GIT_FILES).chain(&GIT_FOLDERS);
    can_match_cmd(
        pattern,
        names.chain(&GIT_SHORT_NAMES),
        &hex_shapes(true),
        false,
    )
}

/// One position of a name's shape: the characters it can be.
type Slot = Vec<char>;

/// A name's shape: what each of its positions can be.
type NameShape = Vec<Slot>;

/// The shape of a name that is `head`, then `hex` positions that can each be
/// a hex digit, then `tail`.
fn shape_of(head: &str, hex: usize, tail: &[Slot]) -> NameShape {
    let mut slots: NameShape = head.chars().map(|c| vec![c]).collect();
    slots.extend((0..hex).map(|_| HEX.chars().collect::<Slot>()));
    slots.extend(tail.iter().cloned());
    slots
}

/// The shapes of the names git gives objects: a loose object's folder and
/// file, and a pack with its index. With `short`, the 8.3 short names of the
/// long ones as well (six hex digits and `~n`, `PACK-` and a digit, `~n`, and
/// the three-letter extension).
fn hex_shapes(short: bool) -> Vec<NameShape> {
    let literal = |text: &str| -> Vec<Slot> { text.chars().map(|c| vec![c]).collect() };
    let mut shapes = vec![
        shape_of("", 2, &[]),
        shape_of("", 38, &[]),
        shape_of("pack-", 40, &literal(".pack")),
        shape_of("pack-", 40, &literal(".idx")),
    ];
    if short {
        let tilde_n: Vec<Slot> = vec![vec!['~'], TAIL_DIGITS.chars().collect()];
        shapes.push(shape_of("", 6, &tilde_n));
        for extension in [".pac", ".idx"] {
            let mut tail = tilde_n.clone();
            tail.extend(literal(extension));
            shapes.push(shape_of("pack-", 1, &tail));
        }
    }
    shapes
}

/// Whether the (non-cmd) pattern can match a name of one of `shapes`. As in
/// [`matches()`], a pattern on POSIX may be read by bash or by zsh (`[.x.]`
/// and `[=x=]` differ), and can match when either reading does.
fn can_match_shape(pattern: &str, flavour: Flavour, shapes: &[NameShape]) -> bool {
    let fold = flavour == Flavour::Windows;
    let readings: &[bool] = if fold { &[false] } else { &[false, true] };
    readings.iter().any(|&zsh| {
        let tokens = tokens(pattern, flavour, zsh);
        let optional = vec![false; tokens.len()];
        shapes.iter().any(|shape| {
            matches_by(&tokens, &optional, shape.len(), &|at, token| {
                shape[at].iter().any(|c| token.takes(*c, fold))
            })
        })
    })
}

/// The name of the repository's folder.
const GIT_FOLDER_NAME: &str = ".git";

/// The 8.3 short name of the `.git` folder itself on a drive that creates
/// them.
const GIT_FOLDER_SHORT_NAME: &str = "GIT~1";

/// Whether the name pattern `pattern` can match `GIT~1`, the 8.3 short name
/// of the `.git` folder, read as cmd reads a wildcard (see
/// [`can_match_git_entry`]).
///
/// It is for a search that hands its pattern to the file system's own
/// matching, as Windows PowerShell's `-Filter` does through `FindFirstFile`,
/// which compares a pattern with the short name as well as the long one: `g*`,
/// `*~1`, `GIT~?` and `?????` find `.git` there, though none matches the name
/// `.git`.
#[must_use]
pub fn can_match_git_short_name(pattern: &str) -> bool {
    can_match_cmd(pattern, [GIT_FOLDER_SHORT_NAME].iter(), &[], true)
}

/// Whether the name pattern `pattern`, handed to the file system's own
/// matching (a `-Filter`), can match the `.git` folder: by its long name or
/// its short one, read as cmd reads a wildcard (see [`can_match_git_entry`]),
/// so `.gi<`, `<` and `.git"` find it.
#[must_use]
pub fn can_match_git_folder(pattern: &str) -> bool {
    can_match_cmd(
        pattern,
        [GIT_FOLDER_NAME, GIT_FOLDER_SHORT_NAME].iter(),
        &[],
        true,
    )
}

/// Whether the cmd pattern `pattern` (or, without its trailing dots and
/// spaces, which are not part of a name) can match one of `names`; `dos`
/// reads cmd's own `<`, `>` and `"` as wildcards.
fn can_match_cmd<'a>(
    pattern: &str,
    names: impl Iterator<Item = &'a &'a str> + Clone,
    shapes: &[NameShape],
    dos: bool,
) -> bool {
    let trimmed = pattern.trim_end_matches(['.', ' ']);
    [pattern, trimmed].iter().any(|pattern| {
        if pattern.is_empty() {
            return false;
        }
        let (tokens, optional) = cmd_tokens(pattern, dos);
        names
            .clone()
            .any(|name| matches_cmd(&tokens, &optional, name))
            || shapes.iter().any(|shape| {
                matches_by(&tokens, &optional, shape.len(), &|at, token| {
                    shape[at].iter().any(|c| token.takes(*c, true))
                })
            })
    })
}

/// The tokens of a cmd pattern and which of them can match nothing: a `?` in
/// a run at the end or just before a `.`, a `.` followed by `*` or `?`
/// (cmd's DOS dot, which can match nothing at the end of a name; any such dot
/// is taken to, to err to Risky), and cmd's own `>` and `"` anywhere.
fn cmd_tokens(pattern: &str, dos: bool) -> (Vec<Token>, Vec<bool>) {
    let tokens = tokens_in(pattern, Flavour::Windows, false, dos);
    let mut optional: Vec<bool> = tokens
        .iter()
        .map(|token| matches!(token, Token::DosAny | Token::DosDot))
        .collect();
    let wild = |token: &Token| matches!(token, Token::Star | Token::Any | Token::DosAny);
    // The tail of wildcards at the end, and the dot before it.
    let tail = tokens
        .iter()
        .rposition(|token| !wild(token))
        .map_or(0, |at| at + 1);
    optional[tail..].fill(true);
    if tail > 0 && tokens[tail - 1] == Token::Literal('.') {
        optional[tail - 1] = true;
    }
    for (at, token) in tokens.iter().enumerate() {
        if *token == Token::Literal('.') {
            if matches!(tokens.get(at + 1), Some(Token::Star | Token::Any)) {
                optional[at] = true;
            }
            let run = tokens[..at]
                .iter()
                .rev()
                .take_while(|token| matches!(token, Token::Any | Token::DosAny))
                .count();
            optional[at - run..at].fill(true);
        }
    }
    (tokens, optional)
}

/// Whether the cmd pattern given as `tokens` (see [`cmd_tokens`]) matches
/// `name`, with no case and with the leading dot open to wildcards.
fn matches_cmd(tokens: &[Token], optional: &[bool], name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    matches_by(tokens, optional, name.len(), &|at, token| {
        token.takes(name[at], true)
    })
}

/// Whether `tokens` can match a name of `len` characters, where
/// `takes(at, token)` says whether the token (not a `*`) takes the character
/// at position `at`. A token marked in `optional` can also match nothing. The
/// name is read position by position, so a position that can be any of
/// several characters is asked once.
fn matches_by(
    tokens: &[Token],
    optional: &[bool],
    len: usize,
    takes: &dyn Fn(usize, &Token) -> bool,
) -> bool {
    // The token positions the name read so far can stand at, after skipping
    // every token that can match nothing.
    let settle = |states: &mut Vec<bool>| {
        for at in 0..tokens.len() {
            if states[at] && (tokens[at] == Token::Star || optional[at]) {
                states[at + 1] = true;
            }
        }
    };
    let mut states = vec![false; tokens.len() + 1];
    states[0] = true;
    settle(&mut states);
    for position in 0..len {
        let mut next = vec![false; tokens.len() + 1];
        for at in 0..tokens.len() {
            if !states[at] {
                continue;
            }
            if tokens[at] == Token::Star {
                next[at] = true;
            } else if takes(position, &tokens[at]) {
                next[at + 1] = true;
            }
        }
        settle(&mut next);
        states = next;
    }
    states[tokens.len()]
}

/// Whether the pattern part `pattern` matches the file name `name`.
///
/// `*` is any run of characters, `?` is one character, and `[...]` is one
/// character of a class (`a-z` is a range; a `]` first in the class is
/// itself). A `[` with no `]` after it is just a `[`. A part never holds a
/// separator, so neither does a name.
///
/// `flavour` says how the pattern is read and how names compare:
/// - `Posix`: `[!x]` and `[^x]` are any other character, and names compare
///   with case.
/// - `Windows`: PowerShell has no negation, so `!` and `^` are members of the
///   class; a backtick makes the next character itself (`` `* `` is a star);
///   names compare without case, by the Unicode lower and upper case of each
///   character, so that `ı` and `İ` count as an `i`.
///
/// `hidden` says whether a wildcard can match a name's leading dot, as
/// PowerShell and cmd wildcards do. When it is `false`, the POSIX rule holds:
/// a name that starts with `.` is matched only by a pattern that starts with
/// a literal `.`.
#[must_use]
pub fn matches(pattern: &str, name: &str, flavour: Flavour, hidden: bool) -> bool {
    let fold = flavour == Flavour::Windows;
    // `[.x.]` and `[=x=]` are elements in bash and plain members in zsh, and
    // a pattern on POSIX may be read by either: it matches when either
    // reading of it does.
    let name: Vec<char> = name.chars().collect();
    let readings: &[bool] = if fold { &[false] } else { &[false, true] };
    readings.iter().any(|&zsh| {
        let tokens = tokens(pattern, flavour, zsh);
        matches_tokens(&tokens, &name, fold, hidden)
    })
}

/// Whether the `tokens` of a pattern match the file name `name`.
fn matches_tokens(tokens: &[Token], name: &[char], fold: bool, hidden: bool) -> bool {
    if !hidden && name.first() == Some(&'.') && tokens.first() != Some(&Token::Literal('.')) {
        return false;
    }
    let (mut at, mut on) = (0, 0);
    // Where the last `*` was and the name position it has taken up to.
    let mut star: Option<(usize, usize)> = None;
    while on < name.len() {
        match tokens.get(at) {
            Some(Token::Star) => {
                star = Some((at, on));
                at += 1;
            }
            Some(token) if token.takes(name[on], fold) => {
                at += 1;
                on += 1;
            }
            _ => match star {
                Some((from, taken)) => {
                    star = Some((from, taken + 1));
                    at = from + 1;
                    on = taken + 1;
                }
                None => return false,
            },
        }
    }
    tokens[at..].iter().all(|token| *token == Token::Star)
}

/// Whether the pattern, whose first part is directly inside a repository's
/// folder, can reach `.git`'s own entries: `parts` are the pattern's parts
/// from its first wildcard part on, to the end of the path. That part must
/// match `.git`. If it is the last part it takes `.git` itself, unless it is
/// a catch-all as written (the whole folder is judged then). Otherwise the next part
/// must match one of `.git`'s own entries (`*\objects` does, `*\bin` does
/// not). A pattern that still holds a `..` is taken to reach it.
///
/// On `Windows` each part is also read as Windows names it: the last part
/// loses every trailing dot and space and a part before it one trailing dot,
/// so `*git.` and `'*git '` are `*git`; the pattern as written is tried too.
/// A part also reaches `.git` when it can match its 8.3 short name, which
/// drops the dot: `GIT~N`, or `GI`, four hex digits and `~N` (`GIT~?`, `*~1`);
/// but only for a pattern that holds a literal `~`, so `*2024*`, `git*`
/// and `*1` are not short names (PowerShell matches none, and `cmd` skips a
/// folder a wildcard matches). A part that only trimming makes a catch-all (`*.` is `*`) is
/// not the whole folder, which the caller judges for a catch-all as written:
/// it matches `.git`, so it reaches it.
///
/// On POSIX a first part of `**` or `***` also stands for no folder, so the
/// parts after it are tried as the pattern's own.
///
/// `hidden` is the same as for [`matches()`].
#[must_use]
pub fn reaches_git(parts: &[&str], flavour: Flavour, hidden: bool) -> bool {
    let windows = flavour == Flavour::Windows;
    // The part as written, and as Windows names it.
    let read = |at: usize| {
        let part = parts[at];
        let named = if windows {
            windows_name(part, at + 1 == parts.len())
        } else {
            part
        };
        [part, named]
    };
    // `short` is set for the first part only: it is read against `.git`
    // itself, so its short name counts. The part after is read against
    // `.git`'s own entries, which have no short name here.
    let reaches = |at: usize, names: &[&str], short: bool| {
        let [written, named] = read(at);
        // The trimmed form only when trimming changed something.
        let forms = [Some(written), (named != written).then_some(named)];
        forms.iter().flatten().any(|pattern| {
            names
                .iter()
                .any(|name| matches(pattern, name, flavour, hidden))
                || (short && windows && matches_short_git(pattern, flavour))
        })
    };
    // On POSIX `**/` and `***/` (bash with `globstar`, zsh) match no folder
    // at all too, so what follows is read against the folder itself:
    // `**/*git` reaches `.git` where `*git` does.
    if !windows
        && parts.len() > 1
        && matches!(parts[0], "**" | "***")
        && reaches_git(&parts[1..], flavour, hidden)
    {
        return true;
    }
    if parts.is_empty() || !reaches(0, &PROTECTED, true) {
        return false;
    }
    match parts.get(1) {
        // A catch-all as written is the whole folder, judged by its caller;
        // one that only trimming makes (`*.` is `*`) is not, since the
        // resolver read the pattern as written.
        None => !catch_all(read(0)[0], flavour),
        Some(&"..") => true,
        Some(_) => reaches(1, &GIT_ENTRIES, false),
    }
}

/// The characters a short name of `.git` is made of, in the order of the
/// bits of a [`Takes`]: `g`, `i`, `t`, `~`, `0` to `9`, `a` to `f`.
const SHORT_CHARS: [char; 20] = [
    'g', 'i', 't', '~', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
    'f',
];

/// Which of [`SHORT_CHARS`] a set holds, one bit each.
type Takes = u32;

/// The bits of the characters of [`SHORT_CHARS`] that `holds` accepts, asked
/// only of those whose bit is in `of`.
fn bits(of: Takes, holds: impl Fn(char) -> bool) -> Takes {
    SHORT_CHARS
        .iter()
        .enumerate()
        .filter(|(at, c)| of & (1 << at) != 0 && holds(**c))
        .fold(0, |all, (at, _)| all | 1 << at)
}

/// Whether the pattern `part` can match the 8.3 short name of `.git`: `git`,
/// then `~` and a number; or, once names collide, `gi` and four hex digits,
/// then `~` and a number. A name compares without case, as on Windows.
///
/// Only a pattern that writes the `~` can match one: it takes a number of
/// any length and may match the hashed form. One that does not (`*2024*`,
/// `*cafe*`, `GI*`, `git*`, `*1`) is an ordinary pattern. A hashed name
/// exists only once `GIT~1` to `GIT~4` are taken and every `*a*` would match
/// it; and `git*` or `*1` matching `GIT~1` is no reason to judge the line
/// risky, since PowerShell does not match short names and `cmd` skips a
/// folder a wildcard matches.
fn matches_short_git(part: &str, flavour: Flavour) -> bool {
    let tokens = tokens(part, flavour, false);
    if !tokens.contains(&Token::Literal('~')) {
        return false;
    }
    // What each token takes of the characters asked about so far: those
    // asked about, and which of them it takes. Each is worked out once and
    // not again for each state (a class can hold many members).
    let mut takes: Vec<(Takes, Takes)> = vec![(0, 0); tokens.len()];
    let one = |wanted: char| bits(!0, |c| c == wanted);
    let hex = bits(!0, |c| c.is_ascii_hexdigit());
    let digits = bits(!0, |c| c.is_ascii_digit());
    let plain = vec![one('g'), one('i'), one('t'), one('~')];
    let hashed = vec![one('g'), one('i'), hex, hex, hex, hex, one('~')];
    // Each form; the number after it has any length.
    let forms = [plain, hashed];
    forms.iter().any(|form| {
        // A state is a token and how much of the name is taken: a place in
        // `form`, then `form.len()` (no digit yet) and one past it (a digit
        // or more, where the name may end).
        let last = form.len() + 1;
        let mut seen = vec![vec![false; last + 1]; tokens.len() + 1];
        let mut todo = vec![(0, 0)];
        seen[0][0] = true;
        while let Some((at, taken)) = todo.pop() {
            if taken == last && tokens[at..].iter().all(|token| *token == Token::Star) {
                return true;
            }
            let Some(token) = tokens.get(at) else {
                continue;
            };
            let allowed = form.get(taken).copied().unwrap_or(digits);
            let next = (taken + 1).min(last);
            let mut go = |at: usize, taken: usize| {
                if !seen[at][taken] {
                    seen[at][taken] = true;
                    todo.push((at, taken));
                }
            };
            if *token == Token::Star {
                go(at + 1, taken);
                go(at, next);
            } else {
                let (asked, taken_by) = &mut takes[at];
                let new = allowed & !*asked;
                *asked |= new;
                *taken_by |= bits(new, |c| token.takes(c, true));
                if *taken_by & allowed != 0 {
                    go(at + 1, next);
                }
            }
        }
        false
    })
}

/// One step of a pattern part.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Star,
    Any,
    /// cmd's `>`: any one character, or nothing.
    DosAny,
    /// cmd's `"`: a dot, or nothing.
    DosDot,
    Literal(char),
    Class {
        negated: bool,
        /// Inclusive ranges; a single character is a range of one.
        ranges: Vec<(char, char)>,
        /// POSIX classes written as `[:alpha:]` inside the brackets.
        named: Vec<Named>,
    },
}

/// A POSIX character class, `[:alpha:]` inside a bracket expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Named {
    Alpha,
    Digit,
    Alnum,
    Upper,
    Lower,
    Punct,
    Space,
    Blank,
    Cntrl,
    Print,
    Graph,
    Xdigit,
}

impl Named {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "alpha" => Self::Alpha,
            "digit" => Self::Digit,
            "alnum" => Self::Alnum,
            "upper" => Self::Upper,
            "lower" => Self::Lower,
            "punct" => Self::Punct,
            "space" => Self::Space,
            "blank" => Self::Blank,
            "cntrl" => Self::Cntrl,
            "print" => Self::Print,
            "graph" => Self::Graph,
            "xdigit" => Self::Xdigit,
            _ => return None,
        })
    }

    /// Whether `c` is in the class. A character outside ASCII is read by
    /// what Unicode says, which a locale may read more widely: names in a
    /// protected folder are ASCII, so that is the side that matters.
    fn holds(self, c: char) -> bool {
        match self {
            Self::Alpha => c.is_alphabetic(),
            Self::Digit => c.is_ascii_digit(),
            Self::Alnum => c.is_alphanumeric(),
            Self::Upper => c.is_uppercase(),
            Self::Lower => c.is_lowercase(),
            Self::Punct => {
                if c.is_ascii() {
                    c.is_ascii_punctuation()
                } else {
                    !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control()
                }
            }
            Self::Space => c.is_whitespace(),
            Self::Blank => matches!(c, ' ' | '\t'),
            Self::Cntrl => c.is_control(),
            Self::Print => !c.is_control(),
            Self::Graph => !c.is_control() && !c.is_whitespace(),
            Self::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

/// `c` in the cases a Windows name compares by: its first lower and upper
/// case character.
fn cases(c: char) -> (char, char) {
    (
        c.to_lowercase().next().unwrap_or(c),
        c.to_uppercase().next().unwrap_or(c),
    )
}

impl Token {
    /// Whether the token (not a `*`) takes the one character `c`.
    fn takes(&self, c: char, fold: bool) -> bool {
        // The cases of `c`, worked out once and not for each member.
        let (lower, upper) = cases(c);
        let same = |a: char| {
            a == c
                || (fold && {
                    let (a_lower, a_upper) = cases(a);
                    a_lower == lower || a_upper == upper
                })
        };
        match self {
            Self::Star => false,
            Self::Any | Self::DosAny => true,
            Self::DosDot => c == '.',
            Self::Literal(literal) => same(*literal),
            Self::Class {
                negated,
                ranges,
                named,
            } => {
                let within = |c: char, low: char, high: char| low <= c && c <= high;
                let inside = ranges.iter().any(|&(low, high)| {
                    within(c, low, high)
                        || (fold
                            && (within(lower, low, high)
                                || within(upper, low, high)
                                // A lone member compares like a literal.
                                || (low == high && same(low))))
                }) || named.iter().any(|class| class.holds(c));
                inside != *negated
            }
        }
    }
}

/// The tokens of `pattern`. `zsh` says a POSIX bracket is read as zsh reads
/// it, where `[.` and `[=` are plain members; otherwise as bash reads it.
fn tokens(pattern: &str, flavour: Flavour, zsh: bool) -> Vec<Token> {
    tokens_in(pattern, flavour, zsh, false)
}

/// The tokens of `pattern`, read as [`tokens`] does; with `dos`, also cmd's
/// own wildcards, which the file system's matching reads and PowerShell's own
/// does not: `<` is a `*` (that stops at the last dot, taken here as a `*`),
/// `>` is a `?` that can match nothing, and `"` is a `.` that can match
/// nothing.
fn tokens_in(pattern: &str, flavour: Flavour, zsh: bool, dos: bool) -> Vec<Token> {
    let windows = flavour == Flavour::Windows;
    let chars: Vec<char> = pattern.chars().collect();
    // A `[` after the last `]` has nothing to close it: it is a plain `[`.
    // Finding that once keeps a long run of `[` linear.
    let last_close = chars.iter().rposition(|c| *c == ']');
    // A bracket whose only `]`s sit inside `[:a:]`-style elements has a last
    // close and still no end. The places a failed scan stepped on are marked
    // here, so the next `[` stops at the first one: from there it can only
    // fail the same way, and no place is stepped on twice.
    let mut dead = vec![false; chars.len()];
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        match c {
            '`' if windows && at < chars.len() => {
                out.push(Token::Literal(chars[at]));
                at += 1;
            }
            _ if c == '*' || (dos && c == '<') => {
                // `**` is `*`.
                if out.last() != Some(&Token::Star) {
                    out.push(Token::Star);
                }
            }
            '?' => out.push(Token::Any),
            '>' if dos => out.push(Token::DosAny),
            '"' if dos => out.push(Token::DosDot),
            '[' if last_close.is_some_and(|close| at <= close) => {
                match class(&chars[at..], windows, zsh, &mut dead[at..]) {
                    Some((token, used)) => {
                        out.push(token);
                        at += used;
                    }
                    None => out.push(Token::Literal('[')),
                }
            }
            _ => out.push(Token::Literal(c)),
        }
    }
    out
}

/// The class that starts just after a `[`, and how many characters it takes
/// up to its `]`; `None` when no `]` closes it. On Windows `!` and `^` first
/// in it are members, and a backtick makes the next character a member.
///
/// On POSIX `[:alpha:]` inside the brackets is a class of its own, and
/// `[=a=]` and `[.a.]` are an equivalence class and a collating symbol. The
/// first is read; the others, an unknown class name, and a range that starts
/// or ends on one are not read exactly, so the bracket takes any character.
/// zsh has no `[=a=]` or `[.a.]`: with `zsh` set they are not elements, `[`
/// and `.` or `=` are plain members, and the first `]` closes the bracket.
///
/// `dead` is as long as `chars`. A place past the first that a scan stepped
/// on is marked in it: what follows such a place does not depend on where the
/// scan began, so a scan that comes to a marked place is one that failed, and
/// fails at once. A scan that closes leaves marks only before the next
/// bracket starts. This keeps a run of brackets that never close linear.
fn class(chars: &[char], windows: bool, zsh: bool, dead: &mut [bool]) -> Option<(Token, usize)> {
    let negated = !windows && matches!(chars.first(), Some('!' | '^'));
    let mut at = usize::from(negated);
    let mut ranges = Vec::new();
    let mut named = Vec::new();
    let mut any = false;
    let mut first = true;
    loop {
        let here = at;
        // The first step reads a `]` as a member, so it is not the same step
        // for a scan that began elsewhere: only the later ones are marked.
        if !first {
            if *dead.get(here)? {
                return None;
            }
            dead[here] = true;
        }
        let mut low = *chars.get(at)?;
        at += 1;
        if low == ']' && !first {
            let token = if any {
                Token::Any
            } else {
                Token::Class {
                    negated,
                    ranges,
                    named,
                }
            };
            return Some((token, at));
        }
        if windows && low == '`' {
            low = *chars.get(at)?;
            at += 1;
        }
        first = false;
        if !windows {
            if let Some((kind, inner, end)) = element(chars, here, zsh) {
                let name: String = inner.iter().collect();
                match (kind, Named::from_name(&name)) {
                    (':', Some(class)) => named.push(class),
                    _ => any = true,
                }
                at = end;
                // A range that starts on it is not read.
                if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|c| *c != ']') {
                    any = true;
                }
                continue;
            }
        }
        if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|next| *next != ']') {
            // A range that ends on one is not read either.
            if !windows {
                if let Some((_, _, end)) = element(chars, at + 1, zsh) {
                    any = true;
                    at = end;
                    continue;
                }
            }
            ranges.push((low, chars[at + 1]));
            at += 2;
        } else {
            ranges.push((low, low));
        }
    }
}

/// The POSIX bracket element that starts at `at`, if one does: `[:alpha:]`,
/// `[=a=]` or `[.a.]`. Its kind (`:`, `=` or `.`), what it holds, and where
/// it ends, just after its `]`. What it holds has no bracket in it, so `[:[:]`
/// is no element and its `]` stays the class's own. With `zsh` only `[:a:]`
/// is one.
fn element(chars: &[char], at: usize, zsh: bool) -> Option<(char, &[char], usize)> {
    if chars.get(at) != Some(&'[') {
        return None;
    }
    let kind = *chars
        .get(at + 1)
        .filter(|c| **c == ':' || (!zsh && matches!(c, '=' | '.')))?;
    let start = at + 2;
    // A name is short; looking only that far keeps a long run of `[:` linear.
    let limit = (start + 16).min(chars.len().saturating_sub(1));
    let close = (start..limit).find(|&j| chars[j] == kind && chars[j + 1] == ']')?;
    let inner = &chars[start..close];
    (!inner.iter().any(|c| matches!(c, '[' | ']'))).then_some((kind, inner, close + 2))
}

/// What a wildcard pattern matches inside the folder before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Shape {
    /// A part starting with `.` (`.g*`, `*/.git`): hidden entries, `.git`
    /// among them.
    Hidden,
    /// Its last part is a catch-all (`*`, `*/*`, `?*`): every entry.
    All,
    /// Its last part picks some names (`*.log`, `*/*.o`).
    Entries,
}

/// The shape of `text`, read from its first wildcard part to its end.
#[must_use]
pub fn shape(text: &str, flavour: Flavour) -> Shape {
    let parts: Vec<&str> = text
        .split(flavour.separators())
        .skip_while(|part| !has_wildcard(part))
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts
        .iter()
        .any(|part| part.starts_with('.') && *part != "..")
    {
        Shape::Hidden
    } else if parts.last().is_some_and(|last| catch_all(last, flavour)) {
        Shape::All
    } else {
        Shape::Entries
    }
}

/// Whether a wildcard pattern matches every entry of its folder (`*`, `**`,
/// `?*`, `[!.]*`): once its wildcards and classes are removed, nothing is
/// left to match against. On Windows `*.*` is one too: it means every entry,
/// with or without an extension.
fn catch_all(part: &str, flavour: Flavour) -> bool {
    if flavour == Flavour::Windows && part == "*.*" {
        return true;
    }
    if !part.contains('*') {
        return false;
    }
    let mut literal = String::new();
    let mut rest = part;
    while let Some(open) = rest.find('[') {
        literal.push_str(&rest[..open]);
        let Some(close) = rest[open..].find(']') else {
            rest = "";
            break;
        };
        rest = &rest[open + close + 1..];
    }
    literal.push_str(rest);
    literal.chars().all(|c| matches!(c, '*' | '?'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_wildcards_are_read_by_the_file_system_only() {
        let windows = Flavour::Windows;
        for pattern in [
            "HEA<", "<", "a<", "o<", "HEA>", "HEAD>>", "HEAD\"", "stash\"", "sta>>",
        ] {
            assert!(can_match_git_entry(pattern, windows), "{pattern}");
            assert!(!can_match_git_entry_powershell(pattern), "{pattern}");
        }
        for pattern in [".gi<", "<", ".git>", ".gi>>", ".git\"", ".g>it", "<.git"] {
            assert!(can_match_git_folder(pattern), "{pattern}");
        }
        for pattern in ["x<", ".gx>", "node_modules\"", "*.t>", ">"] {
            assert!(!can_match_git_folder(pattern), "{pattern}");
        }
        for pattern in ["*.t>", "x<.tmp", "node_modules\"", "b>>n"] {
            assert!(!can_match_git_entry(pattern, windows), "{pattern}");
        }
        assert!(can_match_git_entry("stash", windows));
        assert!(can_match_git_entry("*stash*", Flavour::Posix));
        assert!(can_match_git_entry_powershell("stash"));
    }

    #[test]
    fn a_name_search_can_find_the_files_of_git() {
        let windows = Flavour::Windows;
        for pattern in [
            "HEAD",
            "head",
            "config",
            "index",
            "*",
            "*.*",
            "*.",
            "H*",
            "?????",
            "pack-*",
            "*.pack",
            "*.idx",
            "com*",
            "HEAD.",
            "ma?n",
            "[a-z]ndex",
            "main.*",
            "HEAD.*",
            "HEAD.*.*",
            "*.?.?",
            "*.*.*.*",
            "HEAD?",
            "main.?",
            "????????",
            "ma?n?.*",
            "*.pac",
            "COMMIT~1",
            "PACK-0~1.IDX",
            "pack",
            "Heads",
            "tags",
            "remotes",
            "ORIGIN",
            "pac?",
            "??",
            "???",
            "pack?",
            "1*",
            "*7*",
            "[a-f]?",
            "?a",
            "*ff",
            "0*",
            "pack-1*",
            "pack-*.idx",
            "*.pack",
            "pack-?*.pack",
            "??????~1",
            "AB*~1",
            "PACK-A~1.PAC",
            "*~1.IDX",
        ] {
            assert!(can_match_git_entry(pattern, windows), "{pattern}");
        }
        for pattern in [
            "",
            ".",
            "..",
            "*.obj",
            "*.tmp",
            "*.log",
            "*.exe",
            "Thumbs.db",
            "a.txt",
            "x*y",
            "*.sample",
            "main.obj",
            "*.orig",
            "foo.*",
            "foo?.*",
            "HEAD?.x",
            "mainx.*",
            "bin",
            "obj",
            "Debug",
            "node_modules",
            "target",
            "?x",
            "[g-z]?",
            "x*",
            "*.d",
            "*.o",
            "pack-x*",
            "*.packx",
        ] {
            assert!(!can_match_git_entry(pattern, windows), "{pattern}");
        }
        assert!(can_match_git_entry("HEAD", Flavour::Posix));
        assert!(!can_match_git_entry("head", Flavour::Posix));
        assert!(!can_match_git_entry("HEAD.", Flavour::Posix));
        assert!(!can_match_git_entry("main.*", Flavour::Posix));
        assert!(!can_match_git_entry("*.pac", Flavour::Posix));
        // An object's name is lower case on a case-sensitive file system.
        assert!(can_match_git_entry("1*", Flavour::Posix));
        assert!(can_match_git_entry("??", Flavour::Posix));
        assert!(!can_match_git_entry("A?", Flavour::Posix));
        assert!(!can_match_git_entry("??????~1", Flavour::Posix));
    }

    #[test]
    fn a_pattern_takes_the_shape_of_its_last_part() {
        let posix = Flavour::Posix;
        assert_eq!(shape("*", posix), Shape::All);
        assert_eq!(shape("src/*/*", posix), Shape::All);
        assert_eq!(shape("?*", posix), Shape::All);
        assert_eq!(shape("[!.]*", posix), Shape::All);
        assert_eq!(shape("*.log", posix), Shape::Entries);
        assert_eq!(shape("src/*/*.o", posix), Shape::Entries);
        assert_eq!(shape(".g*", posix), Shape::Hidden);
        assert_eq!(shape("*/.git", posix), Shape::Hidden);
        assert_eq!(shape("a/*/../b", posix), Shape::Entries);
    }

    #[test]
    fn windows_patterns_split_at_both_separators() {
        assert_eq!(shape(r"src\*\.git", Flavour::Windows), Shape::Hidden);
        assert_eq!(shape(r"src\*\.git", Flavour::Posix), Shape::Entries);
        assert_eq!(shape(r"build\*", Flavour::Windows), Shape::All);
    }

    #[test]
    fn an_unclosed_class_swallows_the_rest_and_is_a_catch_all() {
        assert_eq!(shape("[*", Flavour::Posix), Shape::All);
    }

    #[test]
    fn a_windows_wildcard_matches_a_leading_dot() {
        let windows = Flavour::Windows;
        for pattern in [
            "*git", "?git", "*", ".*", "*.git", "*.*", ".g*", "????", "[.]git", "[!.]git",
            "[^.]git", "*[a-z]t",
        ] {
            assert!(matches(pattern, ".git", windows, true), "{pattern}");
        }
        for pattern in [
            "*.tmp", "?git2", "*x", "git", "???", "[a-z]git", "[!x]git", "*gi", "t*",
        ] {
            assert!(!matches(pattern, ".git", windows, true), "{pattern}");
        }
    }

    #[test]
    fn a_windows_class_has_no_negation_and_a_backtick_escapes() {
        let windows = Flavour::Windows;
        // `!` and `^` are members of the class, as in PowerShell.
        assert!(matches("[!.]git", ".git", windows, true));
        assert!(matches("[^.]git", ".git", windows, true));
        assert!(matches("[!x]git", "!git", windows, true));
        assert!(!matches("[!x]git", "ygit", windows, true));
        assert!(matches("[a-]", "-", windows, true));
        // A backtick makes the next character itself.
        assert!(matches("`.gi?", ".git", windows, true));
        assert!(matches("`*git", "*git", windows, true));
        assert!(!matches("`*git", ".git", windows, true));
        assert!(matches("[`]]x", "]x", windows, true));
        assert!(matches("a`", "a`", windows, true));
        // POSIX keeps both as they are.
        assert!(matches("`a", "`a", Flavour::Posix, false));
        assert!(!matches("[!.]git", ".git", Flavour::Posix, true));
        assert!(matches("[!.]git", "xgit", Flavour::Posix, true));
    }

    #[test]
    fn a_windows_wildcard_compares_without_case() {
        let windows = Flavour::Windows;
        assert!(matches("*GIT", ".git", windows, true));
        assert!(matches(".G?T", ".git", windows, true));
        assert!(matches("[A-Z]git", "xgit", windows, true));
        assert!(matches("[a-z]GIT", "Xgit", windows, true));
        assert!(!matches("[A-Z]git", "!git", windows, true));
        assert!(!matches("*GIT", ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_windows_name_compares_by_unicode_case() {
        let windows = Flavour::Windows;
        // A dotless `ı` and a dotted `İ` count as an `i`, to be safe.
        assert!(matches("*g\u{131}t", ".git", windows, true));
        assert!(matches("*G\u{130}T", ".git", windows, true));
        assert!(matches(".G\u{130}T", ".git", windows, true));
        assert!(matches("*\u{212a}", "k", windows, true));
        assert!(!matches("*g\u{131}t", ".git", Flavour::Posix, true));
        assert!(!matches("*g\u{e9}t", ".git", windows, true));
        // A class member folds too.
        assert!(matches("*g[\u{131}]t", ".git", windows, true));
        assert!(matches("*g[x\u{130}]t", ".git", windows, true));
        assert!(!matches("*g[x\u{e9}]t", ".git", windows, true));
        assert!(!matches("*g[\u{131}]t", ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_posix_wildcard_skips_a_leading_dot_unless_the_pattern_has_one() {
        let posix = Flavour::Posix;
        for pattern in ["*git", "?git", "*", "*.*", "????", "[.]git", "[!x]git"] {
            assert!(!matches(pattern, ".git", posix, false), "{pattern}");
        }
        for pattern in [".git", ".g*", ".*", ".???", ".[a-z]it"] {
            assert!(matches(pattern, ".git", posix, false), "{pattern}");
        }
        assert!(matches("*git", "xgit", posix, false));
        assert!(matches("*", "x.git", posix, false));
    }

    #[test]
    fn the_hidden_flag_is_the_only_difference_for_dot_names() {
        // What `dotglob` will switch on for a POSIX shell.
        assert!(matches("*git", ".git", Flavour::Posix, true));
        assert!(!matches("*git", ".git", Flavour::Posix, false));
        assert!(!matches("*GIT", ".git", Flavour::Posix, true));
    }

    #[test]
    fn classes_ranges_and_negation() {
        let posix = Flavour::Posix;
        assert!(matches("[abc]x", "bx", posix, false));
        assert!(!matches("[abc]x", "dx", posix, false));
        assert!(matches("[a-c]x", "bx", posix, false));
        assert!(matches("[!a-c]x", "dx", posix, false));
        assert!(matches("[^a-c]x", "dx", posix, false));
        assert!(!matches("[!a-c]x", "bx", posix, false));
        // A `]` first in a class is a member; a trailing `-` is a dash.
        assert!(matches("[]a]x", "]x", posix, false));
        assert!(matches("[a-]x", "-x", posix, false));
        // A `[` with no `]` after it is a plain character.
        assert!(matches("[a", "[a", posix, false));
        assert!(matches("a[", "a[", posix, false));
        assert!(!matches("[a", "a", posix, false));
        assert!(matches("[!", "[!", posix, false));
    }

    #[test]
    fn posix_classes_inside_a_bracket() {
        let posix = Flavour::Posix;
        assert!(matches("[[:alpha:]]x", "bx", posix, false));
        assert!(!matches("[[:alpha:]]x", "1x", posix, false));
        assert!(matches("[[:digit:]]x", "1x", posix, false));
        assert!(matches("[[:punct:]]git", ".git", posix, true));
        assert!(!matches("[[:punct:]]git", ".git", posix, false));
        assert!(matches("[.[:alpha:]]git", ".git", posix, true));
        assert!(matches("*[[:alpha:]]it", ".git", posix, true));
        assert!(matches("?[[:alpha:]]it", ".git", posix, true));
        assert!(matches("[[:punct:][:alpha:]]x", "_x", posix, false));
        assert!(matches("[[:blank:]]x", "\tx", posix, false));
        assert!(matches("[[:xdigit:]]x", "fx", posix, false));
        assert!(!matches("[[:xdigit:]]x", "gx", posix, false));
        // Negated, and with a range or a literal beside the class.
        assert!(matches("[![:alpha:]]x", "1x", posix, false));
        assert!(!matches("[![:alpha:]]x", "bx", posix, false));
        assert!(matches("[^[:digit:]]x", "bx", posix, false));
        assert!(matches("[a-c[:digit:]]x", "5x", posix, false));
        assert!(!matches("[a-c[:digit:]]x", "dx", posix, false));
        // Not read exactly: any character, whether negated or not.
        assert!(matches("[[:nosuch:]]x", "?x", posix, false));
        assert!(matches("[![:nosuch:]]x", "bx", posix, false));
        assert!(matches("[[=a=]]x", "qx", posix, false));
        assert!(matches("[[.ab.]]x", "qx", posix, false));
        assert!(matches("[a-[.z.]]x", "qx", posix, false));
        assert!(matches("[[:alpha:]-z]x", "1x", posix, false));
        // Without the closing `:]` the `[` is a member of the class.
        assert!(matches("[[:alpha]x", ":x", posix, false));
        assert!(matches("[[:alpha]x", "ax", posix, false));
        assert!(!matches("[[:alpha]x", "bx", posix, false));
        // PowerShell reads no such class: the brackets close at the first `]`.
        assert!(!matches("[[:alpha:]]x", "bx", Flavour::Windows, true));
    }

    #[test]
    fn a_bracket_with_a_collating_element_is_read_as_bash_and_as_zsh_do() {
        let posix = Flavour::Posix;
        // zsh has no `[.x.]` or `[=x=]`: `[` and `.` are members and the first
        // `]` closes the bracket. Bash has no `]` left to close the first `[`,
        // so it is a plain `[`. A pattern matches when either reading does.
        for pattern in [
            "[[.x.]*git",
            "[[.x.]git",
            "[a[.x.]git",
            "[[=.=]*git",
            "[[=.=]git",
        ] {
            assert!(matches(pattern, ".git", posix, true), "{pattern}");
            assert!(!matches(pattern, ".git", posix, false), "{pattern}");
        }
        // Neither reading has a member that takes the dot.
        assert!(!matches("[[=x=]git", ".git", posix, true));
        assert!(!matches("[a[.x.]git", "git", posix, true));
        // Bash's reading still holds: the `[` is plain and `[.x]` a class.
        assert!(matches("[[.x.]*git", "[.git", posix, true));
        assert!(matches("[[.x.]*git", "[xgit", posix, true));
        // With a `]` after the element, bash reads an element and a class.
        assert!(matches("[[.x.]]git", "xgit", posix, true));
        assert!(matches("[[=x=]]git", "qgit", posix, true));
        // PowerShell reads it as zsh does, with its one reading.
        assert!(matches("[[.x.]*git", ".git", Flavour::Windows, true));
        assert!(!matches("[[.x.]]git", "xgit", Flavour::Windows, true));
    }

    #[test]
    fn a_shape_is_matched_by_either_reading_of_a_posix_bracket() {
        // zsh reads `[[.a.]` as a class of `[`, `.` and `a`, so `[[.a.]?` can
        // be a loose object's two hex digits (`a0`); bash reads a plain `[`.
        assert!(can_match_git_entry("[[.a.]?", Flavour::Posix));
        // Neither reading takes a name of two hex digits.
        assert!(!can_match_git_entry("[[.x.]?", Flavour::Posix));
    }

    #[test]
    fn a_long_run_of_posix_class_openers_is_read() {
        let pattern = "[:".repeat(40_000);
        let closed = format!("[{pattern}]");
        for flavour in [Flavour::Posix, Flavour::Windows] {
            assert!(!matches(&closed, ".git", flavour, true));
        }
        let equals = format!("[{}]", "[=".repeat(40_000));
        assert!(!matches(&equals, ".git", Flavour::Posix, true));
        let dots = format!("[{}]", "[.".repeat(40_000));
        assert!(!matches(&dots, ".git", Flavour::Posix, true));
        // A bracket whose only `]`s close elements never closes itself, and
        // each `[` after it must not scan to the end again.
        for element in ["[[:a:]", "[[.x.]", "[[=x=]", "[[:alpha:]", "[[::]"] {
            let run = element.repeat(10_000);
            for pattern in [run.clone(), format!("{run}]"), format!("x{run}y")] {
                assert!(!matches(&pattern, ".git", Flavour::Posix, true));
            }
        }
        // The `]` that closes is still found after a run that did not.
        assert!(matches("[[:a:][[:a:]]x", "[x", Flavour::Posix, true));
        assert!(matches("[[:a:][[:a:][[:a:]]x", "[x", Flavour::Posix, true));
        assert!(matches("[[:a:][[:a:]]]x", "?]x", Flavour::Posix, true));
    }

    /// What each `[` of `pattern` that can be closed reads, the way [`tokens`]
    /// asks `class`; `shared` keeps the marks of failed scans from one `[` to
    /// the next, as `tokens` does, and otherwise each scan starts clean.
    fn brackets(
        pattern: &str,
        windows: bool,
        zsh: bool,
        shared: bool,
    ) -> Vec<Option<(Token, usize)>> {
        let chars: Vec<char> = pattern.chars().collect();
        let last_close = chars.iter().rposition(|c| *c == ']');
        let mut dead = vec![false; chars.len()];
        let (mut at, mut out) = (0, Vec::new());
        while at < chars.len() {
            let c = chars[at];
            at += 1;
            match c {
                '`' if windows && at < chars.len() => at += 1,
                '[' if last_close.is_some_and(|close| at <= close) => {
                    let mut clean = vec![false; chars.len()];
                    let marks = if shared { &mut dead } else { &mut clean };
                    let read = class(&chars[at..], windows, zsh, &mut marks[at..]);
                    if let Some((_, used)) = &read {
                        at += used;
                    }
                    out.push(read);
                }
                _ => {}
            }
        }
        out
    }

    #[test]
    fn a_failed_scan_marks_only_what_fails_the_same_way_from_elsewhere() {
        // Every pattern of up to six of the characters that make or break a
        // bracket: each `[` reads the same with the marks of the scans
        // before it as with none.
        let alphabet = ['[', ']', ':', '=', '.', 'a', '-', '!', '`'];
        let mut patterns = vec![String::new()];
        let mut from = 0;
        for _ in 0..6 {
            let to = patterns.len();
            for at in from..to {
                for c in alphabet {
                    let mut longer = patterns[at].clone();
                    longer.push(c);
                    patterns.push(longer);
                }
            }
            from = to;
        }
        for pattern in &patterns {
            for (windows, zsh) in [(false, false), (false, true), (true, false)] {
                assert_eq!(
                    brackets(pattern, windows, zsh, true),
                    brackets(pattern, windows, zsh, false),
                    "{pattern:?} windows: {windows} zsh: {zsh}"
                );
            }
        }
    }

    #[test]
    fn a_bracket_after_a_failed_scan_is_still_read() {
        let posix = Flavour::Posix;
        // The first `[` fails: its only `]` closes an element. It is a plain
        // `[`, and the `[` of the element opens a bracket of its own.
        assert!(matches("[[:a:]", "[a", posix, false));
        assert!(matches("[[:a:]", "[:", posix, false));
        assert!(!matches("[[:a:]", "[b", posix, false));
        assert!(matches("[a[:a:]", "[aa", posix, false));
        assert!(matches("[a[:a:]", "[a:", posix, false));
        assert!(!matches("[a[:a:]", "[ab", posix, false));
    }

    #[test]
    fn stars_backtrack() {
        let posix = Flavour::Posix;
        assert!(matches("a*b*c", "aXbYbc", posix, false));
        assert!(matches("a**c", "ac", posix, false));
        assert!(matches("*b", "abb", posix, false));
        assert!(!matches("a*b", "abc", posix, false));
        assert!(!matches("a?", "a", posix, false));
        assert!(matches("*", "", posix, false));
        assert!(matches("", "", posix, false));
        assert!(!matches("", "a", posix, false));
    }

    #[test]
    fn star_dot_star_is_a_catch_all_on_windows_only() {
        let windows = Flavour::Windows;
        assert_eq!(shape("*.*", windows), Shape::All);
        assert_eq!(shape(r"build\*.*", windows), Shape::All);
        assert_eq!(shape("*.*", Flavour::Posix), Shape::Entries);
        assert_eq!(shape("*.tmp", windows), Shape::Entries);
        assert_eq!(shape("*git", windows), Shape::Entries);
        assert_eq!(shape(r"build\*", windows), Shape::All);
    }

    #[test]
    fn a_pattern_in_the_workspace_folder_reaches_git_when_a_wildcard_can_match_it() {
        let windows = Flavour::Windows;
        let reaches = |parts: &[&str]| reaches_git(parts, windows, true);
        // The first part is the last: it must match `.git` and pick names.
        for parts in [&["*git"][..], &["?git"], &["*GIT"], &["????"], &["[!.]git"]] {
            assert!(reaches(parts), "{parts:?}");
        }
        for parts in [&["*"][..], &["*.*"], &["*.tmp"], &["*gitx"], &["?git2"]] {
            assert!(!reaches(parts), "{parts:?}");
        }
        // Otherwise the next part must match an entry of `.git`.
        for parts in [
            &["*", "objects"][..],
            &["*", "OBJECTS", "x"],
            &["????", "HEAD"],
            &["*git", "refs"],
            &["*", "*"],
            &["*", "*s"],
            &["*", "pack?d-refs"],
            &["*", "modules"],
            &["*", "LFS"],
            &["*", "worktrees"],
            &["*", "shallow"],
            &["*", "ORIG_HEAD"],
            &["*", "MERGE_HEAD"],
            &["*", "rebase-*"],
            &["*", "sequencer"],
            &["*", ".."],
        ] {
            assert!(reaches(parts), "{parts:?}");
        }
        for parts in [
            &["*", "bin"][..],
            &["*", "obj"],
            &["*", "*.o"],
            &["*", "dist", "objects"],
            &["*tmp", "objects"],
            &["x*", "HEAD"],
        ] {
            assert!(!reaches(parts), "{parts:?}");
        }
        assert!(!reaches(&[]));
    }

    #[test]
    fn a_windows_part_is_trimmed_before_it_is_matched() {
        let windows = Flavour::Windows;
        let reaches = |parts: &[&str]| reaches_git(parts, windows, true);
        // The last part loses every trailing dot and space.
        for parts in [&["*git."][..], &["*git "], &["*git. . "], &["????."]] {
            assert!(reaches(parts), "{parts:?}");
        }
        // A part before the last loses one trailing dot.
        for parts in [
            &["*git.", "objects"][..],
            &["*", "objects."],
            &["*", "objects. "],
        ] {
            assert!(reaches(parts), "{parts:?}");
        }
        // A part that only trimming makes a catch-all is not the whole folder:
        // it matches `.git` and takes it.
        for parts in [&["*."][..], &["*. "], &["?*."], &["*.*."], &["*.* "]] {
            assert!(reaches(parts), "{parts:?}");
        }
        // A name stays a name.
        for parts in [&["*gitx."][..], &["*git.", "bin"], &["*", "bin."]] {
            assert!(!reaches(parts), "{parts:?}");
        }
        // On POSIX a dot is part of the name.
        assert!(!reaches_git(&["*git."], Flavour::Posix, true));
        assert!(!reaches_git(&["*", "objects."], Flavour::Posix, true));
    }

    #[test]
    fn the_part_after_git_is_not_read_as_a_short_name() {
        // `GIT~1` is not an entry of `.git`, so the part after the one that
        // matches `.git` never reaches it by a short name.
        assert!(!reaches_git(&["*", "GIT~1"], Flavour::Windows, true));
        assert!(!reaches_git(&["*", "G*"], Flavour::Windows, true));
        assert!(!reaches_git(&["*", "*1"], Flavour::Windows, true));
        assert!(reaches_git(&["*", "obj*"], Flavour::Windows, true));
    }

    #[test]
    fn a_pattern_reaches_git_by_its_short_name_on_windows() {
        let reaches = |parts: &[&str]| reaches_git(parts, Flavour::Windows, true);
        for parts in [
            &["GIT~1"][..],
            &["git~*"],
            &["GIT~?"],
            &["GIT~[0-9]"],
            &["GIT~??"],
            &["G?T~1"],
            &["*~1"],
            &["*~?"],
            &["*T~1"],
            &["GI????~1"],
            &["GI3F2A~1"],
            &["GI3f2?~?"],
            &["GI[A-F]???~1"],
            &["GI*~1"],
            &["GI3F2A~*"],
            &["*GIT~1"],
            &["GIT~?.", "objects"],
            &["GIT~?", "HEAD"],
            &["*~1", "objects"],
        ] {
            assert!(reaches(parts), "{parts:?}");
        }
        for parts in [
            &["GIT~"][..],
            &["GIT~x"],
            &["GIT~1x"],
            &["GIT~?x"],
            &["GI~?"],
            &["GI??~1"],
            &["GI?????~1"],
            &["GI[g-z]???~1"],
            &["GIT?~1"],
            &["GITX~?"],
            &["PROGRA~?"],
            &["GITHUB~?"],
            &["GITIGN~?"],
            &["*~x"],
            &["*~"],
            &["~1"],
            &["~*"],
            &["GIT~1.txt"],
            &["GIT~?", "bin"],
            &["*~1", "bin"],
            // No literal `~`: an ordinary pattern, though it matches `GIT~1`.
            &["GI*"],
            &["*1"],
            &["git*"],
            &["G*"],
            &["*2"],
            &["?????"],
            &["Git*", "objects"],
            // The hashed form needs a literal `~`.
            &["*2024*"],
            &["*a*"],
            &["*e*"],
            &["*cafe*"],
        ] {
            assert!(!reaches(parts), "{parts:?}");
        }
        // A POSIX name has no short name.
        assert!(!reaches_git(&["GIT~?"], Flavour::Posix, true));
        assert!(!reaches_git(&["*~1"], Flavour::Posix, true));
    }

    #[test]
    fn a_long_short_name_pattern_is_read_in_linear_time() {
        // The number after the `~` has any length, so a long run of `?` fits.
        let pattern = "*~1".to_string() + &"?".repeat(2000);
        assert!(reaches_git(&[&pattern], Flavour::Windows, true));
        // A name before the `~` is six characters at most.
        let pattern = "?*".repeat(2000) + "~1";
        assert!(!reaches_git(&[&pattern], Flavour::Windows, true));
        let pattern = "[".repeat(5000) + "~1";
        assert!(!reaches_git(&[&pattern], Flavour::Windows, true));
    }

    #[test]
    fn a_posix_pattern_reaches_git_only_with_dotglob() {
        let posix = Flavour::Posix;
        assert!(!reaches_git(&["*git"], posix, false));
        assert!(!reaches_git(&["*", "objects"], posix, false));
        assert!(reaches_git(&["*git"], posix, true));
        assert!(reaches_git(&["*", "objects"], posix, true));
    }

    #[test]
    fn a_long_run_of_open_brackets_is_read() {
        let pattern = "[".repeat(60_000);
        for flavour in [Flavour::Posix, Flavour::Windows] {
            assert!(!matches(&pattern, ".git", flavour, true));
            assert_eq!(shape(&pattern, flavour), Shape::Entries);
        }
        let closed = format!("{pattern}]");
        assert!(!matches(&closed, ".git", Flavour::Windows, true));
        let spaced = "[]".repeat(30_000);
        assert!(!matches(&spaced, ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_part_is_a_pattern_when_it_holds_a_wildcard() {
        assert!(has_wildcard("a[b"));
        assert!(!has_wildcard("a.b"));
    }
}
