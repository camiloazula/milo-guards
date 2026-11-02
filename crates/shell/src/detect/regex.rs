//! A small reading of the regular expressions `pkill` and `killall -r` take
//! (POSIX extended syntax), enough to answer two questions about one: does
//! every match of it hold a letter or digit it spells out, and can it match
//! a given name. Anything it does not know exactly is read as matching more
//! (`.`, a set and an escape are any one character; a quantifier is a run of
//! them), so an answer of "no" is always right and "yes" may be too many.

/// The deepest nesting of groups read; deeper cannot be read.
const MAX_NESTING: usize = 32;

/// A regular expression as the guard reads it.
enum Re {
    Char(char),
    /// `.`, an escape, or what is only known to be one character.
    Any,
    Set(Box<Set>),
    /// `^`: only at the start of the name.
    Start,
    /// `$`: only at its end.
    End,
    Seq(Vec<Re>),
    Alt(Vec<Re>),
    /// `x*`.
    Star(Box<Re>),
    /// `x+`.
    Plus(Box<Re>),
    /// `x?`.
    Opt(Box<Re>),
}

/// A `[…]` set.
#[derive(Default)]
struct Set {
    negated: bool,
    /// Something in it that is not read exactly (a collating element, an
    /// escape, a range backwards): it matches any character.
    unknown: bool,
    chars: Vec<char>,
    ranges: Vec<(char, char)>,
    classes: Vec<Class>,
}

/// Whether a character is in a class.
type Class = fn(&char) -> bool;

/// `[:alpha:]` and the others.
const CLASSES: [(&str, Class); 12] = [
    ("alpha", char::is_ascii_alphabetic),
    ("digit", char::is_ascii_digit),
    ("alnum", char::is_ascii_alphanumeric),
    ("upper", char::is_ascii_uppercase),
    ("lower", char::is_ascii_lowercase),
    ("space", |c| c.is_ascii_whitespace() || *c == '\x0b'),
    ("blank", |c| matches!(c, ' ' | '\t')),
    ("punct", char::is_ascii_punctuation),
    ("print", |c| c.is_ascii_graphic() || *c == ' '),
    ("graph", char::is_ascii_graphic),
    ("cntrl", char::is_ascii_control),
    ("xdigit", char::is_ascii_hexdigit),
];

impl Set {
    fn matches(&self, c: char, ignore_case: bool) -> bool {
        if self.unknown {
            return true;
        }
        let holds = |c: char| {
            self.chars.contains(&c)
                || self.ranges.iter().any(|&(low, high)| low <= c && c <= high)
                || self.classes.iter().any(|class| class(&c))
        };
        let found = holds(c)
            || (ignore_case && (holds(c.to_ascii_lowercase()) || holds(c.to_ascii_uppercase())));
        found != self.negated
    }
}

struct Parser<'a> {
    chars: &'a [char],
    at: usize,
    /// Whether a `/` ends a folder: what comes before it in a branch is the
    /// folder of a command line's program, and the program starts where it
    /// ends (`/sbin/init`).
    folders: bool,
}

/// The expression, when it can be read all the way.
fn parse(pattern: &str, folders: bool) -> Option<Re> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut parser = Parser {
        chars: &chars,
        at: 0,
        folders,
    };
    let re = parser.alternation(0)?;
    (parser.at == chars.len()).then_some(re)
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    /// The branches up to a `)` or the end.
    fn alternation(&mut self, depth: usize) -> Option<Re> {
        if depth > MAX_NESTING {
            return None;
        }
        let first = self.branch(depth)?;
        if self.peek() != Some('|') {
            return Some(first);
        }
        let mut branches = vec![first];
        while self.peek() == Some('|') {
            self.at += 1;
            branches.push(self.branch(depth)?);
        }
        Some(Re::Alt(branches))
    }

    /// One branch: a sequence of atoms with their quantifiers.
    fn branch(&mut self, depth: usize) -> Option<Re> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            self.at += 1;
            let atom = match c {
                '^' => {
                    items.push(Re::Start);
                    continue;
                }
                '$' => {
                    items.push(Re::End);
                    continue;
                }
                '/' if self.folders => {
                    items.clear();
                    items.push(Re::Start);
                    continue;
                }
                '\\' => {
                    let escaped = self.peek()?;
                    self.at += 1;
                    escape(escaped)
                }
                '[' => Re::Set(Box::new(self.set()?)),
                '(' => {
                    let inner = self.alternation(depth + 1)?;
                    if self.peek() != Some(')') {
                        return None;
                    }
                    self.at += 1;
                    inner
                }
                // A quantifier with nothing before it is not read exactly.
                '.' | '*' | '+' | '?' => Re::Any,
                c => Re::Char(c),
            };
            items.push(self.quantified(atom));
        }
        Some(Re::Seq(items))
    }

    /// A `[…]` set, whose `]` may be its first character and which may hold
    /// `[:alpha:]`. The `[` is read.
    fn set(&mut self) -> Option<Set> {
        let mut set = Set::default();
        if self.peek() == Some('^') {
            set.negated = true;
            self.at += 1;
        }
        if self.peek() == Some(']') {
            set.chars.push(']');
            self.at += 1;
        }
        loop {
            let c = self.peek()?;
            self.at += 1;
            match c {
                ']' => return Some(set),
                '[' if matches!(self.peek(), Some(':' | '.' | '=')) => {
                    let kind = self.peek()?;
                    self.at += 1;
                    let start = self.at;
                    loop {
                        let c = self.peek()?;
                        self.at += 1;
                        if c == kind && self.peek() == Some(']') {
                            break;
                        }
                    }
                    let name: String = self.chars[start..self.at - 1].iter().collect();
                    self.at += 1;
                    let class = CLASSES.iter().find(|(known, _)| *known == name);
                    match class {
                        Some((_, class)) if kind == ':' => set.classes.push(*class),
                        _ => set.unknown = true,
                    }
                }
                '\\' => set.unknown = true,
                c => {
                    let end = self
                        .chars
                        .get(self.at + 1)
                        .copied()
                        .filter(|end| self.peek() == Some('-') && *end != ']');
                    match end {
                        Some(end) if c <= end => {
                            set.ranges.push((c, end));
                            self.at += 2;
                        }
                        Some(_) => {
                            set.unknown = true;
                            self.at += 2;
                        }
                        None => set.chars.push(c),
                    }
                }
            }
        }
    }

    /// The quantifiers after an atom, as the atom they make: `*`, `?`,
    /// `{0,…}` let it match nothing, and all but `?` and `{0}`/`{1}` let it
    /// repeat.
    fn quantified(&mut self, atom: Re) -> Re {
        let (mut optional, mut repeats) = (false, false);
        loop {
            match self.peek() {
                Some('*') => {
                    optional = true;
                    repeats = true;
                    self.at += 1;
                }
                Some('?') => {
                    optional = true;
                    self.at += 1;
                }
                Some('+') => {
                    repeats = true;
                    self.at += 1;
                }
                Some('{') => {
                    // `{2}`, `{0,3}`: digits and commas up to a `}`. Only those
                    // are scanned, so a run of `{` is read in linear time.
                    let width = self.chars[self.at + 1..]
                        .iter()
                        .take_while(|c| c.is_ascii_digit() || **c == ',')
                        .count();
                    if width == 0 || self.chars.get(self.at + 1 + width) != Some(&'}') {
                        break;
                    }
                    let bound: String = self.chars[self.at + 1..self.at + 1 + width]
                        .iter()
                        .collect();
                    let (least, most) = match bound.split_once(',') {
                        Some((least, most)) => (least, Some(most)),
                        None => (bound.as_str(), None),
                    };
                    optional |= least.chars().all(|c| c == '0');
                    repeats |= match most {
                        None => !at_most_one(least),
                        Some("") => true,
                        Some(most) => !at_most_one(most),
                    };
                    self.at += width + 2;
                }
                _ => break,
            }
        }
        match (optional, repeats) {
            (false, false) => atom,
            (true, false) => Re::Opt(Box::new(atom)),
            (false, true) => Re::Plus(Box::new(atom)),
            (true, true) => Re::Star(Box::new(atom)),
        }
    }
}

/// Whether a bound written in digits is 0 or 1.
fn at_most_one(digits: &str) -> bool {
    let digits = digits.trim_start_matches('0');
    digits.is_empty() || digits == "1"
}

/// What `\x` stands for: usually one character (`\w`, `\.`), but `\b` and
/// `\<` may match no character at all, and `\1` repeats an earlier group.
fn escape(escaped: char) -> Re {
    match escaped {
        'b' | 'B' | '<' | '>' | '`' | '\'' => Re::Opt(Box::new(Re::Any)),
        '1'..='9' => Re::Star(Box::new(Re::Any)),
        _ => Re::Any,
    }
}

/// Whether a .NET regular expression (a PowerShell `-match` pattern) holds
/// something the POSIX reading here would take for plain text: a group that
/// starts with `(?` (a lookaround, an option, a comment, a named group, a
/// conditional) or an escape that is a letter or digit other than `\d \D \w
/// \W \s \S \b \B` (`\x6f`, `\157`, `\cO`, `o`, `\p{L}`, `\k<n>`). Such a
/// pattern is not read at all.
pub(super) fn dotnet_only(pattern: &str) -> bool {
    if pattern.contains("(?") {
        return true;
    }
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(escaped)
                    if escaped.is_alphanumeric()
                        && !matches!(escaped, 'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'b' | 'B') =>
                {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

/// Whether every match of a regular expression holds a letter or digit the
/// expression spells out. One that does not matches every process: `.`,
/// `.*`, `^`, the empty one, `a*`, `(a|)`. What cannot be read as a regular
/// expression counts as not needing one.
pub(super) fn needs_literal(pattern: &str) -> bool {
    parse(pattern, false).is_some_and(|re| needs(&re))
}

fn needs(re: &Re) -> bool {
    match re {
        Re::Char(c) => c.is_alphanumeric(),
        Re::Seq(items) => items.iter().any(needs),
        Re::Alt(branches) => branches.iter().all(needs),
        Re::Plus(inner) => needs(inner),
        Re::Any | Re::Set(_) | Re::Start | Re::End | Re::Star(_) | Re::Opt(_) => false,
    }
}

/// One instruction of the expression run as a machine that follows every way
/// it can match at once.
enum Inst<'a> {
    Char(char),
    Any,
    Set(&'a Set),
    Start,
    End,
    Split(usize, usize),
    Jump(usize),
    Match,
}

fn compile<'a>(re: &'a Re, program: &mut Vec<Inst<'a>>) {
    match re {
        Re::Char(c) => program.push(Inst::Char(*c)),
        Re::Any => program.push(Inst::Any),
        Re::Set(set) => program.push(Inst::Set(set)),
        Re::Start => program.push(Inst::Start),
        Re::End => program.push(Inst::End),
        Re::Seq(items) => {
            for item in items {
                compile(item, program);
            }
        }
        Re::Alt(branches) => {
            let mut jumps = Vec::new();
            for (at, branch) in branches.iter().enumerate() {
                if at + 1 == branches.len() {
                    compile(branch, program);
                    continue;
                }
                let split = program.len();
                program.push(Inst::Split(split + 1, 0));
                compile(branch, program);
                jumps.push(program.len());
                program.push(Inst::Jump(0));
                program[split] = Inst::Split(split + 1, program.len());
            }
            let end = program.len();
            for jump in jumps {
                program[jump] = Inst::Jump(end);
            }
        }
        Re::Star(inner) => {
            let split = program.len();
            program.push(Inst::Split(split + 1, 0));
            compile(inner, program);
            program.push(Inst::Jump(split));
            program[split] = Inst::Split(split + 1, program.len());
        }
        Re::Plus(inner) => {
            let start = program.len();
            compile(inner, program);
            program.push(Inst::Split(start, program.len() + 1));
        }
        Re::Opt(inner) => {
            let split = program.len();
            program.push(Inst::Split(split + 1, 0));
            compile(inner, program);
            program[split] = Inst::Split(split + 1, program.len());
        }
    }
}

/// Whether the regular expression can match one of `names`: searched for in
/// the name, or all of it when `exact`. An expression that cannot be read
/// counts as matching. A `/` in it ends a folder, as a command line's
/// program starts where its folder does.
pub(super) fn matches_any(pattern: &str, names: &[&str], exact: bool, ignore_case: bool) -> bool {
    let Some(re) = parse(pattern, true) else {
        return true;
    };
    search(&re, names, (exact, ignore_case, false))
}

/// Whether the regular expression, searched for in a whole command line as
/// `pkill -f` does, can match the command line of a process that starts as
/// one of `programs` (their paths, with the arguments they usually start
/// with) and is given arguments that are not known: a match that began in
/// the path and can go on into a space and the arguments counts. A `/` is a
/// plain character here, since the program is not what the expression is
/// compared with. An expression that
/// cannot be read counts as matching.
pub(super) fn matches_command_line(
    pattern: &str,
    programs: &[&str],
    exact: bool,
    ignore_case: bool,
) -> bool {
    let Some(re) = parse(pattern, false) else {
        return true;
    };
    search(&re, programs, (exact, ignore_case, true))
}

/// Whether the expression can match any of `names`; `flags` are `exact`,
/// `ignore_case` and `open` (see `run`).
fn search(re: &Re, names: &[&str], flags: (bool, bool, bool)) -> bool {
    let mut program = Vec::new();
    compile(re, &mut program);
    program.push(Inst::Match);
    let mut seen = vec![0_u32; program.len()];
    let mut generation = 0;
    names.iter().any(|name| {
        let name: Vec<char> = name.chars().collect();
        run(&program, &name, flags, &mut seen, &mut generation)
    })
}

/// Run the program over `name`, in time proportional to the program's size
/// times the name's length: the places it can be at after each character are
/// kept as a set, never followed one by one. With `open`, the name is only
/// the start of what is searched: a match that began in it and can go on into a
/// space and what follows counts.
fn run(
    program: &[Inst<'_>],
    name: &[char],
    (exact, ignore_case, open): (bool, bool, bool),
    seen: &mut [u32],
    generation: &mut u32,
) -> bool {
    let mut entering: Vec<usize> = Vec::new();
    let mut stack = Vec::new();
    for at in 0..=name.len() {
        // A search starts anywhere; an exact match only at the start.
        let carried = entering.len();
        if at == 0 || !exact {
            entering.push(0);
        }
        *generation += 1;
        let mut threads = Vec::new();
        let mut going = 0;
        for (index, &start) in entering.iter().enumerate() {
            if index == carried {
                going = threads.len();
            }
            stack.push(start);
            while let Some(pc) = stack.pop() {
                if seen[pc] == *generation {
                    continue;
                }
                seen[pc] = *generation;
                match program[pc] {
                    Inst::Jump(to) => stack.push(to),
                    Inst::Split(first, second) => {
                        stack.push(second);
                        stack.push(first);
                    }
                    Inst::Start => {
                        if at == 0 {
                            stack.push(pc + 1);
                        }
                    }
                    Inst::End => {
                        if at == name.len() {
                            stack.push(pc + 1);
                        }
                    }
                    _ => threads.push(pc),
                }
            }
        }
        if carried == entering.len() {
            going = threads.len();
        }
        // A match that began in the name and goes on past it: a command line
        // is the name, a space, and arguments that are not known.
        if open
            && at == name.len()
            && threads[..going]
                .iter()
                .any(|&pc| takes(program, pc, ' ', ignore_case))
        {
            return true;
        }
        if (!exact || at == name.len())
            && threads.iter().any(|&pc| matches!(program[pc], Inst::Match))
        {
            return true;
        }
        let Some(&c) = name.get(at) else {
            return false;
        };
        entering = threads
            .into_iter()
            .filter(|&pc| takes(program, pc, c, ignore_case))
            .map(|pc| pc + 1)
            .collect();
    }
    false
}

/// Whether the instruction at `pc` reads the character `c`.
fn takes(program: &[Inst<'_>], pc: usize, c: char, ignore_case: bool) -> bool {
    match program[pc] {
        Inst::Char(wanted) => wanted == c || (ignore_case && wanted.eq_ignore_ascii_case(&c)),
        Inst::Any => true,
        Inst::Set(set) => set.matches(c, ignore_case),
        _ => false,
    }
}
