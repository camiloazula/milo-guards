//! The rules about stopping processes by name: `killall`, `pkill`,
//! `taskkill` and `Stop-Process` are judged one way. A plain name is the
//! agent's own business (stopping a dev server is everyday work); a pattern
//! that matches every process, every process of a user, or a process the
//! system needs, stops the system.

use super::Checker;
use crate::powershell::Params;
use crate::unit::{Arg, Unit};
use crate::Rule;

/// How a program reads the name it is given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Names {
    /// As written: `killall node`.
    Literal,
    /// As a regular expression, searched for in each name: `pkill node`.
    Regex,
    /// With the wildcards `*`, `?` and `[a-z]`: `Stop-Process -Name node*`,
    /// `taskkill /IM node*`.
    Wildcard,
}

/// Processes the system needs, in lower case and without `.exe`: stopping
/// one logs you out, freezes the screen or takes the machine down.
const SYSTEM_PROCESSES: [&str; 14] = [
    "launchd",
    "systemd",
    "init",
    "kernel_task",
    "kthreadd",
    "windowserver",
    "loginwindow",
    "explorer",
    "csrss",
    "winlogon",
    "wininit",
    "lsass",
    "smss",
    "services",
];

/// The longest regular expression nesting read; deeper is treated as
/// matching everything.
const MAX_NESTING: usize = 32;

impl Checker<'_> {
    /// `killall`: names as written, or regular expressions with `-r`.
    pub(super) fn killall(&mut self, args: &[Arg]) {
        let options = Options::read(args, "suyoZctn", &KILLALL_LONGS);
        let kind = if options.has("r") || options.has("m") || options.has("regexp") {
            Names::Regex
        } else {
            Names::Literal
        };
        let user = options.has_value("u") || options.has_value("user");
        self.stop_all(&options.operands, kind, user);
    }

    /// `pkill`: regular expressions, searched for in each name.
    pub(super) fn pkill(&mut self, args: &[Arg]) {
        let options = Options::read(args, "uUGgPstFjMN", &PKILL_LONGS);
        let user = ["u", "U", "G", "euid", "uid", "group"]
            .iter()
            .any(|name| options.has_value(name));
        if options.has("v") || options.has("inverse") {
            // Everything but what matches.
            if !options.operands.is_empty() || user {
                self.add(
                    Rule::StopSystem,
                    "stops every process but the ones it names",
                    options.operands.first().copied(),
                );
            }
            return;
        }
        self.stop_all(&options.operands, Names::Regex, user);
    }

    /// The names a stop is given, or every process of a user when it is
    /// given a user and no name.
    fn stop_all(&mut self, names: &[&Arg], kind: Names, user: bool) {
        if names.is_empty() {
            if user {
                self.add(Rule::StopSystem, "stops every process of a user", None);
            }
            return;
        }
        for name in names {
            self.stop_named(name, kind);
        }
    }

    /// One name or pattern a stop is given.
    fn stop_named(&mut self, name: &Arg, kind: Names) {
        let Some(text) = name.known() else {
            self.add(
                Rule::StopSystem,
                "stops processes named only when it runs",
                Some(name),
            );
            return;
        };
        let everything = match kind {
            Names::Literal => false,
            Names::Regex => !needs_literal(text),
            Names::Wildcard => !wildcard_needs_literal(&process_name(text)),
        };
        if everything {
            self.add(Rule::StopSystem, "stops every process", Some(name));
        } else if names_system_process(text, kind) {
            self.add(
                Rule::StopSystem,
                "stops a process the system needs",
                Some(name),
            );
        }
    }

    /// `taskkill /IM name`, `/FI "IMAGENAME eq name"`, `/FI "USERNAME eq me"`.
    pub(super) fn taskkill(&mut self, args: &[Arg]) {
        let mut iter = args.iter();
        let mut named = false;
        let mut filters = Vec::new();
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known() else { continue };
            match text.to_ascii_lowercase().as_str() {
                "/im" | "-im" => {
                    if let Some(name) = iter.next() {
                        named = true;
                        self.stop_named(name, Names::Wildcard);
                    }
                }
                "/fi" | "-fi" => filters.extend(iter.next()),
                _ => {}
            }
        }
        for filter in filters {
            let Some(text) = filter.known() else {
                if !named {
                    self.add(
                        Rule::StopSystem,
                        "stops processes picked by a filter only known when it runs",
                        Some(filter),
                    );
                }
                continue;
            };
            let words: Vec<&str> = text.split_whitespace().collect();
            let field = words.first().map(|word| word.to_ascii_lowercase());
            let operator = words.get(1).map(|word| word.to_ascii_lowercase());
            let value = words
                .get(2..)
                .map(|rest| rest.join(" "))
                .unwrap_or_default();
            match (field.as_deref(), operator.as_deref()) {
                (Some("imagename"), Some("eq")) => {
                    self.stop_named(&Arg::Known(value), Names::Wildcard);
                }
                (Some("imagename"), Some(_)) => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process but the ones it names",
                        Some(filter),
                    );
                }
                (Some("username"), Some(_)) if !named => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process of a user",
                        Some(filter),
                    );
                }
                _ => {}
            }
        }
    }

    /// `Stop-Process -Name name`, and `Get-Process … | Stop-Process`, which
    /// stops what the listing names (every process when it names none).
    pub(super) fn stop_process(&mut self, unit: &Unit) {
        let params = Params::read(&unit.args);
        let names = params.values(&["name"]);
        if !names.is_empty() {
            // `-Name a,b` gives the second name as a positional argument.
            let rest = params
                .positional
                .iter()
                .filter(|arg| arg.known().is_none_or(|text| text.parse::<u64>().is_err()));
            for name in names.into_iter().chain(rest.copied()) {
                self.stop_named(name, Names::Wildcard);
            }
            return;
        }
        let selected = !params.values(&["id", "inputobject"]).is_empty()
            || !params.positional.is_empty()
            || params
                .named
                .iter()
                .any(|(name, _)| "inputobject".starts_with(name.as_str()));
        let Some(stage) = unit.stage.filter(|stage| stage.index > 0 && !selected) else {
            return;
        };
        // What the pipeline's first stage lists.
        let first = self
            .producers
            .get(&(stage.pipeline, 0))
            .and_then(|&at| self.split.units.get(at));
        let Some(listing) = first.filter(|first| first.key().as_deref() == Some("get-process"))
        else {
            self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                None,
            );
            return;
        };
        let listed = Params::read(&listing.args);
        let mut listed_names = listed.values(&["name"]);
        listed_names.extend(listed.positional.iter().copied());
        if listed_names.is_empty() {
            self.add(Rule::StopSystem, "stops every process", None);
        }
        for name in listed_names {
            self.stop_named(name, Names::Wildcard);
        }
    }
}

/// killall's options with a long form.
const KILLALL_LONGS: [Long; 15] = [
    Long::value("signal"),
    Long::value("user"),
    Long::value("younger-than"),
    Long::value("older-than"),
    Long::value("context"),
    Long::value("ns"),
    Long::flag("regexp"),
    Long::flag("exact"),
    Long::flag("ignore-case"),
    Long::flag("interactive"),
    Long::flag("list"),
    Long::flag("process-group"),
    Long::flag("quiet"),
    Long::flag("verbose"),
    Long::flag("wait"),
];

/// pkill's options with a long form.
const PKILL_LONGS: [Long; 22] = [
    Long::value("signal"),
    Long::value("euid"),
    Long::value("uid"),
    Long::value("group"),
    Long::value("pgroup"),
    Long::value("parent"),
    Long::value("session"),
    Long::value("terminal"),
    Long::value("pidfile"),
    Long::value("ns"),
    Long::value("nslist"),
    Long::value("cgroup"),
    Long::value("env"),
    Long::value("older"),
    Long::value("runstates"),
    Long::flag("inverse"),
    Long::flag("exact"),
    Long::flag("full"),
    Long::flag("newest"),
    Long::flag("oldest"),
    Long::flag("ignore-case"),
    Long::flag("ignore-ancestors"),
];

/// A long option, and whether it takes a value.
struct Long {
    name: &'static str,
    value: bool,
}

impl Long {
    const fn value(name: &'static str) -> Self {
        Self { name, value: true }
    }

    const fn flag(name: &'static str) -> Self {
        Self { name, value: false }
    }
}

/// The options and operands of `killall` or `pkill`, read as they read
/// them: bundled letters, `-u me` or `-ume`, `--user me` or `--user=me`,
/// a signal (`-9`, `-HUP`), and long options that may be abbreviated.
struct Options<'a> {
    operands: Vec<&'a Arg>,
    /// Every option given, by its short letter or full long name, and
    /// whether it was given a value.
    given: Vec<(String, bool)>,
}

impl<'a> Options<'a> {
    fn read(args: &'a [Arg], short_values: &str, longs: &[Long]) -> Self {
        let mut options = Self {
            operands: Vec::new(),
            given: Vec::new(),
        };
        let mut iter = args.iter();
        let mut reading = true;
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known().filter(|_| reading) else {
                options.operands.push(arg);
                continue;
            };
            if text == "--" {
                reading = false;
            } else if let Some(long) = text.strip_prefix("--") {
                let (name, attached) = match long.split_once('=') {
                    Some((name, _)) => (name, true),
                    None => (long, false),
                };
                // A long option may be abbreviated to three letters.
                let found = longs.iter().find(|full| full.name == name).or_else(|| {
                    longs
                        .iter()
                        .find(|full| name.len() >= 3 && full.name.starts_with(name))
                });
                match found {
                    Some(full) if full.value => {
                        let valued = attached || iter.next().is_some();
                        options.given.push((full.name.to_string(), valued));
                    }
                    Some(full) => options.given.push((full.name.to_string(), false)),
                    None => options.given.push((name.to_string(), false)),
                }
            } else if text.len() > 1 && text.starts_with('-') {
                options.bundle(&text[1..], short_values, &mut iter);
            } else {
                options.operands.push(arg);
            }
        }
        options
    }

    /// The letters after one `-`.
    fn bundle(&mut self, letters: &str, short_values: &str, iter: &mut std::slice::Iter<'a, Arg>) {
        // A signal, not letters: `-9`, `-KILL`, `-SIGHUP`.
        let signal = letters.chars().all(|c| c.is_ascii_digit())
            || (letters.len() >= 2
                && letters
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        if signal {
            return;
        }
        for (at, letter) in letters.char_indices() {
            if short_values.contains(letter) {
                let rest = &letters[at + letter.len_utf8()..];
                let valued = !rest.is_empty() || iter.next().is_some();
                self.given.push((letter.to_string(), valued));
                return;
            }
            self.given.push((letter.to_string(), false));
        }
    }

    fn has(&self, name: &str) -> bool {
        self.given.iter().any(|(given, _)| given == name)
    }

    /// Whether an option was given a value.
    fn has_value(&self, name: &str) -> bool {
        self.given
            .iter()
            .any(|(given, valued)| given == name && *valued)
    }
}

/// The name as a process is known: lower case, without `.exe`.
fn process_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Whether `text` names a process the system needs, or (for a wildcard)
/// matches one.
fn names_system_process(text: &str, kind: Names) -> bool {
    match kind {
        Names::Literal => SYSTEM_PROCESSES.contains(&process_name(text).as_str()),
        // Each alternative of a pattern, without its anchors and brackets,
        // and its folder when it is a command line's program.
        Names::Regex => text.split('|').any(|alternative| {
            let alternative = alternative.trim_matches(['^', '$', '(', ')']);
            let name = alternative.rsplit('/').next().unwrap_or(alternative);
            SYSTEM_PROCESSES.contains(&process_name(name).as_str())
        }),
        Names::Wildcard => {
            let pattern = process_name(text);
            SYSTEM_PROCESSES
                .iter()
                .any(|system| wildcard_matches(&pattern, system))
        }
    }
}

/// Whether the wildcard `pattern` matches `name`; a `[…]` set counts as
/// any one character, which can only make a pattern match more.
fn wildcard_matches(pattern: &str, name: &str) -> bool {
    fn matches(pattern: &[char], name: &[char]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*', rest)) => (0..=name.len()).any(|skip| matches(rest, &name[skip..])),
            Some(('?', rest)) => name
                .split_first()
                .is_some_and(|(_, tail)| matches(rest, tail)),
            Some(('[', rest)) => {
                let close = rest.iter().position(|c| *c == ']');
                match (close, name.split_first()) {
                    (Some(close), Some((_, tail))) => matches(&rest[close + 1..], tail),
                    (None, Some((c, tail))) => *c == '[' && matches(rest, tail),
                    (_, None) => false,
                }
            }
            Some((c, rest)) => name
                .split_first()
                .is_some_and(|(first, tail)| first == c && matches(rest, tail)),
        }
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    matches(&pattern, &name)
}

/// Whether a wildcard holds a letter or digit outside its `[…]` sets: with
/// none, it matches every name.
fn wildcard_needs_literal(pattern: &str) -> bool {
    let mut in_set = false;
    for c in pattern.chars() {
        match c {
            '[' => in_set = true,
            ']' => in_set = false,
            c if !in_set && c.is_alphanumeric() => return true,
            _ => {}
        }
    }
    false
}

/// Whether every match of a regular expression holds a letter or digit the
/// expression spells out. One that does not matches every process: `.`,
/// `.*`, `^`, the empty one, `a*`, `(a|)`. What cannot be read as a regular
/// expression counts as not needing one.
fn needs_literal(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut at = 0;
    match alternation(&chars, &mut at, 0) {
        Some(needs) if at == chars.len() => needs,
        _ => false,
    }
}

/// The branches up to a `)` or the end; whether every one needs a literal.
fn alternation(chars: &[char], at: &mut usize, depth: usize) -> Option<bool> {
    if depth > MAX_NESTING {
        return None;
    }
    let mut every = true;
    loop {
        every &= branch(chars, at, depth)?;
        if chars.get(*at) == Some(&'|') {
            *at += 1;
        } else {
            return Some(every);
        }
    }
}

/// One branch: whether it holds a required letter or digit.
fn branch(chars: &[char], at: &mut usize, depth: usize) -> Option<bool> {
    let mut needs = false;
    while let Some(&c) = chars.get(*at) {
        if c == '|' || c == ')' {
            break;
        }
        *at += 1;
        let literal = match c {
            '^' | '$' => continue,
            // `\d`, `\w`, `\.`: an escape is one character of some kind, not
            // a letter the expression spells out.
            '\\' => {
                chars.get(*at)?;
                *at += 1;
                false
            }
            '[' => {
                skip_set(chars, at)?;
                false
            }
            '(' => {
                let inner = alternation(chars, at, depth + 1)?;
                if chars.get(*at) != Some(&')') {
                    return None;
                }
                *at += 1;
                inner
            }
            c => c.is_alphanumeric(),
        };
        let optional = quantifiers(chars, at);
        needs |= literal && !optional;
    }
    Some(needs)
}

/// Skip a `[…]` set, whose `]` may be its first character and which may
/// hold `[:alpha:]`.
fn skip_set(chars: &[char], at: &mut usize) -> Option<()> {
    if chars.get(*at) == Some(&'^') {
        *at += 1;
    }
    if chars.get(*at) == Some(&']') {
        *at += 1;
    }
    loop {
        match chars.get(*at)? {
            ']' => {
                *at += 1;
                return Some(());
            }
            '[' if matches!(chars.get(*at + 1), Some(':' | '.' | '=')) => {
                let kind = chars[*at + 1];
                *at += 2;
                loop {
                    let c = *chars.get(*at)?;
                    *at += 1;
                    if c == kind && chars.get(*at) == Some(&']') {
                        *at += 1;
                        break;
                    }
                }
            }
            _ => *at += 1,
        }
    }
}

/// Skip the quantifiers after an atom; whether they let it match nothing
/// (`*`, `?`, `{0,…}`).
fn quantifiers(chars: &[char], at: &mut usize) -> bool {
    let mut optional = false;
    loop {
        match chars.get(*at) {
            Some('*' | '?') => {
                optional = true;
                *at += 1;
            }
            Some('+') => *at += 1,
            Some('{') => {
                let Some(len) = chars[*at..].iter().position(|c| *c == '}') else {
                    return optional;
                };
                let bound: String = chars[*at + 1..*at + len].iter().collect();
                let valid =
                    !bound.is_empty() && bound.chars().all(|c| c.is_ascii_digit() || c == ',');
                if !valid {
                    return optional;
                }
                let least = bound.split(',').next().unwrap_or_default();
                optional |= least.chars().all(|c| c == '0');
                *at += len + 1;
            }
            _ => return optional,
        }
    }
}
