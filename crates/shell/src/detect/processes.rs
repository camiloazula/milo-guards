//! The rules about stopping processes by name: `killall`, `pkill`,
//! `taskkill` and `Stop-Process` are judged one way. A plain name is the
//! agent's own business (stopping a dev server is everyday work); a pattern
//! that matches every process, every process of a user, or a process the
//! system needs, stops the system.

use super::Checker;
use crate::powershell::{Param, Params};
use crate::unit::{Arg, Between, Unit};
use crate::Rule;

/// How a program reads the name it is given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Names {
    /// As written: `killall node`.
    Literal,
    /// As a regular expression, searched for in each name: `pkill node`.
    /// `exact` is `pkill -x`, which wants the whole name to match;
    /// `ignore_case` is `pkill -i` and `killall -I`.
    Regex { exact: bool, ignore_case: bool },
    /// With the wildcards `*`, `?` and `[a-z]`: `Stop-Process -Name node*`,
    /// `taskkill /IM node*`.
    Wildcard,
}

/// Processes the system needs, as they are named without `.exe`: stopping
/// one logs you out, freezes the screen or takes the machine down.
const SYSTEM_PROCESSES: [&str; 15] = [
    "launchd",
    "systemd",
    "init",
    "kernel_task",
    "kthreadd",
    "WindowServer",
    "loginwindow",
    "explorer",
    "csrss",
    "winlogon",
    "wininit",
    "lsass",
    "smss",
    "services",
    "svchost",
];

/// `Stop-Process`'s own parameters.
const STOP_PROCESS: [Param; 7] = [
    Param::value("name", &["processname"]),
    Param::value("id", &[]),
    Param::value("inputobject", &[]),
    Param::switch("passthru", &[]),
    Param::switch("force", &[]),
    Param::switch("whatif", &["wi"]),
    Param::switch("confirm", &["cf"]),
];

/// `Get-Process`'s own parameters.
const GET_PROCESS: [Param; 7] = [
    Param::value("name", &["processname"]),
    Param::value("id", &["pid"]),
    Param::value("inputobject", &[]),
    Param::value("computername", &["cn"]),
    Param::switch("module", &[]),
    Param::switch("fileversioninfo", &[]),
    Param::switch("includeusername", &[]),
];

/// The longest regular expression nesting read; deeper is treated as
/// matching everything.
const MAX_NESTING: usize = 32;

impl Checker<'_> {
    /// `killall`: names as written, or regular expressions with `-r`.
    pub(super) fn killall(&mut self, args: &[Arg]) {
        let options = Options::read(args, "suyoZctn", &KILLALL_LONGS);
        let kind = if options.has("r") || options.has("m") || options.has("regexp") {
            Names::Regex {
                exact: false,
                ignore_case: options.has("I") || options.has("ignore-case"),
            }
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
        let kind = Names::Regex {
            exact: options.has("x") || options.has("exact"),
            ignore_case: options.has("i") || options.has("ignore-case"),
        };
        self.stop_all(&options.operands, kind, user);
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
            Names::Regex { .. } => !needs_literal(text),
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
                // Stopping by id: the processes are named, whichever they are.
                "/pid" | "-pid" => {
                    named = true;
                    iter.next();
                }
                "/fi" | "-fi" => filters.extend(iter.next()),
                _ => {}
            }
        }
        // A filter on the image name names the process; any other filter
        // narrows what it names.
        let named = named
            || filters.iter().any(|filter| {
                let mut words = filter.known().unwrap_or_default().split_whitespace();
                let field = words.next().map(str::to_ascii_lowercase);
                let operator = words.next().map(str::to_ascii_lowercase);
                (field.as_deref(), operator.as_deref()) == (Some("imagename"), Some("eq"))
            });
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
                // The programs that hang: what `taskkill` is everyday for.
                (Some("status"), Some("eq")) if value.eq_ignore_ascii_case("not responding") => {}
                // Without a name or an id, whatever the filter picks is
                // stopped; with one, a filter only narrows what is named.
                _ if !named => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process a filter picks",
                        Some(filter),
                    );
                }
                _ => {}
            }
        }
    }

    /// `Stop-Process -Name name`, and the processes a `Get-Process` listing
    /// hands it, which it stops (every process when the listing names none).
    pub(super) fn stop_process(&mut self, unit: &Unit) {
        let params = Params::cmdlet(&unit.args, &STOP_PROCESS);
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
        if params.has(&["id", "inputobject"]) || !params.positional.is_empty() {
            // Picked by id or by object: judged by what they hold, a
            // listing written in the argument or `$_` in a block that is a
            // stage after one.
            for listing in &unit.listings {
                self.judge_listing(&listing.args, &listing.between);
            }
            let item = params
                .values(&["id", "inputobject"])
                .into_iter()
                .chain(params.positional.iter().copied())
                .any(|arg| *arg == Arg::Input);
            if let Some((listing, between)) = unit
                .stage
                .filter(|stage| item && stage.index > 0)
                .and_then(|stage| self.listing_before(stage))
            {
                self.judge_listing(&listing, &between);
            }
            return;
        }
        let Some(stage) = unit.stage.filter(|stage| stage.index > 0) else {
            return;
        };
        match self.listing_before(stage) {
            Some((listing, between)) => self.judge_listing(&listing, &between),
            None => self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                None,
            ),
        }
    }

    /// The `Get-Process` that starts the pipeline a stage is in, with its
    /// arguments and what stands between it and the stage.
    fn listing_before(&self, stage: crate::unit::Stage) -> Option<(Vec<Arg>, Vec<Between>)> {
        let at = |index: usize| {
            self.producers
                .get(&(stage.pipeline, index))
                .and_then(|&at| self.split.units.get(at))
        };
        let first = at(0).filter(|first| first.key().as_deref() == Some("get-process"))?;
        let between = (1..stage.index)
            .map(|index| at(index).map_or(Between::Other, between))
            .collect();
        Some((first.args.clone(), between))
    }

    /// Judge what `Get-Process` lists, narrowed by the stages after it, as
    /// a `Stop-Process` stops it.
    fn judge_listing(&mut self, listing: &[Arg], between: &[Between]) {
        // A stage that may hand on processes the listing did not.
        if between.iter().any(|stage| matches!(stage, Between::Other)) {
            self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                None,
            );
            return;
        }
        let params = Params::cmdlet(listing, &GET_PROCESS);
        let mut names = params.values(&["name"]);
        names.extend(params.positional.iter().copied());
        // Named by the listing: what follows can only narrow it.
        if !names.is_empty() {
            for name in names {
                self.stop_named(name, Names::Wildcard);
            }
            return;
        }
        // Picked by id or by object.
        if params.has(&["id", "inputobject"]) {
            return;
        }
        if between.is_empty() {
            self.add(Rule::StopSystem, "stops every process", None);
            return;
        }
        // Every process, narrowed: by a name that a filter spells out, or by
        // one the guard cannot read.
        let mut read = false;
        for stage in between {
            if let Between::Where(args) = stage {
                if let Some(name) = filter_name(args) {
                    read = true;
                    self.stop_named(name, Names::Wildcard);
                }
            }
        }
        if !read {
            self.add(
                Rule::StopSystem,
                "stops processes picked by a filter only known when it runs",
                None,
            );
        }
    }
}

/// What a stage between a listing and a stop does to the processes.
fn between(unit: &Unit) -> Between {
    match unit.key().as_deref() {
        Some("where-object") => Between::Where(unit.args.clone()),
        Some("select-object" | "select" | "sort-object" | "sort") => Between::Narrows,
        _ => Between::Other,
    }
}

/// The name a `Where-Object` stage picks processes by, when it is only a
/// comparison of `Name` or `ProcessName` with `-eq` or `-like`:
/// `Where-Object Name -eq node`, `-Property ProcessName -Like -Value 'node*'`
/// (a block of the same is read into this form by the splitter).
fn filter_name(args: &[Arg]) -> Option<&Arg> {
    let mut property = None;
    let mut value = None;
    let mut positional = Vec::new();
    let mut compares = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(name) = arg
            .known()
            .and_then(|text| text.strip_prefix('-'))
            .filter(|name| name.starts_with(|c: char| c.is_ascii_alphabetic()))
        else {
            positional.push(arg);
            continue;
        };
        let name = name.trim_end_matches(':').to_ascii_lowercase();
        let abbreviates = |full: &str| name.len() >= 3 && full.starts_with(name.as_str());
        match name.as_str() {
            "eq" | "ieq" | "ceq" | "like" | "ilike" | "clike" => compares = true,
            _ if abbreviates("property") => property = iter.next(),
            _ if abbreviates("value") => value = iter.next(),
            _ if abbreviates("filterscript") => {}
            _ => return None,
        }
    }
    let mut positional = positional.into_iter();
    let property = property.or_else(|| positional.next())?;
    let value = value.or_else(|| positional.next())?;
    let property = property.known()?.to_ascii_lowercase();
    (compares
        && positional.next().is_none()
        && matches!(property.as_str(), "name" | "processname")
        && value.known().is_some())
    .then_some(value)
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

/// Whether `text` names a process the system needs, or (for a wildcard
/// or a regular expression) matches one.
fn names_system_process(text: &str, kind: Names) -> bool {
    match kind {
        Names::Literal => SYSTEM_PROCESSES
            .iter()
            .any(|system| process_name(system) == process_name(text)),
        Names::Regex { exact, ignore_case } => text.split('|').any(|alternative| {
            // Each alternative of a pattern, without its anchors and
            // brackets, and its folder when it is a command line's program,
            // compared whole.
            let bare = alternative.trim_matches(['^', '$', '(', ')']);
            let name = bare.rsplit('/').next().unwrap_or(bare);
            SYSTEM_PROCESSES
                .iter()
                .any(|system| process_name(system) == process_name(name))
                || inside_system_name(alternative, exact, ignore_case)
        }),
        Names::Wildcard => {
            let pieces = wildcard_pieces(&process_name(text));
            SYSTEM_PROCESSES.iter().any(|system| {
                let name: Vec<char> = process_name(system).chars().collect();
                wildcard_matches(&pieces, &name)
            })
        }
    }
}

/// Whether a regular expression that is a plain literal (with anchors, and
/// `.*` at either end) is found in a system process's name. The expression
/// is searched for in the name, so `login` is in `loginwindow`; `^` wants
/// the name to start with it and `$` to end with it, and `-x` both. Names
/// are compared as they are written (`WindowServer`) unless the case is
/// ignored.
fn inside_system_name(alternative: &str, exact: bool, ignore_case: bool) -> bool {
    let (mut start, mut end) = (exact, exact);
    let mut rest = alternative;
    loop {
        if let Some(inner) = rest.strip_prefix(['(', ')']) {
            rest = inner;
        } else if let Some(inner) = rest.strip_prefix('^') {
            (start, rest) = (true, inner);
        } else if let Some(inner) = rest.strip_prefix(".*") {
            (start, rest) = (false, inner);
        } else {
            break;
        }
    }
    loop {
        if let Some(inner) = rest.strip_suffix(['(', ')']) {
            rest = inner;
        } else if let Some(inner) = rest.strip_suffix('$') {
            (end, rest) = (true, inner);
        } else if let Some(inner) = rest.strip_suffix(".*") {
            (end, rest) = (false, inner);
        } else {
            break;
        }
    }
    // A command line's program starts where its folder ends.
    if let Some(slash) = rest.rfind('/') {
        (start, rest) = (true, &rest[slash + 1..]);
    }
    if rest.is_empty()
        || rest.contains([
            '.', '[', ']', '(', ')', '*', '+', '?', '{', '}', '\\', '^', '$',
        ])
    {
        return false;
    }
    let literal = if ignore_case {
        rest.to_ascii_lowercase()
    } else {
        rest.to_string()
    };
    SYSTEM_PROCESSES.iter().any(|system| {
        let system = if ignore_case {
            system.to_ascii_lowercase()
        } else {
            (*system).to_string()
        };
        match (start, end) {
            (true, true) => system == literal,
            (true, false) => system.starts_with(&literal),
            (false, true) => system.ends_with(&literal),
            (false, false) => system.contains(&literal),
        }
    })
}

/// One piece of a wildcard.
#[derive(Clone, Copy)]
enum Piece {
    /// `*`: any run of characters. Runs of them are one.
    Star,
    /// `?`, or a `[…]` set, which counts as any one character (that can only
    /// make a pattern match more).
    One,
    Char(char),
}

/// A wildcard as pieces. A `[` with no `]` after it is a plain character.
fn wildcard_pieces(pattern: &str) -> Vec<Piece> {
    let chars: Vec<char> = pattern.chars().collect();
    // A `[` has a `]` after it only before the last one, so the scan for
    // its close runs only when there is one and the set is skipped.
    let last_close = chars.iter().rposition(|c| *c == ']');
    let mut pieces = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        match c {
            '*' => {
                if !matches!(pieces.last(), Some(Piece::Star)) {
                    pieces.push(Piece::Star);
                }
            }
            '?' => pieces.push(Piece::One),
            '[' if last_close.is_some_and(|close| close >= at) => {
                if let Some(close) = chars[at..].iter().position(|c| *c == ']') {
                    at += close + 1;
                }
                pieces.push(Piece::One);
            }
            c => pieces.push(Piece::Char(c)),
        }
    }
    pieces
}

/// Whether the wildcard `pieces` match `name`, in time proportional to
/// their number times the name's length.
fn wildcard_matches(pieces: &[Piece], name: &[char]) -> bool {
    // The positions in `pieces` the matching can be at, after the name so
    // far; a star can also match nothing.
    let spread = |at: &mut Vec<bool>| {
        for index in 0..pieces.len() {
            if at[index] && matches!(pieces[index], Piece::Star) {
                at[index + 1] = true;
            }
        }
    };
    let mut at = vec![false; pieces.len() + 1];
    at[0] = true;
    spread(&mut at);
    for &c in name {
        let mut next = vec![false; pieces.len() + 1];
        for (index, piece) in pieces.iter().enumerate() {
            if !at[index] {
                continue;
            }
            match piece {
                Piece::Star => next[index] = true,
                Piece::One => next[index + 1] = true,
                Piece::Char(p) => next[index + 1] |= *p == c,
            }
        }
        spread(&mut next);
        at = next;
    }
    at[pieces.len()]
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
                // `{2}`, `{0,3}`: digits and commas up to a `}`. Only those
                // are scanned, so a run of `{` is read in linear time.
                let width = chars[*at + 1..]
                    .iter()
                    .take_while(|c| c.is_ascii_digit() || **c == ',')
                    .count();
                if width == 0 || chars.get(*at + 1 + width) != Some(&'}') {
                    return optional;
                }
                let bound: String = chars[*at + 1..*at + 1 + width].iter().collect();
                let least = bound.split(',').next().unwrap_or_default();
                optional |= least.chars().all(|c| c == '0');
                *at += width + 2;
            }
            _ => return optional,
        }
    }
}
